//! synq-server — HTTP compile + run server for the SynQ IDE
//!
//! POST /compile        — compile SynQ source, sign with ephemeral ML-DSA-65
//! POST /attest         — EIP-191 EVM verification + PQC attestation (SynQAttestationV1)
//! POST /session/new    — load bytecode into a fresh persistent VM session
//! POST /session/run    — call a function on a persistent session
//! DELETE /session/:id  — destroy a session
//! GET  /health
//!
//! PR-C security hardening (previous):
//!   • CSPRNG session IDs, session cap, body size limit, source size limit,
//!     mutex released before VM execution, configurable CORS
//!
//! PR-G: persistent ML-DSA-65 compiler-attestation key (this commit):
//!   - CompilerKey enum: Persistent { private_key, public_key, key_id } | Ephemeral
//!   - SYNQ_COMPILER_KEY_PATH env var: path to private key hex file on disk
//!   - SYNQ_COMPILER_PUBKEY env var: public key hex
//!   - key_id: first 8 bytes of SHA3-256(pubkey) as 16-char hex fingerprint
//!   - GET /pubkey: serves current compiler public key for independent verification
//!   - Persistent mode: trust_model = "compiler-attested", links to /pubkey
//!   - Ephemeral fallback: WARNING logged at startup, trust_model unchanged
//!   - Testnet key generated at /etc/synq/compiler.key (600 root:root)
//!
//! PR-F operational hardening (previous):
//!   Item 1 — GET /health/ready: separate readiness endpoint (503 when near cap).
//!   Item 2 — Per-IP rate limiting: governor token-bucket, 30 req/min sustained,
//!             burst of 10. Returns 429 with Retry-After header on breach.
//!   Item 3 — VM memory cap: max 1024 distinct addresses per session (enforced
//!             in vm.rs Store opcode; configurable via QuantumVM::max_memory_entries).
//!
//! PR-D cryptographic correctness (previous):
//!   Item 1 — Strict hex decoding: hex_decode_strict() returns Result, rejects
//!             odd-length / invalid-char / empty inputs.
//!   Item 2 — EIP-191 server-side EVM signature verification in /attest:
//!             ecrecover extracts signer address; mismatch with claimed address
//!             is rejected before PQC signing begins.
//!   Item 3 — Honest ephemeral-key labelling: sidecar carries trust_model and
//!             note fields; CLI verify output is updated to match.
//!   Item 4 — SynQAttestationV1 canonical payload: versioned, domain-separated
//!             binary structure; PQC signs this instead of ad-hoc concatenation.

use axum::{
    extract::{ConnectInfo, Json, Path, State},
    http::{Method, StatusCode, HeaderValue},
    response::Json as RespJson,
    routing::{delete, get, post},
    Router,
};
use dashmap::DashMap;
use governor::{
    clock::DefaultClock,
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc as StdArc;
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
};
use synq_compiler::{PQCCompiler, PQCSecurityLevel};
use ruint::aliases::U256;
use synq_vm::{QuantumVM, Value};

// ─── Security constants ───────────────────────────────────────────────────────

const SIGNING_ALGORITHM: &str  = "ML-DSA-65";

// ─── PR-F Item 2: Per-IP rate limiting ───────────────────────────────────────
// Token-bucket: 10 burst, refill 1 token/2s → 30 req/min sustained.
// Configurable via SYNQ_RATE_BURST and SYNQ_RATE_PER_SECOND env vars.
type IpLimiter = RateLimiter<IpAddr, dashmap::DashMap<IpAddr, InMemoryState>, DefaultClock, NoOpMiddleware>;

fn build_rate_limiter() -> StdArc<IpLimiter> {
    let burst = std::env::var("SYNQ_RATE_BURST")
        .ok().and_then(|v| v.parse::<u32>().ok()).unwrap_or(10);
    let per_sec_x2 = std::env::var("SYNQ_RATE_PER_SECOND_X2")
        .ok().and_then(|v| v.parse::<u32>().ok()).unwrap_or(2); // token per N seconds
    let burst    = NonZeroU32::new(burst).unwrap_or(NonZeroU32::new(10).unwrap());
    let refill   = NonZeroU32::new(per_sec_x2).unwrap_or(NonZeroU32::new(2).unwrap());
    let quota    = Quota::with_period(std::time::Duration::from_secs(refill.get() as u64))
        .unwrap()
        .allow_burst(burst);
    StdArc::new(RateLimiter::dashmap(quota))
}
const SESSION_TTL: Duration    = Duration::from_secs(30 * 60);
const MAX_SESSIONS: usize      = 100;
const MAX_SOURCE_BYTES: usize  = 64 * 1024;
const MAX_BODY_BYTES: usize    = 128 * 1024;

// ─── Session store ────────────────────────────────────────────────────────────

struct Session {
    vm:         QuantumVM,
    last_used:  Instant,
    state_vars: Vec<(String, u32)>,
}

// ─── PR-G: Persistent compiler-attestation key ───────────────────────────────

/// Compiler signing key. Loaded once at startup; never regenerated per-request.
#[derive(Clone)]
enum CompilerKey {
    /// Loaded from SYNQ_COMPILER_KEY_PATH + SYNQ_COMPILER_PUBKEY.
    /// Proves artifacts came from *this* compiler service.
    Persistent {
        private_key: Vec<u8>,
        public_key:  Vec<u8>,
        key_id:      String,   // first 8 bytes of SHA3-256(pubkey), hex
    },
    /// Fallback: fresh keypair per compilation. Proves integrity only.
    Ephemeral,
}

/// Derive a short key fingerprint: hex(SHA3-256(pubkey)[0..8]).
fn key_fingerprint(pubkey: &[u8]) -> String {
    use sha3::{Digest, Keccak256};
    let hash = Keccak256::digest(pubkey);
    hex::encode(&hash[..8])
}

/// Load the persistent compiler key from env vars, or return Ephemeral.
fn load_compiler_key() -> CompilerKey {
    let key_path = std::env::var("SYNQ_COMPILER_KEY_PATH").ok();
    let pub_hex  = std::env::var("SYNQ_COMPILER_PUBKEY").ok();

    match (key_path, pub_hex) {
        (Some(path), Some(pub_h)) => {
            let priv_hex = match std::fs::read_to_string(&path) {
                Ok(s)  => s.trim().to_string(),
                Err(e) => {
                    eprintln!("WARNING: SYNQ_COMPILER_KEY_PATH={} unreadable: {} — falling back to ephemeral signing", path, e);
                    return CompilerKey::Ephemeral;
                }
            };
            let private_key = match hex::decode(&priv_hex) {
                Ok(b)  => b,
                Err(e) => {
                    eprintln!("WARNING: private key hex decode failed: {} — ephemeral fallback", e);
                    return CompilerKey::Ephemeral;
                }
            };
            let public_key = match hex::decode(&pub_h) {
                Ok(b)  => b,
                Err(e) => {
                    eprintln!("WARNING: public key hex decode failed: {} — ephemeral fallback", e);
                    return CompilerKey::Ephemeral;
                }
            };
            let key_id = key_fingerprint(&public_key);
            println!("  Compiler key:    persistent (key_id={})", key_id);
            CompilerKey::Persistent { private_key, public_key, key_id }
        }
        _ => {
            eprintln!("WARNING: SYNQ_COMPILER_KEY_PATH / SYNQ_COMPILER_PUBKEY not set — using ephemeral per-compilation key. Artifacts cannot be independently verified as originating from this service.");
            CompilerKey::Ephemeral
        }
    }
}

type SessionStore = Arc<Mutex<HashMap<String, Session>>>;

#[derive(Clone)]
struct AppState {
    sessions:      SessionStore,
    rate_limiter:  StdArc<IpLimiter>,
    compiler_key:  Arc<CompilerKey>,
}

/// PR-F Item 2: check the per-IP rate limit.
/// Returns Ok(()) if the request is within quota, Err(Response) with 429 + Retry-After otherwise.
/// Returns Ok(()) if within quota, Err(wait_secs) if rate-limited.
fn check_rate_limit(limiter: &IpLimiter, ip: IpAddr) -> Result<(), u64> {
    match limiter.check_key(&ip) {
        Ok(_)  => Ok(()),
        Err(not_until) => {
            let wait = not_until.wait_time_from(
                governor::clock::Clock::now(&DefaultClock::default())
            ).as_secs() + 1;
            Err(wait)
        }
    }
}

fn new_session_id() -> String {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("getrandom failed");
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

fn evict_stale(store: &mut HashMap<String, Session>) {
    store.retain(|_, s| s.last_used.elapsed() < SESSION_TTL);
}

fn evict_oldest_if_full(store: &mut HashMap<String, Session>) {
    if store.len() < MAX_SESSIONS { return; }
    let oldest = store.iter().max_by_key(|(_, s)| s.last_used.elapsed()).map(|(k, _)| k.clone());
    if let Some(k) = oldest { store.remove(&k); }
}

// ─── PR-D Item 1: Strict hex decoder ─────────────────────────────────────────
//
// Cryptographic and executable inputs must be decoded strictly.
// This replaces the previous hex_decode_lossy helper which silently dropped
// invalid characters — unacceptable for EVM signatures and bytecode.

fn hex_decode_strict(s: &str) -> Result<Vec<u8>, String> {
    let s = if s.starts_with("0x") || s.starts_with("0X") { &s[2..] } else { s };
    if s.is_empty() {
        return Err("hex string is empty".to_string());
    }
    if s.len() % 2 != 0 {
        return Err(format!("hex string has odd length {}", s.len()));
    }
    s.as_bytes()
        .chunks(2)
        .enumerate()
        .map(|(i, pair)| {
            let hi = pair[0] as char;
            let lo = pair[1] as char;
            let h = hi.to_digit(16)
                .ok_or_else(|| format!("invalid hex character at position {}: {:?}", i * 2, hi))?;
            let l = lo.to_digit(16)
                .ok_or_else(|| format!("invalid hex character at position {}: {:?}", i * 2 + 1, lo))?;
            Ok(((h << 4) | l) as u8)
        })
        .collect()
}

// ─── PR-D Item 2+4: EIP-191 ecrecover + SynQAttestationV1 ───────────────────

/// Keccak-256 digest (Ethereum's hash function).
fn keccak256(data: &[u8]) -> [u8; 32] {
    use sha3::{Keccak256, Digest};
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

/// Recover the Ethereum signer address from an EIP-191 personal_sign signature.
///
/// The browser wallet signs:
///   keccak256("\x19Ethereum Signed Message:\n32" + bytecode_keccak256_bytes)
///
/// `hash`  — the keccak256 of that full EIP-191 prefixed message (32 bytes)
/// `sig65` — the 65-byte ECDSA signature (r[32] ++ s[32] ++ v[1])
///
/// Returns the recovered Ethereum address (20 bytes) or a descriptive error.
fn ecrecover(hash: &[u8; 32], sig65: &[u8]) -> Result<[u8; 20], String> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    if sig65.len() != 65 {
        return Err(format!("signature must be 65 bytes, got {}", sig65.len()));
    }
    let r_s = &sig65[0..64];
    let v    = sig65[64];
    // Ethereum uses v=27/28; ECDSA recovery id is 0/1
    let rec_id = if v >= 27 { v - 27 } else { v };
    let recovery_id = RecoveryId::try_from(rec_id)
        .map_err(|e| format!("invalid recovery id {}: {}", rec_id, e))?;
    let sig = Signature::try_from(r_s)
        .map_err(|e| format!("invalid signature bytes: {}", e))?;
    let vk = VerifyingKey::recover_from_prehash(hash, &sig, recovery_id)
        .map_err(|e| format!("ecrecover failed: {}", e))?;
    // Ethereum address = last 20 bytes of keccak256(uncompressed pubkey, 64 bytes, no 0x04 prefix)
    let uncompressed = vk.to_encoded_point(false);
    let pubkey_bytes = &uncompressed.as_bytes()[1..]; // strip 0x04
    let addr_hash = keccak256(pubkey_bytes);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&addr_hash[12..]);
    Ok(addr)
}

/// Build the SynQAttestationV1 canonical payload (PR-D Item 4).
///
/// Fixed-layout binary structure signed by the PQC layer:
///   [0..16]  = b"SynQAttestation\x01"  (15-byte magic + 1-byte version)
///   [16]     = scheme: 0x01 = EIP-191 personal_sign
///   [17..49] = bytecode keccak256 (32 bytes, server-computed)
///   [49..69] = recovered EVM signer address (20 bytes)
///   [69..73] = issued_at Unix timestamp (u32 big-endian)
///   [73..]   = raw bytecode
///
/// This is deterministic, versioned, and unambiguous.  The PQC signature
/// covers this entire buffer rather than an ad-hoc concatenation.
fn build_attestation_v1(
    bytecode_hash: &[u8; 32],
    evm_signer: &[u8; 20],
    issued_at: u32,
    raw_bytecode: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(73 + raw_bytecode.len());
    payload.extend_from_slice(b"SynQAttestation\x01"); // 16 bytes: magic + version
    payload.push(0x01);                                // scheme: EIP-191 personal_sign
    payload.extend_from_slice(bytecode_hash);          // 32 bytes
    payload.extend_from_slice(evm_signer);             // 20 bytes
    payload.extend_from_slice(&issued_at.to_be_bytes()); // 4 bytes
    payload.extend_from_slice(raw_bytecode);           // variable
    payload
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn value_to_json(v: &Value) -> serde_json::Value {
    match v {
        Value::I32(n)   => json!({"type": "I32",  "value": n}),
        Value::I64(n)   => json!({"type": "I64",  "value": n.to_string()}),
        Value::U128(n)  => json!({"type": "U128", "value": n.to_string()}),
        Value::U256(n)  => json!({"type": "U256", "value": n.to_string()}),
        Value::Bool(b)  => json!({"type": "Bool", "value": b}),
        Value::Bytes(b) => json!({"type": "Bytes","value": hex_encode(b)}),
    }
}

fn value_display(v: &Value) -> String {
    match v {
        Value::I32(n)   => n.to_string(),
        Value::I64(n)   => n.to_string(),
        Value::U128(n)  => n.to_string(),
        Value::U256(n)  => n.to_string(),
        Value::Bool(b)  => b.to_string(),
        Value::Bytes(b) => format!("0x{}", hex_encode(b)),
    }
}

fn parse_arg(v: &serde_json::Value) -> Result<Value, String> {
    match v {
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                if i < 0 { return Err(format!("UInt256 arguments must be non-negative, got {}", i)); }
                return Ok(if i <= i32::MAX as i64 { Value::I32(i as i32) } else { Value::U128(i as u128) });
            }
            if let Some(u) = n.as_u64() { return Ok(Value::U128(u as u128)); }
            match n.to_string().parse::<u128>() {
                Ok(u)  => Ok(Value::U128(u)),
                Err(_) => Err(format!("Cannot represent {} as UInt256", n)),
            }
        }
        serde_json::Value::String(s) => {
            let s = s.trim();
            if s.starts_with('-') { return Err(format!("UInt256 arguments must be non-negative, got {}", s)); }
            if let Ok(u) = s.parse::<u128>() {
                return Ok(if u <= i32::MAX as u128 { Value::I32(u as i32) } else { Value::U128(u) });
            }
            match s.parse::<U256>() {
                Ok(v)  => Ok(Value::U256(v)),
                Err(_) => Err(format!("Cannot parse {:?} as UInt256", s)),
            }
        }
        other => Err(format!("Expected number or string, got {}", other)),
    }
}

// ─── POST /compile ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CompileRequest { source: String }

#[derive(serde::Serialize)]
struct CompileResponse {
    success:            bool,
    bytecode:           Option<String>,
    signature_sidecar:  Option<serde_json::Value>,
    state_vars:         Vec<(String, u32)>,
    errors:             Vec<String>,
    warnings:           Vec<String>,
}

async fn compile_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(req): Json<CompileRequest>,
) -> (StatusCode, RespJson<CompileResponse>) {
    if let Err(wait) = check_rate_limit(&state.rate_limiter, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, RespJson(CompileResponse {
            success: false, bytecode: None, signature_sidecar: None, state_vars: vec![],
            errors: vec![format!("rate limit exceeded — retry in {}s", wait)], warnings: vec![],
        }));
    }
    if req.source.len() > MAX_SOURCE_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE, RespJson(CompileResponse {
            success: false, bytecode: None, signature_sidecar: None, state_vars: vec![],
            errors: vec![format!("Source too large: {} bytes (max {})", req.source.len(), MAX_SOURCE_BYTES)],
            warnings: vec![],
        }));
    }

    let ast = match synq_compiler::parser::parse(&req.source) {
        Ok(a)  => a,
        Err(e) => return (StatusCode::OK, RespJson(CompileResponse {
            success: false, bytecode: None, signature_sidecar: None, state_vars: vec![],
            errors: vec![format!("Parse error: {}", e)], warnings: vec![],
        })),
    };

    let (bytecode, state_vars) = match synq_compiler::codegen::CodeGenerator::new().generate(&ast) {
        Ok(b)  => b,
        Err(e) => return (StatusCode::OK, RespJson(CompileResponse {
            success: false, bytecode: None, signature_sidecar: None, state_vars: vec![],
            errors: vec![format!("Codegen error: {}", e)], warnings: vec![],
        })),
    };

    // PR-G: use persistent compiler key when available, ephemeral otherwise
    let pqc = PQCCompiler::new(PQCSecurityLevel::Enhanced);
    let sidecar = match state.compiler_key.as_ref() {
        CompilerKey::Persistent { private_key, public_key, key_id } => {
            let sig = match pqc.sign_message(private_key, &bytecode, SIGNING_ALGORITHM) {
                Ok(s)  => s,
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, RespJson(CompileResponse {
                    success: false, bytecode: None, signature_sidecar: None, state_vars: vec![],
                    errors: vec![format!("PQC signing failed: {}", e)], warnings: vec![],
                })),
            };
            json!({
                "mode":          "persistent",
                "algorithm":     sig.algorithm,
                "security_level": format!("{:?}", sig.security_level),
                "key_id":        key_id,
                "public_key":    hex_encode(public_key),
                "signature":     hex_encode(&sig.signature),
                "trust_model":   "compiler-attested",
                "note":          "Persistent testnet compiler key. Verify independently at /pubkey.",
            })
        }
        CompilerKey::Ephemeral => {
            let keypair = match pqc.generate_keypair(SIGNING_ALGORITHM) {
                Ok(k)  => k,
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, RespJson(CompileResponse {
                    success: false, bytecode: None, signature_sidecar: None, state_vars: vec![],
                    errors: vec![format!("PQC keygen failed: {}", e)], warnings: vec![],
                })),
            };
            let sig = match pqc.sign_message(&keypair.private_key, &bytecode, SIGNING_ALGORITHM) {
                Ok(s)  => s,
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, RespJson(CompileResponse {
                    success: false, bytecode: None, signature_sidecar: None, state_vars: vec![],
                    errors: vec![format!("PQC signing failed: {}", e)], warnings: vec![],
                })),
            };
            json!({
                "mode":          "ephemeral",
                "algorithm":     sig.algorithm,
                "security_level": format!("{:?}", sig.security_level),
                "public_key":    hex_encode(&keypair.public_key),
                "signature":     hex_encode(&sig.signature),
                "trust_model":   "ephemeral-self-signed",
                "note":          "Ephemeral keypair: proves bytecode integrity but does not establish compiler identity.",
            })
        }
    };

    (StatusCode::OK, RespJson(CompileResponse {
        success: true,
        bytecode: Some(format!("0x{}", hex::encode(&bytecode))),
        signature_sidecar: Some(sidecar),
        state_vars,
        errors: vec![], warnings: vec![],
    }))
}

// ─── POST /attest ─────────────────────────────────────────────────────────────
//
// PR-D Items 2, 3, 4:
//   - Decodes bytecode and EVM signature strictly (Item 1)
//   - Computes bytecode_hash server-side (not trusted from client)
//   - Reconstructs EIP-191 prefixed message and runs ecrecover (Item 2)
//   - Rejects if recovered address != claimed evm_address
//   - Builds SynQAttestationV1 canonical payload (Item 4)
//   - Signs the payload with ephemeral ML-DSA-65
//   - Labels output honestly (Item 3)

#[derive(Deserialize)]
struct AttestRequest {
    bytecode:      String,   // hex-encoded raw bytecode
    evm_signature: String,   // hex-encoded 65-byte EIP-191 personal_sign signature
    evm_address:   String,   // claimed signer address (0x-prefixed, 40 hex chars)
}

#[derive(serde::Serialize)]
struct AttestResponse {
    success:        bool,
    hybrid_sidecar: Option<serde_json::Value>,
    error:          Option<String>,
}

async fn attest_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(req): Json<AttestRequest>,
) -> (StatusCode, RespJson<AttestResponse>) {
    if let Err(_) = check_rate_limit(&state.rate_limiter, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, RespJson(AttestResponse { success: false, hybrid_sidecar: None, error: Some("rate limit exceeded — retry later".into()) }));
    }
    // Item 1: strict hex decode
    let raw_bytecode = match hex_decode_strict(&req.bytecode) {
        Ok(b)  => b,
        Err(e) => return (StatusCode::BAD_REQUEST, RespJson(AttestResponse {
            success: false, hybrid_sidecar: None,
            error: Some(format!("bytecode hex invalid: {}", e)),
        })),
    };
    let evm_sig_bytes = match hex_decode_strict(&req.evm_signature) {
        Ok(b)  => b,
        Err(e) => return (StatusCode::BAD_REQUEST, RespJson(AttestResponse {
            success: false, hybrid_sidecar: None,
            error: Some(format!("evm_signature hex invalid: {}", e)),
        })),
    };
    if raw_bytecode.is_empty() {
        return (StatusCode::BAD_REQUEST, RespJson(AttestResponse {
            success: false, hybrid_sidecar: None, error: Some("bytecode is empty".into()),
        }));
    }
    if evm_sig_bytes.len() != 65 {
        return (StatusCode::BAD_REQUEST, RespJson(AttestResponse {
            success: false, hybrid_sidecar: None,
            error: Some(format!("evm_signature must be 65 bytes, got {}", evm_sig_bytes.len())),
        }));
    }

    // Item 2: server-side EIP-191 verification
    // Step 1: compute bytecode keccak256 server-side (canonical, never trust client hash)
    let bytecode_hash: [u8; 32] = keccak256(&raw_bytecode);
    let bytecode_hash_hex = format!("0x{}", hex_encode(&bytecode_hash));

    // Step 2: reconstruct the exact text message the demo signs via personal_sign.
    // The demo calls: personal_sign("SynQ bytecode keccak256:\n" + keccak256_hex, address)
    // MetaMask applies EIP-191: keccak256("\x19Ethereum Signed Message:\n" + len + message)
    let message = format!("SynQ bytecode keccak256:\n{}", bytecode_hash_hex);
    let message_bytes = message.as_bytes();
    let mut prefixed = Vec::with_capacity(30 + message_bytes.len());
    prefixed.extend_from_slice(b"\x19Ethereum Signed Message:\n");
    prefixed.extend_from_slice(message_bytes.len().to_string().as_bytes());
    prefixed.extend_from_slice(message_bytes);
    let prefixed_hash: [u8; 32] = keccak256(&prefixed);

    // Step 3: ecrecover — extract the signer's address
    let recovered_addr: [u8; 20] = match ecrecover(&prefixed_hash, &evm_sig_bytes) {
        Ok(a)  => a,
        Err(e) => return (StatusCode::BAD_REQUEST, RespJson(AttestResponse {
            success: false, hybrid_sidecar: None,
            error: Some(format!("EVM signature recovery failed: {}", e)),
        })),
    };

    // Step 4: normalize claimed address and compare
    let claimed_hex = req.evm_address.strip_prefix("0x")
        .unwrap_or_else(|| req.evm_address.strip_prefix("0X").unwrap_or(&req.evm_address));
    let claimed_bytes = match hex_decode_strict(claimed_hex) {
        Ok(b) if b.len() == 20 => b,
        Ok(b) => return (StatusCode::BAD_REQUEST, RespJson(AttestResponse {
            success: false, hybrid_sidecar: None,
            error: Some(format!("evm_address must be 20 bytes, got {}", b.len())),
        })),
        Err(e) => return (StatusCode::BAD_REQUEST, RespJson(AttestResponse {
            success: false, hybrid_sidecar: None,
            error: Some(format!("evm_address hex invalid: {}", e)),
        })),
    };
    if recovered_addr != claimed_bytes.as_slice() {
        return (StatusCode::BAD_REQUEST, RespJson(AttestResponse {
            success: false, hybrid_sidecar: None,
            error: Some(format!(
                "EVM signature does not match claimed address — recovered 0x{} vs claimed 0x{}",
                hex_encode(&recovered_addr),
                hex_encode(&claimed_bytes),
            )),
        }));
    }

    // Item 4: build SynQAttestationV1 canonical payload
    let issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH).unwrap_or_default()
        .as_secs() as u32;
    let attestation_payload = build_attestation_v1(
        &bytecode_hash,
        &recovered_addr,
        issued_at,
        &raw_bytecode,
    );

    // PR-G: PQC sign the canonical payload with persistent key when available
    let pqc = PQCCompiler::new(PQCSecurityLevel::Enhanced);
    let (pqc_pub_hex, pqc_sig, pqc_trust, pqc_note, pqc_key_id) = match state.compiler_key.as_ref() {
        CompilerKey::Persistent { private_key, public_key, key_id } => {
            let sig = match pqc.sign_message(private_key, &attestation_payload, SIGNING_ALGORITHM) {
                Ok(s)  => s,
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, RespJson(AttestResponse {
                    success: false, hybrid_sidecar: None, error: Some(format!("PQC sign: {}", e)),
                })),
            };
            (hex_encode(public_key), sig, "compiler-attested",
             "Persistent testnet compiler key. Verify at /pubkey.",
             Some(key_id.clone()))
        }
        CompilerKey::Ephemeral => {
            let keypair = match pqc.generate_keypair(SIGNING_ALGORITHM) {
                Ok(k)  => k,
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, RespJson(AttestResponse {
                    success: false, hybrid_sidecar: None, error: Some(format!("PQC keygen: {}", e)),
                })),
            };
            let sig = match pqc.sign_message(&keypair.private_key, &attestation_payload, SIGNING_ALGORITHM) {
                Ok(s)  => s,
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, RespJson(AttestResponse {
                    success: false, hybrid_sidecar: None, error: Some(format!("PQC sign: {}", e)),
                })),
            };
            (hex_encode(&keypair.public_key), sig, "ephemeral-self-signed",
             "Ephemeral keypair: proves integrity but does not establish compiler identity.",
             None)
        }
    };

    let mut pqc_obj = json!({
        "algorithm":       pqc_sig.algorithm,
        "security_level":  format!("{:?}", pqc_sig.security_level),
        "public_key":      pqc_pub_hex,
        "signature":       hex_encode(&pqc_sig.signature),
        "signed_payload":  "SynQAttestationV1: magic(16) || scheme(1) || keccak256_bytecode(32) || evm_signer(20) || issued_at_u32be(4) || raw_bytecode",
    });
    if let Some(kid) = pqc_key_id {
        pqc_obj["key_id"] = json!(kid);
    }

    (StatusCode::OK, RespJson(AttestResponse {
        success: true, error: None,
        hybrid_sidecar: Some(json!({
            "mode":                "hybrid",
            "attestation_version": "SynQAttestationV1",
            "scheme":              "EIP-191 personal_sign",
            "bytecode_hash":       format!("0x{}", hex_encode(&bytecode_hash)),
            "evm_address":         format!("0x{}", hex_encode(&recovered_addr)),
            "issued_at":           issued_at,
            "pqc":                 pqc_obj,
            "trust_model":         pqc_trust,
            "note":                pqc_note,
        })),
    }))
}

// ─── POST /session/new ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct NewSessionRequest {
    bytecode:   String,
    state_vars: Vec<(String, u32)>,
}

#[derive(serde::Serialize)]
struct NewSessionResponse {
    success:    bool,
    session_id: Option<String>,
    error:      Option<String>,
}

async fn session_new_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<NewSessionRequest>,
) -> (StatusCode, RespJson<NewSessionResponse>) {
    if let Err(_) = check_rate_limit(&state.rate_limiter, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, RespJson(NewSessionResponse { success: false, session_id: None, error: Some("rate limit exceeded — retry later".into()) }));
    }
    let raw = match hex_decode_strict(&req.bytecode) {
        Ok(b) if !b.is_empty() => b,
        Ok(_) => return (StatusCode::BAD_REQUEST, RespJson(NewSessionResponse {
            success: false, session_id: None, error: Some("bytecode is empty".into()),
        })),
        Err(e) => return (StatusCode::BAD_REQUEST, RespJson(NewSessionResponse {
            success: false, session_id: None, error: Some(format!("bytecode hex invalid: {}", e)),
        })),
    };

    let mut vm = QuantumVM::new();
    if let Err(e) = vm.load_bytecode(&raw) {
        return (StatusCode::OK, RespJson(NewSessionResponse {
            success: false, session_id: None, error: Some(format!("Load error: {}", e)),
        }));
    }

    let id = new_session_id();
    {
        let mut map = state.sessions.lock().unwrap();
        evict_stale(&mut map);
        evict_oldest_if_full(&mut map);
        map.insert(id.clone(), Session { vm, last_used: Instant::now(), state_vars: req.state_vars });
    }

    (StatusCode::OK, RespJson(NewSessionResponse { success: true, session_id: Some(id), error: None }))
}

// ─── POST /session/run ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SessionRunRequest {
    session_id: String,
    function:   String,
    args:       Option<Vec<serde_json::Value>>,
}

#[derive(serde::Serialize)]
struct RunResponse {
    success: bool,
    result:  Option<serde_json::Value>,
    output:  String,
    error:   Option<String>,
}

async fn session_run_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<SessionRunRequest>,
) -> (StatusCode, RespJson<RunResponse>) {
    if let Err(_) = check_rate_limit(&state.rate_limiter, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, RespJson(RunResponse { success: false, result: None, output: String::new(), error: Some("rate limit exceeded — retry later".into()) }));
    }
    let mut vm_args: Vec<Value> = Vec::new();
    for (i, raw) in req.args.unwrap_or_default().iter().enumerate() {
        match parse_arg(raw) {
            Ok(v)  => vm_args.push(v),
            Err(e) => return (StatusCode::OK, RespJson(RunResponse {
                success: false, result: None, output: String::new(),
                error: Some(format!("arg[{}]: {}", i, e)),
            })),
        }
    }

    let mut session = {
        let mut map = state.sessions.lock().unwrap();
        match map.remove(&req.session_id) {
            Some(s) => s,
            None    => return (StatusCode::OK, RespJson(RunResponse {
                success: false, result: None, output: String::new(),
                error: Some(format!("Session '{}' not found or expired", req.session_id)),
            })),
        }
    };

    let call_result = session.vm.call_function(&req.function, &vm_args);
    session.last_used = Instant::now();
    { state.sessions.lock().unwrap().insert(req.session_id, session); }

    match call_result {
        Ok(maybe_val) => {
            let (result_json, output) = match &maybe_val {
                Some(v) => (Some(value_to_json(v)), format!("Return value: {}", value_display(v))),
                None    => (None, "Function completed (no return value)".to_string()),
            };
            (StatusCode::OK, RespJson(RunResponse { success: true, result: result_json, output, error: None }))
        }
        Err(synq_vm::VMError::Reverted(msg)) => (StatusCode::OK, RespJson(RunResponse {
            success: false, result: None, output: String::new(),
            error: Some(format!("require failed: {}", msg)),
        })),
        Err(e) => (StatusCode::OK, RespJson(RunResponse {
            success: false, result: None, output: String::new(),
            error: Some(format!("{}", e)),
        })),
    }
}

// ─── DELETE /session/:id ──────────────────────────────────────────────────────

async fn session_delete_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> (StatusCode, RespJson<serde_json::Value>) {
    let removed = state.sessions.lock().unwrap().remove(&id).is_some();
    (StatusCode::OK, RespJson(json!({ "success": removed })))
}

// ─── GET /session/:id/state ───────────────────────────────────────────────────

async fn session_state_handler(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> (StatusCode, RespJson<serde_json::Value>) {
    let map = state.sessions.lock().unwrap();
    let session = match map.get(&session_id) {
        Some(s) => s,
        None    => return (StatusCode::OK, RespJson(json!({ "success": false, "error": "Session not found" }))),
    };
    let mut state_map = serde_json::Map::new();
    for (name, addr) in &session.state_vars {
        let json_val = match session.vm.memory.get(&(*addr as usize)) {
            Some(Value::I32(v))  => json!(v),
            Some(Value::U128(v)) => json!(v.to_string()),
            Some(Value::U256(v)) => json!(v.to_string()),
            None                 => json!(0),
            _                    => json!(null),
        };
        state_map.insert(name.clone(), json_val);
    }
    (StatusCode::OK, RespJson(json!({ "success": true, "state": serde_json::Value::Object(state_map) })))
}

// ─── GET /pubkey ─────────────────────────────────────────────────────────────
//
// PR-G: Returns the current compiler public key so verifiers can independently
// confirm that a sidecar signature came from this service.

async fn pubkey_handler(State(state): State<AppState>) -> RespJson<serde_json::Value> {
    match state.compiler_key.as_ref() {
        CompilerKey::Persistent { public_key, key_id, .. } => {
            RespJson(json!({
                "trust_model": "compiler-attested",
                "algorithm":   SIGNING_ALGORITHM,
                "key_id":      key_id,
                "public_key":  hex_encode(public_key),
                "note":        "Use this public key to verify ML-DSA-65 signatures in /compile and /attest sidecars.",
            }))
        }
        CompilerKey::Ephemeral => {
            RespJson(json!({
                "trust_model": "ephemeral",
                "note":        "No persistent compiler key configured. Each /compile call uses a fresh ephemeral keypair — the public key is embedded in the sidecar but cannot be pre-verified.",
            }))
        }
    }
}

// ─── GET /health ──────────────────────────────────────────────────────────────

async fn health(State(state): State<AppState>) -> RespJson<serde_json::Value> {
    let count = state.sessions.lock().unwrap().len();
    RespJson(json!({
        "status":            "ok",
        "service":           "synq-compiler",
        "active_sessions":   count,
        "max_sessions":      MAX_SESSIONS,
        "session_ttl_secs":  SESSION_TTL.as_secs(),
        "signing_algorithm": SIGNING_ALGORITHM,
        "max_source_bytes":  MAX_SOURCE_BYTES,
        "max_body_bytes":    MAX_BODY_BYTES,
    }))
}

// ─── main ─────────────────────────────────────────────────────────────────────

// ─── GET /health/ready ───────────────────────────────────────────────────────
//
// PR-F Item 1: Separate readiness endpoint for dependency / load-balancer checks.
// Returns 200 OK when the service is fully operational (sessions below cap).
// Returns 503 Service Unavailable when session store is at capacity.
// Liveness (/health) always returns 200; readiness may return 503.

async fn health_ready(State(state): State<AppState>) -> (StatusCode, RespJson<serde_json::Value>) {
    let count = state.sessions.lock().unwrap().len();
    let ready = count < MAX_SESSIONS;
    let status = if ready { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (status, RespJson(json!({
        "ready":           ready,
        "active_sessions": count,
        "max_sessions":    MAX_SESSIONS,
        "reason":          if ready { "ok" } else { "session store at capacity" },
    })))
}

#[tokio::main]
async fn main() {
    let sessions: SessionStore = Arc::new(Mutex::new(HashMap::new()));
    let rate_limiter  = build_rate_limiter();
    let compiler_key  = Arc::new(load_compiler_key());
    let store = AppState { sessions, rate_limiter, compiler_key };

    let cors_origin = std::env::var("SYNQ_CORS_ORIGIN").unwrap_or_else(|_| "*".to_string());
    let cors = if cors_origin == "*" {
        CorsLayer::new()
            .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
            .allow_headers(Any)
            .allow_origin(Any)
    } else {
        let origin = cors_origin.parse::<axum::http::HeaderValue>()
            .expect("Invalid SYNQ_CORS_ORIGIN value");
        CorsLayer::new()
            .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
            .allow_headers(Any)
            .allow_origin(origin)
    };

    let app = Router::new()
        .route("/health",            get(health))
        .route("/health/ready",      get(health_ready))
        .route("/pubkey",            get(pubkey_handler))
        .route("/compile",           post(compile_handler))
        .route("/attest",            post(attest_handler))
        .route("/session/new",       post(session_new_handler))
        .route("/session/run",       post(session_run_handler))
        .route("/session/:id",       delete(session_delete_handler))
        .route("/session/:id/state", get(session_state_handler))
        .with_state(store.clone())
        .layer(
            ServiceBuilder::new()
                .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
                .layer(cors)
        );

    let addr = "0.0.0.0:3030";
    println!("SynQ server listening on {}", addr);
    println!("  Session TTL:     {} min", SESSION_TTL.as_secs() / 60);
    println!("  Max sessions:    {}", MAX_SESSIONS);
    println!("  Max body:        {} KB", MAX_BODY_BYTES / 1024);
    println!("  Max source:      {} KB", MAX_SOURCE_BYTES / 1024);
    let key_mode = match store.compiler_key.as_ref() {
        CompilerKey::Persistent { key_id, .. } => format!("{} (persistent, key_id={})", SIGNING_ALGORITHM, key_id),
        CompilerKey::Ephemeral                 => format!("{} (ephemeral — set SYNQ_COMPILER_KEY_PATH)", SIGNING_ALGORITHM),
    };
    println!("  Signing:         {}", key_mode);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}
