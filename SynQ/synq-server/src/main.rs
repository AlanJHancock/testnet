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
    vm:            QuantumVM,
    last_used:     Instant,
    state_vars:    Vec<(String, u32)>,
    contract_name: Option<String>,      // from compile — used to derive EIP-712 verifyingContract
    workspace_id:  Option<String>,      // workspace this session belongs to (if any)
    pending_nonce: Option<String>,      // server-issued one-time nonce, cleared after use
    used_nonces:   std::collections::HashSet<String>,  // consumed nonces (replay guard)
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

type SessionStore   = Arc<Mutex<HashMap<String, Session>>>;

/// A workspace groups multiple deployed contracts so they can call each other
/// via the ExternCall (0x60) opcode.  Keyed by workspace_id (CSPRNG).
#[derive(Debug)]
struct Workspace {
    /// contract_name -> session_id mapping
    contracts:    HashMap<String, String>,
    /// deploy sequence — contract names in the order they were first registered
    deploy_order: Vec<String>,
    last_used:    Instant,
}

type WorkspaceStore = Arc<Mutex<HashMap<String, Workspace>>>;

#[derive(Clone)]
struct AppState {
    sessions:      SessionStore,
    workspaces:    WorkspaceStore,
    rate_limiter:  StdArc<IpLimiter>,
    compiler_key:  Arc<CompilerKey>,
    source_nonce_secret: Vec<u8>,  // Rev-2: HMAC key for source-nonce derivation
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
// ─── EIP-712 helpers ─────────────────────────────────────────────────────────

fn keccak256_str(s: &str) -> [u8; 32] { keccak256(s.as_bytes()) }

fn pad32(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let start = 32usize.saturating_sub(b.len());
    out[start..].copy_from_slice(&b[..b.len().min(32)]);
    out
}

/// Compute EIP-712 domain separator.
/// verifying_contract: 20-byte address derived from contract name (or zero for attest path).
/// Must exactly match the frontend EIP712Domain type list:
///   { name, version, chainId, verifyingContract }
fn eip712_domain_separator(domain_name: &str, verifying_contract: &[u8; 20]) -> [u8; 32] {
    let type_hash = keccak256_str(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    let name_hash    = keccak256_str(domain_name);
    let version_hash = keccak256_str("1");
    let chain_id     = pad32(&1337u64.to_be_bytes());
    let mut contract_slot = [0u8; 32];
    contract_slot[12..].copy_from_slice(verifying_contract);
    let mut enc = [0u8; 160];
    enc[..32].copy_from_slice(&type_hash);
    enc[32..64].copy_from_slice(&name_hash);
    enc[64..96].copy_from_slice(&version_hash);
    enc[96..128].copy_from_slice(&chain_id);
    enc[128..160].copy_from_slice(&contract_slot);
    keccak256(&enc)
}

/// Zero-address domain separator for /attest (no contract context yet).
fn eip712_domain_separator_zero() -> [u8; 32] {
    eip712_domain_separator("SynQ", &[0u8; 20])
}

/// Contract-name-derived domain separator for /run.
/// domain name = "SynQ · <ContractName>" -- shown verbatim in wallet signing card.
/// verifyingContract = keccak256("SynQ:" + name)[12..] -- stable, unique per contract.
fn eip712_domain_separator_for_contract(contract_name: &str) -> [u8; 32] {
    let domain_name = format!("SynQ · {}", contract_name);
    let hash = keccak256(format!("SynQ:{}", contract_name).as_bytes());
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    eip712_domain_separator(&domain_name, &addr)
}
/// hashStruct(BytecodeAttestation)
/// struct BytecodeAttestation { bytes32 bytecodeHash; uint256 issuedAt; }
fn eip712_hash_bytecode_attestation(bytecode_hash: &[u8; 32], issued_at: u64) -> [u8; 32] {
    let type_hash = keccak256_str(
        "BytecodeAttestation(bytes32 bytecodeHash,uint256 issuedAt)"
    );
    let mut enc = [0u8; 96];
    enc[..32].copy_from_slice(&type_hash);
    enc[32..64].copy_from_slice(bytecode_hash);
    enc[64..96].copy_from_slice(&pad32(&issued_at.to_be_bytes()));
    keccak256(&enc)
}

/// hashStruct(ContractCall)
/// struct ContractCall { string callSignature; string sessionId; string nonce; }
///
/// callSignature = "functionName(arg0, arg1, ...)" -- e.g. "init(1000)" or "burn(500)".
/// Displayed verbatim in the wallet signing card so the user can verify exactly
/// which function and arguments they are authorising before signing.
fn eip712_hash_contract_call(call_sig: &str, session_id: &str, nonce: &str) -> [u8; 32] {
    let type_hash = keccak256_str(
        "ContractCall(string callSignature,string sessionId,string nonce)"
    );
    let mut enc = [0u8; 128];
    enc[..32].copy_from_slice(&type_hash);
    enc[32..64].copy_from_slice(&keccak256_str(call_sig));
    enc[64..96].copy_from_slice(&keccak256_str(session_id));
    enc[96..128].copy_from_slice(&keccak256_str(nonce));
    keccak256(&enc)
}

fn eip712_digest_with_domain(domain_sep: [u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    let mut msg = [0u8; 66];
    msg[0] = 0x19;
    msg[1] = 0x01;
    msg[2..34].copy_from_slice(&domain_sep);
    msg[34..66].copy_from_slice(struct_hash);
    keccak256(&msg)
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
    let r_bytes = &sig65[0..32];
    let s_bytes = &sig65[32..64];
    let v       = sig65[64];
    // Ethereum uses v=27/28; ECDSA recovery id is 0/1
    let mut rec_id = if v >= 27 { v - 27 } else { v };
    // Normalize high-s signatures (Coinbase Wallet may produce them).
    // secp256k1 group order n; if s > n/2, flip s = n - s and toggle rec_id.
    let n: [u8; 32] = [
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
        0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41,
    ];
    let n_half: [u8; 32] = [
        0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,
        0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0,
    ];
    let s_norm: Vec<u8> = if s_bytes > n_half.as_slice() {
        // s > n/2 — compute n - s via big-integer subtraction
        let mut borrow: u16 = 0;
        let mut result = [0u8; 32];
        for i in (0..32).rev() {
            let sub = (n[i] as u16).wrapping_sub(s_bytes[i] as u16).wrapping_sub(borrow);
            result[i] = sub as u8;
            borrow = if sub > 0xFF { 1 } else { 0 };
        }
        rec_id ^= 1;
        result.to_vec()
    } else {
        s_bytes.to_vec()
    };
    let mut r_s_norm = [0u8; 64];
    r_s_norm[..32].copy_from_slice(r_bytes);
    r_s_norm[32..].copy_from_slice(&s_norm);
    let recovery_id = RecoveryId::try_from(rec_id)
        .map_err(|e| format!("invalid recovery id {}: {}", rec_id, e))?;
    let sig = Signature::try_from(r_s_norm.as_slice())
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

fn recover_evm_signer_from_str(message: &str, signature: &[u8]) -> Result<[u8; 20], String> {
    let message_bytes = message.as_bytes();
    let mut prefixed = Vec::with_capacity(30 + message_bytes.len());
    prefixed.extend_from_slice(b"\x19Ethereum Signed Message:\n");
    prefixed.extend_from_slice(message_bytes.len().to_string().as_bytes());
    prefixed.extend_from_slice(message_bytes);
    let prefixed_hash: [u8; 32] = keccak256(&prefixed);
    ecrecover(&prefixed_hash, signature)
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
    payload.push(0x02);                                // scheme: EIP-712 eth_signTypedData_v4
    payload.extend_from_slice(bytecode_hash);          // 32 bytes
    payload.extend_from_slice(evm_signer);             // 20 bytes
    payload.extend_from_slice(&issued_at.to_be_bytes()); // 4 bytes
    payload.extend_from_slice(raw_bytecode);           // variable
    payload
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Upcast any internal numeric variant to U256 for user-facing display.
/// I32 / U128 / U256 are internal VM storage optimisations — the SynQ
/// language only exposes UInt256 to the user, so we always label it that way.
fn value_to_json(v: &Value) -> serde_json::Value {
    match v {
        Value::I32(n)   => json!({"type": "UInt256", "value": n.to_string()}),
        Value::I64(n)   => json!({"type": "UInt256", "value": n.to_string()}),
        Value::U128(n)  => json!({"type": "UInt256", "value": n.to_string()}),
        Value::U256(n)  => json!({"type": "UInt256", "value": n.to_string()}),
        Value::Bool(b)  => json!({"type": "Bool",    "value": b}),
        Value::Bytes(b) => json!({"type": "Bytes",   "value": hex_encode(b)}),
        Value::Map(m)   => {
            let obj: serde_json::Map<String,serde_json::Value> = m.iter()
                .map(|(k,v)| {
                    // Keys are raw bytes — use hex for any non-UTF-8 or null-containing key
                    let key_str = if k.iter().all(|b| *b != 0 && *b < 0x80) {
                        String::from_utf8_lossy(k).to_string()
                    } else {
                        format!("0x{}", hex_encode(k))
                    };
                    (key_str, value_to_json(v))
                })
                .collect();
            json!({"type": "Map", "value": serde_json::Value::Object(obj)})
        }
        Value::Set(s)   => {
            let arr: Vec<serde_json::Value> = s.iter()
                .map(|k| {
                    if k.iter().all(|b| *b != 0 && *b < 0x80) {
                        json!(String::from_utf8_lossy(k).to_string())
                    } else {
                        json!(format!("0x{}", hex_encode(k)))
                    }
                })
                .collect();
            json!({"type": "Set", "value": arr})
        }
    }
}

fn value_display(v: &Value) -> String {
    match v {
        Value::I32(n)   => format!("{} (UInt256)", n),
        Value::I64(n)   => format!("{} (UInt256)", n),
        Value::U128(n)  => format!("{} (UInt256)", n),
        Value::U256(n)  => format!("{} (UInt256)", n),
        Value::Bool(b)  => b.to_string(),
        Value::Bytes(b) => format!("0x{}", hex_encode(b)),
        Value::Map(m)   => format!("Map({} entries)", m.len()),
        Value::Set(s)   => format!("Set({} entries)", s.len()),
    }
}

fn parse_arg(v: &serde_json::Value) -> Result<Value, String> {
    // Normalise to string first — avoids f64 precision loss for large integers
    // (serde_json stores JSON numbers that overflow i64/u64 as f64 internally).
    let s: String = match v {
        serde_json::Value::Number(n) => {
            // Prefer lossless integer paths; fall back to string representation.
            if let Some(i) = n.as_i64() {
                if i < 0 { return Err(format!("UInt256 arguments must be non-negative, got {}", i)); }
                return Ok(if i <= i32::MAX as i64 { Value::I32(i as i32) } else { Value::U128(i as u128) });
            }
            if let Some(u) = n.as_u64() {
                return Ok(if u <= i32::MAX as u64 { Value::I32(u as i32) } else { Value::U128(u as u128) });
            }
            // Number overflows u64 — serde_json has it as f64; use string repr
            // which serde_json formats as the original decimal (no scientific notation)
            n.to_string()
        }
        serde_json::Value::String(s) => s.trim().to_string(),
        other => return Err(format!("Expected number or string, got {}", other)),
    };
    let s = s.trim();
    if s.starts_with('-') { return Err(format!("UInt256 arguments must be non-negative, got {}", s)); }
    // Try small integers first for compact VM representation
    if let Ok(u) = s.parse::<i32>() {
        if u >= 0 { return Ok(Value::I32(u)); }
    }
    if let Ok(u) = s.parse::<u128>() {
        return Ok(if u <= i32::MAX as u128 { Value::I32(u as i32) } else { Value::U128(u) });
    }
    match s.parse::<U256>() {
        Ok(v)  => Ok(Value::U256(v)),
        Err(_) => Err(format!("Cannot parse {:?} as UInt256", s)),
    }
}

// ─── POST /compile ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CompileRequest {
    source: String,
    #[serde(default)]
    wasm_extern_contracts: Option<Vec<String>>,
    /// Set false to skip the §20.2.1 authority check (devnet/smoke-test mode). Default: true.
    #[serde(default = "bool_true")]
    strict_authority: bool,
}

fn bool_true() -> bool { true }

#[derive(serde::Serialize)]
struct CompileResponse {
    success:            bool,
    bytecode:           Option<String>,
    signature_sidecar:  Option<serde_json::Value>,
    state_vars:         Vec<(String, u32)>,
    contract_name:      Option<String>,
    contract_address:   Option<String>,
    /// Contracts this one depends on via extern_call, in declaration order.
    extern_contracts:   Vec<String>,
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
            success: false, bytecode: None, signature_sidecar: None, state_vars: vec![], contract_name: None, contract_address: None,
            extern_contracts: vec![], errors: vec![format!("rate limit exceeded — retry in {}s", wait)], warnings: vec![],
        }));
    }
    if req.source.len() > MAX_SOURCE_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE, RespJson(CompileResponse {
            success: false, bytecode: None, signature_sidecar: None, state_vars: vec![], contract_name: None, contract_address: None, extern_contracts: vec![],
            errors: vec![format!("Source too large: {} bytes (max {})", req.source.len(), MAX_SOURCE_BYTES)],
            warnings: vec![],
        }));
    }

    let ast = match synq_compiler::parser::parse(&req.source) {
        Ok(a)  => a,
        Err(e) => return (StatusCode::OK, RespJson(CompileResponse {
            success: false, bytecode: None, signature_sidecar: None, state_vars: vec![], contract_name: None, contract_address: None, extern_contracts: vec![],
            errors: vec![format!("Parse error: {}", e)], warnings: vec![],
        })),
    };

    // Extract contract name from AST (first Contract node)
    // ── G3: PQC simulation warning ────────────────────────────────────────
    let mut compile_warnings: Vec<String> = Vec::new();
    const PQC_WARN_NAMES: &[&str] = &[
        "dilithium_verify", "falcon_verify", "sphincs_verify",
        "kyber_encapsulate", "kyber_decapsulate", "kyber_decaps",
        "falcon_sign", "mceliece_encapsulate", "mceliece_decapsulate",
        "hqc_encapsulate", "hqc_decapsulate",
    ];
    'pqc_warn: for unit in &ast {
        if let synq_compiler::ast::SourceUnit::Contract(c) = unit {
            for part in &c.parts {
                if let synq_compiler::ast::ContractPart::Function(f) = part {
                    for stmt in &f.body.statements {
                        let exprs: Vec<&synq_compiler::ast::Expression> = match stmt {
                            synq_compiler::ast::Statement::Expression(e) => vec![e],
                            synq_compiler::ast::Statement::Return(Some(e)) => vec![e],
                            synq_compiler::ast::Statement::Assignment(_, e) => vec![e],
                            synq_compiler::ast::Statement::Require(e, _) => vec![e],
                            synq_compiler::ast::Statement::Let { value, .. } => vec![value],
                            _ => vec![],
                        };
                        for expr in exprs {
                            if let synq_compiler::ast::Expression::Call(name, _) = expr {
                                if PQC_WARN_NAMES.contains(&name.as_str()) {
                                    compile_warnings.push(format!(
                                        "PQC builtin '{}' executes via synq-server native VM only. \
                                         In browser (WASM) mode it will throw a RuntimeError.",
                                        name
                                    ));
                                    break 'pqc_warn;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let contract_name: Option<String> = ast.iter().find_map(|unit| match unit {
        synq_compiler::ast::SourceUnit::Contract(c) => Some(c.name.clone()),
        _ => None,
    });

    // Derive a deterministic EVM-style address from the contract name:
    // keccak256("SynQ:" + name), take last 20 bytes → 0x-prefixed hex.
    // This is stable across sessions and matches what the frontend computes.
    let contract_address: Option<String> = contract_name.as_ref().map(|name| {
        let input = format!("SynQ:{}", name);
        let hash  = keccak256(input.as_bytes());
        format!("0x{}", hex_encode(&hash[12..]))
    });

    let mut _cg1 = synq_compiler::codegen::CodeGenerator::new();
    _cg1.strict_authority = req.strict_authority;
    let (bytecode, state_vars) = match _cg1.generate(&ast) {
        Ok(b)  => b,
        Err(e) => return (StatusCode::OK, RespJson(CompileResponse {
            success: false, bytecode: None, signature_sidecar: None, state_vars: vec![], contract_name: None, contract_address: None, extern_contracts: vec![],
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
                    success: false, bytecode: None, signature_sidecar: None, state_vars: vec![], contract_name: None, contract_address: None, extern_contracts: vec![],
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
                    success: false, bytecode: None, signature_sidecar: None, state_vars: vec![], contract_name: None, contract_address: None, extern_contracts: vec![],
                    errors: vec![format!("PQC keygen failed: {}", e)], warnings: vec![],
                })),
            };
            let sig = match pqc.sign_message(&keypair.private_key, &bytecode, SIGNING_ALGORITHM) {
                Ok(s)  => s,
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, RespJson(CompileResponse {
                    success: false, bytecode: None, signature_sidecar: None, state_vars: vec![], contract_name: None, contract_address: None, extern_contracts: vec![],
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
        contract_name:    contract_name.clone(),
        contract_address: contract_address.clone(),
        extern_contracts: {
            let mut ec: Vec<String> = Vec::new();
            for unit in &ast {
                if let synq_compiler::ast::SourceUnit::Contract(c) = unit {
                    for part in &c.parts {
                        if let synq_compiler::ast::ContractPart::Function(f) = part {
                            for stmt in &f.body.statements {
                                if let synq_compiler::ast::Statement::ExternCall { contract, .. } = stmt {
                                    if !ec.contains(contract) { ec.push(contract.clone()); }
                                }
                            }
                        }
                    }
                }
            }
            // ── WASM tamper-detection cross-check ──────────────────────────────
            // If the browser-side WASM compiler reported extern_contracts, they
            // must exactly match what we independently derived from the AST.
            // A mismatch means the WASM output was patched in-memory (e.g. a
            // browser extension or devtools memory poke) before being posted.
            if let Some(ref wasm_ec) = req.wasm_extern_contracts {
                let mut wasm_sorted = wasm_ec.clone();
                let mut server_sorted = ec.clone();
                wasm_sorted.sort();
                server_sorted.sort();
                if wasm_sorted != server_sorted {
                    return (StatusCode::BAD_REQUEST, RespJson(CompileResponse {
                        success: false, bytecode: None, signature_sidecar: None,
                        state_vars: vec![], contract_name: None, contract_address: None,
                        extern_contracts: ec.clone(),
                        errors: vec![format!(
                            "Tamper detected: WASM extern_contracts {:?} does not match \
                             server AST {:?}. Bytecode rejected.",
                            wasm_ec, &ec
                        )],
                        warnings: vec![],
                    }));
                }
            }
            ec
        },
        errors: vec![], warnings: compile_warnings,
    }))
}


// ─── POST /source-nonce ───────────────────────────────────────────────────────
//
// Rev-2 source signing: return a fresh single-use nonce bound to a source hash.
// Stateless — nonce = SHA3_HMAC(source_nonce_secret || source_hash || 10s-bucket).
// Re-requesting within the same 10s bucket returns an identical nonce (idempotent).
// The /compile/sign-source handler accepts nonces up to 120s old.
//
// Body:  { "source_hash": "<64-char lowercase hex, no 0x>" }
// Reply: { "nonce": "<64-char hex>", "expires_in": <seconds> }

#[derive(Deserialize)]
struct SourceNonceRequest {
    source_hash: String,
}
#[derive(serde::Serialize)]
struct SourceNonceResponse {
    nonce:      String,
    expires_in: u64,
}

/// KMAC128 per NIST SP 800-185 §4.3.1 — keyed MAC built on cSHAKE128.
///
/// KMAC128(K, X, L, S) = cSHAKE128(bytepad(encode_string(K), 168) ∥ X ∥ right_encode(L), L, "KMAC", S)
///
/// Parameters used here:
///   K = key (source_nonce_secret, 32 bytes)
///   X = data (source_hash_hex bytes ∥ 8-byte LE bucket)
///   L = 256 bits (32-byte tag)
///   S = b"SynQSourceNonce"  (domain customization)
///
/// The sha3 crate's full CShake128 type (not Core) accepts function_name="KMAC" and
/// customization=S and handles the NIST bytepad(encode_string(N)∥encode_string(S), 168)
/// absorb in its constructor.  We then feed bytepad(encode_string(K),168) as the
/// key block, then the message, then right_encode(L) as the KMAC suffix, and squeeze 32 bytes.
fn kmac128_hex(key: &[u8], data: &[u8]) -> String {
    use sha3::{CShake128Core, digest::{ExtendableOutput, Update, core_api::CoreWrapper}};

    // NIST SP 800-185 §2.3.3  left_encode(x): minimal big-endian encoding, length-prefixed
    fn left_encode(n: usize) -> Vec<u8> {
        if n == 0 { return vec![1, 0]; }
        let bytes = (n as u64).to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        let significant = &bytes[skip..];
        let mut out = vec![significant.len() as u8];
        out.extend_from_slice(significant);
        out
    }
    // NIST SP 800-185 §2.3.3  right_encode(x)
    fn right_encode(n: usize) -> Vec<u8> {
        if n == 0 { return vec![0, 1]; }
        let bytes = (n as u64).to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        let significant = &bytes[skip..];
        let mut out: Vec<u8> = significant.to_vec();
        out.push(significant.len() as u8);
        out
    }
    // NIST SP 800-185 §2.3.3  encode_string(S) = left_encode(len(S)*8) ∥ S
    fn encode_string(s: &[u8]) -> Vec<u8> {
        let mut out = left_encode(s.len() * 8);
        out.extend_from_slice(s);
        out
    }
    // NIST SP 800-185 §2.3.3  bytepad(X, w) = left_encode(w) ∥ X ∥ zeroes to w-byte boundary
    fn bytepad(x: &[u8], w: usize) -> Vec<u8> {
        let mut out = left_encode(w);
        out.extend_from_slice(x);
        let rem = out.len() % w;
        if rem != 0 { out.resize(out.len() + (w - rem), 0u8); }
        out
    }

    // cSHAKE128(·, 256, "KMAC", "SynQSourceNonce")
    // CShake128Core::new_with_function_name absorbs bytepad(encode_string("KMAC")∥encode_string(S), 168)
    // in its constructor; wrap in CoreWrapper to get the Update + ExtendableOutput API.
    let core = CShake128Core::new_with_function_name(b"KMAC", b"SynQSourceNonce");
    let mut h: CoreWrapper<CShake128Core> = CoreWrapper::from_core(core);

    // Feed bytepad(encode_string(K), 168)  — the KMAC key block
    h.update(&bytepad(&encode_string(key), 168));
    // Feed the message
    h.update(data);
    // KMAC suffix: right_encode(L) where L = output bits = 256
    h.update(&right_encode(256));

    // Squeeze 32 bytes
    let mut tag = [0u8; 32];
    h.finalize_xof_into(&mut tag);
    hex_encode(&tag)
}

async fn source_nonce_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<SourceNonceRequest>,
) -> (StatusCode, RespJson<SourceNonceResponse>) {
    if let Err(_) = check_rate_limit(&state.rate_limiter, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, RespJson(SourceNonceResponse { nonce: String::new(), expires_in: 0 }));
    }
    let sh = req.source_hash.trim_start_matches("0x");
    if sh.len() != 64 || hex_decode_strict(sh).is_err() {
        return (StatusCode::BAD_REQUEST, RespJson(SourceNonceResponse { nonce: String::new(), expires_in: 0 }));
    }
    let now    = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let bucket = now / 10;
    let secs_into_bucket = now % 10;
    let expires_in = 120u64.saturating_sub(secs_into_bucket); // ~120s from bucket start
    let mut data = sh.as_bytes().to_vec();
    data.extend_from_slice(&bucket.to_le_bytes());
    let nonce = kmac128_hex(&state.source_nonce_secret, &data);
    (StatusCode::OK, RespJson(SourceNonceResponse { nonce, expires_in }))
}


// ─── POST /compile/sign-source ────────────────────────────────────────────────
//
// Rev-2 source-signing spec: compile SynQ source *and* bind a developer's EVM
// identity to the exact source text via EIP-712 typed-data signature.
//
// Flow:
//   1. Client computes keccak256(source) → source_hash
//   2. Client calls POST /source-nonce with source_hash → nonce
//   3. Client asks wallet to sign EIP-712 SourceCommit struct:
//        domain  : { name:"SynQ", version:"1", chainId:1337,
//                    verifyingContract: keccak256(contractName)[0..20] }
//        struct  : SourceCommit { string sourceHash, string contractName, string nonce }
//        values  : { sourceHash: "0x<64hex>", contractName: "<name>", nonce: "<64hex>" }
//   4. Client posts { source, evm_address, evm_signature, nonce } here
//   5. Server: verifies nonce freshness (HMAC, ≤120s window), ecrecovers author,
//      compiles source, PQC-signs canonical payload, returns compile result +
//      source_commit sidecar.
//
// The canonical PQC payload (SynQSourceCommitV1):
//   b"SynQSourceCommitV1\x00"   (19 bytes)
//   source_hash   (32 bytes, raw)
//   bytecode_hash (32 bytes, raw keccak256 of compiled bytecode)
//   author        (20 bytes, raw recovered EVM address)
//   issued_at     (8 bytes, u64 LE unix seconds)
//   cname_len     (4 bytes, u32 LE)
//   contract_name (bytes)
//
// The source_commit sidecar is embedded in signature_sidecar.source_commit.

#[derive(Deserialize)]
struct SignSourceRequest {
    source:        String,
    evm_address:   String,
    evm_signature: String,
    nonce:         String,
    #[serde(default)]
    wasm_extern_contracts: Option<Vec<String>>,
}

fn eip712_hash_source_commit(source_hash_hex: &str, contract_name: &str, nonce: &str) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    // typeHash
    let type_hash: [u8; 32] = Keccak256::digest(
        b"SourceCommit(string sourceHash,string contractName,string nonce)"
    ).into();
    // EIP-712: string fields encoded as keccak256(value)
    let enc_sh:  [u8; 32] = Keccak256::digest(source_hash_hex.as_bytes()).into();
    let enc_cn:  [u8; 32] = Keccak256::digest(contract_name.as_bytes()).into();
    let enc_nc:  [u8; 32] = Keccak256::digest(nonce.as_bytes()).into();
    let mut buf = [0u8; 128];
    buf[  0.. 32].copy_from_slice(&type_hash);
    buf[ 32.. 64].copy_from_slice(&enc_sh);
    buf[ 64.. 96].copy_from_slice(&enc_cn);
    buf[ 96..128].copy_from_slice(&enc_nc);
    Keccak256::digest(&buf).into()
}

fn build_source_commit_pqc_payload(
    source_hash:   &[u8; 32],
    bytecode_hash: &[u8; 32],
    author:        &[u8; 20],
    issued_at:     u64,
    contract_name: &str,
) -> Vec<u8> {
    let cn = contract_name.as_bytes();
    let mut p = Vec::with_capacity(19 + 32 + 32 + 20 + 8 + 4 + cn.len());
    p.extend_from_slice(b"SynQSourceCommitV1\x00");
    p.extend_from_slice(source_hash);
    p.extend_from_slice(bytecode_hash);
    p.extend_from_slice(author);
    p.extend_from_slice(&issued_at.to_le_bytes());
    p.extend_from_slice(&(cn.len() as u32).to_le_bytes());
    p.extend_from_slice(cn);
    p
}

async fn sign_source_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<SignSourceRequest>,
) -> (StatusCode, RespJson<CompileResponse>) {
    macro_rules! bail {
        ($code:expr, $err:expr) => {
            return ($code, RespJson(CompileResponse {
                success: false, bytecode: None, signature_sidecar: None,
                state_vars: vec![], contract_name: None, contract_address: None,
                extern_contracts: vec![], errors: vec![$err.into()], warnings: vec![],
            }))
        };
    }

    if let Err(wait) = check_rate_limit(&state.rate_limiter, addr.ip()) {
        bail!(StatusCode::TOO_MANY_REQUESTS, format!("rate limit exceeded — retry in {}s", wait));
    }
    if req.source.len() > MAX_SOURCE_BYTES {
        bail!(StatusCode::OK, format!("Source too large: {} bytes (max {})", req.source.len(), MAX_SOURCE_BYTES));
    }

    // 1. Source hash
    use sha3::{Digest, Keccak256};
    let source_hash_bytes: [u8; 32] = Keccak256::digest(req.source.as_bytes()).into();
    let source_hash_hex = hex_encode(&source_hash_bytes);
    let source_hash_with_0x = format!("0x{}", source_hash_hex);

    // 2. Verify nonce (HMAC-derived, 120s window, 10s buckets)
    let clean_nonce = req.nonce.trim_start_matches("0x");
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let nonce_ok = (0u64..=12).any(|offset| {
        let bucket = (now / 10).saturating_sub(offset);
        let mut data = source_hash_hex.as_bytes().to_vec();
        data.extend_from_slice(&bucket.to_le_bytes());
        kmac128_hex(&state.source_nonce_secret, &data) == clean_nonce
    });
    if !nonce_ok {
        bail!(StatusCode::UNAUTHORIZED, "source signing: nonce invalid or expired (max 120s)");
    }

    // 3. Parse + compile
    let ast = match synq_compiler::parser::parse(&req.source) {
        Ok(a)  => a,
        Err(e) => return (StatusCode::OK, RespJson(CompileResponse {
            success: false, bytecode: None, signature_sidecar: None,
            state_vars: vec![], contract_name: None, contract_address: None,
            extern_contracts: vec![],
            errors: vec![format!("Parse error: {}", e)], warnings: vec![],
        })),
    };
    let contract_name: Option<String> = ast.iter().find_map(|unit| match unit {
        synq_compiler::ast::SourceUnit::Contract(c) => Some(c.name.clone()),
        _ => None,
    });
    let cname = contract_name.as_deref().unwrap_or("unknown").to_string();

    // PQC warnings (same logic as /compile)
    let mut compile_warnings: Vec<String> = Vec::new();
    const PQC_WARN_SS: &[&str] = &[
        "dilithium_verify","falcon_verify","sphincs_verify","kyber_encapsulate",
        "kyber_decapsulate","kyber_decaps","falcon_sign","mceliece_encapsulate",
        "mceliece_decapsulate","hqc_encapsulate","hqc_decapsulate",
    ];
    'pw: for unit in &ast {
        if let synq_compiler::ast::SourceUnit::Contract(c) = unit {
            for part in &c.parts {
                if let synq_compiler::ast::ContractPart::Function(f) = part {
                    for stmt in &f.body.statements {
                        let exprs: Vec<&synq_compiler::ast::Expression> = match stmt {
                            synq_compiler::ast::Statement::Expression(e)     => vec![e],
                            synq_compiler::ast::Statement::Return(Some(e))   => vec![e],
                            synq_compiler::ast::Statement::Assignment(_, e)  => vec![e],
                            synq_compiler::ast::Statement::Require(e, _)     => vec![e],
                            synq_compiler::ast::Statement::Let { value, .. } => vec![value],
                            _ => vec![],
                        };
                        for expr in exprs {
                            if let synq_compiler::ast::Expression::Call(name, _) = expr {
                                if PQC_WARN_SS.contains(&name.as_str()) {
                                    compile_warnings.push(format!(
                                        "PQC builtin '{}' executes via synq-server native VM only. \
                                         In browser (WASM) mode it will throw a RuntimeError.", name));
                                    break 'pw;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // extern_contracts + optional tamper-check
    let mut server_extern: Vec<String> = Vec::new();
    for unit in &ast {
        if let synq_compiler::ast::SourceUnit::Contract(c) = unit {
            for part in &c.parts {
                if let synq_compiler::ast::ContractPart::Function(f) = part {
                    for stmt in &f.body.statements {
                        if let synq_compiler::ast::Statement::ExternCall { contract, .. } = stmt {
                            if !server_extern.contains(contract) { server_extern.push(contract.clone()); }
                        }
                    }
                }
            }
        }
    }
    if let Some(ref wasm_ec) = req.wasm_extern_contracts {
        let mut se = server_extern.clone(); se.sort();
        let mut we = wasm_ec.clone();       we.sort();
        if se != we {
            bail!(StatusCode::OK, format!("Tamper detected: WASM extern_contracts {:?} != server AST {:?}", we, se));
        }
    }

    let (bytecode, state_vars_raw) = match synq_compiler::codegen::CodeGenerator::new().generate(&ast) {
        Ok(r)  => r,
        Err(e) => return (StatusCode::OK, RespJson(CompileResponse {
            success: false, bytecode: None, signature_sidecar: None,
            state_vars: vec![], contract_name: None, contract_address: None,
            extern_contracts: vec![],
            errors: vec![format!("Codegen error: {}", e)], warnings: compile_warnings,
        })),
    };
    let bytecode_hash_bytes: [u8; 32] = Keccak256::digest(&bytecode).into();

    // 4. Verify EIP-712 SourceCommit signature
    let domain = eip712_domain_separator_for_contract(&cname);
    let struct_hash = eip712_hash_source_commit(&source_hash_with_0x, &cname, clean_nonce);
    let digest      = eip712_digest_with_domain(domain, &struct_hash);

    let evm_sig = match hex_decode_strict(req.evm_signature.trim_start_matches("0x")) {
        Ok(b) if b.len() == 65 => b,
        Ok(b)  => bail!(StatusCode::BAD_REQUEST, format!("evm_signature must be 65 bytes, got {}", b.len())),
        Err(e) => bail!(StatusCode::BAD_REQUEST, format!("evm_signature hex invalid: {}", e)),
    };
    let recovered = match ecrecover(&digest, &evm_sig) {
        Ok(r)  => r,
        Err(e) => bail!(StatusCode::UNAUTHORIZED, format!("source signing: ecrecover failed: {}", e)),
    };
    let claimed = match hex_decode_strict(req.evm_address.trim_start_matches("0x")) {
        Ok(b) if b.len() == 20 => b,
        _ => bail!(StatusCode::BAD_REQUEST, "evm_address must be a valid 20-byte hex address"),
    };
    if claimed.as_slice() != &recovered {
        bail!(StatusCode::UNAUTHORIZED, format!(
            "source signing: recovered 0x{} != claimed 0x{}",
            hex_encode(&recovered), hex_encode(&claimed)));
    }

    let issued_at = now;
    let author: [u8; 20] = recovered;

    // 5. Build canonical PQC payload and sign
    let commit_payload = build_source_commit_pqc_payload(
        &source_hash_bytes, &bytecode_hash_bytes, &author, issued_at, &cname,
    );
    let pqc = PQCCompiler::new(PQCSecurityLevel::Enhanced);
    let (pqc_pubkey_hex, pqc_sig_hex, trust_model, key_id_val) = match state.compiler_key.as_ref() {
        CompilerKey::Persistent { private_key, public_key, key_id } => {
            match pqc.sign_message(private_key, &commit_payload, SIGNING_ALGORITHM) {
                Ok(sig) => (hex_encode(public_key), hex_encode(&sig.signature), "compiler-attested", serde_json::json!(key_id)),
                Err(e)  => bail!(StatusCode::INTERNAL_SERVER_ERROR, format!("PQC signing failed: {}", e)),
            }
        }
        CompilerKey::Ephemeral => {
            let kp = match pqc.generate_keypair(SIGNING_ALGORITHM) {
                Ok(k) => k, Err(e) => bail!(StatusCode::INTERNAL_SERVER_ERROR, format!("PQC keygen failed: {}", e)),
            };
            match pqc.sign_message(&kp.private_key, &commit_payload, SIGNING_ALGORITHM) {
                Ok(sig) => (hex_encode(&kp.public_key), hex_encode(&sig.signature), "ephemeral-self-signed", serde_json::json!(null)),
                Err(e)  => bail!(StatusCode::INTERNAL_SERVER_ERROR, format!("PQC signing failed: {}", e)),
            }
        }
    };

    // 6. verifyingContract (for sidecar display)
    let vc_hex = format!("0x{}", hex_encode(&Keccak256::digest(cname.as_bytes())[0..20]));

    // 7. Assemble source_commit sidecar + full response
    let source_commit = serde_json::json!({
        "signing_spec":    "SourceCommitV2",
        "author":          format!("0x{}", hex_encode(&author)),
        "source_hash":     source_hash_with_0x,
        "bytecode_hash":   format!("0x{}", hex_encode(&bytecode_hash_bytes)),
        "contract_name":   cname,
        "nonce":           clean_nonce,
        "issued_at":       issued_at,
        "eip712_domain": {
            "name": "SynQ", "version": "1",
            "chainId": 1337, "verifyingContract": vc_hex,
        },
        "pqc_signature":   pqc_sig_hex,
        "pqc_public_key":  pqc_pubkey_hex,
        "pqc_algorithm":   SIGNING_ALGORITHM,
        "trust_model":     trust_model,
        "key_id":          key_id_val,
    });
    let sidecar = serde_json::json!({
        "signature":     pqc_sig_hex,
        "public_key":    pqc_pubkey_hex,
        "algorithm":     SIGNING_ALGORITHM,
        "trust_model":   trust_model,
        "key_id":        key_id_val,
        "source_commit": source_commit,
    });

    let state_var_names: Vec<(String, u32)> = state_vars_raw.iter()
        .map(|(n, a)| (n.clone(), *a)).collect();
    let contract_address = Some(vc_hex);

    (StatusCode::OK, RespJson(CompileResponse {
        success:           true,
        bytecode:          Some(hex_encode(&bytecode)),
        signature_sidecar: Some(sidecar),
        state_vars:        state_var_names,
        contract_name,
        contract_address,
        extern_contracts:  server_extern,
        errors:            vec![],
        warnings:          compile_warnings,
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
    bytecode:      String,        // hex-encoded raw bytecode
    evm_signature: String,        // hex-encoded 65-byte EIP-712 signature
    evm_address:   String,        // claimed signer address (0x-prefixed, 40 hex chars)
    issued_at:     Option<u64>,   // Unix timestamp included in typed data (browser-provided)
    contract_name: Option<String>, // contract name for EIP-712 domain
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

    // EIP-712 verification for /attest
    // Step 1: compute bytecode keccak256 server-side
    let bytecode_hash: [u8; 32] = keccak256(&raw_bytecode);
    let bytecode_hash_hex = format!("0x{}", hex_encode(&bytecode_hash));

    // Step 2: reconstruct EIP-712 digest
    //   struct BytecodeAttestation { bytes32 bytecodeHash; address signer; uint256 issuedAt; }
    // The frontend sends issuedAt in the typed data; we accept it from the request if present,
    // otherwise use 0 (unsigned-attestation path). We iterate over candidate issuedAt values
    // (0 and ±30s window) to tolerate minor clock skew between browser and server.
    // For /attest the issuedAt is embedded in the typed-data the wallet signs; we need the
    // exact value the frontend used. Accept it via the request field (defaulting to 0 for
    // backwards-compat with callers that omit it).
    let issued_at_client = req.issued_at.unwrap_or(0u64);

    // EIP-712 digest: struct BytecodeAttestation { bytes32 bytecodeHash; uint256 issuedAt; }
    // signer is NOT in the struct — it is recovered from the signature after the fact,
    // which avoids the circular dependency and matches the frontend typed data exactly.
    let struct_hash = eip712_hash_bytecode_attestation(&bytecode_hash, issued_at_client);
    let attest_domain = req.contract_name.as_deref()
        .map(eip712_domain_separator_for_contract)
        .unwrap_or_else(eip712_domain_separator_zero);
    let digest      = eip712_digest_with_domain(attest_domain, &struct_hash);

    // Step 3: ecrecover — extract the signer's address
    let recovered_addr: [u8; 20] = match ecrecover(&digest, &evm_sig_bytes) {
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
            "scheme":              "EIP-712 eth_signTypedData_v4",
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
    bytecode:      String,
    state_vars:    Vec<(String, u32)>,
    contract_name: Option<String>,
    workspace_id:  Option<String>,   // if set, register contract into this workspace
}

#[derive(serde::Serialize)]
struct NewSessionResponse {
    success:    bool,
    session_id:    Option<String>,
    contract_name: Option<String>,
    error:      Option<String>,
}


// ─── POST /workspace/new ─────────────────────────────────────────────────────
#[derive(serde::Serialize)]
struct NewWorkspaceResponse { success: bool, workspace_id: Option<String>, error: Option<String> }

async fn workspace_new_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> (StatusCode, RespJson<NewWorkspaceResponse>) {
    if let Err(_) = check_rate_limit(&state.rate_limiter, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, RespJson(NewWorkspaceResponse { success: false, workspace_id: None, error: Some("rate limited".into()) }));
    }
    let wid = new_session_id();
    let mut wmap = state.workspaces.lock().unwrap();
    // cap workspaces at 50
    if wmap.len() >= 50 {
        // evict oldest
        if let Some(oldest) = wmap.iter().min_by_key(|(_, w)| w.last_used).map(|(k, _)| k.clone()) {
            wmap.remove(&oldest);
        }
    }
    wmap.insert(wid.clone(), Workspace { contracts: HashMap::new(), deploy_order: Vec::new(), last_used: Instant::now() });
    (StatusCode::OK, RespJson(NewWorkspaceResponse { success: true, workspace_id: Some(wid), error: None }))
}

// ─── GET /workspace/:id ───────────────────────────────────────────────────────
#[derive(serde::Serialize)]
struct WorkspaceContract { name: String, session_id: String, deploy_index: usize }

#[derive(serde::Serialize)]
struct WorkspaceInfoResponse { success: bool, workspace_id: String, contracts: Vec<WorkspaceContract>, error: Option<String> }

async fn workspace_info_handler(
    State(state): State<AppState>,
    axum::extract::Path(wid): axum::extract::Path<String>,
) -> (StatusCode, RespJson<WorkspaceInfoResponse>) {
    let wmap = state.workspaces.lock().unwrap();
    match wmap.get(&wid) {
        None => (StatusCode::NOT_FOUND, RespJson(WorkspaceInfoResponse {
            success: false, workspace_id: wid, contracts: vec![], error: Some("workspace not found".into()),
        })),
        Some(ws) => {
            let contracts: Vec<WorkspaceContract> = ws.deploy_order.iter().enumerate()
                .filter_map(|(idx, name)| ws.contracts.get(name).map(|sid|
                    WorkspaceContract { name: name.clone(), session_id: sid.clone(), deploy_index: idx }))
                .collect();
            (StatusCode::OK, RespJson(WorkspaceInfoResponse {
                success: true, workspace_id: wid, contracts, error: None,
            }))
        }
    }
}

// ─── DELETE /workspace/:id ────────────────────────────────────────────────────
async fn workspace_delete_handler(
    State(state): State<AppState>,
    axum::extract::Path(wid): axum::extract::Path<String>,
) -> StatusCode {
    let mut wmap = state.workspaces.lock().unwrap();
    if let Some(ws) = wmap.remove(&wid) {
        // also remove all member sessions
        let mut smap = state.sessions.lock().unwrap();
        for sid in ws.contracts.values() {
            smap.remove(sid);
        }
    }
    StatusCode::NO_CONTENT
}


// ─── POST /workspace/:id/join ─────────────────────────────────────────────────
// Register an already-existing session into a workspace without creating a new VM.
// Body: { session_id, contract_name }
#[derive(serde::Deserialize)]
struct WorkspaceJoinRequest {
    session_id:    String,
    contract_name: String,
}
#[derive(serde::Serialize)]
struct WorkspaceJoinResponse { success: bool, error: Option<String> }

async fn workspace_join_handler(
    State(state): State<AppState>,
    axum::extract::Path(wid): axum::extract::Path<String>,
    Json(req): Json<WorkspaceJoinRequest>,
) -> (StatusCode, RespJson<WorkspaceJoinResponse>) {
    // Verify the session exists
    {
        let smap = state.sessions.lock().unwrap();
        if !smap.contains_key(&req.session_id) {
            return (StatusCode::NOT_FOUND, RespJson(WorkspaceJoinResponse {
                success: false, error: Some("session not found".into()),
            }));
        }
    }
    // Register into workspace, creating workspace entry if needed
    {
        let mut wmap = state.workspaces.lock().unwrap();
        if let Some(ws) = wmap.get_mut(&wid) {
            if !ws.contracts.contains_key(&req.contract_name) {
                ws.deploy_order.push(req.contract_name.clone());
            }
            ws.contracts.insert(req.contract_name.clone(), req.session_id.clone());
            ws.last_used = Instant::now();
        } else {
            return (StatusCode::NOT_FOUND, RespJson(WorkspaceJoinResponse {
                success: false, error: Some("workspace not found".into()),
            }));
        }
    }
    // Also stamp workspace_id AND contract_name on the session itself
    {
        let mut smap = state.sessions.lock().unwrap();
        if let Some(sess) = smap.get_mut(&req.session_id) {
            sess.workspace_id   = Some(wid);
            sess.contract_name  = Some(req.contract_name.clone());  // fix: EIP-712 domain
        }
    }
    (StatusCode::OK, RespJson(WorkspaceJoinResponse { success: true, error: None }))
}

// ─── POST /workspace/:id/remove ──────────────────────────────────────────────
// Un-register a session/contract from a workspace. Called when the user removes
// a card from the workspace panel, or when re-deploying an existing contract.
// The session itself is NOT deleted here — that's the client's job via DELETE /session/:id.
#[derive(serde::Deserialize)]
struct WorkspaceRemoveRequest {
    session_id:    String,
    contract_name: String,
}
#[derive(serde::Serialize)]
struct WorkspaceRemoveResponse { success: bool, error: Option<String> }

async fn workspace_remove_handler(
    State(state): State<AppState>,
    axum::extract::Path(wid): axum::extract::Path<String>,
    Json(req): Json<WorkspaceRemoveRequest>,
) -> (StatusCode, RespJson<WorkspaceRemoveResponse>) {
    let mut wmap = state.workspaces.lock().unwrap();
    if let Some(ws) = wmap.get_mut(&wid) {
        // Only remove if the session_id matches — guards against stale client state
        // removing a freshly re-registered contract of the same name.
        if ws.contracts.get(&req.contract_name).map(|s| s == &req.session_id).unwrap_or(false) {
            ws.contracts.remove(&req.contract_name);
            ws.deploy_order.retain(|n| n != &req.contract_name);
        }
        ws.last_used = std::time::Instant::now();
        (StatusCode::OK, RespJson(WorkspaceRemoveResponse { success: true, error: None }))
    } else {
        (StatusCode::NOT_FOUND, RespJson(WorkspaceRemoveResponse {
            success: false, error: Some("workspace not found".into()),
        }))
    }
}

async fn session_new_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<NewSessionRequest>,
) -> (StatusCode, RespJson<NewSessionResponse>) {
    if let Err(_) = check_rate_limit(&state.rate_limiter, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, RespJson(NewSessionResponse { success: false, session_id: None, contract_name: None, error: Some("rate limit exceeded — retry later".into()) }));
    }
    let raw = match hex_decode_strict(&req.bytecode) {
        Ok(b) if !b.is_empty() => b,
        Ok(_) => return (StatusCode::BAD_REQUEST, RespJson(NewSessionResponse {
            success: false, session_id: None, contract_name: None, error: Some("bytecode is empty".into()),
        })),
        Err(e) => return (StatusCode::BAD_REQUEST, RespJson(NewSessionResponse {
            success: false, session_id: None, contract_name: None, error: Some(format!("bytecode hex invalid: {}", e)),
        })),
    };

    let mut vm = QuantumVM::new();
    if let Err(e) = vm.load_bytecode(&raw) {
        return (StatusCode::OK, RespJson(NewSessionResponse {
            success: false, session_id: None, contract_name: None, error: Some(format!("Load error: {}", e)),
        }));
    }

    let id = new_session_id();
    {
        let mut map = state.sessions.lock().unwrap();
        evict_stale(&mut map);
        evict_oldest_if_full(&mut map);
        let wid = req.workspace_id.clone();
        let cname = req.contract_name.clone();
        map.insert(id.clone(), Session {
            vm, last_used: Instant::now(),
            state_vars: req.state_vars,
            contract_name: cname.clone(),
            workspace_id: wid.clone(),
            pending_nonce: None,
            used_nonces: std::collections::HashSet::new(),
        });
        // Register contract in workspace if workspace_id provided
        if let (Some(wid), Some(cname)) = (wid, cname) {
            let mut wmap = state.workspaces.lock().unwrap();
            if let Some(ws) = wmap.get_mut(&wid) {
                ws.contracts.insert(cname, id.clone());
                ws.last_used = Instant::now();
            }
        }
    }

    (StatusCode::OK, RespJson(NewSessionResponse { success: true, session_id: Some(id), contract_name: req.contract_name.clone(), error: None }))
}

// ─── POST /session/run ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SessionRunRequest {
    session_id:     String,
    function:       String,
    args:           Option<Vec<serde_json::Value>>,
    evm_address:    Option<String>,
    evm_signature:  Option<String>,
    call_nonce:     Option<String>,
    call_signature: Option<String>,  // "functionName(arg0, arg1, ...)" — must match frontend
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
    // Build call_sig before args are moved — used in EIP-712 digest if wallet auth is present.
    let call_sig_early: String = match req.call_signature.as_deref() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            let arg_strs: Vec<String> = req.args.as_deref().unwrap_or(&[]).iter().map(|a| match a {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            }).collect();
            format!("{}({})", req.function, arg_strs.join(", "))
        }
    };
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

    // ── Caller authentication ──────────────────────────────────────────────────
    let caller_addr: [u8; 20] = if let (Some(addr_str), Some(sig_str), Some(nonce)) =
        (&req.evm_address, &req.evm_signature, &req.call_nonce)
    {
        // 1. Nonce must match the server-issued pending nonce
        match &session.pending_nonce {
            None => {
                { state.sessions.lock().unwrap().insert(req.session_id.clone(), session); }
                return (StatusCode::UNAUTHORIZED, RespJson(RunResponse {
                    success: false, result: None, output: String::new(),
                    error: Some("caller auth: no pending nonce — call GET /session/:id/nonce first".into()),
                }));
            }
            Some(pn) if pn != nonce => {
                { state.sessions.lock().unwrap().insert(req.session_id.clone(), session); }
                return (StatusCode::UNAUTHORIZED, RespJson(RunResponse {
                    success: false, result: None, output: String::new(),
                    error: Some("caller auth: nonce mismatch — nonces are single-use, request a new one".into()),
                }));
            }
            _ => {}
        }
        // 2. Must not be a replayed nonce
        if session.used_nonces.contains(nonce.as_str()) {
            { state.sessions.lock().unwrap().insert(req.session_id.clone(), session); }
            return (StatusCode::UNAUTHORIZED, RespJson(RunResponse {
                success: false, result: None, output: String::new(),
                error: Some("caller auth: nonce already used — replay attack rejected".into()),
            }));
        }
        // 3. Build EIP-712 ContractCall digest
        //   struct ContractCall { string callSignature; string sessionId; string nonce; }
        //   callSignature must match exactly what the frontend built and the wallet signed.
        //   Accept it from the request; fall back to reconstructing it from function+args
        //   so that the server is always consistent with the frontend regardless of arg count.
        // call_sig_early was built before req.args was moved — use it here.
        // derive domain from contract name stored in session, fall back to zero
        let run_domain = session.contract_name.as_deref()
            .map(eip712_domain_separator_for_contract)
            .unwrap_or_else(eip712_domain_separator_zero);
        let struct_hash = eip712_hash_contract_call(&call_sig_early, &req.session_id, nonce);
        let digest      = eip712_digest_with_domain(run_domain, &struct_hash);
        // 4. ecrecover against EIP-712 digest
        let sig_bytes = hex_decode_strict(sig_str.strip_prefix("0x").unwrap_or(sig_str))
            .map_err(|e| format!("evm_signature hex invalid: {}", e));
        let sig_bytes = match sig_bytes {
            Ok(b) => b,
            Err(e) => {
                { state.sessions.lock().unwrap().insert(req.session_id.clone(), session); }
                return (StatusCode::BAD_REQUEST, RespJson(RunResponse {
                    success: false, result: None, output: String::new(), error: Some(e),
                }));
            }
        };
        let recovered = match ecrecover(&digest, &sig_bytes) {
            Ok(r) => r,
            Err(e) => {
                { state.sessions.lock().unwrap().insert(req.session_id.clone(), session); }
                return (StatusCode::UNAUTHORIZED, RespJson(RunResponse {
                    success: false, result: None, output: String::new(),
                    error: Some(format!("caller auth: ecrecover failed: {}", e)),
                }));
            }
        };
        // 5. Claimed address must match recovered
        let claimed = hex_decode_strict(addr_str.strip_prefix("0x").unwrap_or(addr_str))
            .unwrap_or_default();
        if claimed.len() != 20 || claimed.as_slice() != &recovered {
            { state.sessions.lock().unwrap().insert(req.session_id.clone(), session); }
            return (StatusCode::UNAUTHORIZED, RespJson(RunResponse {
                success: false, result: None, output: String::new(),
                error: Some("caller auth: signature does not match claimed evm_address".into()),
            }));
        }
        // 6. Consume the nonce
        session.pending_nonce = None;
        session.used_nonces.insert(nonce.clone());
        recovered
    } else if req.evm_address.is_some() || req.evm_signature.is_some() || req.call_nonce.is_some() {
        // Partial auth fields — reject rather than silently degrade
        { state.sessions.lock().unwrap().insert(req.session_id.clone(), session); }
        return (StatusCode::BAD_REQUEST, RespJson(RunResponse {
            success: false, result: None, output: String::new(),
            error: Some("caller auth: evm_address, evm_signature, and call_nonce must all be provided together".into()),
        }));
    } else {
        // Unauthenticated call — caller == zero address
        [0u8; 20]
    };
    session.vm.call_context = synq_vm::CallContext::from_address(caller_addr);

    // Wire ExternCall handler if session belongs to a workspace
    if let Some(ref wid) = session.workspace_id.clone() {
        let sessions_arc = state.sessions.clone();
        let workspaces_arc = state.workspaces.clone();
        let wid_clone = wid.clone();
        let caller_clone = caller_addr;
        session.vm.extern_call_handler = Some(std::sync::Arc::new(move |contract: &str, func: &str, args: &[synq_vm::Value]| {
            let wmap = workspaces_arc.lock().unwrap();
            let ws = wmap.get(&wid_clone)
                .ok_or_else(|| synq_vm::VMError::RuntimeError(format!("extern_call: workspace '{}' not found", wid_clone)))?;
            let target_sid = ws.contracts.get(contract)
                .ok_or_else(|| synq_vm::VMError::RuntimeError(format!("extern_call: contract '{}' not in workspace", contract)))?;
            let target_sid = target_sid.clone();
            drop(wmap);
            let mut smap = sessions_arc.lock().unwrap();
            let target = smap.get_mut(&target_sid)
                .ok_or_else(|| synq_vm::VMError::RuntimeError(format!("extern_call: session for '{}' not found", contract)))?;
            target.vm.call_context = synq_vm::CallContext::from_address(caller_clone);
            let result = target.vm.call_function(func, args);
            if let Err(ref e) = result {
                eprintln!("[EC-ERR] {}.{}({:?}) -> {:?}  memory_snapshot: total@0={:?} param@1008000={:?}",
                    contract, func, args, e,
                    target.vm.memory.get(&0),
                    target.vm.memory.get(&1008000));
            }
            target.vm.call_context = synq_vm::CallContext::anonymous();
            target.last_used = std::time::Instant::now();
            result
        }));
    }

    eprintln!("[RUN] fn={} args={:?}", req.function, vm_args);
    let call_result = session.vm.call_function(&req.function, &vm_args);
    eprintln!("[RUN] result={:?}", call_result);
    session.vm.call_context = synq_vm::CallContext::anonymous();
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

async fn session_nonce_handler(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> (StatusCode, RespJson<serde_json::Value>) {
    let mut map = state.sessions.lock().unwrap();
    let session = match map.get_mut(&session_id) {
        Some(s) => s,
        None    => return (StatusCode::NOT_FOUND, RespJson(json!({ "success": false, "error": "Session not found" }))),
    };
    let mut buf = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
    let nonce_hex = hex_encode(&buf);
    session.pending_nonce = Some(nonce_hex.clone());
    session.last_used = Instant::now();
    (StatusCode::OK, RespJson(json!({ "nonce": nonce_hex })))
}

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
            Some(Value::I32(v))   => json!(v),
            Some(Value::U128(v))  => json!(v.to_string()),
            Some(Value::U256(v))  => json!(v.to_string()),
            Some(Value::Bool(b))  => json!(b),
            Some(Value::Bytes(b)) => json!(format!("0x{}", hex::encode(b))),
            Some(Value::Map(m))   => {
                let obj: serde_json::Map<String,serde_json::Value> = m.iter().map(|(k,v)| {
                    // Map keys are raw bytes (UMA = 32-byte hash, integers = BE bytes).
                    // Hex-encode so binary keys display cleanly as 0x... strings.
                    let key_s = if k.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_') {
                        String::from_utf8_lossy(k).to_string()  // plain ASCII key — keep as-is
                    } else {
                        format!("0x{}", hex::encode(k))          // binary key — hex
                    };
                    let val_j = match v {
                        Value::I32(n)   => json!(n),
                        Value::U128(n)  => json!(n.to_string()),
                        Value::U256(n)  => json!(n.to_string()),
                        Value::Bool(b)  => json!(b),
                        Value::Bytes(b) => json!(format!("0x{}", hex::encode(b))),
                        _               => json!(null),
                    };
                    (key_s, val_j)
                }).collect();
                serde_json::Value::Object(obj)
            }
            Some(Value::Set(s))   => {
                let arr: Vec<serde_json::Value> = s.iter()
                    .map(|k| {
                        if k.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_') {
                            json!(String::from_utf8_lossy(k).to_string())
                        } else {
                            json!(format!("0x{}", hex::encode(k)))
                        }
                    })
                    .collect();
                json!(arr)
            }
            None => json!(0),
            _    => json!(null),
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
    let sessions:   SessionStore   = Arc::new(Mutex::new(HashMap::new()));
    let workspaces: WorkspaceStore = Arc::new(Mutex::new(HashMap::new()));
    let rate_limiter  = build_rate_limiter();
    let compiler_key  = Arc::new(load_compiler_key());
    // Rev-2: per-restart HMAC secret for source-nonce derivation.
    // SYNQ_SOURCE_NONCE_SECRET env var (64-char hex) for persistence across restarts.
    // Falls back to keccak256 of compiler key bytes, or CSPRNG if ephemeral.
    let source_nonce_secret: Vec<u8> = std::env::var("SYNQ_SOURCE_NONCE_SECRET")
        .ok()
        .and_then(|s| hex_decode_strict(s.trim()).ok())
        .unwrap_or_else(|| {
            match compiler_key.as_ref() {
                CompilerKey::Persistent { private_key, .. } => {
                    use sha3::{Digest, Keccak256};
                    Keccak256::digest(&private_key[..32]).to_vec()
                }
                CompilerKey::Ephemeral => new_session_id().into_bytes(),
            }
        });
    let store = AppState { sessions, workspaces, rate_limiter, compiler_key, source_nonce_secret };

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
        .route("/source-nonce",      post(source_nonce_handler))
        .route("/compile/sign-source", post(sign_source_handler))
        .route("/session/new",       post(session_new_handler))
        .route("/session/run",       post(session_run_handler))
        .route("/session/:id/nonce", get(session_nonce_handler))
        .route("/session/:id",       delete(session_delete_handler))
        .route("/workspace/new",     post(workspace_new_handler))
        .route("/workspace/:id",     get(workspace_info_handler).delete(workspace_delete_handler))
        .route("/workspace/:id/join",   post(workspace_join_handler))
        .route("/workspace/:id/remove", post(workspace_remove_handler))
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