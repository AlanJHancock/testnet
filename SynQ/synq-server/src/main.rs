//! synq-server — HTTP compile + run server for the SynQ IDE
//!
//! POST /compile        — compile SynQ source, sign with ML-DSA-87 (V3 account-domain)
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
//! PR-G: persistent ML-DSA-87 compiler-attestation key (V3 account-domain):
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
use synq_vm::verify;

mod wasm_compiler;
mod sqb;

// ─── Security constants ───────────────────────────────────────────────────────

const SIGNING_ALGORITHM: &str  = "ML-DSA-87";  // V3: account-domain uses ML-DSA-87 (not consensus ML-DSA-65)

// ── V3 Signature domain tags ──────────────────────────────────────────────────
// V3 requires domain-separated signatures for deploy, call, governance, and attest.
// Each domain tag is prepended to the signed payload to prevent cross-domain replay.
const V3_DOMAIN_DEPLOY:     &str = "SYNQ-DEPLOY-v3";
const V3_DOMAIN_CALL:       &str = "SYNQ-CALL-v3";
const V3_DOMAIN_GOVERNANCE: &str = "SYNQ-GOVERNANCE-v3";
const V3_DOMAIN_ATTEST:     &str = "SYNQ-ATTEST-v3";

/// Derive a V3 governance scope hash (SHA3-256) from a scope name.
/// This must match the compiler's codegen for @governance(ScopeName).
fn governance_scope_hash(scope_name: &str) -> [u8; 32] {
    use sha3::Digest;
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(b"SYNQ-GOVERNANCE-SCOPE-v1:");
    hasher.update(scope_name.as_bytes());
    hasher.finalize().into()
}

/// Derive a V3 authority scope hash (SHA3-256) from a scope name.
/// This must match the compiler's codegen for @authority(ScopeName).
fn authority_scope_hash(scope_name: &str) -> [u8; 32] {
    use sha3::Digest;
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(b"SYNQ-AUTHORITY-SCOPE-v1:");
    hasher.update(scope_name.as_bytes());
    hasher.finalize().into()
}

// V3 chain parameters
const V3_CHAIN_ID: u64 = 1266;
const V3_NETWORK_ID: &str = "synergy-testnet-v3";


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
pub const MAX_SOURCE_BYTES: usize  = 64 * 1024;
const MAX_BODY_BYTES: usize    = 128 * 1024;

// ─── Session store ────────────────────────────────────────────────────────────

/// Master switch for PQC fuel reporting in API responses.
/// Set to `false` to suppress all fuel fields from NewSessionResponse
/// and RunResponse — the fields use `skip_serializing_if` so they
/// vanish from the JSON entirely when this is disabled.
const FUEL_REPORTING: bool = true;

struct Session {
    vm:              QuantumVM,
    max_steps:       usize,
    last_used:       Instant,
    state_vars:      Vec<(String, u32)>,
    contract_name:   Option<String>,      // from compile — used to derive EIP-712 verifyingContract
    workspace_id:    Option<String>,      // workspace this session belongs to (if any)
    pending_nonce:   Option<String>,      // server-issued one-time nonce, cleared after use
    used_nonces:     std::collections::HashSet<String>,  // consumed nonces (replay guard)
    /// Declared return type per function ("bool", "str", "u256" etc.) — used
    /// to coerce I32(0) from uninitialised slots into the correct JSON form.
    fn_return_types: std::collections::HashMap<String, String>,
    /// Governance scope per function name (from @governance attribute).
    /// When present, the server embeds the governance scope hash in the
    /// AuthorityEnvelope and uses the GOVERNANCE domain tag.
    governance_scopes: std::collections::HashMap<String, String>,
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
pub struct AppState {
    sessions:      SessionStore,
    workspaces:    WorkspaceStore,
    rate_limiter:  StdArc<IpLimiter>,
    compiler_key:  Arc<CompilerKey>,
    source_nonce_secret: Vec<u8>,  // Rev-2: HMAC key for source-nonce derivation
    wasm_runtime:     Option<Arc<wasm_compiler::WasmRuntime>>,
}

/// PR-F Item 2: check the per-IP rate limit.
/// Returns Ok(()) if the request is within quota, Err(Response) with 429 + Retry-After otherwise.
/// Returns Ok(()) if within quota, Err(wait_secs) if rate-limited.
pub fn check_rate_limit(limiter: &IpLimiter, ip: IpAddr) -> Result<(), u64> {
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
    // V3: chain ID 1266 (synergy-testnet-v3). Was 1337 (legacy devnet).
    let chain_id     = pad32(&V3_CHAIN_ID.to_be_bytes());
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
    // V3: domain name includes network ID for cross-domain replay resistance.
    let domain_name = format!("SynQ · {} · {}", contract_name, V3_NETWORK_ID);
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

/// V3 ContractCall struct hash with domain tag for cross-domain replay resistance.
/// struct ContractCall(string callSignature, string sessionId, string nonce, string domainTag)
/// domainTag = "SYNQ-CALL-v3" — binds the signature to the V3 call domain.
fn eip712_hash_contract_call_v3(call_sig: &str, session_id: &str, nonce: &str, domain_tag: &str) -> [u8; 32] {
    let type_hash = keccak256_str(
        "ContractCall(string callSignature,string sessionId,string nonce,string domainTag)"
    );
    let mut enc = [0u8; 160];
    enc[..32].copy_from_slice(&type_hash);
    enc[32..64].copy_from_slice(&keccak256_str(call_sig));
    enc[64..96].copy_from_slice(&keccak256_str(session_id));
    enc[96..128].copy_from_slice(&keccak256_str(nonce));
    enc[128..160].copy_from_slice(&keccak256_str(domain_tag));
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
        Value::Bool(b)  => json!({"type": "Bool", "value": if *b { "true" } else { "false" }}),
        Value::Bytes(b) => {
            if let Ok(s) = std::str::from_utf8(b) { json!({"type": "String", "value": s}) }
            else { json!({"type": "Bytes", "value": hex_encode(b)}) }
        },
        Value::Str(s) => json!({"type": "String", "value": s}),
        Value::Map(_)        => json!({"type": "Map",   "value": "[map]"}),
        Value::Set(_)        => json!({"type": "Set",   "value": "[set]"}),
        Value::Tuple(elems)  => json!({"type": "Tuple",  "value": elems.iter().map(value_to_json).collect::<Vec<_>>()}),
        Value::SynqOption(None)     => json!({"type": "Option", "value": null}),
        Value::SynqOption(Some(v))  => json!({"type": "Option", "value": value_to_json(v)}),
        Value::SynqResult(true, v)  => json!({"type": "Result", "variant": "Ok",  "value": value_to_json(v)}),
        Value::SynqResult(false, v) => json!({"type": "Result", "variant": "Err", "value": value_to_json(v)}),
    }
}

/// Type-aware JSON serialisation.  When the VM returns I32(0) for an
/// uninitialised bool/str slot we coerce it using the declared return type.
fn value_to_json_typed(v: &Value, ret_type: Option<&str>) -> serde_json::Value {
    match (v, ret_type) {
        // Uninitialised bool slot: I32(0) → false
        (Value::I32(0), Some("bool")) =>
            json!({"type": "Bool", "value": "false"}),
        // Uninitialised str slot: I32(0) → ""
        (Value::I32(0), Some("str")) =>
            json!({"type": "String", "value": ""}),
        // Promote I32(n)→Bool when declared bool and n==1 (shouldn't happen but be safe)
        (Value::I32(1), Some("bool")) =>
            json!({"type": "Bool", "value": "true"}),
        _ => value_to_json(v),
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
        Value::Map(_)        => "[map]".to_string(),
        Value::Set(_)        => "[set]".to_string(),
        Value::Str(s)        => format!("{:?}", s),
        Value::Tuple(elems)  => format!("({})", elems.iter().map(value_display).collect::<Vec<_>>().join(", ")),
        Value::SynqOption(None)     => "None".to_string(),
        Value::SynqOption(Some(v))  => format!("Some({})", value_display(v)),
        Value::SynqResult(true, v)  => format!("Ok({})", value_display(v)),
        Value::SynqResult(false, v) => format!("Err({})", value_display(v)),
    }
}

fn parse_arg(v: &serde_json::Value) -> Result<Value, String> { parse_arg_typed(v, "") }
fn parse_arg_typed(v: &serde_json::Value, ty_hint: &str) -> Result<Value, String> {
    match v {
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                // Negative → signed Value; positive small → I32; large → U128
                if i < 0 { return Ok(if i >= i32::MIN as i64 { Value::I32(i as i32) } else { Value::I64(i) }); }
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
            // Empty string → UTF-8 string param (not numeric zero)
            if s.is_empty() { return Ok(Value::Bytes(vec![])); }
            // If the caller declared this param as str/string, treat any value as bytes
            // even if it looks numeric — "33" as a label should be Bytes, not I32.
            if ty_hint == "str" || ty_hint == "string" {
                return Ok(Value::Bytes(s.as_bytes().to_vec()));
            }
            // If the caller declared this param as bytes, decode hex string to binary.
            // Accepts both "0x..." prefixed and bare hex strings.
            if ty_hint == "bytes" {
                let hex_str = if s.starts_with("0x") || s.starts_with("0X") { &s[2..] } else { s };
                return match hex::decode(hex_str) {
                    Ok(b)  => Ok(Value::Bytes(b)),
                    Err(_) => Err(format!("Invalid hex bytes: {}", &hex_str[..hex_str.len().min(40)])),
                };
            }
            if s.starts_with('-') {
                if let Ok(i) = s.parse::<i64>() {
                    return Ok(if i >= i32::MIN as i64 { Value::I32(i as i32) } else { Value::I64(i) });
                }
                return Err(format!("Cannot parse negative value: {}", s));
            }
            if let Ok(u) = s.parse::<u128>() {
                return Ok(if u <= i32::MAX as u128 { Value::I32(u as i32) } else { Value::U128(u) });
            }
            // Hex addresses (0x...) → Bytes
            if s.starts_with("0x") || s.starts_with("0X") {
                let hex = if s.len() > 2 { &s[2..] } else { "" };
                // Pad to 32 bytes (64 hex chars) for addresses
                let padded = format!("{:0>64}", hex);
                return match hex::decode(&padded) {
                    Ok(b)  => Ok(Value::Bytes(b)),
                    Err(_) => Err(format!("Invalid hex address: {}", s)),
                };
            }
            // Try U256 for large decimal literals
            match s.parse::<U256>() {
                Ok(v)  => Ok(Value::U256(v)),
                // Non-numeric, non-hex → treat as UTF-8 string (str param)
                Err(_) => Ok(Value::Bytes(s.as_bytes().to_vec())),
            }
        }
        other => Err(format!("Expected number or string, got {}", other)),
    }
}

// ─── POST /compile ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CompileRequest {
    source: String,
    /// extern_contracts reported by the WASM compiler — cross-checked server-side
    /// to detect in-browser memory tampering of compile output.
    #[serde(default)]
    wasm_extern_contracts: Option<Vec<String>>,
}

#[derive(serde::Serialize, Clone)]
struct ParamMeta {
    name: String,
    ty:   String,
}
#[derive(serde::Serialize, Clone)]
struct FunctionMeta {
    name:           String,
    params:         Vec<ParamMeta>,
    has_return:     bool,
    return_type:    Option<String>,
    /// State precondition expressions (raw strings from `requires <expr>` clauses)
    requires_state: Vec<String>,
    /// State variables this function modifies (from `modifies` clause)
    modifies:       Vec<String>,
    /// Governance scope name if @governance(ScopeName) is present
    governance_scope: Option<String>,
}

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
    functions:          Vec<FunctionMeta>,
    state_var_types:    std::collections::HashMap<String, String>,
    /// V3 manifest metadata
    manifest:           Option<ManifestInfo>,
    /// Full SSA IR dump (one string per function, block-by-block)
    ir_dump:            Vec<String>,
    /// SQB binary artifact (base64-encoded) — canonical hash-bound format
    sqb:               Option<String>,
}

/// V3 artifact manifest — matches the Testnet-v3 schema-v2 manifest structure.
#[derive(Debug, Clone, serde::Serialize)]
struct ManifestInfo {
    /// Account-domain signature algorithm (ML-DSA-87 for V3)
    required_signature_algorithm: String,
    /// Consensus signature algorithm (ML-DSA-65 for V3)
    consensus_signature_algorithm: String,
    /// Chain ID (1266 for Testnet-v3)
    chain_id: u64,
    /// Network ID
    network_id: String,
    /// SHA-256 of the bytecode (artifact hash)
    artifact_hash: String,
    /// SHA-256 of the source (for provenance)
    source_hash: String,
    /// Trust model (compiler-attested)
    trust_model: String,
    /// Compiler key fingerprint
    key_id: String,
    /// Signature domain tags
    signature_domains: SignatureDomains,
    /// ML-DSA-87 signature over the manifest hash (hex)
    manifest_signature: Option<String>,
    /// Compiler public key used to sign (hex)
    compiler_public_key: Option<String>,
    /// Function ABI entries
    functions: Vec<ManifestFunction>,
    /// State variable layout
    state_vars: Vec<ManifestStateVar>,
    /// Governance scopes declared in the contract
    governance_scopes: Vec<String>,
    /// Authority scopes declared in the contract
    authority_scopes: Vec<String>,
}

/// Function ABI entry in the V3 manifest
#[derive(Debug, Clone, serde::Serialize)]
struct ManifestFunction {
    name: String,
    params: Vec<ManifestParam>,
    return_type: Option<String>,
    is_public: bool,
    governance_scope: Option<String>,
    authority_scope: Option<String>,
    effects: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ManifestParam {
    name: String,
    ty: String,
}

/// State variable layout entry
#[derive(Debug, Clone, serde::Serialize)]
struct ManifestStateVar {
    name: String,
    ty: String,
    slot: u32,
}

/// Domain-separated signature tags — V3 requires distinct domains for deploy, call, and governance.
#[derive(Debug, Clone, serde::Serialize)]
struct SignatureDomains {
    deploy: String,
    call: String,
    governance: String,
    attest: String,
}

/// Convert AST Type to a canonical string name for IDE use
fn type_name(ty: &synq_compiler::ast::Type) -> String {
    use synq_compiler::ast::Type::*;
    match ty {
        Str                  => "str".to_string(),
        Bool                 => "bool".to_string(),
        Address              => "address".to_string(),
        Bytes                => "bytes".to_string(),
        UInt8  | UInt16 | UInt32 | UInt64 | UInt128 | UInt256 => "u256".to_string(),
        Int8   | Int16 | Int32 | Int64 | Int128 | Int256      => "i256".to_string(),
        DilithiumPublicKey   => "dilithium_pubkey".to_string(),
        FalconPublicKey       => "falcon_pubkey".to_string(),
        KyberPublicKey        => "kyber_pubkey".to_string(),
        DilithiumSignature    => "dilithium_sig".to_string(),
        FalconSignature       => "falcon_sig".to_string(),
        Hash32                => "hash32".to_string(),
        Hash64                => "hash64".to_string(),
        UMAIdentity           => "uma_identity".to_string(),
        Height                => "height".to_string(),
        BytesN(n)             => format!("bytes{}", n),
        Asset(inner)          => format!("Asset<{}>", type_name(inner)),
        Option(inner)         => format!("option<{}>", type_name(inner)),
        Result(ok, err)       => format!("result<{}, {}>", type_name(ok), type_name(err)),
        Tuple(types)          => {
            let parts: Vec<String> = types.iter().map(type_name).collect();
            format!("({})", parts.join(", "))
        }
        Mapping(k, v)         => format!("mapping<{}, {}>", type_name(k), type_name(v)),
        Array(inner)          => format!("[{}]", type_name(inner)),
        Named(name)           => name.clone(),
        ModelId               => "model_id".to_string(),
    }
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
            functions:        Vec::new(),
            state_var_types:  std::collections::HashMap::new(),
            manifest:           None,
            ir_dump:            vec![],
            sqb:               None,
        }));
    }
    if req.source.len() > MAX_SOURCE_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE, RespJson(CompileResponse {
            success: false, bytecode: None, signature_sidecar: None, state_vars: vec![], contract_name: None, contract_address: None, extern_contracts: vec![],
            errors: vec![format!("Source too large: {} bytes (max {})", req.source.len(), MAX_SOURCE_BYTES)],
            warnings: vec![],
            functions:        Vec::new(),
            state_var_types:  std::collections::HashMap::new(),
            manifest:           None,
            ir_dump:            vec![],
            sqb:               None,
        }));
    }

    // Transpile to Solidity for EVM deployment (SXCP)
    let solidity_source = {
        let parsed = synq_compiler::parser::parse(&req.source).ok();
        let contract_def = parsed.as_ref().and_then(|units| {
            units.iter().find_map(|u| {
                if let synq_compiler::ast::SourceUnit::Contract(c) = u {
                    Some(c.clone())
                } else {
                    None
                }
            })
        });
        match contract_def {
            Some(c) => {
                let sol = synq_compiler::transpile_solidity::transpile_to_solidity(&c);
                if !sol.is_empty() { Some(sol) } else { None }
            }
            None => None,
        }
    };

    let ast = match synq_compiler::parser::parse(&req.source) {
        Ok(a)  => a,
        Err(e) => return (StatusCode::OK, RespJson(CompileResponse {
            success: false, bytecode: None, signature_sidecar: None, state_vars: vec![], contract_name: None, contract_address: None, extern_contracts: vec![],
            errors: vec![format!("Parse error: {}", e)], warnings: vec![],
            functions:        Vec::new(),
            state_var_types:  std::collections::HashMap::new(),
            manifest:           None,
            ir_dump:            vec![],
            sqb:               None,
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

    // ── Primary compilation path: SSA IR backend (sole path, no fallback) ───
    // compile_ir() handles parse -> semantic checks -> IR build -> optimization
    // passes (including mem2reg/phi insertion) -> analysis -> lowering to QVM
    // bytecode, returning a CompileResult with bytecode, state_vars, warnings,
    // extern_contracts, and ir_dump.
    let compile_result = match synq_compiler::compile_ir(&req.source) {
        Ok(r)  => r,
        Err(e) => return (StatusCode::OK, RespJson(CompileResponse {
            success: false, bytecode: None, signature_sidecar: None, state_vars: vec![], contract_name: None, contract_address: None, extern_contracts: vec![],
            errors: vec![format!("Compile error: {}", e)], warnings: vec![],
            functions:        Vec::new(),
            state_var_types:  std::collections::HashMap::new(),
            manifest:           None,
            ir_dump:            vec![],
            sqb:               None,
        })),
    };
    let bytecode = compile_result.bytecode;
    let state_vars = compile_result.state_vars;
    // Merge IR backend warnings (pass reports, analysis stats) into compile warnings
    compile_warnings.extend(compile_result.warnings);

    // Layer 1 + Layer 2 verification — belt-and-suspenders check on our own codegen output
    match synq_vm::verify::verify(&bytecode) {
        Ok(report) => {
            eprintln!("[VERIFY] {} instructions, {} jumps, {} calls in {} bytes",
                report.instruction_count, report.jump_targets.len(), report.call_targets.len(), report.code_size);
            // Always surface a verification summary so the IDE shows verification ran
            if report.stack_warnings.is_empty() {
                compile_warnings.push(format!(
                    "[VERIFY] Layer 1 passed (structural) + Layer 2 passed (stack safety) | {} instructions, {} jumps, {} calls, {} bytes code",
                    report.instruction_count, report.jump_targets.len(), report.call_targets.len(), report.code_size,
                ));
            } else {
                compile_warnings.push(format!(
                    "[VERIFY] Layer 1 passed | Layer 2: {} stack warning(s) — see below",
                    report.stack_warnings.len(),
                ));
                for sw in &report.stack_warnings {
                    eprintln!("[VERIFY] stack warning: {}", sw);
                    compile_warnings.push(format!("Stack safety: {}", sw));
                }
            }
        }
        Err(e) => {
            compile_warnings.push(format!("Bytecode verification FAILED: {}", e));
        }
    }

    // IR dump comes from compile_ir() — no separate build needed
    let ir_dump: Vec<String> = compile_result.ir_dump;

    // ── SSA IR analysis already done by compile_ir() ──────────────────────
    // Pass reports and analysis stats are merged into compile_warnings above.


    // PR-G: use persistent compiler key when available, ephemeral otherwise
    let pqc = PQCCompiler::new(PQCSecurityLevel::Enhanced);
    let sidecar = match state.compiler_key.as_ref() {
        CompilerKey::Persistent { private_key, public_key, key_id } => {
            let sig = match pqc.sign_message(private_key, &bytecode, SIGNING_ALGORITHM) {
                Ok(s)  => s,
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, RespJson(CompileResponse {
                    success: false, bytecode: None, signature_sidecar: None, state_vars: vec![], contract_name: None, contract_address: None, extern_contracts: vec![],
                    errors: vec![format!("PQC signing failed: {}", e)], warnings: vec![],
                    functions:        Vec::new(), state_var_types: std::collections::HashMap::new(),
            manifest:           None,
            ir_dump:            vec![],
            sqb:               None,
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
                    functions:        Vec::new(), state_var_types: std::collections::HashMap::new(),
                    manifest:           None,
                    ir_dump:            vec![],
            sqb:               None,
                })),
            };
            let sig = match pqc.sign_message(&keypair.private_key, &bytecode, SIGNING_ALGORITHM) {
                Ok(s)  => s,
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, RespJson(CompileResponse {
                    success: false, bytecode: None, signature_sidecar: None, state_vars: vec![], contract_name: None, contract_address: None, extern_contracts: vec![],
                    errors: vec![format!("PQC signing failed: {}", e)], warnings: vec![],
                    functions:        Vec::new(), state_var_types: std::collections::HashMap::new(),
            manifest:           None,
            ir_dump:            vec![],
            sqb:               None,
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

    // Build function metadata for IDE param types
    let functions: Vec<FunctionMeta> = ast.iter()
        .find_map(|unit| match unit {
            synq_compiler::ast::SourceUnit::Contract(c) if contract_name.as_deref() == Some(c.name.as_str()) => {
                Some(c.parts.iter().filter_map(|p| match p {
                    synq_compiler::ast::ContractPart::Function(f) => Some(FunctionMeta {
                        name:           f.name.clone(),
                        params:         f.params.iter().map(|p| ParamMeta {
                            name: p.name.clone(),
                            ty:   type_name(&p.ty),
                        }).collect(),
                        has_return:     f.returns.is_some(),
                        return_type:    f.returns.as_ref().map(type_name),
                        requires_state: f.requires_state.clone(),
                    governance_scope: f.attributes.iter().find_map(|a|
                        if let synq_compiler::ast::Attribute::Governance(scope) = a {
                            Some(scope.clone())
                        } else { None }
                    ),
                        modifies:       f.modifies.clone(),
                    }),
                    _ => None,
                }).collect())
            },
            _ => None,
        })
        .unwrap_or_default();

    // Clone state_vars for manifest use (it gets moved into CompileResponse)
    let manifest_state_vars = state_vars.clone();

    // Clone values needed by the SQB encoder (they get moved into CompileResponse fields)
    let sqb_functions = functions.clone();
    let sqb_state_vars = state_vars.clone();
    let sqb_ir_dump = ir_dump.clone();
    let sqb_bytecode = bytecode.clone();
    let sqb_source = req.source.clone();

    (StatusCode::OK, RespJson(CompileResponse {
        success: true,
        bytecode: Some(format!("0x{}", hex::encode(&bytecode))),
        signature_sidecar: Some(sidecar),
        state_vars,
        state_var_types: {
            let mut svm: std::collections::HashMap<String,String> = std::collections::HashMap::new();
            for unit in &ast {
                if let synq_compiler::ast::SourceUnit::Contract(con) = unit {
                    for part in &con.parts {
                        if let synq_compiler::ast::ContractPart::StateVariable(sv) = part {
                            svm.insert(sv.name.clone(), type_name(&sv.ty));
                        }
                    }
                }
            }
            svm
        },
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
                        functions:        Vec::new(), state_var_types: std::collections::HashMap::new(),
            manifest:           None,
            ir_dump:            vec![],
            sqb:               None,
                        }));
                }
            }
            ec
        },
        errors: vec![], warnings: compile_warnings,
        functions,
        manifest: {
            use sha3::{Digest, Sha3_256};
            let artifact_hash = hex::encode(Sha3_256::digest(&bytecode));
            let source_hash    = hex::encode(Sha3_256::digest(req.source.as_bytes()));
            let key_id = match state.compiler_key.as_ref() {
                CompilerKey::Persistent { key_id, .. } => key_id.clone(),
                CompilerKey::Ephemeral                   => "ephemeral".to_string(),
            };
            // Build function ABI entries for manifest
            let manifest_fns: Vec<ManifestFunction> = {
                let mut fns = Vec::new();
                for unit in &ast {
                    if let synq_compiler::ast::SourceUnit::Contract(c) = unit {
                        for part in &c.parts {
                            if let synq_compiler::ast::ContractPart::Function(f) = part {
                                let is_public = f.attributes.iter().any(|a| matches!(a, synq_compiler::ast::Attribute::Public));
                                let gov_scope = f.attributes.iter().find_map(|a|
                                    if let synq_compiler::ast::Attribute::Governance(s) = a { Some(s.clone()) } else { None });
                                let auth_scope = f.attributes.iter().find_map(|a|
                                    if let synq_compiler::ast::Attribute::Authority(s) = a { Some(s.clone()) } else { None });
                                let effects = f.attributes.iter().find_map(|a|
                                    if let synq_compiler::ast::Attribute::Effects(v) = a { Some(v.clone()) } else { None })
                                    .unwrap_or_default();
                                fns.push(ManifestFunction {
                                    name: f.name.clone(),
                                    params: f.params.iter().map(|p| ManifestParam {
                                        name: p.name.clone(), ty: type_name(&p.ty)
                                    }).collect(),
                                    return_type: f.returns.as_ref().map(type_name),
                                    is_public,
                                    governance_scope: gov_scope,
                                    authority_scope: auth_scope,
                                    effects,
                                });
                            }
                        }
                    }
                }
                fns
            };

            // Collect governance + authority scopes
            let mut gov_scopes: Vec<String> = Vec::new();
            let mut auth_scopes: Vec<String> = Vec::new();
            for unit in &ast {
                if let synq_compiler::ast::SourceUnit::Contract(c) = unit {
                    for part in &c.parts {
                        if let synq_compiler::ast::ContractPart::Function(f) = part {
                            for attr in &f.attributes {
                                if let synq_compiler::ast::Attribute::Governance(s) = attr {
                                    if !gov_scopes.contains(s) { gov_scopes.push(s.clone()); }
                                }
                                if let synq_compiler::ast::Attribute::Authority(s) = attr {
                                    if !auth_scopes.contains(s) { auth_scopes.push(s.clone()); }
                                }
                            }
                        }
                    }
                }
            }

            // Build state variable layout for manifest
            let manifest_state: Vec<ManifestStateVar> = manifest_state_vars.iter().map(|(name, slot)| {
                let ty = {
                    let mut t = "u256".to_string();
                    for unit in &ast {
                        if let synq_compiler::ast::SourceUnit::Contract(c) = unit {
                            for part in &c.parts {
                                if let synq_compiler::ast::ContractPart::StateVariable(sv) = part {
                                    if sv.name == *name { t = type_name(&sv.ty); }
                                }
                            }
                        }
                    }
                    t
                };
                ManifestStateVar { name: name.clone(), ty, slot: *slot }
            }).collect();

            // Sign the manifest hash with ML-DSA-87
            let manifest_json = serde_json::json!({
                "artifact_hash": artifact_hash,
                "source_hash": source_hash,
                "chain_id": V3_CHAIN_ID,
                "network_id": V3_NETWORK_ID,
                "functions": manifest_fns,
                "state_vars": manifest_state,
                "governance_scopes": gov_scopes,
                "authority_scopes": auth_scopes,
            });
            let manifest_bytes = serde_json::to_vec(&manifest_json).unwrap_or_default();
            let manifest_hash = {
                use sha3::Digest;
                sha3::Sha3_256::digest(&manifest_bytes)
            };

            let (manifest_sig, manifest_pubkey) = match state.compiler_key.as_ref() {
                CompilerKey::Persistent { private_key, public_key, .. } => {
                    let pqc = synq_compiler::PQCCompiler::new(PQCSecurityLevel::Enhanced);
                    match pqc.sign_message(private_key, &manifest_hash, SIGNING_ALGORITHM) {
                        Ok(sig) => (Some(hex_encode(&sig.signature)), Some(hex_encode(public_key))),
                        Err(_) => (None, None),
                    }
                }
                CompilerKey::Ephemeral => {
                    let pqc = synq_compiler::PQCCompiler::new(PQCSecurityLevel::Enhanced);
                    let keypair = match pqc.generate_keypair(SIGNING_ALGORITHM) {
                        Ok(k) => (k.private_key, k.public_key),
                        Err(_) => (vec![], vec![]),
                    };
                    match pqc.sign_message(&keypair.0, &manifest_hash, SIGNING_ALGORITHM) {
                        Ok(sig) => (Some(hex_encode(&sig.signature)), Some(hex_encode(&keypair.1))),
                        Err(_) => (None, None),
                    }
                }
            };

            Some(ManifestInfo {
                required_signature_algorithm: SIGNING_ALGORITHM.to_string(),
                consensus_signature_algorithm: "ML-DSA-65".to_string(),
                chain_id: V3_CHAIN_ID,
                network_id: V3_NETWORK_ID.to_string(),
                artifact_hash,
                source_hash,
                trust_model: "compiler-attested".to_string(),
                key_id,
                signature_domains: SignatureDomains {
                    deploy:     V3_DOMAIN_DEPLOY.to_string(),
                    call:       V3_DOMAIN_CALL.to_string(),
                    governance: V3_DOMAIN_GOVERNANCE.to_string(),
                    attest:     V3_DOMAIN_ATTEST.to_string(),
                },
                manifest_signature: manifest_sig,
                compiler_public_key: manifest_pubkey,
                functions: manifest_fns,
                state_vars: manifest_state,
                governance_scopes: gov_scopes,
                authority_scopes: auth_scopes,
            })
        },
        ir_dump,
        sqb: {
            // ── SQB Binary Artifact Generation (ACTS-VM-001..011) ─────────
            // Build a canonical, hash-bound .sqb artifact from the compiled
            // bytecode, ABI, manifest, and IR dump. All section hashes are
            // bound into the artifact root (SHA3-256).
            use base64::{Engine, prelude::BASE64_STANDARD};
            use sha3::{Digest, Sha3_256};

            // CODE section: raw QVM bytecode
            let sqb_code = sqb_bytecode.clone();

            // ABI section: function metadata as JSON (self-contained)
            let mut ec: Vec<String> = Vec::new();
            for unit in &ast {
                if let synq_compiler::ast::SourceUnit::Contract(c) = unit {
                    for part in &c.parts {
                        if let synq_compiler::ast::ContractPart::Function(fn_) = part {
                            for stmt in &fn_.body.statements {
                                if let synq_compiler::ast::Statement::ExternCall { contract, .. } = stmt {
                                    if !ec.contains(contract) { ec.push(contract.clone()); }
                                }
                            }
                        }
                    }
                }
            }
            let abi_json = serde_json::json!({
                "contract_name": &contract_name,
                "functions": sqb_functions.iter().map(|f| serde_json::json!({
                    "name": f.name,
                    "params": f.params,
                    "return_type": f.return_type,
                    "has_return": f.has_return,
                    "governance_scope": f.governance_scope,
                    "requires_state": f.requires_state,
                    "modifies": f.modifies,
                })).collect::<Vec<_>>(),
                "extern_contracts": &ec,
            });
            let abi_bytes = serde_json::to_vec(&abi_json).unwrap_or_default();

            // IR section: binary SIR1 format (compact, machine-readable)
            let ir_bytes = compile_result.ir_binary.clone();

            // META section: compiler metadata
            let meta_json = serde_json::json!({
                "compiler_version": "0.9",
                "chain_id": V3_CHAIN_ID,
                "network_id": V3_NETWORK_ID,
                "contract_name": &contract_name,
                "timestamp": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs()).unwrap_or(0),
                "acts_vm_conformance": "ACTS-VM-001..011",
            });
            let meta_bytes = serde_json::to_vec(&meta_json).unwrap_or_default();

            // EFFECTS section: per-function read/write/emit declarations
            let effects_json = serde_json::json!({
                "functions": sqb_functions.iter().map(|f| serde_json::json!({
                    "name": f.name,
                    "requires_state": f.requires_state,
                    "modifies": f.modifies,
                })).collect::<Vec<_>>(),
            });
            let effects_bytes = serde_json::to_vec(&effects_json).unwrap_or_default();

            // STATE_LAYOUT section: canonical state variable slot mapping
            let state_layout_json = serde_json::json!({
                "state_vars": sqb_state_vars.iter().map(|(name, slot)| {
                    let ty = {
                        let mut t = "u256".to_string();
                        for unit in &ast {
                            if let synq_compiler::ast::SourceUnit::Contract(c) = unit {
                                for part in &c.parts {
                                    if let synq_compiler::ast::ContractPart::StateVariable(sv) = part {
                                        if sv.name == *name { t = type_name(&sv.ty); }
                                    }
                                }
                            }
                        }
                        serde_json::json!({"name": name, "ty": t, "slot": slot})
                    };
                    ty
                }).collect::<Vec<_>>(),
            });
            let state_layout_bytes = serde_json::to_vec(&state_layout_json).unwrap_or_default();


            // Compute sections_hash = SHA3-256(concat of all non-manifest section hashes)
            // This covers CODE, ABI, IR, EFFECTS, STATE_LAYOUT, META — everything except
            // the manifest itself. Embedded in the manifest so the manifest signature
            // covers ALL sections, not just bytecode (ACTS-VM-009 extended).
            let source_bytes = req.source.clone().into_bytes();
            let solidity_bytes = solidity_source.as_ref().map(|s| s.as_bytes().to_vec()).unwrap_or_default();
            let sections_hash = {
                let code_h = Sha3_256::digest(&sqb_code);
                let abi_h = Sha3_256::digest(&abi_bytes);
                let ir_h = Sha3_256::digest(&ir_bytes);
                let effects_h = Sha3_256::digest(&effects_bytes);
                let state_layout_h = Sha3_256::digest(&state_layout_bytes);
                let meta_h = Sha3_256::digest(&meta_bytes);
                let source_h = Sha3_256::digest(&source_bytes);
                let mut concat = Vec::new();
                concat.extend_from_slice(&code_h);
                concat.extend_from_slice(&abi_h);
                concat.extend_from_slice(&ir_h);
                concat.extend_from_slice(&effects_h);
                concat.extend_from_slice(&state_layout_h);
                concat.extend_from_slice(&meta_h);
                concat.extend_from_slice(&source_h);
                let sol_h = Sha3_256::digest(&solidity_bytes);
                concat.extend_from_slice(&sol_h);
                hex::encode(Sha3_256::digest(&concat))
            };

            // MANIFEST section: V3 manifest JSON (self-contained)
            let artifact_hash = hex::encode(Sha3_256::digest(&bytecode));
            let source_hash = hex::encode(Sha3_256::digest(sqb_source.as_bytes()));
            // Build SQB manifest JSON — self-contained with signature fields
            // so L3 verification works from the SQB artifact alone.
            let sqb_key_id = match state.compiler_key.as_ref() {
                CompilerKey::Persistent { key_id, .. } => Some(key_id.clone()),
                CompilerKey::Ephemeral => None,
            };
            let sqb_gov_scopes: std::collections::HashMap<String, String> = sqb_functions.iter()
                .filter_map(|f| f.governance_scope.as_ref().map(|s| (f.name.clone(), s.clone())))
                .collect();

            let manifest_json = serde_json::json!({
                "artifact_hash": artifact_hash,
                "sections_hash": sections_hash,
                "source_hash": source_hash,
                "chain_id": V3_CHAIN_ID,
                "network_id": V3_NETWORK_ID,
                "required_signature_algorithm": SIGNING_ALGORITHM,
                "signature_domains": {
                    "deploy": V3_DOMAIN_DEPLOY,
                    "call": V3_DOMAIN_CALL,
                    "governance": V3_DOMAIN_GOVERNANCE,
                    "attest": V3_DOMAIN_ATTEST,
                },
                "functions": sqb_functions.iter().map(|f| serde_json::json!({
                    "name": f.name,
                    "params": f.params,
                    "return_type": f.return_type,
                })).collect::<Vec<_>>(),
                "state_vars": sqb_state_vars.iter().map(|(name, slot)| {
                    let ty = {
                        let mut t = "u256".to_string();
                        for unit in &ast {
                            if let synq_compiler::ast::SourceUnit::Contract(c) = unit {
                                for part in &c.parts {
                                    if let synq_compiler::ast::ContractPart::StateVariable(sv) = part {
                                        if sv.name == *name { t = type_name(&sv.ty); }
                                    }
                                }
                            }
                        }
                        serde_json::json!({"name": name, "ty": t, "slot": slot})
                    };
                    ty
                }).collect::<Vec<_>>(),
                "governance_scopes": sqb_gov_scopes,
                "authority_scopes": {},
            });

            // Compute manifest signature using the SAME canonical 8-field form
            // that verify_manifest() reconstructs — this is critical for L3.
            let canonical_manifest = serde_json::json!({
                "artifact_hash":   manifest_json.get("artifact_hash").cloned().unwrap_or_default(),
                "sections_hash":   manifest_json.get("sections_hash").cloned().unwrap_or_default(),
                "source_hash":     manifest_json.get("source_hash").cloned().unwrap_or_default(),
                "chain_id":        manifest_json.get("chain_id").cloned().unwrap_or_default(),
                "network_id":      manifest_json.get("network_id").cloned().unwrap_or_default(),
                "functions":       manifest_json.get("functions").cloned().unwrap_or_default(),
                "state_vars":      manifest_json.get("state_vars").cloned().unwrap_or_default(),
                "governance_scopes": manifest_json.get("governance_scopes").cloned().unwrap_or_default(),
                "authority_scopes":  manifest_json.get("authority_scopes").cloned().unwrap_or_default(),
            });
            let sqb_manifest_bytes = serde_json::to_vec(&canonical_manifest).unwrap_or_default();
            let sqb_manifest_hash = Sha3_256::digest(&sqb_manifest_bytes);
            let (sqb_mf_sig, sqb_mf_pubkey) = match state.compiler_key.as_ref() {
                CompilerKey::Persistent { private_key, public_key, .. } => {
                    let pqc = PQCCompiler::new(PQCSecurityLevel::Enhanced);
                    match pqc.sign_message(private_key, &sqb_manifest_hash, SIGNING_ALGORITHM) {
                        Ok(sig) => (Some(hex_encode(&sig.signature)), Some(hex_encode(public_key))),
                        Err(_) => (None, None),
                    }
                }
                CompilerKey::Ephemeral => {
                    let pqc = PQCCompiler::new(PQCSecurityLevel::Enhanced);
                    let keypair = match pqc.generate_keypair(SIGNING_ALGORITHM) {
                        Ok(k) => (k.private_key, k.public_key),
                        Err(_) => (vec![], vec![]),
                    };
                    match pqc.sign_message(&keypair.0, &sqb_manifest_hash, SIGNING_ALGORITHM) {
                        Ok(sig) => (Some(hex_encode(&sig.signature)), Some(hex_encode(&keypair.1))),
                        Err(_) => (None, None),
                    }
                }
            };

            // Rebuild manifest JSON with signature fields included
            let manifest_json = serde_json::json!({
                "artifact_hash": artifact_hash,
                "sections_hash": sections_hash,
                "source_hash": source_hash,
                "chain_id": V3_CHAIN_ID,
                "network_id": V3_NETWORK_ID,
                "required_signature_algorithm": SIGNING_ALGORITHM,
                "manifest_signature": sqb_mf_sig,
                "compiler_public_key": sqb_mf_pubkey,
                "key_id": sqb_key_id,
                "signature_domains": {
                    "deploy": V3_DOMAIN_DEPLOY,
                    "call": V3_DOMAIN_CALL,
                    "governance": V3_DOMAIN_GOVERNANCE,
                    "attest": V3_DOMAIN_ATTEST,
                },
                "functions": sqb_functions.iter().map(|f| serde_json::json!({
                    "name": f.name,
                    "params": f.params,
                    "return_type": f.return_type,
                })).collect::<Vec<_>>(),
                "state_vars": sqb_state_vars.iter().map(|(name, slot)| {
                    let ty = {
                        let mut t = "u256".to_string();
                        for unit in &ast {
                            if let synq_compiler::ast::SourceUnit::Contract(c) = unit {
                                for part in &c.parts {
                                    if let synq_compiler::ast::ContractPart::StateVariable(sv) = part {
                                        if sv.name == *name { t = type_name(&sv.ty); }
                                    }
                                }
                            }
                        }
                        serde_json::json!({"name": name, "ty": t, "slot": slot})
                    };
                    ty
                }).collect::<Vec<_>>(),
                "governance_scopes": sqb_gov_scopes,
                "authority_scopes": {},
            });
            let manifest_bytes = serde_json::to_vec(&manifest_json).unwrap_or_default();

            // Sign the artifact root with the compiler's ML-DSA-87 key
            // (v7.0: SQB artifacts are signed at the artifact-root level)
            let sqb_signature = match state.compiler_key.as_ref() {
                CompilerKey::Persistent { private_key, .. } => {
                    // Build the SQB without signature first to compute the root
                    let pre_sig = sqb::SqbEncoder::new(V3_CHAIN_ID as u32)
                        .code(sqb_code.clone())
                        .abi(abi_bytes.clone())
                        .manifest(manifest_bytes.clone())
                        .ir_dump(ir_bytes.clone())
                        .effects(effects_bytes.clone())
                        .state_layout(state_layout_bytes.clone())
                        .meta(meta_bytes.clone())
                        .source(source_bytes.clone())
                        .solidity_source(solidity_bytes.clone())
                        .build();
                    match pre_sig {
                        Ok(bin) => {
                            // Extract artifact root (last 32 bytes before any signature)
                            let root_offset = bin.len() - sqb::HASH_SIZE;
                            let root: [u8; 32] = bin[root_offset..].try_into().unwrap_or([0u8; 32]);
                            let pqc = PQCCompiler::new(PQCSecurityLevel::Enhanced);
                            match pqc.sign_message(private_key, &root, SIGNING_ALGORITHM) {
                                Ok(sig) => Some(sig.signature),
                                Err(e) => {
                                    eprintln!("[SQB] Failed to sign artifact root: {}", e);
                                    None
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[SQB] Pre-sig build failed: {}", e);
                            None
                        }
                    }
                }
                CompilerKey::Ephemeral => None,
            };

            let mut encoder = sqb::SqbEncoder::new(V3_CHAIN_ID as u32)
                .code(sqb_code)
                .abi(abi_bytes)
                .manifest(manifest_bytes)
                .ir_dump(ir_bytes)
                .effects(effects_bytes)
                .state_layout(state_layout_bytes)
                .meta(meta_bytes)
                .source(source_bytes)
                .solidity_source(solidity_bytes);

            let was_signed = sqb_signature.is_some();
            if let Some(sig) = sqb_signature {
                encoder = encoder.signature(sig);
            }

            match encoder.build() {
                Ok(sqb_binary) => {
                    eprintln!("[SQB] Artifact encoded: {} bytes, 7 sections, signed={}",
                               sqb_binary.len(), was_signed);
                    Some(BASE64_STANDARD.encode(&sqb_binary))
                }
                Err(e) => {
                    eprintln!("[SQB] Failed to encode artifact: {}", e);
                    None
                }
            }
        },
    }))
}


// ── POST /decompile ─────────────────────────────────────────────────────────────────────────────
//
// Decompiles an SQB artifact's SIR1 IR section into pseudo-SynQ source.
// Takes base64-encoded SQB, extracts the IR section, deserializes SIR1,
// and reconstructs readable pseudo-SynQ with provenance comments.

#[derive(serde::Deserialize)]
struct DecompileRequest {
    sqb: String,
}

#[derive(serde::Serialize)]
struct DecompileResponse {
    success: bool,
    source: Option<String>,
    /// Original source from SQB SOURCE section (if embedded)
    original_source: Option<String>,
    /// Solidity source from SQB SOLIDITY_SOURCE section (if embedded)
    solidity_source: Option<String>,
    contract_name: Option<String>,
    error: Option<String>,
}

async fn decompile_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<DecompileRequest>,
) -> (StatusCode, RespJson<DecompileResponse>) {
    use base64::{Engine, prelude::BASE64_STANDARD};

    if let Err(_) = check_rate_limit(&state.rate_limiter, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, RespJson(DecompileResponse {
            success: false, source: None, contract_name: None,
            error: Some("rate limit exceeded".into()),
            original_source: None,
            solidity_source: None,
        }));
    }

    let sqb_bytes = match BASE64_STANDARD.decode(&req.sqb) {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, RespJson(DecompileResponse {
            success: false, source: None, contract_name: None,
            error: Some(format!("SQB base64 decode failed: {}", e)),
            original_source: None,
            solidity_source: None,
        })),
    };

    let artifact = match sqb::decode(&sqb_bytes) {
        Ok(a) => a,
        Err(e) => return (StatusCode::BAD_REQUEST, RespJson(DecompileResponse {
            success: false, source: None, contract_name: None,
            error: Some(format!("SQB decode failed: {}", e)),
            original_source: None,
            solidity_source: None,
        })),
    };

    // Get IR section (type 0x04)
    let ir_data = match artifact.get(sqb::SectionType::Ir) {
        Some(s) => &s.data,
        None => return (StatusCode::OK, RespJson(DecompileResponse {
            success: false, source: None, contract_name: None,
            error: Some("SQB artifact has no IR section — cannot decompile".into()),
            original_source: None,
            solidity_source: None,
        })),
    };

    // Deserialize SIR1 IR
    let module = match synq_compiler::ir::deserialize(ir_data) {
        Ok(m) => m,
        Err(e) => return (StatusCode::OK, RespJson(DecompileResponse {
            success: false, source: None, contract_name: None,
            error: Some(format!("SIR1 deserialization failed: {}", e)),
            original_source: None,
            solidity_source: None,
        })),
    };

    let contract_name = module.contract_name.clone();

    // Decompile
    let source = synq_compiler::ir::decompile(&module);

    eprintln!("[DECOMPILE] Contract: {}, source: {} bytes", contract_name, source.len());

    let original_source = artifact.source_text().map(|s| s.to_string());
    let solidity_source = artifact.solidity_source_text().map(|s| s.to_string());

    (StatusCode::OK, RespJson(DecompileResponse {
        success: true,
        source: Some(source),
        original_source,
        solidity_source,
        contract_name: Some(contract_name),
        error: None,
    }))
}

// ─── POST /source-nonce ───────────────────────────────────────────────────────────────────────────
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
// The canonical PQC payload (SynQSourceCommitV3):
//   b"SynQSourceCommitV3\x00"   (19 bytes)
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
    p.extend_from_slice(b"SynQSourceCommitV3\x00");
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
                functions:        Vec::new(),
            state_var_types:  std::collections::HashMap::new(),
            manifest:           None,
            ir_dump:            vec![],
            sqb:               None,
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
            functions:        Vec::new(),
            state_var_types:  std::collections::HashMap::new(),
            manifest:           None,
            ir_dump:            vec![],
            sqb:               None,
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

    // Use compile_ir() as the sole compilation path (SSA IR backend with phi).
    let wasm_compile = match synq_compiler::compile_ir(&req.source) {
        Ok(r)  => r,
        Err(e) => return (StatusCode::OK, RespJson(CompileResponse {
            success: false, bytecode: None, signature_sidecar: None,
            state_vars: vec![], contract_name: None, contract_address: None,
            extern_contracts: vec![],
            errors: vec![format!("Compilation error: {}", e)], warnings: compile_warnings,
            functions:        Vec::new(),
            state_var_types:  std::collections::HashMap::new(),
            manifest:           None,
            ir_dump:            vec![],
            sqb:               None,
        })),
    };
    let bytecode = wasm_compile.bytecode;
    let state_vars_raw = wasm_compile.state_vars;
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
        "signing_spec":    "SourceCommitV3",
        "author":          format!("0x{}", hex_encode(&author)),
        "source_hash":     source_hash_with_0x,
        "bytecode_hash":   format!("0x{}", hex_encode(&bytecode_hash_bytes)),
        "contract_name":   cname,
        "nonce":           clean_nonce,
        "issued_at":       issued_at,
        "eip712_domain": {
            "name": "SynQ", "version": "3",
            "chainId": 1266, "verifyingContract": vc_hex,
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
        state_var_types: {
            let mut svm: std::collections::HashMap<String,String> = std::collections::HashMap::new();
            for unit in &ast {
                if let synq_compiler::ast::SourceUnit::Contract(con) = unit {
                    for part in &con.parts {
                        if let synq_compiler::ast::ContractPart::StateVariable(sv) = part {
                            svm.insert(sv.name.clone(), type_name(&sv.ty));
                        }
                    }
                }
            }
            svm
        },
        contract_name,
        contract_address,
        extern_contracts:  server_extern,
        errors:            vec![],
        warnings:          compile_warnings,
        functions:        Vec::new(),
            manifest:           None,
            ir_dump:            vec![],
            sqb:               None,
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
    #[serde(default)]
    bytecode:        Option<String>,
    state_vars:      Vec<(String, u32)>,
    contract_name:   Option<String>,
    workspace_id:    Option<String>,
    fn_return_types: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    governance_scopes: Option<std::collections::HashMap<String, String>>,
    /// V3 manifest from compile — used for Layer 3 verification (artifact hash + ML-DSA-87 signature)
    #[serde(default)]
    manifest: Option<serde_json::Value>,
    /// Optional step limit override (default: 100M). Allows the IDE to configure
    /// a lower limit for testing or a higher limit for loop-heavy contracts.
    #[serde(default)]
    max_steps: Option<usize>,
    /// SQB binary artifact (base64-encoded) — v7.0 unified deployment unit.
    /// If provided, the CODE section is extracted and used as the bytecode,
    /// and the SQB's embedded manifest+signature are used for L3 verification.
    /// The raw `bytecode` field is ignored when `sqb` is present.
    #[serde(default)]
    sqb: Option<String>,
}

#[derive(serde::Serialize)]
struct NewSessionResponse {
    success:    bool,
    session_id:    Option<String>,
    contract_name: Option<String>,
    error:      Option<String>,
    /// Layer 3 manifest verification result
    #[serde(skip_serializing_if = "Option::is_none")]
    layer3: Option<Layer3Result>,
    /// PQC fuel budget for this session (ACTS-VM-005).
    #[serde(skip_serializing_if = "Option::is_none")]
    fuel_budget: Option<u64>,
    /// Step limit for this session (ACTS-VM-003).
    #[serde(skip_serializing_if = "Option::is_none")]
    max_steps: Option<usize>,
    /// VM steps used so far (0 at session creation).
    #[serde(skip_serializing_if = "Option::is_none")]
    steps_used: Option<usize>,
    /// Remaining VM step budget.
    #[serde(skip_serializing_if = "Option::is_none")]
    steps_remaining: Option<usize>,
    /// SQB artifact verification result (v7.0 unified deployment).
    /// Present when deployment was via SQB artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    sqb_verified: Option<bool>,
}

/// Layer 3: Manifest + ML-DSA-87 signature verification result
#[derive(Debug, Clone, serde::Serialize)]
struct Layer3Result {
    verified:           bool,
    artifact_hash_match: bool,
    signature_valid:    bool,
    artifact_hash:       String,
    algorithm:           String,
    key_id:              String,
    warning:             Option<String>,
}


// ─── GET /pqc/test-vector ─────────────────────────────────────────────────────
/// Generates a fresh ML-DSA-65 test vector (keypair + signed message).
/// Used by the IDE PQC demo to auto-fill function arguments.
async fn pqc_test_vector_handler(
) -> impl axum::response::IntoResponse {
    use synq_pqc_shims::dilithium;

    let (pk, sk) = dilithium::keygen();
    let msg = b"Hello SynQ PQC!";
    let sig = dilithium::sign(msg, &sk);
    let valid = dilithium::verify(msg, &sig, &pk);

    serde_json::json!({
        "algorithm": "ML-DSA-65",
        "message": String::from_utf8_lossy(msg),
        "message_hex": hex::encode(msg),
        "public_key_hex": hex::encode(&pk),
        "signature_hex": hex::encode(&sig),
        "public_key_len": pk.len(),
        "signature_len": sig.len(),
        "verified": valid,
    }).to_string()
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


// ─── Layer 3: Manifest + ML-DSA-87 signature verification ─────────────────────

/// Verify a V3 manifest against bytecode:
/// 1. Recompute artifact_hash = SHA3-256(bytecode) and compare with manifest
/// 2. Reconstruct the canonical manifest JSON, hash it, verify ML-DSA-87 signature
fn verify_manifest(
    bytecode: &[u8],
    manifest: &serde_json::Value,
    sqb_artifact_root: Option<&[u8; 32]>,
    sqb_signature: Option<&[u8]>,
    sqb_sections_hash: Option<&[u8; 32]>,
) -> Layer3Result {
    use sha3::{Digest, Sha3_256};

    // Extract fields from the manifest JSON
    let artifact_hash_stored = manifest.get("artifact_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let manifest_sig = manifest.get("manifest_signature")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let compiler_pubkey = manifest.get("compiler_public_key")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let algorithm = manifest.get("required_signature_algorithm")
        .and_then(|v| v.as_str())
        .unwrap_or("ML-DSA-87");
    let key_id = manifest.get("key_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Step 1: artifact hash check (bytecode only)
    let computed_hash = hex::encode(Sha3_256::digest(bytecode));
    let hash_match = computed_hash == artifact_hash_stored;

    // Step 1b: sections hash check (ALL non-manifest sections: CODE, ABI, IR, EFFECTS, STATE_LAYOUT, META)
    let sections_hash_stored = manifest.get("sections_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let sections_hash_match = if let Some(computed_sh) = sqb_sections_hash {
        let computed_sh_hex = hex::encode(computed_sh);
        if sections_hash_stored.is_empty() {
            // Legacy manifest without sections_hash — warn but don't fail
            true
        } else {
            computed_sh_hex == sections_hash_stored
        }
    } else {
        true // No SQB sections available (raw bytecode path) — skip
    };

    // Step 2: signature verification
    let mut sig_valid = false;
    let mut warning = None;

    if manifest_sig.is_empty() || compiler_pubkey.is_empty() {
        warning = Some("Manifest has no signature or public key".into());
    } else if !hash_match {
        warning = Some(format!(
            "Artifact hash mismatch: manifest={}, computed={}", 
            &artifact_hash_stored[..16.min(artifact_hash_stored.len())],
            &computed_hash[..16.min(computed_hash.len())]
        ));
    } else {
        // Reconstruct the canonical manifest JSON (same fields used during compile-time signing)
        let canonical_json = serde_json::json!({
            "artifact_hash":   manifest.get("artifact_hash").cloned().unwrap_or_default(),
            "sections_hash":   manifest.get("sections_hash").cloned().unwrap_or_default(),
            "source_hash":     manifest.get("source_hash").cloned().unwrap_or_default(),
            "chain_id":        manifest.get("chain_id").cloned().unwrap_or_default(),
            "network_id":      manifest.get("network_id").cloned().unwrap_or_default(),
            "functions":       manifest.get("functions").cloned().unwrap_or_default(),
            "state_vars":      manifest.get("state_vars").cloned().unwrap_or_default(),
            "governance_scopes": manifest.get("governance_scopes").cloned().unwrap_or_default(),
            "authority_scopes":  manifest.get("authority_scopes").cloned().unwrap_or_default(),
        });
        let manifest_bytes = serde_json::to_vec(&canonical_json).unwrap_or_default();
        let manifest_hash = Sha3_256::digest(&manifest_bytes);

        match (hex::decode(manifest_sig), hex::decode(compiler_pubkey)) {
            (Ok(sig), Ok(pk)) => {
                let pqc = synq_compiler::PQCCompiler::new(
                    synq_compiler::PQCSecurityLevel::Enhanced
                );
                match pqc.verify_signature(&pk, &sig, &manifest_hash, algorithm) {
                    Ok(valid) => sig_valid = valid,
                    Err(e) => {
                        warning = Some(format!("Signature verification error: {}", e));
                    }
                }
            }
            (Err(e), _) | (_, Err(e)) => {
                warning = Some(format!("Hex decode failed: {}", e));
            }
        }

        if !sig_valid && warning.is_none() {
            warning = Some("ML-DSA-87 signature invalid".into());
        }
    }

    // Step 3: Verify SQB embedded signature over artifact root (covers ALL sections)
    let mut sqb_sig_valid = false;
    if let (Some(root), Some(sig)) = (sqb_artifact_root, sqb_signature) {
        if !sig.is_empty() && !compiler_pubkey.is_empty() {
            match hex::decode(compiler_pubkey) {
                Ok(pk) => {
                    let pqc = synq_compiler::PQCCompiler::new(
                        synq_compiler::PQCSecurityLevel::Enhanced
                    );
                    match pqc.verify_signature(&pk, sig, root, algorithm) {
                        Ok(valid) => {
                            sqb_sig_valid = valid;
                            if !valid && warning.is_none() {
                                warning = Some("SQB artifact root signature invalid — a section has been tampered".into());
                            }
                        }
                        Err(e) => {
                            if warning.is_none() {
                                warning = Some(format!("SQB signature verification error: {}", e));
                            }
                        }
                    }
                }
                Err(e) => {
                    if warning.is_none() {
                        warning = Some(format!("Compiler pubkey hex decode failed: {}", e));
                    }
                }
            }
        }
    } else if sqb_artifact_root.is_some() && sqb_signature.is_none() {
        // SQB has artifact root but no signature — fail
        if warning.is_none() {
            warning = Some("SQB artifact has no embedded signature — cannot verify section integrity".into());
        }
    }

    // Step 4: Check sections hash mismatch
    if !sections_hash_match && warning.is_none() {
        warning = Some("Sections hash mismatch — one or more SQB sections (ABI, IR, META, etc.) have been tampered".into());
    }

    let verified = hash_match && sig_valid && sqb_sig_valid && sections_hash_match;

    Layer3Result {
        verified,
        artifact_hash_match: hash_match,
        signature_valid:     sig_valid,
        artifact_hash:       computed_hash,
        algorithm:           algorithm.to_string(),
        key_id:              key_id.to_string(),
        warning,
    }
}

async fn session_new_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<NewSessionRequest>,
) -> (StatusCode, RespJson<NewSessionResponse>) {
    if let Err(_) = check_rate_limit(&state.rate_limiter, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, RespJson(NewSessionResponse { success: false, session_id: None, contract_name: None, error: Some("rate limit exceeded — retry later".into()), layer3: None, fuel_budget: None, max_steps: None, steps_used: None, steps_remaining: None, sqb_verified: None }));
    }

    // ── v7.0: SQB unified deployment path ────────────────────────────────────
    // If an SQB artifact is provided, decode it, extract the CODE section,
    // and use the SQB's embedded manifest+signature for L3 verification.
    // The raw bytecode field is ignored when SQB is present.
    let mut sqb_verified = None;
    let mut sqb_manifest = None;
    let mut sqb_artifact_root: Option<[u8; 32]> = None;
    let mut sqb_signature: Option<Vec<u8>> = None;
    let mut sqb_sections_hash: Option<[u8; 32]> = None;

    let raw = if let Some(ref sqb_b64) = req.sqb {
        use base64::{Engine, prelude::BASE64_STANDARD};

        let sqb_bytes = match BASE64_STANDARD.decode(sqb_b64) {
            Ok(b) => b,
            Err(e) => return (StatusCode::BAD_REQUEST, RespJson(NewSessionResponse {
                success: false, session_id: None, contract_name: None,
                error: Some(format!("SQB base64 decode failed: {}", e)),
                layer3: None, fuel_budget: None, max_steps: None, steps_used: None, steps_remaining: None,
                sqb_verified: None,
            })),
        };

        let artifact = match sqb::decode(&sqb_bytes) {
            Ok(a) => a,
            Err(e) => return (StatusCode::BAD_REQUEST, RespJson(NewSessionResponse {
                success: false, session_id: None, contract_name: None,
                error: Some(format!("SQB decode failed: {}", e)),
                layer3: None, fuel_budget: None, max_steps: None, steps_used: None, steps_remaining: None,
                sqb_verified: None,
            })),
        };

        // Extract CODE section
        let code = match artifact.code() {
            Some(c) => c.to_vec(),
            None => return (StatusCode::BAD_REQUEST, RespJson(NewSessionResponse {
                success: false, session_id: None, contract_name: None,
                error: Some("SQB artifact has no CODE section".into()),
                layer3: None, fuel_budget: None, max_steps: None, steps_used: None, steps_remaining: None,
                sqb_verified: None,
            })),
        };

        // Verify artifact signature (if present)
        let sig_ok = if let Some(ref sig) = artifact.signature {
            // Verify ML-DSA-87 signature over artifact root
            match state.compiler_key.as_ref() {
                CompilerKey::Persistent { public_key, .. } => {
                    // For SQB with embedded signature, we verify against the
                    // manifest's compiler_public_key if available
                    if let Some(manifest_str) = artifact.manifest_json() {
                        if let Ok(mf) = serde_json::from_str::<serde_json::Value>(manifest_str) {
                            let pk_hex = mf.get("compiler_public_key")
                                .and_then(|v| v.as_str()).unwrap_or("");
                            if let Ok(pk) = hex::decode(pk_hex) {
                                let pqc = synq_compiler::PQCCompiler::new(PQCSecurityLevel::Enhanced);
                                match pqc.verify_signature(&pk, sig, &artifact.artifact_root, SIGNING_ALGORITHM) {
                                    Ok(valid) => valid,
                                    Err(_) => false,
                                }
                            } else { false }
                        } else { false }
                    } else { false }
                }
                CompilerKey::Ephemeral => true, // devnet: accept unsigned/ephemeral
            }
        } else {
            true // No signature present — acceptable in devnet
        };

        sqb_verified = Some(sig_ok);

        if !sig_ok {
            return (StatusCode::OK, RespJson(NewSessionResponse {
                success: false, session_id: None, contract_name: None,
                error: Some("SQB signature verification failed — artifact may be tampered".into()),
                layer3: None, fuel_budget: None, max_steps: None, steps_used: None, steps_remaining: None,
                sqb_verified: Some(false),
            }));
        }

        // Extract manifest from SQB for L3 (if present)
        if let Some(manifest_str) = artifact.manifest_json() {
            if let Ok(mf) = serde_json::from_str::<serde_json::Value>(manifest_str) {
                sqb_manifest = Some(mf);
            }
        }

        // Extract artifact root, signature, and sections hash for L3 verification
        sqb_artifact_root = Some(artifact.artifact_root);
        sqb_signature = artifact.signature.clone();
        // Compute sections_hash = SHA3-256(concat of all section hashes EXCEPT manifest)
        // This covers ALL non-manifest sections (CODE, ABI, IR, EFFECTS, STATE_LAYOUT, META)
        {
            use sha3::{Digest, Sha3_256};
            let mut hash_concat = Vec::new();
            for s in &artifact.sections {
                if s.section_type != sqb::SectionType::Manifest {
                    hash_concat.extend_from_slice(&s.hash);
                }
            }
            let sections_hash = Sha3_256::digest(&hash_concat);
            sqb_sections_hash = Some(sections_hash.into());
        }

        eprintln!("[SQB] Deployed from artifact: {} sections, {} bytes, sig_verified={}",
            artifact.sections.len(), code.len(), sig_ok);

        code
    } else {
        // Legacy path: raw bytecode hex (now optional — may be None when SQB not provided either)
        match req.bytecode.as_deref().and_then(|s| hex_decode_strict(s).ok()).filter(|b| !b.is_empty()) {
            Some(b) => b,
            None => return (StatusCode::BAD_REQUEST, RespJson(NewSessionResponse {
                success: false, session_id: None, contract_name: None, error: Some("no bytecode or SQB artifact provided".into()),
                layer3: None, fuel_budget: None, max_steps: None, steps_used: None, steps_remaining: None,
                sqb_verified: None,
            })),
        }
    };

    // Layer 1 structural verification — reject malformed bytecode before loading
    if let Err(e) = verify::verify(&raw) {
        return (StatusCode::OK, RespJson(NewSessionResponse {
            success: false, session_id: None, contract_name: None,
            error: Some(format!("Bytecode verification failed: {}", e)),
            layer3: None, fuel_budget: None, max_steps: None, steps_used: None, steps_remaining: None,
            sqb_verified,
        }));
    }

    // Layer 3: Manifest + ML-DSA-87 signature verification
    // ── MANDATORY for SQB deployments (ACTS-VM-008) ──────────────────────
    // SQB artifacts always embed a manifest; if missing or verification
    // fails, the deployment is REJECTED — no skip path for SQB.
    // For raw bytecode deployments (no SQB), L3 remains advisory:
    //   priority: request-provided manifest > skip
    let l3_manifest = if sqb_verified.unwrap_or(false) {
        // SQB path — manifest must come from the artifact itself
        match sqb_manifest.as_ref() {
            Some(m) => Some(m),
            None => return (StatusCode::OK, RespJson(NewSessionResponse {
                success: false, session_id: None, contract_name: None,
                error: Some("SQB artifact missing manifest — L3 verification mandatory for SQB deployments".into()),
                layer3: None, fuel_budget: None, max_steps: None, steps_used: None,
                steps_remaining: None, sqb_verified,
            })),
        }
    } else {
        // Raw bytecode path — advisory, may skip
        sqb_manifest.as_ref().or(req.manifest.as_ref())
    };
    let layer3_result = l3_manifest.map(|m| {
        verify_manifest(
            &raw,
            m,
            sqb_artifact_root.as_ref(),
            sqb_signature.as_deref(),
            sqb_sections_hash.as_ref(),
        )
    });

    // Enforce L3: reject if SQB deploy and L3 failed
    if sqb_verified.unwrap_or(false) {
        if let Some(ref l3) = layer3_result {
            if !l3.verified {
                let reason = if !l3.artifact_hash_match {
                    "artifact hash mismatch — bytecode has been tampered"
                } else if !l3.signature_valid {
                    "ML-DSA-87 signature invalid — manifest is forged or corrupted"
                } else {
                    "unknown L3 verification failure"
                };
                return (StatusCode::OK, RespJson(NewSessionResponse {
                    success: false, session_id: None, contract_name: None,
                    error: Some(format!("L3 verification FAILED: {}", reason)),
                    layer3: layer3_result.clone(), fuel_budget: None, max_steps: None,
                    steps_used: None, steps_remaining: None, sqb_verified,
                }));
            }
        }
    }

    let mut vm = QuantumVM::new();
    if let Err(e) = vm.load_bytecode(&raw) {
        return (StatusCode::OK, RespJson(NewSessionResponse {
            success: false, session_id: None, contract_name: None, error: Some(format!("Load error: {}", e)),
            layer3: None, fuel_budget: None, max_steps: None, steps_used: None, steps_remaining: None,
            sqb_verified,
        }));
    }
    // Apply optional step limit override
    let effective_max_steps = req.max_steps.unwrap_or(synq_vm::DEFAULT_MAX_STEPS);
    vm.max_steps = effective_max_steps;

    // Log Layer 3 result
    if let Some(ref l3) = layer3_result {
        if l3.verified {
            eprintln!("[VERIFY] Layer 3 passed (manifest + ML-DSA-87 signature) | hash={}...", &l3.artifact_hash[..16]);
        } else {
            eprintln!("[VERIFY] Layer 3 FAILED: hash_match={}, sig_valid={}", l3.artifact_hash_match, l3.signature_valid);
            if let Some(ref w) = l3.warning { eprintln!("[VERIFY] Layer 3 warning: {}", w); }
        }
    } else {
        eprintln!("[VERIFY] Layer 3 skipped (no manifest provided)");
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
            max_steps: effective_max_steps,
            state_vars: req.state_vars,
            contract_name: cname.clone(),
            workspace_id: wid.clone(),
            pending_nonce: None,
            used_nonces: std::collections::HashSet::new(),
            fn_return_types: req.fn_return_types.unwrap_or_default(),
            governance_scopes: req.governance_scopes.unwrap_or_default(),
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

    (StatusCode::OK, RespJson(NewSessionResponse { success: true, session_id: Some(id), contract_name: req.contract_name.clone(), error: None, layer3: layer3_result,
        fuel_budget: if FUEL_REPORTING { Some(synq_vm::DEFAULT_MAX_FUEL) } else { None },
        max_steps: Some(effective_max_steps),
        steps_used: if FUEL_REPORTING { Some(0) } else { None },
        steps_remaining: if FUEL_REPORTING { Some(effective_max_steps) } else { None },
        sqb_verified,
    }))
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
    param_types:    Option<Vec<String>>,  // declared types per arg ("str","u256","bool")
    display_synw:   Option<String>,  // Manual synw address override (devnet only)
    // ── Runtime fault injection (cosmic ray simulation) ──
    fault_step:       Option<usize>,
    fault_byte_offset: Option<usize>,
    fault_xor_mask:   Option<u8>,
}

#[derive(Debug, serde::Serialize)]
struct EventLog {
    name: String,
    args: Vec<serde_json::Value>,
}

#[derive(serde::Serialize)]
struct RunResponse {
    success: bool,
    result:  Option<serde_json::Value>,
    output:  String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    events:  Vec<EventLog>,
    error:   Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    caller_syna: Option<String>,
    /// Structured error code from named revert (RevertCode opcode).
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<u32>,
    /// Error name extracted from the revert message.
    #[serde(skip_serializing_if = "Option::is_none")]
    error_name: Option<String>,
    /// PQC fuel consumed by this call (ACTS-VM-005).
    #[serde(skip_serializing_if = "Option::is_none")]
    fuel_used: Option<u64>,
    /// Remaining PQC fuel budget after this call.
    #[serde(skip_serializing_if = "Option::is_none")]
    fuel_remaining: Option<u64>,
    /// VM steps consumed by this call (ACTS-VM-003).
    #[serde(skip_serializing_if = "Option::is_none")]
    steps_used: Option<usize>,
    /// Remaining VM step budget after this call.
    #[serde(skip_serializing_if = "Option::is_none")]
    steps_remaining: Option<usize>,
}


/// Parse structured EventLog entries from raw Print output.
/// emit codegen emits: Print("event:Name") then Print(arg0), Print(arg1), ...
fn parse_event_logs(log: &[String]) -> Vec<EventLog> {
    let mut events: Vec<EventLog> = Vec::new();
    let mut i = 0;
    while i < log.len() {
        if let Some(name) = log[i].strip_prefix("event:") {
            let event_name = name.to_string();
            let mut args: Vec<serde_json::Value> = Vec::new();
            i += 1;
            while i < log.len() && !log[i].starts_with("event:") {
                let s = &log[i];
                let v = if let Ok(n) = s.parse::<i64>() { serde_json::json!(n) }
                        else if s == "true"  { serde_json::json!(true)  }
                        else if s == "false" { serde_json::json!(false) }
                        else { serde_json::Value::String(s.clone()) };
                args.push(v);
                i += 1;
            }
            events.push(EventLog { name: event_name, args });
        } else {
            i += 1;
        }
    }
    events
}

async fn session_run_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<SessionRunRequest>,
) -> (StatusCode, RespJson<RunResponse>) {
    if let Err(_) = check_rate_limit(&state.rate_limiter, addr.ip()) {
        return (StatusCode::TOO_MANY_REQUESTS, RespJson(RunResponse { success: false, result: None, output: String::new(), events: Vec::new(), error: Some("rate limit exceeded — retry later".into()), caller_syna: None, error_code: None, error_name: None, fuel_used: None, fuel_remaining: None, steps_used: None, steps_remaining: None }));
    }
    let mut vm_args: Vec<Value> = Vec::new();
    // Build call_sig before args are moved — used in EIP-712 digest if wallet auth is present.
    let call_sig_early: String = match req.call_signature.as_deref() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            let arg_strs: Vec<String> = req.args.as_deref().unwrap_or(&[]).iter().map(|a| match a {
                serde_json::Value::String(s) => s.clone(),
                // Numbers must not go through serde f64 formatting — that loses precision for
                // UInt256 values (>2^53). Use the raw JSON representation which preserves the
                // exact digits the browser sent. This ensures the EIP-712 callSignature the
                // server builds matches the one the browser signed.
                serde_json::Value::Number(n) => n.to_string(),
                other => other.to_string(),
            }).collect();
            format!("{}({})", req.function, arg_strs.join(", "))
        }
    };
    let param_types_hint: Vec<String> = req.param_types.unwrap_or_default();
    for (i, raw) in req.args.unwrap_or_default().iter().enumerate() {
        let ty_hint = param_types_hint.get(i).map(|s| s.as_str()).unwrap_or("");
        match parse_arg_typed(raw, ty_hint) {
            Ok(v)  => vm_args.push(v),
            Err(e) => return (StatusCode::OK, RespJson(RunResponse {
                success: false, result: None, output: String::new(),
                events: Vec::new(),
                error: Some(format!("arg[{}]: {}", i, e)),
            caller_syna: None,
            error_code: None,
            error_name: None,
            fuel_used: None, fuel_remaining: None, steps_used: None, steps_remaining: None,
            })),
        }
    }

    let mut session = {
        let mut map = state.sessions.lock().unwrap();
        match map.remove(&req.session_id) {
            Some(s) => s,
            None    => return (StatusCode::OK, RespJson(RunResponse {
                success: false, result: None, output: String::new(),
                events: Vec::new(),
                error: Some(format!("Session '{}' not found or expired", req.session_id)),
            caller_syna: None,
            error_code: None,
            error_name: None,
            fuel_used: None, fuel_remaining: None, steps_used: None, steps_remaining: None,
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
                    events: Vec::new(),
                    error: Some("caller auth: no pending nonce — call GET /session/:id/nonce first".into()),
                caller_syna: None,
                error_code: None,
                error_name: None,
                fuel_used: None, fuel_remaining: None, steps_used: None, steps_remaining: None,
                }));
            }
            Some(pn) if pn != nonce => {
                { state.sessions.lock().unwrap().insert(req.session_id.clone(), session); }
                return (StatusCode::UNAUTHORIZED, RespJson(RunResponse {
                    success: false, result: None, output: String::new(),
                    events: Vec::new(),
                    error: Some("caller auth: nonce mismatch — nonces are single-use, request a new one".into()),
                caller_syna: None,
                error_code: None,
                error_name: None,
                fuel_used: None, fuel_remaining: None, steps_used: None, steps_remaining: None,
                }));
            }
            _ => {}
        }
        // 2. Must not be a replayed nonce
        if session.used_nonces.contains(nonce.as_str()) {
            { state.sessions.lock().unwrap().insert(req.session_id.clone(), session); }
            return (StatusCode::UNAUTHORIZED, RespJson(RunResponse {
                success: false, result: None, output: String::new(),
                events: Vec::new(),
                error: Some("caller auth: nonce already used — replay attack rejected".into()),
            caller_syna: None,
            error_code: None,
            error_name: None,
            fuel_used: None, fuel_remaining: None, steps_used: None, steps_remaining: None,
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
        let struct_hash = eip712_hash_contract_call_v3(&call_sig_early, &req.session_id, nonce, V3_DOMAIN_CALL);
        let digest      = eip712_digest_with_domain(run_domain, &struct_hash);
        eprintln!("[AUTH] contract_name={:?} call_sig={:?}",
            session.contract_name.as_deref().unwrap_or("(none)"), call_sig_early);
        eprintln!("[AUTH] domain_sep={} struct_hash={} digest={}",
            hex_encode(&run_domain), hex_encode(&struct_hash), hex_encode(&digest));
        // 4. ecrecover against EIP-712 digest
        let sig_bytes = hex_decode_strict(sig_str.strip_prefix("0x").unwrap_or(sig_str))
            .map_err(|e| format!("evm_signature hex invalid: {}", e));
        let sig_bytes = match sig_bytes {
            Ok(b) => b,
            Err(e) => {
                { state.sessions.lock().unwrap().insert(req.session_id.clone(), session); }
                return (StatusCode::BAD_REQUEST, RespJson(RunResponse {
                    success: false, result: None, output: String::new(), events: Vec::new(), error: Some(e),
                caller_syna: None,
                error_code: None,
                error_name: None,
                fuel_used: None, fuel_remaining: None, steps_used: None, steps_remaining: None,
                }));
            }
        };
        let recovered = match ecrecover(&digest, &sig_bytes) {
            Ok(r) => {
                eprintln!("[AUTH] recovered={} claimed={}", hex_encode(&r), addr_str);
                r
            }
            Err(e) => {
                { state.sessions.lock().unwrap().insert(req.session_id.clone(), session); }
                return (StatusCode::UNAUTHORIZED, RespJson(RunResponse {
                    success: false, result: None, output: String::new(),
                    events: Vec::new(),
                    error: Some(format!("caller auth: ecrecover failed: {}", e)),
                caller_syna: None,
                error_code: None,
                error_name: None,
                fuel_used: None, fuel_remaining: None, steps_used: None, steps_remaining: None,
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
                events: Vec::new(),
                error: Some("caller auth: signature does not match claimed evm_address".into()),
            caller_syna: None,
            error_code: None,
            error_name: None,
            fuel_used: None, fuel_remaining: None, steps_used: None, steps_remaining: None,
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
            events: Vec::new(),
            error: Some("caller auth: evm_address, evm_signature, and call_nonce must all be provided together".into()),
        caller_syna: None,
        error_code: None,
        error_name: None,
        fuel_used: None, fuel_remaining: None, steps_used: None, steps_remaining: None,
        }));
    } else {
        // Unauthenticated call — caller == zero address
        [0u8; 20]
    };
    // ── Authority envelope construction ─────────────────────────────────────
    // Build a devnet authority envelope from the recovered EVM address.
    // Format: identity(32) + scope_hash(32) + nonce(8) + expiry(8) + caps(8) + reserved(16) = 104 bytes
    //
    // Devnet: identity = padded EVM address (zero-extended to 32 bytes)
    //         scope_hash = all-zeros (accept any scope on devnet)
    //         nonce = current session nonce (if available)
    //         expiry = 0 (no expiry on devnet)
    //         caps = 0xFF (all capabilities enabled on devnet)
    //
    // Mainnet: the consensus layer will construct the real envelope with
    // resolved UMA, Aegis receipt, and proper scope/capability fields.
    let mut auth_envelope = vec![0u8; 104];
    // Identity: EVM address right-aligned in 32 bytes
    auth_envelope[12..32].copy_from_slice(&caller_addr);

    // Scope hash: all-zeros = accept any scope (devnet convenience).
    // For @governance functions, embed the actual SHA3-256 scope hash so
    // the VM's AuthRequire matches the compiler-emitted hash.
    let mut domain_tag_bytes: &[u8] = V3_DOMAIN_CALL.as_bytes();

    if let Some(ref gov_scope) = session.governance_scopes.get(&req.function) {
        let scope_hash = governance_scope_hash(gov_scope);
        auth_envelope[32..64].copy_from_slice(&scope_hash);
        domain_tag_bytes = V3_DOMAIN_GOVERNANCE.as_bytes();
        // Devnet: if no authenticated caller, use a non-zero governance identity
        // so the AuthRequire identity check passes. Mainnet would use real UMA.
        if auth_envelope[0..32].iter().all(|&b| b == 0) {
            // Use a devnet governance identity: SHA3-256("SYNQ-DEVNET-GOVERNANCE")
            use sha3::Digest;
            let gov_id = sha3::Sha3_256::digest(b"SYNQ-DEVNET-GOVERNANCE");
            auth_envelope[0..32].copy_from_slice(&gov_id);
        }
        eprintln!("[RUN] governance scope '{}' for function '{}'", gov_scope, req.function);
    }

    // Nonce: current session nonce if available
    if let Some(ref pn) = session.pending_nonce {
        if let Ok(nonce_bytes) = hex::decode(pn) {
            let nonce_val = if nonce_bytes.len() >= 8 {
                u64::from_be_bytes(nonce_bytes[..8].try_into().unwrap_or([0u8; 8]))
            } else {
                0u64
            };
            auth_envelope[64..72].copy_from_slice(&nonce_val.to_be_bytes());
        }
    }
    // Expiry: 0 = no expiry (devnet)
    // auth_envelope[72..80] already zero
    // Capabilities: 0xFF = all enabled (devnet)
    auth_envelope[80] = 0xFF;
    // Reserved (16 bytes): V3 domain tag for cross-domain replay resistance.
    // First 8 bytes of the domain tag string, right-padded with zeros.
    // Uses GOVERNANCE tag for @governance functions, CALL tag otherwise.
    let copy_len = domain_tag_bytes.len().min(16);
    auth_envelope[88..88 + copy_len].copy_from_slice(&domain_tag_bytes[..copy_len]);

    // Devnet: if display_synw is provided, override caller_addr with the synw address.
    // The EVM signature still authenticates the request (nonce + ephemeral key),
    // but the contract sees the user's synw identity as the caller.
    let mut effective_caller = caller_addr;
    if let Some(ref synw) = req.display_synw {
        if let Ok(decoded) = synq_vm::bech32::from_any_syn(synw) {
            eprintln!("[RUN] display_synw override: {} -> {}", synw, hex_encode(&decoded));
            effective_caller = decoded;
        } else {
            eprintln!("[RUN] display_synw decode failed for: {}", synw);
        }
    }

    session.vm.call_context = synq_vm::CallContext::with_authority(
        effective_caller,
        None, // uma_ref: None on devnet (NullUmaRegistry)
        auth_envelope,
    );

    // Wire ExternCall handler if session belongs to a workspace
    if let Some(ref wid) = session.workspace_id.clone() {
        let sessions_arc = state.sessions.clone();
        let workspaces_arc = state.workspaces.clone();
        let wid_clone = wid.clone();
        let caller_clone = effective_caller;
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

    // If display_synw was provided, show it as the caller; otherwise encode the EVM address
    let caller_syna = if let Some(ref synw) = req.display_synw {
        synw.clone()
    } else {
        synq_vm::bech32::evm_to_syna(&caller_addr).unwrap_or_else(|_| hex_encode(&caller_addr))
    };
    eprintln!("[RUN] sid={} caller={} fn={} args_len={}", &req.session_id, caller_syna, req.function, vm_args.len());

    // ── Runtime fault injection (cosmic ray / Rowhammer simulation) ────────
    if let (Some(step), Some(offset), Some(mask)) = (req.fault_step, req.fault_byte_offset, req.fault_xor_mask) {
        eprintln!("[RUN] ⚡ fault injection enabled: step={} byte_offset={} xor_mask=0x{:02x}", step, offset, mask);
        session.vm.fault_injection = Some((step, offset, mask));
    }

    // Ensure per-session step limit is applied (in case VM was reset)
    session.vm.max_steps = session.max_steps;
    let call_result = session.vm.call_function(&req.function, &vm_args);
    eprintln!("[RUN] result={:?}", call_result);
    // ACTS-VM-005: read fuel consumption after the call
    let (fuel_used, fuel_remaining) = if FUEL_REPORTING {
        (Some(session.vm.fuel_used()), Some(session.vm.fuel_remaining()))
    } else {
        (None, None)
    };
    // ACTS-VM-003: read step consumption after the call
    let (steps_used, steps_remaining) = if FUEL_REPORTING {
        (Some(session.vm.steps_used()), Some(session.vm.steps_remaining()))
    } else {
        (None, None)
    };
    session.vm.call_context = synq_vm::CallContext::anonymous();
    let raw_log = std::mem::take(&mut session.vm.print_log);
    session.last_used = Instant::now();
    // Extract return-type hint before session is moved into the store.
    let declared_ret_owned: Option<String> = session.fn_return_types.get(&req.function).cloned();
    { state.sessions.lock().unwrap().insert(req.session_id, session); }
    let event_logs = parse_event_logs(&raw_log);

    match call_result {
        Ok(maybe_val) => {
            let declared_ret = declared_ret_owned.as_deref();
            let (result_json, output) = match &maybe_val {
                Some(v) => (Some(value_to_json_typed(v, declared_ret)), format!("Return value: {}", value_display(v))),
                None    => (None, "Function completed (no return value)".to_string()),
            };
            {
        let caller_syna = if let Some(ref synw) = req.display_synw { Some(synw.clone()) } else { synq_vm::bech32::evm_to_syna(&caller_addr).ok() };
        (StatusCode::OK, RespJson(RunResponse { success: true, result: result_json, output, events: event_logs, error: None, error_code: None, error_name: None, caller_syna, fuel_used, fuel_remaining, steps_used, steps_remaining }))
    }
        }
        Err(synq_vm::VMError::RevertedNamed { code, message }) => (StatusCode::OK, RespJson(RunResponse {
            success: false, result: None, output: String::new(),
            events: Vec::new(),
            error: Some(format!("revert: {}", message)),
            caller_syna: req.display_synw.clone().or_else(|| synq_vm::bech32::evm_to_syna(&caller_addr).ok()),
            error_code: Some(code),
            error_name: Some(message.split('(').next().unwrap_or(&message).split("::").last().unwrap_or(&message).to_string()),
            fuel_used, fuel_remaining, steps_used, steps_remaining,
        })),
        Err(synq_vm::VMError::Reverted(msg)) => (StatusCode::OK, RespJson(RunResponse {
            success: false, result: None, output: String::new(),
            events: Vec::new(),
            error: Some(format!("require failed: {}", msg)),
        caller_syna: req.display_synw.clone().or_else(|| synq_vm::bech32::evm_to_syna(&caller_addr).ok()),
        error_code: None,
        error_name: None,
        fuel_used, fuel_remaining, steps_used, steps_remaining,
        })),
        Err(e) => (StatusCode::OK, RespJson(RunResponse {
            success: false, result: None, output: String::new(),
            events: Vec::new(),
            error: Some(format!("{}", e)),
        caller_syna: req.display_synw.clone().or_else(|| synq_vm::bech32::evm_to_syna(&caller_addr).ok()),
        error_code: None,
        error_name: None,
        fuel_used, fuel_remaining, steps_used, steps_remaining,
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
    let contract_name = session.contract_name.clone();
    let network_id = V3_NETWORK_ID;
    let chain_id = V3_CHAIN_ID;
    let domain_tag = V3_DOMAIN_CALL;
    (StatusCode::OK, RespJson(json!({
        "nonce": nonce_hex,
        "chainId": chain_id,
        "networkId": network_id,
        "domainTag": domain_tag,
        "contractName": contract_name,
        "eip712Type": "ContractCall(string callSignature,string sessionId,string nonce,string domainTag)",
        "eip712Domain": {
            "name": "SynQ",
            "version": "1",
            "chainId": chain_id,
            "verifyingContract": null
        }
    })))
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
            Some(Value::Str(s))   => json!(format!("0x{}", hex::encode(s.as_bytes()))),
            Some(Value::Bytes(b)) => json!(format!("0x{}", hex::encode(b))),
            Some(Value::Map(m))   => {
                let obj: serde_json::Map<String,serde_json::Value> = m.iter().map(|(k,v)| {
                    // Always hex-encode map keys — they are 32-byte BE integers
                    // (addresses, UMA hashes, etc.) and must not go through
                    // from_utf8_lossy which corrupts non-ASCII bytes.
                    // Strip leading zero bytes so 0x000...dead → 0xdead
                    let hex_full = hex_encode(k);
                    let stripped = hex_full.trim_start_matches('0');
                    let key_s = format!("0x{}", if stripped.is_empty() { "0" } else { stripped });
                    let val_j = match v {
                        Value::I32(n)   => json!(n),
                        Value::U128(n)  => json!(n.to_string()),
                        Value::U256(n)  => json!(n.to_string()),
                        Value::Bool(b)  => json!(b),
                        Value::Str(s)   => json!(format!("0x{}", hex::encode(s.as_bytes()))),
                        Value::Bytes(b) => json!(hex_encode(b)),
                        _               => json!(null),
                    };
                    (key_s, val_j)
                }).collect();
                serde_json::Value::Object(obj)
            }
            Some(Value::Set(s))   => {
                let arr: Vec<serde_json::Value> = s.iter()
                    .map(|k| { let h = hex_encode(k); let s = h.trim_start_matches('0'); json!(format!("0x{}", if s.is_empty() { "0" } else { s })) })
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
                "note":        "Use this public key to verify ML-DSA-87 signatures in /compile and /attest sidecars (V3 account-domain).",
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


// ── Bench compile (loopback timing, no PQC signing, no rate-limit) ────────
#[derive(serde::Deserialize)]
struct BenchCompileRequest { source: String }

#[derive(serde::Serialize)]
struct BenchCompileResponse {
    success:        bool,
    parse_ns:       u64,   // nanoseconds spent in parser only
    codegen_ns:     u64,   // nanoseconds spent in codegen only
    total_ns:       u64,   // parse + codegen combined
    bytecode_bytes: usize, // output size (proves identical result)
    error:          Option<String>,
}

async fn bench_compile_handler(
    Json(req): Json<BenchCompileRequest>,
) -> RespJson<BenchCompileResponse> {
    use std::time::Instant;

    let t0 = Instant::now();
    let ast = match synq_compiler::parser::parse(&req.source) {
        Ok(a)  => a,
        Err(e) => return RespJson(BenchCompileResponse {
            success: false, parse_ns: t0.elapsed().as_nanos() as u64,
            codegen_ns: 0, total_ns: t0.elapsed().as_nanos() as u64,
            bytecode_bytes: 0, error: Some(format!("Parse error: {}", e)),

        }),
    };
    let parse_ns = t0.elapsed().as_nanos() as u64;

    let t1 = Instant::now();
    let bench_result = match synq_compiler::compile_ir(&req.source) {
        Ok(r)  => r,
        Err(e) => return RespJson(BenchCompileResponse {
            success: false, parse_ns,
            codegen_ns: t1.elapsed().as_nanos() as u64,
            total_ns: t0.elapsed().as_nanos() as u64,
            bytecode_bytes: 0, error: Some(format!("Compilation error: {}", e)),

        }),
    };
    let bytecode = bench_result.bytecode;
    let codegen_ns = t1.elapsed().as_nanos() as u64;

    RespJson(BenchCompileResponse {
        success: true,
        parse_ns,
        codegen_ns,
        total_ns: parse_ns + codegen_ns,
        bytecode_bytes: bytecode.len(),
        error: None,

    })
}


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

#[derive(serde::Deserialize)]
struct DebugEcrecoverRequest { hash: String, signature: String }
#[derive(serde::Serialize)]
struct DebugEcrecoverResponse { recovered: String, error: Option<String> }

async fn debug_ecrecover_handler(
    Json(req): Json<DebugEcrecoverRequest>,
) -> axum::Json<DebugEcrecoverResponse> {
    let hash_bytes = match hex_decode_strict(req.hash.trim_start_matches("0x")) {
        Ok(b) if b.len() == 32 => b,
        _ => return axum::Json(DebugEcrecoverResponse { recovered: String::new(), error: Some("hash must be 32 hex bytes".into()) }),
    };
    let sig_bytes = match hex_decode_strict(req.signature.trim_start_matches("0x")) {
        Ok(b) if b.len() == 65 => b,
        _ => return axum::Json(DebugEcrecoverResponse { recovered: String::new(), error: Some("sig must be 65 hex bytes".into()) }),
    };
    let hash: [u8; 32] = hash_bytes.try_into().unwrap();
    match ecrecover(&hash, &sig_bytes) {
        Ok(addr) => axum::Json(DebugEcrecoverResponse { recovered: format!("0x{}", hex_encode(&addr)), error: None }),
        Err(e)   => axum::Json(DebugEcrecoverResponse { recovered: String::new(), error: Some(e) }),
    }
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
    let wasm_runtime = {
        let path = std::env::var("SYNQ_WASM_PATH").unwrap_or_else(|_| {
            "/root/Downloads/synergy-testnet/SynQ/synq-compiler-wasm/target/wasm32-unknown-unknown/release/synq_compiler_wasm.wasm".to_string()
        });
        match wasm_compiler::WasmRuntime::new(&path) {
            Ok(rt) => { println!("  WASM runtime:   loaded from {}", path); Some(Arc::new(rt)) }
            Err(e) => { eprintln!("  WASM runtime:   FAILED: {}", e); None }
        }
    };
    let store = AppState { sessions, workspaces, rate_limiter, compiler_key, source_nonce_secret, wasm_runtime };

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
        .route("/pqc/test-vector",
        axum::routing::get(pqc_test_vector_handler))
    .route("/session/:id/state", get(session_state_handler))
        .route("/debug/ecrecover",   post(debug_ecrecover_handler))
        .route("/bench-compile",      post(bench_compile_handler))
        .route("/compile-wasm",     post(wasm_compiler::compile_wasm_handler))
        .route("/decompile",         post(decompile_handler))
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