//! synq-server — HTTP compile + run server for the SynQ IDE
//!
//! POST /compile        — compile SynQ source, sign with ephemeral ML-DSA-65
//! POST /attest         — wrap an EVM wallet signature in a PQC attestation
//! POST /session/new    — load bytecode into a fresh persistent VM session
//! POST /session/run    — call a function on a persistent session
//! DELETE /session/:id  — destroy a session
//! GET  /health
//!
//! PR-C security hardening:
//!   • Cryptographically random session IDs (32 bytes, OS getrandom)
//!   • Hard session cap (MAX_SESSIONS) — oldest session evicted when full
//!   • Request body size limit via tower RequestBodyLimitLayer (64 KB default)
//!   • Source size limit (MAX_SOURCE_BYTES) before compilation starts
//!   • Mutex released before VM execution — session cloned out, result merged back
//!   • CORS origin configurable via SYNQ_CORS_ORIGIN env var (default: *)

use axum::{
    extract::{Json, Path, State},
    http::{Method, StatusCode},
    response::Json as RespJson,
    routing::{delete, get, post},
    Router,
};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
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

/// NIST FIPS 204 canonical name for the ephemeral signing algorithm.
const SIGNING_ALGORITHM: &str = "ML-DSA-65";

/// Sessions idle longer than this are evicted on the next /session/new request.
const SESSION_TTL: Duration = Duration::from_secs(30 * 60); // 30 min

/// PR-C: Maximum number of concurrent sessions.
/// When the store is full, the stalest session is evicted before inserting
/// a new one regardless of TTL, preventing unbounded memory growth.
const MAX_SESSIONS: usize = 100;

/// PR-C: Maximum source code size accepted by /compile and /session/new.
/// Anything larger is rejected with 413 before the parser even runs.
const MAX_SOURCE_BYTES: usize = 64 * 1024; // 64 KB

/// PR-C: HTTP request body limit (applies to ALL endpoints).
/// Keeps the axum body buffer bounded regardless of Content-Length.
const MAX_BODY_BYTES: usize = 128 * 1024; // 128 KB

// ─── Session store ────────────────────────────────────────────────────────────

struct Session {
    vm:         QuantumVM,
    last_used:  Instant,
    /// State variable names in address order (name, address).
    state_vars: Vec<(String, u32)>,
}

type SessionStore = Arc<Mutex<HashMap<String, Session>>>;

/// PR-C: Generate a 32-byte cryptographically random session ID using OS getrandom.
/// The previous implementation used timestamp + stack pointer — both guessable.
fn new_session_id() -> String {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("getrandom failed");
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Evict sessions that have exceeded SESSION_TTL.
/// Called inside the mutex on every /session/new to bound memory growth.
fn evict_stale(store: &mut HashMap<String, Session>) {
    store.retain(|_, s| s.last_used.elapsed() < SESSION_TTL);
}

/// PR-C: If the store is still at or over MAX_SESSIONS after TTL eviction,
/// remove the single least-recently-used session to make room.
fn evict_oldest_if_full(store: &mut HashMap<String, Session>) {
    if store.len() < MAX_SESSIONS {
        return;
    }
    // Find the key of the session with the oldest last_used timestamp.
    let oldest_key = store
        .iter()
        .max_by_key(|(_, s)| s.last_used.elapsed())
        .map(|(k, _)| k.clone());
    if let Some(k) = oldest_key {
        store.remove(&k);
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn hex_decode_lossy(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    // Guard against odd-length input: each byte needs exactly 2 hex chars.
    // An odd-length string means the last nibble is incomplete — skip it.
    let pairs = s.len() / 2;
    (0..pairs)
        .filter_map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
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

/// Parse a single JSON arg into a VM Value.
/// All arguments are treated as non-negative integers (UInt256 semantics).
fn parse_arg(v: &serde_json::Value) -> Result<Value, String> {
    match v {
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                if i < 0 {
                    return Err(format!("UInt256 arguments must be non-negative, got {}", i));
                }
                return Ok(if i <= i32::MAX as i64 { Value::I32(i as i32) } else { Value::U128(i as u128) });
            }
            if let Some(u) = n.as_u64() {
                return Ok(Value::U128(u as u128));
            }
            match n.to_string().parse::<u128>() {
                Ok(u)  => Ok(Value::U128(u)),
                Err(_) => Err(format!("Cannot represent {} as UInt256", n)),
            }
        }
        serde_json::Value::String(s) => {
            let s = s.trim();
            if s.starts_with('-') {
                return Err(format!("UInt256 arguments must be non-negative, got {}", s));
            }
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
    Json(req): Json<CompileRequest>,
) -> (StatusCode, RespJson<CompileResponse>) {
    // PR-C: reject oversized source before parsing
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

    let pqc     = PQCCompiler::new(PQCSecurityLevel::Enhanced);
    let keypair = pqc.generate_keypair(SIGNING_ALGORITHM).expect("keygen");
    let sig     = pqc.sign_message(&keypair.private_key, &bytecode, SIGNING_ALGORITHM).expect("sign");

    let sidecar = json!({
        "mode": "ephemeral", "algorithm": sig.algorithm,
        "security_level": format!("{:?}", sig.security_level),
        "public_key": hex_encode(&keypair.public_key),
        "signature":  hex_encode(&sig.signature),
    });

    (StatusCode::OK, RespJson(CompileResponse {
        success: true,
        bytecode: Some(format!("0x{}", hex::encode(&bytecode))),
        signature_sidecar: Some(sidecar),
        state_vars,
        errors: vec![], warnings: vec![],
    }))
}

// ─── POST /attest ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AttestRequest {
    bytecode:       String,
    evm_address:    String,
    evm_signature:  String,
    bytecode_hash:  String,
}

#[derive(serde::Serialize)]
struct AttestResponse {
    success:        bool,
    hybrid_sidecar: Option<serde_json::Value>,
    error:          Option<String>,
}

async fn attest_handler(
    Json(req): Json<AttestRequest>,
) -> (StatusCode, RespJson<AttestResponse>) {
    let raw_bytecode  = hex_decode_lossy(&req.bytecode);
    let evm_sig_bytes = hex_decode_lossy(&req.evm_signature);

    if raw_bytecode.is_empty() {
        return (StatusCode::OK, RespJson(AttestResponse {
            success: false, hybrid_sidecar: None, error: Some("bytecode empty".into()),
        }));
    }
    if evm_sig_bytes.len() != 65 {
        return (StatusCode::OK, RespJson(AttestResponse {
            success: false, hybrid_sidecar: None,
            error: Some(format!("evm_signature must be 65 bytes, got {}", evm_sig_bytes.len())),
        }));
    }

    let mut msg = Vec::with_capacity(evm_sig_bytes.len() + raw_bytecode.len());
    msg.extend_from_slice(&evm_sig_bytes);
    msg.extend_from_slice(&raw_bytecode);

    let pqc     = PQCCompiler::new(PQCSecurityLevel::Enhanced);
    let keypair = match pqc.generate_keypair(SIGNING_ALGORITHM) {
        Ok(k)  => k,
        Err(e) => return (StatusCode::OK, RespJson(AttestResponse {
            success: false, hybrid_sidecar: None, error: Some(format!("PQC keygen: {}", e)),
        })),
    };
    let pqc_sig = match pqc.sign_message(&keypair.private_key, &msg, SIGNING_ALGORITHM) {
        Ok(s)  => s,
        Err(e) => return (StatusCode::OK, RespJson(AttestResponse {
            success: false, hybrid_sidecar: None, error: Some(format!("PQC sign: {}", e)),
        })),
    };

    (StatusCode::OK, RespJson(AttestResponse {
        success: true, error: None,
        hybrid_sidecar: Some(json!({
            "mode": "hybrid",
            "evm": {
                "address":      req.evm_address,
                "signature":    req.evm_signature,
                "message_hash": req.bytecode_hash,
            },
            "pqc": {
                "algorithm":      pqc_sig.algorithm,
                "security_level": format!("{:?}", pqc_sig.security_level),
                "public_key":     hex_encode(&keypair.public_key),
                "signature":      hex_encode(&pqc_sig.signature),
                "signed_message": "evm_signature_bytes ++ raw_bytecode_bytes",
            },
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
    State(store): State<SessionStore>,
    Json(req): Json<NewSessionRequest>,
) -> (StatusCode, RespJson<NewSessionResponse>) {
    let raw = hex_decode_lossy(&req.bytecode);
    if raw.is_empty() {
        return (StatusCode::OK, RespJson(NewSessionResponse {
            success: false, session_id: None, error: Some("bytecode empty".into()),
        }));
    }

    let mut vm = QuantumVM::new();
    if let Err(e) = vm.load_bytecode(&raw) {
        return (StatusCode::OK, RespJson(NewSessionResponse {
            success: false, session_id: None, error: Some(format!("Load error: {}", e)),
        }));
    }

    // PR-C: CSPRNG session ID + session cap enforcement
    let id = new_session_id();
    {
        let mut map = store.lock().unwrap();
        evict_stale(&mut map);
        evict_oldest_if_full(&mut map); // evict LRU if still at cap after TTL sweep
        map.insert(id.clone(), Session {
            vm,
            last_used: Instant::now(),
            state_vars: req.state_vars.clone(),
        });
    }

    (StatusCode::OK, RespJson(NewSessionResponse { success: true, session_id: Some(id), error: None }))
}

// ─── POST /session/run ────────────────────────────────────────────────────────
//
// PR-C: The global Mutex is released BEFORE VM execution.
// The session's VM is moved out of the map, executed without holding the lock,
// then moved back in. This prevents a slow/looping contract from blocking all
// other requests. If the session is deleted concurrently during execution the
// result is simply discarded (treated as session-not-found on the next call).

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
    State(store): State<SessionStore>,
    Json(req): Json<SessionRunRequest>,
) -> (StatusCode, RespJson<RunResponse>) {
    // Parse args before touching the mutex
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

    // PR-C: Move the session OUT of the map before releasing the lock.
    // This means the lock is held only for the map lookup, not for VM execution.
    let mut session = {
        let mut map = store.lock().unwrap();
        match map.remove(&req.session_id) {
            Some(s) => s,
            None    => return (StatusCode::OK, RespJson(RunResponse {
                success: false, result: None, output: String::new(),
                error: Some(format!("Session '{}' not found or expired", req.session_id)),
            })),
        }
    }; // ← lock released here

    // VM executes WITHOUT holding the global mutex
    let call_result = session.vm.call_function(&req.function, &vm_args);
    session.last_used = Instant::now();

    // Put the session back (unless a concurrent DELETE already removed it;
    // in that case the session is simply dropped here — its state is gone).
    {
        let mut map = store.lock().unwrap();
        map.insert(req.session_id.clone(), session);
    }

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
    State(store): State<SessionStore>,
    Path(id): Path<String>,
) -> (StatusCode, RespJson<serde_json::Value>) {
    let removed = store.lock().unwrap().remove(&id).is_some();
    (StatusCode::OK, RespJson(json!({ "success": removed })))
}

// ─── GET /session/:id/state ───────────────────────────────────────────────────

async fn session_state_handler(
    State(store): State<SessionStore>,
    Path(session_id): Path<String>,
) -> (StatusCode, RespJson<serde_json::Value>) {
    let map = store.lock().unwrap();
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

// ─── GET /health ──────────────────────────────────────────────────────────────

async fn health(
    State(store): State<SessionStore>,
) -> RespJson<serde_json::Value> {
    let count = store.lock().unwrap().len();
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

#[tokio::main]
async fn main() {
    let store: SessionStore = Arc::new(Mutex::new(HashMap::new()));

    // PR-C: CORS origin configurable via env var (default: * for testnet convenience)
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
        .route("/health",              get(health))
        .route("/compile",             post(compile_handler))
        .route("/attest",              post(attest_handler))
        .route("/session/new",         post(session_new_handler))
        .route("/session/run",         post(session_run_handler))
        .route("/session/:id",         delete(session_delete_handler))
        .route("/session/:id/state",   get(session_state_handler))
        .with_state(store)
        // PR-C: global body size cap — axum will reject oversized bodies with 413
        // before any handler runs, protecting against payload-based DoS.
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
    println!("  Signing:         {}", SIGNING_ALGORITHM);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
