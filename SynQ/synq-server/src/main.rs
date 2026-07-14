//! synq-server — HTTP compile + run server for the SynQ IDE
//!
//! POST /compile  — compile SynQ source, sign with ephemeral ML-DSA-65
//! POST /attest   — wrap an EVM wallet signature in a Dilithium attestation
//! POST /run      — execute a compiled .qvm bytecode, calling a named function
//! GET  /health

use axum::{
    extract::Json,
    http::{Method, StatusCode},
    response::Json as RespJson,
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use serde_json::json;
use tower_http::cors::{Any, CorsLayer};
use synq_compiler::{PQCCompiler, PQCSecurityLevel};
use synq_vm::{QuantumVM, Value};

const SIGNING_ALGORITHM: &str = "dilithium";

// ─── helpers ─────────────────────────────────────────────────────────────────

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn hex_decode_lossy(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len()).step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i+2], 16).ok())
        .collect()
}

fn value_to_json(v: &Value) -> serde_json::Value {
    match v {
        Value::I32(n)   => json!({"type": "I32",  "value": n}),
        Value::I64(n)   => json!({"type": "I64",  "value": n.to_string()}),
        Value::U128(n)  => json!({"type": "U128", "value": n.to_string()}),
        Value::Bool(b)  => json!({"type": "Bool", "value": b}),
        Value::Bytes(b) => json!({"type": "Bytes","value": hex_encode(b)}),
    }
}

// ─── /compile ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CompileRequest {
    source: String,
}

#[derive(serde::Serialize)]
struct CompileResponse {
    success: bool,
    bytecode: Option<String>,
    signature_sidecar: Option<serde_json::Value>,
    errors: Vec<String>,
    warnings: Vec<String>,
}

async fn compile_handler(
    Json(req): Json<CompileRequest>,
) -> (StatusCode, RespJson<CompileResponse>) {
    let ast = match synq_compiler::parser::parse(&req.source) {
        Ok(a) => a,
        Err(e) => {
            return (StatusCode::OK, RespJson(CompileResponse {
                success: false, bytecode: None, signature_sidecar: None,
                errors: vec![format!("Parse error: {}", e)], warnings: vec![],
            }));
        }
    };

    let codegen = synq_compiler::codegen::CodeGenerator::new();
    let bytecode = match codegen.generate(&ast) {
        Ok(b) => b,
        Err(e) => {
            return (StatusCode::OK, RespJson(CompileResponse {
                success: false, bytecode: None, signature_sidecar: None,
                errors: vec![format!("Codegen error: {}", e)], warnings: vec![],
            }));
        }
    };

    let pqc = PQCCompiler::new(PQCSecurityLevel::Enhanced);
    let keypair = pqc.generate_keypair(SIGNING_ALGORITHM).expect("keygen failed");
    let sig = pqc.sign_message(&keypair.private_key, &bytecode, SIGNING_ALGORITHM)
                 .expect("signing failed");

    let sidecar = json!({
        "mode":           "ephemeral",
        "algorithm":      sig.algorithm,
        "security_level": format!("{:?}", sig.security_level),
        "public_key":     hex_encode(&keypair.public_key),
        "signature":      hex_encode(&sig.signature),
    });

    (StatusCode::OK, RespJson(CompileResponse {
        success: true,
        bytecode: Some(format!("0x{}", hex::encode(&bytecode))),
        signature_sidecar: Some(sidecar),
        errors: vec![], warnings: vec![],
    }))
}

// ─── /attest ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AttestRequest {
    bytecode:      String,
    evm_address:   String,
    evm_signature: String,
    bytecode_hash: String,
}

#[derive(serde::Serialize)]
struct AttestResponse {
    success: bool,
    hybrid_sidecar: Option<serde_json::Value>,
    error: Option<String>,
}

async fn attest_handler(
    Json(req): Json<AttestRequest>,
) -> (StatusCode, RespJson<AttestResponse>) {
    let raw_bytecode = hex_decode_lossy(&req.bytecode);
    if raw_bytecode.is_empty() {
        return (StatusCode::OK, RespJson(AttestResponse {
            success: false, hybrid_sidecar: None,
            error: Some("bytecode is empty or invalid hex".into()),
        }));
    }

    let evm_sig_bytes = hex_decode_lossy(&req.evm_signature);
    if evm_sig_bytes.len() != 65 {
        return (StatusCode::OK, RespJson(AttestResponse {
            success: false, hybrid_sidecar: None,
            error: Some(format!("evm_signature must be 65 bytes, got {}", evm_sig_bytes.len())),
        }));
    }

    let mut pqc_message = Vec::with_capacity(evm_sig_bytes.len() + raw_bytecode.len());
    pqc_message.extend_from_slice(&evm_sig_bytes);
    pqc_message.extend_from_slice(&raw_bytecode);

    let pqc = PQCCompiler::new(PQCSecurityLevel::Enhanced);
    let keypair = match pqc.generate_keypair(SIGNING_ALGORITHM) {
        Ok(k) => k,
        Err(e) => return (StatusCode::OK, RespJson(AttestResponse {
            success: false, hybrid_sidecar: None,
            error: Some(format!("PQC keygen failed: {}", e)),
        })),
    };
    let pqc_sig = match pqc.sign_message(&keypair.private_key, &pqc_message, SIGNING_ALGORITHM) {
        Ok(s) => s,
        Err(e) => return (StatusCode::OK, RespJson(AttestResponse {
            success: false, hybrid_sidecar: None,
            error: Some(format!("PQC signing failed: {}", e)),
        })),
    };

    let hybrid = json!({
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
        }
    });

    (StatusCode::OK, RespJson(AttestResponse {
        success: true, hybrid_sidecar: Some(hybrid), error: None,
    }))
}

// ─── /run ────────────────────────────────────────────────────────────────────
//
// POST /run
// Body: { bytecode: "0x...", function: "mint", args: [1000] }
//
// Loads the bytecode into a fresh QVM instance, calls the named function
// with the supplied integer arguments, and returns the result.
//
// Each call starts a fresh VM (stateless per request). State persistence
// across calls is not yet supported server-side — use the CLI for that.

#[derive(Deserialize)]
struct RunRequest {
    bytecode: String,         // 0x-prefixed hex
    function: String,         // function name from dispatch table
    args: Option<Vec<i64>>,   // integer arguments (mapped to I32 or U128 by value)
}

#[derive(serde::Serialize)]
struct RunResponse {
    success: bool,
    result:  Option<serde_json::Value>,   // Value returned by the function
    output:  String,                      // human-readable summary
    error:   Option<String>,
}

async fn run_handler(
    Json(req): Json<RunRequest>,
) -> (StatusCode, RespJson<RunResponse>) {
    let raw = hex_decode_lossy(&req.bytecode);
    if raw.len() < 15 {
        return (StatusCode::OK, RespJson(RunResponse {
            success: false, result: None,
            output: String::new(),
            error: Some("bytecode too short or invalid".into()),
        }));
    }

    let mut vm = QuantumVM::new();
    if let Err(e) = vm.load_bytecode(&raw) {
        return (StatusCode::OK, RespJson(RunResponse {
            success: false, result: None, output: String::new(),
            error: Some(format!("Failed to load bytecode: {}", e)),
        }));
    }

    // Map supplied integers to VM Values.
    // Values that fit in i32 stay as I32 (most common); larger values promoted to U128.
    let vm_args: Vec<Value> = req.args.unwrap_or_default().iter().map(|&n| {
        if n >= i32::MIN as i64 && n <= i32::MAX as i64 {
            Value::I32(n as i32)
        } else {
            Value::U128(n as u128)
        }
    }).collect();

    match vm.call_function(&req.function, &vm_args) {
        Ok(maybe_val) => {
            let (result_json, output) = match &maybe_val {
                Some(v) => (Some(value_to_json(v)), format!("Return value: {}", value_display(v))),
                None    => (None, "Function completed (no return value)".to_string()),
            };
            (StatusCode::OK, RespJson(RunResponse {
                success: true, result: result_json, output, error: None,
            }))
        }
        Err(e) => {
            (StatusCode::OK, RespJson(RunResponse {
                success: false, result: None, output: String::new(),
                error: Some(format!("Runtime error: {}", e)),
            }))
        }
    }
}

fn value_display(v: &Value) -> String {
    match v {
        Value::I32(n)   => n.to_string(),
        Value::I64(n)   => n.to_string(),
        Value::U128(n)  => n.to_string(),
        Value::Bool(b)  => b.to_string(),
        Value::Bytes(b) => format!("0x{}", hex_encode(b)),
    }
}

// ─── /health ─────────────────────────────────────────────────────────────────

async fn health() -> RespJson<serde_json::Value> {
    RespJson(json!({"status": "ok", "service": "synq-compiler"}))
}

// ─── main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any)
        .allow_origin(Any);

    let app = Router::new()
        .route("/health",  get(health))
        .route("/compile", post(compile_handler))
        .route("/attest",  post(attest_handler))
        .route("/run",     post(run_handler))
        .layer(cors);

    let addr = "0.0.0.0:3030";
    println!("SynQ compile server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
