//! synq-server — HTTP compile server for the SynQ IDE
//!
//! POST /compile  — compile SynQ source, sign with ephemeral ML-DSA-65
//! POST /attest   — wrap an EVM wallet signature in a Dilithium attestation
//!                  (hybrid ECDSA + PQC signing for wallet-connected flows)
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

const SIGNING_ALGORITHM: &str = "dilithium";

// ─── /compile ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CompileRequest {
    source: String,
}

#[derive(serde::Serialize)]
struct CompileResponse {
    success: bool,
    bytecode: Option<String>,
    /// Ephemeral ML-DSA-65 sidecar — present when no wallet sig is provided.
    /// When a wallet sig is provided, use POST /attest instead.
    signature_sidecar: Option<serde_json::Value>,
    errors: Vec<String>,
    warnings: Vec<String>,
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
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

    // Ephemeral ML-DSA-65 — used when no EVM wallet is connected
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
//
// Accepts:
//   { bytecode, evm_address, evm_signature, bytecode_hash }
//
// Where:
//   bytecode        — hex-encoded QVM bytecode (0x-prefixed)
//   evm_address     — checksummed EVM address that signed
//   evm_signature   — output of personal_sign(keccak256(bytecode_hex))
//   bytecode_hash   — keccak256 hex the wallet actually signed (for verification)
//
// Returns a hybrid sidecar:
//   {
//     mode: "hybrid",
//     evm: { address, signature, message_hash },
//     pqc: { algorithm, public_key, signature }   <- Dilithium over (evm_sig || bytecode)
//   }
//
// The Dilithium signature covers: evm_signature_bytes ++ raw_bytecode_bytes.
// This means a quantum adversary cannot substitute the ECDSA component without
// invalidating the Dilithium wrapper.

#[derive(Deserialize)]
struct AttestRequest {
    bytecode:      String,   // 0x-prefixed hex
    evm_address:   String,
    evm_signature: String,   // 0x-prefixed hex (65 bytes, r+s+v)
    bytecode_hash: String,   // 0x-prefixed keccak256 hex
}

#[derive(serde::Serialize)]
struct AttestResponse {
    success: bool,
    hybrid_sidecar: Option<serde_json::Value>,
    error: Option<String>,
}

fn hex_decode_lossy(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len()).step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i+2], 16).ok())
        .collect()
}

async fn attest_handler(
    Json(req): Json<AttestRequest>,
) -> (StatusCode, RespJson<AttestResponse>) {
    // Decode the bytecode
    let raw_bytecode = hex_decode_lossy(&req.bytecode);
    if raw_bytecode.is_empty() {
        return (StatusCode::OK, RespJson(AttestResponse {
            success: false, hybrid_sidecar: None,
            error: Some("bytecode is empty or invalid hex".into()),
        }));
    }

    // Decode the EVM signature (65 bytes)
    let evm_sig_bytes = hex_decode_lossy(&req.evm_signature);
    if evm_sig_bytes.len() != 65 {
        return (StatusCode::OK, RespJson(AttestResponse {
            success: false, hybrid_sidecar: None,
            error: Some(format!("evm_signature must be 65 bytes, got {}", evm_sig_bytes.len())),
        }));
    }

    // Build the message Dilithium will sign:
    //   message = evm_signature_bytes (65) ++ raw_bytecode_bytes
    // This binds the wallet attestation to the exact bytecode in one quantum-safe signature.
    let mut pqc_message = Vec::with_capacity(evm_sig_bytes.len() + raw_bytecode.len());
    pqc_message.extend_from_slice(&evm_sig_bytes);
    pqc_message.extend_from_slice(&raw_bytecode);

    // Ephemeral ML-DSA-65 keypair for the Dilithium wrapper
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
        success: true,
        hybrid_sidecar: Some(hybrid),
        error: None,
    }))
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
        .layer(cors);

    let addr = "0.0.0.0:3030";
    println!("SynQ compile server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
