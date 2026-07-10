//! synq-server — HTTP compile server for the SynQ IDE
//!
//! Exposes POST /compile: compiles SynQ source, signs the bytecode with an
//! ephemeral ML-DSA-65 keypair, and returns bytecode + signature_sidecar in
//! the response (same .sig.json format as synq-cli produces).

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

#[derive(Deserialize)]
struct CompileRequest {
    source: String,
}

#[derive(serde::Serialize)]
struct CompileResponse {
    success: bool,
    /// Hex-encoded bytecode prefixed with "0x" on success.
    bytecode: Option<String>,
    /// Signature sidecar matching the .sig.json format produced by synq-cli.
    /// Present only on success; download alongside the .qvm for local verify.
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
    // ── Parse ────────────────────────────────────────────────────────────────
    let ast = match synq_compiler::parser::parse(&req.source) {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::OK,
                RespJson(CompileResponse {
                    success: false,
                    bytecode: None,
                    signature_sidecar: None,
                    errors: vec![format!("Parse error: {}", e)],
                    warnings: vec![],
                }),
            );
        }
    };

    // ── Codegen ──────────────────────────────────────────────────────────────
    let codegen = synq_compiler::codegen::CodeGenerator::new();
    let bytecode = match codegen.generate(&ast) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::OK,
                RespJson(CompileResponse {
                    success: false,
                    bytecode: None,
                    signature_sidecar: None,
                    errors: vec![format!("Codegen error: {}", e)],
                    warnings: vec![],
                }),
            );
        }
    };

    // ── Sign with ephemeral ML-DSA-65 keypair ────────────────────────────────
    // Private key is never persisted; public key + signature are returned in
    // the response so the caller can store a .sig.json sidecar alongside the
    // downloaded .qvm and run `synq-cli verify` against it locally.
    let pqc = PQCCompiler::new(PQCSecurityLevel::Enhanced);
    let keypair = pqc
        .generate_keypair(SIGNING_ALGORITHM)
        .expect("ML-DSA-65 keygen failed");
    let sig = pqc
        .sign_message(&keypair.private_key, &bytecode, SIGNING_ALGORITHM)
        .expect("ML-DSA-65 signing failed");

    let sidecar = json!({
        "algorithm":      sig.algorithm,
        "security_level": format!("{:?}", sig.security_level),
        "public_key":     hex_encode(&keypair.public_key),
        "signature":      hex_encode(&sig.signature),
    });

    let hex_bytecode = format!("0x{}", hex::encode(&bytecode));

    (
        StatusCode::OK,
        RespJson(CompileResponse {
            success: true,
            bytecode: Some(hex_bytecode),
            signature_sidecar: Some(sidecar),
            errors: vec![],
            warnings: vec![],
        }),
    )
}

async fn health() -> RespJson<serde_json::Value> {
    RespJson(json!({"status": "ok", "service": "synq-compiler"}))
}

#[tokio::main]
async fn main() {
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any)
        .allow_origin(Any);

    let app = Router::new()
        .route("/health", get(health))
        .route("/compile", post(compile_handler))
        .layer(cors);

    let addr = "0.0.0.0:3030";
    println!("SynQ compile server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
