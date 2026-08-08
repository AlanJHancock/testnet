//! AIVM compile handler — compiles SynQ source to spec-compliant AIVM bytecode

use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use synq_compiler::parser;
use synq_compiler::ast::SourceUnit;
use synq_compiler::aivm_codegen::compile_to_aivm;

use aivm::bytecode::{BytecodeArtifact, Section, section_type};
use aivm::manifest::Manifest;
use aivm::instructions::Instruction;

use crate::{AppState, check_rate_limit, RespJson, MAX_SOURCE_BYTES};

/// Request for AIVM compilation
#[derive(Debug, Deserialize)]
pub struct CompileAivmRequest {
    pub source: String,
}

/// Response for AIVM compilation
#[derive(Debug, Serialize)]
pub struct CompileAivmResponse {
    pub success: bool,
    pub contract_name: Option<String>,
    pub bytecode_hex: Option<String>,
    pub abi: Option<serde_json::Value>,
    pub abi_hash: Option<String>,
    pub manifest: Option<serde_json::Value>,
    pub manifest_hash: Option<String>,
    pub code_hash: Option<String>,
    pub functions: Vec<AivmFunctionInfo>,
    pub state_vars: Vec<AivmStateVarInfo>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AivmFunctionInfo {
    pub name: String,
    pub selector: String,
    pub visibility: String,
    pub mutability: String,
    pub param_count: u16,
}

#[derive(Debug, Serialize)]
pub struct AivmStateVarInfo {
    pub name: String,
    pub key_index: u16,
    pub abi_type: String,
}

/// Handle AIVM compilation request
pub async fn compile_aivm_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(req): Json<CompileAivmRequest>,
) -> (StatusCode, RespJson<CompileAivmResponse>) {
    let err_resp = |errors: Vec<String>| -> (StatusCode, RespJson<CompileAivmResponse>) {
        (StatusCode::OK, RespJson(CompileAivmResponse {
            success: false,
            contract_name: None,
            bytecode_hex: None,
            abi: None,
            abi_hash: None,
            manifest: None,
            manifest_hash: None,
            code_hash: None,
            functions: vec![],
            state_vars: vec![],
            warnings: vec![],
            errors,
        }))
    };

    // Rate limit
    if let Err(wait) = check_rate_limit(&state.rate_limiter, addr.ip()) {
        return err_resp(vec![format!("rate limit exceeded — retry in {}s", wait)]);
    }

    if req.source.len() > MAX_SOURCE_BYTES {
        return err_resp(vec![format!("Source too large: {} bytes (max {})", req.source.len(), MAX_SOURCE_BYTES)]);
    }

    // Parse
    let ast = match parser::parse(&req.source) {
        Ok(a) => a,
        Err(e) => return err_resp(vec![format!("Parse error: {}", e)]),
    };

    // Extract contract
    let contract = match ast.iter().find_map(|u| {
        if let SourceUnit::Contract(c) = u { Some(c) } else { None }
    }) {
        Some(c) => c,
        None => return err_resp(vec!["No contract found in source".to_string()]),
    };

    // Compile to AIVM
    let result = match compile_to_aivm(contract) {
        Ok(r) => r,
        Err(e) => return err_resp(vec![format!("AIVM compilation error: {}", e)]),
    };

    // Build canonical ABI
    let abi_canonical = result.abi.canonical_json();
    let abi_hash = result.abi.hash();
    let abi_json: serde_json::Value = serde_json::from_slice(&abi_canonical).unwrap_or(serde_json::json!({}));

    // Build manifest
    let manifest = Manifest::testnet_default(&contract.name, "0.1.0");
    let manifest_canonical = manifest.canonical_json();
    let manifest_hash = manifest.hash();
    let manifest_json: serde_json::Value = serde_json::from_slice(&manifest_canonical).unwrap_or(serde_json::json!({}));

    // Build instruction bytes
    let instruction_bytes = Instruction::encode_all(&result.instructions);

    // Build SYNQ bytecode artifact (first pass — manifest bytecode_hash is placeholder)
    let artifact = BytecodeArtifact::build(
        &abi_canonical,
        &manifest_canonical,
        &instruction_bytes,
        vec![
            Section { section_type: section_type::CONSTANTS, data: vec![] },
            Section { section_type: section_type::FUNCTIONS, data: vec![] },
            Section { section_type: section_type::EXPORTS, data: vec![] },
        ],
    );
    let final_bytecode = artifact.encode();
    let code_hash = format!("0x{}", hex::encode(&artifact.header.code_hash));

    // Build function info
    let functions: Vec<AivmFunctionInfo> = result.functions.iter().map(|f| {
        let selector = result.abi.methods.iter()
            .find(|m| m.name == f.name)
            .map(|m| m.selector.clone())
            .unwrap_or_else(|| "0x00000000".to_string());
        AivmFunctionInfo {
            name: f.name.clone(),
            selector,
            visibility: if f.visibility == aivm::vm::FunctionVisibility::Public { "public" } else { "private" }.to_string(),
            mutability: if f.mutability == aivm::vm::FunctionMutability::View { "view" } else { "write" }.to_string(),
            param_count: f.param_count,
        }
    }).collect();

    // Build state var info
    let state_vars: Vec<AivmStateVarInfo> = result.state_var_map.iter().map(|(name, idx)| {
        let abi_type = result.abi.state_schema.iter()
            .find(|s| s.name == *name)
            .map(|s| s.field_type.type_string())
            .unwrap_or("u64".to_string());
        AivmStateVarInfo {
            name: name.clone(),
            key_index: *idx,
            abi_type,
        }
    }).collect();

    (StatusCode::OK, RespJson(CompileAivmResponse {
        success: true,
        contract_name: Some(contract.name.clone()),
        bytecode_hex: Some(hex::encode(&final_bytecode)),
        abi: Some(abi_json),
        abi_hash: Some(format!("0x{}", hex::encode(&abi_hash))),
        manifest: Some(manifest_json),
        manifest_hash: Some(format!("0x{}", hex::encode(&manifest_hash))),
        code_hash: Some(code_hash),
        functions,
        state_vars,
        warnings: result.warnings,
        errors: vec![],
    }))
}
