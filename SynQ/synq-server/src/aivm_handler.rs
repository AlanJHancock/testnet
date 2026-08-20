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

// ─── POST /aivm/estimate-gas ───────────────────────────────────────────────
// Real dry-run gas estimate: compiles the contract, executes the target
// function once against a throwaway StateOverlay via the real AIVM
// interpreter (real per-opcode weighted GasMeter/PqGasMeter), and reports
// gas_used / pq_gas_used. The overlay is never persisted anywhere — there is
// no session, no commit path wired to storage — so "estimate" here means
// exactly what it should: run it for real, measure it, throw the state away.
// This deliberately does NOT try to estimate gas *price* — there is no gas
// oracle on Synergy testnet (see atlas.synergy-network.io/gas methodology),
// and price is an economic/fee-market question, not an execution-cost one.

/// Request for a dry-run gas estimate
#[derive(Debug, Deserialize)]
pub struct EstimateGasRequest {
    pub source: String,
    pub function: String,
    #[serde(default)]
    pub args: Vec<serde_json::Value>,
    /// Optional pre-seeded state, keyed by state slot index as a string, e.g. {"0": 42}
    #[serde(default)]
    pub state: std::collections::HashMap<String, serde_json::Value>,
    /// Optional caller address (0x-prefixed, 41 bytes hex) to run the dry-run
    /// as. Needed to exercise @authority / @governance / "as caller" gated
    /// functions -- without this every dry-run executes as the zero address.
    #[serde(default)]
    pub caller: Option<String>,
}

/// Response for a dry-run gas estimate
#[derive(Debug, Serialize)]
pub struct EstimateGasResponse {
    pub success: bool,
    pub function: Option<String>,
    pub caller: Option<String>,
    pub status: Option<String>,
    pub gas_used: Option<u64>,
    pub pq_gas_used: Option<u64>,
    pub gas_limit: Option<u64>,
    pub pq_gas_limit: Option<u64>,
    pub return_value: Option<serde_json::Value>,
    pub events: Vec<serde_json::Value>,
    pub state_discarded: bool,
    pub note: String,
    pub errors: Vec<String>,
}

fn parse_caller_address(s: &str) -> Result<[u8; 41], String> {
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid caller hex: {}", e))?;
    if bytes.len() != 41 {
        return Err(format!("caller address must be 41 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 41];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn json_to_aivm_value(v: &serde_json::Value) -> Result<aivm::host::Value, String> {
    use aivm::host::Value;
    match v {
        serde_json::Value::Bool(b) => Ok(Value::Bool(*b)),
        serde_json::Value::Number(n) => {
            n.as_u64().map(Value::U64).ok_or_else(|| format!("unsupported number: {}", n))
        }
        serde_json::Value::String(s) => {
            if let Some(hex_str) = s.strip_prefix("0x") {
                let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {}", e))?;
                if bytes.len() == 41 {
                    let mut arr = [0u8; 41];
                    arr.copy_from_slice(&bytes);
                    Ok(Value::Address(arr))
                } else if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Ok(Value::Bytes32(arr))
                } else {
                    Ok(Value::Bytes(bytes))
                }
            } else {
                Ok(Value::String(s.clone()))
            }
        }
        other => Err(format!("unsupported arg type: {}", other)),
    }
}

fn aivm_value_to_json(v: &aivm::host::Value) -> serde_json::Value {
    use aivm::host::Value;
    match v {
        Value::U64(n) => serde_json::json!(n),
        Value::U128(n) => serde_json::json!(n.to_string()),
        Value::I64(n) => serde_json::json!(n),
        Value::Bool(b) => serde_json::json!(b),
        Value::Bytes(b) => serde_json::json!(format!("0x{}", hex::encode(b))),
        Value::Bytes32(b) => serde_json::json!(format!("0x{}", hex::encode(b))),
        Value::Address(b) => serde_json::json!(format!("0x{}", hex::encode(b))),
        Value::String(s) => serde_json::json!(s),
        Value::Array(arr) => serde_json::json!(arr.iter().map(aivm_value_to_json).collect::<Vec<_>>()),
    }
}

pub async fn estimate_gas_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    Json(req): Json<EstimateGasRequest>,
) -> (StatusCode, RespJson<EstimateGasResponse>) {
    let note = "Dry-run only: real AIVM execution + weighted gas metering, state never persisted. \
This is an execution-cost estimate, not a gas price — Synergy testnet has no gas oracle.".to_string();

    let err_resp = |errors: Vec<String>| -> (StatusCode, RespJson<EstimateGasResponse>) {
        (StatusCode::OK, RespJson(EstimateGasResponse {
            success: false,
            function: None,
            caller: None,
            status: None,
            gas_used: None,
            pq_gas_used: None,
            gas_limit: None,
            pq_gas_limit: None,
            return_value: None,
            events: vec![],
            state_discarded: true,
            note: note.clone(),
            errors,
        }))
    };

    if let Err(wait) = check_rate_limit(&state.rate_limiter, addr.ip()) {
        return err_resp(vec![format!("rate limit exceeded — retry in {}s", wait)]);
    }
    if req.source.len() > MAX_SOURCE_BYTES {
        return err_resp(vec![format!("Source too large: {} bytes (max {})", req.source.len(), MAX_SOURCE_BYTES)]);
    }

    // Backlog item 7: bound concurrent CPU-bound dry-runs independently of
    // per-IP rate limiting (see AppState::estimate_gas_semaphore doc comment).
    // try_acquire (not .acquire().await) so we fail fast with a clear error
    // instead of queuing this request behind other CPU-bound work.
    let _permit = match state.estimate_gas_semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return err_resp(vec![
            "server busy: too many concurrent gas estimations in flight — retry shortly".to_string()
        ]),
    };

    let ast = match parser::parse(&req.source) {
        Ok(a) => a,
        Err(e) => return err_resp(vec![format!("Parse error: {}", e)]),
    };
    let contract = match ast.iter().find_map(|u| if let SourceUnit::Contract(c) = u { Some(c) } else { None }) {
        Some(c) => c,
        None => return err_resp(vec!["No contract found in source".to_string()]),
    };
    let compiled = match compile_to_aivm(contract) {
        Ok(r) => r,
        Err(e) => return err_resp(vec![format!("AIVM compilation error: {}", e)]),
    };

    let host = aivm::host::HostFunctions::default_v01();
    let avm = aivm::vm::Avm::new(compiled.instructions, compiled.functions, host);

    let func_idx = match avm.find_function(&req.function) {
        Some(i) => i,
        None => return err_resp(vec![format!("function '{}' not found", req.function)]),
    };

    let mut args = Vec::with_capacity(req.args.len());
    for a in &req.args {
        match json_to_aivm_value(a) {
            Ok(v) => args.push(v),
            Err(e) => return err_resp(vec![format!("bad argument: {}", e)]),
        }
    }

    let mut seeded: std::collections::HashMap<u16, aivm::host::Value> = std::collections::HashMap::new();
    for (k, v) in &req.state {
        let key: u16 = match k.parse() {
            Ok(n) => n,
            Err(_) => return err_resp(vec![format!("bad state key: {}", k)]),
        };
        match json_to_aivm_value(v) {
            Ok(val) => { seeded.insert(key, val); }
            Err(e) => return err_resp(vec![format!("bad state value: {}", e)]),
        }
    }

    let caller = match &req.caller {
        Some(s) if !s.is_empty() => match parse_caller_address(s) {
            Ok(addr) => addr,
            Err(e) => return err_resp(vec![format!("bad caller: {}", e)]),
        },
        _ => [0u8; 41],
    };
    let ctx = aivm::context::ExecutionContext::testnet(caller, [0u8; 41]);
    // This overlay is local to the request and is dropped at the end of this
    // function. avm.execute() may internally .commit() it on success — that
    // only merges staged writes into THIS in-memory overlay's own map, which
    // is about to be discarded. Nothing is written to any session, file, or
    // persistent store. That's the entire "dry run" mechanism.
    let mut overlay = aivm::vm::StateOverlay::with_state(seeded);

    match avm.execute(func_idx, args, &ctx, &mut overlay) {
        Ok(result) => {
            let status = match result.receipt.status {
                aivm::receipt::ReceiptStatus::Success => "success",
                aivm::receipt::ReceiptStatus::Reverted => "reverted",
                aivm::receipt::ReceiptStatus::Failed => "failed",
            };
            let events: Vec<serde_json::Value> = result.receipt.events.iter().map(|e| serde_json::json!({
                "event_index": e.event_index,
                "topic_hash": format!("0x{}", hex::encode(e.topic_hash)),
                "data": format!("0x{}", hex::encode(&e.data)),
            })).collect();
            (StatusCode::OK, RespJson(EstimateGasResponse {
                success: true,
                function: Some(req.function.clone()),
                caller: Some(format!("0x{}", hex::encode(caller))),
                status: Some(status.to_string()),
                gas_used: Some(result.receipt.gas_used),
                pq_gas_used: Some(result.receipt.pq_gas_used),
                gas_limit: Some(ctx.gas_limit),
                pq_gas_limit: Some(ctx.pq_gas_limit),
                return_value: result.return_value.as_ref().map(aivm_value_to_json),
                events,
                state_discarded: true,
                note,
                errors: vec![],
            }))
        }
        Err(e) => err_resp(vec![format!("execution error: {}", e)]),
    }
}


// ─── Unit/integration tests: estimate_gas_handler (gas/fee estimator backlog item 13) ─
//
// Calls the handler function directly (real extractors: ConnectInfo,
// State, Json) rather than standing up the full axum Router -- main.rs's
// router is built inline inside `main()` with dozens of handler fns
// declared as local items scoped to that function body, so it can't be
// reused from an external test harness without a much larger refactor.
// Calling the handler directly still exercises all the real logic that
// matters for regressions: rate limiting, size limits, the item-7
// concurrency guard, real AIVM compilation + execution, gas/pq-gas
// metering, and the no-persistence guarantee. It only skips the generic
// axum middleware (CORS, body-size layer) that isn't estimator-specific.
#[cfg(test)]
mod estimate_gas_handler_tests {
    use super::*;
    use crate::{AppState, CompilerKey};
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    const COUNTER_SRC: &str = "contract Counter { state { counter: u256; } impl { @public function increment() -> u256 { counter = counter + 1; return counter; } } }";

    fn test_state() -> AppState {
        AppState {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            workspaces: Arc::new(Mutex::new(HashMap::new())),
            wallet_workspaces: Arc::new(Mutex::new(HashMap::new())),
            rate_limiter: crate::build_rate_limiter(),
            compiler_key: Arc::new(CompilerKey::Ephemeral),
            source_nonce_secret: vec![0u8; 32],
            wasm_runtime: None,
            estimate_gas_semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
        }
    }

    fn test_addr() -> SocketAddr {
        "127.0.0.1:1".parse().unwrap()
    }

    fn req(source: &str, function: &str) -> EstimateGasRequest {
        EstimateGasRequest {
            source: source.to_string(),
            function: function.to_string(),
            args: vec![],
            state: HashMap::new(),
            caller: None,
        }
    }

    #[tokio::test]
    async fn success_reports_gas_used_and_pq_gas_used_as_separate_numeric_fields() {
        let state = test_state();
        let (status, RespJson(body)) = estimate_gas_handler(
            ConnectInfo(test_addr()),
            State(state),
            Json(req(COUNTER_SRC, "increment")),
        ).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.success);
        assert!(body.gas_used.is_some(), "gas_used should be populated: {body:?}");
        assert!(body.pq_gas_used.is_some(), "pq_gas_used should be populated: {body:?}");
        // Confirm they can genuinely diverge (separate meters, not one value
        // mirrored into two fields) -- this contract does no PQ operations,
        // so gas_used should be > 0 while pq_gas_used stays 0.
        assert!(body.gas_used.unwrap() > 0);
        assert_eq!(body.pq_gas_used.unwrap(), 0);
        assert!(body.state_discarded);
    }

    #[tokio::test]
    async fn unknown_function_is_a_clean_execution_failure() {
        let state = test_state();
        let (status, RespJson(body)) = estimate_gas_handler(
            ConnectInfo(test_addr()),
            State(state),
            Json(req(COUNTER_SRC, "does_not_exist")),
        ).await;
        // err_resp always answers 200 with success:false for
        // request-shaped-but-semantically-rejected dry runs -- distinct
        // from the endpoint itself being unreachable (that's a proxy-layer
        // concern, see forge-v3's /api/estimate-gas route).
        assert_eq!(status, StatusCode::OK);
        assert!(!body.success);
        assert!(!body.errors.is_empty());
    }

    #[tokio::test]
    async fn oversized_source_is_rejected_before_any_compilation() {
        let state = test_state();
        let huge_source = "a".repeat(MAX_SOURCE_BYTES + 1);
        let (status, RespJson(body)) = estimate_gas_handler(
            ConnectInfo(test_addr()),
            State(state),
            Json(req(&huge_source, "increment")),
        ).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body.success);
        assert!(
            body.errors.iter().any(|e| e.contains("too large")),
            "expected a 'too large' error, got: {:?}", body.errors
        );
    }

    #[tokio::test]
    async fn repeated_dry_runs_never_persist_state_across_calls() {
        // Backlog item 6/13: state changes are computed then discarded.
        // Running the same increment() dry run twice in a row on the same
        // AppState must return the identical result both times -- if state
        // leaked between calls, the second would see counter=1 already.
        let state = test_state();
        let (_, RespJson(first)) = estimate_gas_handler(
            ConnectInfo(test_addr()),
            State(state.clone()),
            Json(req(COUNTER_SRC, "increment")),
        ).await;
        let (_, RespJson(second)) = estimate_gas_handler(
            ConnectInfo(test_addr()),
            State(state),
            Json(req(COUNTER_SRC, "increment")),
        ).await;
        assert!(first.success && second.success);
        assert_eq!(
            first.return_value, second.return_value,
            "state leaked between dry runs: {:?} vs {:?}", first.return_value, second.return_value
        );
    }

    #[tokio::test]
    async fn concurrency_guard_rejects_when_semaphore_is_exhausted() {
        // Backlog item 7 regression test. Deterministic: start the
        // semaphore with zero permits so the very first call is guaranteed
        // to observe exhaustion -- no need to race real concurrent calls
        // (flaky, since a single dry run completes in well under a
        // millisecond).
        let mut state = test_state();
        state.estimate_gas_semaphore = Arc::new(tokio::sync::Semaphore::new(0));
        let (status, RespJson(body)) = estimate_gas_handler(
            ConnectInfo(test_addr()),
            State(state),
            Json(req(COUNTER_SRC, "increment")),
        ).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body.success);
        assert!(
            body.errors.iter().any(|e| e.contains("server busy")),
            "expected a 'server busy' error from the exhausted semaphore, got: {:?}", body.errors
        );
    }

    #[tokio::test]
    async fn concurrency_guard_allows_requests_when_a_permit_is_free() {
        // Sanity counterpart to the exhaustion test: a semaphore with
        // capacity still lets a normal dry run through untouched.
        let mut state = test_state();
        state.estimate_gas_semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let (status, RespJson(body)) = estimate_gas_handler(
            ConnectInfo(test_addr()),
            State(state),
            Json(req(COUNTER_SRC, "increment")),
        ).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.success, "expected success with a free permit: {body:?}");
    }
}
