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
use synq_vm::bech32::{bech32m_decode, SynqAddress, HRP_TESTNET, HRP_MAINNET, ALGO_ML_DSA_65, NETWORK_ID_TESTNET, decode_network_address};

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
    let struct_defs: Vec<synq_compiler::ast::StructDefinition> = ast.iter()
        .filter_map(|u| if let SourceUnit::Struct(s) = u { Some(s.clone()) } else { None })
        .collect();

    // Compile to AIVM
    let result = match compile_to_aivm(contract, &struct_defs) {
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

/// Wire format for one asset record, carried in `EstimateGasRequest::assets`
/// / `EstimateGasResponse::final_assets` -- the asset-lifecycle counterpart
/// of the `state`/`final_state` slot-index chaining (see `AssetLedger` doc
/// comment). `owner` is a `0x`-prefixed hex string of the full 41-byte
/// SynqAddress (same shape as the top-level `caller` field below and
/// `aivm_value_to_json`'s `Value::Address` case) -- previously a decimal
/// u128 string, switched when `AssetRecord::owner` widened from a lossy
/// truncated u128 to the full address so `asset_owner(id) == caller()`
/// compares byte-for-byte (see aivm::host::AssetRecord doc comment).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetRecordWire {
    pub id: u64,
    pub owner: String,
    pub value: u64,
    pub type_tag: String,
    pub active: bool,
}

fn default_next_asset_id() -> u64 { 1 }

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
    /// Optional pre-seeded asset ledger, carried over from a previous dry
    /// run's `final_assets` -- the asset-lifecycle counterpart of `state`.
    /// Empty/omitted means "start with an empty ledger" (a fresh contract).
    #[serde(default)]
    pub assets: Vec<AssetRecordWire>,
    /// Next asset id counter to resume from -- paired with `assets` (see
    /// AssetLedger::with_records doc). Defaults to 1 (fresh ledger, matching
    /// AssetLedger::new()) if omitted.
    #[serde(default = "default_next_asset_id")]
    pub next_asset_id: u64,
}

/// Backlog item 9's target canonical `synergy_estimateGas` response shape
/// (see synq-internal/docs/backlog/gas-fee-estimator-backlog.md), computed
/// from this exact same dry-run rather than a separate call -- an early,
/// additive preview so Forge/Atlas can start integrating against the
/// eventual real field names now, without waiting on item 8's server
/// migration. All existing flat fields above are unchanged; this is purely
/// additive. `simulation_block` is deliberately `None` today: this
/// dev-sandbox dry-run has no real chain height to attach to (see backlog
/// items 5/8 -- no network-side contract state exists yet), and item 10's
/// "never fabricate a number" rule extends to this field too. No SNRG
/// price field on this struct on purpose -- gas usage (AJ) and gas price
/// (Justin) stay structurally separate per the backlog's ownership split.
#[derive(Debug, Serialize)]
pub struct CanonicalEstimate {
    pub gas_used: String,
    pub pq_gas_used: String,
    /// Heuristic dev-estimator margin (measured usage + 20%, min +1 for any
    /// nonzero usage) -- NOT a protocol-defined gas-limit policy. Real
    /// gas-limit policy is Justin's workstream; treat this purely as a
    /// starting suggestion for a caller building a transaction today.
    pub gas_limit_suggested: String,
    pub pq_gas_limit_suggested: String,
    pub simulation_block: Option<String>,
    pub execution_status: String,
    pub state_persisted: bool,
}

/// 20% headroom rounded up, +1 minimum bump so any nonzero measured cost
/// gets some margin. See `CanonicalEstimate::gas_limit_suggested` doc.
fn suggested_gas_limit(used: u64) -> u64 {
    if used == 0 { 0 } else { used + (used / 5).max(1) }
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
    /// Snapshot of every state slot after this call, keyed by slot index
    /// as a string -- same JSON schema as the request-side `state` seed
    /// field. Nothing here is persisted server-side (see state_discarded);
    /// it exists purely so a client can pass it back as next call's `state`
    /// to chain a sequence of dry-runs (e.g. init() then setCorner()) into
    /// what feels like one debug session. Populated on both success and
    /// revert (a revert still reflects rollback-to-seeded state, which is
    /// useful for seeing exactly what precondition failed).
    #[serde(default)]
    pub final_state: std::collections::HashMap<String, serde_json::Value>,
    /// Snapshot of the asset ledger after this call -- the asset-lifecycle
    /// counterpart of `final_state`. Pass both `final_assets` and
    /// `next_asset_id` back as the next call's `assets`/`next_asset_id` to
    /// chain asset_create/transfer/burn/balance/owner calls across separate
    /// dry-run invocations (see `AssetLedger` doc comment, fixed 2026-08-22
    /// -- previously every dry-run call got a fresh, empty ledger with no
    /// way to carry records forward, so e.g. checkBalance() in a later call
    /// always saw 0 for an asset createAsset() had just minted).
    #[serde(default)]
    pub final_assets: Vec<AssetRecordWire>,
    #[serde(default)]
    pub next_asset_id: u64,
    /// Backlog item 9 preview -- see `CanonicalEstimate` doc comment.
    /// `None` whenever there's no real execution result to compute it from
    /// (validation/rate-limit/compile-error responses via `err_resp`).
    #[serde(default)]
    pub canonical: Option<CanonicalEstimate>,
    pub note: String,
    pub errors: Vec<String>,
}

fn parse_caller_address(s: &str) -> Result<[u8; 41], String> {
    let trimmed = s.trim();
    // Bech32m SynQ address (`tsynq1...` testnet / `synq1...` mainnet) -- the
    // same human-facing format used everywhere else in the toolchain (wallet
    // display, /session/new caller_address, EIP-712 domain, etc). Accepting
    // it here too means callers can paste a real address instead of having
    // to hand-derive raw hex just for a dry-run.
    if trimmed.starts_with("tsynq1") || trimmed.starts_with("synq1") {
        let (hrp, data) = bech32m_decode(trimmed)
            .map_err(|e| format!("invalid bech32 caller address: {}", e))?;
        if hrp != HRP_TESTNET && hrp != HRP_MAINNET {
            return Err(format!("unexpected caller address HRP {} (expected {} or {})", hrp, HRP_TESTNET, HRP_MAINNET));
        }
        let addr = SynqAddress::from_bytes(&data)
            .map_err(|e| format!("invalid bech32 caller address: {}", e))?;
        return Ok(addr.to_bytes());
    }
    // Community-facing Synergy Address Engine format (synw/syna/sync/etc,
    // or the all-zero syn0... sentinel) -- what the actual wallet extension
    // and Forge's connected-wallet auto-fill send. This is a *different*,
    // shorter Bech32m scheme than this VM's own tsynq/synq format above (see
    // vm::bech32 module doc), so it needs its own decode path rather than
    // falling through to raw hex, which used to fail with a confusing
    // "invalid caller hex: Odd number of digits" error.
    if trimmed.len() == 41 && trimmed.starts_with("syn") && !trimmed.starts_with("tsynq1") {
        let id20 = decode_network_address(trimmed)
            .map_err(|e| format!("invalid network caller address: {}", e))?;
        let addr = SynqAddress::from_20_bytes(&id20, ALGO_ML_DSA_65, NETWORK_ID_TESTNET);
        return Ok(addr.to_bytes());
    }
    // Fall back to raw hex (0x-prefixed or bare), the original format.
    let hex_str = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid caller hex: {}", e))?;
    if bytes.len() != 41 {
        return Err(format!("caller address must be 41 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 41];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Best-effort sanity check for a hand-built (non-bech32) caller address.
/// The numeric identity slot is `bytes[5..21]` -- the exact 16-byte
/// big-endian range `Value::as_u128()` reads for the `Ne`/`Lt`/`Gt`/`Le`/
/// `Ge` comparison opcodes, and the exact range `Value::map_key_bytes()`
/// now canonicalizes `Value::Address` map keys through (fixed 2026-08-25,
/// see aivm-scenario-testing-backlog.md item 7). A real bech32m-decoded
/// address (tsynq1.../synq1.../synw.../syna...) always has its pk_hash
/// land in that slot by construction, so this only fires for the raw-hex
/// fallback path in `parse_caller_address` -- e.g. a hand-crafted test
/// caller that put a distinguishing byte at the end of the 41-byte array
/// instead of inside `[5..21]`. That caller silently aliases to identity
/// `0` for every map lookup and every `caller`-vs-literal comparison, which
/// is exactly the mistake this project's own `ComprehensiveToken` test
/// scenario made before item 7 was diagnosed. Non-fatal: surfaced via the
/// response's `note` field, never blocks execution.
fn caller_identity_slot_warning(addr: &[u8; 41]) -> Option<String> {
    let identity_is_zero = addr[5..21].iter().all(|b| *b == 0);
    let anything_nonzero = addr.iter().any(|b| *b != 0);
    if identity_is_zero && anything_nonzero {
        Some(format!(
            "warning: caller address 0x{} has an all-zero identity slot (bytes[5..21]) but non-zero bytes elsewhere. \
This will alias to identity 0 for every map lookup and comparison against a plain numeric literal (isAdmin(n)/isRegistered(n)/ \
balanceOf(n)-style getters, and any caller-vs-literal Ne/Lt/Gt/Le/Ge check). If you hand-built this address for a test, encode \
the distinguishing number as a 16-byte big-endian value written into bytes[5..21] -- the same slot Value::as_address() writes \
a plain u128 literal into -- not at the end of the array. See aivm-scenario-testing-backlog.md item 7.",
            hex::encode(addr)
        ))
    } else {
        None
    }
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

/// Look up a function's (or the constructor's, for "init") declared
/// parameter types, in order — used to decode struct-shaped JSON args
/// (`{"x": 12, "y": 14}`) into the right field order instead of guessing.
fn find_function_param_types(
    contract: &synq_compiler::ast::ContractDefinition,
    name: &str,
) -> Option<Vec<synq_compiler::ast::Type>> {
    use synq_compiler::ast::ContractPart;
    for part in &contract.parts {
        match part {
            ContractPart::Function(f) if f.name == name => {
                return Some(f.params.iter().map(|p| p.ty.clone()).collect());
            }
            ContractPart::Constructor(c) if name == "init" => {
                return Some(c.params.iter().map(|p| p.ty.clone()).collect());
            }
            _ => {}
        }
    }
    None
}

/// Type-aware arg decoder — like `json_to_aivm_value`, but when the expected
/// type is a known struct, decodes a JSON object into a `Value::Array` in
/// the struct's DECLARED field order (matching what the AIVM codegen's
/// StructLiteral/FieldAccess ArrayGet indices expect), instead of rejecting
/// objects outright or trusting arbitrary JSON key order.
/// Builds a correctly-SHAPED zero default for a declared state-var type,
/// recursing into struct fields (and tuple elements) so a never-seeded
/// struct-typed state slot defaults to Value::Array([...zeroes...]) with
/// the right field count -- not a bare Value::U64(0) -- matching what a
/// freshly-deployed contract's storage would actually look like before
/// any field is written. Without this, any FieldAccess (`x.field`) on an
/// unset struct state var trips the VM's ArrayGet type check (expected
/// Array, got u64) the moment a caller (Forge, Playground, a raw
/// estimate-gas request) invokes a read function before calling init().
fn default_aivm_value_for_type(
    ty: &synq_compiler::ast::Type,
    structs: &std::collections::HashMap<String, &synq_compiler::ast::StructDefinition>,
) -> aivm::host::Value {
    use aivm::host::Value;
    use synq_compiler::ast::Type;

    match ty {
        Type::Named(sname) => {
            if let Some(sdef) = structs.get(sname.as_str()) {
                Value::Array(sdef.fields.iter()
                    .map(|f| default_aivm_value_for_type(&f.ty, structs))
                    .collect())
            } else {
                // Enum or unknown named type -- zero is a reasonable default
                // (matches the VMs existing bare-scalar fallback).
                Value::U64(0)
            }
        }
        Type::Tuple(types) => Value::Array(
            types.iter().map(|t| default_aivm_value_for_type(t, structs)).collect(),
        ),
        Type::Array(_) => Value::Array(vec![]),
        // A never-written map-typed state slot must default to a real,
        // empty Value::Map, not Value::Array([]) -- the AIVM VM's
        // MapGetVal/MapSetVal only recognize Value::Map as "a map with
        // entries" and otherwise fall back to a fresh empty map anyway,
        // but seeding this correctly up front means a freshly-deployed
        // contract's map state round-trips through get/set the same way
        // a written-then-read one does, and any future direct state
        // inspection sees the right shape immediately.
        Type::Mapping(_, _) => Value::Map(std::collections::BTreeMap::new()),
        Type::Bool => Value::Bool(false),
        Type::UInt128 | Type::Int128 => Value::U128(0),
        Type::Str => Value::String(String::new()),
        Type::Bytes | Type::BytesN(_) | Type::Hash32 | Type::Hash64
        | Type::Address | Type::UMAIdentity
        | Type::DilithiumPublicKey | Type::FalconPublicKey | Type::KyberPublicKey
        | Type::DilithiumSignature | Type::FalconSignature => Value::Bytes(vec![]),
        _ => Value::U64(0),
    }
}

fn json_to_aivm_value_typed(
    v: &serde_json::Value,
    ty: Option<&synq_compiler::ast::Type>,
    structs: &std::collections::HashMap<String, &synq_compiler::ast::StructDefinition>,
) -> Result<aivm::host::Value, String> {
    use aivm::host::Value;
    use synq_compiler::ast::Type;

    if let (serde_json::Value::Object(map), Some(Type::Named(sname))) = (v, ty) {
        if let Some(sdef) = structs.get(sname.as_str()) {
            let mut vals = Vec::with_capacity(sdef.fields.len());
            for f in &sdef.fields {
                let fv = map.get(&f.name)
                    .ok_or_else(|| format!("struct '{}' missing field '{}'", sname, f.name))?;
                vals.push(json_to_aivm_value_typed(fv, Some(&f.ty), structs)?);
            }
            return Ok(Value::Array(vals));
        }
        return Err(format!("unknown struct type '{}' for object argument", sname));
    }
    // Map-typed state var, fed back from a previous dry-run's `final_state`
    // (see `aivm_value_to_json`'s Value::Map case: a JSON object keyed by
    // "0x<hex map_key_bytes>" -> value). The hex key round-trips byte-for-
    // byte into the BTreeMap key (map_key_bytes is exactly what produced
    // it), so no re-canonicalization is needed here -- just hex-decode it
    // back. Each entry's value is decoded with the map's declared value
    // type so nested maps (map<K, map<K,V>>) recurse correctly.
    if let (serde_json::Value::Object(obj), Some(Type::Mapping(_key_ty, value_ty))) = (v, ty) {
        let mut m = std::collections::BTreeMap::new();
        for (k, val) in obj {
            let key_bytes = match k.strip_prefix("0x") {
                Some(hexstr) => hex::decode(hexstr)
                    .map_err(|e| format!("bad map key hex '{}': {}", k, e))?,
                None => return Err(format!(
                    "map key '{}' must be a 0x-hex string (as produced by a previous dry-run's final_state)", k
                )),
            };
            let decoded = json_to_aivm_value_typed(val, Some(value_ty.as_ref()), structs)?;
            m.insert(key_bytes, decoded);
        }
        return Ok(Value::Map(m));
    }
    if let serde_json::Value::Array(arr) = v {
        let elem_ty = if let Some(Type::Array(inner)) = ty { Some(inner.as_ref()) } else { None };
        // If the target type is a known struct, also validate arity against
        // its declared field count (positional struct literal: [x, y] for
        // Point) so a wrong-length array is rejected up front instead of
        // silently building a mis-shapen Array the VM has to trip over
        // later. Structs whose fields have their own concrete element
        // types get those propagated positionally too.
        if let Some(Type::Named(sname)) = ty {
            if let Some(sdef) = structs.get(sname.as_str()) {
                if arr.len() != sdef.fields.len() {
                    return Err(format!(
                        "struct '{}' expects {} field(s) ({}), got an array of length {}",
                        sname, sdef.fields.len(),
                        sdef.fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>().join(", "),
                        arr.len(),
                    ));
                }
                let vals: Result<Vec<Value>, String> = arr.iter().zip(sdef.fields.iter())
                    .map(|(x, f)| json_to_aivm_value_typed(x, Some(&f.ty), structs))
                    .collect();
                return Ok(Value::Array(vals?));
            }
        }
        let vals: Result<Vec<Value>, String> = arr.iter()
            .map(|x| json_to_aivm_value_typed(x, elem_ty, structs))
            .collect();
        return Ok(Value::Array(vals?));
    }
    // A decimal-string numeric value for a numeric-typed field: the
    // ENCODE side (`aivm_value_to_json`'s `Value::U128` case) deliberately
    // stringifies u128/u256-mapped values because they can exceed JS's
    // safe-integer range (2^53) -- any real token amount/balance routinely
    // does. But until this check existed, the decoder had no matching path
    // back: a plain non-"0x" JSON string fell straight through to the
    // untyped `json_to_aivm_value` fallback below, which has no numeric
    // parsing for strings and returns an opaque `Value::String` instead.
    // That silently corrupts the value -- it round-trips fine through a
    // bare `return`, but the moment it's used in a comparison or arithmetic
    // op (`!=`, `+`, ...) the VM throws `TypeMismatch { expected: "u128",
    // got: "string" }`. Repro: DomainRegistry.set_record(11,22,33,"999")
    // then update_record(11,22,33,555) -- `require(current != 0, ...)`
    // reading that same nested-map value back throws. Passing 999 as a
    // JSON number instead of a string avoided it, but a real u256 amount
    // over 2^53 has no choice but to arrive as a string, so this needed a
    // real fix, not just "pass numbers" caller guidance. Signed types are
    // included for symmetry even though this AIVM's `Value` enum has no
    // I128 variant yet (i64::MAX is the ceiling until one is added) --
    // untested against a live signed-int example since none exist in the
    // current demo set, but strictly safer than the prior silent
    // corruption for any string that does show up there.
    // IMPORTANT: only intercept plain decimal strings here. A "0x..."
    // string is NEVER a decimal numeric encoding in this protocol -- it's
    // the hex encoding used for Address/Bytes32/Bytes (see
    // `json_to_aivm_value` below), and that includes values whose
    // DECLARED SynQ type is a numeric one but whose actual runtime Value
    // is an Address -- e.g. `owner: u256; ... owner = caller;` stores a
    // real `Value::Address`, which `aivm_value_to_json` serializes as a
    // "0x"-prefixed 41-byte hex string. Treating that as decimal would
    // (and, before this guard was added during testing, briefly did)
    // break every `x = caller`-assigned-to-a-numeric-slot state var on
    // its next round trip through `state`/`final_state` chaining --
    // caught via SimpleToken.init()/getTotalSupply() regression-testing
    // this same fix. Only a string with no "0x" prefix reaches here.
    if let serde_json::Value::String(s) = v {
        if !s.starts_with("0x") {
            let is_unsigned = matches!(
                ty,
                Some(Type::UInt8) | Some(Type::UInt16) | Some(Type::UInt32) | Some(Type::UInt64)
                    | Some(Type::UInt128) | Some(Type::UInt256) | Some(Type::Height)
            );
            let is_signed = matches!(
                ty,
                Some(Type::Int8) | Some(Type::Int16) | Some(Type::Int32)
                    | Some(Type::Int64) | Some(Type::Int128) | Some(Type::Int256)
            );
            if is_unsigned {
                return s.parse::<u128>()
                    .map(Value::U128)
                    .map_err(|_| format!("expected an unsigned integer string for this argument, got '{}'", s));
            }
            if is_signed {
                return s.parse::<i64>()
                    .map(Value::I64)
                    .map_err(|_| format!("expected an integer string for this argument, got '{}'", s));
            }
        }
    }
    // A scalar (number/bool/string/null) can never represent a struct --
    // accepting one here would silently corrupt the value: e.g. setCorner
    // called with a bare 10 instead of {x, y} would store corner as
    // Value::U64(10), and the very next read of corner.x/.y would crash the
    // VM with TypeMismatch { expected: Array, got: u64 } instead of this
    // request failing with an honest, actionable error.
    if let Some(Type::Named(sname)) = ty {
        if let Some(sdef) = structs.get(sname.as_str()) {
            return Err(format!(
                "struct '{}' expects an object ({{{}}}) or a {}-element array, got a scalar value",
                sname,
                sdef.fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>().join(", "),
                sdef.fields.len(),
            ));
        }
    }
    json_to_aivm_value(v)
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
        // Maps serialize as a JSON object keyed by the canonical map-key
        // bytes (hex-encoded, since map keys aren't necessarily strings --
        // e.g. an address or u256 key). This is a debug/inspection shape,
        // not an ABI-typed decode target; scenario tests and normal
        // contract calls read individual entries back out via the
        // contract's own getter functions (e.g. balanceOf(addr)), not by
        // decoding this JSON directly.
        Value::Map(entries) => serde_json::json!(entries.iter()
            .map(|(k, v)| (format!("0x{}", hex::encode(k)), aivm_value_to_json(v)))
            .collect::<std::collections::BTreeMap<String, serde_json::Value>>()),
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
            final_state: std::collections::HashMap::new(),
            final_assets: vec![],
            next_asset_id: 1,
            canonical: None,
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
    let struct_defs: Vec<synq_compiler::ast::StructDefinition> = ast.iter()
        .filter_map(|u| if let SourceUnit::Struct(s) = u { Some(s.clone()) } else { None })
        .collect();
    let struct_map: std::collections::HashMap<String, &synq_compiler::ast::StructDefinition> =
        struct_defs.iter().map(|s| (s.name.clone(), s)).collect();
    let compiled = match compile_to_aivm(contract, &struct_defs) {
        Ok(r) => r,
        Err(e) => return err_resp(vec![format!("AIVM compilation error: {}", e)]),
    };

    let host = aivm::host::HostFunctions::default_v01();
    let avm = aivm::vm::Avm::new(compiled.instructions, compiled.functions, host);

    let func_idx = match avm.find_function(&req.function) {
        Some(i) => i,
        None => return err_resp(vec![format!("function '{}' not found", req.function)]),
    };

    let param_types = find_function_param_types(contract, &req.function);
    let mut args = Vec::with_capacity(req.args.len());
    for (i, a) in req.args.iter().enumerate() {
        let expected_ty = param_types.as_ref().and_then(|v| v.get(i));
        match json_to_aivm_value_typed(a, expected_ty, &struct_map) {
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
        // Pass the slot's declared type (now that we look it up by index
        // here) so the typed decoder can tell a map-typed state var's JSON
        // object (as emitted by aivm_value_to_json's Value::Map case, e.g.
        // {"0x03...": 111}) apart from a struct-typed one ({"x":1,"y":2}) --
        // both are JSON objects, and only the declared Type::Mapping vs.
        // Type::Named distinguishes them. Previously this always passed
        // `None`, so a map-typed state var's `final_state` from one
        // dry-run could never be fed back into a later dry-run's `state`
        // (every chained call after the first that touched a map failed
        // with "bad state value: unsupported arg type: {...}").
        let expected_ty = compiled.state_var_types.iter().find(|(idx, _)| *idx == key).map(|(_, ty)| ty);
        match json_to_aivm_value_typed(v, expected_ty, &struct_map) {
            Ok(val) => { seeded.insert(key, val); }
            Err(e) => return err_resp(vec![format!("bad state value: {}", e)]),
        }
    }

    // Pre-populate every declared state slot the request didn't explicitly
    // seed with a correctly-shaped zero default (see
    // default_aivm_value_for_type doc comment) -- so reading a struct-typed
    // state var before init() has run yields a properly-shaped zero struct
    // instead of the VM's bare Value::U64(0) fallback tripping ArrayGet's
    // type check on the very first FieldAccess.
    for (idx, ty) in &compiled.state_var_types {
        seeded.entry(*idx).or_insert_with(|| default_aivm_value_for_type(ty, &struct_map));
    }

    let caller = match &req.caller {
        Some(s) if !s.is_empty() => match parse_caller_address(s) {
            Ok(addr) => addr,
            Err(e) => return err_resp(vec![format!("bad caller: {}", e)]),
        },
        _ => [0u8; 41],
    };
    let caller_warning = caller_identity_slot_warning(&caller);
    let ctx = aivm::context::ExecutionContext::testnet(caller, [0u8; 41]);
    // This overlay is local to the request and is dropped at the end of this
    // function. avm.execute() may internally .commit() it on success — that
    // only merges staged writes into THIS in-memory overlay's own map, which
    // is about to be discarded. Nothing is written to any session, file, or
    // persistent store. That's the entire "dry run" mechanism.
    let mut overlay = aivm::vm::StateOverlay::with_state(seeded);

    // Rebuild the asset ledger from the previous call's final_assets (see
    // AssetLedger::with_records doc) -- same "seed it, execute, snapshot it
    // back" pattern as the state overlay just above. Still fully ephemeral:
    // this HashMap and counter are dropped with the rest of the request.
    let mut seeded_assets: std::collections::HashMap<u64, aivm::host::AssetRecord> =
        std::collections::HashMap::new();
    for rec in &req.assets {
        let owner_hex = rec.owner.trim_start_matches("0x");
        let owner_bytes = match hex::decode(owner_hex) {
            Ok(b) if b.len() == 41 => b,
            Ok(b) => return err_resp(vec![format!("bad asset owner (expected 41-byte 0x-hex address, got {} bytes): {}", b.len(), rec.owner)]),
            Err(e) => return err_resp(vec![format!("bad asset owner (expected 0x-hex address): {}: {}", rec.owner, e)]),
        };
        let mut owner = [0u8; 41];
        owner.copy_from_slice(&owner_bytes);
        seeded_assets.insert(rec.id, aivm::host::AssetRecord {
            owner,
            value: rec.value,
            type_tag: rec.type_tag.clone(),
            active: rec.active,
        });
    }
    let mut asset_ledger = aivm::host::AssetLedger::with_records(seeded_assets, req.next_asset_id);

    match avm.execute_with_assets(func_idx, args, &ctx, &mut overlay, &mut asset_ledger) {
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
            let final_state: std::collections::HashMap<String, serde_json::Value> = overlay
                .committed_snapshot()
                .iter()
                .map(|(slot, val)| (slot.to_string(), aivm_value_to_json(val)))
                .collect();
            let (asset_records, next_asset_id) = asset_ledger.snapshot();
            let final_assets: Vec<AssetRecordWire> = asset_records
                .iter()
                .map(|(id, rec)| AssetRecordWire {
                    id: *id,
                    owner: format!("0x{}", hex::encode(rec.owner)),
                    value: rec.value,
                    type_tag: rec.type_tag.clone(),
                    active: rec.active,
                })
                .collect();
            let canonical = CanonicalEstimate {
                gas_used: result.receipt.gas_used.to_string(),
                pq_gas_used: result.receipt.pq_gas_used.to_string(),
                gas_limit_suggested: suggested_gas_limit(result.receipt.gas_used).to_string(),
                pq_gas_limit_suggested: suggested_gas_limit(result.receipt.pq_gas_used).to_string(),
                simulation_block: None,
                execution_status: status.to_string(),
                state_persisted: false,
            };
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
                final_state,
                final_assets,
                next_asset_id,
                canonical: Some(canonical),
                note: match &caller_warning {
                    Some(w) => format!("{} {}", note, w),
                    None => note.clone(),
                },
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
            assets: vec![],
            next_asset_id: 1,
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

    #[tokio::test]
    async fn explicit_revert_reports_reverted_status_not_a_transport_error() {
        // A controlled `revert IDENT;` compiles to Trap(0), which the VM
        // turns into Ok(ExecutionResult{ receipt.status: Reverted, .. }) --
        // not an Err. Confirms the estimator surfaces this as a genuine,
        // successful dry run (success:true) that *reports* a revert via the
        // `status` field, rather than conflating "the contract reverted"
        // with "the estimator itself failed".
        let src = "contract Reverter { state { dummy: u256; } impl { @public function always_reverts() -> u256 { revert Blocked; } } }";
        let state = test_state();
        let (status, RespJson(body)) = estimate_gas_handler(
            ConnectInfo(test_addr()),
            State(state),
            Json(req(src, "always_reverts")),
        ).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.success, "a controlled revert should still be success:true: {body:?}");
        assert_eq!(body.status.as_deref(), Some("reverted"));
        assert!(body.gas_used.unwrap_or(0) > 0, "gas up to the trap point should still be charged: {body:?}");
        assert!(body.return_value.is_none());
    }

    #[tokio::test]
    async fn out_of_gas_is_reported_as_a_clean_execution_failure_not_a_crash() {
        // A while loop with no reachable exit condition within the default
        // 1,000,000 gas_limit (aivm::context::ExecutionContext::testnet)
        // must terminate the dry run via GasMeter::charge's bounds check
        // (aivm/src/gas.rs) rather than looping forever or panicking the
        // handler. Confirms item 7's "resource limits work" checklist
        // entry for ordinary (non-PQ) gas.
        let src = "contract Looper { state { counter: u256; } impl { @public function burn() -> u256 { while (counter < 999999999) { counter = counter + 1; } return counter; } } }";
        let state = test_state();
        let (status, RespJson(body)) = estimate_gas_handler(
            ConnectInfo(test_addr()),
            State(state),
            Json(req(src, "burn")),
        ).await;
        assert_eq!(status, StatusCode::OK, "out-of-gas must still answer cleanly, not hang/crash");
        assert!(!body.success, "exhausting the gas limit should be reported as a failure: {body:?}");
        assert!(
            body.errors.iter().any(|e| e.contains("exhaust")),
            "expected a gas-exhaustion error, got: {:?}", body.errors
        );
    }

    #[tokio::test]
    async fn stack_overflow_is_reported_as_a_clean_execution_failure_not_a_crash() {
        // Unbounded recursion (no base case) must be stopped by AIVM's
        // call_depth_limit (64, aivm/src/vm.rs) well before the 1,000,000
        // gas_limit would ever be reached, and reported the same clean way
        // as out-of-gas above -- not a hang, not a panic, not a real stack
        // overflow in the synq-server process itself. This was previously
        // completely untested at every layer (no aivm/tests coverage, no
        // handler coverage) -- backlog item 13's "resource-limit tests on
        // the Rust side... not yet written" checklist entry. Verified live
        // against the running server before writing this regression test.
        let src = "contract Recur { state { } impl { @public function recurse(n: u256) -> u256 { return recurse(n + 1); } } }";
        let mut request = req(src, "recurse");
        request.args = vec![serde_json::json!(0)];
        let state = test_state();
        let (status, RespJson(body)) = estimate_gas_handler(
            ConnectInfo(test_addr()),
            State(state),
            Json(request),
        ).await;
        assert_eq!(status, StatusCode::OK, "unbounded recursion must still answer cleanly, not hang/crash");
        assert!(!body.success, "unbounded recursion should be reported as a failure: {body:?}");
        assert!(
            body.errors.iter().any(|e| e.contains("StackOverflow")),
            "expected a StackOverflow error (call_depth_limit), got: {:?}", body.errors
        );
    }

    #[tokio::test]
    async fn seeded_state_is_honored_by_the_dry_run() {
        // The optional `state` request field lets a caller pre-seed a
        // state slot (dev-mode convenience per backlog item 5's notes on
        // the current shape vs a future canonical one). Confirms a read of
        // a pre-seeded slot actually reflects the seeded value rather than
        // silently defaulting to 0.
        let src = "contract Reader { state { counter: u256; } impl { @public function read_counter() -> u256 { return counter; } } }";
        let mut request = req(src, "read_counter");
        request.state.insert("0".to_string(), serde_json::json!(42));
        let state = test_state();
        let (status, RespJson(body)) = estimate_gas_handler(
            ConnectInfo(test_addr()),
            State(state),
            Json(request),
        ).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.success, "{body:?}");
        assert_eq!(body.return_value, Some(serde_json::json!(42)));
    }

    #[tokio::test]
    async fn identical_inputs_produce_stable_gas_measurements() {
        // Determinism check: the exact same source/function/args/state
        // dry-run twice (fresh AppState each time, so there is zero shared
        // mutable context) must report the identical gas_used both times.
        // A weighted per-opcode GasMeter over a deterministic interpreter
        // has no business varying run to run; if this ever flakes it means
        // something non-deterministic (timing, uninitialized memory, map
        // iteration order) leaked into the cost model.
        let (_, RespJson(first)) = estimate_gas_handler(
            ConnectInfo(test_addr()),
            State(test_state()),
            Json(req(COUNTER_SRC, "increment")),
        ).await;
        let (_, RespJson(second)) = estimate_gas_handler(
            ConnectInfo(test_addr()),
            State(test_state()),
            Json(req(COUNTER_SRC, "increment")),
        ).await;
        assert!(first.success && second.success);
        assert_eq!(first.gas_used, second.gas_used, "gas measurement is not stable across identical runs");
        assert_eq!(first.pq_gas_used, second.pq_gas_used);
    }

    #[tokio::test]
    async fn canonical_preview_mirrors_the_flat_fields_and_never_persists() {
        // Backlog item 9 regression guard: the additive `canonical` block
        // must report the exact same numbers as the existing flat fields
        // (it's a reshape of the same dry run, not a second execution),
        // suggest a >= measured headroom on gas (never less than what was
        // actually used), and always claim state_persisted:false since a
        // dry run never writes anywhere durable regardless of receipt
        // status. Also confirms canonical is present on success responses
        // and absent on request-level rejections (item 10's "don't
        // fabricate" spirit extended to the preview: no canonical block
        // when there's no real execution to compute it from).
        let state = test_state();
        let (status, RespJson(body)) = estimate_gas_handler(
            ConnectInfo(test_addr()),
            State(state),
            Json(req(COUNTER_SRC, "increment")),
        ).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.success);
        let canonical = body.canonical.as_ref().expect("canonical block missing on success");
        assert_eq!(canonical.gas_used, body.gas_used.unwrap().to_string());
        assert_eq!(canonical.pq_gas_used, body.pq_gas_used.unwrap().to_string());
        assert_eq!(canonical.execution_status, body.status.clone().unwrap());
        assert!(!canonical.state_persisted);
        assert!(canonical.simulation_block.is_none(), "no real chain to attach a block to yet -- must not fabricate one");
        let suggested: u64 = canonical.gas_limit_suggested.parse().unwrap();
        assert!(suggested >= body.gas_used.unwrap(), "suggested limit must never undercut measured usage");

        // Rejection path (oversized source) never executes anything, so
        // there is nothing real to compute a canonical preview from.
        let state2 = test_state();
        let huge_source = "a".repeat(MAX_SOURCE_BYTES + 1);
        let (_, RespJson(rejected)) = estimate_gas_handler(
            ConnectInfo(test_addr()),
            State(state2),
            Json(req(&huge_source, "increment")),
        ).await;
        assert!(rejected.canonical.is_none(), "no canonical preview for a request-level rejection");
    }

    #[tokio::test]
    async fn unimplemented_host_function_fails_closed_not_unsafely() {
        // Item 6 audit finding (a): several builtins declared in the
        // import table (addr.*, auth.*) aren't wired up in
        // execute_host_call yet and return HostFunctionNotDeclared.
        // (asset.* used to be in this bucket too -- fixed 2026-08-22; and
        // string.length/string.concat/string.eq (str_len/str_concat/
        // str_eq) used to be too -- fixed 2026-08-25, see
        // aivm/src/host.rs's "String builtins" arms. to_tsynq/addr.encode
        // now stands in as the still-unimplemented case.)
        // Regression guard: calling one of them through a real dry run
        // must still come back as a clean success:false with a clear
        // error -- not a panic, not a silently-wrong success, and
        // critically not partial state changes made visible (state stays
        // discarded regardless of where execution stopped).
        let src = "contract AddrTest { state { dummy: u256; } impl { @public function check_addr() as caller -> str { return to_tsynq(caller); } } }";
        let state = test_state();
        let (status, RespJson(body)) = estimate_gas_handler(
            ConnectInfo(test_addr()),
            State(state),
            Json(req(src, "check_addr")),
        ).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body.success, "an unimplemented host function must fail closed: {body:?}");
        assert!(body.state_discarded);
        assert!(!body.errors.is_empty());
    }

    #[tokio::test]
    async fn asset_lifecycle_create_transfer_balance_burn_round_trips() {
        // Regression guard for the "forge run createAsset(123) ->
        // HostFunctionNotDeclared(asset.create)" bug report (2026-08-22):
        // asset.create/transfer/burn/balance/owner were declared in AIVM's
        // host import table but never wired up in execute_host_call, so
        // every SynQ contract calling any asset_* builtin under AIVM
        // failed instantly. Exercises the full lifecycle in one dry run:
        // create(value=100) -> balance reads 100 -> transfer reissues a
        // new asset id with the same value -> burn returns that value.
        let src = "contract AssetOpsTest { state { dummy: u256; } impl { @public function run_ops() -> u256 { let id: u256 = asset_create(\"Widget\", 100); let bal: u256 = asset_balance(id); dummy = bal; let new_id: u256 = asset_transfer(id, 999); let burned: u256 = asset_burn(new_id); return burned; } } }";
        let state = test_state();
        let (status, RespJson(body)) = estimate_gas_handler(
            ConnectInfo(test_addr()),
            State(state),
            Json(req(src, "run_ops")),
        ).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.success, "asset lifecycle dry run should succeed: {body:?}");
        assert!(body.errors.is_empty(), "unexpected errors: {:?}", body.errors);
        // balance was staged into `dummy` mid-function; the transfer +
        // burn chain must preserve that same value (100) through to the
        // final burn() return.
        assert_eq!(body.return_value, Some(serde_json::json!(100)));
    }

    #[tokio::test]
    async fn asset_ledger_persists_across_chained_dry_runs() {
        // Regression guard for the "forge run createAsset(12) then a
        // separate forge run checkBalance(1) returns 0" bug report
        // (2026-08-22): each dry run used to get a brand-new, empty
        // AssetLedger with no way to carry records from a prior call
        // forward -- unlike declared state, which already chains via
        // final_state/state. Fixed by giving AssetLedger the same
        // with_records/snapshot seed-and-restore pair StateOverlay already
        // had, wired through EstimateGasRequest.assets/next_asset_id and
        // EstimateGasResponse.final_assets/next_asset_id.
        let src = "contract AssetPersistTest { state { dummy: u256; } impl { @public function mint(v: u256) -> u256 { return asset_create(\"Widget\", v); } @public function bal(id: u256) -> u256 { return asset_balance(id); } } }";

        let mut mint_req = req(src, "mint");
        mint_req.args = vec![serde_json::json!(12)];
        let state = test_state();
        let (status, RespJson(mint_body)) = estimate_gas_handler(
            ConnectInfo(test_addr()),
            State(state),
            Json(mint_req),
        ).await;
        assert_eq!(status, StatusCode::OK);
        assert!(mint_body.success, "mint dry run should succeed: {mint_body:?}");
        assert_eq!(mint_body.return_value, Some(serde_json::json!(1)), "first minted asset should get id 1");
        assert!(!mint_body.final_assets.is_empty(), "mint should snapshot at least one asset record: {mint_body:?}");

        // Simulate the frontend auto-chaining final_assets/next_asset_id
        // from the first call into the second, exactly as ForgeIDE.tsx's
        // sessionState chaining does for final_state already.
        let mut bal_req = req(src, "bal");
        bal_req.args = vec![serde_json::json!(1)];
        bal_req.assets = mint_body.final_assets.clone();
        bal_req.next_asset_id = mint_body.next_asset_id;
        let state2 = test_state();
        let (status2, RespJson(bal_body)) = estimate_gas_handler(
            ConnectInfo(test_addr()),
            State(state2),
            Json(bal_req),
        ).await;
        assert_eq!(status2, StatusCode::OK);
        assert!(bal_body.success, "balance dry run should succeed: {bal_body:?}");
        assert_eq!(
            bal_body.return_value, Some(serde_json::json!(12)),
            "balance of the asset minted in the previous call must carry through, not reset to 0: {bal_body:?}"
        );
    }

    #[tokio::test]
    async fn bool_literal_return_value_serializes_as_json_true_not_one() {
        // Regression guard for the "init() -> success · returned 1 (not
        // true)" bug report (2026-08-22): `Literal::Bool` used to compile
        // to PushU64(0/1), producing a Value::U64 at runtime that
        // JSON-serializes as the raw number instead of a real boolean.
        // Fixed with a dedicated PushBool instruction that preserves
        // Value::Bool end to end.
        let src = "contract BoolTest { state { initialised: bool; } impl { @public function init() -> bool { initialised = true; return true; } @public function is_off() -> bool { return false; } } }";
        let state = test_state();
        let (status, RespJson(body)) = estimate_gas_handler(
            ConnectInfo(test_addr()),
            State(state),
            Json(req(src, "init")),
        ).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.success, "{body:?}");
        assert_eq!(body.return_value, Some(serde_json::json!(true)), "expected JSON true, not 1: {body:?}");

        let state2 = test_state();
        let (status2, RespJson(body2)) = estimate_gas_handler(
            ConnectInfo(test_addr()),
            State(state2),
            Json(req(src, "is_off")),
        ).await;
        assert_eq!(status2, StatusCode::OK);
        assert!(body2.success, "{body2:?}");
        assert_eq!(body2.return_value, Some(serde_json::json!(false)), "expected JSON false, not 0: {body2:?}");
    }
}
