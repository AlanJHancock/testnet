// ── SynQ WASM Compiler — uses synq-compiler crate IR backend ──────────────────
// v0.2: Uses compile_ir() from the compiler crate for bytecode consistency
//       with the native server. Eliminates vendored compiler duplication.

use wasm_bindgen::prelude::*;
use synq_compiler::{self, ast::*, parser};
use synq_compiler::ast::{SourceUnit, ContractPart, Statement, Expression, Type};
use synq_compiler::transpile_solidity;

// ── Vendored VM for browser-side execution (not used for compilation) ────────
mod vm_inner {
    pub mod pqc_shims {
        pub mod dilithium {
            pub fn verify(_msg: &[u8], _sig: &[u8], _pk: &[u8]) -> bool { false }
        }
        pub mod kyber {
            pub fn keygen() -> Result<(Vec<u8>, Vec<u8>), String> { Ok((vec![0;32], vec![0;32])) }
            pub fn encaps(_pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> { Ok((vec![0;32], vec![0;32])) }
            pub fn decaps(_ct: &[u8], _sk: &[u8]) -> Result<Vec<u8>, String> { Ok(vec![0;32]) }
        }
        pub mod falcon {
            pub fn verify(_msg: &[u8], _sig: &[u8], _pk: &[u8]) -> bool { false }
        }
        pub mod sphincs {
            pub fn verify(_msg: &[u8], _sig: &[u8], _pk: &[u8]) -> bool { false }
        }
    }
    pub mod opcode;
    pub mod assembler;
    pub mod vm;
    pub use vm::QuantumVM;
    pub use opcode::{OpCode, VMError};
    pub use assembler::Assembler;
}

// ── Types we re-export for external use ───────────────────────────────────────
pub use vm_inner::QuantumVM;

// ── WASM CompileResult for the browser IDE ───────────────────────────────────
// This wraps the compiler crate's CompileResult, adding IDE-specific metadata.

/// Helper: convert AST Type to the string the IDE expects.
///
/// `struct_names` is the set of struct names declared in the source unit --
/// `Type::Named(name)` covers BOTH struct and enum references (see ast.rs),
/// so this only formats as "struct<Name>" when `name` is a known struct;
/// enum/unknown named types fall through to the pre-existing "u256"
/// scalar-encoding behavior to avoid changing enum ABI shape.
fn type_name(ty: &Type, struct_names: &std::collections::HashSet<String>) -> String {
    match ty {
        Type::Bool    => "bool".to_string(),
        Type::Str     => "str".to_string(),
        Type::Address => "address".to_string(),
        Type::UInt8   => "u8".to_string(),
        Type::UInt16  => "u16".to_string(),
        Type::UInt32  => "u32".to_string(),
        Type::UInt64  => "u64".to_string(),
        Type::UInt128 => "u128".to_string(),
        Type::UInt256 => "u256".to_string(),
        Type::Bytes   => "bytes".to_string(),
        Type::Named(name) if struct_names.contains(name) => format!("struct<{}>", name),
        _             => "u256".to_string(),
    }
}

/// Result of compiling a SynQ source file for the WASM IDE.
#[derive(Debug)]
struct WasmCompileResult {
    pub bytecode:          Option<String>,
    pub state_vars:        Vec<(String, u32)>,
    pub warnings:          Vec<String>,
    pub errors:            Vec<String>,
    pub extern_contracts:  Vec<String>,
}

/// Walk a statement and collect unique extern_call target contract names.
fn wasm_collect_extern_contracts(stmt: &Statement, out: &mut Vec<String>) {
    match stmt {
        Statement::ExternCall { contract, .. } => {
            if !out.contains(contract) { out.push(contract.clone()); }
        }
        Statement::If { then_block, else_block, .. } => {
            for s in &then_block.statements { wasm_collect_extern_contracts(s, out); }
            if let Some(eb) = else_block {
                for s in &eb.statements { wasm_collect_extern_contracts(s, out); }
            }
        }
        _ => {}
    }
}

/// Walk a statement (recursing into if/while) checking whether it writes to
/// any name in . Used to derive ABI method mutability honestly
/// from the actual function body instead of relying on the opt-in
///  attribute, which most contracts don't declare.
fn wasm_stmt_writes_state(stmt: &Statement, state_names: &[String], out: &mut bool) {
    if *out { return; }
    match stmt {
        Statement::Assignment(name, _) => {
            if state_names.iter().any(|s| s == name) { *out = true; }
        }
        Statement::FieldAssignment { object, .. } => {
            if state_names.iter().any(|s| s == object) { *out = true; }
        }
        Statement::MapAssignment { map, .. } => {
            if state_names.iter().any(|s| s == map) { *out = true; }
        }
        Statement::SetOp { set, .. } => {
            if state_names.iter().any(|s| s == set) { *out = true; }
        }
        Statement::ExternCall { .. } => { *out = true; }
        Statement::If { then_block, else_block, .. } => {
            for s in &then_block.statements { wasm_stmt_writes_state(s, state_names, out); }
            if let Some(eb) = else_block {
                for s in &eb.statements { wasm_stmt_writes_state(s, state_names, out); }
            }
        }
        Statement::While { body, .. } => {
            for s in &body.statements { wasm_stmt_writes_state(s, state_names, out); }
        }
        _ => {}
    }
}

/// Add PQC warnings for WASM mode (PQC builtins compile but throw at runtime).
fn add_pqc_warnings(ast: &[SourceUnit], warnings: &mut Vec<String>) {
    const PQC_BUILTINS_WARN: &[&str] = &[
        "dilithium_verify", "falcon_verify", "sphincs_verify",
        "kyber_encapsulate", "kyber_decapsulate", "kyber_decaps",
        "falcon_sign", "mceliece_encapsulate", "mceliece_decapsulate",
        "hqc_encapsulate", "hqc_decapsulate",
    ];
    'pqc_check: for unit in ast {
        if let SourceUnit::Contract(c) = unit {
            for part in &c.parts {
                if let ContractPart::Function(f) = part {
                    for stmt in &f.body.statements {
                        let exprs: Vec<&Expression> = match stmt {
                            Statement::Expression(e) => vec![e],
                            Statement::Return(Some(e)) => vec![e],
                            Statement::Assignment(_, e) => vec![e],
                            Statement::Require(e, _) => vec![e],
                            Statement::Let { value, .. } => vec![value],
                            Statement::LetDestructure { value, .. } => vec![value.as_ref()],
                            _ => vec![],
                        };
                        for expr in exprs {
                            if let Expression::Call(name, _) = expr {
                                if PQC_BUILTINS_WARN.contains(&name.as_str()) {
                                    warnings.push(format!(
                                        "PQC builtin '{}' will throw a RuntimeError in browser (WASM) mode. \
                                         Deploy to synq-server for real PQC verification.",
                                        name
                                    ));
                                    break 'pqc_check;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ── WASM-bindgen exports for browser IDE ─────────────────────────────────────

#[derive(serde::Serialize)]
struct WasmParamInfo {
    name: String,
    ty: String,
}

#[derive(serde::Serialize)]
struct WasmFunctionInfo {
    name: String,
    params: Vec<WasmParamInfo>,
    return_type: Option<String>,
    argc: usize,
}

#[derive(serde::Serialize)]
struct WasmCompileResultJson {
    success: bool,
    bytecode: Option<String>,
    state_vars: Vec<(String, u32)>,
    warnings: Vec<String>,
    errors: Vec<String>,
    extern_contracts: Vec<String>,
    functions: Vec<WasmFunctionInfo>,
    state_var_types: std::collections::HashMap<String, String>,
}

/// Compile using the IR backend (same as native server) for bytecode consistency.
#[wasm_bindgen]
pub fn compile_synq(source: &str) -> String {
    let ast = parser::parse(source).unwrap_or_default();

    let result = match synq_compiler::compile_ir(source) {
        Ok(cr) => {
            let mut warnings = cr.warnings.clone();
            add_pqc_warnings(&ast, &mut warnings);

            // Collect extern_call targets from AST (for IDE cross-check)
            let mut extern_contracts: Vec<String> = Vec::new();
            for unit in &ast {
                if let SourceUnit::Contract(c) = unit {
                    for part in &c.parts {
                        if let ContractPart::Function(f) = part {
                            for stmt in &f.body.statements {
                                wasm_collect_extern_contracts(stmt, &mut extern_contracts);
                            }
                        }
                    }
                }
            }

            // Extract function metadata from AST for IDE
            let struct_names: std::collections::HashSet<String> = ast.iter()
                .filter_map(|u| match u {
                    SourceUnit::Struct(sd) => Some(sd.name.clone()),
                    _ => None,
                })
                .collect();
            let mut functions: Vec<WasmFunctionInfo> = Vec::new();
            let mut state_var_types: std::collections::HashMap<String, String> = std::collections::HashMap::new();
            for unit in &ast {
                if let SourceUnit::Contract(c) = unit {
                    for part in &c.parts {
                        if let ContractPart::Function(f) = part {
                            let params: Vec<WasmParamInfo> = f.params.iter().map(|p| WasmParamInfo {
                                name: p.name.clone(),
                                ty: type_name(&p.ty, &struct_names),
                            }).collect();
                            let argc = params.len();
                            functions.push(WasmFunctionInfo {
                                name: f.name.clone(),
                                params,
                                return_type: f.returns.as_ref().map(|t| type_name(t, &struct_names)),
                                argc,
                            });
                        }
                        if let ContractPart::StateVariable(sv) = part {
                            state_var_types.insert(sv.name.clone(), type_name(&sv.ty, &struct_names));
                        }
                    }
                }
            }

            WasmCompileResultJson {
                success: true,
                bytecode: Some(hex::encode(&cr.bytecode)),
                state_vars: cr.state_vars,
                warnings,
                errors: vec![],
                extern_contracts,
                functions,
                state_var_types,
            }
        },
        Err(e) => WasmCompileResultJson {
            success: false,
            bytecode: None,
            state_vars: vec![],
            warnings: vec![],
            errors: vec![e],
            extern_contracts: vec![],
            functions: vec![],
            state_var_types: std::collections::HashMap::new(),
        },
    };
    serde_json::to_string(&result)
        .unwrap_or_else(|e| format!("{{\"success\":false,\"errors\":[\"serialisation error: {}\"]}}", e))
}

/// Compiler version string.
#[wasm_bindgen]
pub fn synq_version() -> String { "0.2.0-wasm".to_string() }


// ── C-ABI export for server-side wasmtime execution ──────────────────────────
#[no_mangle]
pub unsafe extern "C" fn compile_synq_c(src_ptr: *const u8, src_len: usize, out_ptr: *mut u8, out_len: usize) -> i32 {
    let source = match std::slice::from_raw_parts(src_ptr, src_len) {
        s => match std::str::from_utf8(s) {
            Ok(st) => st,
            Err(_) => return -1,
        }
    };

    let result_json = compile_synq(source);
    let result_bytes = result_json.as_bytes();
    let written = result_bytes.len();
    if written > out_len {
        return -1;
    }
    std::ptr::copy_nonoverlapping(result_bytes.as_ptr(), out_ptr, written);
    written as i32
}

// ── Memory allocator for server-side wasmtime C-ABI calls ────────────────────
// ── ForgeIDE-facing compile entry point ───────────────────────────────────────
// forge-v3 (app/lib/ide/compiler.ts) imports this WASM module and calls
// `compiler.compileSynq(source)` expecting a plain JS object shaped exactly
// like the TS `RawCompileResult` / `SynqArtifacts` / `ForgeDiagnostic` types
// in app/lib/ide/types.ts. Everything below is real: bytecode + Solidity
// transpilation come straight from the same IR backend / transpiler the
// native server uses, and every hash is a real SHA3-256 of the actual bytes
// produced — nothing here is fabricated placeholder data. The `manifest`
// field is explicitly a compiler-local *preview* manifest (unsigned) — it is
// not the ML-DSA-87-signed on-chain manifest the server produces, and is
// labelled as such so ForgeIDE never implies an on-chain guarantee it can't
// back up client-side.
#[wasm_bindgen(js_name = compileSynq)]
pub fn compile_synq_ide(source: &str) -> JsValue {
    use sha3::{Digest, Sha3_256};

    fn sha3_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    fn selector_hex(name: &str, param_types: &[String]) -> String {
        let sig = format!("{}({})", name, param_types.join(","));
        let full = sha3_hex(sig.as_bytes());
        format!("0x{}", &full[..8])
    }

    let ast = parser::parse(source).unwrap_or_default();

    let mut diagnostics: Vec<serde_json::Value> = Vec::new();
    let mut artifacts: Option<serde_json::Value> = None;
    let ok;

    match synq_compiler::compile_ir(source) {
        Ok(cr) => {
            ok = true;

            let mut warnings = cr.warnings.clone();
            add_pqc_warnings(&ast, &mut warnings);
            for w in &warnings {
                // IR pipeline stats ("[IR] fn foo: N blocks, ...") are
                // per-function diagnostic telemetry, not something the
                // developer needs to act on - keep them out of the
                // Problems panel by tagging them "info" instead of
                // "warning". Real compiler warnings keep severity "warning".
                let severity = if w.starts_with("[IR] fn ") { "info" } else { "warning" };
                diagnostics.push(serde_json::json!({
                    "severity": severity,
                    "message": w,
                    "line": null,
                    "column": null,
                    "source": "synq-compiler",
                }));
            }

            let contract_name = ast.iter().find_map(|u| match u {
                SourceUnit::Contract(c) => Some(c.name.clone()),
                _ => None,
            }).unwrap_or_else(|| "Contract".to_string());

            // ── ABI methods (real signatures, real selectors) ──────────────
            // First pass: collect state variable names so mutability can be
            // derived from real body analysis (see wasm_stmt_writes_state),
            // not just the opt-in @effects(modifies:) attribute.
            let mut state_var_names: Vec<String> = Vec::new();
            for unit in &ast {
                if let SourceUnit::Contract(c) = unit {
                    for part in &c.parts {
                        if let ContractPart::StateVariable(sv) = part {
                            state_var_names.push(sv.name.clone());
                        }
                    }
                }
            }

            // Collect declared struct names up-front so type_name() can tell
            // a struct-typed Named("Point") apart from an enum-typed
            // Named("Color") -- both use the same AST variant.
            let struct_names: std::collections::HashSet<String> = ast.iter()
                .filter_map(|u| match u {
                    SourceUnit::Struct(sd) => Some(sd.name.clone()),
                    _ => None,
                })
                .collect();

            let mut methods: Vec<serde_json::Value> = Vec::new();
            let mut state_schema: Vec<serde_json::Value> = Vec::new();

            for unit in &ast {
                if let SourceUnit::Contract(c) = unit {
                    for part in &c.parts {
                        match part {
                            ContractPart::Function(f) if f.is_public => {
                                let param_types: Vec<String> =
                                    f.params.iter().map(|p| type_name(&p.ty, &struct_names)).collect();
                                let params: Vec<serde_json::Value> = f.params.iter().map(|p| {
                                    serde_json::json!({ "name": p.name, "type": type_name(&p.ty, &struct_names) })
                                }).collect();
                                let returns: Vec<String> = match &f.returns {
                                    Some(t) => vec![type_name(t, &struct_names)],
                                    None => vec![],
                                };
                                let mut writes = !f.modifies.is_empty();
                                for stmt in &f.body.statements {
                                    wasm_stmt_writes_state(stmt, &state_var_names, &mut writes);
                                }
                                let mutability = if writes { "write" } else { "read" };
                                methods.push(serde_json::json!({
                                    "mutability": mutability,
                                    "name": f.name,
                                    "params": params,
                                    "returns": returns,
                                    "selector": selector_hex(&f.name, &param_types),
                                    "visibility": "public",
                                }));
                            }
                            ContractPart::StateVariable(sv) => {
                                state_schema.push(serde_json::json!({
                                    "name": sv.name,
                                    "type": type_name(&sv.ty, &struct_names),
                                    "visibility": "internal",
                                }));
                            }
                            _ => {}
                        }
                    }
                }
            }

            let mut struct_defs: Vec<serde_json::Value> = Vec::new();
            for unit in &ast {
                if let SourceUnit::Struct(sd) = unit {
                    let fields: Vec<serde_json::Value> = sd.fields.iter().map(|p| {
                        serde_json::json!({ "name": p.name, "type": type_name(&p.ty, &struct_names) })
                    }).collect();
                    struct_defs.push(serde_json::json!({ "name": sd.name, "fields": fields }));
                }
            }

            let abi = serde_json::json!({
                "abi_version": "synq-v3-preview-1",
                "contract": contract_name,
                "methods": methods,
                "events": [],
                "errors": [],
                "security_requirements": {},
                "state_schema": state_schema,
                "structs": struct_defs,
            });

            let bytecode_hex = hex::encode(&cr.bytecode);
            let solidity_compatibility = transpile_solidity::transpile_to_solidity(&ast);

            let manifest = serde_json::json!({
                "kind": "compiler-local-preview",
                "signed": false,
                "note": "Unsigned client-side preview manifest. Not the ML-DSA-87-signed on-chain manifest produced by the SynQ server.",
                "contract": contract_name,
                "compilerVersion": synq_version(),
            });

            let abi_json = serde_json::to_vec(&abi).unwrap_or_default();
            let manifest_json = serde_json::to_vec(&manifest).unwrap_or_default();
            let storage_schema_json = serde_json::to_vec(&state_schema).unwrap_or_default();

            let hashes = serde_json::json!({
                "abi": sha3_hex(&abi_json),
                "bytecode": sha3_hex(&cr.bytecode),
                "manifest": sha3_hex(&manifest_json),
                "source": sha3_hex(source.as_bytes()),
                "storageSchema": sha3_hex(&storage_schema_json),
            });

            artifacts = Some(serde_json::json!({
                "abi": abi,
                "manifest": manifest,
                "bytecodeHex": bytecode_hex,
                "solidityCompatibility": solidity_compatibility,
                "hashes": hashes,
            }));
        }
        Err(e) => {
            ok = false;
            diagnostics.push(serde_json::json!({
                "severity": "error",
                "message": e,
                "line": null,
                "column": null,
                "source": "synq-compiler",
            }));
        }
    }

    let result = serde_json::json!({
        "ok": ok,
        "compilerVersion": format!("SynQ Compiler {} (IR backend, sole path)", synq_version()),
        "diagnostics": diagnostics,
        "artifacts": artifacts,
    });

    let serializer = serde_wasm_bindgen::Serializer::json_compatible();
    serde::Serialize::serialize(&result, &serializer).unwrap_or_else(|e| {
        let fallback = serde_json::json!({
            "ok": false,
            "compilerVersion": "unavailable",
            "diagnostics": [{
                "severity": "error",
                "message": format!("serialisation error: {}", e),
                "line": null,
                "column": null,
                "source": "synq-compiler",
            }],
            "artifacts": null,
        });
        serde::Serialize::serialize(&fallback, &serde_wasm_bindgen::Serializer::json_compatible()).unwrap_or(JsValue::NULL)
    })
}

// The server's wasm_compiler.rs calls synq_wasm_alloc(size) to get a pointer
// into WASM linear memory, writes the source string there, then calls
// compile_synq_c. We use Rust's global allocator (dlmalloc via wasm-bindgen)
// to avoid corrupting heap metadata — a custom bump allocator at a fixed
// offset would overwrite dlmalloc's free list.

use std::alloc::{alloc, Layout};

#[no_mangle]
pub unsafe extern "C" fn synq_wasm_alloc(size: i32) -> i32 {
    if size <= 0 { return 0; }
    let layout = match Layout::from_size_align(size as usize, 1) {
        Ok(l) => l,
        Err(_) => return 0,
    };
    let ptr = alloc(layout);
    if ptr.is_null() { return 0; }
    ptr as i32
}

