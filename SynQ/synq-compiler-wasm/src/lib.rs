// ── SynQ WASM Compiler — uses synq-compiler crate IR backend ──────────────────
// v0.2: Uses compile_ir() from the compiler crate for bytecode consistency
//       with the native server. Eliminates vendored compiler duplication.

use wasm_bindgen::prelude::*;
use synq_compiler::{self, ast::*, parser};
use synq_compiler::ast::{SourceUnit, ContractPart, Statement, Expression, Type};

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
fn type_name(ty: &Type) -> String {
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
            let mut functions: Vec<WasmFunctionInfo> = Vec::new();
            let mut state_var_types: std::collections::HashMap<String, String> = std::collections::HashMap::new();
            for unit in &ast {
                if let SourceUnit::Contract(c) = unit {
                    for part in &c.parts {
                        if let ContractPart::Function(f) = part {
                            let params: Vec<WasmParamInfo> = f.params.iter().map(|p| WasmParamInfo {
                                name: p.name.clone(),
                                ty: type_name(&p.ty),
                            }).collect();
                            let argc = params.len();
                            functions.push(WasmFunctionInfo {
                                name: f.name.clone(),
                                params,
                                return_type: f.returns.as_ref().map(|t| type_name(t)),
                                argc,
                            });
                        }
                        if let ContractPart::StateVariable(sv) = part {
                            state_var_types.insert(sv.name.clone(), type_name(&sv.ty));
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

