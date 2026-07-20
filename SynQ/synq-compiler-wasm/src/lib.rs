
// ── Vendored SynQ compiler + VM source ────────────────────────────────────────
#[macro_use]
extern crate pest_derive;

mod compiler {
    pub mod ast;
    pub mod parser;
    pub mod codegen;
}

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

// ── compile() — exact copy from synq-compiler/src/lib.rs ─────────────────────
use compiler::ast::*;
use compiler::{parser, codegen};
use std::collections::{HashMap, HashSet};

/// Result of compiling a SynQ source file.
#[derive(Debug)]
pub struct CompileResult {
    pub bytecode:          Vec<u8>,
    pub state_vars:        Vec<(String, u32)>,
    pub warnings:          Vec<String>,
    /// Contract names called via extern_call, in first-appearance order, deduplicated.
    pub extern_contracts:  Vec<String>,
}


/// Top-level compile entry point.
/// Returns `Err(String)` for hard errors, `Ok(CompileResult)` with warnings for soft issues.
pub fn compile(source: &str) -> Result<CompileResult, String> {
    let mut warnings: Vec<String> = Vec::new();

    // 1. Parse
    let ast = parser::parse(source)?;

    // 2. Semantic checks per contract
    for unit in &ast {
        if let SourceUnit::Contract(c) = unit {
            check_undefined_refs(&c, &mut warnings)?;
            check_call_graph(&c)?;
        }
    }

    // 3. Codegen
    let gen = codegen::CodeGenerator::new();
    let (bytecode, state_vars) = gen.generate(&ast)?;

    // ── G3: PQC simulation warning ──────────────────────────────────────
    // PQC builtins compile fine but the WASM VM cannot execute them —
    // they throw RuntimeError at runtime. Warn the developer explicitly
    // so they are not surprised when running in the browser IDE.
    const PQC_BUILTINS_WARN: &[&str] = &[
        "dilithium_verify", "falcon_verify", "sphincs_verify",
        "kyber_encapsulate", "kyber_decapsulate", "kyber_decaps",
        "falcon_sign", "mceliece_encapsulate", "mceliece_decapsulate",
        "hqc_encapsulate", "hqc_decapsulate",
    ];
    'pqc_check: for unit in &ast {
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

    // Collect extern_call targets for tamper-detection cross-check with server.
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

    Ok(CompileResult { bytecode, state_vars, warnings, extern_contracts })
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

fn collect_identifiers(expr: &Expression, out: &mut Vec<String>) {
    match expr {
        Expression::Identifier(n) => out.push(n.clone()),
        Expression::BinaryOp(l, _, r) => {
            collect_identifiers(l, out);
            collect_identifiers(r, out);
        }
        Expression::Call(_, args) => {
            for a in args { collect_identifiers(a, out); }
        }
        _ => {}
    }
}

fn collect_calls(expr: &Expression, out: &mut Vec<(String, usize)>) {
    match expr {
        Expression::Call(name, args) => {
            out.push((name.clone(), args.len()));
            for a in args { collect_calls(a, out); }
        }
        Expression::BinaryOp(l, _, r) => {
            collect_calls(l, out);
            collect_calls(r, out);
        }
        _ => {}
    }
}

const PQC_BUILTINS: &[&str] = &[
    "dilithium_verify", "falcon_verify", "sphincs_verify",
    "kyber_encapsulate", "kyber_decapsulate", "kyber_decaps",
    "falcon_sign", "mceliece_encapsulate", "mceliece_decapsulate",
    "hqc_encapsulate", "hqc_decapsulate",
];

fn check_undefined_refs(contract: &ContractDefinition, warnings: &mut Vec<String>) -> Result<(), String> {
    let state_names: HashSet<&str> = contract.parts.iter().filter_map(|p| {
        if let ContractPart::StateVariable(sv) = p { Some(sv.name.as_str()) } else { None }
    }).collect();

    let fn_names: HashSet<&str> = contract.parts.iter().filter_map(|p| {
        if let ContractPart::Function(f) = p { Some(f.name.as_str()) } else { None }
    }).collect();

    for part in &contract.parts {
        if let ContractPart::Function(f) = part {
            let param_names: HashSet<&str> = f.params.iter().map(|p| p.name.as_str()).collect();

            let all_stmts: Vec<&Statement> = f.body.statements.iter().collect();
            for stmt in all_stmts {
                let exprs: Vec<&Expression> = match stmt {
                    Statement::Expression(e) => vec![e],
                    Statement::Require(e, _) => vec![e],
                    Statement::Assignment(_, e) => vec![e],
                    Statement::Return(Some(e)) => vec![e],
                    Statement::Return(None) => vec![],
                    Statement::ExternCall { args, .. } => args.iter().collect(),
                    Statement::Emit { args, .. } => args.iter().collect(),
                    Statement::RevertNamed { args, .. } => args.iter().collect(),
                    Statement::If { condition, then_block: _, else_block: _ } => vec![condition],
                    Statement::Let { value, .. } => vec![value],
                    Statement::MapAssignment { key, value, .. } => vec![key, value],
                    Statement::SetOp { value, .. } => vec![value],
                    Statement::While { condition, .. } => vec![condition],
                    Statement::Break | Statement::Continue => vec![],
                };
                for expr in exprs {
                    // Check identifiers
                    let mut idents = Vec::new();
                    collect_identifiers(expr, &mut idents);
                    for id in &idents {
                        if !state_names.contains(id.as_str())
                            && !param_names.contains(id.as_str())
                            && !PQC_BUILTINS.contains(&id.as_str())
                        {
                            return Err(format!(
                                "undefined variable '{}' in function '{}' of contract '{}'",
                                id, f.name, contract.name
                            ));
                        }
                    }
                    // Check calls
                    let mut calls = Vec::new();
                    collect_calls(expr, &mut calls);
                    for (callee, _arg_count) in &calls {
                        if !fn_names.contains(callee.as_str())
                            && !PQC_BUILTINS.contains(&callee.as_str())
                        {
                            return Err(format!(
                                "undefined function '{}' called in '{}' of contract '{}'",
                                callee, f.name, contract.name
                            ));
                        }
                    }
                    // Warn on negative literal pattern (0 - N for UInt256)
                    check_negative_literal(expr, &f.name, warnings);
                }
            }
        }
    }
    Ok(())
}

fn check_negative_literal(expr: &Expression, fn_name: &str, warnings: &mut Vec<String>) {
    if let Expression::BinaryOp(l, BinaryOperator::Sub, r) = expr {
        if let Expression::Literal(Literal::Number(0)) = l.as_ref() {
            if let Expression::Literal(Literal::Number(n)) = r.as_ref() {
                warnings.push(format!(
                    "negative literal (-{}) in function '{}': UInt256 has no sign; this will underflow at runtime",
                    n, fn_name
                ));
            }
        }
    }
    // Recurse
    match expr {
        Expression::BinaryOp(l, _, r) => {
            check_negative_literal(l, fn_name, warnings);
            check_negative_literal(r, fn_name, warnings);
        }
        Expression::Call(_, args) => {
            for a in args { check_negative_literal(a, fn_name, warnings); }
        }
        _ => {}
    }
}

// ─── Semantic check: call-graph cycle detection (max depth 8) ────────────────

fn check_call_graph(contract: &ContractDefinition) -> Result<(), String> {
    // Build adjacency: fn_name -> set of called fn names (contract-internal only)
    let fn_names: HashSet<&str> = contract.parts.iter().filter_map(|p| {
        if let ContractPart::Function(f) = p { Some(f.name.as_str()) } else { None }
    }).collect();

    let mut adj: HashMap<&str, Vec<String>> = HashMap::new();
    for part in &contract.parts {
        if let ContractPart::Function(f) = part {
            let mut calls: Vec<(String, usize)> = Vec::new();
            for stmt in &f.body.statements {
                let exprs: Vec<&Expression> = match stmt {
                    Statement::Expression(e) => vec![e],
                    Statement::Require(e, _) => vec![e],
                    Statement::Assignment(_, e) => vec![e],
                    Statement::Return(Some(e)) => vec![e],
                    Statement::Return(None) => vec![],
                    Statement::ExternCall { args, .. } => args.iter().collect(),
                    Statement::Emit { args, .. } => args.iter().collect(),
                    Statement::RevertNamed { args, .. } => args.iter().collect(),
                    Statement::If { condition, then_block: _, else_block: _ } => vec![condition],
                    Statement::Let { value, .. } => vec![value],
                    Statement::MapAssignment { key, value, .. } => vec![key, value],
                    Statement::SetOp { value, .. } => vec![value],
                    Statement::While { condition, .. } => vec![condition],
                    Statement::Break | Statement::Continue => vec![],
                };
                for expr in exprs { collect_calls(expr, &mut calls); }
            }
            let callees: Vec<String> = calls.iter()
                .filter_map(|(name, _)| if fn_names.contains(name.as_str()) { Some(name.clone()) } else { None })
                .collect();
            adj.insert(f.name.as_str(), callees);
        }
    }

    // DFS cycle + depth check from each function
    for start in fn_names.iter() {
        let mut path: Vec<&str> = Vec::new();
        dfs_check(start, &adj, &mut path)?;
    }
    Ok(())
}

// Maximum static call-chain depth enforced at compile time.
//
// Rationale for 64:
//   - Recursion (cycles) is banned entirely by the DFS cycle check above,
//     independent of this limit.
//   - This limit guards against pathologically deep *non-recursive* call chains
//     that would exhaust the QVM's call stack at runtime.
//   - Comparison with other runtimes:
//       EVM (Ethereum)  1 024  — hard consensus rule, one frame per CALL opcode
//       Solana BPF         64  — explicit VM-level call depth limit
//       WASM (browsers) ~10k+  — bounded by host OS stack
//       Move / Cairo        0  — recursion banned by type system (no limit needed)
//   - 64 matches Solana BPF, a well-studied non-EVM smart-contract VM with
//     similar resource-constraint goals to QVM.
//   - The QVM does not yet have per-call stack frames (that work lands in PR-B).
//     Once PR-B ships, the *runtime* will enforce its own depth limit naturally;
//     this static check then becomes a fast-fail for obviously degenerate
//     contracts rather than an absolute ceiling.
//   - 8 (the previous value) was too conservative: a normal contract with
//     init → validate → checkOwner → resolveAddress already consumes 4 hops,
//     leaving only 4 hops of headroom for real business logic.
const MAX_CALL_DEPTH: usize = 64;

fn dfs_check<'a>(
    node: &'a str,
    adj: &'a HashMap<&'a str, Vec<String>>,
    path: &mut Vec<&'a str>,
) -> Result<(), String> {
    if path.contains(&node) {
        let cycle_start = path.iter().position(|&n| n == node).unwrap();
        let cycle: Vec<&str> = path[cycle_start..].iter().copied().chain(std::iter::once(node)).collect();
        return Err(format!("recursive call detected: {}", cycle.join(" -> ")));
    }
    if path.len() >= MAX_CALL_DEPTH {
        return Err(format!("call chain exceeds maximum depth ({}) starting from '{}'", MAX_CALL_DEPTH, path[0]));
    }
    path.push(node);
    if let Some(callees) = adj.get(node) {
        for callee in callees {
            dfs_check(callee.as_str(), adj, path)?;
        }
    }
    path.pop();
    Ok(())
}

// ── wasm-bindgen surface ──────────────────────────────────────────────────────
use wasm_bindgen::prelude::*;
use serde::Serialize;

#[derive(Serialize)]
struct WasmCompileResult {
    success:           bool,
    bytecode:          Option<String>,
    state_vars:        Vec<(String, u32)>,
    warnings:          Vec<String>,
    errors:            Vec<String>,
    /// Contract names this contract calls via extern_call.
    /// Returned to the frontend so it can be sent to the server for cross-validation.
    extern_contracts:  Vec<String>,
}

/// Compile a SynQ source string in-browser. Returns JSON.
/// Bytecode is lowercase hex. Call POST /synq/sign to attach ML-DSA-65 sidecar.
#[wasm_bindgen]
pub fn compile_synq(source: &str) -> String {
    let result = match compile(source) {
        Ok(cr) => WasmCompileResult {
            success:          true,
            bytecode:         Some(hex::encode(&cr.bytecode)),
            state_vars:       cr.state_vars,
            warnings:         cr.warnings,
            errors:           vec![],
            extern_contracts: cr.extern_contracts,
        },
        Err(e) => WasmCompileResult {
            success:          false,
            bytecode:         None,
            state_vars:       vec![],
            warnings:         vec![],
            errors:           vec![e],
            extern_contracts: vec![],
        },
    };
    serde_json::to_string(&result)
        .unwrap_or_else(|e| format!("{{\"success\":false,\"errors\":[\"serialisation error: {}\"]}}", e))
}

/// Compiler version string.
#[wasm_bindgen]
pub fn synq_version() -> String { "0.1.0-wasm".to_string() }
