#[macro_use]
extern crate pest_derive;

pub mod ast;
pub mod parser;
pub mod codegen;
pub mod pqc_integration;

pub use pqc_integration::{PQCCompiler, PQCSecurityLevel};

use ast::*;
use std::collections::{HashMap, HashSet};

/// Result of compiling a SynQ source file.
#[derive(Debug)]
pub struct CompileResult {
    pub bytecode: Vec<u8>,
    pub state_vars: Vec<(String, u32)>,
    pub warnings: Vec<String>,
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
            check_undefined_refs(c, &mut warnings)?;
            check_call_graph(c)?;
        }
    }

    // 3. Codegen
    let gen = codegen::CodeGenerator::new();
    let (bytecode, state_vars) = gen.generate(&ast)?;

    Ok(CompileResult { bytecode, state_vars, warnings })
}

// ─── Semantic check: undefined variables and calls ───────────────────────────

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

fn dfs_check<'a>(
    node: &'a str,
    adj: &'a HashMap<&'a str, Vec<String>>,
    path: &mut Vec<&'a str>,
) -> Result<(), String> {
    const MAX_DEPTH: usize = 8;
    if path.contains(&node) {
        let cycle_start = path.iter().position(|&n| n == node).unwrap();
        let cycle: Vec<&str> = path[cycle_start..].iter().copied().chain(std::iter::once(node)).collect();
        return Err(format!("recursive call detected: {}", cycle.join(" -> ")));
    }
    if path.len() >= MAX_DEPTH {
        return Err(format!("call chain exceeds maximum depth ({}) starting from '{}'", MAX_DEPTH, path[0]));
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
