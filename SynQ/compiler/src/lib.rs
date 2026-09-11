#[macro_use]
extern crate pest_derive;

pub mod ast;
pub mod ir;
pub mod parser;
pub mod pqc_integration;
pub mod aivm_codegen;
pub mod transpile_solidity;

pub use pqc_integration::{PQCCompiler, PQCSecurityLevel};

use ast::*;
use std::collections::{HashMap, HashSet};

/// Result of compiling a SynQ source file.
#[derive(Debug)]
pub struct CompileResult {
    pub bytecode:         Vec<u8>,
    pub state_vars:       Vec<(String, u32)>,
    pub warnings:         Vec<String>,
    /// Contract names called via extern_call, in first-appearance order, deduplicated.
    pub extern_contracts: Vec<String>,
    /// Full SSA IR dump for each function (block-by-block instruction listing).
    pub ir_dump:          Vec<String>,
    /// Binary-serialized SSA IR (SIR1 format) for SQB IR section.
    pub ir_binary:        Vec<u8>,
}

/// Compile using the IR -> bytecode backend (v7.0 path).
/// Builds SSA IR, runs optimization passes, and lowers to QVM bytecode.
pub fn compile_ir(source: &str) -> Result<CompileResult, String> {
    let mut warnings: Vec<String> = Vec::new();

    // 1. Parse
    let ast = parser::parse(source)?;

    // 2. Semantic checks per contract. check_undefined_refs now collects
    // every undefined-variable/-function error it finds (see its own doc
    // comment) instead of stopping at the first one -- gather those across
    // ALL contracts in the file before failing, so e.g. two unrelated typos
    // in two different functions both come back in one compile instead of
    // only ever surfacing the first (line-order-wise) one. check_call_graph
    // only runs once every contract's refs are clean.
    let mut semantic_errors: Vec<String> = Vec::new();
    for unit in &ast {
        if let SourceUnit::Contract(ref c) = unit {
            if let Err(errs) = check_undefined_refs(c, &mut warnings) {
                semantic_errors.extend(errs);
            }
        }
    }
    if !semantic_errors.is_empty() {
        return Err(semantic_errors.join("\n"));
    }
    for unit in &ast {
        if let SourceUnit::Contract(ref c) = unit {
            check_call_graph(c)?;
        }
    }

    // 3. Collect extern_call targets
    let mut extern_contracts: Vec<String> = Vec::new();
    for unit in &ast {
        if let SourceUnit::Contract(ref c) = unit {
            for part in &c.parts {
                if let crate::ast::ContractPart::Function(f) = part {
                    for stmt in &f.body.statements {
                        collect_extern_contracts_stmt(stmt, &mut extern_contracts);
                    }
                }
            }
        }
    }

    // 4. Build SSA IR and run optimization passes
    let mut ir_dump: Vec<String> = Vec::new();
    let mut ir_module = {
        let mut ir_builder = ir::IrBuilder::new();
        match ir_builder.build(&ast) {
            Ok(m) => m,
            Err(e) => return Err(format!("IR build error: {}", e)),
        }
    };

    // Run SSA optimization passes
    for func in &mut ir_module.functions {
        let pass_reports = ir::passes::run_passes(func);
        for report in &pass_reports {
            warnings.push(format!("[IR] fn {}: {}", func.name, report));
        }
    }

    let ir_report = ir::analyze(&mut ir_module);
    if !ir_report.is_ok() {
        for err in &ir_report.errors {
            warnings.push(format!("[IR] {}", err));
        }
    }
    for stat in &ir_report.function_stats {
        warnings.push(format!(
            "[IR] fn {}: {} blocks, {} insts, {} reachable, {} effects, {} host_profiles, {} auth_checks, {} linear_creates, {} linear_consumes",
            stat.name, stat.block_count, stat.instruction_count,
            stat.reachable_blocks, stat.effects.len(),
            stat.host_profiles, stat.authority_checks,
            stat.linear_creates, stat.linear_consumes
        ));
    }

    ir_dump.push(ir_module.dump());

    // 5. Lower IR to bytecode
    let bytecode = ir::lower::IrLowerer::lower(&ir_module)?;

    // Collect state vars from IR module
    let state_vars: Vec<(String, u32)> = ir_module.state_vars.iter()
        .map(|(name, _ty, addr)| (name.clone(), *addr))
        .collect();

    // Serialize IR module to binary format for SQB
    let ir_binary = ir::serialize::serialize(&ir_module);

    Ok(CompileResult { bytecode, state_vars, warnings, extern_contracts, ir_dump, ir_binary })
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
        Expression::FieldAccess { object, .. } => {
            // Only collect the root identifier, not field names
            collect_identifiers(object, out);
        }
        Expression::StructLiteral { fields, .. } => {
            for (_, v) in fields { collect_identifiers(v, out); }
        }
        Expression::MapIndex(map, keys) => {
            out.push(map.clone());
            for k in keys { collect_identifiers(k, out); }
        }
        Expression::MapMethod { map, args, .. } => {
            out.push(map.clone());
            for a in args { collect_identifiers(a, out); }
        }
        Expression::SetMethod { set, args, .. } => {
            out.push(set.clone());
            for a in args { collect_identifiers(a, out); }
        }
        Expression::UnaryOp(_, inner) => collect_identifiers(inner, out),
        Expression::Tuple(exprs) => {
            for e in exprs { collect_identifiers(e, out); }
        }
        Expression::Some(inner) => collect_identifiers(inner, out),
        Expression::Ok(inner) => collect_identifiers(inner, out),
        Expression::Err(inner) => collect_identifiers(inner, out),
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
    // Authority builtins (v7.0 authority model)
    "authority_envelope", "authority_require", "authority_identity",
    // Address builtins (V3 Bech32)
    "to_tsynq", "from_tsynq", "to_syna", "from_syna", "contract_address",
    // AEG1 builtins
    "aegis_call", "aegis_verify", "aegis_decaps",
    // String builtins
    "str_len", "str_concat", "str_eq",
    // Asset builtins
    "asset_create", "asset_transfer", "asset_burn", "asset_balance", "asset_owner",
    // Map builtins
    "map_get", "map_set",
    // External call (expression context)
    "extern_call",
];

fn check_undefined_refs(contract: &ContractDefinition, warnings: &mut Vec<String>) -> Result<(), Vec<String>> {
    // Accumulates every undefined-variable/-function error found across the
    // whole contract. Previously this function returned on the FIRST bad
    // identifier via `return Err(...)`, so a second, unrelated typo later in
    // the file (even in a different function) was invisible until the first
    // one was fixed and the file recompiled. Now every statement is still
    // checked and all errors are collected, so ForgeIDE/Playground can list
    // them all in one compile.
    let state_names: HashSet<&str> = contract.parts.iter().filter_map(|p| {
        if let ContractPart::StateVariable(sv) = p { Some(sv.name.as_str()) } else { None }
    }).collect();

    let fn_names: HashSet<&str> = contract.parts.iter().filter_map(|p| {
        if let ContractPart::Function(f) = p { Some(f.name.as_str()) } else { None }
    }).collect();

    let mut errors: Vec<String> = Vec::new();

    for part in &contract.parts {
        if let ContractPart::Function(f) = part {
            let param_names: HashSet<&str> = f.params.iter().map(|p| p.name.as_str()).collect();

            // Collect let-bound variable names (function-scoped)
            let let_names: HashSet<String> = f.body.statements.iter().flat_map(|s| {
                match s {
                    Statement::Let { name, .. } => vec![name.clone()],
                    Statement::LetDestructure { names, .. } => names.clone(),
                    _ => vec![],
                }
            }).collect();

            // f.body.spans is parallel to f.body.statements (see Block's
            // doc comment) -- every statement the parser produced carries
            // its real source line/column. Undefined-variable/-function
            // errors previously reported no position at all, so Forge's
            // Problems tab and Contracts panel both fell back to a fake
            // "line 1" location for these. Zip statements with their span
            // and append it in the same "--> LINE:COL" form the pest parse
            // errors already use, so the existing frontend regex that
            // extracts a diagnostic's real position picks it up for free.
            for (stmt_idx, stmt) in f.body.statements.iter().enumerate() {
                let span = f.body.spans.get(stmt_idx).copied().unwrap_or_default();
                let exprs: Vec<&Expression> = match stmt {
                    Statement::Expression(e) => vec![e],
                    Statement::Require(e, _) => vec![e],
                    Statement::Assignment(_, e) => vec![e],
                    Statement::Return(Some(e)) => vec![e],
                    Statement::Return(None) => vec![],
                    Statement::ExternCall { args, .. } => args.iter().collect(),
                    Statement::Emit { args, .. } => args.iter().collect(),
                    Statement::RevertNamed { args, .. } => args.iter().collect(),
                    Statement::RevertEnum { args, .. } => args.iter().collect(),
                    Statement::If { condition, then_block: _, else_block: _ } => vec![condition],
                    Statement::Let { value, .. } => vec![value],
                    Statement::LetDestructure { value, .. } => vec![value.as_ref()],
                    Statement::MapAssignment { keys, value, .. } => { let mut v: Vec<&Expression> = keys.iter().collect(); v.push(value); v },
                    Statement::FieldAssignment { value, .. } => vec![value],
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
                            && !let_names.contains(id)
                            && !PQC_BUILTINS.contains(&id.as_str())
                            && id != "caller"
                        {
                            errors.push(format!(
                                "undefined variable '{}' in function '{}' of contract '{}' --> {}:{}",
                                id, f.name, contract.name, span.line, span.column
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
                            errors.push(format!(
                                "undefined function '{}' called in '{}' of contract '{}' --> {}:{}",
                                callee, f.name, contract.name, span.line, span.column
                            ));
                        }
                    }
                    // Warn on negative literal pattern (0 - N for UInt256)
                    check_negative_literal(expr, &f.name, warnings);
                }
            }
        }
    }
    if errors.is_empty() { Ok(()) } else { Err(errors) }
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
                    Statement::RevertEnum { args, .. } => args.iter().collect(),
                    Statement::If { condition, then_block: _, else_block: _ } => vec![condition],
                    Statement::Let { value, .. } => vec![value],
                    Statement::LetDestructure { value, .. } => vec![value.as_ref()],
                    Statement::MapAssignment { keys, value, .. } => { let mut v: Vec<&Expression> = keys.iter().collect(); v.push(value); v },
                    Statement::FieldAssignment { value, .. } => vec![value],
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

/// Recursively walk a statement collecting unique extern_call contract targets.
fn collect_extern_contracts_stmt(stmt: &crate::ast::Statement, out: &mut Vec<String>) {
    use crate::ast::Statement;
    match stmt {
        Statement::ExternCall { contract, .. } => {
            if !out.contains(contract) { out.push(contract.clone()); }
        }
        Statement::If { then_block, else_block, .. } => {
            for s in &then_block.statements { collect_extern_contracts_stmt(s, out); }
            if let Some(eb) = else_block {
                for s in &eb.statements { collect_extern_contracts_stmt(s, out); }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod struct_tests {
    use super::*;
// Test: Struct creation + field access via TuplePack/TupleGet
// Verifies that struct literals create Tuple values and field access extracts fields.

use crate::parser::parse;

#[test]
fn test_ir_backend_simple_contract() {
    let source = r#"pragma synq ^0.9;
contract SimpleContract {
    state {
        value: u256;
        initialised: bool;
    }
    @public
    function init() -> bool {
        if (!initialised) {
            value = 42;
            initialised = true;
        }
        return true;
    }
    @public
    function get_value() -> u256 {
        return value;
    }
}
"#;
    let result = compile_ir(source).expect("IR compile failed");
    assert!(!result.bytecode.is_empty(), "IR bytecode should not be empty");
    assert!(result.bytecode.len() > 20, "IR bytecode should have header + code");
    // Verify header magic (QVM\0)
    let magic = u32::from_le_bytes(result.bytecode[0..4].try_into().unwrap());
    assert_eq!(magic, 0x51564D00, "IR bytecode should have QVM magic");
    // Verify state vars
    assert_eq!(result.state_vars.len(), 2, "should have 2 state vars");
}

#[test]
fn test_ir_backend_arithmetic() {
    let source = r#"pragma synq ^0.9;
contract ArithContract {
    state {
        a: u256;
        b: u256;
    }
    @public
    function set_values(x: u256, y: u256) -> bool {
        a = x;
        b = y;
        return true;
    }
    @public
    function add() -> u256 {
        return a + b;
    }
    @public
    function multiply() -> u256 {
        return a * b;
    }
}
"#;
    let result = compile_ir(source).expect("IR compile failed");
    assert!(!result.bytecode.is_empty());
    // Should have Add (0x10) and Mul (0x12) opcodes somewhere in the bytecode
    let code_start = 15; // past header
    let code = &result.bytecode[code_start..];
    assert!(code.contains(&(0x10)), "IR bytecode should contain Add opcode");
    assert!(code.contains(&(0x12)), "IR bytecode should contain Mul opcode");
}

#[test]
fn test_ir_backend_conditional() {
    let source = r#"pragma synq ^0.9;
contract CondContract {
    state {
        flag: bool;
        result: u256;
    }
    @public
    function set_if(x: u256) -> bool {
        if (x > 10) {
            result = x;
            flag = true;
        } else {
            result = 0;
            flag = false;
        }
        return true;
    }
    @public
    function get_result() -> u256 {
        return result;
    }
}
"#;
    let result = compile_ir(source).expect("IR compile failed");
    assert!(!result.bytecode.is_empty());
    // Should have JumpIf (0x31) and Jump (0x30) for if/else
    let code = &result.bytecode[15..];
    assert!(code.contains(&(0x31)), "IR bytecode should contain JumpIf for if/else");
    assert!(code.contains(&(0x30)), "IR bytecode should contain Jump for else branch");
}

#[test]
fn test_ir_backend_loop() {
    let source = r#"pragma synq ^0.9;
contract LoopContract {
    state {
        counter: u256;
        sum: u256;
    }
    @public
    function loop_sum(n: u256) -> bool {
        let i: u256 = 0;
        sum = 0;
        while (i < n) {
            sum = sum + i;
            i = i + 1;
        }
        return true;
    }
    @public
    function get_sum() -> u256 {
        return sum;
    }
}
"#;
    let result = compile_ir(source).expect("IR compile failed");
    assert!(!result.bytecode.is_empty());
    // Should have JumpIf (0x31) for while loop condition and Jump (0x30) for back-edge
    let code = &result.bytecode[15..];
    assert!(code.contains(&(0x31)), "IR bytecode should contain JumpIf for while loop");
}


#[test]
fn test_ir_backend_struct_contract() {
    let source = r#"pragma synq ^0.9;
struct Point {
    x: u256;
    y: u256;
}
contract StructContract {
    state {
        origin: Point;
    }
    @public
    function set_origin(x: u256, y: u256) -> bool {
        origin = Point { x: x, y: y };
        return true;
    }
    @public
    function get_x() -> u256 {
        return origin.x;
    }
}
"#;
    let result = compile_ir(source).expect("IR compile failed");
    assert!(!result.bytecode.is_empty());
    // Should have TuplePack (0xA0) for struct literal
    let code = &result.bytecode[15..];
    assert!(code.contains(&(0xA0)), "IR bytecode should contain TuplePack for struct literal");
}

#[test]
fn test_ir_backend_enum_access() {
    let source = r#"pragma synq ^0.9;
enum Status { Active, Inactive, Pending }
contract EnumContract {
    state {
        status: u256;
    }
    @public
    function set_active() -> bool {
        status = Status::Active;
        return true;
    }
    @public
    function set_pending() -> bool {
        status = Status::Pending;
        return true;
    }
}
"#;
    let result = compile_ir(source).expect("IR compile failed");
    assert!(!result.bytecode.is_empty());
    // Status::Active should emit Push 0, Status::Pending should emit Push 2
    let code = &result.bytecode[15..];
    // Just verify it compiles and has Push opcodes
    assert!(code.contains(&(0x01)), "IR bytecode should contain Push for enum tag");
}

}
