//! Integration test: compile SynQ source → AIVM instructions → execute on AIVM

use synq_compiler::parser::parse;
use synq_compiler::aivm_codegen::compile_to_aivm;
use synq_compiler::ast::SourceUnit;
use aivm::vm::{Avm, StateOverlay, FunctionVisibility};
use aivm::host::{HostFunctions, Value};
use aivm::context::ExecutionContext;
use aivm::receipt::ReceiptStatus;

const COUNTER_SOURCE: &str = "contract Counter {\n  state {\n    count: u64;\n  }\n  impl {\n    @public\n    function init() -> bool {\n      count = 0;\n      return true;\n    }\n\n    @public\n    function increment() -> bool {\n      count = count + 1;\n      return true;\n    }\n\n    @public\n    function get() -> u64 {\n      return count;\n    }\n  }\n}\n";

fn extract_contract(ast: &[SourceUnit]) -> &synq_compiler::ast::ContractDefinition {
    ast.iter().find_map(|u| {
        if let SourceUnit::Contract(c) = u { Some(c) } else { None }
    }).expect("no contract found")
}

#[test]
fn test_compile_counter_to_aivm() {
    let ast = parse(COUNTER_SOURCE).unwrap();
    let contract = extract_contract(&ast);
    assert_eq!(contract.name, "Counter");

    let result = compile_to_aivm(contract, &[]).unwrap();

    // Should have 3 functions (init, increment, get)
    assert_eq!(result.functions.len(), 3);
    assert_eq!(result.functions[0].name, "init");
    assert_eq!(result.functions[1].name, "increment");
    assert_eq!(result.functions[2].name, "get");

    // All should be public
    for f in &result.functions {
        assert_eq!(f.visibility, FunctionVisibility::Public);
    }

    // Should have instructions
    assert!(!result.instructions.is_empty());

    // ABI should have 3 methods
    assert_eq!(result.abi.methods.len(), 3);

    // State schema should have 1 field (count)
    assert_eq!(result.abi.state_schema.len(), 1);
    assert_eq!(result.abi.state_schema[0].name, "count");
}

#[test]
fn test_execute_counter_on_aivm() {
    let ast = parse(COUNTER_SOURCE).unwrap();
    let contract = extract_contract(&ast);
    let result = compile_to_aivm(contract, &[]).unwrap();

    let host = HostFunctions::default_v01();
    let avm = Avm::new(result.instructions, result.functions, host);

    let ctx = ExecutionContext::testnet([0u8; 41], [0u8; 41]);
    let mut state = StateOverlay::new();

    // Find init function
    let init_idx = avm.find_function("init").expect("init function not found");
    let init_result = avm.execute(init_idx, vec![], &ctx, &mut state).unwrap();
    assert_eq!(init_result.receipt.status, ReceiptStatus::Success);

    // count should be 0
    let count = state.read(0).unwrap();
    assert_eq!(count, Value::U64(0));

    // Increment 5 times
    let incr_idx = avm.find_function("increment").expect("increment function not found");
    for _ in 0..5 {
        let r = avm.execute(incr_idx, vec![], &ctx, &mut state).unwrap();
        assert_eq!(r.receipt.status, ReceiptStatus::Success);
    }

    // count should be 5
    let count = state.read(0).unwrap();
    assert_eq!(count, Value::U64(5));

    // Get should return 5
    let get_idx = avm.find_function("get").expect("get function not found");
    let get_result = avm.execute(get_idx, vec![], &ctx, &mut state).unwrap();
    assert_eq!(get_result.receipt.status, ReceiptStatus::Success);
    assert_eq!(get_result.return_value, Some(Value::U64(5)));
}

#[test]
fn test_aivm_abi_selectors() {
    let ast = parse(COUNTER_SOURCE).unwrap();
    let contract = extract_contract(&ast);
    let result = compile_to_aivm(contract, &[]).unwrap();

    // Each method should have a unique selector
    let selectors: Vec<&str> = result.abi.methods.iter()
        .map(|m| m.selector.as_str())
        .collect();
    assert_eq!(selectors.len(), 3);
    assert_ne!(selectors[0], selectors[1]);
    assert_ne!(selectors[1], selectors[2]);
    assert_ne!(selectors[0], selectors[2]);

    for s in &selectors {
        assert!(s.starts_with("0x"));
        assert_eq!(s.len(), 10);
    }
}
// BUG FIX REGRESSION (2026-08-22): `continue`/`break` inside a while loop
// used to compile to an unconditional `Ret`, i.e. they returned from the
// *whole function* immediately instead of affecting only the loop. Any
// function that used `continue` to skip an iteration silently exited with
// no return value (decoded client-side as `null`) the first time it hit
// the `continue`. Root cause: aivm_codegen.rs's `Statement::Continue` /
// `Statement::Break` arms literally emitted `Instruction::Ret`. Fixed by
// tracking a loop_stack of (loop_start, break_patch_indices) so `continue`
// jumps back to the condition re-check and `break` jumps to the loop's end.

const COUNT_EVEN_SOURCE: &str = "contract LoopDemo {\n  impl {\n    @public\n    function countEven(n: u256) -> u256 {\n      let count: u256 = 0;\n      let i: u256 = 1;\n      while (i <= n) {\n        let remainder: u256 = i % 2;\n        if (remainder != 0) {\n          i = i + 1;\n          continue;\n        }\n        count = count + 1;\n        i = i + 1;\n      }\n      return count;\n    }\n  }\n}\n";

#[test]
fn test_aivm_continue_does_not_abort_function() {
    let ast = parse(COUNT_EVEN_SOURCE).unwrap();
    let contract = extract_contract(&ast);
    let result = compile_to_aivm(contract, &[]).unwrap();

    let host = HostFunctions::default_v01();
    let avm = Avm::new(result.instructions, result.functions, host);

    let ctx = ExecutionContext::testnet([0u8; 41], [0u8; 41]);
    let mut state = StateOverlay::new();

    let idx = avm.find_function("countEven").expect("countEven function not found");
    // n = 5 -> even numbers are {2, 4} -> count = 2. Before the fix, the
    // first odd iteration's `continue` returned from the function
    // immediately with no return value at all (None, decoded as null).
    let r = avm.execute(idx, vec![Value::U64(5)], &ctx, &mut state).unwrap();
    assert_eq!(r.receipt.status, ReceiptStatus::Success);
    assert_eq!(r.return_value, Some(Value::U64(2)));

    // n = 10 -> evens {2,4,6,8,10} -> count = 5. Exercises multiple
    // continue/loop-back cycles, not just the very first one.
    let r2 = avm.execute(idx, vec![Value::U64(10)], &ctx, &mut state).unwrap();
    assert_eq!(r2.receipt.status, ReceiptStatus::Success);
    assert_eq!(r2.return_value, Some(Value::U64(5)));

    // n = 0 -> loop body never runs -> count = 0.
    let r3 = avm.execute(idx, vec![Value::U64(0)], &ctx, &mut state).unwrap();
    assert_eq!(r3.receipt.status, ReceiptStatus::Success);
    assert_eq!(r3.return_value, Some(Value::U64(0)));
}

const BREAK_SOURCE: &str = "contract BreakDemo {\n  impl {\n    @public\n    function firstMultiple(n: u256, m: u256) -> u256 {\n      let i: u256 = 1;\n      let found: u256 = 0;\n      while (i <= n) {\n        if (i % m == 0) {\n          found = i;\n          break;\n        }\n        i = i + 1;\n      }\n      return found;\n    }\n  }\n}\n";

#[test]
fn test_aivm_break_exits_loop_not_function() {
    let ast = parse(BREAK_SOURCE).unwrap();
    let contract = extract_contract(&ast);
    let result = compile_to_aivm(contract, &[]).unwrap();

    let host = HostFunctions::default_v01();
    let avm = Avm::new(result.instructions, result.functions, host);

    let ctx = ExecutionContext::testnet([0u8; 41], [0u8; 41]);
    let mut state = StateOverlay::new();

    let idx = avm.find_function("firstMultiple").expect("firstMultiple function not found");
    // First multiple of 3 in [1,20] is 3. Before the fix, `break` also
    // compiled to an unconditional Ret, so this happened to still return
    // early -- but the point of this test is `found` (set right before
    // break) makes it out correctly, proving break targets the loop end
    // and not a mid-function abort that skips the rest of the block.
    let r = avm.execute(idx, vec![Value::U64(20), Value::U64(3)], &ctx, &mut state).unwrap();
    assert_eq!(r.receipt.status, ReceiptStatus::Success);
    assert_eq!(r.return_value, Some(Value::U64(3)));

    // No multiple of 100 in [1,20] -> loop runs to completion -> found stays 0.
    let r2 = avm.execute(idx, vec![Value::U64(20), Value::U64(100)], &ctx, &mut state).unwrap();
    assert_eq!(r2.receipt.status, ReceiptStatus::Success);
    assert_eq!(r2.return_value, Some(Value::U64(0)));
}
