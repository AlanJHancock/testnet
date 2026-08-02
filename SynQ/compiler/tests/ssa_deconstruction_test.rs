//! Comprehensive SSA deconstruction tests.
//! Verifies that the SSA IR → phi → moves → bytecode pipeline produces
//! correct results for all major CFG patterns.

use synq_compiler::compile_ir;
use quantumvm::{QuantumVM, Value};
use ruint::aliases::U256;

fn as_u128(v: &Value) -> u128 {
    match v {
        Value::I32(n) => *n as u128,
        Value::U128(n) => *n,
        Value::U256(n) => n.to::<u128>(),
        _ => 0,
    }
}

fn compile_and_call(source: &str, fn_name: &str, args: &[Value]) -> Value {
    let result = compile_ir(source).expect("compile_ir failed");
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&result.bytecode).expect("load_bytecode failed");
    
    // Call init if it exists
    let _ = vm.call_function("init", &[]);
    
    let ret = vm.call_function(fn_name, args).expect("call_function failed");
    ret.expect("function returned void")
}

// ── Pattern 1: Simple loop with counter ──────────────────────────────
#[test]
fn test_ssa_simple_loop_counter() {
    let source = r#"
pragma synq ^0.9;
contract Test {
    state { initialised: bool; }
    @public
    function init() -> bool { initialised = true; return true; }
    @public
    function sumTo(n: u256) -> u256 {
        let i: u256 = 0;
        let total: u256 = 0;
        while (i < n) {
            total = total + i;
            i = i + 1;
        }
        return total;
    }
}
"#;
    let result = compile_and_call(source, "sumTo", &[Value::I32(10)]);
    assert_eq!(as_u128(&result), 45, "sumTo(10) should be 45 (0+1+...+9)");
}

// ── Pattern 2: If-else with variable merge ────────────────────────────
#[test]
fn test_ssa_if_else_merge() {
    let source = r#"
pragma synq ^0.9;
contract Test {
    state { initialised: bool; }
    @public
    function init() -> bool { initialised = true; return true; }
    @public
    function branch(flag: u256) -> u256 {
        let result: u256 = 0;
        if (flag > 0) {
            result = 100;
        } else {
            result = 200;
        }
        return result;
    }
}
"#;
    let r1 = compile_and_call(source, "branch", &[Value::I32(1)]);
    assert_eq!(as_u128(&r1), 100, "branch(1) should be 100");
    let r2 = compile_and_call(source, "branch", &[Value::I32(0)]);
    assert_eq!(as_u128(&r2), 200, "branch(0) should be 200");
}

// ── Pattern 3: Nested loops ───────────────────────────────────────────
#[test]
fn test_ssa_nested_loops() {
    let source = r#"
pragma synq ^0.9;
contract Test {
    state { initialised: bool; }
    @public
    function init() -> bool { initialised = true; return true; }
    @public
    function nestedSum(n: u256, m: u256) -> u256 {
        let total: u256 = 0;
        let i: u256 = 0;
        while (i < n) {
            let j: u256 = 0;
            while (j < m) {
                total = total + 1;
                j = j + 1;
            }
            i = i + 1;
        }
        return total;
    }
}
"#;
    let result = compile_and_call(source, "nestedSum", &[Value::I32(3), Value::I32(4)]);
    assert_eq!(as_u128(&result), 12, "nestedSum(3,4) should be 12 (3*4)");
}

// ── Pattern 4: Loop with break ─────────────────────────────────────────
#[test]
fn test_ssa_loop_break() {
    let source = r#"
pragma synq ^0.9;
contract Test {
    state { initialised: bool; }
    @public
    function init() -> bool { initialised = true; return true; }
    @public
    function findFirst(target: u256, max: u256) -> u256 {
        let i: u256 = 0;
        let found: u256 = 999;
        while (i < max) {
            if (i == target) {
                found = i;
                break;
            }
            i = i + 1;
        }
        return found;
    }
}
"#;
    let r1 = compile_and_call(source, "findFirst", &[Value::I32(5), Value::I32(10)]);
    assert_eq!(as_u128(&r1), 5, "findFirst(5,10) should be 5");
    let r2 = compile_and_call(source, "findFirst", &[Value::I32(15), Value::I32(10)]);
    assert_eq!(as_u128(&r2), 999, "findFirst(15,10) should be 999 (not found)");
}

// ── Pattern 5: Loop with continue ────────────────────────────────────
#[test]
fn test_ssa_loop_continue() {
    let source = r#"
pragma synq ^0.9;
contract Test {
    state { initialised: bool; }
    @public
    function init() -> bool { initialised = true; return true; }
    @public
    function sumSkipEvens(n: u256) -> u256 {
        let i: u256 = 0;
        let total: u256 = 0;
        while (i < n) {
            if (i % 2 == 0) {
                i = i + 1;
                continue;
            }
            total = total + i;
            i = i + 1;
        }
        return total;
    }
}
"#;
    let result = compile_and_call(source, "sumSkipEvens", &[Value::I32(10)]);
    // Sum of odds from 0-9: 1+3+5+7+9 = 25
    assert_eq!(as_u128(&result), 25, "sumSkipEvens(10) should be 25");
}

// ── Pattern 6: Multiple variables in loop ────────────────────────────
#[test]
fn test_ssa_multiple_loop_vars() {
    let source = r#"
pragma synq ^0.9;
contract Test {
    state { initialised: bool; }
    @public
    function init() -> bool { initialised = true; return true; }
    @public
    function fibonacci(n: u256) -> u256 {
        let a: u256 = 0;
        let b: u256 = 1;
        let i: u256 = 0;
        while (i < n) {
            let temp: u256 = a + b;
            a = b;
            b = temp;
            i = i + 1;
        }
        return a;
    }
}
"#;
    let r0 = compile_and_call(source, "fibonacci", &[Value::I32(0)]);
    assert_eq!(as_u128(&r0), 0, "fib(0) = 0");
    let r1 = compile_and_call(source, "fibonacci", &[Value::I32(1)]);
    assert_eq!(as_u128(&r1), 1, "fib(1) = 1");
    let r10 = compile_and_call(source, "fibonacci", &[Value::I32(10)]);
    assert_eq!(as_u128(&r10), 55, "fib(10) = 55");
}

// ── Pattern 7: If-else-if chain (multiple merge points) ────────────────
#[test]
fn test_ssa_if_elseif_chain() {
    let source = r#"
pragma synq ^0.9;
contract Test {
    state { initialised: bool; }
    @public
    function init() -> bool { initialised = true; return true; }
    @public
    function classify(x: u256) -> u256 {
        let category: u256 = 0;
        if (x < 10) {
            category = 1;
        } else {
            if (x < 100) {
                category = 2;
            } else {
                category = 3;
            }
        }
        return category;
    }
}
"#;
    let r1 = compile_and_call(source, "classify", &[Value::I32(5)]);
    assert_eq!(as_u128(&r1), 1, "classify(5) = 1");
    let r2 = compile_and_call(source, "classify", &[Value::I32(50)]);
    assert_eq!(as_u128(&r2), 2, "classify(50) = 2");
    let r3 = compile_and_call(source, "classify", &[Value::I32(500)]);
    assert_eq!(as_u128(&r3), 3, "classify(500) = 3");
}

// ── Pattern 8: Variable used after loop (exit value) ──────────────────
#[test]
fn test_ssa_loop_exit_value() {
    let source = r#"
pragma synq ^0.9;
contract Test {
    state { initialised: bool; }
    @public
    function init() -> bool { initialised = true; return true; }
    @public
    function countIterations(n: u256) -> u256 {
        let i: u256 = 0;
        while (i < n) {
            i = i + 1;
        }
        return i;
    }
}
"#;
    let result = compile_and_call(source, "countIterations", &[Value::I32(7)]);
    assert_eq!(as_u128(&result), 7, "countIterations(7) = 7");
}

// ── Pattern 9: Loop with accumulation and condition ───────────────────
#[test]
fn test_ssa_accumulate_with_condition() {
    let source = r#"
pragma synq ^0.9;
contract Test {
    state { initialised: bool; }
    @public
    function init() -> bool { initialised = true; return true; }
    @public
    function conditionalSum(n: u256) -> u256 {
        let i: u256 = 0;
        let total: u256 = 0;
        while (i < n) {
            if (i % 3 == 0) {
                total = total + i;
            }
            i = i + 1;
        }
        return total;
    }
}
"#;
    let result = compile_and_call(source, "conditionalSum", &[Value::I32(10)]);
    // Multiples of 3 below 10: 0+3+6+9 = 18
    assert_eq!(as_u128(&result), 18, "conditionalSum(10) = 18");
}


// ── Pattern 10a: Simple inter-function call (no loop) ────────────────
#[test]
fn test_ssa_simple_call_no_loop() {
    let source = r#"
pragma synq ^0.9;
contract Test {
    state { initialised: bool; }
    @public
    function init() -> bool { initialised = true; return true; }
    @public
    function double(x: u256) -> u256 { return x * 2; }
    @public
    function run(x: u256) -> u256 {
        return double(x);
    }
}
"#;
    let result = compile_and_call(source, "run", &[Value::I32(5)]);
    assert_eq!(as_u128(&result), 10, "double(5) = 10");
}

// ── Pattern 10b: Call with accumulation (no loop) ────────────────────
#[test]
fn test_ssa_call_accumulate_no_loop() {
    let source = r#"
pragma synq ^0.9;
contract Test {
    state { initialised: bool; }
    @public
    function init() -> bool { initialised = true; return true; }
    @public
    function double(x: u256) -> u256 { return x * 2; }
    @public
    function run(x: u256) -> u256 {
        let a: u256 = double(x);
        let b: u256 = double(a);
        return a + b;
    }
}
"#;
    let result = compile_and_call(source, "run", &[Value::I32(5)]);
    // double(5)=10, double(10)=20, 10+20=30
    assert_eq!(as_u128(&result), 30, "double(5)+double(double(5)) = 30");
}

// ── Pattern 10: Inter-function call inside loop ────────────────────────
#[test]
fn test_ssa_call_inside_loop() {
    let source = r#"
pragma synq ^0.9;
contract Test {
    state { initialised: bool; }
    @public
    function init() -> bool { initialised = true; return true; }
    @public
    function double(x: u256) -> u256 { return x * 2; }
    @public
    function sumDoubles(n: u256) -> u256 {
        let i: u256 = 0;
        let total: u256 = 0;
        while (i < n) {
            total = total + double(i);
            i = i + 1;
        }
        return total;
    }
}
"#;
    let result = compile_and_call(source, "sumDoubles", &[Value::I32(5)]);
    // 2*0 + 2*1 + 2*2 + 2*3 + 2*4 = 0+2+4+6+8 = 20
    assert_eq!(as_u128(&result), 20, "sumDoubles(5) = 20");
}


// ── Pattern 10c: Multiply in loop (no Call) ──────────────────────────
#[test]
fn test_ssa_multiply_in_loop() {
    let source = r#"
pragma synq ^0.9;
contract Test {
    state { initialised: bool; }
    @public
    function init() -> bool { initialised = true; return true; }
    @public
    function sumDoubles(n: u256) -> u256 {
        let i: u256 = 0;
        let total: u256 = 0;
        while (i < n) {
            total = total + (i * 2);
            i = i + 1;
        }
        return total;
    }
}
"#;
    let result = compile_and_call(source, "sumDoubles", &[Value::I32(5)]);
    assert_eq!(as_u128(&result), 20, "sumDoubles(5) without call = 20");
}

// ── Pattern 10d: Call inside loop without SSA (single-block locals) ──
#[test]
fn test_ssa_call_no_phi() {
    let source = r#"
pragma synq ^0.9;
contract Test {
    state { counter: u256; initialised: bool; }
    @public
    function init() -> bool { counter = 0; initialised = true; return true; }
    @public
    function double(x: u256) -> u256 { return x * 2; }
    @public
    function run(n: u256) -> u256 {
        counter = double(n);
        return counter;
    }
}
"#;
    let result = compile_and_call(source, "run", &[Value::I32(5)]);
    assert_eq!(as_u128(&result), 10, "double(5) via state = 10");
}

// ── Pattern 11: State variable modified in loop ───────────────────────
#[test]
fn test_ssa_state_var_in_loop() {
    let source = r#"
pragma synq ^0.9;
contract Test {
    state { counter: u256; initialised: bool; }
    @public
    function init() -> bool { counter = 0; initialised = true; return true; }
    @public
    function increment(times: u256) -> u256 {
        let i: u256 = 0;
        while (i < times) {
            counter = counter + 1;
            i = i + 1;
        }
        return counter;
    }
}
"#;
    let result = compile_and_call(source, "increment", &[Value::I32(5)]);
    assert_eq!(as_u128(&result), 5, "increment(5) = 5");
}
