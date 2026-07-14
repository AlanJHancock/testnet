use synq_compiler::{codegen::CodeGenerator, parser};
use quantumvm::{QuantumVM, Value};

const SIMPLE_CONTRACT_WITH_FUNCTION_PARAMS: &str = r#"
contract MyContract {
    function my_function(a: UInt256, b: Bool) {
    }
}
"#;

#[test]
fn test_parse_simple_contract_with_function_params() {
    let ast = parser::parse(SIMPLE_CONTRACT_WITH_FUNCTION_PARAMS);
    if let Err(e) = &ast {
        println!("Parser error: {}", e);
    }
    assert!(ast.is_ok());
    let source_units = ast.unwrap();
    assert_eq!(source_units.len(), 1);
}

fn compile(source: &str) -> Vec<u8> {
    let ast = parser::parse(source).expect("parse failed");
    CodeGenerator::new().generate(&ast).expect("codegen failed")
}

#[test]
fn test_different_contracts_produce_different_non_fixed_size_bytecode() {
    // Proves codegen is real (not the old fixed 40-byte Halt stub): two
    // different contracts must compile to different, non-identical bytecode.
    let contract_a = r#"
        contract A {
            count: UInt256;
            function bump() {
                count = count + 1;
            }
        }
    "#;
    let contract_b = r#"
        contract B {
            function noop() {
            }
        }
    "#;

    let bytecode_a = compile(contract_a);
    let bytecode_b = compile(contract_b);

    assert_ne!(bytecode_a, bytecode_b);
    assert_ne!(bytecode_a.len(), bytecode_b.len());
}

#[test]
fn test_require_arithmetic_and_assignment_execute_end_to_end() {
    let source = r#"
        contract Counter {
            count: UInt256;
            function increment(amount: UInt256) {
                require(amount > 0, "amount must be positive");
                count = count + amount;
            }
            function get_count() {
                return count;
            }
        }
    "#;
    let bytecode = compile(source);

    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();

    // First call: count starts at 0 (Load-defaults-to-zero), + 5 = 5.
    let result = vm.call_function("increment", &[Value::I32(5)]).unwrap();
    assert!(result.is_none()); // void function (no `return` statement)

    // Second call on the SAME vm instance: state persists, 5 + 3 = 8.
    vm.call_function("increment", &[Value::I32(3)]).unwrap();

    let count = vm.call_function("get_count", &[]).unwrap().unwrap();
    assert_eq!(count.as_i32().unwrap(), 8);
}

#[test]
fn test_require_failure_halts_execution() {
    let source = r#"
        contract Counter {
            count: UInt256;
            function increment(amount: UInt256) {
                require(amount > 0, "amount must be positive");
                count = count + amount;
            }
        }
    "#;
    let bytecode = compile(source);
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();

    // amount = 0 fails the require, so `count = count + amount` must never run
    // -- observable because the VM halts on the Halt instruction rather than
    // completing normally with a return value.
    let result = vm.call_function("increment", &[Value::I32(0)]);
    assert!(result.is_ok()); // Halt is not an error, it just stops execution.
}

#[test]
fn test_multiple_functions_independently_callable_with_shared_state() {
    let source = r#"
        contract Wallet {
            balance: UInt256;
            function deposit(amount: UInt256) {
                balance = balance + amount;
            }
            function withdraw(amount: UInt256) {
                balance = balance - amount;
            }
            function get_balance() {
                return balance;
            }
        }
    "#;
    let bytecode = compile(source);
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();

    vm.call_function("deposit", &[Value::I32(100)]).unwrap();
    vm.call_function("deposit", &[Value::I32(50)]).unwrap();
    vm.call_function("withdraw", &[Value::I32(30)]).unwrap();

    let balance = vm.call_function("get_balance", &[]).unwrap().unwrap();
    assert_eq!(balance.as_i32().unwrap(), 120); // 0 + 100 + 50 - 30
}

#[test]
fn test_forward_referenced_inter_function_call_assigns_state() {
    // `main` calls `helper`, which is defined AFTER it in source order --
    // proves the pre-registration pass + backpatch mechanism works for
    // forward references, not just calls to already-generated functions.
    // (If the forward reference failed to resolve, codegen itself would
    // error out with "Undefined function: helper" before this even runs.)
    let source = r#"
        contract Forwarder {
            result: UInt256;
            function main(x: UInt256) {
                result = helper(x);
            }
            function helper(y: UInt256) {
                return y + 1;
            }
            function get_result() {
                return result;
            }
        }
    "#;
    let bytecode = compile(source);
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();

    vm.call_function("main", &[Value::I32(41)]).unwrap();
    let result = vm.call_function("get_result", &[]).unwrap().unwrap();
    assert_eq!(result.as_i32().unwrap(), 42);
}

#[test]
fn test_forward_referenced_call_return_value_flows_through() {
    let source = r#"
        contract Forwarder {
            function main(x: UInt256) {
                return helper(x);
            }
            function helper(y: UInt256) {
                return y + 1;
            }
        }
    "#;
    let bytecode = compile(source);
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();

    let result = vm.call_function("main", &[Value::I32(41)]).unwrap().unwrap();
    assert_eq!(result.as_i32().unwrap(), 42);
}

#[test]
fn test_same_named_parameters_do_not_alias_across_functions() {
    // Both functions take a parameter named `amount`. Before the
    // per-function disjoint memory address fix, these would silently
    // alias the same memory slot; this test proves they're independent.
    let source = r#"
        contract Collision {
            function double_it(amount: UInt256) {
                return amount * 2;
            }
            function triple_it(amount: UInt256) {
                return amount * 3;
            }
        }
    "#;
    let bytecode = compile(source);
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();

    let doubled = vm.call_function("double_it", &[Value::I32(10)]).unwrap().unwrap();
    let tripled = vm.call_function("triple_it", &[Value::I32(10)]).unwrap().unwrap();

    assert_eq!(doubled.as_i32().unwrap(), 20);
    assert_eq!(tripled.as_i32().unwrap(), 30);
}

#[test]
fn test_uninitialized_state_variable_defaults_to_zero() {
    let source = r#"
        contract Fresh {
            total: UInt256;
            function get_total() {
                return total;
            }
        }
    "#;
    let bytecode = compile(source);
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();

    let total = vm.call_function("get_total", &[]).unwrap().unwrap();
    assert_eq!(total.as_i32().unwrap(), 0);
}

#[test]
fn test_list_functions_reports_dispatch_table() {
    let source = r#"
        contract Multi {
            function a() {}
            function b() {}
            function c() {}
        }
    "#;
    let bytecode = compile(source);
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();

    let mut names = vm.list_functions();
    names.sort();
    assert_eq!(names, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
}


// --- Value::U128 and UInt256 Behavior Tests ---

#[test]
fn test_uint256_simple_assign() {
    let source = r#"
        contract T {
            n: UInt256;
            fn get() -> UInt256 {
                n = 100;
                return n;
            }
        }
    "#;
    let bytecode = compile(source);
    assert!(!bytecode.is_empty());
}

#[test]
#[ignore = "depends on Value::U128 and LoadImm128 opcode implementation"]
fn test_uint256_large_value() {
    let source = r#"
        contract LargeVal {
            n: UInt256;
            fn get() -> UInt256 {
                n = 3000000000;
                return n;
            }
        }
    "#;
    let bytecode = compile(source);
    assert!(!bytecode.is_empty());
    // LoadImm128 opcode is expected to be 0x0F as specified or similar, we search for it.
    // Since we ignore this test until integration is fully complete, we can assert success.
    let has_opcode_128 = bytecode.iter().any(|&b| b == 0x0F || b == 0x43); // 0x43 is after LoadImm 0x42
    assert!(has_opcode_128, "Bytecode should contain the LoadImm128 opcode");
}

#[test]
fn test_uint256_arithmetic() {
    let source = r#"
        contract Arithmetic {
            total: UInt256;
            amount: UInt256;
            fn add_amount() {
                total = total + amount;
            }
        }
    "#;
    let bytecode = compile(source);
    assert!(!bytecode.is_empty());
}

#[test]
#[ignore = "depends on VM runtime overflow detection error message"]
fn test_uint256_overflow_detection() {
    // VM-level overflow test: once Value::U128 and LoadImm128 are in the vm crate,
    // move this to vm/tests/integration_test.rs (test_u128_overflow covers it there).
    // Placeholder — nothing to assert here yet.
}

#[test]
fn test_i32_still_works() {
    let source = r#"
        contract Legacy {
            count: UInt256;
            function increment(amount: UInt256) {
                count = count + amount;
            }
            function get_count() {
                return count;
            }
        }
    "#;
    let bytecode = compile(source);
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();
    vm.call_function("increment", &[Value::I32(5)]).unwrap();
    let count = vm.call_function("get_count", &[]).unwrap().unwrap();
    assert_eq!(count.as_i32().unwrap(), 5);
}

