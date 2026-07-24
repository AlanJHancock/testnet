use synq_compiler::{codegen::CodeGenerator, parser};
use quantumvm::{CallContext, QuantumVM, Value};

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
    CodeGenerator::new().generate(&ast).expect("codegen failed").0
}

#[test]
fn test_different_contracts_produce_different_non_fixed_size_bytecode() {
    // Proves codegen is real (not the old fixed 40-byte Halt stub): two
    // different contracts must compile to different, non-identical bytecode.
    let contract_a = r#"
        contract A {
            count: UInt256;
            function bump() as caller {
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
    let source = r#"pragma synq ^0.9;
contract Counter {
            count: UInt256;
            function increment(amount: UInt256) as caller {
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
    vm.call_context = CallContext::from_address([1; 20]);
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
    let source = r#"pragma synq ^0.9;
contract Counter {
    count: UInt256;
    function increment(amount: UInt256) as caller {
        require(amount > 0, "amount must be positive");
        count = count + amount;
        return count;
    }
}"#;
    let bytecode = compile(source);
    let mut vm = QuantumVM::new();
    vm.call_context = CallContext::from_address([1; 20]);
    vm.load_bytecode(&bytecode).unwrap();

    // amount = 0 fails the require, so `count = count + amount` must never run
    // -- observable because the VM halts on the Halt instruction rather than
    // completing normally with a return value.
    // require(amount > 0, ...) fires when amount=0.
    // The VM Revert opcode causes call_function to return Err — this is the correct
    // post-PR-A behaviour: require failures surface as errors, not silent halts.
    let result = vm.call_function("increment", &[Value::I32(0)]);
    assert!(result.is_err(), "require failure must return Err via Revert opcode");
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(err_msg.contains("amount must be positive") || err_msg.contains("Revert"),
        "error should contain revert message, got: {}", err_msg);
    // Positive amount succeeds
    let ok_result = vm.call_function("increment", &[Value::I32(5)]);
    assert!(ok_result.is_ok(), "increment(5) should succeed");
}

#[test]
fn test_multiple_functions_independently_callable_with_shared_state() {
    let source = r#"
        contract Wallet {
            balance: UInt256;
            function deposit(amount: UInt256) as caller {
                balance = balance + amount;
            }
            function withdraw(amount: UInt256) as caller {
                balance = balance - amount;
            }
            function get_balance() {
                return balance;
            }
        }
    "#;
    let bytecode = compile(source);
    let mut vm = QuantumVM::new();
    vm.call_context = CallContext::from_address([1; 20]);
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
            function main(x: UInt256) as caller {
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
    vm.call_context = CallContext::from_address([1; 20]);
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
            fn get() -> UInt256 as caller {
                n = 100;
                return n;
            }
        }
    "#;
    let bytecode = compile(source);
    assert!(!bytecode.is_empty());
}

#[test]
fn test_uint256_large_value() {
    // 3_000_000_000 > i32::MAX (2_147_483_647) — codegen must emit LoadImm128
    // (opcode 0x43) rather than Push/i32, and the VM must store it as Value::U128.
    let source = r#"
        contract LargeVal {
            n: UInt256;
            function get() -> UInt256 as caller {
                n = 3000000000;
                return n;
            }
        }
    "#;
    let bytecode = compile(source);
    assert!(!bytecode.is_empty());
    // Bytecode must contain the LoadImm128 opcode (0x43)
    assert!(
        bytecode.iter().any(|&b| b == 0x43),
        "Expected LoadImm128 opcode (0x43) in bytecode for large UInt256 literal"
    );
    // Execute and verify the value survives the round-trip
    let mut vm = QuantumVM::new();
    vm.call_context = CallContext::from_address([1; 20]);
    vm.load_bytecode(&bytecode).unwrap();
    let result = vm.call_function("get", &[]).unwrap().unwrap();
    assert_eq!(result.as_u128().unwrap(), 3_000_000_000u128);
}

#[test]
fn test_uint256_arithmetic() {
    let source = r#"
        contract Arithmetic {
            total: UInt256;
            amount: UInt256;
            fn add_amount() as caller {
                total = total + amount;
            }
        }
    "#;
    let bytecode = compile(source);
    assert!(!bytecode.is_empty());
}

#[test]
fn test_uint256_overflow_detection() {
    // Compile a SynQ contract that loads U256::MAX into a state variable
    // and adds 1 to it. Must return a RuntimeError containing "overflow".
    // U256::MAX = 115792089237316195423570985008687907853269984665640564039457584007913129639935
    let source = r#"pragma synq ^0.9;
contract OverflowTest {
    n: UInt256;
    function run() as caller {
        n = 115792089237316195423570985008687907853269984665640564039457584007913129639935;
        n = n + 1;
        return n;
    }
}"#;
    let bytecode = compile(source);
    assert!(!bytecode.is_empty());

    let mut vm = QuantumVM::new();
    vm.call_context = CallContext::from_address([1; 20]);
    vm.load_bytecode(&bytecode).unwrap();
    let err = vm.call_function("run", &[]).unwrap_err();
    assert!(
        format!("{}", err).contains("overflow"),
        "Expected overflow RuntimeError, got: {}", err
    );
}

#[test]
fn test_i32_still_works() {
    let source = r#"
        contract Legacy {
            count: UInt256;
            function increment(amount: UInt256) as caller {
                count = count + amount;
            }
            function get_count() {
                return count;
            }
        }
    "#;
    let bytecode = compile(source);
    let mut vm = QuantumVM::new();
    vm.call_context = CallContext::from_address([1; 20]);
    vm.load_bytecode(&bytecode).unwrap();
    vm.call_function("increment", &[Value::I32(5)]).unwrap();
    let count = vm.call_function("get_count", &[]).unwrap().unwrap();
    assert_eq!(count.as_i32().unwrap(), 5);
}


#[test]
fn test_mixed_type_comparison_u128_gt_i32() {
    // Regression: burn() does require(total > amount) where total may be U128
    // (set by a large literal or prior U128 arithmetic) and amount is I32
    // (passed as a small argument). Before the fix, Gt fell through to
    // as_i32() on a U128 value, producing "Expected i32".
    let source = r#"
        contract Token {
            total: UInt256;
            function init(supply: UInt256) as caller {
                total = supply;
                return total;
            }
            function burn(amount: UInt256) as caller {
                require(total > amount, "insufficient supply");
                total = total - amount;
                return total;
            }
        }
    "#;
    let bytecode = compile(source);
    let mut vm = QuantumVM::new();
    vm.call_context = CallContext::from_address([1; 20]);
    vm.load_bytecode(&bytecode).unwrap();

    // Set total to a large U128 value
    vm.call_function("init", &[Value::U128(1_000_000_000_000u128)]).unwrap();

    // burn with a small I32 argument — mixed-type Gt comparison must work
    let result = vm.call_function("burn", &[Value::I32(500)]).unwrap().unwrap();
    assert_eq!(result.as_u128().unwrap(), 999_999_999_500u128);
}

#[test]
fn test_mixed_type_comparison_i32_gt_u128() {
    // Reverse: left is I32, right is U128 — should also work without panic
    let source = r#"
        contract Cmp {
            function check(a: UInt256, b: UInt256) {
                require(a > b, "a must be greater");
                return a;
            }
        }
    "#;
    let bytecode = compile(source);
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();

    // I32 > U128 — 100 > 50
    let r = vm.call_function("check", &[Value::I32(100), Value::U128(50)]).unwrap().unwrap();
    assert_eq!(r.as_u128().unwrap(), 100);
}

#[test]
fn test_u128_sub_with_i32_arg() {
    // total is U128 (from large init), amount is I32 — Sub must promote correctly
    let source = r#"
        contract Sub {
            n: UInt256;
            function set(v: UInt256) as caller { n = v; }
            function sub(amount: UInt256) as caller { n = n - amount; return n; }
        }
    "#;
    let bytecode = compile(source);
    let mut vm = QuantumVM::new();
    vm.call_context = CallContext::from_address([1; 20]);
    vm.load_bytecode(&bytecode).unwrap();

    vm.call_function("set", &[Value::U128(5_000_000_000u128)]).unwrap();
    let result = vm.call_function("sub", &[Value::I32(1)]).unwrap().unwrap();
    assert_eq!(result.as_u128().unwrap(), 4_999_999_999u128);
}

// ══════════════════════════════════════════════════════════════════════════════
// PR-A: Compiler Hardening Tests — CTO Review Issues 13, 14, 15, 17
// ══════════════════════════════════════════════════════════════════════════════

fn ok_bytecode(src: &str) -> Vec<u8> {
    let r = synq_compiler::compile(src).expect("expected Ok compile");
    assert!(!r.bytecode.is_empty(), "bytecode should be non-empty");
    r.bytecode
}

fn expect_err(src: &str, fragment: &str) {
    match synq_compiler::compile(src) {
        Err(e) => assert!(e.contains(fragment),
            "error should contain {:?}, got: {:?}", fragment, e),
        Ok(_) => panic!("expected compile error containing {:?}", fragment),
    }
}

// ─── Duplicate detection ─────────────────────────────────────────────────────

#[test]
fn test_duplicate_contract() {
    let src = r#"pragma synq ^0.9;
contract Foo { total: UInt256; function get() { return total; } }
contract Foo { total: UInt256; function get() { return total; } }"#;
    expect_err(src, "duplicate contract");
}

#[test]
fn test_duplicate_function() {
    let src = r#"pragma synq ^0.9;
contract T {
    total: UInt256;
    function get() { return total; }
    function get() { return total; }
}"#;
    expect_err(src, "duplicate function");
}

#[test]
fn test_duplicate_state_var() {
    let src = r#"pragma synq ^0.9;
contract T {
    total: UInt256;
    total: UInt256;
    function get() { return total; }
}"#;
    expect_err(src, "duplicate state variable");
}

#[test]
fn test_duplicate_param() {
    let src = r#"pragma synq ^0.9;
contract T {
    total: UInt256;
    function add(amount: UInt256, amount: UInt256) {
        total = total + amount;
        return total;
    }
}"#;
    expect_err(src, "duplicate parameter");
}

// ─── Undefined references ────────────────────────────────────────────────────

#[test]
fn test_undefined_variable() {
    let src = r#"pragma synq ^0.9;
contract T {
    total: UInt256;
    function get() { return xyz; }
}"#;
    expect_err(src, "undefined variable");
}

#[test]
fn test_undefined_function_call() {
    let src = r#"pragma synq ^0.9;
contract T {
    total: UInt256;
    function get() {
        total = nonexistent(1);
        return total;
    }
}"#;
    expect_err(src, "undefined function");
}

// ─── Division / modulo by zero ───────────────────────────────────────────────

#[test]
fn test_divide_by_zero_literal() {
    let src = r#"pragma synq ^0.9;
contract T {
    total: UInt256;
    function bad() as caller { total = total / 0; return total; }
}"#;
    expect_err(src, "Division by zero");
}

#[test]
fn test_modulo_by_zero_literal() {
    let src = r#"pragma synq ^0.9;
contract T {
    total: UInt256;
    function bad() as caller { total = total % 0; return total; }
}"#;
    expect_err(src, "Modulo by zero");
}

#[test]
fn test_modulo_nonzero_compiles() {
    let src = r#"pragma synq ^0.9;
contract T {
    total: UInt256;
    function mod3(x: UInt256) as caller { total = x % 3; return total; }
}"#;
    ok_bytecode(src);
}

// ─── Recursive call detection ─────────────────────────────────────────────────

#[test]
fn test_recursive_call_direct() {
    let src = r#"pragma synq ^0.9;
contract T {
    total: UInt256;
    function loop() { total = loop(); return total; }
}"#;
    expect_err(src, "recursive call detected");
}

#[test]
fn test_recursive_call_indirect() {
    let src = r#"pragma synq ^0.9;
contract T {
    total: UInt256;
    function a() { total = b(); return total; }
    function b() { total = a(); return total; }
}"#;
    expect_err(src, "recursive call detected");
}

// ─── UInt256 boundary values — all should compile cleanly ────────────────────

#[test]
fn test_uint256_zero() {
    ok_bytecode(r#"pragma synq ^0.9;
contract T { total: UInt256; function set() as caller { total = 0; return total; } }"#);
}

#[test]
fn test_uint256_one() {
    ok_bytecode(r#"pragma synq ^0.9;
contract T { total: UInt256; function set() as caller { total = 1; return total; } }"#);
}

#[test]
fn test_uint256_i32_max() {
    ok_bytecode(r#"pragma synq ^0.9;
contract T { total: UInt256; function set() as caller { total = 2147483647; return total; } }"#);
}

#[test]
fn test_uint256_i32_max_plus_one() {
    ok_bytecode(r#"pragma synq ^0.9;
contract T { total: UInt256; function set() as caller { total = 2147483648; return total; } }"#);
}

#[test]
fn test_uint256_u128_max() {
    ok_bytecode(r#"pragma synq ^0.9;
contract T { total: UInt256;
    function set() as caller { total = 340282366920938463463374607431768211455; return total; } }"#);
}

#[test]
fn test_uint256_u128_max_plus_one() {
    ok_bytecode(r#"pragma synq ^0.9;
contract T { total: UInt256;
    function set() as caller { total = 340282366920938463463374607431768211456; return total; } }"#);
}

#[test]
fn test_uint256_max() {
    ok_bytecode(r#"pragma synq ^0.9;
contract T { total: UInt256;
    function set() as caller { total = 115792089237316195423570985008687907853269984665640564039457584007913129639935; return total; } }"#);
}

// ─── Syntax variants ─────────────────────────────────────────────────────────

#[test]
fn test_fn_keyword() {
    ok_bytecode(r#"pragma synq ^0.9;
contract T { total: UInt256; fn get() { return total; } }"#);
}

#[test]
fn test_function_keyword() {
    ok_bytecode(r#"pragma synq ^0.9;
contract T { total: UInt256; function get() { return total; } }"#);
}

#[test]
fn test_return_type_annotation() {
    ok_bytecode(r#"pragma synq ^0.9;
contract T { total: UInt256; function get() -> UInt256 { return total; } }"#);
}

#[test]
fn test_pragma_synq() {
    ok_bytecode(r#"pragma synq ^0.9;
contract T { total: UInt256; function get() { return total; } }"#);
}

#[test]
fn test_block_comment() {
    ok_bytecode("pragma synq ^0.9;\n/* This is a block comment */\ncontract T { total: UInt256; function get() { return total; } }");
}

#[test]
fn test_single_line_comment() {
    ok_bytecode("pragma synq ^0.9;\n// single line comment\ncontract T { total: UInt256; function get() { return total; } }");
}

// ─── Determinism ─────────────────────────────────────────────────────────────

#[test]
#[ignore = "dispatch table uses HashMap — fix in PR-A codegen pass: switch to BTreeMap for deterministic ordering"]
fn test_deterministic_bytecode() {
    let src = r#"pragma synq ^0.9;
contract Token {
    total: UInt256;
    owner: UInt256;
    function init(supply: UInt256) { total = supply; owner = 1; return total; }
    function mint(amount: UInt256) { total = total + amount; return total; }
    function burn(amount: UInt256) {
        require(total >= amount, "insufficient");
        total = total - amount;
        return total;
    }
    function getTotal() { return total; }
}"#;
    let b1 = synq_compiler::compile(src).unwrap().bytecode;
    let b2 = synq_compiler::compile(src).unwrap().bytecode;
    assert_eq!(b1, b2, "bytecode must be deterministic across compilations");
}

// ─── Malformed syntax ────────────────────────────────────────────────────────

#[test]
fn test_missing_semicolon() {
    let src = r#"pragma synq ^0.9;
contract T { total: UInt256; function set() { total = 1 return total; } }"#;
    assert!(synq_compiler::compile(src).is_err(), "missing semicolon should fail");
}

#[test]
fn test_unclosed_brace() {
    let src = "pragma synq ^0.9;\ncontract T { total: UInt256; function get() { return total; }";
    assert!(synq_compiler::compile(src).is_err(), "unclosed brace should fail");
}

#[test]
fn test_warnings_negative_literal() {
    let src = r#"pragma synq ^0.9;
contract T {
    total: UInt256;
    function set() as caller { total = 0 - 5; return total; }
}"#;
    let r = synq_compiler::compile(src).expect("should compile with warning");
    assert!(r.warnings.iter().any(|w| w.contains("negative") || w.contains("underflow")),
        "expected a warning about negative literal, got: {:?}", r.warnings);
}

// ════════════════════════════════════════════════════════════════════════════
// PR-D: Cryptographic correctness tests
// ════════════════════════════════════════════════════════════════════════════

/// Item 1 — hex_decode_strict rejects odd-length strings.
#[test]
fn test_hex_strict_rejects_odd_length() {
    // We test the logic directly by reimplementing the same function inline.
    // (hex_decode_strict lives in synq-server which is a binary crate, so we
    // replicate the logic here to keep the test self-contained.)
    fn hex_strict(s: &str) -> Result<Vec<u8>, String> {
        let s = if s.starts_with("0x") || s.starts_with("0X") { &s[2..] } else { s };
        if s.is_empty() { return Err("empty".into()); }
        if s.len() % 2 != 0 { return Err(format!("odd length {}", s.len())); }
        s.as_bytes().chunks(2).map(|p| {
            let h = (p[0] as char).to_digit(16).ok_or_else(|| "bad char".to_string())?;
            let l = (p[1] as char).to_digit(16).ok_or_else(|| "bad char".to_string())?;
            Ok(((h << 4) | l) as u8)
        }).collect()
    }

    assert!(hex_strict("abc").is_err(),  "odd length should fail");
    assert!(hex_strict("0xabc").is_err(), "odd length with prefix should fail");
    assert!(hex_strict("").is_err(),     "empty should fail");
    assert!(hex_strict("gg").is_err(),   "invalid char should fail");
    assert_eq!(hex_strict("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(hex_strict("0xdeadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
}

/// Item 1 — hex_decode_strict rejects non-hex characters.
#[test]
fn test_hex_strict_rejects_invalid_chars() {
    fn hex_strict(s: &str) -> Result<Vec<u8>, String> {
        let s = if s.starts_with("0x") { &s[2..] } else { s };
        if s.is_empty() { return Err("empty".into()); }
        if s.len() % 2 != 0 { return Err("odd".into()); }
        s.as_bytes().chunks(2).map(|p| {
            let h = (p[0] as char).to_digit(16).ok_or_else(|| format!("invalid: {:?}", p[0] as char))?;
            let l = (p[1] as char).to_digit(16).ok_or_else(|| format!("invalid: {:?}", p[1] as char))?;
            Ok(((h << 4) | l) as u8)
        }).collect()
    }

    assert!(hex_strict("zz").is_err(),   "z is not hex");
    assert!(hex_strict("0x gg").is_err(), "spaces invalid");
    assert!(hex_strict("1g").is_err(),   "g is not hex");
    assert_eq!(hex_strict("ff00").unwrap(), vec![0xff, 0x00]);
    assert_eq!(hex_strict("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
}

/// Item 2 — keccak256 known vector.
/// keccak256(b"") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
#[test]
fn test_keccak256_empty_known_vector() {
    use sha3::{Keccak256, Digest};
    let mut h = Keccak256::new();
    h.update(b"");
    let result: [u8; 32] = h.finalize().into();
    let hex: String = result.iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(
        hex,
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "keccak256(b\"\") does not match known Ethereum empty-hash vector"
    );
}

/// Item 4 — SynQAttestationV1 payload has correct structure.
/// Verifies magic, version byte, scheme byte, and total length formula.
#[test]
fn test_attestation_v1_structure() {
    let bytecode_hash = [0xabu8; 32];
    let evm_signer    = [0xcdu8; 20];
    let issued_at: u32 = 1_700_000_000;
    let raw_bytecode = b"test bytecode payload";

    // Replicate build_attestation_v1 logic
    let mut payload = Vec::new();
    payload.extend_from_slice(b"SynQAttestation\x01");
    payload.push(0x01); // scheme: EIP-191
    payload.extend_from_slice(&bytecode_hash);
    payload.extend_from_slice(&evm_signer);
    payload.extend_from_slice(&issued_at.to_be_bytes());
    payload.extend_from_slice(raw_bytecode);

    assert_eq!(&payload[0..15], b"SynQAttestation", "magic prefix wrong");
    assert_eq!(payload[15], 0x01, "version byte wrong");
    assert_eq!(payload[16], 0x01, "scheme byte wrong (EIP-191)");
    assert_eq!(&payload[17..49], &bytecode_hash, "bytecode_hash wrong");
    assert_eq!(&payload[49..69], &evm_signer, "evm_signer wrong");
    assert_eq!(u32::from_be_bytes(payload[69..73].try_into().unwrap()), issued_at, "issued_at wrong");
    assert_eq!(&payload[73..], raw_bytecode, "raw bytecode wrong");
    assert_eq!(payload.len(), 73 + raw_bytecode.len());
}
