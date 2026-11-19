//! Signed function parameters through the REAL compile_ir() -> QuantumVM path.
//!
//! The IR backend used to write `false` (unsigned) into the function table for
//! EVERY parameter. The VM coerces arguments to the declared signedness when a
//! function is called, so a non-negative i32 argument was turned into an
//! unsigned value and any arithmetic that mixed it with a negative number, or
//! went below zero, reverted (addI(-5, 2), subI(3, 9), x - 7 with x = 6).
//!
//! IrType collapses u8/u16/u32 and i8/i16/i32 into the same I32 (and u64/i64/
//! i128 into I64), so the signedness has to be carried from the AST. These
//! tests pin both directions: signed params are signed, unsigned params are not.

use synq_compiler::compile_ir;
use quantumvm::{QuantumVM, Value};

fn call(source: &str, func: &str, args: Vec<Value>) -> Result<Option<Value>, String> {
    let result = compile_ir(source).expect("compile failed");
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&result.bytecode).expect("load failed");
    vm.call_function(func, &args).map_err(|e| format!("{:?}", e))
}

fn as_i64(v: Option<Value>) -> i64 {
    match v.expect("no return value") {
        Value::I32(n) => n as i64,
        Value::I64(n) => n,
        Value::U128(n) => n as i64,
        other => panic!("expected an integer, got {:?}", other),
    }
}

const SIGNED_SRC: &str = r#"
contract SignedProbe {
  state { r: i32; }
  function addI(x: i32, y: i32) -> i32 { r = x + y; return r; }
  function subI(x: i32, y: i32) -> i32 { r = x - y; return r; }
  function mulI(x: i32, y: i32) -> i32 { r = x * y; return r; }
  function subLit(x: i32) -> i32 { r = x - 7; return r; }
}
"#;

#[test]
fn signed_param_add_with_negative_operand() {
    // The VM receives the non-negative 2 as an unsigned value unless the
    // function table marks the parameter signed.
    let got = call(SIGNED_SRC, "addI", vec![Value::I32(-5), Value::I32(2)]).expect("addI(-5, 2) must not revert");
    assert_eq!(as_i64(got), -3);
}

#[test]
fn signed_param_subtract_below_zero() {
    let got = call(SIGNED_SRC, "subI", vec![Value::I32(3), Value::I32(9)]).expect("subI(3, 9) must not revert");
    assert_eq!(as_i64(got), -6);
}

#[test]
fn signed_param_subtract_literal_below_zero() {
    let got = call(SIGNED_SRC, "subLit", vec![Value::I32(6)]).expect("subLit(6) must not revert");
    assert_eq!(as_i64(got), -1);
}

#[test]
fn signed_param_multiply_mixed_signs() {
    let got = call(SIGNED_SRC, "mulI", vec![Value::I32(-4), Value::I32(3)]).expect("mulI(-4, 3) must not revert");
    assert_eq!(as_i64(got), -12);
}

#[test]
fn signed_params_that_already_worked_still_work() {
    assert_eq!(as_i64(call(SIGNED_SRC, "addI", vec![Value::I32(7), Value::I32(3)]).unwrap()), 10);
    assert_eq!(as_i64(call(SIGNED_SRC, "addI", vec![Value::I32(-7), Value::I32(-3)]).unwrap()), -10);
    assert_eq!(as_i64(call(SIGNED_SRC, "subI", vec![Value::I32(100), Value::I32(10)]).unwrap()), 90);
}

// A u32 parameter shares IrType::I32 with i32, so it must stay UNSIGNED.
// 3 - 9 on unsigned values must still revert (underflow), exactly as before.
const UNSIGNED_SRC: &str = r#"
contract UnsignedProbe {
  state { r: u32; }
  function subU(x: u32, y: u32) -> u32 { r = x - y; return r; }
  function addU(x: u32, y: u32) -> u32 { r = x + y; return r; }
}
"#;

#[test]
fn unsigned_u32_param_stays_unsigned_and_still_underflows() {
    assert!(call(UNSIGNED_SRC, "subU", vec![Value::U128(3), Value::U128(9)]).is_err(),
        "u32 3 - 9 must still revert; a u32 parameter must not be treated as signed");
}

#[test]
fn unsigned_u32_param_still_adds() {
    assert_eq!(as_i64(call(UNSIGNED_SRC, "addU", vec![Value::U128(7), Value::U128(3)]).unwrap()), 10);
}

// Mixed signature: only the signed parameter is marked signed.
const MIXED_SRC: &str = r#"
contract MixedProbe {
  state { r: i32; }
  function f(a: i32, b: u32) -> i32 { r = a - 7; return r; }
}
"#;

#[test]
fn mixed_signature_marks_each_parameter_by_its_own_type() {
    let got = call(MIXED_SRC, "f", vec![Value::I32(6), Value::U128(1)]).expect("f(6, 1) must not revert");
    assert_eq!(as_i64(got), -1);
}
