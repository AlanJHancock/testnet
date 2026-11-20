//! Signed (i8..i64) arithmetic and comparison on the AIVM (2026-11-20).
//!
//! The AIVM used to have only unsigned arithmetic, so any negative i32 result
//! (for example `i_val = -42`) raised ArithmeticUnderflow on Dry Run. The
//! compiler now emits AddI/SubI/MulI/DivI/ModI/LtI/GtI/LeI/GeI when an operand
//! is provably a signed int. These tests pin: signed results are right,
//! unsigned (u256) arithmetic still reverts on underflow, and a contract
//! with no signed values compiles to exactly the same instructions as before.

use synq_compiler::parser::parse;
use synq_compiler::aivm_codegen::compile_to_aivm;
use synq_compiler::ast::SourceUnit;
use aivm::vm::{Avm, StateOverlay};
use aivm::host::{HostFunctions, Value};
use aivm::context::ExecutionContext;
use aivm::receipt::ReceiptStatus;
use aivm::instructions::Instruction;

const SRC: &str = r#"
contract S {
  state {
    i: i32;
    u: u256;
  }
  impl {
    @public
    function setNeg() -> bool { i = -42; return true; }
    @public
    function getI() -> i32 { return i; }
    @public
    function neq(a: i32, b: i32) -> bool { return a != b; }
    @public
    function eq(a: i32, b: i32) -> bool { return a == b; }
    @public
    function roundTrip(x: i32, y: i32) -> i32 {
      let s = x + y;
      let d = x - y;
      let p = x * y;
      if (s - y != x) { return 1; }
      if (d + y != x) { return 2; }
      if (x != 0) { if (p / x != y) { return 3; } }
      return 0;
    }
    @public
    function sub(a: i32, b: i32) -> i32 { return a - b; }
    @public
    function add(a: i32, b: i32) -> i32 { return a + b; }
    @public
    function mul(a: i32, b: i32) -> i32 { return a * b; }
    @public
    function div(a: i32, b: i32) -> i32 { return a / b; }
    @public
    function modu(a: i32, b: i32) -> i32 { return a % b; }
    @public
    function neg(a: i32) -> i32 { return 0 - a; }
    @public
    function lt(a: i32, b: i32) -> bool { return a < b; }
    @public
    function ge(a: i32, b: i32) -> bool { return a >= b; }
    @public
    function usub(a: u256, b: u256) -> u256 { return a - b; }
    @public
    function uneg(a: u256) -> u256 { return 0 - a; }
    @public
    function setUNegLit() -> bool { u = 0 - 5; return true; }
    @public
    function retNegLit() -> i32 { return 0 - 7; }
    @public
    function retUNegLit() -> u256 { return 0 - 7; }
  }
}
"#;

fn build() -> (aivm::vm::Avm, StateOverlay, ExecutionContext) {
    let ast = parse(SRC).expect("parse");
    let c = ast.iter().find_map(|u| if let SourceUnit::Contract(c) = u { Some(c) } else { None }).unwrap();
    let r = compile_to_aivm(c, &[]).expect("compile");
    let avm = Avm::new(r.instructions, r.functions, HostFunctions::default_v01());
    (avm, StateOverlay::new(), ExecutionContext::testnet([0u8; 41], [0u8; 41]))
}

fn call(f: &str, args: Vec<Value>) -> Result<Value, String> {
    let (avm, mut st, ctx) = build();
    let idx = avm.find_function(f).unwrap_or_else(|| panic!("no fn {f}"));
    match avm.execute(idx, args, &ctx, &mut st) {
        Ok(res) if res.receipt.status == ReceiptStatus::Success => {
            Ok(res.return_value.unwrap_or(Value::Bool(false)))
        }
        Ok(res) => Err(format!("{:?}", res.receipt.status)),
        Err(e) => Err(format!("{e:?}")),
    }
}

fn i(v: i64) -> Value { Value::I64(v) }

#[test]
fn signed_subtraction_goes_negative() {
    assert_eq!(call("sub", vec![i(3), i(9)]).unwrap(), i(-6));
    assert_eq!(call("sub", vec![i(9), i(3)]).unwrap(), i(6));
}

#[test]
fn signed_add_mul_div_mod_with_negatives() {
    assert_eq!(call("add", vec![i(-7), i(-3)]).unwrap(), i(-10));
    assert_eq!(call("add", vec![i(-7), i(10)]).unwrap(), i(3));
    assert_eq!(call("mul", vec![i(-7), i(3)]).unwrap(), i(-21));
    assert_eq!(call("mul", vec![i(-7), i(-3)]).unwrap(), i(21));
    assert_eq!(call("div", vec![i(-7), i(2)]).unwrap(), i(-3));   // truncates toward zero
    assert_eq!(call("modu", vec![i(-7), i(3)]).unwrap(), i(-1));  // sign follows dividend
}

#[test]
fn negation_of_a_signed_value() {
    assert_eq!(call("neg", vec![i(5)]).unwrap(), i(-5));
    assert_eq!(call("neg", vec![i(-5)]).unwrap(), i(5));
}

#[test]
fn signed_comparison_orders_negatives_correctly() {
    assert_eq!(call("lt", vec![i(-1), i(0)]).unwrap(), Value::Bool(true));
    assert_eq!(call("lt", vec![i(0), i(-1)]).unwrap(), Value::Bool(false));
    assert_eq!(call("ge", vec![i(-5), i(-6)]).unwrap(), Value::Bool(true));
}

#[test]
fn signed_division_by_zero_is_an_error_not_a_panic() {
    assert!(call("div", vec![i(5), i(0)]).is_err());
    assert!(call("modu", vec![i(5), i(0)]).is_err());
}

#[test]
fn storing_a_negative_literal_works_and_round_trips() {
    // The TypeTestContract.init() case: `i_val = -42;`
    let (avm, mut st, ctx) = build();
    let set = avm.find_function("setNeg").unwrap();
    let r = avm.execute(set, vec![], &ctx, &mut st).unwrap();
    assert_eq!(r.receipt.status, ReceiptStatus::Success);
    let get = avm.find_function("getI").unwrap();
    let g = avm.execute(get, vec![], &ctx, &mut st).unwrap();
    assert_eq!(g.return_value.unwrap(), i(-42));
}

#[test]
fn unsigned_underflow_still_reverts() {
    // u256 must stay strictly unsigned: 3 - 9 is an underflow, not -6.
    assert!(call("usub", vec![Value::U64(3), Value::U64(9)]).is_err(),
        "u256 subtraction below zero must still fail");
    assert_eq!(call("usub", vec![Value::U64(9), Value::U64(3)]).unwrap(), Value::U64(6));
}

#[test]
fn unsigned_negation_still_reverts() {
    assert!(call("uneg", vec![Value::U64(5)]).is_err(),
        "0 - x on a u256 must still fail");
}

#[test]
fn contract_without_signed_values_compiles_to_no_signed_opcodes() {
    let src = "contract U {\n state {\n  a: u256;\n }\n impl {\n  @public\n  function f(x: u256, y: u256) -> u256 { return x - y + x * y / (x % y); }\n  @public\n  function g(x: u256, y: u256) -> bool { return x < y; }\n }\n}\n";
    let ast = parse(src).unwrap();
    let c = ast.iter().find_map(|u| if let SourceUnit::Contract(c) = u { Some(c) } else { None }).unwrap();
    let r = compile_to_aivm(c, &[]).unwrap();
    for ins in &r.instructions {
        assert!(!matches!(ins,
            Instruction::AddI | Instruction::SubI | Instruction::MulI | Instruction::DivI | Instruction::ModI |
            Instruction::LtI | Instruction::GtI | Instruction::LeI | Instruction::GeI),
            "unsigned-only contract emitted a signed opcode: {ins:?}");
    }
}

#[test]
fn unsigned_state_target_rejects_a_negative_literal() {
    // `u: u256 = 0 - 5` must still be an underflow: only a signed TARGET makes
    // two bare literals signed.
    assert!(call("setUNegLit", vec![]).is_err(), "u256 = 0 - 5 must still fail");
}

#[test]
fn return_type_decides_signedness_of_a_literal_expression() {
    assert_eq!(call("retNegLit", vec![]).unwrap(), i(-7));
    assert!(call("retUNegLit", vec![]).is_err(), "returning 0 - 7 as u256 must still fail");
}

// `!=` used to convert both sides to u256, so any negative operand failed with
// TypeMismatch { expected: "u256", got: "i64_negative" } (TypeTestContract's
// testSigned(-7, -3) and testSigned(-5, 2) scenario steps).
#[test]
fn not_equal_works_on_negative_values() {
    assert_eq!(call("neq", vec![i(-7), i(0)]), Ok(Value::Bool(true)));
    assert_eq!(call("neq", vec![i(-7), i(-3)]), Ok(Value::Bool(true)));
    assert_eq!(call("neq", vec![i(-3), i(-3)]), Ok(Value::Bool(false)));
    assert_eq!(call("neq", vec![i(-1), i(1)]), Ok(Value::Bool(true)));
}

#[test]
fn not_equal_unchanged_for_non_negative_values() {
    assert_eq!(call("neq", vec![i(5), i(5)]), Ok(Value::Bool(false)));
    assert_eq!(call("neq", vec![i(5), i(6)]), Ok(Value::Bool(true)));
    assert_eq!(call("neq", vec![Value::U64(5), i(5)]), Ok(Value::Bool(false)));
    assert_eq!(call("neq", vec![i(0), i(0)]), Ok(Value::Bool(false)));
}

#[test]
fn equal_and_not_equal_agree_on_negatives() {
    for (a, b) in [(-7, -7), (-7, -3), (-1, 1), (0, -1), (-42, -42)] {
        let e = call("eq", vec![i(a), i(b)]).unwrap();
        let n = call("neq", vec![i(a), i(b)]).unwrap();
        assert_ne!(e, n, "eq and neq must disagree for ({a}, {b})");
    }
}

// The exact identity checks TypeTestContract.testSigned runs, on the exact
// argument pairs the scenarios use. 0 means every identity holds.
#[test]
fn signed_identities_hold_for_scenario_arguments() {
    for (x, y) in [(-7, -3), (-5, 2), (7, 3), (3, -9), (-100, 3), (0, -4), (-8, 0)] {
        assert_eq!(call("roundTrip", vec![i(x), i(y)]), Ok(Value::U64(0)), "roundTrip({x},{y})");
    }
}
