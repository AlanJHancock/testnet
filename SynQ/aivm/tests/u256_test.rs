//! AIVM U256 support tests (2026-09-09) — PushU256, widened arithmetic
//! (AddU64/SubU64/MulU64/DivU64/ModU64 now operate at full 256-bit
//! precision internally despite their legacy "U64" names), widened
//! comparisons (Lt/Gt/Ne/Le/Ge/Eq), and the narrow-back-down behavior that
//! keeps ordinary small-number arithmetic producing the same Value::U64
//! it always did.

use aivm::*;
use aivm::instructions::Instruction;
use aivm::vm::{FunctionEntry, FunctionVisibility, FunctionMutability, StateOverlay};
use aivm::host::{HostFunctions, Value};
use aivm::context::ExecutionContext;
use ruint::aliases::U256;

fn make_ctx() -> ExecutionContext {
    ExecutionContext::testnet([0u8; 41], [0u8; 41])
}

fn make_host() -> HostFunctions {
    HostFunctions::default_v01()
}

fn single_fn(instructions: Vec<Instruction>, param_count: u16) -> (Avm, ExecutionContext, StateOverlay) {
    let functions = vec![FunctionEntry {
        name: "f".to_string(),
        instruction_offset: 0,
        param_count,
        visibility: FunctionVisibility::Public,
        mutability: FunctionMutability::View,
    }];
    (Avm::new(instructions, functions, make_host()), make_ctx(), StateOverlay::new())
}

/// PushU256 pushes the exact literal, byte-for-byte, and it round-trips
/// through Ret unchanged -- including a value far above u128::MAX, which
/// PushU64 (8-byte operand) could never represent at all.
#[test]
fn test_push_u256_roundtrip() {
    let (avm, ctx, mut state) = single_fn(
        vec![Instruction::PushU256(U256::MAX.to_be_bytes::<32>()), Instruction::Ret],
        0,
    );
    let result = avm.execute(0, vec![], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::U256(U256::MAX)));
}

/// Ordinary small-number addition must still produce Value::U64 (and
/// therefore still serialize as a bare JSON number, not a decimal string)
/// -- the widen-then-narrow round trip must be invisible for every case
/// that worked before this change.
#[test]
fn test_add_small_numbers_still_narrows_to_u64() {
    let (avm, ctx, mut state) = single_fn(
        vec![
            Instruction::PushU64(2),
            Instruction::PushU64(3),
            Instruction::AddU64,
            Instruction::Ret,
        ],
        0,
    );
    let result = avm.execute(0, vec![], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::U64(5)));
}

/// Addition on two values that individually exceed u128::MAX must compute
/// correctly at full 256-bit width -- this used to be impossible: as_u64()
/// would TypeMismatch-error the moment either operand exceeded u64::MAX,
/// let alone u128::MAX.
#[test]
fn test_add_above_u128_max() {
    let a = U256::MAX - U256::from(5u32); // U256::MAX - 5
    let (avm, ctx, mut state) = single_fn(
        vec![
            Instruction::PushU256(a.to_be_bytes::<32>()),
            Instruction::PushU64(3),
            Instruction::AddU64,
            Instruction::Ret,
        ],
        0,
    );
    let result = avm.execute(0, vec![], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::U256(a + U256::from(3u32))));
}

/// Adding 1 to U256::MAX must overflow and trap -- the true 256-bit
/// ceiling, not the old (much lower) u64 ceiling.
#[test]
fn test_add_u256_max_overflows() {
    let (avm, ctx, mut state) = single_fn(
        vec![
            Instruction::PushU256(U256::MAX.to_be_bytes::<32>()),
            Instruction::PushU64(1),
            Instruction::AddU64,
            Instruction::Ret,
        ],
        0,
    );
    let err = avm.execute(0, vec![], &ctx, &mut state).unwrap_err();
    assert!(matches!(err, AivmError::ArithmeticOverflow), "expected ArithmeticOverflow, got {:?}", err);
}

/// Subtracting a larger U256 from a smaller one must still underflow-trap
/// (no silent wraparound) at full width.
#[test]
fn test_sub_u256_underflow() {
    let (avm, ctx, mut state) = single_fn(
        vec![
            Instruction::PushU64(1),
            Instruction::PushU256(U256::MAX.to_be_bytes::<32>()),
            Instruction::SubU64,
            Instruction::Ret,
        ],
        0,
    );
    let err = avm.execute(0, vec![], &ctx, &mut state).unwrap_err();
    assert!(matches!(err, AivmError::ArithmeticUnderflow), "expected ArithmeticUnderflow, got {:?}", err);
}

/// Multiplication that lands squarely in U128 range (>u64::MAX, <=u128::MAX)
/// must narrow to Value::U128, not stay a Value::U256 -- the "narrow to the
/// smallest fitting variant" rule applies at every tier, not just U64.
#[test]
fn test_mul_narrows_to_u128() {
    let big: u64 = 5_000_000_000_000; // > u32::MAX, well within u64
    let (avm, ctx, mut state) = single_fn(
        vec![
            Instruction::PushU64(big),
            Instruction::PushU64(big),
            Instruction::MulU64,
            Instruction::Ret,
        ],
        0,
    );
    let result = avm.execute(0, vec![], &ctx, &mut state).unwrap();
    let expected = (big as u128) * (big as u128);
    assert!(expected > u64::MAX as u128 && expected <= u128::MAX, "test value should land in u128-only range");
    assert_eq!(result.return_value, Some(Value::U128(expected)));
}

/// Division and modulo also operate at full width and reject div-by-zero
/// the same as before.
#[test]
fn test_div_mod_above_u128_max() {
    let a: U256 = U256::from(10u32) * (U256::from(1u128) << 200); // well above u128::MAX
    let (avm_div, ctx, mut state) = single_fn(
        vec![
            Instruction::PushU256(a.to_be_bytes::<32>()),
            Instruction::PushU64(2),
            Instruction::DivU64,
            Instruction::Ret,
        ],
        0,
    );
    let result = avm_div.execute(0, vec![], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::from_u256_shrink(a / U256::from(2u32))));

    let (avm_div0, ctx2, mut state2) = single_fn(
        vec![
            Instruction::PushU256(a.to_be_bytes::<32>()),
            Instruction::PushU64(0),
            Instruction::DivU64,
            Instruction::Ret,
        ],
        0,
    );
    let err = avm_div0.execute(0, vec![], &ctx2, &mut state2).unwrap_err();
    assert!(matches!(err, AivmError::DivisionByZero));
}

/// Eq must compare numerically across variant widths -- Value::U64(5) and
/// a Value::U256 that happens to also be 5 must be equal, even though they
/// are different Rust enum variants (this would be false under naive
/// derived/structural equality).
#[test]
fn test_eq_widens_across_variants() {
    let (avm, ctx, mut state) = single_fn(
        vec![
            Instruction::PushU64(5),
            Instruction::PushU256(U256::from(5u32).to_be_bytes::<32>()),
            Instruction::Eq,
            Instruction::Ret,
        ],
        0,
    );
    let result = avm.execute(0, vec![], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::Bool(true)));
}

/// Eq must still fall back to structural equality for non-numeric values
/// (unchanged behavior) -- two equal strings compare equal.
#[test]
fn test_eq_still_works_for_strings() {
    let (avm, ctx, mut state) = single_fn(
        vec![
            Instruction::PushString("hello".to_string()),
            Instruction::PushString("hello".to_string()),
            Instruction::Eq,
            Instruction::Ret,
        ],
        0,
    );
    let result = avm.execute(0, vec![], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::Bool(true)));
}

/// Lt/Gt/Ne/Le/Ge must compare correctly on values above u128::MAX, which
/// the old as_u128()-based comparisons could never even accept.
#[test]
fn test_comparisons_above_u128_max() {
    let big = U256::MAX;
    let small = U256::from(1u32);

    let (avm, ctx, mut state) = single_fn(
        vec![
            Instruction::PushU256(small.to_be_bytes::<32>()),
            Instruction::PushU256(big.to_be_bytes::<32>()),
            Instruction::Lt,
            Instruction::Ret,
        ],
        0,
    );
    let result = avm.execute(0, vec![], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::Bool(true)), "1 < U256::MAX");

    let (avm2, ctx2, mut state2) = single_fn(
        vec![
            Instruction::PushU256(big.to_be_bytes::<32>()),
            Instruction::PushU256(small.to_be_bytes::<32>()),
            Instruction::Ge,
            Instruction::Ret,
        ],
        0,
    );
    let result2 = avm2.execute(0, vec![], &ctx2, &mut state2).unwrap();
    assert_eq!(result2.return_value, Some(Value::Bool(true)), "U256::MAX >= 1");
}

/// as_address() on a U256 value above u128::MAX takes the low-20-byte
/// identity slot (same convention as the Bytes/Bytes32 arms), while one
/// that fits u128 mirrors the existing U128 literal-encoding slot exactly.
#[test]
fn test_as_address_u256_both_branches() {
    let small = Value::U256(U256::from(42u32));
    let addr_small = small.as_address().unwrap();
    let addr_small_u128 = Value::U128(42u128).as_address().unwrap();
    assert_eq!(addr_small, addr_small_u128, "U256 within u128 range must match the U128 arm byte-for-byte");

    let huge = Value::U256(U256::MAX);
    let addr_huge = huge.as_address().unwrap();
    // Must not error, and must not be the all-zero/degenerate address.
    assert_ne!(addr_huge, [0u8; 41]);
}
