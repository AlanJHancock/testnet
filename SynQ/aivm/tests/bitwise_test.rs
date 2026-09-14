//! AIVM bitwise/shift opcode tests (2026-09-14) — BitAnd/BitOr/BitXor/Shl/
//! Shr, all operating at full 256-bit precision via the same
//! as_u256()/Value::from_u256_shrink widen/narrow pattern the U256
//! arithmetic fix (2026-09-09, see u256_test.rs) already established.
//! `~` (BitNot) has no dedicated opcode -- the compiler synthesizes it as
//! `x XOR 0xFF..FF`, so it's covered by the codegen-level test instead
//! (compiler/tests/aivm_codegen_test.rs).

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

/// BitAnd on two values both above u128::MAX must compute correctly at
/// full 256-bit width -- this is exactly the range the old "AIVM has no
/// bitwise ops at all" gap could never reach, by definition.
#[test]
fn test_bitand_above_u128_max() {
    let a = U256::MAX - U256::from(0b1010u32); // ...11110101
    let b = U256::MAX - U256::from(0b0110u32); // ...11111001
    let (avm, ctx, mut state) = single_fn(
        vec![
            Instruction::PushU256(a.to_be_bytes::<32>()),
            Instruction::PushU256(b.to_be_bytes::<32>()),
            Instruction::BitAnd,
            Instruction::Ret,
        ],
        0,
    );
    let result = avm.execute(0, vec![], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::from_u256_shrink(a & b)));
}

#[test]
fn test_bitor_above_u128_max() {
    let a = U256::from(1u32) << 200usize; // bit 200 set, nothing else
    let b = U256::from(1u32) << 5usize;   // bit 5 set, nothing else
    let (avm, ctx, mut state) = single_fn(
        vec![
            Instruction::PushU256(a.to_be_bytes::<32>()),
            Instruction::PushU256(b.to_be_bytes::<32>()),
            Instruction::BitOr,
            Instruction::Ret,
        ],
        0,
    );
    let result = avm.execute(0, vec![], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::from_u256_shrink(a | b)));
    assert_eq!(result.return_value, Some(Value::U256(a | b))); // above u128::MAX -- stays U256
}

#[test]
fn test_bitxor_self_is_zero_at_full_width() {
    let a = U256::MAX;
    let (avm, ctx, mut state) = single_fn(
        vec![
            Instruction::PushU256(a.to_be_bytes::<32>()),
            Instruction::PushU256(a.to_be_bytes::<32>()),
            Instruction::BitXor,
            Instruction::Ret,
        ],
        0,
    );
    let result = avm.execute(0, vec![], &ctx, &mut state).unwrap();
    // U256::MAX ^ U256::MAX == 0, narrows all the way down to U64(0).
    assert_eq!(result.return_value, Some(Value::U64(0)));
}

/// Shl must operate at full 256-bit width, not wrap at 64/128 bits -- a
/// shift that pushes a set bit past bit 128 must still be visible in the
/// U256 result.
#[test]
fn test_shl_past_u128_boundary() {
    let (avm, ctx, mut state) = single_fn(
        vec![
            Instruction::PushU64(1),
            Instruction::PushU64(200),
            Instruction::Shl,
            Instruction::Ret,
        ],
        0,
    );
    let result = avm.execute(0, vec![], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::U256(U256::from(1u32) << 200usize)));
}

/// Shift amounts >= 256 must saturate to zero (ruint's own Shl/Shr
/// semantics), not panic or wrap the shift amount modulo 256.
#[test]
fn test_shl_saturates_to_zero_past_256() {
    let (avm, ctx, mut state) = single_fn(
        vec![
            Instruction::PushU256(U256::MAX.to_be_bytes::<32>()),
            Instruction::PushU64(256),
            Instruction::Shl,
            Instruction::Ret,
        ],
        0,
    );
    let result = avm.execute(0, vec![], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::U64(0)));
}

#[test]
fn test_shr_basic_and_narrows_back_to_u64() {
    let (avm, ctx, mut state) = single_fn(
        vec![
            Instruction::PushU64(64),
            Instruction::PushU64(2),
            Instruction::Shr,
            Instruction::Ret,
        ],
        0,
    );
    let result = avm.execute(0, vec![], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::U64(16)));
}

/// Gas is actually charged for these ops (BITWISE cost), not free --
/// regression guard against a gas-metering gap on the new opcodes.
#[test]
fn test_bitwise_op_charges_gas() {
    let (avm, ctx, mut state) = single_fn(
        vec![
            Instruction::PushU64(6),
            Instruction::PushU64(3),
            Instruction::BitAnd,
            Instruction::Ret,
        ],
        0,
    );
    let result = avm.execute(0, vec![], &ctx, &mut state).unwrap();
    assert!(result.receipt.gas_used > 0, "expected non-zero gas usage for a BitAnd op");
    assert_eq!(result.return_value, Some(Value::U64(2))); // 6 & 3 == 2
}
