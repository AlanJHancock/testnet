//! addr.encode / addr.decode host function tests (2026-09-09).
//!
//! Covers the HostFunctionNotDeclared("addr.encode") bug: to_tsynq(caller)/
//! to_syna(owner)-style calls (compiled to HostCall(17)) and from_tsynq/
//! from_syn/from_syna calls (HostCall(18)) had no dispatch arm at all in
//! execute_host_call before this fix, so every such call reverted in AIVM
//! dry-run while the equivalent Live QVM session succeeded (native vm
//! crate's OpCode::AddrEncode/AddrDecode have always been implemented).

use aivm::*;
use aivm::instructions::Instruction;
use aivm::vm::{FunctionEntry, FunctionVisibility, FunctionMutability, StateOverlay};
use aivm::host::{HostFunctions, Value};
use aivm::context::ExecutionContext;

fn make_host() -> HostFunctions {
    HostFunctions::default_v01()
}

fn one_fn(instructions: Vec<Instruction>) -> (Vec<Instruction>, Vec<FunctionEntry>) {
    let functions = vec![FunctionEntry {
        name: "run".to_string(),
        instruction_offset: 0,
        param_count: 0,
        visibility: FunctionVisibility::Public,
        mutability: FunctionMutability::View,
    }];
    (instructions, functions)
}

/// to_tsynq(caller()) -- HostCall(5) then HostCall(17) -- must return the
/// exact same synw string encode_wallet_address would produce for the
/// caller's 20-byte identity, matching what Live QVM's OpCode::AddrEncode
/// already returns for the same caller.
#[test]
fn test_addr_encode_matches_wallet_address() {
    let id20: [u8; 20] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
        0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05,
    ];
    let caller = aivm::addr::decoded_id_to_address_bytes(&id20);
    let ctx = ExecutionContext::testnet(caller, [0u8; 41]);

    let (instructions, functions) = one_fn(vec![
        Instruction::HostCall(5),  // context.caller
        Instruction::HostCall(17), // addr.encode
        Instruction::Ret,
    ]);

    let avm = Avm::new(instructions, functions, make_host());
    let mut state = StateOverlay::new();
    let result = avm.execute(0, vec![], &ctx, &mut state).unwrap();

    let expected = aivm::addr::encode_wallet_address(&id20).unwrap();
    assert!(expected.starts_with("synw1"), "sanity: expected a synw address, got {}", expected);
    assert_eq!(result.return_value, Some(Value::String(expected)));
}

/// The all-zero caller (no caller override supplied) must encode to the
/// literal SNTS-01 zero sentinel, not a derived Bech32m string -- matches
/// vm::bech32::encode_network_address's special case.
#[test]
fn test_addr_encode_zero_caller_is_sentinel() {
    let ctx = ExecutionContext::testnet([0u8; 41], [0u8; 41]);
    let (instructions, functions) = one_fn(vec![
        Instruction::HostCall(5),
        Instruction::HostCall(17),
        Instruction::Ret,
    ]);
    let avm = Avm::new(instructions, functions, make_host());
    let mut state = StateOverlay::new();
    let result = avm.execute(0, vec![], &ctx, &mut state).unwrap();
    assert_eq!(
        result.return_value,
        Some(Value::String("syn00000000000000000000000000000000000000".to_string()))
    );
}

/// from_tsynq(s)/from_syna(s) round-trip: decode a synw address string back
/// into an address value, then re-encode it -- must reproduce the exact
/// original string. Exercises addr.decode's real dispatch arm (HostCall(18)),
/// previously also HostFunctionNotDeclared.
#[test]
fn test_addr_decode_then_encode_roundtrips() {
    let id20: [u8; 20] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    ];
    let original = aivm::addr::encode_wallet_address(&id20).unwrap();

    let ctx = ExecutionContext::testnet([0u8; 41], [0u8; 41]);
    let (instructions, functions) = one_fn(vec![
        Instruction::PushString(original.clone()),
        Instruction::HostCall(18), // addr.decode
        Instruction::HostCall(17), // addr.encode
        Instruction::Ret,
    ]);
    let avm = Avm::new(instructions, functions, make_host());
    let mut state = StateOverlay::new();
    let result = avm.execute(0, vec![], &ctx, &mut state).unwrap();

    assert_eq!(result.return_value, Some(Value::String(original)));
}

/// Legacy tsynq addresses are explicitly unsupported in the AIVM sandbox
/// (retired per Synergy Protocol Naming & Encoding Standards v1.3) -- must
/// fail with a clear, named error rather than silently misdecoding or
/// falling back to HostFunctionNotDeclared.
#[test]
fn test_addr_decode_rejects_legacy_tsynq() {
    let ctx = ExecutionContext::testnet([0u8; 41], [0u8; 41]);
    let (instructions, functions) = one_fn(vec![
        Instruction::PushString("tsynq1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".to_string()),
        Instruction::HostCall(18),
        Instruction::Ret,
    ]);
    let avm = Avm::new(instructions, functions, make_host());
    let mut state = StateOverlay::new();
    let err = avm.execute(0, vec![], &ctx, &mut state).unwrap_err();
    let msg = format!("{:?}", err);
    assert!(msg.contains("addr.decode"), "expected addr.decode context in error, got: {}", msg);
    assert!(msg.contains("legacy"), "expected a legacy-tsynq-specific message, got: {}", msg);
}


/// Bug report (2026-09-09, live): calling `getOwnerSyna()` fresh (no prior
/// `init()`) failed with `TypeMismatch { expected: "address", got: "bytes"
/// }`. Root cause: a freshly-deployed contract's `Bytes<20>`/`Address`-typed
/// state var (e.g. `V3Types.owner`) defaults to `Value::Bytes(vec![])` --
/// synq-server's `default_aivm_value_for_type` (aivm_handler.rs) seeds an
/// EMPTY `Value::Bytes`, not a `Value::Address` -- and `as_address()` had no
/// arm for `Value::Bytes` at all before this fix (only `Address`/`U128`/
/// `U64`), so `to_tsynq(owner)` on that default value TypeMismatched instead
/// of encoding to the zero-sentinel address. Reproduces the same shape at
/// the aivm-crate level: seed state key 0 with an empty `Value::Bytes`
/// (exactly what a never-written `Bytes<20>`/`Address` field holds) and
/// confirm `addr.encode` now succeeds.
#[test]
fn test_addr_encode_accepts_default_empty_bytes_state_value() {
    let ctx = ExecutionContext::testnet([0u8; 41], [0u8; 41]);
    let (instructions, functions) = one_fn(vec![
        Instruction::LoadState(0),
        Instruction::HostCall(17), // addr.encode
        Instruction::Ret,
    ]);
    let avm = Avm::new(instructions, functions, make_host());
    // Seed committed state key 0 with an empty Bytes value, matching
    // synq-server's default_aivm_value_for_type() for a never-written
    // Bytes<20>/Address state var -- NOT Value::Address.
    let mut state = StateOverlay::with_state(
        [(0u16, Value::Bytes(vec![]))].into_iter().collect(),
    );
    let result = avm.execute(0, vec![], &ctx, &mut state).unwrap();
    assert_eq!(
        result.return_value,
        Some(Value::String("syn00000000000000000000000000000000000000".to_string()))
    );
}

/// Same bug, non-empty short/long `Value::Bytes` shapes: `as_address()`'s
/// `Bytes` arm must byte-for-byte match `vm::vm.rs`'s native `AddrEncode`
/// padding/truncation rules (left-pad under 20 bytes, keep the last 20 of
/// 21..=32 bytes) so a `Bytes<20>` identity encodes identically in AIVM
/// dry-run and Live QVM.
#[test]
fn test_addr_encode_pads_and_truncates_bytes_like_native_vm() {
    let ctx = ExecutionContext::testnet([0u8; 41], [0u8; 41]);

    // Exactly 20 bytes -- direct passthrough into the identity slot.
    let id20: [u8; 20] = [0x42; 20];
    let expected20 = aivm::addr::encode_wallet_address(&id20).unwrap();
    let (instructions, functions) = one_fn(vec![
        Instruction::LoadState(0),
        Instruction::HostCall(17),
        Instruction::Ret,
    ]);
    let avm = Avm::new(instructions, functions, make_host());
    let mut state = StateOverlay::with_state(
        [(0u16, Value::Bytes(id20.to_vec()))].into_iter().collect(),
    );
    let result = avm.execute(0, vec![], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::String(expected20)));

    // Short (5-byte) value -- left-padded with zeros to 20 bytes, matching
    // vm.rs's `b.len() < 20` arm.
    let short: Vec<u8> = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    let mut padded_id20 = [0u8; 20];
    padded_id20[15..20].copy_from_slice(&short);
    let expected_short = aivm::addr::encode_wallet_address(&padded_id20).unwrap();
    let (instructions2, functions2) = one_fn(vec![
        Instruction::LoadState(0),
        Instruction::HostCall(17),
        Instruction::Ret,
    ]);
    let avm2 = Avm::new(instructions2, functions2, make_host());
    let mut state2 = StateOverlay::with_state(
        [(0u16, Value::Bytes(short))].into_iter().collect(),
    );
    let result2 = avm2.execute(0, vec![], &ctx, &mut state2).unwrap();
    assert_eq!(result2.return_value, Some(Value::String(expected_short)));

    // Oversized (32-byte) value -- last 20 bytes kept, matching vm.rs's
    // `b.len() <= 32` arm.
    let long: Vec<u8> = (1u8..=32u8).collect();
    let mut truncated_id20 = [0u8; 20];
    truncated_id20.copy_from_slice(&long[12..32]);
    let expected_long = aivm::addr::encode_wallet_address(&truncated_id20).unwrap();
    let (instructions3, functions3) = one_fn(vec![
        Instruction::LoadState(0),
        Instruction::HostCall(17),
        Instruction::Ret,
    ]);
    let avm3 = Avm::new(instructions3, functions3, make_host());
    let mut state3 = StateOverlay::with_state(
        [(0u16, Value::Bytes(long))].into_iter().collect(),
    );
    let result3 = avm3.execute(0, vec![], &ctx, &mut state3).unwrap();
    assert_eq!(result3.return_value, Some(Value::String(expected_long)));
}

/// A `Bytes` value longer than 32 bytes has no unambiguous 20-byte identity
/// and must fail closed with a clear error -- not silently truncate --
/// exactly mirroring `vm.rs`'s `AddrEncode` (its match arms stop at 32
/// bytes; anything longer falls to its own `_ => Err` arm).
#[test]
fn test_addr_encode_rejects_oversized_bytes() {
    let ctx = ExecutionContext::testnet([0u8; 41], [0u8; 41]);
    let (instructions, functions) = one_fn(vec![
        Instruction::LoadState(0),
        Instruction::HostCall(17),
        Instruction::Ret,
    ]);
    let avm = Avm::new(instructions, functions, make_host());
    let mut state = StateOverlay::with_state(
        [(0u16, Value::Bytes(vec![0u8; 33]))].into_iter().collect(),
    );
    let err = avm.execute(0, vec![], &ctx, &mut state).unwrap_err();
    let msg = format!("{:?}", err);
    assert!(msg.contains("address"), "expected an address-related TypeMismatch, got: {}", msg);
}
