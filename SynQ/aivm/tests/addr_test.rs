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
