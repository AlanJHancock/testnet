use synq_vm::{Assembler, OpCode, QuantumVM};

#[test]
fn test_basic_arithmetic() {
    let mut assembler = Assembler::new();
    assembler.emit_op(OpCode::Push);
    assembler.emit_i32(10);
    assembler.emit_op(OpCode::Push);
    assembler.emit_i32(20);
    assembler.emit_op(OpCode::Add);
    assembler.emit_op(OpCode::Halt);

    let bytecode = assembler.build();
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();
    vm.execute().unwrap();

    let result = vm.stack.pop().unwrap().as_i32().unwrap();
    assert_eq!(result, 30);
}

#[test]
fn test_dilithium_verify_shim() {
    // Uses a REAL ML-DSA-65 keypair + real signature (not the old zeroed
    // placeholder bytes) so this test actually exercises the fixed
    // real-crypto verify path end to end through the VM opcode.
    let (pk, sk) = pqc_shims::dilithium::keygen();
    let message = b"Hello, quantum world!";
    let signature = pqc_shims::dilithium::sign(message, &sk);

    let mut assembler = Assembler::new();

    // The arguments are popped in reverse order of how they are pushed.
    // Push order: signature, message, public_key (public_key ends up on
    // top of the stack, popped first by the VM's DilithiumVerify handler).
    assembler.emit_op(OpCode::LoadImm);
    assembler.emit_bytes(&signature);

    assembler.emit_op(OpCode::LoadImm);
    assembler.emit_bytes(message);

    assembler.emit_op(OpCode::LoadImm);
    assembler.emit_bytes(&pk);

    assembler.emit_op(OpCode::DilithiumVerify);
    assembler.emit_op(OpCode::Halt);

    let bytecode = assembler.build();
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();
    vm.execute().unwrap();

    let result = vm.stack.pop().unwrap().as_bool().unwrap();
    assert_eq!(result, true);
}

#[test]
fn test_dilithium_verify_shim_rejects_forged_signature() {
    // A signature made with a DIFFERENT keypair must not verify against
    // the original public key — proves the VM path enforces real security
    // properties rather than the old always-true stub.
    let (pk, _sk) = pqc_shims::dilithium::keygen();
    let (_other_pk, other_sk) = pqc_shims::dilithium::keygen();
    let message = b"Hello, quantum world!";
    let forged_signature = pqc_shims::dilithium::sign(message, &other_sk);

    let mut assembler = Assembler::new();
    assembler.emit_op(OpCode::LoadImm);
    assembler.emit_bytes(&forged_signature);
    assembler.emit_op(OpCode::LoadImm);
    assembler.emit_bytes(message);
    assembler.emit_op(OpCode::LoadImm);
    assembler.emit_bytes(&pk);
    assembler.emit_op(OpCode::DilithiumVerify);
    assembler.emit_op(OpCode::Halt);

    let bytecode = assembler.build();
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();
    vm.execute().unwrap();

    let result = vm.stack.pop().unwrap().as_bool().unwrap();
    assert_eq!(result, false);
}

#[test]
fn test_kyber_decaps_shim() {
    // Uses a REAL Kyber-768 keypair + real encapsulation (not the old
    // fake fixed-size byte arrays) so decapsulation inside the VM must
    // recover the exact same shared secret that encaps produced.
    let (pk, sk) = pqc_shims::kyber::keygen().unwrap();
    let (ciphertext, expected_shared_secret) = pqc_shims::kyber::encaps(&pk).unwrap();

    let mut assembler = Assembler::new();

    // The decaps function expects (ciphertext, private_key), and the VM
    // pops private_key first, so push order is: ciphertext, private_key.
    assembler.emit_op(OpCode::LoadImm);
    assembler.emit_bytes(&ciphertext);

    assembler.emit_op(OpCode::LoadImm);
    assembler.emit_bytes(&sk);

    assembler.emit_op(OpCode::KyberKeyExchange); // This opcode maps to decaps
    assembler.emit_op(OpCode::Halt);

    let bytecode = assembler.build();
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();
    vm.execute().unwrap();

    let shared_secret = vm.stack.pop().unwrap().as_bytes().unwrap().to_vec();
    assert_eq!(shared_secret, expected_shared_secret);
}


// --- VM Value::U128 & LoadImm128 Tests ---

#[test]
fn test_u128_push_and_return() {
    // Verify LoadImm128 pushes the correct Value::U128 onto the stack.
    let expected: u128 = 1_000_000_000_000_000_000_000u128; // 10^21 — well above i32::MAX
    let mut assembler = Assembler::new();
    assembler.emit_op(OpCode::LoadImm128);
    assembler.emit_u128(expected);
    assembler.emit_op(OpCode::Halt);
    let bytecode = assembler.build();
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();
    vm.execute().unwrap();
    let result = vm.stack.pop().unwrap();
    assert_eq!(result.as_u128().unwrap(), expected);
}

#[test]
fn test_u128_add() {
    // 1T + 2T = 3T — values that would silently truncate under i32.
    let a: u128 = 1_000_000_000_000u128;
    let b: u128 = 2_000_000_000_000u128;
    let mut assembler = Assembler::new();
    assembler.emit_op(OpCode::LoadImm128);
    assembler.emit_u128(a);
    assembler.emit_op(OpCode::LoadImm128);
    assembler.emit_u128(b);
    assembler.emit_op(OpCode::Add);
    assembler.emit_op(OpCode::Halt);
    let bytecode = assembler.build();
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();
    vm.execute().unwrap();
    let result = vm.stack.pop().unwrap();
    assert_eq!(result.as_u128().unwrap(), 3_000_000_000_000u128);
}

#[test]
fn test_u128_overflow() {
    // With real U256 support, u128::MAX + 1 is a valid U256 value (no overflow).
    // This test now uses U256::MAX + 1, which MUST overflow and return RuntimeError.
    // U256::MAX is emitted as LoadImm256 with 32 bytes of 0xFF.
    let mut assembler = Assembler::new();
    assembler.emit_op(OpCode::LoadImm256);
    assembler.emit_u256_bytes(&[0xFFu8; 32]); // U256::MAX
    assembler.emit_op(OpCode::LoadImm128);
    assembler.emit_u128(1u128);
    assembler.emit_op(OpCode::Add);
    assembler.emit_op(OpCode::Halt);
    let bytecode = assembler.build();
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();
    let err = vm.execute().unwrap_err();
    assert!(format!("{}", err).contains("overflow"),
        "Expected overflow error, got: {}", err);
}

#[test]
fn test_u128_i32_mixed_add() {
    // Push an i32(5) then a U128(10) — Add should promote and return U128(15).
    let mut assembler = Assembler::new();
    assembler.emit_op(OpCode::Push);
    assembler.emit_i32(5);
    assembler.emit_op(OpCode::LoadImm128);
    assembler.emit_u128(10u128);
    assembler.emit_op(OpCode::Add);
    assembler.emit_op(OpCode::Halt);
    let bytecode = assembler.build();
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).unwrap();
    vm.execute().unwrap();
    let result = vm.stack.pop().unwrap();
    assert_eq!(result.as_u128().unwrap(), 15u128);
}

// ════════════════════════════════════════════════════════════════════════════
// PR-B: VM Hardening tests
// ════════════════════════════════════════════════════════════════════════════

/// Item 3 — Step limit terminates infinite loops.
///
/// loop_forever() unconditionally jumps to its own start.
/// With max_steps = 100 the VM must return StepLimitExceeded(100).
#[test]
fn test_step_limit() {
    use synq_vm::vm::QuantumVM;
    use synq_vm::opcode::{OpCode, VMError};
    use synq_vm::assembler::Assembler;

    let mut asm = Assembler::new();
    let fn_addr = asm.current_pos() as u32;
    // Jump back to fn_addr — infinite loop
    asm.emit_op(OpCode::Jump);
    asm.emit_u32(fn_addr);

    asm.add_function_entry("loop_forever", fn_addr, &[], false);
    let bytecode = asm.build();

    let mut vm = QuantumVM::new();
    vm.max_steps = 100;
    vm.load_bytecode(&bytecode).expect("load");

    let result = vm.call_function("loop_forever", &[]);
    assert!(
        matches!(result, Err(VMError::StepLimitExceeded(100))),
        "expected StepLimitExceeded(100), got {:?}", result
    );
}

/// Item 4 — Runtime call depth guard.
///
/// recurse() calls itself unconditionally via the Call opcode.
/// With max_call_depth = 4 the VM must error before frame 5.
#[test]
fn test_call_depth_limit() {
    use synq_vm::vm::QuantumVM;
    use synq_vm::opcode::{OpCode, VMError};
    use synq_vm::assembler::Assembler;

    let mut asm = Assembler::new();
    let fn_addr = asm.current_pos() as u32;
    // Call self — infinite recursion via Call opcode
    asm.emit_op(OpCode::Call);
    asm.emit_u32(fn_addr);
    asm.emit_op(OpCode::Halt);

    asm.add_function_entry("recurse", fn_addr, &[], false);
    let bytecode = asm.build();

    let mut vm = QuantumVM::new();
    vm.max_call_depth = 4;
    vm.max_steps = 1_000_000;
    vm.load_bytecode(&bytecode).expect("load");

    let result = vm.call_function("recurse", &[]);
    match &result {
        Err(VMError::RuntimeError(msg)) => {
            assert!(msg.contains("call depth limit exceeded"),
                "wrong error message: {}", msg);
        }
        other => panic!("expected call depth RuntimeError, got {:?}", other),
    }
}

/// Items 1 + 2 — Sequential calls preserve committed state.
///
/// set_a() writes 42 to memory[10].
/// set_b() writes 99 to memory[20].
/// After both succeed, both values must be intact — the second call's
/// rollback snapshot must not wipe the first call's committed writes.
#[test]
fn test_sequential_calls_preserve_state() {
    use synq_vm::vm::{QuantumVM, Value};
    use synq_vm::opcode::OpCode;
    use synq_vm::assembler::Assembler;

    let mut asm = Assembler::new();

    let addr_a = asm.current_pos() as u32;
    asm.emit_op(OpCode::Push); asm.emit_i32(42);
    asm.emit_op(OpCode::Push); asm.emit_i32(10);
    asm.emit_op(OpCode::Store);
    asm.emit_op(OpCode::Halt);

    let addr_b = asm.current_pos() as u32;
    asm.emit_op(OpCode::Push); asm.emit_i32(99);
    asm.emit_op(OpCode::Push); asm.emit_i32(20);
    asm.emit_op(OpCode::Store);
    asm.emit_op(OpCode::Halt);

    asm.add_function_entry("set_a", addr_a, &[], false);
    asm.add_function_entry("set_b", addr_b, &[], false);
    let bytecode = asm.build();

    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).expect("load");

    vm.call_function("set_a", &[]).expect("set_a failed");
    vm.call_function("set_b", &[]).expect("set_b failed");

    let val_a = vm.memory.get(&10).cloned().unwrap_or(Value::I32(0));
    let val_b = vm.memory.get(&20).cloned().unwrap_or(Value::I32(0));

    assert!(matches!(val_a, Value::I32(42)), "set_a was wiped: {:?}", val_a);
    assert!(matches!(val_b, Value::I32(99)), "set_b not committed: {:?}", val_b);
}

/// Item 2 — Transactional rollback on Revert.
///
/// Uses the SynQ compiler to produce a real contract: bad_mint() stores 999
/// into `total` then hits `require(false)`. After the call, `total` must
/// still be 0 (rollback) and we must get a Reverted error.
#[test]
fn test_rollback_on_revert() {
    use synq_vm::vm::{QuantumVM, Value};
    use synq_vm::opcode::VMError;
    use synq_compiler::compile;

    let src = r#"
pragma synq ^0.9;
contract RollbackTest {
    total: UInt256;
    function bad_mint() {
        total = 999;
        require(false, "always reverts");
    }
}
"#;
    let result = compile(src).expect("compile failed");
    // CompileResult.bytecode is already Vec<u8>
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&result.bytecode).expect("load bytecode");

    // total starts at 0
    let before = vm.memory.get(&0).cloned().unwrap_or(Value::I32(0));
    assert!(matches!(before, Value::I32(0)), "initial total should be 0");

    // Call bad_mint — must revert
    let call_result = vm.call_function("bad_mint", &[]);
    assert!(matches!(call_result, Err(VMError::Reverted(_))),
        "expected Reverted, got {:?}", call_result);

    // After revert, total must be rolled back to 0
    let after = vm.memory.get(&0).cloned().unwrap_or(Value::I32(0));
    assert!(matches!(after, Value::I32(0)),
        "rollback failed — total is {:?}, expected I32(0)", after);
}
