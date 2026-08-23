//! AIVM execution tests — Counter contract

use aivm::*;
use aivm::instructions::Instruction;
use aivm::vm::{FunctionEntry, FunctionVisibility, FunctionMutability, StateOverlay};
use aivm::host::{HostFunctions, Value};
use aivm::context::ExecutionContext;

fn make_ctx() -> ExecutionContext {
    ExecutionContext::testnet([0u8; 41], [0u8; 41])
}

fn make_host() -> HostFunctions {
    HostFunctions::default_v01()
}

/// Counter: state.count at key 0
/// init() — sets count = 0
/// increment() — count = count + 1
/// get() -> u64 — returns count
fn make_counter() -> (Vec<Instruction>, Vec<FunctionEntry>) {
    // Function layout:
    // 0: init()  — PushU64(0), StoreState(0), Ret
    // 3: increment() — LoadState(0), PushU64(1), AddU64, StoreState(0), Ret
    // 8: get() — LoadState(0), Ret

    let instructions = vec![
        // init() at offset 0
        Instruction::PushU64(0),       // 0
        Instruction::StoreState(0),    // 1
        Instruction::Ret,              // 2

        // increment() at offset 3
        Instruction::LoadState(0),      // 3
        Instruction::PushU64(1),        // 4
        Instruction::AddU64,            // 5
        Instruction::StoreState(0),     // 6
        Instruction::Ret,               // 7

        // get() at offset 8
        Instruction::LoadState(0),      // 8
        Instruction::Ret,               // 9
    ];

    let functions = vec![
        FunctionEntry {
            name: "init".to_string(),
            instruction_offset: 0,
            param_count: 0,
            visibility: FunctionVisibility::Public,
            mutability: FunctionMutability::Write,
        },
        FunctionEntry {
            name: "increment".to_string(),
            instruction_offset: 3,
            param_count: 0,
            visibility: FunctionVisibility::Public,
            mutability: FunctionMutability::Write,
        },
        FunctionEntry {
            name: "get".to_string(),
            instruction_offset: 8,
            param_count: 0,
            visibility: FunctionVisibility::Public,
            mutability: FunctionMutability::View,
        },
    ];

    (instructions, functions)
}

#[test]
fn test_counter_init() {
    let (instructions, functions) = make_counter();
    let avm = Avm::new(instructions, functions, make_host());
    let ctx = make_ctx();
    let mut state = StateOverlay::new();

    let result = avm.execute(0, vec![], &ctx, &mut state).unwrap();
    assert_eq!(result.receipt.status, ReceiptStatus::Success);

    // count should be 0
    let val = state.read(0).unwrap();
    assert_eq!(val, Value::U64(0));
}

#[test]
fn test_counter_increment() {
    let (instructions, functions) = make_counter();
    let avm = Avm::new(instructions, functions, make_host());
    let ctx = make_ctx();
    let mut state = StateOverlay::new();

    // init
    avm.execute(0, vec![], &ctx, &mut state).unwrap();

    // increment 3 times
    for _ in 0..3 {
        avm.execute(1, vec![], &ctx, &mut state).unwrap();
    }

    let val = state.read(0).unwrap();
    assert_eq!(val, Value::U64(3));
}

#[test]
fn test_counter_get() {
    let (instructions, functions) = make_counter();
    let avm = Avm::new(instructions, functions, make_host());
    let ctx = make_ctx();
    let mut state = StateOverlay::new();

    // init
    avm.execute(0, vec![], &ctx, &mut state).unwrap();

    // increment
    avm.execute(1, vec![], &ctx, &mut state).unwrap();

    // get
    let result = avm.execute(2, vec![], &ctx, &mut state).unwrap();
    assert_eq!(result.receipt.status, ReceiptStatus::Success);
    assert_eq!(result.return_value, Some(Value::U64(1)));
}

#[test]
fn test_state_rollback_on_trap() {
    // A function that writes state then traps
    let instructions = vec![
        // bad_fn at offset 0
        Instruction::PushU64(999),      // 0
        Instruction::StoreState(0),     // 1
        Instruction::Trap(5),           // 2 — unauthorized
        Instruction::Ret,               // 3
    ];

    let functions = vec![FunctionEntry {
        name: "bad_fn".to_string(),
        instruction_offset: 0,
        param_count: 0,
        visibility: FunctionVisibility::Public,
        mutability: FunctionMutability::Write,
    }];

    let avm = Avm::new(instructions, functions, make_host());
    let ctx = make_ctx();
    let mut state = StateOverlay::new();

    // Pre-set some state
    state.write(0, Value::U64(42));
    state.commit();

    let result = avm.execute(0, vec![], &ctx, &mut state).unwrap();
    assert_eq!(result.receipt.status, ReceiptStatus::Reverted);

    // State should be rolled back — 999 should NOT be there
    let val = state.read(0).unwrap();
    assert_eq!(val, Value::U64(42)); // original value preserved
}

#[test]
fn test_arithmetic_overflow_traps() {
    let instructions = vec![
        // overflow_fn at offset 0
        Instruction::PushU64(u64::MAX),  // 0
        Instruction::PushU64(1),         // 1
        Instruction::AddU64,              // 2 — overflow!
        Instruction::Ret,                // 3
    ];

    let functions = vec![FunctionEntry {
        name: "overflow_fn".to_string(),
        instruction_offset: 0,
        param_count: 0,
        visibility: FunctionVisibility::Public,
        mutability: FunctionMutability::Write,
    }];

    let avm = Avm::new(instructions, functions, make_host());
    let ctx = make_ctx();
    let mut state = StateOverlay::new();

    let result = avm.execute(0, vec![], &ctx, &mut state);
    assert!(result.is_err());
    match result.unwrap_err() {
        AivmError::ArithmeticOverflow => {}
        other => panic!("expected ArithmeticOverflow, got {:?}", other),
    }
}

#[test]
fn test_division_by_zero_traps() {
    let instructions = vec![
        Instruction::PushU64(100),  // 0
        Instruction::PushU64(0),     // 1
        Instruction::DivU64,         // 2
        Instruction::Ret,            // 3
    ];

    let functions = vec![FunctionEntry {
        name: "div_fn".to_string(),
        instruction_offset: 0,
        param_count: 0,
        visibility: FunctionVisibility::Public,
        mutability: FunctionMutability::Write,
    }];

    let avm = Avm::new(instructions, functions, make_host());
    let ctx = make_ctx();
    let mut state = StateOverlay::new();

    let result = avm.execute(0, vec![], &ctx, &mut state);
    assert!(result.is_err());
    match result.unwrap_err() {
        AivmError::DivisionByZero => {}
        other => panic!("expected DivisionByZero, got {:?}", other),
    }
}

#[test]
fn test_host_call_context() {
    // Call context.chain_id, should push 1266
    let instructions = vec![
        Instruction::HostCall(3),    // 0 — context.chain_id
        Instruction::Ret,            // 1
    ];

    let functions = vec![FunctionEntry {
        name: "get_chain".to_string(),
        instruction_offset: 0,
        param_count: 0,
        visibility: FunctionVisibility::Public,
        mutability: FunctionMutability::View,
    }];

    let avm = Avm::new(instructions, functions, make_host());
    let ctx = make_ctx();
    let mut state = StateOverlay::new();

    let result = avm.execute(0, vec![], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::U64(1266)));
}

#[test]
fn test_function_call() {
    // A calls a helper that doubles a value
    let instructions = vec![
        // double(x) at offset 0: LoadLocal(0), PushU64(2), MulU64, Ret
        Instruction::LoadLocal(0),    // 0
        Instruction::PushU64(2),       // 1
        Instruction::MulU64,           // 2
        Instruction::Ret,              // 3

        // main() at offset 4: PushU64(21), Call(0), Ret
        Instruction::PushU64(21),      // 4
        Instruction::Call(0),           // 5 — calls double
        Instruction::Ret,              // 6
    ];

    let functions = vec![
        FunctionEntry {
            name: "double".to_string(),
            instruction_offset: 0,
            param_count: 1,
            visibility: FunctionVisibility::Private,
            mutability: FunctionMutability::View,
        },
        FunctionEntry {
            name: "main".to_string(),
            instruction_offset: 4,
            param_count: 0,
            visibility: FunctionVisibility::Public,
            mutability: FunctionMutability::View,
        },
    ];

    let avm = Avm::new(instructions, functions, make_host());
    let ctx = make_ctx();
    let mut state = StateOverlay::new();

    let result = avm.execute(1, vec![], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::U64(42)));
}

#[test]
fn test_conditional_jump() {
    // If x > 10, return x * 2, else return x
    let instructions = vec![
        // smart(x) at offset 0
        Instruction::LoadLocal(0),    // 0: load x
        Instruction::PushU64(10),     // 1: push 10
        Instruction::Gt,               // 2: x > 10
        Instruction::JmpIf(7),         // 3: if true, jump to offset 7
        // else: return x
        Instruction::LoadLocal(0),    // 4
        Instruction::Ret,              // 5
        Instruction::Nop,              // 6 (padding to make offset 7 clean)
        // if branch: return x * 2
        Instruction::LoadLocal(0),    // 7
        Instruction::PushU64(2),       // 8
        Instruction::MulU64,           // 9
        Instruction::Ret,              // 10
    ];

    let functions = vec![FunctionEntry {
        name: "smart".to_string(),
        instruction_offset: 0,
        param_count: 1,
        visibility: FunctionVisibility::Public,
        mutability: FunctionMutability::View,
    }];

    let avm = Avm::new(instructions, functions, make_host());
    let ctx = make_ctx();
    let mut state = StateOverlay::new();

    // x = 5 → should return 5 (else branch)
    let result = avm.execute(0, vec![Value::U64(5)], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::U64(5)));

    // x = 15 → should return 30 (if branch)
    let result = avm.execute(0, vec![Value::U64(15)], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::U64(30)));
}

#[test]
fn test_operand_stack_overflow_traps_cleanly() {
    // Backlog item 13's other open resource-limit case (see the
    // call-depth/StackOverflow regression test added to synq-server's
    // estimate_gas_handler on 2026-08-23, commit 821889f): the VM's
    // *operand* stack depth cap (`stack_limit`, 1024 -- distinct from
    // `call_depth_limit`, 64, which bounds function-call nesting) had
    // zero test coverage anywhere in the workspace.
    //
    // This is deliberately a low-level VM test with hand-built
    // instructions rather than a synq-server handler test like the
    // call-depth one: the compiler's nesting-depth cap (16, item 6's DoS
    // fix in synq_compiler::parser::parse) means no real SynQ source
    // compiled through compile_to_aivm can currently leave anywhere near
    // 1024 live values on the operand stack at once -- ordinary
    // expression evaluation pops what it pushes almost immediately, and
    // recursive calls exhaust call_depth_limit (64) long before 1024
    // pushes ever accumulate. So the only way to actually exercise this
    // specific guard is to construct bytecode directly, confirming the
    // VM-level mechanism itself is sound even though it isn't reachable
    // via the compiler pipeline today.
    let mut instructions: Vec<Instruction> = (0..1100)
        .map(|_| Instruction::PushU64(1))
        .collect();
    instructions.push(Instruction::Ret);

    let functions = vec![FunctionEntry {
        name: "push_too_many".to_string(),
        instruction_offset: 0,
        param_count: 0,
        visibility: FunctionVisibility::Public,
        mutability: FunctionMutability::View,
    }];

    let avm = Avm::new(instructions, functions, make_host());
    let ctx = make_ctx();
    let mut state = StateOverlay::new();

    let result = avm.execute(0, vec![], &ctx, &mut state);
    assert!(result.is_err(), "1100 unpopped pushes must trip stack_limit (1024), not succeed");
    match result.unwrap_err() {
        AivmError::StackOverflow => {}
        other => panic!("expected StackOverflow (operand stack_limit), got {:?}", other),
    }
}
