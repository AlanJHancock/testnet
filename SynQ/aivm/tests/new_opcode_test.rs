//! AIVM new opcode tests — Ne, Le, Ge, ModU64, Call resolution

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

/// Test Ne opcode: 5 != 3 → true, 5 != 5 → false
#[test]
fn test_ne_opcode() {
    let instructions = vec![
        // compare(a, b) at offset 0 — returns a != b
        Instruction::LoadLocal(0),   // 0: load a
        Instruction::LoadLocal(1),   // 1: load b
        Instruction::Ne,             // 2: a != b
        Instruction::Ret,            // 3
    ];

    let functions = vec![FunctionEntry {
        name: "compare".to_string(),
        instruction_offset: 0,
        param_count: 2,
        visibility: FunctionVisibility::Public,
        mutability: FunctionMutability::View,
    }];

    let avm = Avm::new(instructions, functions, make_host());
    let ctx = make_ctx();
    let mut state = StateOverlay::new();

    // 5 != 3 → true
    let result = avm.execute(0, vec![Value::U64(5), Value::U64(3)], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::Bool(true)));

    // 5 != 5 → false
    let result = avm.execute(0, vec![Value::U64(5), Value::U64(5)], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::Bool(false)));
}

/// Test Le opcode: 3 <= 5 → true, 5 <= 3 → false, 5 <= 5 → true
#[test]
fn test_le_opcode() {
    let instructions = vec![
        Instruction::LoadLocal(0),
        Instruction::LoadLocal(1),
        Instruction::Le,
        Instruction::Ret,
    ];

    let functions = vec![FunctionEntry {
        name: "le".to_string(),
        instruction_offset: 0,
        param_count: 2,
        visibility: FunctionVisibility::Public,
        mutability: FunctionMutability::View,
    }];

    let avm = Avm::new(instructions, functions, make_host());
    let ctx = make_ctx();
    let mut state = StateOverlay::new();

    let result = avm.execute(0, vec![Value::U64(3), Value::U64(5)], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::Bool(true)));

    let result = avm.execute(0, vec![Value::U64(5), Value::U64(3)], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::Bool(false)));

    let result = avm.execute(0, vec![Value::U64(5), Value::U64(5)], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::Bool(true)));
}

/// Test Ge opcode: 5 >= 3 → true, 3 >= 5 → false, 5 >= 5 → true
#[test]
fn test_ge_opcode() {
    let instructions = vec![
        Instruction::LoadLocal(0),
        Instruction::LoadLocal(1),
        Instruction::Ge,
        Instruction::Ret,
    ];

    let functions = vec![FunctionEntry {
        name: "ge".to_string(),
        instruction_offset: 0,
        param_count: 2,
        visibility: FunctionVisibility::Public,
        mutability: FunctionMutability::View,
    }];

    let avm = Avm::new(instructions, functions, make_host());
    let ctx = make_ctx();
    let mut state = StateOverlay::new();

    let result = avm.execute(0, vec![Value::U64(5), Value::U64(3)], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::Bool(true)));

    let result = avm.execute(0, vec![Value::U64(3), Value::U64(5)], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::Bool(false)));

    let result = avm.execute(0, vec![Value::U64(5), Value::U64(5)], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::Bool(true)));
}

/// Test ModU64 opcode: 17 % 5 → 2, 10 % 3 → 1
#[test]
fn test_mod_opcode() {
    let instructions = vec![
        Instruction::LoadLocal(0),
        Instruction::LoadLocal(1),
        Instruction::ModU64,
        Instruction::Ret,
    ];

    let functions = vec![FunctionEntry {
        name: "mod".to_string(),
        instruction_offset: 0,
        param_count: 2,
        visibility: FunctionVisibility::Public,
        mutability: FunctionMutability::View,
    }];

    let avm = Avm::new(instructions, functions, make_host());
    let ctx = make_ctx();
    let mut state = StateOverlay::new();

    let result = avm.execute(0, vec![Value::U64(17), Value::U64(5)], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::U64(2)));

    let result = avm.execute(0, vec![Value::U64(10), Value::U64(3)], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::U64(1)));
}

/// Test Call instruction — function calling with proper index resolution
/// double(x) → x * 2, quad(x) → calls double(x) then calls double(result)
#[test]
fn test_call_resolution() {
    // quad(x) at offset 0:
    //   load x, Call(double), load result, Call(double), ret
    // double(x) at offset 5:
    //   load x, push 2, mul, ret

    let instructions = vec![
        // quad() at offset 0 — takes 1 param
        Instruction::LoadLocal(0),   // 0: load x
        Instruction::Call(1),         // 1: call double(x) → pushes result on stack
        Instruction::StoreLocal(1),  // 2: store intermediate result (need local for second call)
        Instruction::LoadLocal(1),    // 3: load intermediate
        Instruction::Call(1),         // 4: call double(intermediate)
        Instruction::Ret,            // 5: return

        // double() at offset 6 — takes 1 param
        Instruction::LoadLocal(0),   // 6: load x
        Instruction::PushU64(2),      // 7: push 2
        Instruction::MulU64,          // 8: x * 2
        Instruction::Ret,            // 9: return result
    ];

    let functions = vec![
        FunctionEntry {
            name: "quad".to_string(),
            instruction_offset: 0,
            param_count: 1,
            visibility: FunctionVisibility::Public,
            mutability: FunctionMutability::View,
        },
        FunctionEntry {
            name: "double".to_string(),
            instruction_offset: 6,
            param_count: 1,
            visibility: FunctionVisibility::Private,
            mutability: FunctionMutability::View,
        },
    ];

    let avm = Avm::new(instructions, functions, make_host());
    let ctx = make_ctx();
    let mut state = StateOverlay::new();

    // quad(3) → double(3)=6 → double(6)=12
    let result = avm.execute(0, vec![Value::U64(3)], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::U64(12)));

    // quad(10) → double(10)=20 → double(20)=40
    let result = avm.execute(0, vec![Value::U64(10)], &ctx, &mut state).unwrap();
    assert_eq!(result.return_value, Some(Value::U64(40)));
}

/// Test bytecode encode/decode roundtrip with new opcodes
#[test]
fn test_new_opcodes_roundtrip() {
    let instructions = vec![
        Instruction::ModU64,
        Instruction::Ne,
        Instruction::Le,
        Instruction::Ge,
        Instruction::Ret,
    ];

    let encoded = Instruction::encode_all(&instructions);
    let decoded = Instruction::decode_all(&encoded).unwrap();

    assert_eq!(instructions.len(), decoded.len());
    assert_eq!(decoded[0], Instruction::ModU64);
    assert_eq!(decoded[1], Instruction::Ne);
    assert_eq!(decoded[2], Instruction::Le);
    assert_eq!(decoded[3], Instruction::Ge);
    assert_eq!(decoded[4], Instruction::Ret);
}
