//! Layer 1 — Structural bytecode verification.
//!
//! Validates QVM bytecode before execution:
//! - Header integrity (magic, version, length fields)
//! - Every opcode is valid
//! - Every inline operand has enough trailing bytes (no truncation)
//! - All Jump/JumpIf/Call targets land on valid instruction boundaries
//!
//! This is a single-pass static check — no stack analysis, no execution.
//! Cost: O(n) in bytecode length.

use crate::opcode::{OpCode, VMError};

/// Result of a successful verification.
#[derive(Debug, Clone)]
pub struct VerificationReport {
    pub code_size:       usize,
    pub data_size:       usize,
    pub instruction_count: usize,
    pub jump_targets:    Vec<u32>,
    pub call_targets:    Vec<u32>,
}

/// Verify a complete QVM bytecode artifact (header + code + data).
///
/// Returns `Ok(report)` if the bytecode is structurally valid, or
/// `Err(VMError::InvalidBytecode(msg))` with a human-readable explanation.
pub fn verify(bytecode: &[u8]) -> Result<VerificationReport, VMError> {
    // ── Header ───────────────────────────────────────────────────────
    if bytecode.len() < 15 {
        return Err(VMError::InvalidBytecode(
            "Bytecode too short for header (need 15 bytes)".into(),
        ));
    }

    let magic = u32::from_le_bytes([
        bytecode[0], bytecode[1], bytecode[2], bytecode[3],
    ]);
    const QVM_MAGIC: u32 = 0x51564D00; // "QVM\0"
    if magic != QVM_MAGIC {
        return Err(VMError::InvalidBytecode(format!(
            "Bad magic: 0x{:08x} (expected 0x{:08x})",
            magic, QVM_MAGIC,
        )));
    }

    let version = bytecode[4];
    if version != 1 {
        return Err(VMError::InvalidBytecode(format!(
            "Unsupported bytecode version: {} (expected 1)",
            version,
        )));
    }

    let header_length = u16::from_le_bytes([bytecode[5], bytecode[6]]) as usize;
    if header_length != 15 {
        return Err(VMError::InvalidBytecode(format!(
            "Bad header_length: {} (expected 15)",
            header_length,
        )));
    }

    let code_length = u32::from_le_bytes([
        bytecode[7], bytecode[8], bytecode[9], bytecode[10],
    ]) as usize;
    let data_length = u32::from_le_bytes([
        bytecode[11], bytecode[12], bytecode[13], bytecode[14],
    ]) as usize;

    let code_end = header_length + code_length;
    let data_end = code_end + data_length;

    if data_end > bytecode.len() {
        return Err(VMError::InvalidBytecode(format!(
            "Bytecode truncated: header claims {} code + {} data bytes (total {} needed, have {})",
            code_length, data_length, data_end, bytecode.len(),
        )));
    }

    // ── Code section walk ────────────────────────────────────────────
    let code = &bytecode[header_length..code_end];
    let mut pc = 0usize;
    let mut instruction_count = 0usize;
    let mut jump_targets: Vec<u32> = Vec::new();
    let mut call_targets: Vec<u32> = Vec::new();
    let mut instruction_starts: std::collections::HashSet<usize> = std::collections::HashSet::new();

    macro_rules! need {
        ($n:expr, $what:expr) => {
            if pc + $n > code.len() {
                let op_byte = code[pc - 1]; // opcode byte we just read
                let op_name = OpCode::try_from(op_byte)
                    .map(|o| format!("{:?}", o))
                    .unwrap_or_else(|_| format!("0x{:02x}", op_byte));
                return Err(VMError::InvalidBytecode(format!(
                    "{} at offset {}: needs {} more byte(s), only {} remaining",
                    op_name, pc - 1, $n, code.len() - pc, 
                )));
            }
        };
    }

    macro_rules! read_u32_le {
        () => {{
            need!(4, "u32 operand");
            let v = u32::from_le_bytes([
                code[pc], code[pc+1], code[pc+2], code[pc+3],
            ]);
            pc += 4;
            v
        }};
    }

    macro_rules! read_bytes {
        ($len:expr) => {{
            let len = $len as usize;
            need!(len, "inline bytes");
            pc += len;
        }};
    }

    while pc < code.len() {
        // Record this as a valid instruction boundary
        instruction_starts.insert(pc);

        let op_byte = code[pc];
        pc += 1; // consume opcode byte
        instruction_count += 1;

        let opcode = match OpCode::try_from(op_byte) {
            Ok(op) => op,
            Err(_) => {
                return Err(VMError::InvalidBytecode(format!(
                    "Unknown opcode 0x{:02x} at offset {}",
                    op_byte, pc - 1,
                )));
            }
        };

        // Consume inline operands based on opcode
        match opcode {
            // ── 4-byte inline operands ──
            OpCode::Push   => { let _ = read_u32_le!(); }
            OpCode::Jump   => { let target = read_u32_le!(); jump_targets.push(target); }
            OpCode::JumpIf => { let target = read_u32_le!(); jump_targets.push(target); }
            OpCode::Call   => { let target = read_u32_le!(); call_targets.push(target); }

            // ── Length-prefixed inline data ──
            OpCode::Revert => {
                let msg_len = read_u32_le!() as usize;
                read_bytes!(msg_len);
            }
            OpCode::RevertCode => {
                let _code = read_u32_le!();
                let msg_len = read_u32_le!() as usize;
                read_bytes!(msg_len);
            }
            OpCode::LoadImm => {
                let len = read_u32_le!() as usize;
                read_bytes!(len);
            }
            OpCode::MapNew => {
                let nlen = read_u32_le!() as usize;
                read_bytes!(nlen);
            }
            OpCode::SetNew => {
                let nlen = read_u32_le!() as usize;
                read_bytes!(nlen);
            }

            // ── Fixed-size inline data ──
            OpCode::LoadImm128 => { read_bytes!(16); }
            OpCode::LoadImm256 => { read_bytes!(32); }

            // ── No inline operands ──
            // Stack ops
            OpCode::Pop | OpCode::Dup | OpCode::Swap
            // Arithmetic
            | OpCode::Add | OpCode::Sub | OpCode::Mul | OpCode::Div | OpCode::Rem
            // Comparison
            | OpCode::Eq | OpCode::Ne | OpCode::Lt | OpCode::Le | OpCode::Gt | OpCode::Ge
            // Control flow (no operand)
            | OpCode::Return
            // Memory
            | OpCode::Load | OpCode::Store
            // Authority
            | OpCode::LoadCaller | OpCode::LoadAuthority
            | OpCode::AuthRequire | OpCode::AuthIdentity
            | OpCode::AddrEncode | OpCode::AddrDecode | OpCode::ContractAddr
            // Assets
            | OpCode::AssetCreate | OpCode::AssetTransfer | OpCode::AssetBurn
            | OpCode::AssetBalance | OpCode::AssetOwner
            // ExternCall
            | OpCode::ExternCall
            // Map ops (no inline)
            | OpCode::MapGet | OpCode::MapSet | OpCode::MapContains
            | OpCode::MapRemove | OpCode::MapLen
            // Set ops (no inline)
            | OpCode::SetAdd | OpCode::SetContains | OpCode::SetRemove | OpCode::SetLen
            // String ops
            | OpCode::StrLen | OpCode::StrConcat | OpCode::StrEq
            // Compound types
            | OpCode::TuplePack | OpCode::TupleUnpack | OpCode::TupleGet
            | OpCode::TupleSet
            | OpCode::OptionSome | OpCode::OptionNone | OpCode::OptionUnwrap
            | OpCode::ResultOk | OpCode::ResultErr | OpCode::ResultUnwrap
            | OpCode::IsOk | OpCode::IsSome
            // PQC
            | OpCode::DilithiumVerify | OpCode::KyberKeyExchange
            | OpCode::FalconVerify | OpCode::SphincsVerify | OpCode::AegisCall
            // Utility
            | OpCode::Print | OpCode::Halt => {
                // No inline operands — opcode byte only
            }
        }
    }

    // ── Validate jump/call targets ──────────────────────────────────
    for &target in jump_targets.iter().chain(call_targets.iter()) {
        let target_usize = target as usize;
        if target_usize >= code.len() {
            return Err(VMError::InvalidBytecode(format!(
                "Jump/Call target {} is out of bounds (code size {})",
                target, code.len(),
            )));
        }
        if !instruction_starts.contains(&target_usize) {
            return Err(VMError::InvalidBytecode(format!(
                "Jump/Call target {} lands mid-instruction (not on a valid instruction boundary)",
                target,
            )));
        }
    }

    // ── Validate data section starts with a valid function table ─────
    // (quick sanity: data section should be parseable — but we don't
    // duplicate the full parse_function_table here; that's already done
    // at load time. For Layer 1 we just confirm the data section is
    // non-empty if code is non-empty.)
    if code_length > 0 && data_length == 0 {
        return Err(VMError::InvalidBytecode(
            "Code section is non-empty but data section is empty (no function table)".into(),
        ));
    }

    Ok(VerificationReport {
        code_size: code_length,
        data_size: data_length,
        instruction_count,
        jump_targets,
        call_targets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header(code_len: u32, data_len: u32) -> Vec<u8> {
        let mut h = vec![];
        h.extend_from_slice(&0x51564D00u32.to_le_bytes()); // magic
        h.push(1);                                            // version
        h.extend_from_slice(&15u16.to_le_bytes());           // header_length
        h.extend_from_slice(&code_len.to_le_bytes());         // code_length
        h.extend_from_slice(&data_len.to_le_bytes());         // data_length
        h
    }

    #[test]
    fn test_valid_halt_only() {
        // Code: just Halt (0xFF)
        // Data: minimal function table (count=0)
        let code = vec![0xFF];
        let data = vec![0, 0, 0, 0]; // 0 functions
        let mut bytecode = make_header(code.len() as u32, data.len() as u32);
        bytecode.extend_from_slice(&code);
        bytecode.extend_from_slice(&data);

        let report = verify(&bytecode).unwrap();
        assert_eq!(report.instruction_count, 1);
        assert!(report.jump_targets.is_empty());
        assert!(report.call_targets.is_empty());
    }

    #[test]
    fn test_push_then_halt() {
        // Push(42) + Halt
        let mut code = vec![0x01]; // Push
        code.extend_from_slice(&42i32.to_le_bytes());
        code.push(0xFF); // Halt
        let data = vec![0, 0, 0, 0];
        let mut bytecode = make_header(code.len() as u32, data.len() as u32);
        bytecode.extend_from_slice(&code);
        bytecode.extend_from_slice(&data);

        let report = verify(&bytecode).unwrap();
        assert_eq!(report.instruction_count, 2);
    }

    #[test]
    fn test_truncated_push() {
        // Push with only 2 bytes instead of 4
        let mut code = vec![0x01, 0x2A, 0x00]; // Push + 2 bytes (need 4)
        let data = vec![0, 0, 0, 0];
        let mut bytecode = make_header(code.len() as u32, data.len() as u32);
        bytecode.extend_from_slice(&code);
        bytecode.extend_from_slice(&data);

        let err = verify(&bytecode).unwrap_err();
        assert!(matches!(err, VMError::InvalidBytecode(_)));
        assert!(err.to_string().contains("Push"));
    }

    #[test]
    fn test_unknown_opcode() {
        let code = vec![0x99, 0xFF]; // 0x99 is not a valid opcode... wait, it is SetContains
        // Use a truly invalid opcode
        let code = vec![0xFE, 0xFF]; // 0xFE is not in our opcode table
        let data = vec![0, 0, 0, 0];
        let mut bytecode = make_header(code.len() as u32, data.len() as u32);
        bytecode.extend_from_slice(&code);
        bytecode.extend_from_slice(&data);

        let err = verify(&bytecode).unwrap_err();
        assert!(matches!(err, VMError::InvalidBytecode(_)));
        assert!(err.to_string().contains("Unknown opcode 0xfe"));
    }

    #[test]
    fn test_bad_magic() {
        let mut bytecode = vec![0xDE, 0xAD, 0xBE, 0xEF]; // bad magic
        bytecode.push(1); // version
        bytecode.extend_from_slice(&15u16.to_le_bytes());
        bytecode.extend_from_slice(&0u32.to_le_bytes());
        bytecode.extend_from_slice(&0u32.to_le_bytes());

        let err = verify(&bytecode).unwrap_err();
        assert!(matches!(err, VMError::InvalidBytecode(_)));
        assert!(err.to_string().contains("Bad magic"));
    }

    #[test]
    fn test_truncated_bytecode() {
        // Header claims 100 bytes of code but only 1 is present
        let mut bytecode = make_header(100, 4);
        bytecode.push(0xFF); // only 1 byte of code
        bytecode.extend_from_slice(&[0, 0, 0, 0]);

        let err = verify(&bytecode).unwrap_err();
        assert!(matches!(err, VMError::InvalidBytecode(_)));
        assert!(err.to_string().contains("truncated"));
    }

    #[test]
    fn test_jump_to_mid_instruction_fails() {
        // Jump(1) — offset 1 is inside the Jump's own operand → must fail
        let mut code = vec![];
        code.push(0x30); code.extend_from_slice(&1u32.to_le_bytes()); // 0: Jump(1)
        code.push(0xFF); // 5: Halt
        let data = vec![0, 0, 0, 0];
        let mut bytecode = make_header(code.len() as u32, data.len() as u32);
        bytecode.extend_from_slice(&code);
        bytecode.extend_from_slice(&data);

        let err = verify(&bytecode).unwrap_err();
        assert!(matches!(err, VMError::InvalidBytecode(_)));
        assert!(err.to_string().contains("mid-instruction"));
    }

    #[test]
    fn test_jump_to_valid_target() {
        // Layout:
        // offset 0: Halt (1 byte) → this is dead code
        // offset 1: Jump(3) (5 bytes) → jump to offset 3
        // offset 6: Halt — wait this is getting confusing
        // Let me be precise:
        // offset 0: Push(0)   = 5 bytes → next at 5
        // offset 5: Jump(10)  = 5 bytes → next at 10
        // offset 10: Halt     = 1 byte
        let mut code = vec![];
        code.push(0x01); code.extend_from_slice(&0i32.to_le_bytes());   // 0: Push(0)
        code.push(0x30); code.extend_from_slice(&10u32.to_le_bytes());  // 5: Jump(10)
        code.push(0xFF);                                                  // 10: Halt
        let data = vec![0, 0, 0, 0];
        let mut bytecode = make_header(code.len() as u32, data.len() as u32);
        bytecode.extend_from_slice(&code);
        bytecode.extend_from_slice(&data);

        let report = verify(&bytecode).unwrap();
        assert_eq!(report.jump_targets, vec![10]);
    }

    #[test]
    fn test_jump_to_mid_instruction() {
        // Jump target 7 lands inside LoadImm256's 32-byte operand
        // offset 0: LoadImm256 (1+32=33 bytes) → next at 33
        // offset 33: Jump(7) (5 bytes) → next at 38
        // offset 38: Halt
        // Jump target 7 = inside the LoadImm256 operand → should fail
        let mut code = vec![];
        code.push(0x44); code.extend_from_slice(&[0u8; 32]);            // 0: LoadImm256
        code.push(0x30); code.extend_from_slice(&7u32.to_le_bytes());  // 33: Jump(7)
        code.push(0xFF);                                                 // 38: Halt
        let data = vec![0, 0, 0, 0];
        let mut bytecode = make_header(code.len() as u32, data.len() as u32);
        bytecode.extend_from_slice(&code);
        bytecode.extend_from_slice(&data);

        let err = verify(&bytecode).unwrap_err();
        assert!(matches!(err, VMError::InvalidBytecode(_)));
        assert!(err.to_string().contains("mid-instruction"));
    }

    #[test]
    fn test_jump_out_of_bounds() {
        // Jump target 999 exceeds code length
        let mut code = vec![];
        code.push(0x30); code.extend_from_slice(&999u32.to_le_bytes()); // Jump(999)
        code.push(0xFF); // Halt
        let data = vec![0, 0, 0, 0];
        let mut bytecode = make_header(code.len() as u32, data.len() as u32);
        bytecode.extend_from_slice(&code);
        bytecode.extend_from_slice(&data);

        let err = verify(&bytecode).unwrap_err();
        assert!(matches!(err, VMError::InvalidBytecode(_)));
        assert!(err.to_string().contains("out of bounds"));
    }

    #[test]
    fn test_revert_with_message() {
        // Revert(5, "hello")
        let msg = b"hello";
        let mut code = vec![0x34]; // Revert
        code.extend_from_slice(&(msg.len() as u32).to_le_bytes());
        code.extend_from_slice(msg);
        code.push(0xFF); // Halt (unreachable but valid)
        let data = vec![0, 0, 0, 0];
        let mut bytecode = make_header(code.len() as u32, data.len() as u32);
        bytecode.extend_from_slice(&code);
        bytecode.extend_from_slice(&data);

        let report = verify(&bytecode).unwrap();
        assert_eq!(report.instruction_count, 2);
    }

    #[test]
    fn test_revert_code_with_message() {
        // RevertCode(code=2, msg_len=13, "MyError::Bad")
        let msg = b"MyError::Bad";
        let mut code = vec![0x35]; // RevertCode
        code.extend_from_slice(&2u32.to_le_bytes()); // error_code
        code.extend_from_slice(&(msg.len() as u32).to_le_bytes()); // msg_len
        code.extend_from_slice(msg);
        code.push(0xFF); // Halt
        let data = vec![0, 0, 0, 0];
        let mut bytecode = make_header(code.len() as u32, data.len() as u32);
        bytecode.extend_from_slice(&code);
        bytecode.extend_from_slice(&data);

        let report = verify(&bytecode).unwrap();
        assert_eq!(report.instruction_count, 2);
    }

    #[test]
    fn test_truncated_loadimm256() {
        // LoadImm256 with only 16 bytes instead of 32
        let mut code = vec![0x44]; // LoadImm256
        code.extend_from_slice(&[0u8; 16]); // only 16 bytes (need 32)
        code.push(0xFF);
        let data = vec![0, 0, 0, 0];
        let mut bytecode = make_header(code.len() as u32, data.len() as u32);
        bytecode.extend_from_slice(&code);
        bytecode.extend_from_slice(&data);

        let err = verify(&bytecode).unwrap_err();
        assert!(matches!(err, VMError::InvalidBytecode(_)));
    }

    #[test]
    fn test_mapnew_with_name() {
        // MapNew(name_len=4, "balances")
        let name = b"test";
        let mut code = vec![0x90]; // MapNew
        code.extend_from_slice(&(name.len() as u32).to_le_bytes());
        code.extend_from_slice(name);
        code.push(0xFF);
        let data = vec![0, 0, 0, 0];
        let mut bytecode = make_header(code.len() as u32, data.len() as u32);
        bytecode.extend_from_slice(&code);
        bytecode.extend_from_slice(&data);

        let report = verify(&bytecode).unwrap();
        assert_eq!(report.instruction_count, 2);
    }

    #[test]
    fn test_empty_code_with_data() {
        // No code, just data (valid — a contract with only a function table)
        let code: Vec<u8> = vec![];
        let data = vec![0, 0, 0, 0]; // 0 functions
        let mut bytecode = make_header(0, data.len() as u32);
        bytecode.extend_from_slice(&data);

        let report = verify(&bytecode).unwrap();
        assert_eq!(report.instruction_count, 0);
    }

    #[test]
    fn test_code_without_data() {
        // Code present but data section empty → should fail
        let code = vec![0xFF]; // Halt
        let data: Vec<u8> = vec![];
        let mut bytecode = make_header(code.len() as u32, 0);
        bytecode.extend_from_slice(&code);

        let err = verify(&bytecode).unwrap_err();
        assert!(matches!(err, VMError::InvalidBytecode(_)));
        assert!(err.to_string().contains("no function table"));
    }

    #[test]
    fn test_call_to_valid_target() {
        // offset 0: Call(6) → calls offset 6
        // offset 5: Halt (dead code)
        // offset 6: Return
        // offset 7: Halt
        let mut code = vec![];
        code.push(0x32); code.extend_from_slice(&6u32.to_le_bytes()); // 0: Call(6)
        code.push(0xFF); // 5: Halt
        code.push(0x33); // 6: Return
        code.push(0xFF); // 7: Halt
        let data = vec![0, 0, 0, 0];
        let mut bytecode = make_header(code.len() as u32, data.len() as u32);
        bytecode.extend_from_slice(&code);
        bytecode.extend_from_slice(&data);

        let report = verify(&bytecode).unwrap();
        assert_eq!(report.call_targets, vec![6]);
    }
}
