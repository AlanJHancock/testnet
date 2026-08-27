//! Bytecode verification — Layer 1 (structural) + Layer 2 (stack safety).
//!
//! Layer 1: Single-pass structural validation.
//! - Header integrity (magic, version, length fields)
//! - Every opcode is valid with enough trailing bytes for inline operands
//! - All Jump/JumpIf/Call targets land on valid instruction boundaries
//!
//! Layer 2: Static stack safety analysis.
//! - Builds a control flow graph from the instruction list
//! - Tracks minimum stack depth across all paths via fixed-point dataflow
//! - Reports any instruction that would pop below zero on any reachable path
//! - Dynamic-stack-effect opcodes (TuplePack, TupleUnpack) mark depth as
//!   "unknown" — the VM's runtime checks handle those

use crate::opcode::{OpCode, VMError};
use std::collections::{HashMap, HashSet};

// ── Types ───────────────────────────────────────────────────────────────

/// Result of a successful verification.
#[derive(Debug, Clone)]
pub struct VerificationReport {
    pub code_size:         usize,
    pub data_size:         usize,
    pub instruction_count: usize,
    pub jump_targets:      Vec<u32>,
    pub call_targets:      Vec<u32>,
    pub stack_warnings:    Vec<String>,
}

/// A parsed instruction from the code walk.
#[derive(Debug, Clone)]
struct Instruction {
    offset: usize,
    opcode: OpCode,
    /// For ExternCall: the arg_count byte from inline operands.
    extern_arg_count: Option<u8>,
}

/// A basic block in the CFG.
#[derive(Debug, Clone)]
struct BasicBlock {
    start:      usize,
    successors: Vec<usize>, // start offsets of successor blocks
    /// Entry stack depth: None = unknown (after dynamic opcode or Call return).
    entry_depth: Option<i32>,
    instructions: Vec<Instruction>,
}

// ── Stack effects ──────────────────────────────────────────────────────

/// Returns (items_popped, items_pushed) for opcodes with fixed stack effects.
/// Returns None for dynamic opcodes (TuplePack, TupleUnpack) where the
/// effect depends on runtime values.
fn stack_effect(op: OpCode, extern_arg_count: Option<u8>) -> Option<(i32, i32)> {
    match op {
        // Stack ops
        OpCode::Push   => Some((0, 1)),
        OpCode::Pop    => Some((1, 0)),
        OpCode::Dup    => Some((0, 1)),  // peek + push
        OpCode::Swap   => Some((2, 2)),  // pop 2, push 2

        // Arithmetic (pop 2, push 1)
        OpCode::Add | OpCode::Sub | OpCode::Mul | OpCode::Div | OpCode::Rem => Some((2, 1)),

        // Bitwise / shift (pop 2, push 1)
        OpCode::BitAnd | OpCode::BitOr | OpCode::BitXor | OpCode::Shl | OpCode::Shr => Some((2, 1)),

        // Comparison (pop 2, push 1)
        OpCode::Eq | OpCode::Ne | OpCode::Lt | OpCode::Le | OpCode::Gt | OpCode::Ge => Some((2, 1)),

        // Control flow
        OpCode::Jump   => Some((0, 0)),
        OpCode::JumpIf => Some((1, 0)),  // pops condition
        OpCode::Call   => Some((0, 0)),  // data stack unaffected
        OpCode::Return => Some((0, 0)),
        OpCode::Revert => Some((0, 0)),
        OpCode::RevertCode => Some((0, 0)),
        OpCode::RevertCodeDyn => Some((1, 0)),  // pops message from stack

        // Memory
        OpCode::Load      => Some((1, 1)),  // pops addr, pushes value
        OpCode::Store     => Some((2, 0)),  // pops addr + value
        OpCode::LoadImm   => Some((0, 1)),
        OpCode::LoadImm128 => Some((0, 1)),
        OpCode::LoadImm256 => Some((0, 1)),

        // Authority
        OpCode::LoadCaller   => Some((0, 1)),
        OpCode::LoadCallSender => Some((0, 1)),
        OpCode::LoadAuthority => Some((0, 1)),
        OpCode::AuthRequire  => Some((2, 1)),  // pops envelope + scope_hash, pushes bool
        OpCode::AuthIdentity  => Some((1, 1)),
        OpCode::AddrEncode    => Some((1, 1)),
        OpCode::AddrDecode    => Some((1, 1)),
        OpCode::ContractAddr  => Some((3, 1)),  // pops deployer + nonce + artifact_hash

        // Assets
        OpCode::AssetCreate   => Some((2, 1)),
        OpCode::AssetTransfer => Some((2, 1)),
        OpCode::AssetBurn     => Some((1, 1)),
        OpCode::AssetBalance  => Some((1, 1)),
        OpCode::AssetOwner    => Some((1, 1)),

        // ExternCall — arg_count is in inline operands
        OpCode::ExternCall => {
            let argc = extern_arg_count.unwrap_or(0) as i32;
            Some((argc, 1))
        }

        // Maps
        OpCode::MapNew      => Some((1, 1)),
        OpCode::MapGet      => Some((2, 1)),
        OpCode::MapSet      => Some((3, 0)),
        OpCode::MapContains => Some((2, 1)),
        OpCode::MapRemove   => Some((2, 0)),
        OpCode::MapLen      => Some((1, 1)),

        // Sets
        OpCode::SetNew      => Some((1, 1)),
        OpCode::SetAdd      => Some((2, 0)),
        OpCode::SetContains => Some((2, 1)),
        OpCode::SetRemove   => Some((2, 0)),
        OpCode::SetLen      => Some((1, 1)),

        // Strings
        OpCode::StrLen    => Some((1, 1)),
        OpCode::StrConcat => Some((2, 1)),
        OpCode::StrEq     => Some((2, 1)),
        OpCode::ToString   => Some((1, 1)),  // pops value, pushes Str

        // Compound types — fixed effect
        OpCode::TupleGet  => Some((2, 1)),  // pops idx + tuple, pushes element
        OpCode::TupleSet  => Some((3, 1)),  // pops idx + value + tuple, pushes new tuple
        OpCode::OptionSome   => Some((1, 1)),
        OpCode::OptionNone   => Some((0, 1)),
        OpCode::OptionUnwrap => Some((1, 1)),
        OpCode::ResultOk     => Some((1, 1)),
        OpCode::ResultErr    => Some((1, 1)),
        OpCode::ResultUnwrap => Some((1, 1)),
        OpCode::IsOk         => Some((1, 1)),
        OpCode::IsSome       => Some((1, 1)),

        // Dynamic — effect depends on runtime values
        OpCode::TuplePack   => None,  // pops 1 (count) + count items, pushes 1
        OpCode::TupleUnpack => None,  // pops 1 (tuple), pushes N + 1

        // PQC (all pop fixed amounts, push 1)
        OpCode::DilithiumVerify  => Some((3, 1)),
        OpCode::KyberKeyExchange => Some((2, 1)),
        OpCode::FalconVerify     => Some((3, 1)),
        OpCode::SphincsVerify    => Some((3, 1)),
        OpCode::AegisCall        => Some((1, 1)),

        // Utility
        OpCode::Print => Some((1, 0)),
        OpCode::Halt  => Some((0, 0)),
    }
}

/// True if this opcode is a control-flow terminator (ends a basic block).
fn is_block_terminator(op: OpCode) -> bool {
    matches!(op,
        OpCode::Jump | OpCode::JumpIf | OpCode::Call |
        OpCode::Return | OpCode::Revert | OpCode::RevertCode | OpCode::RevertCodeDyn |
        OpCode::Halt
    )
}

// ── Layer 1: Parse instructions ─────────────────────────────────────────

/// Walk the code section and parse all instructions with their inline operands.
/// Returns the instruction list or an error.
fn parse_instructions(code: &[u8]) -> Result<Vec<Instruction>, VMError> {
    let mut instructions = Vec::new();
    let mut pc = 0usize;
    #[allow(unused_assignments)]
    let mut cur_op_name = String::new();

    macro_rules! need {
        ($n:expr) => {
            if pc + $n > code.len() {
                return Err(VMError::InvalidBytecode(format!(
                    "{} at offset {}: needs {} more byte(s), only {} remaining",
                    cur_op_name, pc - 1, $n, code.len() - pc,
                )));
            }
        };
    }
    macro_rules! read_u32_le {
        () => {{
            need!(4);
            let v = u32::from_le_bytes([code[pc], code[pc+1], code[pc+2], code[pc+3]]);
            pc += 4;
            v
        }};
    }
    macro_rules! read_bytes {
        ($len:expr) => {{ let len = $len as usize; need!(len); pc += len; }};
    }

    while pc < code.len() {
        let offset = pc;
        let op_byte = code[pc];
        pc += 1;

        let opcode = match OpCode::try_from(op_byte) {
            Ok(op) => op,
            Err(_) => return Err(VMError::InvalidBytecode(format!(
                "Unknown opcode 0x{:02x} at offset {}", op_byte, offset,
            ))),
        };
        cur_op_name = format!("{:?}", opcode);

        let mut extern_arg_count = None;

        match opcode {
            OpCode::Push   => { let _ = read_u32_le!(); }
            OpCode::Jump   => { let _ = read_u32_le!(); }
            OpCode::JumpIf => { let _ = read_u32_le!(); }
            OpCode::Call   => { let _ = read_u32_le!(); }

            OpCode::Revert => {
                let msg_len = read_u32_le!() as usize;
                read_bytes!(msg_len);
            }
            OpCode::RevertCode => {
                let _ = read_u32_le!();
                let msg_len = read_u32_le!() as usize;
                read_bytes!(msg_len);
            }
            OpCode::RevertCodeDyn => {
                let _ = read_u32_le!();  // error_code (4B LE)
            }
            OpCode::ToString => { /* no inline operands */ }
            OpCode::LoadImm => {
                let len = read_u32_le!() as usize;
                read_bytes!(len);
            }
            OpCode::LoadImm128 => { read_bytes!(16); }
            OpCode::LoadImm256 => { read_bytes!(32); }

            // ExternCall: 4B clen + clen bytes + 4B flen + flen bytes + 1B arg_count
            OpCode::ExternCall => {
                let clen = read_u32_le!() as usize;
                read_bytes!(clen);
                let flen = read_u32_le!() as usize;
                read_bytes!(flen);
                need!(1);
                extern_arg_count = Some(code[pc]);
                pc += 1;
            }

            OpCode::MapNew => {
                let nlen = read_u32_le!() as usize;
                read_bytes!(nlen);
            }
            OpCode::SetNew => {
                let nlen = read_u32_le!() as usize;
                read_bytes!(nlen);
            }

            // All other opcodes: no inline operands
            _ => {}
        }

        instructions.push(Instruction { offset, opcode, extern_arg_count });
    }

    Ok(instructions)
}

// ── Layer 1: Structural verification ────────────────────────────────────

/// Verify a complete QVM bytecode artifact (header + code + data).
pub fn verify(bytecode: &[u8]) -> Result<VerificationReport, VMError> {
    verify_with_options(bytecode, true) // Layer 2 enabled by default
}

/// Verify bytecode with optional Layer 2 stack safety analysis.
pub fn verify_with_options(bytecode: &[u8], run_stack_safety: bool) -> Result<VerificationReport, VMError> {
    // ── Header ───────────────────────────────────────────────────────
    if bytecode.len() < 15 {
        return Err(VMError::InvalidBytecode("Bytecode too short for header (need 15 bytes)".into()));
    }

    let magic = u32::from_le_bytes([bytecode[0], bytecode[1], bytecode[2], bytecode[3]]);
    const QVM_MAGIC: u32 = 0x51564D00;
    if magic != QVM_MAGIC {
        return Err(VMError::InvalidBytecode(format!(
            "Bad magic: 0x{:08x} (expected 0x{:08x})", magic, QVM_MAGIC,
        )));
    }

    let version = bytecode[4];
    if version != 1 {
        return Err(VMError::InvalidBytecode(format!(
            "Unsupported bytecode version: {} (expected 1)", version,
        )));
    }

    let header_length = u16::from_le_bytes([bytecode[5], bytecode[6]]) as usize;
    if header_length != 15 {
        return Err(VMError::InvalidBytecode(format!(
            "Bad header_length: {} (expected 15)", header_length,
        )));
    }

    let code_length = u32::from_le_bytes([bytecode[7], bytecode[8], bytecode[9], bytecode[10]]) as usize;
    let data_length = u32::from_le_bytes([bytecode[11], bytecode[12], bytecode[13], bytecode[14]]) as usize;

    let code_end = header_length + code_length;
    let data_end = code_end + data_length;

    if data_end > bytecode.len() {
        return Err(VMError::InvalidBytecode(format!(
            "Bytecode truncated: header claims {} code + {} data bytes (total {} needed, have {})",
            code_length, data_length, data_end, bytecode.len(),
        )));
    }

    // ── Parse instructions (Layer 1 walk) ────────────────────────────
    let code = &bytecode[header_length..code_end];
    let instructions = parse_instructions(code)?;

    // ── Validate jump/call targets ──────────────────────────────────
    let mut jump_targets = Vec::new();
    let mut call_targets = Vec::new();
    let instruction_starts: HashSet<usize> = instructions.iter().map(|i| i.offset).collect();

    for inst in &instructions {
        match inst.opcode {
            OpCode::Jump | OpCode::JumpIf => {
                // Target is the 4-byte LE value after the opcode
                let target_pos = inst.offset + 1;
                if target_pos + 4 <= code.len() {
                    let target = u32::from_le_bytes([
                        code[target_pos], code[target_pos+1],
                        code[target_pos+2], code[target_pos+3],
                    ]);
                    jump_targets.push(target);
                }
            }
            OpCode::Call => {
                let target_pos = inst.offset + 1;
                if target_pos + 4 <= code.len() {
                    let target = u32::from_le_bytes([
                        code[target_pos], code[target_pos+1],
                        code[target_pos+2], code[target_pos+3],
                    ]);
                    call_targets.push(target);
                }
            }
            _ => {}
        }
    }

    for &target in jump_targets.iter().chain(call_targets.iter()) {
        let t = target as usize;
        if t >= code.len() {
            return Err(VMError::InvalidBytecode(format!(
                "Jump/Call target {} is out of bounds (code size {})", target, code.len(),
            )));
        }
        if !instruction_starts.contains(&t) {
            return Err(VMError::InvalidBytecode(format!(
                "Jump/Call target {} lands mid-instruction (not on a valid instruction boundary)", target,
            )));
        }
    }

    // ── Data section sanity ─────────────────────────────────────────
    if code_length > 0 && data_length == 0 {
        return Err(VMError::InvalidBytecode(
            "Code section is non-empty but data section is empty (no function table)".into(),
        ));
    }

    let mut report = VerificationReport {
        code_size: code_length,
        data_size: data_length,
        instruction_count: instructions.len(),
        jump_targets,
        call_targets,
        stack_warnings: Vec::new(),
    };

    // ── Layer 2: Stack safety ───────────────────────────────────────
    if run_stack_safety && !instructions.is_empty() {
        report.stack_warnings = verify_stack_safety(&instructions, code);
    }

    Ok(report)
}

// ── Layer 2: Stack safety analysis ──────────────────────────────────────

/// Build the CFG using the code bytes to read jump targets.
/// (An earlier `build_cfg(instructions, code_len)` variant without access to
/// the raw code bytes was abandoned mid-implementation — it could not read
/// jump targets and ended in `todo!()`. It's been removed; this is the only
/// CFG builder now, and it's the one every caller already uses.)
fn build_cfg_from_code(instructions: &[Instruction], code: &[u8]) -> Vec<BasicBlock> {
    let code_len = code.len();

    // Collect all block start offsets
    let mut block_starts: HashSet<usize> = HashSet::new();
    if !instructions.is_empty() {
        block_starts.insert(instructions[0].offset);
    }

    for (i, inst) in instructions.iter().enumerate() {
        // After a terminator, the next instruction starts a new block
        if is_block_terminator(inst.opcode) && i + 1 < instructions.len() {
            block_starts.insert(instructions[i + 1].offset);
        }
        // Jump/JumpIf/Call targets are block starts
        match inst.opcode {
            OpCode::Jump | OpCode::JumpIf | OpCode::Call => {
                let tp = inst.offset + 1;
                if tp + 4 <= code_len {
                    let target = u32::from_le_bytes([
                        code[tp], code[tp+1], code[tp+2], code[tp+3],
                    ]) as usize;
                    block_starts.insert(target);
                }
            }
            _ => {}
        }
    }

    let mut sorted_starts: Vec<usize> = block_starts.into_iter().collect();
    sorted_starts.sort();

    // Build blocks
    let mut blocks: Vec<BasicBlock> = Vec::new();
    for (bi, &start) in sorted_starts.iter().enumerate() {
        let end = if bi + 1 < sorted_starts.len() {
            sorted_starts[bi + 1]
        } else {
            code_len
        };

        // Collect instructions in this block
        let block_insts: Vec<Instruction> = instructions.iter()
            .filter(|i| i.offset >= start && i.offset < end)
            .cloned()
            .collect();

        // Determine successors
        let mut successors = Vec::new();
        if let Some(last) = block_insts.last() {
            match last.opcode {
                OpCode::Jump => {
                    let tp = last.offset + 1;
                    if tp + 4 <= code_len {
                        let target = u32::from_le_bytes([code[tp], code[tp+1], code[tp+2], code[tp+3]]) as usize;
                        successors.push(target);
                    }
                }
                OpCode::JumpIf => {
                    // Fall-through (next block) + jump target
                    if bi + 1 < sorted_starts.len() {
                        successors.push(sorted_starts[bi + 1]);
                    }
                    let tp = last.offset + 1;
                    if tp + 4 <= code_len {
                        let target = u32::from_le_bytes([code[tp], code[tp+1], code[tp+2], code[tp+3]]) as usize;
                        successors.push(target);
                    }
                }
                OpCode::Call => {
                    // Call target + return point (next block)
                    let tp = last.offset + 1;
                    if tp + 4 <= code_len {
                        let target = u32::from_le_bytes([code[tp], code[tp+1], code[tp+2], code[tp+3]]) as usize;
                        successors.push(target);
                    }
                    if bi + 1 < sorted_starts.len() {
                        successors.push(sorted_starts[bi + 1]); // return point
                    }
                }
                OpCode::Return | OpCode::Halt | OpCode::Revert | OpCode::RevertCode | OpCode::RevertCodeDyn => {
                    // No successors — block ends execution
                }
                _ => {
                    // Fall-through to next block
                    if bi + 1 < sorted_starts.len() {
                        successors.push(sorted_starts[bi + 1]);
                    }
                }
            }
        }

        blocks.push(BasicBlock {
            start,
            successors,
            entry_depth: None,
            instructions: block_insts,
        });
    }

    blocks
}

/// Run stack safety analysis. Returns a list of warnings (underflow errors).
fn verify_stack_safety(instructions: &[Instruction], code: &[u8]) -> Vec<String> {
    let mut blocks = build_cfg_from_code(instructions, code);

    // Map: block start → index in blocks vector
    let mut block_index: HashMap<usize, usize> = HashMap::new();
    for (i, b) in blocks.iter().enumerate() {
        block_index.insert(b.start, i);
    }

    // Initialize: entry block has depth 0
    if !blocks.is_empty() {
        blocks[0].entry_depth = Some(0);
    }

    // Fixed-point iteration
    let mut changed = true;
    let mut iterations = 0;
    let max_iterations = 1000; // safety limit

    while changed && iterations < max_iterations {
        changed = false;
        iterations += 1;

        // Phase 1: compute exit depths for all blocks (read-only)
        let exit_depths: Vec<Option<i32>> = blocks.iter().map(|block| {
            match block.entry_depth {
                None => None,
                Some(mut depth) => {
                    for inst in &block.instructions {
                        match stack_effect(inst.opcode, inst.extern_arg_count) {
                            Some((pop, push)) => {
                                depth -= pop;
                                if depth < 0 { depth = 0; } // clamp
                                depth += push;
                            }
                            None => return None, // dynamic opcode → unknown
                        }
                    }
                    Some(depth)
                }
            }
        }).collect();

        // Phase 2: propagate exit depths to successors (write phase)
        for bi in 0..blocks.len() {
            let exit_depth = exit_depths[bi];
            let successors = blocks[bi].successors.clone();
            let is_call = blocks[bi].instructions.last()
                .map(|l| l.opcode == OpCode::Call).unwrap_or(false);

            for (si, &succ_start) in successors.iter().enumerate() {
                if let Some(&succ_idx) = block_index.get(&succ_start) {
                    // For Call, the return point (2nd successor) gets unknown depth
                    let new_depth = if is_call && si == 1 {
                        None // function return: unknown stack effect
                    } else {
                        match (exit_depth, blocks[succ_idx].entry_depth) {
                            (None, _) => None,
                            (Some(d), None) => Some(d),
                            (Some(d), Some(existing)) => Some(d.min(existing)),
                        }
                    };

                    if new_depth != blocks[succ_idx].entry_depth {
                        blocks[succ_idx].entry_depth = new_depth;
                        changed = true;
                    }
                }
            }
        }
    }

    // ── Check for underflows within each block ───────────────────────
    let mut warnings = Vec::new();

    for block in &blocks {
        if let Some(mut depth) = block.entry_depth {
            for inst in &block.instructions {
                match stack_effect(inst.opcode, inst.extern_arg_count) {
                    Some((pop, push)) => {
                        depth -= pop;
                        if depth < 0 {
                            warnings.push(format!(
                                "Stack underflow at offset {}: {:?} pops {} but only {} available",
                                inst.offset, inst.opcode, pop, depth + pop,
                            ));
                            depth = 0; // clamp
                        }
                        depth += push;
                    }
                    None => {
                        // Dynamic opcode — can't verify further in this block
                        break;
                    }
                }
            }
        }
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header(code_len: u32, data_len: u32) -> Vec<u8> {
        let mut h = vec![];
        h.extend_from_slice(&0x51564D00u32.to_le_bytes());
        h.push(1);
        h.extend_from_slice(&15u16.to_le_bytes());
        h.extend_from_slice(&code_len.to_le_bytes());
        h.extend_from_slice(&data_len.to_le_bytes());
        h
    }

    fn make_bytecode(code: &[u8], data: &[u8]) -> Vec<u8> {
        let mut bc = make_header(code.len() as u32, data.len() as u32);
        bc.extend_from_slice(code);
        bc.extend_from_slice(data);
        bc
    }

    // ── Layer 1 tests (unchanged) ──

    #[test]
    fn test_valid_halt_only() {
        let code = vec![0xFF];
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert_eq!(r.instruction_count, 1);
    }

    #[test]
    fn test_push_then_halt() {
        let mut code = vec![0x01];
        code.extend_from_slice(&42i32.to_le_bytes());
        code.push(0xFF);
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert_eq!(r.instruction_count, 2);
    }

    #[test]
    fn test_truncated_push() {
        let code = vec![0x01, 0x2A, 0x00];
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let err = verify(&bc).unwrap_err();
        assert!(err.to_string().contains("Push"));
    }

    #[test]
    fn test_unknown_opcode() {
        let code = vec![0xFE, 0xFF];
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let err = verify(&bc).unwrap_err();
        assert!(err.to_string().contains("Unknown opcode 0xfe"));
    }

    #[test]
    fn test_bad_magic() {
        let mut bc = vec![0xDE, 0xAD, 0xBE, 0xEF, 1];
        bc.extend_from_slice(&15u16.to_le_bytes());
        bc.extend_from_slice(&0u32.to_le_bytes());
        bc.extend_from_slice(&0u32.to_le_bytes());
        let err = verify(&bc).unwrap_err();
        assert!(err.to_string().contains("Bad magic"));
    }

    #[test]
    fn test_truncated_bytecode() {
        let mut bc = make_header(100, 4);
        bc.push(0xFF);
        bc.extend_from_slice(&[0, 0, 0, 0]);
        let err = verify(&bc).unwrap_err();
        assert!(err.to_string().contains("truncated"));
    }

    #[test]
    fn test_jump_to_valid_target() {
        let mut code = vec![];
        code.push(0x01); code.extend_from_slice(&0i32.to_le_bytes());   // 0: Push(0)
        code.push(0x30); code.extend_from_slice(&10u32.to_le_bytes());  // 5: Jump(10)
        code.push(0xFF);                                                  // 10: Halt
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert_eq!(r.jump_targets, vec![10]);
    }

    #[test]
    fn test_jump_to_mid_instruction() {
        let mut code = vec![];
        code.push(0x44); code.extend_from_slice(&[0u8; 32]);            // 0: LoadImm256
        code.push(0x30); code.extend_from_slice(&7u32.to_le_bytes());  // 33: Jump(7)
        code.push(0xFF);                                                 // 38: Halt
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let err = verify(&bc).unwrap_err();
        assert!(err.to_string().contains("mid-instruction"));
    }

    #[test]
    fn test_jump_to_mid_instruction_fails() {
        let mut code = vec![];
        code.push(0x30); code.extend_from_slice(&1u32.to_le_bytes()); // 0: Jump(1)
        code.push(0xFF); // 5: Halt
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let err = verify(&bc).unwrap_err();
        assert!(err.to_string().contains("mid-instruction"));
    }

    #[test]
    fn test_jump_out_of_bounds() {
        let mut code = vec![];
        code.push(0x30); code.extend_from_slice(&999u32.to_le_bytes());
        code.push(0xFF);
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let err = verify(&bc).unwrap_err();
        assert!(err.to_string().contains("out of bounds"));
    }

    #[test]
    fn test_revert_with_message() {
        let msg = b"hello";
        let mut code = vec![0x34];
        code.extend_from_slice(&(msg.len() as u32).to_le_bytes());
        code.extend_from_slice(msg);
        code.push(0xFF);
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert_eq!(r.instruction_count, 2);
    }

    #[test]
    fn test_revert_code_with_message() {
        let msg = b"MyError::Bad";
        let mut code = vec![0x35];
        code.extend_from_slice(&2u32.to_le_bytes());
        code.extend_from_slice(&(msg.len() as u32).to_le_bytes());
        code.extend_from_slice(msg);
        code.push(0xFF);
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert_eq!(r.instruction_count, 2);
    }

    #[test]
    fn test_truncated_loadimm256() {
        let mut code = vec![0x44];
        code.extend_from_slice(&[0u8; 16]);
        code.push(0xFF);
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let err = verify(&bc).unwrap_err();
        assert!(matches!(err, VMError::InvalidBytecode(_)));
    }

    #[test]
    fn test_mapnew_with_name() {
        let name = b"test";
        let mut code = vec![0x90];
        code.extend_from_slice(&(name.len() as u32).to_le_bytes());
        code.extend_from_slice(name);
        code.push(0xFF);
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert_eq!(r.instruction_count, 2);
    }

    #[test]
    fn test_empty_code_with_data() {
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&[], &data);
        let r = verify(&bc).unwrap();
        assert_eq!(r.instruction_count, 0);
    }

    #[test]
    fn test_code_without_data() {
        let code = vec![0xFF];
        let bc = make_bytecode(&code, &[]);
        let err = verify(&bc).unwrap_err();
        assert!(err.to_string().contains("no function table"));
    }

    #[test]
    fn test_call_to_valid_target() {
        let mut code = vec![];
        code.push(0x32); code.extend_from_slice(&6u32.to_le_bytes()); // 0: Call(6)
        code.push(0xFF); // 5: Halt
        code.push(0x33); // 6: Return
        code.push(0xFF); // 7: Halt
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert_eq!(r.call_targets, vec![6]);
    }

    // ── Layer 2 tests (stack safety) ──

    #[test]
    fn test_stack_safe_push_add_halt() {
        // Push(1), Push(2), Add, Halt — stack: 0→1→2→1→0. No underflow.
        let mut code = vec![];
        code.push(0x01); code.extend_from_slice(&1i32.to_le_bytes()); // Push(1)
        code.push(0x01); code.extend_from_slice(&2i32.to_le_bytes()); // Push(2)
        code.push(0x10); // Add
        code.push(0xFF); // Halt
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert!(r.stack_warnings.is_empty(), "Expected no warnings: {:?}", r.stack_warnings);
    }

    #[test]
    fn test_stack_underflow_add() {
        // Add with empty stack → underflow!
        let code = vec![0x10, 0xFF]; // Add, Halt
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert!(!r.stack_warnings.is_empty(), "Expected underflow warning");
        assert!(r.stack_warnings[0].contains("Add"), "Warning: {:?}", r.stack_warnings);
    }

    #[test]
    fn test_stack_underflow_store() {
        // Store needs 2 (addr + value), but stack has 0 → underflow
        let code = vec![0x41, 0xFF]; // Store, Halt
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert!(!r.stack_warnings.is_empty());
        assert!(r.stack_warnings[0].contains("Store"));
    }

    #[test]
    fn test_stack_underflow_pop() {
        // Pop with empty stack → underflow
        let code = vec![0x02, 0xFF]; // Pop, Halt
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert!(!r.stack_warnings.is_empty());
        assert!(r.stack_warnings[0].contains("Pop"));
    }

    #[test]
    fn test_stack_safe_after_push_pop() {
        // Push(1), Pop, Halt — stack: 0→1→0. Safe.
        let mut code = vec![];
        code.push(0x01); code.extend_from_slice(&1i32.to_le_bytes()); // Push(1)
        code.push(0x02); // Pop
        code.push(0xFF); // Halt
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert!(r.stack_warnings.is_empty(), "Unexpected warnings: {:?}", r.stack_warnings);
    }

    #[test]
    fn test_stack_underflow_swap() {
        // Swap needs 2, but stack has 0 → underflow
        let code = vec![0x04, 0xFF]; // Swap, Halt
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert!(!r.stack_warnings.is_empty());
        assert!(r.stack_warnings[0].contains("Swap"));
    }

    #[test]
    fn test_stack_safe_jumpif() {
        // Push(1), JumpIf(target), Halt, Halt(target)
        // JumpIf pops 1 — stack has 1 → safe
        let mut code = vec![];
        code.push(0x01); code.extend_from_slice(&1i32.to_le_bytes()); // 0: Push(1)
        code.push(0x31); code.extend_from_slice(&7u32.to_le_bytes()); // 5: JumpIf(7)
        code.push(0xFF); // 10: Halt (fall-through)
        code.push(0xFF); // 11: Halt (jump target) — wait, offsets are wrong
        // Let me recalculate:
        // 0: Push(1) = 5 bytes → next at 5
        // 5: JumpIf(10) = 5 bytes → next at 10
        // 10: Halt = 1 byte
        let mut code = vec![];
        code.push(0x01); code.extend_from_slice(&1i32.to_le_bytes()); // 0: Push(1)
        code.push(0x31); code.extend_from_slice(&10u32.to_le_bytes()); // 5: JumpIf(10)
        code.push(0xFF); // 10: Halt
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert!(r.stack_warnings.is_empty(), "Unexpected warnings: {:?}", r.stack_warnings);
    }

    #[test]
    fn test_stack_underflow_jumpif() {
        // JumpIf with empty stack → underflow (pops condition)
        let mut code = vec![];
        code.push(0x31); code.extend_from_slice(&5u32.to_le_bytes()); // 0: JumpIf(5)
        code.push(0xFF); // 5: Halt
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert!(!r.stack_warnings.is_empty());
        assert!(r.stack_warnings[0].contains("JumpIf"));
    }

    #[test]
    fn test_stack_safe_externcall() {
        // Push(42), Push(99), ExternCall("A","b",2), Halt
        // ExternCall pops 2 args, pushes 1 result → net -1
        let mut code = vec![];
        code.push(0x01); code.extend_from_slice(&42i32.to_le_bytes()); // Push(42)
        code.push(0x01); code.extend_from_slice(&99i32.to_le_bytes()); // Push(99)
        // ExternCall: clen=1 "A" flen=1 "b" arg_count=2
        code.push(0x60); // ExternCall
        code.extend_from_slice(&1u32.to_le_bytes()); // clen
        code.push(b'A'); // contract name
        code.extend_from_slice(&1u32.to_le_bytes()); // flen
        code.push(b'b'); // fn name
        code.push(2);    // arg_count
        code.push(0xFF); // Halt
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert!(r.stack_warnings.is_empty(), "Unexpected warnings: {:?}", r.stack_warnings);
    }

    #[test]
    fn test_stack_underflow_externcall() {
        // ExternCall with arg_count=2 but stack has 0 → underflow
        let mut code = vec![];
        code.push(0x60); // ExternCall
        code.extend_from_slice(&1u32.to_le_bytes()); // clen
        code.push(b'A');
        code.extend_from_slice(&1u32.to_le_bytes()); // flen
        code.push(b'b');
        code.push(2);    // arg_count=2 — but stack is empty!
        code.push(0xFF); // Halt
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert!(!r.stack_warnings.is_empty(), "Expected underflow for ExternCall");
        assert!(r.stack_warnings[0].contains("ExternCall"));
    }

    #[test]
    fn test_stack_safe_mapset() {
        // Push(0), Push(1), Push(2), MapSet — needs 3 (map_addr, key, value)
        let mut code = vec![];
        code.push(0x01); code.extend_from_slice(&0i32.to_le_bytes()); // Push(0) — map_addr
        code.push(0x01); code.extend_from_slice(&1i32.to_le_bytes()); // Push(1) — key
        code.push(0x01); code.extend_from_slice(&2i32.to_le_bytes()); // Push(2) — value
        code.push(0x92); // MapSet
        code.push(0xFF); // Halt
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert!(r.stack_warnings.is_empty(), "Unexpected warnings: {:?}", r.stack_warnings);
    }

    #[test]
    fn test_stack_underflow_mapset() {
        // MapSet needs 3 but stack has only 2 → underflow
        let mut code = vec![];
        code.push(0x01); code.extend_from_slice(&0i32.to_le_bytes()); // Push(0)
        code.push(0x01); code.extend_from_slice(&1i32.to_le_bytes()); // Push(1)
        code.push(0x92); // MapSet — needs 3, only has 2
        code.push(0xFF); // Halt
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert!(!r.stack_warnings.is_empty());
        assert!(r.stack_warnings[0].contains("MapSet"));
    }

    #[test]
    fn test_stack_underflow_print() {
        // Print with empty stack → underflow
        let code = vec![0xF0, 0xFF]; // Print, Halt
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert!(!r.stack_warnings.is_empty());
        assert!(r.stack_warnings[0].contains("Print"));
    }

    #[test]
    fn test_stack_safe_contract_addr() {
        // ContractAddr needs 3 (deployer, nonce, artifact_hash)
        // Push 3 values then ContractAddr
        let mut code = vec![];
        code.push(0x01); code.extend_from_slice(&1i32.to_le_bytes()); // deployer
        code.push(0x01); code.extend_from_slice(&2i32.to_le_bytes()); // nonce
        code.push(0x01); code.extend_from_slice(&3i32.to_le_bytes()); // artifact_hash (as I32 placeholder)
        code.push(0x56); // ContractAddr
        code.push(0xFF); // Halt
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert!(r.stack_warnings.is_empty(), "Unexpected warnings: {:?}", r.stack_warnings);
    }

    #[test]
    fn test_stack_underflow_contract_addr() {
        // ContractAddr needs 3 but stack has 1 → underflow
        let mut code = vec![];
        code.push(0x01); code.extend_from_slice(&1i32.to_le_bytes()); // only 1 value
        code.push(0x56); // ContractAddr — needs 3
        code.push(0xFF); // Halt
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert!(!r.stack_warnings.is_empty());
        assert!(r.stack_warnings[0].contains("ContractAddr"));
    }

    #[test]
    fn test_layer2_disabled() {
        // Add with empty stack — should NOT warn when Layer 2 is disabled
        let code = vec![0x10, 0xFF]; // Add, Halt
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify_with_options(&bc, false).unwrap();
        assert!(r.stack_warnings.is_empty());
    }

    #[test]
    fn test_stack_safe_dilithium_verify() {
        // DilithiumVerify pops 3 (pub_key, msg, sig), pushes 1 (bool)
        let mut code = vec![];
        code.push(0x01); code.extend_from_slice(&1i32.to_le_bytes()); // sig
        code.push(0x01); code.extend_from_slice(&2i32.to_le_bytes()); // msg
        code.push(0x01); code.extend_from_slice(&3i32.to_le_bytes()); // pub_key
        code.push(0x80); // DilithiumVerify
        code.push(0xFF); // Halt
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert!(r.stack_warnings.is_empty(), "Unexpected warnings: {:?}", r.stack_warnings);
    }

    #[test]
    fn test_stack_underflow_dilithium_verify() {
        // DilithiumVerify pops 3 but stack has 2 → underflow
        let mut code = vec![];
        code.push(0x01); code.extend_from_slice(&1i32.to_le_bytes()); // 1 value
        code.push(0x01); code.extend_from_slice(&2i32.to_le_bytes()); // 2 values
        code.push(0x80); // DilithiumVerify — needs 3
        code.push(0xFF); // Halt
        let data = vec![0, 0, 0, 0];
        let bc = make_bytecode(&code, &data);
        let r = verify(&bc).unwrap();
        assert!(!r.stack_warnings.is_empty());
        assert!(r.stack_warnings[0].contains("DilithiumVerify"));
    }
}
