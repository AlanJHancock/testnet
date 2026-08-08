//! AIVM instruction set per synq-bytecode-spec.md
//!
//! Each instruction is opcode(1B) + fixed operands.
//! All multi-byte integers are unsigned big-endian.

use crate::errors::AivmError;

/// AIVM opcodes
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Nop = 0x00,
    PushU64 = 0x01,
    PushBytes = 0x02,
    LoadState = 0x10,
    StoreState = 0x11,
    LoadLocal = 0x12,
    StoreLocal = 0x13,
    AddU64 = 0x20,
    SubU64 = 0x21,
    MulU64 = 0x22,
    DivU64 = 0x23,
    ModU64 = 0x24,
    Eq = 0x30,
    Lt = 0x31,
    Gt = 0x32,
    Ne = 0x33,
    Le = 0x34,
    Ge = 0x35,
    Jmp = 0x40,
    JmpIf = 0x41,
    Call = 0x50,
    Ret = 0x51,
    Emit = 0x60,
    Trap = 0x70,
    HostCall = 0x80,
}

impl Opcode {
    /// Parse from byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Opcode::Nop),
            0x01 => Some(Opcode::PushU64),
            0x02 => Some(Opcode::PushBytes),
            0x10 => Some(Opcode::LoadState),
            0x11 => Some(Opcode::StoreState),
            0x12 => Some(Opcode::LoadLocal),
            0x13 => Some(Opcode::StoreLocal),
            0x20 => Some(Opcode::AddU64),
            0x21 => Some(Opcode::SubU64),
            0x22 => Some(Opcode::MulU64),
            0x23 => Some(Opcode::DivU64),
            0x24 => Some(Opcode::ModU64),
            0x30 => Some(Opcode::Eq),
            0x31 => Some(Opcode::Lt),
            0x32 => Some(Opcode::Gt),
            0x33 => Some(Opcode::Ne),
            0x34 => Some(Opcode::Le),
            0x35 => Some(Opcode::Ge),
            0x40 => Some(Opcode::Jmp),
            0x41 => Some(Opcode::JmpIf),
            0x50 => Some(Opcode::Call),
            0x51 => Some(Opcode::Ret),
            0x60 => Some(Opcode::Emit),
            0x70 => Some(Opcode::Trap),
            0x80 => Some(Opcode::HostCall),
            _ => None,
        }
    }

    /// Get the operand size for this opcode (in bytes after the opcode byte)
    pub fn operand_size(&self) -> usize {
        match self {
            Opcode::Nop => 0,
            Opcode::PushU64 => 8,
            Opcode::PushBytes => 4, // length prefix (actual data follows after)
            Opcode::LoadState => 2,
            Opcode::StoreState => 2,
            Opcode::LoadLocal => 2,
            Opcode::StoreLocal => 2,
            Opcode::AddU64 | Opcode::SubU64 | Opcode::MulU64 | Opcode::DivU64 | Opcode::ModU64 => 0,
            Opcode::Eq | Opcode::Lt | Opcode::Gt | Opcode::Ne | Opcode::Le | Opcode::Ge => 0,
            Opcode::Jmp | Opcode::JmpIf => 4,
            Opcode::Call => 4,
            Opcode::Ret => 0,
            Opcode::Emit => 2,
            Opcode::Trap => 2,
            Opcode::HostCall => 2,
        }
    }
}

/// A decoded instruction
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction {
    Nop,
    PushU64(u64),
    PushBytes(Vec<u8>),
    LoadState(u16),
    StoreState(u16),
    LoadLocal(u16),
    StoreLocal(u16),
    AddU64,
    SubU64,
    MulU64,
    DivU64,
    ModU64,
    Eq,
    Lt,
    Gt,
    Ne,
    Le,
    Ge,
    Jmp(u32),
    JmpIf(u32),
    Call(u32),
    Ret,
    Emit(u16),
    Trap(u16),
    HostCall(u16),
}

impl Instruction {
    /// Encode a single instruction to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Instruction::Nop => buf.push(Opcode::Nop as u8),
            Instruction::PushU64(v) => {
                buf.push(Opcode::PushU64 as u8);
                buf.extend_from_slice(&v.to_be_bytes());
            }
            Instruction::PushBytes(data) => {
                buf.push(Opcode::PushBytes as u8);
                buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
                buf.extend_from_slice(data);
            }
            Instruction::LoadState(idx) => {
                buf.push(Opcode::LoadState as u8);
                buf.extend_from_slice(&idx.to_be_bytes());
            }
            Instruction::StoreState(idx) => {
                buf.push(Opcode::StoreState as u8);
                buf.extend_from_slice(&idx.to_be_bytes());
            }
            Instruction::LoadLocal(idx) => {
                buf.push(Opcode::LoadLocal as u8);
                buf.extend_from_slice(&idx.to_be_bytes());
            }
            Instruction::StoreLocal(idx) => {
                buf.push(Opcode::StoreLocal as u8);
                buf.extend_from_slice(&idx.to_be_bytes());
            }
            Instruction::AddU64 => buf.push(Opcode::AddU64 as u8),
            Instruction::SubU64 => buf.push(Opcode::SubU64 as u8),
            Instruction::MulU64 => buf.push(Opcode::MulU64 as u8),
            Instruction::DivU64 => buf.push(Opcode::DivU64 as u8),
            Instruction::ModU64 => buf.push(Opcode::ModU64 as u8),
            Instruction::Eq => buf.push(Opcode::Eq as u8),
            Instruction::Lt => buf.push(Opcode::Lt as u8),
            Instruction::Gt => buf.push(Opcode::Gt as u8),
            Instruction::Ne => buf.push(Opcode::Ne as u8),
            Instruction::Le => buf.push(Opcode::Le as u8),
            Instruction::Ge => buf.push(Opcode::Ge as u8),
            Instruction::Jmp(target) => {
                buf.push(Opcode::Jmp as u8);
                buf.extend_from_slice(&target.to_be_bytes());
            }
            Instruction::JmpIf(target) => {
                buf.push(Opcode::JmpIf as u8);
                buf.extend_from_slice(&target.to_be_bytes());
            }
            Instruction::Call(func_idx) => {
                buf.push(Opcode::Call as u8);
                buf.extend_from_slice(&func_idx.to_be_bytes());
            }
            Instruction::Ret => buf.push(Opcode::Ret as u8),
            Instruction::Emit(event_idx) => {
                buf.push(Opcode::Emit as u8);
                buf.extend_from_slice(&event_idx.to_be_bytes());
            }
            Instruction::Trap(code) => {
                buf.push(Opcode::Trap as u8);
                buf.extend_from_slice(&code.to_be_bytes());
            }
            Instruction::HostCall(import_idx) => {
                buf.push(Opcode::HostCall as u8);
                buf.extend_from_slice(&import_idx.to_be_bytes());
            }
        }
        buf
    }

    /// Encode a list of instructions
    pub fn encode_all(instructions: &[Instruction]) -> Vec<u8> {
        let mut buf = Vec::new();
        for instr in instructions {
            buf.extend_from_slice(&instr.encode());
        }
        buf
    }

    /// Decode instructions from bytes
    pub fn decode_all(bytes: &[u8]) -> Result<Vec<Instruction>, AivmError> {
        let mut instructions = Vec::new();
        let mut offset = 0usize;

        while offset < bytes.len() {
            let opcode_byte = bytes[offset];
            let opcode = Opcode::from_byte(opcode_byte).ok_or_else(|| {
                AivmError::MalformedSection {
                    section_type: crate::bytecode::section_type::INSTRUCTIONS,
                    reason: format!("unknown opcode 0x{:02x} at offset {}", opcode_byte, offset),
                }
            })?;
            offset += 1;

            match opcode {
                Opcode::Nop => instructions.push(Instruction::Nop),
                Opcode::PushU64 => {
                    if offset + 8 > bytes.len() {
                        return Err(AivmError::OperandOutOfBounds { offset, needed: 8, available: bytes.len() - offset });
                    }
                    let val = u64::from_be_bytes([
                        bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3],
                        bytes[offset+4], bytes[offset+5], bytes[offset+6], bytes[offset+7],
                    ]);
                    offset += 8;
                    instructions.push(Instruction::PushU64(val));
                }
                Opcode::PushBytes => {
                    if offset + 4 > bytes.len() {
                        return Err(AivmError::OperandOutOfBounds { offset, needed: 4, available: bytes.len() - offset });
                    }
                    let len = u32::from_be_bytes([
                        bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3],
                    ]) as usize;
                    offset += 4;
                    if offset + len > bytes.len() {
                        return Err(AivmError::OperandOutOfBounds { offset, needed: len, available: bytes.len() - offset });
                    }
                    instructions.push(Instruction::PushBytes(bytes[offset..offset+len].to_vec()));
                    offset += len;
                }
                Opcode::LoadState => {
                    let idx = read_u16(bytes, &mut offset)?;
                    instructions.push(Instruction::LoadState(idx));
                }
                Opcode::StoreState => {
                    let idx = read_u16(bytes, &mut offset)?;
                    instructions.push(Instruction::StoreState(idx));
                }
                Opcode::LoadLocal => {
                    let idx = read_u16(bytes, &mut offset)?;
                    instructions.push(Instruction::LoadLocal(idx));
                }
                Opcode::StoreLocal => {
                    let idx = read_u16(bytes, &mut offset)?;
                    instructions.push(Instruction::StoreLocal(idx));
                }
                Opcode::AddU64 => instructions.push(Instruction::AddU64),
                Opcode::SubU64 => instructions.push(Instruction::SubU64),
                Opcode::MulU64 => instructions.push(Instruction::MulU64),
                Opcode::DivU64 => instructions.push(Instruction::DivU64),
                Opcode::ModU64 => instructions.push(Instruction::ModU64),
                Opcode::Eq => instructions.push(Instruction::Eq),
                Opcode::Lt => instructions.push(Instruction::Lt),
                Opcode::Gt => instructions.push(Instruction::Gt),
                Opcode::Ne => instructions.push(Instruction::Ne),
                Opcode::Le => instructions.push(Instruction::Le),
                Opcode::Ge => instructions.push(Instruction::Ge),
                Opcode::Jmp => {
                    let target = read_u32(bytes, &mut offset)?;
                    instructions.push(Instruction::Jmp(target));
                }
                Opcode::JmpIf => {
                    let target = read_u32(bytes, &mut offset)?;
                    instructions.push(Instruction::JmpIf(target));
                }
                Opcode::Call => {
                    let func_idx = read_u32(bytes, &mut offset)?;
                    instructions.push(Instruction::Call(func_idx));
                }
                Opcode::Ret => instructions.push(Instruction::Ret),
                Opcode::Emit => {
                    let event_idx = read_u16(bytes, &mut offset)?;
                    instructions.push(Instruction::Emit(event_idx));
                }
                Opcode::Trap => {
                    let code = read_u16(bytes, &mut offset)?;
                    instructions.push(Instruction::Trap(code));
                }
                Opcode::HostCall => {
                    let import_idx = read_u16(bytes, &mut offset)?;
                    instructions.push(Instruction::HostCall(import_idx));
                }
            }
        }

        Ok(instructions)
    }
}

fn read_u16(bytes: &[u8], offset: &mut usize) -> Result<u16, AivmError> {
    if *offset + 2 > bytes.len() {
        return Err(AivmError::OperandOutOfBounds { offset: *offset, needed: 2, available: bytes.len() - *offset });
    }
    let val = u16::from_be_bytes([bytes[*offset], bytes[*offset + 1]]);
    *offset += 2;
    Ok(val)
}

fn read_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, AivmError> {
    if *offset + 4 > bytes.len() {
        return Err(AivmError::OperandOutOfBounds { offset: *offset, needed: 4, available: bytes.len() - *offset });
    }
    let val = u32::from_be_bytes([bytes[*offset], bytes[*offset+1], bytes[*offset+2], bytes[*offset+3]]);
    *offset += 4;
    Ok(val)
}
