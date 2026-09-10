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
    /// Same as `Trap` but carries the actual `require(cond, "message")` /
    /// `revert Name(...)` text (2026-09-10: this is what fixes "reverted ·
    /// gas 14 · returned null" giving zero indication of WHY -- the
    /// message string was sitting right there in the SynQ source and the
    /// AST the whole time, `Statement::Require(cond, _msg)` in
    /// aivm_codegen.rs just discarded it at compile time (`_msg`) in favor
    /// of one of two generic numeric Trap codes). Length-prefixed UTF-8,
    /// same framing as `PushString`, with the numeric trap code kept
    /// immediately before it so the canonical on-chain `Receipt` (fixed
    /// spec shape, no string field) is unaffected -- this message only
    /// ever surfaces through `ExecutionResult.revert_message`, the AIVM
    /// crate's own richer (non-canonical) return type used by
    /// synq-server's dry-run JSON responses.
    TrapMsg = 0x71,
    HostCall = 0x80,
    /// Pop N values, push a single Value::Array of them (struct/array construction)
    Pack = 0x90,
    /// Pop an array value, push its element at the given index (struct field access)
    ArrayGet = 0x91,
    /// Pop [value, array] (value on top), set array[index]=value, push updated array back (struct field assignment)
    ArraySet = 0x92,
    /// Push a UTF-8 string literal, producing a real Value::String at
    /// runtime (was previously routed through PushBytes, which produces
    /// Value::Bytes -- JSON-serialized as opaque hex instead of text, so
    /// any string literal return value showed up as "0x..." garbage
    /// instead of the readable string).
    PushString = 0x93,
    /// Push a real Value::Bool literal (was previously routed through
    /// PushU64(0/1), which produces Value::U64 -- JSON-serialized as the
    /// raw number 1/0 instead of true/false, so any bool literal return
    /// value (e.g. `return true;`) showed up as "1" instead of "true").
    PushBool = 0x94,
    /// Push a real `Value::U256` literal with a fixed 32-byte big-endian
    /// operand (2026-09-09, U256 support). Added because `PushU64`'s 8-byte
    /// operand can only represent literals up to `u64::MAX` -- any SynQ
    /// source literal bigger than that (a legitimate `u256` constant, e.g.
    /// a large token-supply initializer) previously failed to COMPILE at
    /// all (`aivm_codegen.rs`'s `Literal::BigNumber` arm hard-errored
    /// "too large for u64"). The compiler now falls back to this opcode
    /// for any literal that doesn't fit `u64`; small literals still use
    /// the cheaper `PushU64` unchanged.
    PushU256 = 0x95,
    /// Pop [key, map] (key on top -- pushed after the map), look up
    /// `map_key_bytes(key)` in the map, push the found value, or -- if the
    /// map slot isn't a `Value::Map` yet (never written) or doesn't
    /// contain that key -- push a type-appropriate zero/default value
    /// instead of always `Value::U64(0)` (2026-08-25 fix: a blind
    /// `U64(0)` default meant `map<K, bool>[missing_key] == false`
    /// evaluated false, since `Eq` requires the same `Value` variant --
    /// `U64(0) != Bool(false)` -- breaking any `if (role_map[x] ==
    /// false)`-style check on a never-granted key). The operand is a
    /// compact tag selecting that default, set by the compiler from the
    /// map's declared value type (see `map_value_default_tag` in
    /// compiler/src/aivm_codegen.rs, which is the single source of truth
    /// for the tag numbering):
    ///   0 = Value::U64(0)      -- numeric types (the pre-fix behaviour;
    ///                             still correct for these, since
    ///                             `as_u64`/`as_u128` treat U64/U128
    ///                             interchangeably)
    ///   1 = Value::Bool(false)
    ///   2 = Value::String(String::new())
    ///   3 = Value::Bytes(vec![])
    ///   4 = Value::Bytes32([0u8; 32])
    ///   5 = Value::Address([0u8; 41])
    ///   6 = Value::Map(BTreeMap::new()) -- an intermediate nesting level
    ///                             in `map[k1][k2]...` (not the final
    ///                             key), where a miss means "no nested
    ///                             map here yet", not a scalar default
    /// Used for both top-level `state_map[key]` reads (map value comes
    /// from LoadState first) and each descending level of a nested
    /// `map[k1][k2]...` read (map value comes from the previous
    /// MapGetVal) -- each level carries its own tag for its own declared
    /// value type.
    MapGetVal = 0xA0,
    /// Pop [value, key, map] (value on top, pushed last), insert
    /// `map_key_bytes(key) -> value` into the map (auto-initializing an
    /// empty map if the popped value wasn't already a `Value::Map`), push
    /// the updated map back so the caller can StoreState/chain it into an
    /// outer map's MapSetVal for nested writes.
    MapSetVal = 0xA1,
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
            0x90 => Some(Opcode::Pack),
            0x91 => Some(Opcode::ArrayGet),
            0x92 => Some(Opcode::ArraySet),
            0x93 => Some(Opcode::PushString),
            0x94 => Some(Opcode::PushBool),
            0x95 => Some(Opcode::PushU256),
            0xa0 => Some(Opcode::MapGetVal),
            0xa1 => Some(Opcode::MapSetVal),
            0x71 => Some(Opcode::TrapMsg),
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
            Opcode::TrapMsg => 6, // code(u16) + length prefix(u32), same framing as PushString
            Opcode::HostCall => 2,
            Opcode::Pack => 1,
            Opcode::ArrayGet => 1,
            Opcode::ArraySet => 1,
            Opcode::PushString => 4, // length prefix, same framing as PushBytes
            Opcode::PushBool => 1,
            Opcode::PushU256 => 32,
            Opcode::MapSetVal => 0,
            // One-byte "miss default type" tag -- see MapGetVal(u8) doc on
            // the Instruction enum below.
            Opcode::MapGetVal => 1,
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
    /// See `Opcode::TrapMsg` doc comment.
    TrapMsg(u16, String),
    HostCall(u16),
    /// Pop N values (in push order), push Value::Array([v0, v1, ..., vN-1])
    Pack(u8),
    /// Pop a Value::Array, push element at index (errors if not an array or out of bounds)
    ArrayGet(u8),
    /// Pop [value, array] (value on top), set array[index]=value, push updated array back
    ArraySet(u8),
    /// Push a UTF-8 string literal as a real Value::String (see Opcode::PushString doc)
    PushString(String),
    /// Push a real boolean literal as Value::Bool (see Opcode::PushBool doc)
    PushBool(bool),
    /// Push a real Value::U256 literal (see Opcode::PushU256 doc). Operand
    /// is the literal's raw 32-byte big-endian representation.
    PushU256([u8; 32]),
    /// See Opcode::MapGetVal doc. u8 operand = miss-default type tag.
    MapGetVal(u8),
    /// See Opcode::MapSetVal doc.
    MapSetVal,
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
            Instruction::Pack(count) => {
                buf.push(Opcode::Pack as u8);
                buf.push(*count);
            }
            Instruction::ArrayGet(index) => {
                buf.push(Opcode::ArrayGet as u8);
                buf.push(*index);
            }
            Instruction::ArraySet(index) => {
                buf.push(Opcode::ArraySet as u8);
                buf.push(*index);
            }
            Instruction::PushString(s) => {
                buf.push(Opcode::PushString as u8);
                let bytes = s.as_bytes();
                buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                buf.extend_from_slice(bytes);
            }
            Instruction::TrapMsg(code, msg) => {
                buf.push(Opcode::TrapMsg as u8);
                buf.extend_from_slice(&code.to_be_bytes());
                let bytes = msg.as_bytes();
                buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                buf.extend_from_slice(bytes);
            }
            Instruction::PushBool(b) => {
                buf.push(Opcode::PushBool as u8);
                buf.push(if *b { 1 } else { 0 });
            }
            Instruction::PushU256(bytes) => {
                buf.push(Opcode::PushU256 as u8);
                buf.extend_from_slice(bytes);
            }
            Instruction::MapGetVal(tag) => {
                buf.push(Opcode::MapGetVal as u8);
                buf.push(*tag);
            }
            Instruction::MapSetVal => {
                buf.push(Opcode::MapSetVal as u8);
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
                Opcode::Pack => {
                    let count = read_u8(bytes, &mut offset)?;
                    instructions.push(Instruction::Pack(count));
                }
                Opcode::ArrayGet => {
                    let index = read_u8(bytes, &mut offset)?;
                    instructions.push(Instruction::ArrayGet(index));
                }
                Opcode::ArraySet => {
                    let index = read_u8(bytes, &mut offset)?;
                    instructions.push(Instruction::ArraySet(index));
                }
                Opcode::PushString => {
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
                    let s = String::from_utf8(bytes[offset..offset+len].to_vec()).map_err(|_| {
                        AivmError::MalformedSection {
                            section_type: crate::bytecode::section_type::INSTRUCTIONS,
                            reason: format!("PushString operand at offset {} is not valid UTF-8", offset),
                        }
                    })?;
                    instructions.push(Instruction::PushString(s));
                    offset += len;
                }
                Opcode::TrapMsg => {
                    if offset + 2 > bytes.len() {
                        return Err(AivmError::OperandOutOfBounds { offset, needed: 2, available: bytes.len() - offset });
                    }
                    let code = u16::from_be_bytes([bytes[offset], bytes[offset+1]]);
                    offset += 2;
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
                    let msg = String::from_utf8(bytes[offset..offset+len].to_vec()).map_err(|_| {
                        AivmError::MalformedSection {
                            section_type: crate::bytecode::section_type::INSTRUCTIONS,
                            reason: format!("TrapMsg operand at offset {} is not valid UTF-8", offset),
                        }
                    })?;
                    instructions.push(Instruction::TrapMsg(code, msg));
                    offset += len;
                }
                Opcode::PushBool => {
                    let b = read_u8(bytes, &mut offset)?;
                    instructions.push(Instruction::PushBool(b != 0));
                }
                Opcode::PushU256 => {
                    if offset + 32 > bytes.len() {
                        return Err(AivmError::OperandOutOfBounds { offset, needed: 32, available: bytes.len() - offset });
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes[offset..offset+32]);
                    offset += 32;
                    instructions.push(Instruction::PushU256(arr));
                }
                Opcode::MapGetVal => {
                    let tag = read_u8(bytes, &mut offset)?;
                    instructions.push(Instruction::MapGetVal(tag));
                }
                Opcode::MapSetVal => instructions.push(Instruction::MapSetVal),
            }
        }

        Ok(instructions)
    }
}

fn read_u8(bytes: &[u8], offset: &mut usize) -> Result<u8, AivmError> {
    if *offset + 1 > bytes.len() {
        return Err(AivmError::OperandOutOfBounds { offset: *offset, needed: 1, available: bytes.len() - *offset });
    }
    let val = bytes[*offset];
    *offset += 1;
    Ok(val)
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
