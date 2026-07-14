use std::collections::HashMap;
use super::opcode::{OpCode, VMError};
use pqc_shims::{dilithium, kyber, falcon, sphincs};

// Value types that can be stored on the stack
#[derive(Debug, Clone)]
pub enum Value {
    I32(i32),
    I64(i64),
    /// UInt256 values — covers up to 2^128 (full realistic token supply range).
    /// TODO: promote to U256([u8; 32]) when primitive-types crate is added.
    U128(u128),
    Bytes(Vec<u8>),
    Bool(bool),
}

impl Value {
    pub fn as_i32(&self) -> Result<i32, VMError> {
        match self {
            Value::I32(v) => Ok(*v),
            _ => Err(VMError::RuntimeError("Expected i32".to_string())),
        }
    }

    pub fn as_i64(&self) -> Result<i64, VMError> {
        match self {
            Value::I64(v) => Ok(*v),
            Value::I32(v) => Ok(*v as i64),
            _ => Err(VMError::RuntimeError("Expected i64".to_string())),
        }
    }

    /// Coerce to u128. I32 values >= 0 are promoted automatically so
    /// mixed-type arithmetic (i32 literal + UInt256 state var) just works.
    pub fn as_u128(&self) -> Result<u128, VMError> {
        match self {
            Value::U128(v) => Ok(*v),
            Value::I32(v) if *v >= 0 => Ok(*v as u128),
            _ => Err(VMError::RuntimeError("Expected UInt256 (u128)".to_string())),
        }
    }

    pub fn as_bytes(&self) -> Result<&[u8], VMError> {
        match self {
            Value::Bytes(v) => Ok(v),
            _ => Err(VMError::RuntimeError("Expected bytes".to_string())),
        }
    }

    pub fn as_bool(&self) -> Result<bool, VMError> {
        match self {
            Value::Bool(v) => Ok(*v),
            Value::I32(v)  => Ok(*v != 0),
            Value::U128(v) => Ok(*v != 0),
            _ => Err(VMError::RuntimeError("Expected bool".to_string())),
        }
    }

    /// True if this value is a U128 or can be promoted to one.
    fn is_u128_compat(&self) -> bool {
        matches!(self, Value::U128(_) | Value::I32(_))
    }
}

// Bytecode header
#[derive(Debug)]
pub struct Header {
    pub magic: u32,
    pub version: u8,
    pub header_length: u16,
    pub code_length: u32,
    pub data_length: u32,
}

impl Header {
    pub const MAGIC: u32 = 0x51564D00; // QVM\0

    pub fn parse(bytes: &[u8]) -> Result<Self, VMError> {
        if bytes.len() < 12 {
            return Err(VMError::InvalidBytecode("Header too short".to_string()));
        }

        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != Self::MAGIC {
            return Err(VMError::InvalidBytecode("Invalid magic number".to_string()));
        }

        let version = bytes[4];
        let header_length = u16::from_le_bytes([bytes[5], bytes[6]]);
        let code_length = u32::from_le_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]);
        let data_length = u32::from_le_bytes([bytes[11], bytes[12], bytes[13], bytes[14]]);

        Ok(Header {
            magic,
            version,
            header_length,
            code_length,
            data_length,
        })
    }
}

/// A single entry in the function dispatch table.
#[derive(Debug, Clone)]
pub struct FunctionEntry {
    pub name: String,
    pub address: u32,
    pub param_addresses: Vec<u32>,
    pub has_return: bool,
}

fn parse_function_table(data: &[u8]) -> Result<HashMap<String, FunctionEntry>, VMError> {
    let mut table = HashMap::new();
    if data.len() < 4 {
        return Ok(table);
    }
    let mut pos = 0usize;
    let read_u32 = |data: &[u8], pos: &mut usize| -> Result<u32, VMError> {
        if *pos + 4 > data.len() {
            return Err(VMError::InvalidBytecode("truncated function table".to_string()));
        }
        let bytes = [data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]];
        *pos += 4;
        Ok(u32::from_le_bytes(bytes))
    };

    let count = read_u32(data, &mut pos)?;
    for _ in 0..count {
        let name_len = read_u32(data, &mut pos)? as usize;
        if pos + name_len > data.len() {
            return Err(VMError::InvalidBytecode("truncated function name".to_string()));
        }
        let name = String::from_utf8_lossy(&data[pos..pos + name_len]).to_string();
        pos += name_len;

        let address = read_u32(data, &mut pos)?;
        let param_count = read_u32(data, &mut pos)? as usize;
        let mut param_addresses = Vec::with_capacity(param_count);
        for _ in 0..param_count {
            param_addresses.push(read_u32(data, &mut pos)?);
        }
        if pos >= data.len() {
            return Err(VMError::InvalidBytecode("truncated has_return flag".to_string()));
        }
        let has_return = data[pos] != 0;
        pos += 1;

        table.insert(name.clone(), FunctionEntry { name, address, param_addresses, has_return });
    }

    Ok(table)
}

// The main VM struct
pub struct QuantumVM {
    pub stack: Vec<Value>,
    memory: HashMap<usize, Value>,
    code: Vec<u8>,
    data: Vec<u8>,
    pc: usize,
    call_stack: Vec<usize>,
    halted: bool,
    functions: HashMap<String, FunctionEntry>,
}

impl QuantumVM {
    pub fn new() -> Self {
        QuantumVM {
            stack: Vec::new(),
            memory: HashMap::new(),
            code: Vec::new(),
            data: Vec::new(),
            pc: 0,
            call_stack: Vec::new(),
            halted: false,
            functions: HashMap::new(),
        }
    }

    pub fn load_bytecode(&mut self, bytecode: &[u8]) -> Result<(), VMError> {
        let header = Header::parse(bytecode)?;

        let header_end = header.header_length as usize;
        let code_end   = header_end + header.code_length as usize;
        let data_end   = code_end   + header.data_length as usize;

        if bytecode.len() < data_end {
            return Err(VMError::InvalidBytecode("Bytecode too short".to_string()));
        }

        self.code  = bytecode[header_end..code_end].to_vec();
        self.data  = bytecode[code_end..data_end].to_vec();
        self.pc    = 0;
        self.halted = false;
        self.functions = parse_function_table(&self.data)?;

        Ok(())
    }

    pub fn list_functions(&self) -> Vec<String> {
        self.functions.keys().cloned().collect()
    }

    pub fn call_function(&mut self, name: &str, args: &[Value]) -> Result<Option<Value>, VMError> {
        let entry = self
            .functions
            .get(name)
            .cloned()
            .ok_or_else(|| VMError::RuntimeError(format!("Unknown function: {}", name)))?;

        if args.len() != entry.param_addresses.len() {
            return Err(VMError::RuntimeError(format!(
                "Function '{}' expects {} argument(s), got {}",
                name, entry.param_addresses.len(), args.len()
            )));
        }

        for (addr, value) in entry.param_addresses.iter().zip(args.iter()) {
            self.memory.insert(*addr as usize, value.clone());
        }

        let sentinel = self.code.len();
        self.call_stack.push(sentinel);
        self.pc = entry.address as usize;
        self.halted = false;

        while !self.halted {
            if self.pc == sentinel {
                self.halted = true;
                break;
            }
            if self.pc >= self.code.len() {
                return Err(VMError::InvalidAddress(self.pc));
            }
            self.execute_instruction()?;
        }

        Ok(self.stack.pop())
    }

    pub fn execute(&mut self) -> Result<(), VMError> {
        while !self.halted && self.pc < self.code.len() {
            self.execute_instruction()?;
        }
        Ok(())
    }

    fn execute_instruction(&mut self) -> Result<(), VMError> {
        if self.pc >= self.code.len() {
            return Err(VMError::InvalidAddress(self.pc));
        }

        let opcode = OpCode::try_from(self.code[self.pc])?;
        self.pc += 1;

        match opcode {
            OpCode::Push => {
                let value = self.read_i32()?;
                self.push(Value::I32(value))?;
            }
            OpCode::Pop => { self.pop()?; }
            OpCode::Dup => {
                let value = self.peek()?.clone();
                self.push(value)?;
            }
            OpCode::Swap => {
                let a = self.pop()?;
                let b = self.pop()?;
                self.push(a)?;
                self.push(b)?;
            }

            // ── Arithmetic — handles I32, U128, and mixed ──────────────────
            OpCode::Add => {
                let b = self.pop()?;
                let a = self.pop()?;
                let av = match &a {
                    Value::U128(v) => *v,
                    Value::I32(v)  => {
                        if *v < 0 { return Err(VMError::RuntimeError(
                            format!("UInt256 value {} is negative; UInt256 cannot be negative", v))); }
                        *v as u128
                    }
                    _ => return Err(VMError::RuntimeError("Add: expected numeric value".to_string())),
                };
                let bv = match &b {
                    Value::U128(v) => *v,
                    Value::I32(v)  => {
                        if *v < 0 { return Err(VMError::RuntimeError(
                            format!("UInt256 value {} is negative; UInt256 cannot be negative", v))); }
                        *v as u128
                    }
                    _ => return Err(VMError::RuntimeError("Add: expected numeric value".to_string())),
                };
                let result = av.checked_add(bv)
                    .ok_or_else(|| VMError::RuntimeError("UInt256 overflow on Add".to_string()))?;
                if result <= i32::MAX as u128 {
                    self.push(Value::I32(result as i32))?;
                } else {
                    self.push(Value::U128(result))?;
                }
            }
            OpCode::Sub => {
                let b = self.pop()?;
                let a = self.pop()?;
                // All numeric values in SynQ are UInt256 — treat I32 as unsigned.
                // Promote both operands to u128, check for underflow, shrink result
                // back to I32 if it fits (avoids unnecessary U128 inflation).
                let av = match &a {
                    Value::U128(v) => *v,
                    Value::I32(v)  => {
                        if *v < 0 { return Err(VMError::RuntimeError(
                            format!("UInt256 underflow: left operand {} is negative", v))); }
                        *v as u128
                    }
                    _ => return Err(VMError::RuntimeError("Sub: expected numeric value".to_string())),
                };
                let bv = match &b {
                    Value::U128(v) => *v,
                    Value::I32(v)  => {
                        if *v < 0 { return Err(VMError::RuntimeError(
                            format!("UInt256 underflow: right operand {} is negative", v))); }
                        *v as u128
                    }
                    _ => return Err(VMError::RuntimeError("Sub: expected numeric value".to_string())),
                };
                let result = av.checked_sub(bv)
                    .ok_or_else(|| VMError::RuntimeError(
                        format!("UInt256 underflow on Sub: {} - {} would be negative", av, bv)))?;
                if result <= i32::MAX as u128 {
                    self.push(Value::I32(result as i32))?;
                } else {
                    self.push(Value::U128(result))?;
                }
            }
            OpCode::Mul => {
                let b = self.pop()?;
                let a = self.pop()?;
                if a.is_u128_compat() && b.is_u128_compat() && (matches!(a, Value::U128(_)) || matches!(b, Value::U128(_))) {
                    let av = a.as_u128()?;
                    let bv = b.as_u128()?;
                    let result = av.checked_mul(bv)
                        .ok_or_else(|| VMError::RuntimeError("UInt256 overflow on Mul".to_string()))?;
                    self.push(Value::U128(result))?;
                } else {
                    let av = a.as_i32()?;
                    let bv = b.as_i32()?;
                    self.push(Value::I32(av.wrapping_mul(bv)))?;
                }
            }
            OpCode::Div => {
                let b = self.pop()?;
                let a = self.pop()?;
                if a.is_u128_compat() && b.is_u128_compat() && (matches!(a, Value::U128(_)) || matches!(b, Value::U128(_))) {
                    let av = a.as_u128()?;
                    let bv = b.as_u128()?;
                    if bv == 0 { return Err(VMError::RuntimeError("Division by zero".to_string())); }
                    self.push(Value::U128(av / bv))?;
                } else {
                    let av = a.as_i32()?;
                    let bv = b.as_i32()?;
                    if bv == 0 { return Err(VMError::RuntimeError("Division by zero".to_string())); }
                    self.push(Value::I32(av / bv))?;
                }
            }

            // ── Comparisons — handles I32, U128, and mixed ─────────────────
            OpCode::Eq => {
                let b = self.pop()?;
                let a = self.pop()?;
                let result = match (&a, &b) {
                    (Value::U128(av), Value::U128(bv)) => av == bv,
                    (Value::U128(av), Value::I32(bv))  => *bv >= 0 && *av == (*bv as u128),
                    (Value::I32(av),  Value::U128(bv)) => *av >= 0 && (*av as u128) == *bv,
                    _ => a.as_i32()? == b.as_i32()?,
                };
                self.push(Value::Bool(result))?;
            }
            OpCode::Ne => {
                let b = self.pop()?;
                let a = self.pop()?;
                let result = match (&a, &b) {
                    (Value::U128(av), Value::U128(bv)) => av != bv,
                    (Value::U128(av), Value::I32(bv))  => *bv < 0 || *av != (*bv as u128),
                    (Value::I32(av),  Value::U128(bv)) => *av < 0 || (*av as u128) != *bv,
                    _ => a.as_i32()? != b.as_i32()?,
                };
                self.push(Value::Bool(result))?;
            }
            OpCode::Lt => {
                let b = self.pop()?;
                let a = self.pop()?;
                let result = match (&a, &b) {
                    (Value::U128(av), Value::U128(bv)) => av < bv,
                    (Value::U128(av), Value::I32(bv))  => if *bv < 0 { false } else { *av < (*bv as u128) },
                    (Value::I32(av),  Value::U128(bv))  => if *av < 0 { true  } else { (*av as u128) < *bv },
                    _ => a.as_i32()? < b.as_i32()?,
                };
                self.push(Value::Bool(result))?;
            }
            OpCode::Le => {
                let b = self.pop()?;
                let a = self.pop()?;
                let result = match (&a, &b) {
                    (Value::U128(av), Value::U128(bv)) => av <= bv,
                    (Value::U128(av), Value::I32(bv))  => if *bv < 0 { false } else { *av <= (*bv as u128) },
                    (Value::I32(av),  Value::U128(bv))  => if *av < 0 { true  } else { (*av as u128) <= *bv },
                    _ => a.as_i32()? <= b.as_i32()?,
                };
                self.push(Value::Bool(result))?;
            }
            OpCode::Gt => {
                let b = self.pop()?;
                let a = self.pop()?;
                let result = match (&a, &b) {
                    (Value::U128(av), Value::U128(bv)) => av > bv,
                    (Value::U128(av), Value::I32(bv))  => if *bv < 0 { true  } else { *av > (*bv as u128) },
                    (Value::I32(av),  Value::U128(bv))  => if *av < 0 { false } else { (*av as u128) > *bv },
                    _ => a.as_i32()? > b.as_i32()?,
                };
                self.push(Value::Bool(result))?;
            }
            OpCode::Ge => {
                let b = self.pop()?;
                let a = self.pop()?;
                let result = match (&a, &b) {
                    (Value::U128(av), Value::U128(bv)) => av >= bv,
                    (Value::U128(av), Value::I32(bv))  => if *bv < 0 { true  } else { *av >= (*bv as u128) },
                    (Value::I32(av),  Value::U128(bv))  => if *av < 0 { false } else { (*av as u128) >= *bv },
                    _ => a.as_i32()? >= b.as_i32()?,
                };
                self.push(Value::Bool(result))?;
            }

            // ── Control flow ───────────────────────────────────────────────
            OpCode::Jump => {
                let addr = self.read_u32()? as usize;
                if addr >= self.code.len() {
                    return Err(VMError::InvalidAddress(addr));
                }
                self.pc = addr;
            }
            OpCode::JumpIf => {
                let addr = self.read_u32()? as usize;
                let condition = self.pop()?.as_bool()?;
                if condition {
                    if addr >= self.code.len() {
                        return Err(VMError::InvalidAddress(addr));
                    }
                    self.pc = addr;
                }
            }
            OpCode::Call => {
                let addr = self.read_u32()? as usize;
                if addr >= self.code.len() {
                    return Err(VMError::InvalidAddress(addr));
                }
                self.call_stack.push(self.pc);
                self.pc = addr;
            }
            OpCode::Return => {
                if let Some(return_addr) = self.call_stack.pop() {
                    self.pc = return_addr;
                } else {
                    self.halted = true;
                }
            }

            // ── Memory ─────────────────────────────────────────────────────
            OpCode::Load => {
                let addr = self.pop()?.as_i32()? as usize;
                let value = self.memory.get(&addr).cloned().unwrap_or(Value::I32(0));
                self.push(value)?;
            }
            OpCode::Store => {
                let addr = self.pop()?.as_i32()? as usize;
                let value = self.pop()?;
                self.memory.insert(addr, value);
            }
            OpCode::LoadImm => {
                // Raw bytes (strings, PQC keys)
                let len = self.read_u32()? as usize;
                let bytes = self.read_bytes(len)?;
                self.push(Value::Bytes(bytes))?;
            }
            OpCode::LoadImm128 => {
                // 16 big-endian bytes → Value::U128  (UInt256 literals)
                let bytes = self.read_bytes(16)?;
                let v = u128::from_be_bytes(bytes.try_into().unwrap());
                self.push(Value::U128(v))?;
            }

            // ── PQC ────────────────────────────────────────────────────────
            OpCode::DilithiumVerify => {
                let public_key = self.pop()?.as_bytes()?.to_vec();
                let message    = self.pop()?.as_bytes()?.to_vec();
                let signature  = self.pop()?.as_bytes()?.to_vec();
                let result = dilithium::verify(&message, &signature, &public_key);
                self.push(Value::Bool(result))?;
            }
            OpCode::KyberKeyExchange => {
                let private_key = self.pop()?.as_bytes()?.to_vec();
                let ciphertext  = self.pop()?.as_bytes()?.to_vec();
                let shared_secret = kyber::decaps(&ciphertext, &private_key)
                    .map_err(VMError::RuntimeError)?;
                self.push(Value::Bytes(shared_secret))?;
            }
            OpCode::FalconVerify => {
                let public_key = self.pop()?.as_bytes()?.to_vec();
                let message    = self.pop()?.as_bytes()?.to_vec();
                let signature  = self.pop()?.as_bytes()?.to_vec();
                let result = falcon::verify(&message, &signature, &public_key);
                self.push(Value::Bool(result))?;
            }
            OpCode::SphincsVerify => {
                let public_key = self.pop()?.as_bytes()?.to_vec();
                let message    = self.pop()?.as_bytes()?.to_vec();
                let signature  = self.pop()?.as_bytes()?.to_vec();
                let result = sphincs::verify(&message, &signature, &public_key);
                self.push(Value::Bool(result))?;
            }
            OpCode::Print => {
                let value = self.pop()?;
                println!("{:?}", value);
            }
            OpCode::Halt => {
                self.halted = true;
            }
            OpCode::Revert => {
                // Followed by: 4-byte LE message length + message bytes
                let msg_len = self.read_u32()? as usize;
                let msg_bytes = self.read_bytes(msg_len)?;
                let msg = String::from_utf8_lossy(&msg_bytes).into_owned();
                return Err(VMError::Reverted(msg));
            }
        }

        Ok(())
    }

    fn push(&mut self, value: Value) -> Result<(), VMError> {
        if self.stack.len() >= 1000 {
            return Err(VMError::StackOverflow);
        }
        self.stack.push(value);
        Ok(())
    }

    fn pop(&mut self) -> Result<Value, VMError> {
        self.stack.pop().ok_or(VMError::StackUnderflow)
    }

    fn peek(&self) -> Result<&Value, VMError> {
        self.stack.last().ok_or(VMError::StackUnderflow)
    }

    fn read_i32(&mut self) -> Result<i32, VMError> {
        if self.pc + 4 > self.code.len() {
            return Err(VMError::InvalidAddress(self.pc));
        }
        let bytes = [self.code[self.pc], self.code[self.pc+1],
                     self.code[self.pc+2], self.code[self.pc+3]];
        self.pc += 4;
        Ok(i32::from_le_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, VMError> {
        if self.pc + 4 > self.code.len() {
            return Err(VMError::InvalidAddress(self.pc));
        }
        let bytes = [self.code[self.pc], self.code[self.pc+1],
                     self.code[self.pc+2], self.code[self.pc+3]];
        self.pc += 4;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>, VMError> {
        if self.pc + len > self.code.len() {
            return Err(VMError::InvalidAddress(self.pc));
        }
        let bytes = self.code[self.pc..self.pc + len].to_vec();
        self.pc += len;
        Ok(bytes)
    }
}
