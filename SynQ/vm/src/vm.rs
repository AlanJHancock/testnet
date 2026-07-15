use std::collections::HashMap;
use super::opcode::{OpCode, VMError};
use ruint::aliases::U256;
use pqc_shims::{dilithium, kyber, falcon, sphincs};

// ── PR-B constants ──────────────────────────────────────────────────────────

/// Default maximum execution steps per call_function() invocation.
/// 1,000,000 steps is generous for any real contract but terminates
/// infinite loops in bounded time (milliseconds at native speed).
pub const DEFAULT_MAX_STEPS: usize = 1_000_000;

/// Default maximum call-stack depth enforced at runtime.
/// Matches the compile-time MAX_CALL_DEPTH = 64 in compiler/src/lib.rs —
/// belt-and-suspenders: the compiler rejects obvious infinite recursion
/// statically; this catches anything that slips through at runtime.
pub const DEFAULT_MAX_CALL_DEPTH: usize = 64;

// Value types that can be stored on the stack
#[derive(Debug, Clone)]
pub enum Value {
    I32(i32),
    I64(i64),
    /// UInt256 values — covers up to 2^128 (full realistic token supply range).
    U128(u128),
    /// Full 256-bit unsigned integer (Ethereum address, real UInt256).
    U256(U256),
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
            Value::U256(v) => {
                let u128_max = U256::from(u128::MAX);
                if *v > u128_max {
                    return Err(VMError::RuntimeError(
                        "Value too large for u128 operation".to_string()));
                }
                Ok(v.wrapping_to::<u128>())
            }
            Value::I32(v) if *v >= 0 => Ok(*v as u128),
            _ => Err(VMError::RuntimeError("Expected UInt256 (u128)".to_string())),
        }
    }

    pub fn as_u256(&self) -> Result<U256, VMError> {
        match self {
            Value::U256(v) => Ok(*v),
            Value::U128(v) => Ok(U256::from(*v)),
            Value::I32(v) if *v >= 0 => Ok(U256::from(*v as u128)),
            _ => Err(VMError::RuntimeError("Expected UInt256".to_string())),
        }
    }

    pub fn as_bool(&self) -> Result<bool, VMError> {
        match self {
            Value::Bool(b) => Ok(*b),
            Value::I32(v)  => Ok(*v != 0),
            _ => Err(VMError::RuntimeError("Expected bool".to_string())),
        }
    }

    pub fn as_bytes(&self) -> Result<&[u8], VMError> {
        match self {
            Value::Bytes(b) => Ok(b),
            _ => Err(VMError::RuntimeError("Expected bytes".to_string())),
        }
    }

    /// True if this value is a large uint or can be promoted to one.
    fn is_uint_compat(&self) -> bool {
        matches!(self, Value::U256(_) | Value::U128(_) | Value::I32(_))
    }

    /// Convert to a canonical Value: shrink U256→U128→I32 when it fits.
    fn from_u256_shrink(v: U256) -> Value {
        let u128_max = U256::from(u128::MAX);
        let i32_max  = U256::from(i32::MAX as u64);
        if v <= i32_max {
            Value::I32(v.wrapping_to::<u128>() as i32)
        } else if v <= u128_max {
            Value::U128(v.wrapping_to::<u128>())
        } else {
            Value::U256(v)
        }
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

// ── PR-B Item 1: Per-call stack frame ───────────────────────────────────────
//
// Each Call opcode pushes a CallFrame onto call_stack. Return pops it and
// restores pc. The frame carries no cloned memory — the compiler already
// assigns disjoint address blocks per function (state vars at low addresses,
// each function's locals/params at a unique higher range) so there is no
// aliasing between frames. This is the simplest correct design given the
// existing compiler address layout.
//
// call_function() (the external API) uses a separate snapshot/rollback
// mechanism (PR-B Item 2) on the full memory, which subsumes any frame
// isolation concern for the top-level call.
#[derive(Debug, Clone)]
struct CallFrame {
    /// The PC to return to when this frame's Return opcode fires.
    return_pc: usize,
}

// The main VM struct
pub struct QuantumVM {
    pub stack: Vec<Value>,
    pub memory:             HashMap<usize, Value>,
    /// Maximum distinct memory addresses per session (PR-F Item 3). Default: 1024.
    pub max_memory_entries: usize,
    code: Vec<u8>,
    data: Vec<u8>,
    pc: usize,
    /// PR-B Item 1: call stack now carries full CallFrame structs, not bare PCs.
    call_stack: Vec<CallFrame>,
    halted: bool,
    functions: HashMap<String, FunctionEntry>,

    // ── PR-B Item 3: step limit ─────────────────────────────────────────────
    /// Steps executed in the current call_function() invocation.
    /// Reset to 0 at the start of each call_function() call.
    steps: usize,
    /// Hard limit on steps per invocation.  Default: DEFAULT_MAX_STEPS.
    /// Set this before calling call_function() to override.
    pub max_steps: usize,

    // ── PR-B Item 4: runtime call depth guard ──────────────────────────────
    /// Hard limit on call_stack depth enforced at the Call opcode.
    /// Default: DEFAULT_MAX_CALL_DEPTH.
    pub max_call_depth: usize,
}

impl QuantumVM {
    pub fn new() -> Self {
        QuantumVM {
            stack: Vec::new(),
            memory:             HashMap::new(),
            max_memory_entries: 1024,
            code: Vec::new(),
            data: Vec::new(),
            pc: 0,
            call_stack: Vec::new(),
            halted: false,
            functions: HashMap::new(),
            steps: 0,
            max_steps: DEFAULT_MAX_STEPS,
            max_call_depth: DEFAULT_MAX_CALL_DEPTH,
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
        self.steps  = 0;  // reset step counter on fresh load
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

        // ── PR-B Item 2: snapshot memory before any mutations ───────────────
        // On ANY error (Revert, RuntimeError, overflow, etc.) we restore the
        // snapshot so partial state changes from a failed call never persist.
        // This matches EVM atomicity: a reverted transaction leaves no trace.
        let snapshot = self.memory.clone();

        // Write params into memory
        for (addr, value) in entry.param_addresses.iter().zip(args.iter()) {
            self.memory.insert(*addr as usize, value.clone());
        }

        let sentinel = self.code.len();
        self.call_stack.push(CallFrame { return_pc: sentinel });
        self.pc = entry.address as usize;
        self.halted = false;
        // ── PR-B Item 3: reset step counter for this invocation ─────────────
        self.steps = 0;

        let result = loop {
            if self.halted {
                break Ok(());
            }
            if self.pc == sentinel {
                self.halted = true;
                break Ok(());
            }
            if self.pc >= self.code.len() {
                break Err(VMError::InvalidAddress(self.pc));
            }
            match self.execute_instruction() {
                Ok(()) => {}
                Err(e) => break Err(e),
            }
        };

        match result {
            Ok(()) => Ok(self.stack.pop()),
            Err(e) => {
                // ── PR-B Item 2: rollback on any error ──────────────────────
                self.memory = snapshot;
                // Clean up any dangling call frames from this invocation
                self.call_stack.clear();
                self.stack.clear();
                Err(e)
            }
        }
    }

    pub fn execute(&mut self) -> Result<(), VMError> {
        self.steps = 0;
        let snapshot = self.memory.clone();
        loop {
            if self.halted || self.pc >= self.code.len() {
                break;
            }
            match self.execute_instruction() {
                Ok(()) => {}
                Err(e) => {
                    self.memory = snapshot;
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    fn execute_instruction(&mut self) -> Result<(), VMError> {
        if self.pc >= self.code.len() {
            return Err(VMError::InvalidAddress(self.pc));
        }

        // ── PR-B Item 3: step counter / gas analogue ────────────────────────
        self.steps += 1;
        if self.steps > self.max_steps {
            return Err(VMError::StepLimitExceeded(self.max_steps));
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

            // ── Arithmetic — handles I32, U128, and U256 ───────────────────
            OpCode::Add => {
                let b = self.pop()?;
                let a = self.pop()?;
                if a.is_uint_compat() && b.is_uint_compat() {
                    let av = a.as_u256()?;
                    let bv = b.as_u256()?;
                    let result = av.checked_add(bv)
                        .ok_or_else(|| VMError::RuntimeError("UInt256 overflow on Add".to_string()))?;
                    self.push(Value::from_u256_shrink(result))?;
                } else {
                    return Err(VMError::RuntimeError("Add: expected numeric value".to_string()));
                }
            }
            OpCode::Sub => {
                let b = self.pop()?;
                let a = self.pop()?;
                if a.is_uint_compat() && b.is_uint_compat() {
                    let av = a.as_u256()?;
                    let bv = b.as_u256()?;
                    let result = av.checked_sub(bv)
                        .ok_or_else(|| VMError::RuntimeError(
                            format!("UInt256 underflow on Sub: {} - {} would be negative", av, bv)))?;
                    self.push(Value::from_u256_shrink(result))?;
                } else {
                    return Err(VMError::RuntimeError("Sub: expected numeric value".to_string()));
                }
            }
            OpCode::Mul => {
                let b = self.pop()?;
                let a = self.pop()?;
                if a.is_uint_compat() && b.is_uint_compat() {
                    let av = a.as_u256()?;
                    let bv = b.as_u256()?;
                    let result = av.checked_mul(bv)
                        .ok_or_else(|| VMError::RuntimeError("UInt256 overflow on Mul".to_string()))?;
                    self.push(Value::from_u256_shrink(result))?;
                } else {
                    return Err(VMError::RuntimeError("Mul: expected numeric value".to_string()));
                }
            }
            OpCode::Div => {
                let b = self.pop()?;
                let a = self.pop()?;
                if a.is_uint_compat() && b.is_uint_compat() {
                    let av = a.as_u256()?;
                    let bv = b.as_u256()?;
                    if bv == U256::ZERO {
                        return Err(VMError::RuntimeError("Division by zero".to_string()));
                    }
                    let result = av.checked_div(bv)
                        .ok_or_else(|| VMError::RuntimeError("UInt256 Div error".to_string()))?;
                    self.push(Value::from_u256_shrink(result))?;
                } else {
                    return Err(VMError::RuntimeError("Div: expected numeric value".to_string()));
                }
            }
            OpCode::Rem => {
                let b = self.pop()?;
                let a = self.pop()?;
                if a.is_uint_compat() && b.is_uint_compat() {
                    let av = a.as_u256()?;
                    let bv = b.as_u256()?;
                    if bv == U256::ZERO {
                        return Err(VMError::RuntimeError("Remainder by zero".to_string()));
                    }
                    let result = av.checked_rem(bv)
                        .ok_or_else(|| VMError::RuntimeError("UInt256 Rem error".to_string()))?;
                    self.push(Value::from_u256_shrink(result))?;
                } else {
                    return Err(VMError::RuntimeError("Rem: expected numeric value".to_string()));
                }
            }

            // ── Comparison ─────────────────────────────────────────────────
            OpCode::Eq => {
                let b = self.pop()?;
                let a = self.pop()?;
                let result = if a.is_uint_compat() && b.is_uint_compat() {
                    a.as_u256()? == b.as_u256()?
                } else {
                    matches!((&a, &b), (Value::Bool(x), Value::Bool(y)) if x == y)
                };
                self.push(Value::Bool(result))?;
            }
            OpCode::Ne => {
                let b = self.pop()?;
                let a = self.pop()?;
                let result = if a.is_uint_compat() && b.is_uint_compat() {
                    a.as_u256()? != b.as_u256()?
                } else {
                    !matches!((&a, &b), (Value::Bool(x), Value::Bool(y)) if x == y)
                };
                self.push(Value::Bool(result))?;
            }
            OpCode::Lt => {
                let b = self.pop()?;
                let a = self.pop()?;
                if a.is_uint_compat() && b.is_uint_compat() {
                    self.push(Value::Bool(a.as_u256()? < b.as_u256()?))?;
                } else {
                    return Err(VMError::RuntimeError("Lt: expected numeric value".to_string()));
                }
            }
            OpCode::Le => {
                let b = self.pop()?;
                let a = self.pop()?;
                if a.is_uint_compat() && b.is_uint_compat() {
                    self.push(Value::Bool(a.as_u256()? <= b.as_u256()?))?;
                } else {
                    return Err(VMError::RuntimeError("Le: expected numeric value".to_string()));
                }
            }
            OpCode::Gt => {
                let b = self.pop()?;
                let a = self.pop()?;
                if a.is_uint_compat() && b.is_uint_compat() {
                    self.push(Value::Bool(a.as_u256()? > b.as_u256()?))?;
                } else {
                    return Err(VMError::RuntimeError("Gt: expected numeric value".to_string()));
                }
            }
            OpCode::Ge => {
                let b = self.pop()?;
                let a = self.pop()?;
                if a.is_uint_compat() && b.is_uint_compat() {
                    self.push(Value::Bool(a.as_u256()? >= b.as_u256()?))?;
                } else {
                    return Err(VMError::RuntimeError("Ge: expected numeric value".to_string()));
                }
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
                // ── PR-B Item 4: runtime call depth guard ───────────────────
                // Belt-and-suspenders over the compile-time MAX_CALL_DEPTH = 64.
                // The compiler rejects obvious infinite recursion statically;
                // this catches anything that slips through at runtime.
                if self.call_stack.len() >= self.max_call_depth {
                    return Err(VMError::RuntimeError(format!(
                        "call depth limit exceeded ({} frames): possible unbounded recursion",
                        self.max_call_depth
                    )));
                }
                // ── PR-B Item 1: push a proper CallFrame ────────────────────
                self.call_stack.push(CallFrame { return_pc: self.pc });
                self.pc = addr;
            }
            OpCode::Return => {
                // ── PR-B Item 1: pop the CallFrame, restore pc ──────────────
                if let Some(frame) = self.call_stack.pop() {
                    self.pc = frame.return_pc;
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
                let addr  = self.pop()?.as_i32()? as usize;
                let value = self.pop()?;
                // PR-F Item 3: enforce per-session memory cap
                if !self.memory.contains_key(&addr) && self.memory.len() >= self.max_memory_entries {
                    return Err(VMError::RuntimeError(format!(
                        "memory cap exceeded: max {} distinct addresses per session",
                        self.max_memory_entries
                    )));
                }
                self.memory.insert(addr, value);
            }
            OpCode::LoadImm => {
                // Raw bytes (strings, PQC keys)
                let len = self.read_u32()? as usize;
                let bytes = self.read_bytes(len)?;
                self.push(Value::Bytes(bytes))?;
            }
            OpCode::LoadImm128 => {
                // 16 big-endian bytes → Value::U128  (UInt256 literals ≤ 2^128)
                let bytes = self.read_bytes(16)?;
                let v = u128::from_be_bytes(bytes.try_into().unwrap());
                self.push(Value::U128(v))?;
            }
            OpCode::LoadImm256 => {
                // 32 big-endian bytes → Value::U256  (full Ethereum address / real UInt256)
                let bytes = self.read_bytes(32)?;
                let v = U256::from_be_bytes::<32>(bytes.try_into().unwrap());
                self.push(Value::from_u256_shrink(v))?;
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
                // Rollback is handled by the call_function() wrapper (PR-B Item 2).
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
