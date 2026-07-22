use std::collections::{HashMap, BTreeMap, BTreeSet};
use super::opcode::{OpCode, VMError};
use ruint::aliases::U256;
#[cfg(feature = "native")]
#[cfg(feature = "native")]
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
    /// Map<key_bytes, Value> — heap-allocated per session address slot.
    Map(BTreeMap<Vec<u8>, Value>),
    /// Set<value_bytes> — heap-allocated per session address slot.
    Set(BTreeSet<Vec<u8>>),
    /// UTF-8 string — length-prefixed (4-byte LE) in bytecode.
    Str(String),
    /// Ordered tuple of values.
    Tuple(Vec<Value>),
    /// Option<Value> — None or Some(Value).
    SynqOption(Option<Box<Value>>),
    /// Result<Value> — bool true=Ok, false=Err.
    SynqResult(bool, Box<Value>),
}

/// Coerce any Value to a stable byte key for map/set indexing.
fn hex_encode(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }

fn value_to_key(v: &Value) -> Result<Vec<u8>, VMError> {
    // All key types normalised to 32-byte big-endian so that
    // I32(0xDEAD) and U256(0xDEAD) produce the same map key.
    let mut key = [0u8; 32];
    match v {
        Value::I32(n)  => {
            // Sign-extend to i64, then treat as unsigned 32-byte BE
            let u = *n as u64;
            key[24..].copy_from_slice(&u.to_be_bytes());
        }
        Value::I64(n)  => {
            let u = *n as u64;
            key[24..].copy_from_slice(&u.to_be_bytes());
        }
        Value::U128(n) => {
            key[16..].copy_from_slice(&n.to_be_bytes());
        }
        Value::U256(n) => {
            let b = n.to_be_bytes::<32>();
            key.copy_from_slice(&b);
        }
        Value::Bytes(b) => {
            // Right-align bytes into 32-byte buffer (same as U256 BE)
            if b.len() >= 32 {
                key.copy_from_slice(&b[b.len()-32..]);
            } else {
                key[32-b.len()..].copy_from_slice(b);
            }
        }
        Value::Bool(b) => { key[31] = *b as u8; }
        Value::Str(s) => {
            let b = s.as_bytes();
            if b.len() <= 32 { key[32-b.len()..].copy_from_slice(b); }
            else { key.copy_from_slice(&b[b.len()-32..]); }
        }
        Value::Map(_)        => return Err(VMError::RuntimeError("Map cannot be used as a map key".into())),
        Value::Set(_)        => return Err(VMError::RuntimeError("Set cannot be used as a map key".into())),
        Value::Tuple(_)      => return Err(VMError::RuntimeError("Tuple cannot be used as a map key".into())),
        Value::SynqOption(_) => return Err(VMError::RuntimeError("Option cannot be used as a map key".into())),
        Value::SynqResult(..)=> return Err(VMError::RuntimeError("Result cannot be used as a map key".into())),
    }
    Ok(key.to_vec())
}

impl Value {
    pub fn as_i32(&self) -> Result<i32, VMError> {
        match self {
            Value::I32(v) => Ok(*v),
            _ => Err(VMError::RuntimeError("Expected i32".to_string())),
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
            Value::I64(v) if *v >= 0 => Ok(U256::from(*v as u128)),
            Value::Bool(b) => Ok(if *b { U256::from(1u32) } else { U256::ZERO }),
            Value::Bytes(b) if b.len() <= 32 => {
                let mut arr = [0u8; 32];
                arr[32 - b.len()..].copy_from_slice(b);
                Ok(U256::from_be_bytes::<32>(arr))
            }
            Value::Str(s) => {
                let b = s.as_bytes();
                if b.len() <= 32 {
                    let mut arr = [0u8; 32];
                    arr[32 - b.len()..].copy_from_slice(b);
                    Ok(U256::from_be_bytes::<32>(arr))
                } else {
                    Err(VMError::RuntimeError("String too long for U256 coercion".to_string()))
                }
            }
            _ => Err(VMError::RuntimeError(format!("Cannot coerce {:?} to UInt256", self))),
        }
    }

    fn as_i64(&self) -> Result<i64, VMError> {
        match self {
            Value::I32(v)  => Ok(*v as i64),
            Value::I64(v)  => Ok(*v),
            Value::Bool(b) => Ok(if *b { 1 } else { 0 }),
            Value::U128(v) if *v <= i64::MAX as u128 => Ok(*v as i64),
            _ => Err(VMError::RuntimeError(format!("Cannot coerce {:?} to i64", self))),
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
            Value::Str(s)   => Ok(s.as_bytes()),
            _ => Err(VMError::RuntimeError(format!("Expected bytes, got {:?}", std::mem::discriminant(self)))),
        }
    }

    /// True if this value is a large uint or can be promoted to one.
    fn is_uint_compat(&self) -> bool {
        matches!(self, Value::U256(_) | Value::U128(_) | Value::I32(_) | Value::Bool(_) | Value::I64(_))
    }
    fn is_signed(&self) -> bool { matches!(self, Value::I32(_) | Value::I64(_)) }
    fn as_i128(&self) -> Result<i128, VMError> {
        match self {
            Value::I32(v)  => Ok(*v as i128),
            Value::I64(v)  => Ok(*v as i128),
            Value::Bool(b) => Ok(if *b { 1 } else { 0 }),
            Value::U128(v) if *v <= i128::MAX as u128 => Ok(*v as i128),
            Value::U256(v) => {
                let mx = U256::from(i128::MAX as u128);
                if *v <= mx { Ok(v.wrapping_to::<u128>() as i128) }
                else { Err(VMError::RuntimeError(format!("Value {} too large for signed arithmetic", v))) }
            }
            _ => Err(VMError::RuntimeError(format!("Cannot coerce {:?} to i128", self))),
        }
    }
    fn from_i128_shrink(v: i128) -> Value {
        if v >= i32::MIN as i128 && v <= i32::MAX as i128 { Value::I32(v as i32) }
        else if v >= i64::MIN as i128 && v <= i64::MAX as i128 { Value::I64(v as i64) }
        else if v >= 0 { Value::U128(v as u128) }
        else { Value::I64(v as i64) }
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
    pub param_is_signed: Vec<bool>,
    pub has_return: bool,
    pub requires_caller: bool,
    pub capabilities: Vec<String>,
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
        let name = String::from_utf8(data[pos..pos + name_len].to_vec())
            .map_err(|_| VMError::InvalidBytecode("function name is not valid UTF-8".to_string()))?;
        pos += name_len;

        let address = read_u32(data, &mut pos)?;
        let param_count = read_u32(data, &mut pos)? as usize;
        let mut param_addresses = Vec::with_capacity(param_count);
        for _ in 0..param_count {
            param_addresses.push(read_u32(data, &mut pos)?);
        }
        let mut param_is_signed: Vec<bool> = Vec::with_capacity(param_count);
        for _ in 0..param_count {
            if pos < data.len() { param_is_signed.push(data[pos] != 0); pos += 1; }
            else { param_is_signed.push(false); }
        }
        if pos >= data.len() {
            return Err(VMError::InvalidBytecode("truncated has_return flag".to_string()));
        }
        let has_return = data[pos] != 0;
        pos += 1;

        // Extended fields: requires_caller (1 byte) + cap_count (4 bytes LE) + cap strings
        let requires_caller = if pos < data.len() { data[pos] != 0 } else { false };
        if pos < data.len() { pos += 1; }

        let cap_count = if pos + 4 <= data.len() {
            let n = read_u32(data, &mut pos)? as usize;
            n
        } else {
            0
        };
        let mut capabilities = Vec::with_capacity(cap_count);
        for _ in 0..cap_count {
            let cap_len = read_u32(data, &mut pos)? as usize;
            if pos + cap_len > data.len() {
                return Err(VMError::InvalidBytecode("truncated capability name".to_string()));
            }
            let cap_name = String::from_utf8(data[pos..pos + cap_len].to_vec())
            .map_err(|_| VMError::InvalidBytecode("capability name is not valid UTF-8".to_string()))?;
            pos += cap_len;
            capabilities.push(cap_name);
        }

        table.insert(name.clone(), FunctionEntry {
            name, address, param_addresses, param_is_signed, has_return, requires_caller, capabilities
        });
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
    pub extern_call_handler: Option<std::sync::Arc<dyn Fn(&str, &str, &[Value]) -> Result<Option<Value>, VMError> + Send + Sync>>,
    pub call_context: CallContext,

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
    /// Captured Print/emit output — drained by caller after call_function().
    pub print_log: Vec<String>,

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

/// Format a VM Value for Print/emit output.
fn vm_value_display(v: &Value) -> String {
    match v {
        Value::I32(n)   => n.to_string(),
        Value::I64(n)   => n.to_string(),
        Value::U128(n)  => n.to_string(),
        Value::U256(n)  => n.to_string(),
        Value::Bool(b)  => b.to_string(),
        Value::Bytes(b) => String::from_utf8(b.clone())
                              .unwrap_or_else(|_| format!("0x{}", b.iter().map(|x| format!("{:02x}", x)).collect::<String>())),
        Value::Str(s)   => s.clone(),
        _               => "[complex]".to_string(),
    }
}

impl QuantumVM {
    pub fn new() -> Self {
        QuantumVM {
            extern_call_handler: None,
            call_context: CallContext::anonymous(),

            stack: Vec::new(),
            memory:             HashMap::new(),
            max_memory_entries: 4096,
            code: Vec::new(),
            data: Vec::new(),
            pc: 0,
            call_stack: Vec::new(),
            halted: false,
            functions: HashMap::new(),
            print_log: Vec::new(),
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

        // Clear any residual stack state from a previous call so each
        // top-level call_function invocation starts with a clean stack.
        self.stack.clear();
        self.call_stack.clear();
        self.halted = false;
        self.print_log.clear();

        // Write params into memory — coerce to declared signedness
        for ((addr, value), is_signed) in entry.param_addresses.iter()
            .zip(args.iter())
            .zip(entry.param_is_signed.iter().chain(std::iter::repeat(&false)))
        {
            let coerced = if *is_signed {
                match value {
                    Value::I32(_) | Value::I64(_) => value.clone(),
                    Value::U128(v) if *v <= i32::MAX as u128 => Value::I32(*v as i32),
                    Value::U128(v) if *v <= i64::MAX as u128 => Value::I64(*v as i64),
                    _ => value.clone(),
                }
            } else {
                match value {
                    Value::I32(v) if *v >= 0 => Value::U128(*v as u128),
                    Value::I64(v) if *v >= 0 => Value::U128(*v as u128),
                    _ => value.clone(),
                }
            };
            self.memory.insert(*addr as usize, coerced);
        }

        let sentinel = self.code.len();
        self.call_stack.push(CallFrame { return_pc: sentinel });
        self.pc = entry.address as usize;
        self.halted = false;
        // ── PR-B Item 3: reset step counter for this invocation ─────────────
        self.steps = 0;
        eprintln!("[VM] call_function name={:?} pc={} code_len={} memory_slots={}",
            name, self.pc, self.code.len(), self.memory.len());
        // Dump 200 bytes starting at entry PC
        let dump_end = (self.pc + 200).min(self.code.len());
        if self.pc < self.code.len() {
            let chunk = &self.code[self.pc..dump_end];
            let hex: String = chunk.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
            eprintln!("[VM] bytecode[{}..{}] = {}", self.pc, dump_end, hex);
        }

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
                let b = self.pop()?; let a = self.pop()?;
                if a.is_signed() && b.is_signed() {
                    let av=a.as_i128()?;let bv=b.as_i128()?;let r=av.checked_add(bv).ok_or_else(||VMError::RuntimeError(format!("Signed overflow on Add: {}+{}",av,bv)))?;self.push(Value::from_i128_shrink(r))?;
                } else if a.is_uint_compat() && b.is_uint_compat() {
                    let av=a.as_u256()?;let bv=b.as_u256()?;let r=av.checked_add(bv).ok_or_else(||VMError::RuntimeError(format!("UInt256 overflow on Add: {}+{}",av,bv)))?;self.push(Value::from_u256_shrink(r))?;
                } else { return Err(VMError::RuntimeError("Add: expected numeric".to_string())); }
            }
            OpCode::Sub => {
                let b = self.pop()?; let a = self.pop()?;
                if a.is_signed() && b.is_signed() {
                    let av=a.as_i128()?;let bv=b.as_i128()?;let r=av.checked_sub(bv).ok_or_else(||VMError::RuntimeError(format!("Signed overflow on Sub: {}-{}",av,bv)))?;self.push(Value::from_i128_shrink(r))?;
                } else if a.is_uint_compat() && b.is_uint_compat() {
                    let av=a.as_u256()?;let bv=b.as_u256()?;let r=av.checked_sub(bv).ok_or_else(||VMError::RuntimeError(format!("UInt256 underflow on Sub: {}-{} would be negative",av,bv)))?;self.push(Value::from_u256_shrink(r))?;
                } else { return Err(VMError::RuntimeError("Sub: expected numeric".to_string())); }
            }
            OpCode::Mul => {
                let b = self.pop()?; let a = self.pop()?;
                if a.is_signed() && b.is_signed() {
                    let av=a.as_i128()?;let bv=b.as_i128()?;let r=av.checked_mul(bv).ok_or_else(||VMError::RuntimeError(format!("Signed overflow on Mul: {}×{}",av,bv)))?;self.push(Value::from_i128_shrink(r))?;
                } else if a.is_uint_compat() && b.is_uint_compat() {
                    let av=a.as_u256()?;let bv=b.as_u256()?;let r=av.checked_mul(bv).ok_or_else(||VMError::RuntimeError(format!("UInt256 overflow on Mul: {}×{}",av,bv)))?;self.push(Value::from_u256_shrink(r))?;
                } else { return Err(VMError::RuntimeError("Mul: expected numeric".to_string())); }
            }
            OpCode::Div => {
                let b = self.pop()?; let a = self.pop()?;
                if a.is_signed() && b.is_signed() {
                    let av=a.as_i128()?;let bv=b.as_i128()?;
                    if bv==0 {return Err(VMError::RuntimeError(format!("Div by zero: {} / 0",av)));}
                    let r=av.checked_div(bv).ok_or_else(||VMError::RuntimeError(format!("Signed overflow on Div: {} / {}",av,bv)))?;
                    self.push(Value::from_i128_shrink(r))?;
                } else if a.is_uint_compat() && b.is_uint_compat() {
                    let av=a.as_u256()?;let bv=b.as_u256()?;
                    if bv==U256::ZERO {return Err(VMError::RuntimeError(format!("Div by zero: {} / 0",av)));}
                    let r=av.checked_div(bv).ok_or_else(||VMError::RuntimeError(format!("UInt256 Div error: {} / {}",av,bv)))?;
                    self.push(Value::from_u256_shrink(r))?;
                } else {return Err(VMError::RuntimeError("Div: expected numeric".to_string()));}
            }
            OpCode::Rem => {
                let b = self.pop()?; let a = self.pop()?;
                if a.is_signed() && b.is_signed() {
                    let av=a.as_i128()?;let bv=b.as_i128()?;
                    if bv==0 {return Err(VMError::RuntimeError(format!("Rem by zero: {} % 0",av)));}
                    let r=av.checked_rem(bv).ok_or_else(||VMError::RuntimeError(format!("Signed overflow on Rem: {} % {}",av,bv)))?;
                    self.push(Value::from_i128_shrink(r))?;
                } else if a.is_uint_compat() && b.is_uint_compat() {
                    let av=a.as_u256()?;let bv=b.as_u256()?;
                    if bv==U256::ZERO {return Err(VMError::RuntimeError(format!("Rem by zero: {} % 0",av)));}
                    let r=av.checked_rem(bv).ok_or_else(||VMError::RuntimeError(format!("UInt256 Rem error: {} % {}",av,bv)))?;
                    self.push(Value::from_u256_shrink(r))?;
                } else {return Err(VMError::RuntimeError("Rem: expected numeric".to_string()));}
            }

            // ── Comparison ─────────────────────────────────────────────────
            OpCode::Eq => {
                let b = self.pop()?; let a = self.pop()?;
                // Use signed path only when BOTH operands are signed ints.
                // If either is a large uint (U128/U256), promote both to U256.
                let result = if a.is_signed() && b.is_signed() { a.as_i128()? == b.as_i128()? }
                    else if a.is_uint_compat() && b.is_uint_compat() { a.as_u256()? == b.as_u256()? }
                    else if let (Value::Bool(x), Value::Bool(y)) = (&a, &b) { x == y }
                    else if let (Value::Str(x), Value::Str(y)) = (&a, &b) { x == y }
                    else { return Err(VMError::RuntimeError(format!("Eq: cannot compare {:?} and {:?}", a, b))); };
                self.push(Value::Bool(result))?;
            }
            OpCode::Ne => {
                let b = self.pop()?; let a = self.pop()?;
                let result = if a.is_signed() && b.is_signed() { a.as_i128()? != b.as_i128()? }
                    else if a.is_uint_compat() && b.is_uint_compat() { a.as_u256()? != b.as_u256()? }
                    else if let (Value::Bool(x), Value::Bool(y)) = (&a, &b) { x != y }
                    else if let (Value::Str(x), Value::Str(y)) = (&a, &b) { x != y }
                    else { return Err(VMError::RuntimeError(format!("Ne: cannot compare {:?} and {:?}", a, b))); };
                self.push(Value::Bool(result))?;
            }
            OpCode::Lt => {
                let b = self.pop()?; let a = self.pop()?;
                if a.is_signed() && b.is_signed() {
                    self.push(Value::Bool(a.as_i128()? < b.as_i128()?))?;
                } else if a.is_uint_compat() && b.is_uint_compat() {
                    self.push(Value::Bool(a.as_u256()? < b.as_u256()?))?;
                } else {return Err(VMError::RuntimeError("Lt: expected numeric".to_string()));}
            }
            OpCode::Le => {
                let b = self.pop()?; let a = self.pop()?;
                if a.is_signed() && b.is_signed() {
                    self.push(Value::Bool(a.as_i128()? <= b.as_i128()?))?;
                } else if a.is_uint_compat() && b.is_uint_compat() {
                    self.push(Value::Bool(a.as_u256()? <= b.as_u256()?))?;
                } else {return Err(VMError::RuntimeError("Le: expected numeric".to_string()));}
            }
            OpCode::Gt => {
                let b = self.pop()?; let a = self.pop()?;
                if a.is_signed() && b.is_signed() {
                    self.push(Value::Bool(a.as_i128()? > b.as_i128()?))?;
                } else if a.is_uint_compat() && b.is_uint_compat() {
                    self.push(Value::Bool(a.as_u256()? > b.as_u256()?))?;
                } else {return Err(VMError::RuntimeError("Gt: expected numeric".to_string()));}
            }
            OpCode::Ge => {
                let b = self.pop()?; let a = self.pop()?;
                if a.is_signed() && b.is_signed() {
                    self.push(Value::Bool(a.as_i128()? >= b.as_i128()?))?;
                } else if a.is_uint_compat() && b.is_uint_compat() {
                    self.push(Value::Bool(a.as_u256()? >= b.as_u256()?))?;
                } else {return Err(VMError::RuntimeError("Ge: expected numeric".to_string()));}
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
                // Raw bytes — may be a length-prefixed UTF-8 string or raw Bytes.
                // String encoding from codegen: [outer_len:4LE][inner_len:4LE][utf8...]
                // Detect: outer_len >= 4 AND first 4 bytes as LE == outer_len - 4.
                let len = self.read_u32()? as usize;
                let bytes = self.read_bytes(len)?;
                // Try to decode as length-prefixed string
                let value = if len >= 4 {
                    let inner_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
                    if inner_len + 4 == len {
                        // Matches string encoding — attempt UTF-8 decode
                        match std::str::from_utf8(&bytes[4..]) {
                            Ok(s) => Value::Str(s.to_string()),
                            Err(_) => Value::Bytes(bytes),  // not valid UTF-8 — keep as Bytes
                        }
                    } else {
                        Value::Bytes(bytes)
                    }
                } else {
                    Value::Bytes(bytes)
                };
                self.push(value)?;
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
            OpCode::LoadCaller => {
                // ── LoadCaller (0x50) ─────────────────────────────────────
                //
                // Pushes the caller identity as a 32-byte UInt256.
                //
                // Devnet:   signing_key (EVM address) right-aligned in 32 bytes
                //           — bytes 0..11 zero, bytes 12..31 = 20-byte address.
                //
                // Mainnet:  consensus-resolved UMA reference (32 bytes).
                //           The consensus layer populates CallContext.uma_ref
                //           BEFORE the VM executes (U-8: resolution must not
                //           influence consensus ordering).  The VM never
                //           derives or resolves UMA itself (U-13).
                //
                // `caller_value()` encapsulates the devnet/mainnet switch.
                // No code change is needed here when the UMA registry is
                // wired — only CallContext construction at the call site
                // (synq-server /session/run) needs updating.
                let b = self.call_context.caller_value();
                self.stack.push(Value::U256(U256::from_be_bytes::<32>(b)));
            }

            // ── PQC ────────────────────────────────────────────────────────

            // ── Map operations ──────────────────────────────────────────────
            // MapNew: reads inline name, initialises an empty Map at the named
            // state address and pushes that address (I32) as the handle.
            OpCode::MapNew => {
                if self.pc + 4 > self.code.len() {
                    return Err(VMError::InvalidBytecode("MapNew: truncated name_len".into()));
                }
                let nlen = u32::from_le_bytes(self.code[self.pc..self.pc+4].try_into().unwrap()) as usize;
                self.pc += 4;
                if self.pc + nlen > self.code.len() {
                    return Err(VMError::InvalidBytecode("MapNew: truncated name".into()));
                }
                self.pc += nlen; // name is for debugging only; handle is the addr on stack
                // The address is already on the stack (pushed by LoadImm/Push before MapNew)
                // MapNew just confirms and ensures the slot holds a Map value.
                let addr_val = self.pop()?;
                let addr = addr_val.as_i32()? as usize;
                self.memory.entry(addr).or_insert_with(|| Value::Map(BTreeMap::new()));
                self.push(Value::I32(addr as i32))?;
            }
            OpCode::MapGet => {
                let map_addr = self.pop()?.as_i32()? as usize;
                let key_val  = self.pop()?;
                let key = value_to_key(&key_val)?;
                eprintln!("[VM] MapGet slot={} key_type={} key_hex={}",
                    map_addr,
                    match &key_val { Value::U256(_) => "U256", Value::Bytes(_) => "Bytes",
                        Value::U128(_) => "U128", Value::I32(_) => "I32", _ => "other" },
                    key.iter().map(|b| format!("{:02x}", b)).collect::<String>());
                match self.memory.get(&map_addr) {
                    Some(Value::Map(m)) => {
                        let v = m.get(&key).cloned().unwrap_or(Value::I32(0));
                        eprintln!("[VM] MapGet slot={} result={:?}", map_addr, v);
                        self.push(v)?;
                    }
                    None => { self.push(Value::I32(0))?; eprintln!("[VM] MapGet slot={} empty memory", map_addr); }
                    _ => return Err(VMError::RuntimeError("MapGet: slot is not a Map".into())),
                }
            }
            OpCode::MapSet => {
                let map_addr = self.pop()?.as_i32()? as usize;
                let key_val  = self.pop()?;
                let val      = self.pop()?;
                let key = value_to_key(&key_val)?;
                eprintln!("[VM] MapSet slot={} key_type={} key_hex={} val={:?}",
                    map_addr,
                    match &key_val { Value::U256(_) => "U256", Value::Bytes(_) => "Bytes",
                        Value::U128(_) => "U128", Value::I32(_) => "I32", _ => "other" },
                    key.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
                    val);
                match self.memory.entry(map_addr).or_insert_with(|| Value::Map(BTreeMap::new())) {
                    Value::Map(m) => { m.insert(key, val); }
                    _ => return Err(VMError::RuntimeError("MapSet: slot is not a Map".into())),
                }
            }
            OpCode::MapContains => {
                let map_addr = self.pop()?.as_i32()? as usize;
                let key_val  = self.pop()?;
                let key = value_to_key(&key_val)?;
                let found = match self.memory.get(&map_addr) {
                    Some(Value::Map(m)) => m.contains_key(&key),
                    _ => false,
                };
                self.push(Value::Bool(found))?;
            }
            OpCode::MapRemove => {
                let map_addr = self.pop()?.as_i32()? as usize;
                let key_val  = self.pop()?;
                let key = value_to_key(&key_val)?;
                if let Some(Value::Map(m)) = self.memory.get_mut(&map_addr) {
                    m.remove(&key);
                }
            }
            OpCode::MapLen => {
                let map_addr = self.pop()?.as_i32()? as usize;
                let len = match self.memory.get(&map_addr) {
                    Some(Value::Map(m)) => m.len() as i32,
                    _ => 0,
                };
                self.push(Value::I32(len))?;
            }

            // ── Set operations ───────────────────────────────────────────────
            OpCode::SetNew => {
                if self.pc + 4 > self.code.len() {
                    return Err(VMError::InvalidBytecode("SetNew: truncated name_len".into()));
                }
                let nlen = u32::from_le_bytes(self.code[self.pc..self.pc+4].try_into().unwrap()) as usize;
                self.pc += 4;
                if self.pc + nlen > self.code.len() {
                    return Err(VMError::InvalidBytecode("SetNew: truncated name".into()));
                }
                self.pc += nlen;
                let addr_val = self.pop()?;
                let addr = addr_val.as_i32()? as usize;
                self.memory.entry(addr).or_insert_with(|| Value::Set(BTreeSet::new()));
                self.push(Value::I32(addr as i32))?;
            }
            OpCode::SetAdd => {
                let set_addr = self.pop()?.as_i32()? as usize;
                let val      = self.pop()?;
                let key = value_to_key(&val)?;
                match self.memory.entry(set_addr).or_insert_with(|| Value::Set(BTreeSet::new())) {
                    Value::Set(s) => { s.insert(key); }
                    _ => return Err(VMError::RuntimeError("SetAdd: slot is not a Set".into())),
                }
            }
            OpCode::SetContains => {
                let set_addr = self.pop()?.as_i32()? as usize;
                let val      = self.pop()?;
                let key = value_to_key(&val)?;
                let found = match self.memory.get(&set_addr) {
                    Some(Value::Set(s)) => s.contains(&key),
                    _ => false,
                };
                self.push(Value::Bool(found))?;
            }
            OpCode::SetRemove => {
                let set_addr = self.pop()?.as_i32()? as usize;
                let val      = self.pop()?;
                let key = value_to_key(&val)?;
                if let Some(Value::Set(s)) = self.memory.get_mut(&set_addr) {
                    s.remove(&key);
                }
            }
            OpCode::SetLen => {
                let set_addr = self.pop()?.as_i32()? as usize;
                let len = match self.memory.get(&set_addr) {
                    Some(Value::Set(s)) => s.len() as i32,
                    _ => 0,
                };
                self.push(Value::I32(len))?;
            }

            // ── String operations ────────────────────────────────────────────
            // Strings are stored as Value::Bytes(UTF-8 bytes) — LoadImm already does this.
            OpCode::StrLen => {
                let addr_val = self.pop()?;
                let len = match &addr_val {
                    Value::Bytes(b) => b.len() as i32,
                    Value::Str(s)   => s.len() as i32,
                    Value::I32(a) => {
                        match self.memory.get(&(*a as usize)) {
                            Some(Value::Bytes(b)) => b.len() as i32,
                            _ => 0,
                        }
                    }
                    _ => return Err(VMError::RuntimeError("StrLen: expected Bytes or address".into())),
                };
                self.push(Value::I32(len))?;
            }
            OpCode::StrConcat => {
                let b = self.pop()?;
                let a = self.pop()?;
                let mut ab = a.as_bytes()?.to_vec();
                ab.extend_from_slice(b.as_bytes()?);
                self.push(Value::Bytes(ab))?;
            }
            OpCode::StrEq => {
                let b = self.pop()?;
                let a = self.pop()?;
                let eq = a.as_bytes()? == b.as_bytes()?;
                self.push(Value::Bool(eq))?;
            }

#[cfg(feature = "native")]
            OpCode::DilithiumVerify => {
                let public_key = self.pop()?.as_bytes()?.to_vec();
                let message    = self.pop()?.as_bytes()?.to_vec();
                let signature  = self.pop()?.as_bytes()?.to_vec();
                let result = dilithium::verify(&message, &signature, &public_key);
                self.push(Value::Bool(result))?;
            }
#[cfg(feature = "native")]
            OpCode::KyberKeyExchange => {
                let private_key = self.pop()?.as_bytes()?.to_vec();
                let ciphertext  = self.pop()?.as_bytes()?.to_vec();
                let shared_secret = kyber::decaps(&ciphertext, &private_key)
                    .map_err(VMError::RuntimeError)?;
                self.push(Value::Bytes(shared_secret))?;
            }
#[cfg(feature = "native")]
            OpCode::FalconVerify => {
                let public_key = self.pop()?.as_bytes()?.to_vec();
                let message    = self.pop()?.as_bytes()?.to_vec();
                let signature  = self.pop()?.as_bytes()?.to_vec();
                let result = falcon::verify(&message, &signature, &public_key);
                self.push(Value::Bool(result))?;
            }
#[cfg(feature = "native")]
            OpCode::SphincsVerify => {
                let public_key = self.pop()?.as_bytes()?.to_vec();
                let message    = self.pop()?.as_bytes()?.to_vec();
                let signature  = self.pop()?.as_bytes()?.to_vec();
                let result = sphincs::verify(&message, &signature, &public_key);
                self.push(Value::Bool(result))?;
            }
#[cfg(not(feature = "native"))]
            OpCode::DilithiumVerify | OpCode::KyberKeyExchange |
            OpCode::FalconVerify    | OpCode::SphincsVerify => {
                return Err(VMError::RuntimeError(
                    "PQC opcodes require native build — use synq-server for signing".into()
                ));
            }
            // ── ExternCall (0x60): call function on another workspace contract ─────
            OpCode::ExternCall => {
                let _ec_start_pc = self.pc - 1;
                eprintln!("[SynQ EC] at pc={} code_len={} stack_len={}", _ec_start_pc, self.code.len(), self.stack.len());
                if self.pc + 4 > self.code.len() {
                    return Err(VMError::InvalidBytecode("ExternCall: truncated contract_len".into()));
                }
                let clen = u32::from_le_bytes(self.code[self.pc..self.pc+4].try_into().unwrap()) as usize;
                eprintln!("[SynQ EC] clen={} bytes_at_pc={:?}", clen, &self.code[self.pc..std::cmp::min(self.pc+16,self.code.len())]);
                self.pc += 4;
                if self.pc + clen > self.code.len() {
                    return Err(VMError::InvalidBytecode("ExternCall: truncated contract name".into()));
                }
                let contract_name = String::from_utf8(self.code[self.pc..self.pc+clen].to_vec())
            .map_err(|_| VMError::InvalidBytecode("ExternCall: contract name is not valid UTF-8".to_string()))?;
                self.pc += clen;
                if self.pc + 4 > self.code.len() {
                    return Err(VMError::InvalidBytecode("ExternCall: truncated fn_len".into()));
                }
                let flen = u32::from_le_bytes(self.code[self.pc..self.pc+4].try_into().unwrap()) as usize;
                self.pc += 4;
                if self.pc + flen > self.code.len() {
                    return Err(VMError::InvalidBytecode("ExternCall: truncated fn name".into()));
                }
                let fn_name = String::from_utf8(self.code[self.pc..self.pc+flen].to_vec())
            .map_err(|_| VMError::InvalidBytecode("ExternCall: fn name is not valid UTF-8".to_string()))?;
                self.pc += flen;
                if self.pc >= self.code.len() {
                    return Err(VMError::InvalidBytecode("ExternCall: missing arg_count".into()));
                }
                let arg_count = self.code[self.pc] as usize;
                self.pc += 1;
                let mut args: Vec<Value> = Vec::with_capacity(arg_count);
                for _ in 0..arg_count {
                    args.push(self.stack.pop().ok_or_else(|| {
                        eprintln!("[SynQ debug] ExternCall StackUnderflow: contract='{}' fn='{}' argc={} stack_len={} pc={}", contract_name, fn_name, arg_count, self.stack.len(), self.pc);
                        VMError::StackUnderflow
                    })?);
                }
                args.reverse();
                eprintln!("[EC] calling {}.{}({:?})", contract_name, fn_name, args);
                let result = match &self.extern_call_handler {
                    Some(h) => h(&contract_name, &fn_name, &args)?,
                    None    => return Err(VMError::RuntimeError(format!(
                        "extern_call: no workspace active — '{}' not reachable", contract_name))),
                };
                self.stack.push(result.unwrap_or(Value::I32(0)));
            }

            OpCode::TuplePack => {
                let count = self.stack.pop().ok_or(VMError::StackUnderflow)?.as_i32().map_err(|_| VMError::RuntimeError("TuplePack: expected count".into()))? as usize;
                if self.stack.len() < count { return Err(VMError::StackUnderflow); }
                let mut elems = Vec::with_capacity(count);
                for _ in 0..count { elems.push(self.stack.pop().ok_or(VMError::StackUnderflow)?); }
                elems.reverse(); // restore push order
                self.stack.push(Value::Tuple(elems));
            }
            OpCode::TupleUnpack => {
                let t = self.stack.pop().ok_or(VMError::StackUnderflow)?;
                if let Value::Tuple(elems) = t {
                    let n = elems.len();
                    for e in elems { self.stack.push(e); }
                    self.stack.push(Value::I32(n as i32));
                } else { return Err(VMError::RuntimeError("TupleUnpack: not a Tuple".into())); }
            }
            OpCode::TupleGet => {
                let idx = self.stack.pop().ok_or(VMError::StackUnderflow)?.as_i32().map_err(|_| VMError::RuntimeError("TupleGet: expected index".into()))? as usize;
                let t   = self.stack.pop().ok_or(VMError::StackUnderflow)?;
                if let Value::Tuple(elems) = t {
                    let v = elems.into_iter().nth(idx).ok_or_else(|| VMError::RuntimeError(format!("TupleGet: index {} out of range", idx)))?;
                    self.stack.push(v);
                } else { return Err(VMError::RuntimeError("TupleGet: not a Tuple".into())); }
            }
            OpCode::OptionSome => {
                let v = self.stack.pop().ok_or(VMError::StackUnderflow)?;
                self.stack.push(Value::SynqOption(Some(Box::new(v))));
            }
            OpCode::OptionNone => {
                self.stack.push(Value::SynqOption(None));
            }
            OpCode::OptionUnwrap => {
                let v = self.stack.pop().ok_or(VMError::StackUnderflow)?;
                if let Value::SynqOption(Some(inner)) = v { self.stack.push(*inner); }
                else { return Err(VMError::RuntimeError("OptionUnwrap: None".into())); }
            }
            OpCode::ResultOk => {
                let v = self.stack.pop().ok_or(VMError::StackUnderflow)?;
                self.stack.push(Value::SynqResult(true, Box::new(v)));
            }
            OpCode::ResultErr => {
                let v = self.stack.pop().ok_or(VMError::StackUnderflow)?;
                self.stack.push(Value::SynqResult(false, Box::new(v)));
            }
            OpCode::ResultUnwrap => {
                let v = self.stack.pop().ok_or(VMError::StackUnderflow)?;
                if let Value::SynqResult(true, inner) = v { self.stack.push(*inner); }
                else { return Err(VMError::RuntimeError("ResultUnwrap: Err variant".into())); }
            }
            OpCode::IsOk => {
                let v = self.stack.pop().ok_or(VMError::StackUnderflow)?;
                let ok = matches!(v, Value::SynqResult(true, _));
                self.stack.push(Value::I32(if ok { 1 } else { 0 }));
            }
            OpCode::IsSome => {
                let v = self.stack.pop().ok_or(VMError::StackUnderflow)?;
                let some = matches!(v, Value::SynqOption(Some(_)));
                self.stack.push(Value::I32(if some { 1 } else { 0 }));
            }
            OpCode::Print => {
                let value = self.pop()?;
                self.print_log.push(vm_value_display(&value));
            }
            OpCode::Halt => {
                self.halted = true;
            }
            OpCode::Revert => {
                // Followed by: 4-byte LE message length + message bytes
                // Rollback is handled by the call_function() wrapper (PR-B Item 2).
                let msg_len = self.read_u32()? as usize;
                let msg_bytes = self.read_bytes(msg_len)?;
                let msg = String::from_utf8(msg_bytes.to_vec())
            .unwrap_or_else(|e| format!("revert(0x{})", hex::encode(&msg_bytes[..e.utf8_error().valid_up_to()])));
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
        self.stack.pop().ok_or_else(|| {
            eprintln!("[SynQ debug] StackUnderflow at pc={} stack_len={}", self.pc, self.stack.len());
            VMError::StackUnderflow
        })
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

#[derive(Clone, Debug, Default)]
/// Identity context supplied to the VM before each function call.
///
/// # Devnet vs mainnet semantics
///
/// `signing_key` — the 20-byte EVM address recovered from the EIP-712
/// signature on the call.  This is the ONLY field populated on devnet.
///
/// `uma_ref` — the 32-byte Universal Meta-Address reference resolved by the
/// Synergy consensus layer *before* the VM executes.  On devnet this is
/// always `None`.  On mainnet the consensus layer will resolve the signing
/// key to a stable UMA and populate this field; `LoadCaller` (0x50) will
/// then push `uma_ref` rather than `signing_key`, satisfying invariants
/// U-2, U-3, and U-4 from the Synergy Security Specification v1.6.
///
/// Resolution is performed outside the VM (U-8: must not influence
/// consensus ordering) and failures must be handled upstream (U-14: must
/// not halt execution).  The VM itself MUST NOT attempt UMA derivation —
/// that would violate U-13 (no contract-specific semantics in the UMA
/// layer).
pub struct CallContext {
    /// Raw 20-byte EVM signing address — devnet identity proxy.
    pub signing_key: [u8; 20],
    /// Consensus-resolved UMA reference (32 bytes).  `None` on devnet.
    /// When `Some`, `LoadCaller` pushes this value instead of `signing_key`.
    pub uma_ref: Option<[u8; 32]>,
}

impl CallContext {
    /// Construct a devnet call context from a recovered EVM address.
    /// `uma_ref` is set to `None` — UMA resolution is not yet wired.
    pub fn from_address(addr: [u8; 20]) -> Self {
        Self { signing_key: addr, uma_ref: None }
    }

    /// Construct a mainnet-ready call context with a resolved UMA reference.
    /// The signing key is retained for audit / logging purposes.
    pub fn from_uma(uma: [u8; 32], signing_key: [u8; 20]) -> Self {
        Self { signing_key, uma_ref: Some(uma) }
    }

    /// Anonymous context — no authenticated caller.
    pub fn anonymous() -> Self {
        Self { signing_key: [0u8; 20], uma_ref: None }
    }

    /// Returns the 32-byte value that `LoadCaller` pushes onto the stack.
    /// Devnet (uma_ref = None): signing key right-aligned in 32 bytes.
    /// Mainnet (uma_ref = Some): the resolved UMA reference directly.
    pub fn caller_value(&self) -> [u8; 32] {
        match self.uma_ref {
            Some(uma) => uma,
            None => {
                let mut b = [0u8; 32];
                b[12..32].copy_from_slice(&self.signing_key);
                b
            }
        }
    }
}
