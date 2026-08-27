use std::collections::{HashMap, BTreeMap, BTreeSet};
use super::opcode::{OpCode, VMError};
use ruint::aliases::U256;
#[cfg(feature = "native")]
use pqc_shims::{dilithium, kyber, falcon, sphincs};
#[cfg(feature = "native")]
use pqc_shims::aeg1;

// ── PR-B constants ──────────────────────────────────────────────────────────

/// Default maximum execution steps per call_function() invocation.
/// 100,000,000 steps allows loop-heavy demo contracts (~10M iterations)
/// while still terminating infinite loops in bounded time (~100ms at native speed).
pub const DEFAULT_MAX_STEPS: usize = 100_000_000;

/// Default maximum PQC fuel budget per call_function() invocation.
/// Each AEG1 operation deducts from this budget per the ACTS-15 cost model:
///   cost = base_op,alg + cbyte * input_bytes + carg * argument_count
/// 100,000,000 is sufficient for ~8,000 ML-DSA-87 verifications.
pub const DEFAULT_MAX_FUEL: u64 = 100_000_000;

/// Minimum bounded cost charged for any AegisCall attempt, even if the
/// payload is malformed and cannot be parsed (ACTS-15 §4).
pub const AEGIS_MIN_COST: u64 = 1_000;

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
            // Uninitialised str/bytes slot loads as I32(0) — treat as empty.
            Value::I32(0)   => Ok(&[]),
            Value::Bool(_) | Value::I32(_) | Value::I64(_)
                | Value::U128(_) | Value::U256(_)
                => Err(VMError::RuntimeError(format!("Expected bytes, got {:?}", std::mem::discriminant(self)))),
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
/// Runtime record for a linear asset.
pub struct AssetRecord {
    pub owner:    U256,
    pub value:    U256,
    pub type_tag: u32,
    pub active:   bool,
}

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

    // ── ACTS-VM-005: PQC fuel budget ──────────────────────────────────────
    /// Fuel consumed so far in the current call_function() invocation.
    /// Reset to 0 at the start of each call.
    fuel_used: u64,
    /// Hard limit on PQC fuel per invocation.  Default: DEFAULT_MAX_FUEL.
    pub max_fuel: u64,

    // ── PR-B Item 4: runtime call depth guard ──────────────────────────────
    /// Hard limit on call_stack depth enforced at the Call opcode.
    /// Default: DEFAULT_MAX_CALL_DEPTH.
    pub max_call_depth: usize,

    // ── Fault injection (cosmic ray / Rowhammer simulation) ────────────────
    /// When set, at the given step, XOR the byte at byte_offset with xor_mask.
    /// One-shot: cleared after firing. Used for runtime fault injection demos.
    pub fault_injection: Option<(usize, usize, u8)>,

    // ── Linear asset registry ────────────────────────────────────────────
    pub assets: HashMap<u64, AssetRecord>,
    pub next_asset_id: u64,
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
            fuel_used: 0,
            max_fuel: DEFAULT_MAX_FUEL,
            max_call_depth: DEFAULT_MAX_CALL_DEPTH,
            fault_injection: None,
            assets: HashMap::new(),
            next_asset_id: 1,
        }
    }

    /// PQC fuel consumed so far in the current invocation (ACTS-VM-005).
    pub fn fuel_used(&self) -> u64 { self.fuel_used }
    /// Remaining PQC fuel budget.
    pub fn fuel_remaining(&self) -> u64 { self.max_fuel.saturating_sub(self.fuel_used) }
    /// VM steps consumed in the current invocation (ACTS-VM-003).
    pub fn steps_used(&self) -> usize { self.steps }
    /// Remaining VM step budget for this invocation.
    pub fn steps_remaining(&self) -> usize { self.max_steps.saturating_sub(self.steps) }

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
        self.fuel_used = 0;  // reset fuel budget
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
        self.fuel_used = 0;
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
                // Wrap the error with the function name for easier debugging
                match e {
                    VMError::RuntimeError(msg) => Err(VMError::RuntimeError(
                        format!("{}: {}", name, msg)
                    )),
                    VMError::Reverted(msg) => Err(VMError::Reverted(
                        format!("{}: {}", name, msg)
                    )),
                    // Pass through structured errors (StepLimitExceeded, etc.)
                    other => Err(other),
                }
            }
        }
    }

    pub fn execute(&mut self) -> Result<(), VMError> {
        self.steps = 0;
        self.fuel_used = 0;
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

        // ── Fault injection: simulate cosmic ray / Rowhammer bit flip ───────
        if let Some((target_step, byte_offset, xor_mask)) = self.fault_injection.take() {
            if self.steps == target_step && byte_offset < self.code.len() {
                let orig = self.code[byte_offset];
                self.code[byte_offset] ^= xor_mask;
                eprintln!("[VM] ⚡ FAULT INJECTION at step {}: code[{}] 0x{:02x} → 0x{:02x}",
                    self.steps, byte_offset, orig, self.code[byte_offset]);
            } else {
                // Not yet or out of range — keep it for the next step
                self.fault_injection = Some((target_step, byte_offset, xor_mask));
            }
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
            OpCode::BitAnd => {
                let b = self.pop()?; let a = self.pop()?;
                if a.is_uint_compat() && b.is_uint_compat() {
                    let av=a.as_u256()?;let bv=b.as_u256()?;self.push(Value::from_u256_shrink(av & bv))?;
                } else { return Err(VMError::RuntimeError("BitAnd: expected numeric".to_string())); }
            }
            OpCode::BitOr => {
                let b = self.pop()?; let a = self.pop()?;
                if a.is_uint_compat() && b.is_uint_compat() {
                    let av=a.as_u256()?;let bv=b.as_u256()?;self.push(Value::from_u256_shrink(av | bv))?;
                } else { return Err(VMError::RuntimeError("BitOr: expected numeric".to_string())); }
            }
            OpCode::BitXor => {
                let b = self.pop()?; let a = self.pop()?;
                if a.is_uint_compat() && b.is_uint_compat() {
                    let av=a.as_u256()?;let bv=b.as_u256()?;self.push(Value::from_u256_shrink(av ^ bv))?;
                } else { return Err(VMError::RuntimeError("BitXor: expected numeric".to_string())); }
            }
            OpCode::Shl => {
                // Full 256-bit logical shift; shift amounts >= 256 saturate to zero
                // (ruint's overflowing_shl_big already implements this).
                let b = self.pop()?; let a = self.pop()?;
                if a.is_uint_compat() && b.is_uint_compat() {
                    let av=a.as_u256()?;let bv=b.as_u256()?;self.push(Value::from_u256_shrink(av << bv))?;
                } else { return Err(VMError::RuntimeError("Shl: expected numeric".to_string())); }
            }
            OpCode::Shr => {
                // Full 256-bit logical shift; shift amounts >= 256 saturate to zero.
                let b = self.pop()?; let a = self.pop()?;
                if a.is_uint_compat() && b.is_uint_compat() {
                    let av=a.as_u256()?;let bv=b.as_u256()?;self.push(Value::from_u256_shrink(av >> bv))?;
                } else { return Err(VMError::RuntimeError("Shr: expected numeric".to_string())); }
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
            OpCode::LoadCallSender => {
                let b = match &self.call_context.calling_contract_addr {
                    Some(addr) => {
                        let mut b = [0u8; 32];
                        b[12..32].copy_from_slice(addr);
                        b
                    }
                    None => [0u8; 32],
                };
                self.stack.push(Value::U256(U256::from_be_bytes::<32>(b)));
            }

            // ── LoadAuthority (0x51): push current call's authority envelope ──
            OpCode::LoadAuthority => {
                let env = self.call_context.authority_envelope.clone();
                self.stack.push(Value::Bytes(env));
            }

            // ── AuthRequire (0x52): validate authority envelope against scope ──
            // Pops: scope_hash (Bytes, 32B), envelope (Bytes, ≥80B)
            // Pushes: Bool(true) if valid + scope matches, Bool(false) otherwise
            OpCode::AuthRequire => {
                let scope_hash = match self.pop()? {
                    Value::Bytes(b) => b,
                    Value::U256(v) => v.to_be_bytes::<32>().to_vec(),
                    Value::I32(n) => {
                        let mut b = vec![0u8; 28];
                        b.extend_from_slice(&n.to_be_bytes());
                        b
                    }
                    _ => return Err(VMError::RuntimeError("AuthRequire: scope_hash must be Bytes or U256".into())),
                };
                let envelope = match self.pop()? {
                    Value::Bytes(b) => b,
                    _ => return Err(VMError::RuntimeError("AuthRequire: envelope must be Bytes".into())),
                };

                if envelope.len() < 80 {
                    self.stack.push(Value::Bool(false));
                } else {
                    let env_scope = &envelope[32..64];
                    let env_expiry = u64::from_be_bytes(
                        envelope[72..80].try_into().unwrap_or([0u8; 8])
                    );
                    let scope_matches = env_scope == scope_hash.as_slice()
                        || env_scope.iter().all(|&b| b == 0);  // devnet wildcard
                    let now_height = 0u64;
                    let not_expired = env_expiry == 0 || env_expiry > now_height;
                    let identity_is_set = envelope[0..32].iter().any(|&b| b != 0);
                    self.stack.push(Value::Bool(scope_matches && not_expired && identity_is_set));
                }
            }

            // ── AuthIdentity (0x53): extract UMA identity from envelope ──
            // Pops: envelope (Bytes, ≥32B) → pushes U256 (32-byte UMA identity)
            OpCode::AuthIdentity => {
                let envelope = self.pop()?.as_bytes()?.to_vec();
                if envelope.len() < 32 {
                    self.stack.push(Value::U256(U256::ZERO));
                } else {
                    let mut identity = [0u8; 32];
                    identity.copy_from_slice(&envelope[0..32]);
                    self.stack.push(Value::U256(U256::from_be_bytes::<32>(identity)));
                }
            }

            // ── PQC ────────────────────────────────────────────────────────
            // ── Map operations ──────────────────────────────────────────────
            // state address and pushes that address (I32) as the handle.
            
            // ── AddrEncode (0x54): pop value → push tsynq... Bech32m string ──
            // Accepts: Bytes (any length, left-padded to 20), U256 (low 20 bytes), I32
            OpCode::AddrEncode => {
                let v = self.stack.pop().ok_or(VMError::StackUnderflow)?;
                let addr20 = match v {
                    Value::Bytes(ref b) if b.len() == 20 => {
                        let mut a = [0u8; 20];
                        a.copy_from_slice(b);
                        a
                    }
                    Value::Bytes(ref b) if b.len() < 20 => {
                        // Left-pad to 20 bytes
                        let mut a = [0u8; 20];
                        a[20 - b.len()..].copy_from_slice(b);
                        a
                    }
                    Value::Bytes(ref b) if b.len() <= 32 => {
                        // Right-truncate to 20 bytes (take last 20)
                        let mut a = [0u8; 20];
                        a.copy_from_slice(&b[b.len() - 20..]);
                        a
                    }
                    Value::U256(ref u) => {
                        let bytes = u.to_be_bytes::<32>();
                        let mut a = [0u8; 20];
                        a.copy_from_slice(&bytes[12..32]);
                        a
                    }
                    Value::I32(i) => {
                        let mut a = [0u8; 20];
                        a[19] = (i & 0xFF) as u8;
                        a[18] = ((i >> 8) & 0xFF) as u8;
                        a[17] = ((i >> 16) & 0xFF) as u8;
                        a[16] = ((i >> 24) & 0xFF) as u8;
                        a
                    }
                    Value::U128(v) => {
                        let bytes = v.to_be_bytes();
                        let mut a = [0u8; 20];
                        a[20 - bytes.len()..].copy_from_slice(&bytes);
                        a
                    }
                    _ => return Err(VMError::RuntimeError("AddrEncode: expected address value (Bytes/U256/U128/I32)".into())),
                };
                match crate::bech32::encode_address(&addr20) {
                    Ok(encoded) => self.stack.push(Value::Bytes(encoded.into_bytes())),
                    Err(e) => return Err(VMError::RuntimeError(format!("AddrEncode: {}", e))),
                }
            }

            // ── AddrDecode (0x55): pop Bech32m string → push 20-byte value ──
            OpCode::AddrDecode => {
                let v = self.stack.pop().ok_or(VMError::StackUnderflow)?;
                let s = match v {
                    Value::Bytes(b) => String::from_utf8(b)
                        .map_err(|_| VMError::RuntimeError("AddrDecode: invalid UTF-8".into()))?,
                    _ => return Err(VMError::RuntimeError("AddrDecode: expected Bytes (Bech32 string)".into())),
                };
                let addr = crate::bech32::decode_address(&s)
                    .map_err(|e| VMError::RuntimeError(format!("AddrDecode: {}", e)))?;
                let mut b32 = [0u8; 32];
                b32[12..32].copy_from_slice(&addr);
                self.stack.push(Value::U256(U256::from_be_bytes::<32>(b32)));
            }

            // ── ContractAddr (0x56): pop deployer + nonce + artifact_hash → push tsynq... ──
            OpCode::ContractAddr => {
                let deployer_v = self.stack.pop().ok_or(VMError::StackUnderflow)?;
                let nonce_v = self.stack.pop().ok_or(VMError::StackUnderflow)?;
                let artifact_v = self.stack.pop().ok_or(VMError::StackUnderflow)?;

                let deployer = match deployer_v {
                    Value::U256(ref u) => {
                        let bytes = u.to_be_bytes::<32>();
                        let mut a = [0u8; 20];
                        a.copy_from_slice(&bytes[12..32]);
                        a
                    }
                    Value::Bytes(ref b) if b.len() <= 20 => {
                        let mut a = [0u8; 20];
                        a[20 - b.len()..].copy_from_slice(b);
                        a
                    }
                    Value::Bytes(ref b) => {
                        let mut a = [0u8; 20];
                        a.copy_from_slice(&b[b.len() - 20..]);
                        a
                    }
                    Value::I32(i) => {
                        let mut a = [0u8; 20];
                        a[16..20].copy_from_slice(&(i as u32).to_be_bytes());
                        a
                    }
                    Value::U128(v) => {
                        let bytes = v.to_be_bytes();
                        let mut a = [0u8; 20];
                        a[20 - bytes.len()..].copy_from_slice(&bytes);
                        a
                    }
                    Value::Bool(b) => {
                        let mut a = [0u8; 20];
                        a[19] = if b { 1 } else { 0 };
                        a
                    }
                    _ => return Err(VMError::RuntimeError("ContractAddr: expected address value for deployer".into())),
                };

                let nonce: u64 = match nonce_v {
                    Value::I32(i) => i as u64,
                    Value::U128(v) => v as u64,
                    Value::U256(ref u) => u.try_into().map_err(|_| VMError::RuntimeError("ContractAddr: nonce overflow".into()))?,
                    _ => return Err(VMError::RuntimeError("ContractAddr: expected integer nonce".into())),
                };

                let artifact_hash = match artifact_v {
                    Value::Bytes(ref b) if b.len() == 32 => {
                        let mut h = [0u8; 32];
                        h.copy_from_slice(b);
                        h
                    }
                    Value::Bytes(ref b) if b.len() < 32 => {
                        let mut h = [0u8; 32];
                        h[32 - b.len()..].copy_from_slice(b);
                        h
                    }
                    Value::Bytes(ref b) => {
                        let mut h = [0u8; 32];
                        h.copy_from_slice(&b[b.len() - 32..]);
                        h
                    }
                    Value::U256(ref u) => u.to_be_bytes::<32>(),
                    Value::I32(i) => {
                        let mut h = [0u8; 32];
                        h[28..32].copy_from_slice(&(i as u32).to_be_bytes());
                        h
                    }
                    Value::U128(v) => {
                        let mut h = [0u8; 32];
                        h[16..32].copy_from_slice(&v.to_be_bytes());
                        h
                    }
                    _ => return Err(VMError::RuntimeError("ContractAddr: expected hash value for artifact".into())),
                };

                let constructor_hash = [0u8; 32];
                let network = std::option_env!("SYNQ_NETWORK_ID").unwrap_or("synergy-testnet-v3");

                match crate::bech32::derive_contract_address(&deployer, nonce, &artifact_hash, &constructor_hash, network) {
                    Ok(encoded) => self.stack.push(Value::Bytes(encoded.into_bytes())),
                    Err(e) => return Err(VMError::RuntimeError(format!("ContractAddr: {}", e))),
                }
            }
            // ── Linear asset opcodes (0x57-0x5B) ─────────────────────────────
            OpCode::AssetCreate => {
                let type_tag = self.stack.pop().ok_or(VMError::StackUnderflow)?.as_i32()? as u32;
                let value = self.stack.pop().ok_or(VMError::StackUnderflow)?.as_u256()?;
                let id = self.next_asset_id;
                self.next_asset_id += 1;
                let owner = {
                    let mut arr = [0u8; 32];
                    arr[12..32].copy_from_slice(&self.call_context.signing_key);
                    U256::from_be_bytes::<32>(arr)
                };
                self.assets.insert(id, AssetRecord { owner, value, type_tag, active: true });
                self.stack.push(Value::U256(U256::from(id)));
            }
            OpCode::AssetTransfer => {
                let new_owner = self.stack.pop().ok_or(VMError::StackUnderflow)?.as_u256()?;
                let asset_id = self.stack.pop().ok_or(VMError::StackUnderflow)?.as_u256()?;
                let id: u64 = asset_id.try_into().map_err(|_| VMError::RuntimeError("AssetTransfer: asset_id overflow".into()))?;
                let record = self.assets.get(&id)
                    .filter(|r| r.active)
                    .ok_or_else(|| VMError::RuntimeError(format!("AssetTransfer: asset {} not found or inactive", id)))?;
                let value = record.value;
                let type_tag = record.type_tag;
                self.assets.get_mut(&id).unwrap().active = false;
                let new_id = self.next_asset_id;
                self.next_asset_id += 1;
                self.assets.insert(new_id, AssetRecord { owner: new_owner, value, type_tag, active: true });
                self.stack.push(Value::U256(U256::from(new_id)));
            }
            OpCode::AssetBurn => {
                let asset_id = self.stack.pop().ok_or(VMError::StackUnderflow)?.as_u256()?;
                let id: u64 = asset_id.try_into().map_err(|_| VMError::RuntimeError("AssetBurn: asset_id overflow".into()))?;
                let record = self.assets.get(&id)
                    .filter(|r| r.active)
                    .ok_or_else(|| VMError::RuntimeError(format!("AssetBurn: asset {} not found or inactive", id)))?;
                let value = record.value;
                self.assets.get_mut(&id).unwrap().active = false;
                self.stack.push(Value::U256(value));
            }
            OpCode::AssetBalance => {
                let asset_id = self.stack.pop().ok_or(VMError::StackUnderflow)?.as_u256()?;
                let id: u64 = asset_id.try_into().map_err(|_| VMError::RuntimeError("AssetBalance: asset_id overflow".into()))?;
                let value = self.assets.get(&id).filter(|r| r.active).map(|r| r.value).unwrap_or(U256::ZERO);
                self.stack.push(Value::U256(value));
            }
            OpCode::AssetOwner => {
                let asset_id = self.stack.pop().ok_or(VMError::StackUnderflow)?.as_u256()?;
                let id: u64 = asset_id.try_into().map_err(|_| VMError::RuntimeError("AssetOwner: asset_id overflow".into()))?;
                let owner = self.assets.get(&id).filter(|r| r.active).map(|r| r.owner).unwrap_or(U256::ZERO);
                self.stack.push(Value::U256(owner));
            }

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
                    match &key_val { crate::Value::U256(_) => "U256", crate::Value::Bytes(_) => "Bytes",
                        crate::Value::U128(_) => "U128", crate::Value::I32(_) => "I32", _ => "other" },
                    key.iter().map(|b| format!("{:02x}", b)).collect::<String>());
                match self.memory.get(&map_addr) {
                    Some(Value::Map(m)) => {
                        let v = m.get(&key).cloned().unwrap_or(Value::I32(0));
                        eprintln!("[VM] MapGet slot={} result={:?}", map_addr, v);
                        self.push(v)?;
                    }
                    None => { self.push(Value::I32(0))?; eprintln!("[VM] MapGet slot={} empty memory", map_addr); }
                    _ => { self.push(Value::I32(0))?; eprintln!("[VM] MapGet slot={} non-map default", map_addr); }
                }
            }
            OpCode::MapSet => {
                let map_addr = self.pop()?.as_i32()? as usize;
                let key_val  = self.pop()?;
                let val      = self.pop()?;
                let key = value_to_key(&key_val)?;
                eprintln!("[VM] MapSet slot={} key_type={} key_hex={} val={:?}",
                    map_addr,
                    match &key_val { crate::Value::U256(_) => "U256", crate::Value::Bytes(_) => "Bytes",
                        crate::Value::U128(_) => "U128", crate::Value::I32(_) => "I32", _ => "other" },
                    key.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
                    val);
                match self.memory.entry(map_addr).or_insert_with(|| Value::Map(BTreeMap::new())) {
                    Value::Map(m) => { m.insert(key, val); }
                    slot @ _ => {
                        *slot = Value::Map(BTreeMap::new());
                        if let Value::Map(m) = slot { m.insert(key, val); }
                    }
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
                // Produce Str so callers get a proper string value (not raw bytes).
                let s = String::from_utf8(ab).unwrap_or_default();
                self.push(Value::Str(s))?;
            }
            OpCode::StrEq => {
                let b = self.pop()?;
                let a = self.pop()?;
                // Compare as str slices; I32(0) treated as empty via as_bytes().
                let eq = a.as_bytes()? == b.as_bytes()?;
                self.push(Value::Bool(eq))?;
            }

            // ── Legacy PQC opcodes (0x80-0x83): also charge fuel (ACTS-VM-005) ──
            #[cfg(feature = "native")]
            OpCode::DilithiumVerify => {
                let cost = AEGIS_MIN_COST;
                let remaining = self.max_fuel.saturating_sub(self.fuel_used);
                if cost > remaining {
                    return Err(VMError::FuelExhausted { cost, remaining });
                }
                let public_key = self.pop()?.as_bytes()?.to_vec();
                let message    = self.pop()?.as_bytes()?.to_vec();
                let signature  = self.pop()?.as_bytes()?.to_vec();
                let result = dilithium::verify(&message, &signature, &public_key);
                self.push(Value::Bool(result))?;
                self.fuel_used += cost;
            }
            #[cfg(feature = "native")]
            OpCode::KyberKeyExchange => {
                let cost = AEGIS_MIN_COST;
                let remaining = self.max_fuel.saturating_sub(self.fuel_used);
                if cost > remaining {
                    return Err(VMError::FuelExhausted { cost, remaining });
                }
                let private_key = self.pop()?.as_bytes()?.to_vec();
                let ciphertext  = self.pop()?.as_bytes()?.to_vec();
                let shared_secret = kyber::decaps(&ciphertext, &private_key)
                    .map_err(VMError::RuntimeError)?;
                self.push(Value::Bytes(shared_secret))?;
                self.fuel_used += cost;
            }
            #[cfg(feature = "native")]
            OpCode::FalconVerify => {
                let cost = AEGIS_MIN_COST;
                let remaining = self.max_fuel.saturating_sub(self.fuel_used);
                if cost > remaining {
                    return Err(VMError::FuelExhausted { cost, remaining });
                }
                let public_key = self.pop()?.as_bytes()?.to_vec();
                let message    = self.pop()?.as_bytes()?.to_vec();
                let signature  = self.pop()?.as_bytes()?.to_vec();
                let result = falcon::verify(&message, &signature, &public_key);
                self.push(Value::Bool(result))?;
                self.fuel_used += cost;
            }
            #[cfg(feature = "native")]
            OpCode::SphincsVerify => {
                let cost = AEGIS_MIN_COST;
                let remaining = self.max_fuel.saturating_sub(self.fuel_used);
                if cost > remaining {
                    return Err(VMError::FuelExhausted { cost, remaining });
                }
                let public_key = self.pop()?.as_bytes()?.to_vec();
                let message    = self.pop()?.as_bytes()?.to_vec();
                let signature  = self.pop()?.as_bytes()?.to_vec();
                let result = sphincs::verify(&message, &signature, &public_key);
                self.push(Value::Bool(result))?;
                self.fuel_used += cost;
            }

            // ── AEG1 unified PQC dispatch (0x8F) ──────────────────────────────
            // Pops an AEG1 frame from the stack, dispatches to the appropriate
            // PQC shim, and pushes the response frame back.
            // This is the spec v7.0 aligned interface — replaces algorithm-
            // specific opcodes 0x80-0x83 for new contracts.
            #[cfg(feature = "native")]
            OpCode::AegisCall => {
                // ACTS-15 §3+§4: deterministic VM dispatcher with cost model
                let frame = self.pop()?.as_bytes()?.to_vec();

                // ACTS-VM-005: compute and charge cost BEFORE dispatch.
                // If the payload is malformed, charge the minimum bounded cost.
                let cost = match aeg1::Aeg1Request::decode(&frame) {
                    Ok(req) => aeg1::compute_cost(&req),
                    Err(_)  => AEGIS_MIN_COST,  // malformed: bounded cost (ACTS-15 §4)
                };

                let remaining = self.max_fuel.saturating_sub(self.fuel_used);
                if cost > remaining {
                    eprintln!("[AEG1] fuel exhausted: needed {} but only {} remaining", cost, remaining);
                    return Err(VMError::FuelExhausted { cost, remaining });
                }
                self.fuel_used += cost;

                match aeg1::process_frame_deterministic(&frame) {
                    Ok(response_frame) => {
                        // Decode the response to determine VM-level result
                        match aeg1::Aeg1Response::decode(&response_frame) {
                            Ok(aeg1::Aeg1Response::Ok(result)) => {
                                if result.is_empty() {
                                    // Verify operations return empty body → push Bool(true)
                                    self.push(Value::Bool(true))?;
                                } else {
                                    // Decapsulate returns shared secret → push Bytes
                                    self.push(Value::Bytes(result))?;
                                }
                            }
                            Ok(aeg1::Aeg1Response::Error(code, msg)) => {
                                eprintln!("[AEG1] error: {:?} - {}", code, msg);
                                self.push(Value::Bool(false))?;
                            }
                            Err(e) => {
                                eprintln!("[AEG1] response decode error: {}", e);
                                self.push(Value::Bool(false))?;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[AEG1] dispatch error: {}", e);
                        self.push(Value::Bool(false))?;
                    }
                }
            }
#[cfg(not(feature = "native"))]
            OpCode::DilithiumVerify | OpCode::KyberKeyExchange |
            OpCode::FalconVerify    | OpCode::SphincsVerify |
            OpCode::AegisCall => {
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
            OpCode::TupleSet => {
                let idx = self.stack.pop().ok_or(VMError::StackUnderflow)?.as_i32().map_err(|_| VMError::RuntimeError("TupleSet: expected index".into()))? as usize;
                let val = self.stack.pop().ok_or(VMError::StackUnderflow)?;
                let t   = self.stack.pop().ok_or(VMError::StackUnderflow)?;
                if let Value::Tuple(mut elems) = t {
                    if idx >= elems.len() {
                        return Err(VMError::RuntimeError(format!("TupleSet: index {} out of range", idx)));
                    }
                    elems[idx] = val;
                    self.stack.push(Value::Tuple(elems));
                } else { return Err(VMError::RuntimeError("TupleSet: not a Tuple".into())); }
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
            OpCode::ToString => {
                let value = self.pop()?;
                self.push(Value::Str(vm_value_display(&value)))?;
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
            OpCode::RevertCode => {
                // Named error revert: error_code (4B LE) + msg_len (4B LE) + msg_bytes
                let code = self.read_u32()?;
                let msg_len = self.read_u32()? as usize;
                let msg_bytes = self.read_bytes(msg_len)?;
                let msg = String::from_utf8(msg_bytes.to_vec())
                    .unwrap_or_else(|e| format!("revert(0x{})", hex::encode(&msg_bytes[..e.utf8_error().valid_up_to()])));
                return Err(VMError::RevertedNamed { code, message: msg });
            }
            OpCode::RevertCodeDyn => {
                let code = self.read_u32()?;
                let msg_val = self.pop()?;
                let msg = match &msg_val {
                    Value::Str(s) => s.clone(),
                    Value::Bytes(b) => String::from_utf8(b.clone())
                        .unwrap_or_else(|_| format!("0x{}", hex::encode(b))),
                    _ => vm_value_display(&msg_val),
                };
                return Err(VMError::RevertedNamed { code, message: msg });
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
    /// Authority envelope for the current call — populated by the server
    /// from the EIP-712 signature, nonce, and caller context.
    /// Format: identity(32) + scope_hash(32) + nonce(8) + expiry(8) + caps(8) + reserved(16) = 104 bytes
    /// Empty on devnet unless the server constructs it.
    pub authority_envelope: Vec<u8>,
    /// Immediate calling contract address. None for direct calls.
    pub calling_contract_addr: Option<[u8; 20]>,
}

impl CallContext {
    /// Construct a devnet call context from a recovered EVM address.
    /// `uma_ref` is set to `None` — UMA resolution is not yet wired.
    pub fn from_address(addr: [u8; 20]) -> Self {
        Self { signing_key: addr, uma_ref: None, authority_envelope: Vec::new(), calling_contract_addr: None }
    }

    /// Construct a mainnet-ready call context with a resolved UMA reference.
    /// The signing key is retained for audit / logging purposes.
    pub fn from_uma(uma: [u8; 32], signing_key: [u8; 20]) -> Self {
        Self { signing_key, uma_ref: Some(uma), authority_envelope: Vec::new(), calling_contract_addr: None }
    }

    /// Anonymous context — no authenticated caller.
    pub fn anonymous() -> Self {
        Self { signing_key: [0u8; 20], uma_ref: None, authority_envelope: Vec::new(), calling_contract_addr: None }
    }

    /// Construct a call context with a pre-built authority envelope.
    /// Used by the server when it has constructed the envelope from the
    /// EIP-712 signature, nonce, and consensus state.
    pub fn with_authority(addr: [u8; 20], uma: Option<[u8; 32]>, envelope: Vec<u8>) -> Self {
        Self { signing_key: addr, uma_ref: uma, authority_envelope: envelope, calling_contract_addr: None }
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

// ── Authority model tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod authority_tests {
    use super::*;
    use crate::opcode::OpCode;

    fn build_test_envelope(identity: [u8; 32], scope_hash: [u8; 32], nonce: u64, expiry: u64) -> Vec<u8> {
        let mut env = vec![0u8; 104];
        env[0..32].copy_from_slice(&identity);
        env[32..64].copy_from_slice(&scope_hash);
        env[64..72].copy_from_slice(&nonce.to_be_bytes());
        env[72..80].copy_from_slice(&expiry.to_be_bytes());
        env[80] = 0xFF;
        env
    }

    fn run_code(code: Vec<u8>, ctx: CallContext) -> QuantumVM {
        let mut vm = QuantumVM::new();
        vm.call_context = ctx;
        vm.max_steps = 1000;
        vm.code = code;
        vm.execute().unwrap();
        vm
    }

    #[test]
    fn test_load_authority_pushes_envelope() {
        let envelope = build_test_envelope([0xAA; 32], [0xBB; 32], 42, 0);
        let mut vm = run_code(
            vec![OpCode::LoadAuthority as u8, OpCode::Halt as u8],
            CallContext::with_authority([0x11; 20], None, envelope.clone()),
        );
        let result = vm.pop().unwrap();
        assert_eq!(result.as_bytes().unwrap(), &envelope[..]);
    }

    #[test]
    fn test_auth_identity_extracts_uma() {
        let envelope = build_test_envelope([0xCD; 32], [0x00; 32], 0, 0);
        let mut vm = run_code(
            vec![OpCode::LoadAuthority as u8, OpCode::AuthIdentity as u8, OpCode::Halt as u8],
            CallContext::with_authority([0x11; 20], None, envelope),
        );
        let result = vm.pop().unwrap();
        match result {
            Value::U256(v) => assert_eq!(v.to_be_bytes::<32>(), [0xCD; 32]),
            _ => panic!("expected U256"),
        }
    }

    #[test]
    fn test_auth_require_valid_scope() {
        let scope = [0x42; 32];
        let envelope = build_test_envelope([0xEF; 32], scope, 1, 0);
        let ctx = CallContext::with_authority([0x11; 20], None, envelope.clone());
        let mut vm = QuantumVM::new();
        vm.call_context = ctx;
        vm.max_steps = 1000;
        // Push envelope (bottom), then scope_hash (top) — matches AuthRequire pop order
        vm.stack.push(Value::Bytes(envelope));
        vm.stack.push(Value::Bytes(scope.to_vec()));
        vm.code = vec![OpCode::AuthRequire as u8, OpCode::Halt as u8];
        vm.execute().unwrap();
        assert_eq!(vm.pop().unwrap().as_bool().unwrap(), true);
    }

    #[test]
    fn test_auth_require_wrong_scope() {
        let envelope = build_test_envelope([0xEF; 32], [0x42; 32], 1, 0);
        let ctx = CallContext::with_authority([0x11; 20], None, envelope);
        let mut vm = QuantumVM::new();
        vm.call_context = ctx;
        vm.max_steps = 1000;
        vm.code = vec![OpCode::LoadAuthority as u8, OpCode::AuthRequire as u8, OpCode::Halt as u8];
        vm.stack.push(Value::Bytes(vec![0x99; 32]));
        vm.execute().unwrap();
        assert_eq!(vm.pop().unwrap().as_bool().unwrap(), false);
    }

    #[test]
    fn test_auth_require_zero_identity_rejected() {
        let envelope = build_test_envelope([0x00; 32], [0x42; 32], 1, 0);
        let ctx = CallContext::with_authority([0x00; 20], None, envelope);
        let mut vm = QuantumVM::new();
        vm.call_context = ctx;
        vm.max_steps = 1000;
        vm.code = vec![OpCode::LoadAuthority as u8, OpCode::AuthRequire as u8, OpCode::Halt as u8];
        vm.stack.push(Value::Bytes(vec![0x42; 32]));
        vm.execute().unwrap();
        assert_eq!(vm.pop().unwrap().as_bool().unwrap(), false, "zero identity rejected");
    }

    #[test]
    fn test_auth_require_expired() {
        let envelope = build_test_envelope([0xEF; 32], [0x42; 32], 1, 1);
        let ctx = CallContext::with_authority([0x11; 20], None, envelope);
        let mut vm = QuantumVM::new();
        vm.call_context = ctx;
        vm.max_steps = 1000;
        vm.code = vec![OpCode::LoadAuthority as u8, OpCode::AuthRequire as u8, OpCode::Halt as u8];
        vm.stack.push(Value::Bytes(vec![0x42; 32]));
        vm.execute().unwrap();
        assert_eq!(vm.pop().unwrap().as_bool().unwrap(), false, "expired rejected");
    }

    #[test]
    fn test_auth_require_short_envelope() {
        let ctx = CallContext::with_authority([0x11; 20], None, vec![0u8; 10]);
        let mut vm = QuantumVM::new();
        vm.call_context = ctx;
        vm.max_steps = 1000;
        vm.code = vec![OpCode::LoadAuthority as u8, OpCode::AuthRequire as u8, OpCode::Halt as u8];
        vm.stack.push(Value::Bytes(vec![0x42; 32]));
        vm.execute().unwrap();
        assert_eq!(vm.pop().unwrap().as_bool().unwrap(), false, "short envelope rejected");
    }

    #[test]
    fn test_devnet_envelope_identity_matches_caller() {
        let caller_addr = [0x11; 20];
        let mut envelope = vec![0u8; 104];
        envelope[12..32].copy_from_slice(&caller_addr);
        envelope[80] = 0xFF;
        let mut vm = run_code(
            vec![OpCode::LoadAuthority as u8, OpCode::AuthIdentity as u8, OpCode::Halt as u8],
            CallContext::with_authority(caller_addr, None, envelope),
        );
        let result = vm.pop().unwrap();
        match result {
            Value::U256(v) => {
                let bytes = v.to_be_bytes::<32>();
                assert_eq!(&bytes[0..12], &[0u8; 12]);
                assert_eq!(&bytes[12..32], &caller_addr);
            }
            _ => panic!("expected U256"),
        }
    }

    /// ACTS-VM-005: AegisCall must charge fuel based on the cost model.
    #[cfg(feature = "native")]
    #[test]
    fn test_aegis_call_charges_fuel() {
        let req = aeg1::Aeg1Request {
            operation: aeg1::Operation::MlDsaVerify,
            algorithm: aeg1::Algorithm::MlDsa65,
            args: vec![b"msg".to_vec(), vec![0xFF; 64], vec![0xEE; 32]],
        };
        let frame = req.encode();
        let expected_cost = aeg1::compute_cost(&req);
        // base(8000) + cbyte(1)*(3+64+32) + carg(100)*3 = 8000 + 99 + 300 = 8399
        assert_eq!(expected_cost, 8000 + 99 + 300);

        let mut vm = QuantumVM::new();
        vm.push(Value::Bytes(frame.clone()));
        vm.code = vec![OpCode::AegisCall as u8, OpCode::Halt as u8];
        vm.pc = 0;
        let _ = vm.execute();
        assert_eq!(vm.fuel_used(), expected_cost);
    }

    /// ACTS-VM-005: Fuel exhaustion must halt with FuelExhausted error.
    #[test]
    fn test_fuel_exhaustion() {
        let req = aeg1::Aeg1Request {
            operation: aeg1::Operation::MlDsaVerify,
            algorithm: aeg1::Algorithm::MlDsa87,
            args: vec![vec![0xAB; 1000], vec![0xCD; 2000], vec![0xEF; 500]],
        };
        let frame = req.encode();
        let expected_cost = aeg1::compute_cost(&req);

        let mut vm = QuantumVM::new();
        vm.max_fuel = expected_cost - 1;
        vm.push(Value::Bytes(frame));
        vm.code = vec![OpCode::AegisCall as u8, OpCode::Halt as u8];
        vm.pc = 0;
        let result = vm.execute();
        assert!(result.is_err());
        match result.unwrap_err() {
            VMError::FuelExhausted { cost, remaining } => {
                assert_eq!(cost, expected_cost);
                assert_eq!(remaining, expected_cost - 1);
            }
            e => panic!("expected FuelExhausted, got {:?}", e),
        }
    }

    /// ACTS-VM-005: Malformed payloads must still charge the minimum bounded cost.
    #[test]
    fn test_malformed_aegis_call_charges_min_cost() {
        let mut vm = QuantumVM::new();
        vm.push(Value::Bytes(b"NOT_AEG1".to_vec()));
        vm.code = vec![OpCode::AegisCall as u8, OpCode::Halt as u8];
        vm.pc = 0;
        let _ = vm.execute();
        assert_eq!(vm.fuel_used(), AEGIS_MIN_COST);
    }

    /// ACTS-VM-005: Multiple AegisCalls accumulate fuel usage.
    #[test]
    fn test_fuel_accumulates() {
        let req = aeg1::Aeg1Request {
            operation: aeg1::Operation::MlDsaVerify,
            algorithm: aeg1::Algorithm::MlDsa65,
            args: vec![b"msg".to_vec(), vec![0xFF; 32], vec![0xEE; 16]],
        };
        let frame = req.encode();
        let single_cost = aeg1::compute_cost(&req);

        let mut vm = QuantumVM::new();
        // Use execute_instruction directly — execute() resets fuel to 0
        vm.code = vec![OpCode::AegisCall as u8, OpCode::Halt as u8];

        // First call
        vm.push(Value::Bytes(frame.clone()));
        vm.pc = 0;
        let _ = vm.execute_instruction();
        assert_eq!(vm.fuel_used(), single_cost);

        // Pop the Bool(false) pushed by the first AegisCall
        let _ = vm.pop();

        // Second call — fuel should accumulate
        vm.push(Value::Bytes(frame.clone()));
        vm.pc = 0;
        let _ = vm.execute_instruction();
        assert_eq!(vm.fuel_used(), single_cost * 2);
    }

    // ── End-to-end IR compilation + VM execution tests ─────────────────────────
    //
    // These tests compile contracts via the IR backend (compile_ir), load the
    // resulting bytecode into the QVM, and execute functions to verify that
    // state variables are correctly updated — not just that compilation succeeds.
    //
    // They specifically catch the class of bug where cross-block SSA value
    // references resolve to the wrong memory slot (ValueId collision across
    // blocks), which compile-only tests cannot detect.

    fn compile_ir_and_load(source: &str) -> QuantumVM {
        let result = synq_compiler::compile_ir(source)
            .expect("IR compilation should succeed");
        assert!(!result.bytecode.is_empty(), "IR bytecode should not be empty");

        // Verify state vars are present
        assert!(!result.state_vars.is_empty(), "should have state vars");

        let mut vm = QuantumVM::new();
        vm.load_bytecode(&result.bytecode)
            .expect("bytecode should load into VM");
        vm
    }

    #[test]
    fn test_ir_loop_state_vars_update() {
        // This contract has a loop (runIterations) that:
        // 1. Runs a while loop accumulating a local `total`
        // 2. After the loop, updates state vars `accumulator` and `iterationCount`
        //
        // The bug: ValueId collisions across blocks caused the lowerer to
        // resolve cross-block value references to the wrong memory slots,
        // so state vars never updated (stayed at 0).
        let source = r#"pragma synq ^0.9;
contract LoopStateTest {
    state {
        accumulator: u256;
        iterationCount: u256;
        initialised: bool;
    }

    @public
    function init() -> bool {
        if (initialised) { return false; }
        accumulator = 0;
        iterationCount = 0;
        initialised = true;
        return true;
    }

    @public
    function runIterations(n: u256) -> u256 {
        require(initialised, "not initialised");
        let total: u256 = 0;
        let i: u256 = 0;
        while (i < n) {
            total = total + i;
            i = i + 1;
        }
        accumulator = accumulator + total;
        iterationCount = iterationCount + n;
        return total;
    }

    @public
    function get_accumulator() -> u256 {
        return accumulator;
    }

    @public
    function get_iteration_count() -> u256 {
        return iterationCount;
    }
}
"#;

        let mut vm = compile_ir_and_load(source);

        // Step 1: Call init() — should return true and set initialised
        let init_result = vm.call_function("init", &[])
            .expect("init() should execute");
        match init_result {
            Some(Value::I32(1)) | Some(Value::Bool(true)) => {},
            other => panic!("init() should return true, got {:?}", other),
        }

        // Step 2: Call runIterations(8) — should return 0+1+2+3+4+5+6+7 = 28
        let result = vm.call_function("runIterations", &[Value::U256(U256::from(8u32))])
            .expect("runIterations(8) should execute");
        match result {
            Some(Value::U256(v)) => assert_eq!(v, U256::from(28u32),
                "runIterations(8) should return 28 (sum 0..=7), got {}", v),
            Some(Value::I32(v)) => assert_eq!(v, 28,
                "runIterations(8) should return 28 (sum 0..=7), got {}", v),
            Some(Value::I32(v)) => assert_eq!(v, 28,
                "runIterations(8) should return 28 (sum 0..=7), got {}", v),
            other => panic!("runIterations should return U256 or I32, got {:?}", other),
        }

        // Step 3: Verify state variables actually updated
        // accumulator should be 28 (0+1+2+...+7)
        let acc = vm.call_function("get_accumulator", &[])
            .expect("get_accumulator() should execute");
        match acc {
            Some(Value::U256(v)) => assert_eq!(v, U256::from(28u32),
                "accumulator should be 28 after runIterations(8), got {}", v),
            Some(Value::I32(v)) => assert_eq!(v, 28,
                "accumulator should be 28 after runIterations(8), got {}", v),
            other => panic!("get_accumulator should return U256 or I32, got {:?}", other),
        }

        // iterationCount should be 8
        let count = vm.call_function("get_iteration_count", &[])
            .expect("get_iteration_count() should execute");
        match count {
            Some(Value::U256(v)) => assert_eq!(v, U256::from(8u32),
                "iterationCount should be 8 after runIterations(8), got {}", v),
            Some(Value::I32(v)) => assert_eq!(v, 8,
                "iterationCount should be 8 after runIterations(8), got {}", v),
            other => panic!("get_iteration_count should return U256 or I32, got {:?}", other),
        }
    }

    #[test]
    fn test_ir_loop_factorial() {
        // Test a pure loop function (factorial) to verify correct return values.
        // factorial(5) = 5*4*3*2*1 = 120
        let source = r#"pragma synq ^0.9;
contract FactorialTest {
    state {
        initialised: bool;
    }

    @public
    function init() -> bool {
        if (initialised) { return false; }
        initialised = true;
        return true;
    }

    @public
    function factorial(n: u256) -> u256 {
        let result: u256 = 1;
        let i: u256 = 1;
        while (i <= n) {
            result = result * i;
            i = i + 1;
        }
        return result;
    }
}
"#;

        let mut vm = compile_ir_and_load(source);

        // Init
        vm.call_function("init", &[]).expect("init() should succeed");

        // factorial(5) = 120
        let result = vm.call_function("factorial", &[Value::U256(U256::from(5u32))])
            .expect("factorial(5) should execute");
        match result {
            Some(Value::U256(v)) => assert_eq!(v, U256::from(120u32),
                "factorial(5) should be 120, got {}", v),
            Some(Value::I32(v)) => assert_eq!(v, 120,
                "factorial(5) should be 120, got {}", v),
            other => panic!("factorial should return U256 or I32, got {:?}", other),
        }

        // factorial(10) = 3628800
        let result = vm.call_function("factorial", &[Value::U256(U256::from(10u32))])
            .expect("factorial(10) should execute");
        match result {
            Some(Value::U256(v)) => assert_eq!(v, U256::from(3628800u32),
                "factorial(10) should be 3628800, got {}", v),
            Some(Value::I32(v)) => assert_eq!(v, 3628800,
                "factorial(10) should be 3628800, got {}", v),
            other => panic!("factorial should return U256 or I32, got {:?}", other),
        }
    }

    #[test]
    fn test_ir_loop_sum_range() {
        // Test sumRange — a loop that accumulates and returns the result.
        // sumRange(1, 100) = 5050
        let source = r#"pragma synq ^0.9;
contract SumRangeTest {
    state {
        initialised: bool;
    }

    @public
    function init() -> bool {
        if (initialised) { return false; }
        initialised = true;
        return true;
    }

    @public
    function sumRange(start: u256, end: u256) -> u256 {
        let total: u256 = 0;
        let i: u256 = start;
        while (i <= end) {
            total = total + i;
            i = i + 1;
        }
        return total;
    }
}
"#;

        let mut vm = compile_ir_and_load(source);
        vm.call_function("init", &[]).expect("init() should succeed");

        // sumRange(1, 100) = 5050
        let result = vm.call_function("sumRange", &[Value::U256(U256::from(1u32)), Value::U256(U256::from(100u32))])
            .expect("sumRange(1, 100) should execute");
        match result {
            Some(Value::U256(v)) => assert_eq!(v, U256::from(5050u32),
                "sumRange(1,100) should be 5050, got {}", v),
            Some(Value::I32(v)) => assert_eq!(v, 5050,
                "sumRange(1,100) should be 5050, got {}", v),
            other => panic!("sumRange should return U256 or I32, got {:?}", other),
        }
    }

    #[test]
    fn test_ir_loop_accumulating_state_across_calls() {
        // Call runIterations multiple times and verify state accumulates correctly.
        // This tests that state variables persist across calls when compiled via IR.
        let source = r#"pragma synq ^0.9;
contract AccumStateTest {
    state {
        total: u256;
        initialised: bool;
    }

    @public
    function init() -> bool {
        if (initialised) { return false; }
        total = 0;
        initialised = true;
        return true;
    }

    @public
    function addRange(n: u256) -> u256 {
        require(initialised, "not initialised");
        let sum: u256 = 0;
        let i: u256 = 0;
        while (i < n) {
            sum = sum + i;
            i = i + 1;
        }
        total = total + sum;
        return total;
    }

    @public
    function get_total() -> u256 {
        return total;
    }
}
"#;

        let mut vm = compile_ir_and_load(source);
        vm.call_function("init", &[]).expect("init() should succeed");

        // First call: addRange(5) → sum = 0+1+2+3+4 = 10, total = 10
        let r1 = vm.call_function("addRange", &[Value::U256(U256::from(5u32))])
            .expect("addRange(5) should execute");
        match r1 {
            Some(Value::U256(v)) => assert_eq!(v, U256::from(10u32),
                "after addRange(5), total should be 10, got {}", v),
            Some(Value::I32(v)) => assert_eq!(v, 10,
                "after addRange(5), total should be 10, got {}", v),
            _ => panic!("expected U256"),
        }

        // Second call: addRange(4) → sum = 0+1+2+3 = 6, total = 10 + 6 = 16
        let r2 = vm.call_function("addRange", &[Value::U256(U256::from(4u32))])
            .expect("addRange(4) should execute");
        match r2 {
            Some(Value::U256(v)) => assert_eq!(v, U256::from(16u32),
                "after addRange(4), total should be 16, got {}", v),
            Some(Value::I32(v)) => assert_eq!(v, 16,
                "after addRange(4), total should be 16, got {}", v),
            _ => panic!("expected U256"),
        }

        // Verify via getter
        let total = vm.call_function("get_total", &[])
            .expect("get_total() should execute");
        match total {
            Some(Value::U256(v)) => assert_eq!(v, U256::from(16u32),
                "get_total should be 16, got {}", v),
            Some(Value::I32(v)) => assert_eq!(v, 16,
                "get_total should be 16, got {}", v),
            _ => panic!("expected U256"),
        }
    }

    #[test]
    fn test_ir_loop_continue() {
        // Test a loop with `continue` — exercises branching within a loop body.
        // countEven(10) counts even numbers 2,4,6,8,10 → 5
        let source = r#"pragma synq ^0.9;
contract ContinueTest {
    state {
        initialised: bool;
    }

    @public
    function init() -> bool {
        if (initialised) { return false; }
        initialised = true;
        return true;
    }

    @public
    function countEven(n: u256) -> u256 {
        let count: u256 = 0;
        let i: u256 = 1;
        while (i <= n) {
            let remainder: u256 = i % 2;
            if (remainder != 0) {
                i = i + 1;
                continue;
            }
            count = count + 1;
            i = i + 1;
        }
        return count;
    }
}
"#;

        let mut vm = compile_ir_and_load(source);
        vm.call_function("init", &[]).expect("init() should succeed");

        // countEven(10) = 5 (even numbers: 2,4,6,8,10)
        let result = vm.call_function("countEven", &[Value::U256(U256::from(10u32))])
            .expect("countEven(10) should execute");
        match result {
            Some(Value::U256(v)) => assert_eq!(v, U256::from(5u32),
                "countEven(10) should be 5, got {}", v),
            Some(Value::I32(v)) => assert_eq!(v, 5,
                "countEven(10) should be 5, got {}", v),
            other => panic!("countEven should return U256 or I32, got {:?}", other),
        }
    }

    #[test]
    fn test_ir_loop_sqrt_binary_search() {
        // Test binary search inside a loop — the overflow-safe sqrt pattern.
        // sqrtFloor(100) = 10, sqrtFloor(99) = 9, sqrtFloor(1000000) = 1000
        let source = r#"pragma synq ^0.9;
contract SqrtTest {
    state {
        initialised: bool;
    }

    @public
    function init() -> bool {
        if (initialised) { return false; }
        initialised = true;
        return true;
    }

    @public
    function sqrtFloor(target: u256) -> u256 {
        if (target == 0) { return 0; }
        let lo: u256 = 1;
        let hi: u256 = target;
        let mid: u256 = 0;
        let result: u256 = 0;
        while (lo <= hi) {
            mid = lo + (hi - lo) / 2;
            if (mid <= target / mid) {
                result = mid;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        return result;
    }
}
"#;

        let mut vm = compile_ir_and_load(source);
        vm.call_function("init", &[]).expect("init() should succeed");

        // sqrtFloor(100) = 10
        let r1 = vm.call_function("sqrtFloor", &[Value::U256(U256::from(100u32))])
            .expect("sqrtFloor(100) should execute");
        match r1 {
            Some(Value::U256(v)) => assert_eq!(v, U256::from(10u32),
                "sqrtFloor(100) should be 10, got {}", v),
            Some(Value::I32(v)) => assert_eq!(v, 10,
                "sqrtFloor(100) should be 10, got {}", v),
            _ => panic!("expected U256"),
        }

        // sqrtFloor(99) = 9
        let r2 = vm.call_function("sqrtFloor", &[Value::U256(U256::from(99u32))])
            .expect("sqrtFloor(99) should execute");
        match r2 {
            Some(Value::U256(v)) => assert_eq!(v, U256::from(9u32),
                "sqrtFloor(99) should be 9, got {}", v),
            Some(Value::I32(v)) => assert_eq!(v, 9,
                "sqrtFloor(99) should be 9, got {}", v),
            _ => panic!("expected U256"),
        }

        // sqrtFloor(1000000) = 1000
        let r3 = vm.call_function("sqrtFloor", &[Value::U256(U256::from(1000000u32))])
            .expect("sqrtFloor(1000000) should execute");
        match r3 {
            Some(Value::U256(v)) => assert_eq!(v, U256::from(1000u32),
                "sqrtFloor(1000000) should be 1000, got {}", v),
            Some(Value::I32(v)) => assert_eq!(v, 1000,
                "sqrtFloor(1000000) should be 1000, got {}", v),
            _ => panic!("expected U256"),
        }
    }

    #[test]
    fn test_ir_unary_not_negates_correctly() {
        // Regression test: UnaryOperator::Not was lowered as `(x == 1)`
        // (the identity function on 0/1 booleans) instead of `(x == 0)`
        // (true negation). This made `eq == !ne` always evaluate false
        // instead of always true, since eq and ne are always opposite.
        let source = r#"pragma synq ^0.9;
contract NotTest {
    state {
        initialised: bool;
    }

    @public
    function init() -> bool {
        if (initialised) { return false; }
        initialised = true;
        return true;
    }

    @public
    function testNot(a: u256, b: u256) -> bool {
        let eq = (a == b);
        let ne = (a != b);
        // eq and ne are always logical opposites, so eq == !ne must
        // always be true regardless of a and b.
        return eq == !ne;
    }

    @public
    function notOfFalse() -> bool {
        return !false;
    }

    @public
    function notOfTrue() -> bool {
        return !true;
    }
}
"#;

        let mut vm = compile_ir_and_load(source);
        vm.call_function("init", &[]).expect("init() should succeed");

        for (a, b) in [(5u32, 5u32), (3, 7), (7, 3), (0, 0), (100, 1)] {
            let r = vm.call_function("testNot", &[
                Value::U256(U256::from(a)),
                Value::U256(U256::from(b)),
            ]).expect("testNot should execute");
            match r {
                Some(Value::Bool(v)) => assert!(v,
                    "testNot({}, {}) should always be true, got {}", a, b, v),
                Some(Value::I32(v)) => assert_eq!(v, 1,
                    "testNot({}, {}) should always be true (1), got {}", a, b, v),
                Some(Value::U256(v)) => assert_eq!(v, U256::from(1u32),
                    "testNot({}, {}) should always be true (1), got {}", a, b, v),
                other => panic!("testNot({}, {}) unexpected result: {:?}", a, b, other),
            }
        }

        let rf = vm.call_function("notOfFalse", &[]).expect("notOfFalse should execute");
        match rf {
            Some(Value::Bool(v)) => assert!(v, "!false should be true, got {}", v),
            Some(Value::I32(v)) => assert_eq!(v, 1, "!false should be true (1), got {}", v),
            Some(Value::U256(v)) => assert_eq!(v, U256::from(1u32), "!false should be true (1), got {}", v),
            other => panic!("notOfFalse unexpected result: {:?}", other),
        }

        let rt = vm.call_function("notOfTrue", &[]).expect("notOfTrue should execute");
        match rt {
            Some(Value::Bool(v)) => assert!(!v, "!true should be false, got {}", v),
            Some(Value::I32(v)) => assert_eq!(v, 0, "!true should be false (0), got {}", v),
            Some(Value::U256(v)) => assert_eq!(v, U256::from(0u32), "!true should be false (0), got {}", v),
            other => panic!("notOfTrue unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_ir_backend_loop_bytecode() {
        // Verify that the IR backend produces correct bytecode for loops.
        // The IR backend uses a slot-based
        // approach, so byte-for-byte patterns are not the focus.
        // Instead, we verify it compiles and executes correctly.
        let source = r#"pragma synq ^0.9;
contract BytecodeMatchLoop {
    state {
        counter: u256;
        sum: u256;
        initialised: bool;
    }

    @public
    function init() -> bool {
        if (initialised) { return false; }
        counter = 0;
        sum = 0;
        initialised = true;
        return true;
    }

    @public
    function loop_sum(n: u256) -> bool {
        let i: u256 = 0;
        sum = 0;
        while (i < n) {
            sum = sum + i;
            i = i + 1;
        }
        counter = counter + n;
        return true;
    }

    @public
    function get_sum() -> u256 {
        return sum;
    }

    @public
    function get_counter() -> u256 {
        return counter;
    }
}
"#;

        // IR backend is the primary compilation path (v7.0)
        let result_ir = synq_compiler::compile_ir(source)
            .expect("IR compile should succeed");
        assert!(!result_ir.bytecode.is_empty(), "IR bytecode empty");

        // Should contain JumpIf (0x31) for the while loop
        let ir_code = &result_ir.bytecode[15..];
        assert!(ir_code.contains(&0x31), "IR should have JumpIf for while loop");

        // Execute IR-compiled bytecode
        let mut vm_ir = QuantumVM::new();
        vm_ir.load_bytecode(&result_ir.bytecode).expect("ir load");

        // init()
        let ir_init = vm_ir.call_function("init", &[]).expect("ir init");
        assert!(matches!(ir_init, Some(Value::Bool(true)) | Some(Value::I32(1))), "init should return true: {:?}", ir_init);

        // loop_sum(5) — should accumulate sum=10, counter=5
        let n = Value::U256(U256::from(5u32));
        let ir_loop = vm_ir.call_function("loop_sum", &[n.clone()]).expect("ir loop_sum");

        // Verify state vars
        let ir_sum = vm_ir.call_function("get_sum", &[]).expect("ir get_sum");
        let ir_ctr = vm_ir.call_function("get_counter", &[]).expect("ir get_counter");
        assert!(matches!(ir_sum, Some(Value::U256(ref v)) if *v == U256::from(10u32)) || matches!(ir_sum, Some(Value::I32(10))),
            "sum mismatch: got {:?}", ir_sum);
        assert!(matches!(ir_ctr, Some(Value::U256(ref v)) if *v == U256::from(5u32)) || matches!(ir_ctr, Some(Value::I32(5))),
            "counter mismatch: got {:?}", ir_ctr);
    }


    #[test]
    fn test_nested_map_allowance() {
        // Allowance contract with map<address, map<address, u256>>
        // Tests nested map reads, writes, and read-modify-write chains
        let source = r#"pragma synq ^0.9;
contract Allowance {
    state {
        allowances: map<address, map<address, u256>>;
        balances: map<address, u256>;
        initialised: bool;
    }

    @public
    function init() -> bool {
        if (initialised) { return true; }
        initialised = true;
        return true;
    }

    @public
    function deposit(who: address, amount: u256) -> bool {
        balances[who] = balances[who] + amount;
        return true;
    }

    @public
    function approve(owner: address, spender: address, amount: u256) -> bool {
        allowances[owner][spender] = amount;
        return true;
    }

    @public
    function get_balance(who: address) -> u256 {
        return balances[who];
    }

    @public
    function get_allowance(owner: address, spender: address) -> u256 {
        return allowances[owner][spender];
    }
}
"#;

        let mut vm = compile_ir_and_load(source);

        // init
        let r = vm.call_function("init", &[]).expect("init");
        match r {
            Some(Value::I32(1)) | Some(Value::Bool(true)) => {}
            other => panic!("init should return true, got {:?}", other),
        }

        // deposit(0xAABB, 1000)
        let addr1 = Value::Bytes(vec![0xAA, 0xBB, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let r = vm.call_function("deposit", &[addr1.clone(), Value::U256(U256::from(1000u32))])
            .expect("deposit");
        match r {
            Some(Value::I32(1)) | Some(Value::Bool(true)) => {}
            other => panic!("deposit should return true, got {:?}", other),
        }

        // get_balance(0xAABB) should be 1000
        let r = vm.call_function("get_balance", &[addr1.clone()])
            .expect("get_balance");
        match r {
            Some(Value::U256(v)) => assert_eq!(v, U256::from(1000u32), "balance should be 1000"),
            Some(Value::I32(v)) => assert_eq!(v, 1000, "balance should be 1000"),
            other => panic!("get_balance should return 1000, got {:?}", other),
        }

        // approve(0xAABB, 0xCCDD, 500) — nested write
        let addr2 = Value::Bytes(vec![0xCC, 0xDD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let r = vm.call_function("approve", &[addr1.clone(), addr2.clone(), Value::U256(U256::from(500u32))])
            .expect("approve");
        match r {
            Some(Value::I32(1)) | Some(Value::Bool(true)) => {}
            other => panic!("approve should return true, got {:?}", other),
        }

        // get_allowance(0xAABB, 0xCCDD) should be 500 — nested read
        let r = vm.call_function("get_allowance", &[addr1.clone(), addr2.clone()])
            .expect("get_allowance");
        match r {
            Some(Value::U256(v)) => assert_eq!(v, U256::from(500u32), "allowance should be 500"),
            Some(Value::I32(v)) => assert_eq!(v, 500, "allowance should be 500"),
            other => panic!("get_allowance should return 500, got {:?}", other),
        }
    }


    #[test]
    fn test_3level_nested_map() {
        // 3-level nested map: map<address, map<address, map<address, u256>>>
        // Domain registry: domain => record_type => record_name => value
        let source = r#"pragma synq ^0.9;
contract DomainRegistry {
    state {
        registry: map<address, map<address, map<address, u256>>>;
        initialised: bool;
    }

    @public
    function init() -> bool {
        if (initialised) { return true; }
        initialised = true;
        return true;
    }

    @public
    function set_record(domain: address, record_type: address, record_name: address, value: u256) -> bool {
        registry[domain][record_type][record_name] = value;
        return true;
    }

    @public
    function get_record(domain: address, record_type: address, record_name: address) -> u256 {
        return registry[domain][record_type][record_name];
    }
}
"#;

        let mut vm = compile_ir_and_load(source);

        // init
        let r = vm.call_function("init", &[]).expect("init");
        match r {
            Some(Value::I32(1)) | Some(Value::Bool(true)) => {}
            other => panic!("init should return true, got {:?}", other),
        }

        let addr1 = Value::Bytes(vec![0xAA; 20]);
        let addr2 = Value::Bytes(vec![0xBB; 20]);
        let addr3 = Value::Bytes(vec![0xCC; 20]);

        // set_record(0xAA, 0xBB, 0xCC, 42) — 3-level nested write
        let r = vm.call_function("set_record", &[addr1.clone(), addr2.clone(), addr3.clone(), Value::U256(U256::from(42u32))])
            .expect("set_record");
        match r {
            Some(Value::I32(1)) | Some(Value::Bool(true)) => {}
            other => panic!("set_record should return true, got {:?}", other),
        }

        // get_record(0xAA, 0xBB, 0xCC) should be 42 — 3-level nested read
        let r = vm.call_function("get_record", &[addr1.clone(), addr2.clone(), addr3.clone()])
            .expect("get_record");
        match r {
            Some(Value::U256(v)) => assert_eq!(v, U256::from(42u32), "record should be 42"),
            Some(Value::I32(v)) => assert_eq!(v, 42, "record should be 42"),
            other => panic!("get_record should return 42, got {:?}", other),
        }

        // get_record on uninitialized keys should return 0
        let addr4 = Value::Bytes(vec![0xDD; 20]);
        let r = vm.call_function("get_record", &[addr1.clone(), addr2.clone(), addr4.clone()])
            .expect("get_record unset");
        match r {
            Some(Value::U256(v)) => assert_eq!(v, U256::from(0u32), "unset record should be 0"),
            Some(Value::I32(v)) => assert_eq!(v, 0, "unset record should be 0"),
            other => panic!("unset get_record should return 0, got {:?}", other),
        }

        // Update existing record
        let r = vm.call_function("set_record", &[addr1.clone(), addr2.clone(), addr3.clone(), Value::U256(U256::from(99u32))])
            .expect("set_record update");
        match r {
            Some(Value::I32(1)) | Some(Value::Bool(true)) => {}
            other => panic!("set_record update should return true, got {:?}", other),
        }

        let r = vm.call_function("get_record", &[addr1, addr2, addr3])
            .expect("get_record after update");
        match r {
            Some(Value::U256(v)) => assert_eq!(v, U256::from(99u32), "updated record should be 99"),
            Some(Value::I32(v)) => assert_eq!(v, 99, "updated record should be 99"),
            other => panic!("updated get_record should return 99, got {:?}", other),
        }
    }


    #[test]
    fn test_ir_bitwise_and_shift_ops_full_width() {
        // Covers the new BitAnd/BitOr/BitXor/Shl/Shr/BitNot operators end-to-end
        // (grammar -> AST -> IR -> VM), specifically exercising the FULL
        // 256-bit range — not just u64/u128 — since that's the whole point
        // of these being u256-native ops.
        let source = r#"pragma synq ^0.9;
contract BitwiseTest {
    state {
        initialised: bool;
    }

    @public
    function init() -> bool {
        if (initialised) { return false; }
        initialised = true;
        return true;
    }

    @public
    function shiftLeftFull(bits: u256) -> u256 {
        let one: u256 = 1;
        return one << bits;
    }

    @public
    function shiftRightFull(x: u256, bits: u256) -> u256 {
        return x >> bits;
    }

    @public
    function bitAndOp(a: u256, b: u256) -> u256 {
        return a & b;
    }

    @public
    function bitOrOp(a: u256, b: u256) -> u256 {
        return a | b;
    }

    @public
    function bitXorOp(a: u256, b: u256) -> u256 {
        return a ^ b;
    }

    @public
    function bitNotOp(a: u256) -> u256 {
        return ~a;
    }

    @public
    function precedenceCheck() -> u256 {
        // & binds tighter than |: (6 & 3) | 8 = 2 | 8 = 10
        return 6 & 3 | 8;
    }
}
"#;

        let mut vm = compile_ir_and_load(source);
        vm.call_function("init", &[]).expect("init() should succeed");

        fn as_u256(r: Option<Value>) -> U256 {
            match r {
                Some(Value::U256(v)) => v,
                Some(Value::I32(v)) => U256::from(v as u64),
                other => panic!("expected U256-compatible result, got {:?}", other),
            }
        }

        // 1 << 255 — a value that only exists in the top half of a 256-bit
        // word; u64/u128 arithmetic could never produce this.
        let shifted = as_u256(vm.call_function("shiftLeftFull", &[Value::U256(U256::from(255u32))])
            .expect("shiftLeftFull(255) should execute"));
        let expected_2pow255 = U256::from(1u32) << U256::from(255u32);
        assert_eq!(shifted, expected_2pow255, "1 << 255 should equal 2^255");

        // Shift back down and recover 1.
        let back = as_u256(vm.call_function("shiftRightFull", &[Value::U256(expected_2pow255), Value::U256(U256::from(255u32))])
            .expect("shiftRightFull should execute"));
        assert_eq!(back, U256::from(1u32), "2^255 >> 255 should equal 1");

        // Shift amount >= 256 saturates to zero (EVM-style semantics), not a panic
        // and not a wrap-around modulo 256.
        let over_shift = as_u256(vm.call_function("shiftLeftFull", &[Value::U256(U256::from(300u32))])
            .expect("shiftLeftFull(300) should execute"));
        assert_eq!(over_shift, U256::ZERO, "1 << 300 should saturate to 0, not wrap");

        let over_shift_r = as_u256(vm.call_function("shiftRightFull", &[Value::U256(U256::from(1u32)), Value::U256(U256::from(256u32))])
            .expect("shiftRightFull(1, 256) should execute"));
        assert_eq!(over_shift_r, U256::ZERO, "1 >> 256 should saturate to 0");

        // BitAnd/BitOr/BitXor at the high end of the range.
        let high_a = expected_2pow255; // 2^255
        let high_b = expected_2pow255 - U256::from(1u32); // 2^255 - 1 (all lower bits set)
        let and_r = as_u256(vm.call_function("bitAndOp", &[Value::U256(high_a), Value::U256(high_b)])
            .expect("bitAndOp should execute"));
        assert_eq!(and_r, U256::ZERO, "2^255 & (2^255 - 1) should be 0 (disjoint bit ranges)");

        let or_r = as_u256(vm.call_function("bitOrOp", &[Value::U256(high_a), Value::U256(high_b)])
            .expect("bitOrOp should execute"));
        assert_eq!(or_r, high_a | high_b, "bitwise OR should combine both bit ranges");

        let xor_r = as_u256(vm.call_function("bitXorOp", &[Value::U256(high_a), Value::U256(high_a)])
            .expect("bitXorOp should execute"));
        assert_eq!(xor_r, U256::ZERO, "x ^ x should always be 0");

        // Full-width bitwise complement: ~0 must be ALL 256 bits set
        // (U256::MAX), not just the low 64/128 bits set.
        let not_zero = as_u256(vm.call_function("bitNotOp", &[Value::U256(U256::ZERO)])
            .expect("bitNotOp(0) should execute"));
        assert_eq!(not_zero, U256::MAX, "~0 should be U256::MAX across the full 256-bit width");

        let not_max = as_u256(vm.call_function("bitNotOp", &[Value::U256(U256::MAX)])
            .expect("bitNotOp(MAX) should execute"));
        assert_eq!(not_max, U256::ZERO, "~U256::MAX should be 0");

        // Operator precedence: & binds tighter than |.
        let prec = as_u256(vm.call_function("precedenceCheck", &[])
            .expect("precedenceCheck should execute"));
        assert_eq!(prec, U256::from(10u32), "(6 & 3) | 8 should be 10, not 6 & (3 | 8) = 6");
    }


    #[test]
    fn test_ir_shl_constant_fold_does_not_silently_truncate() {
        // Regression test for a real compile-time miscompilation:
        // BinaryOperator::Shl constant-folding guarded only on the shift
        // AMOUNT being < 128 (u128's bit width), not on whether the shifted
        // RESULT still fits in 128 bits. u128::checked_shl(r) never returns
        // None for r < 128 -- it just performs a truncating shift within
        // the fixed 128-bit width, silently discarding any bits pushed
        // past bit 127.
        //
        // Concretely: (2^100) << 50 is a perfectly valid u256 expression
        // (correct answer 2^150), but the old guard let it fold at COMPILE
        // TIME to 2u128.pow(100).checked_shl(50) == 0 (since 2^150 mod
        // 2^128 == 0) -- a wrong constant baked into the bytecode with no
        // error at all. This test proves the compiled contract now returns
        // the true 256-bit answer, not the old silently-truncated zero.
        let source = r#"pragma synq ^0.9;
contract ShlFoldTest {
    state {
        initialised: bool;
    }

    @public
    function init() -> bool {
        if (initialised) { return false; }
        initialised = true;
        return true;
    }

    @public
    function shiftLiteralOverflow() -> u256 {
        // 2^100 literal, shifted left by 50 -> true answer is 2^150.
        return 1267650600228229401496703205376 << 50;
    }
}
"#;

        let mut vm = compile_ir_and_load(source);
        vm.call_function("init", &[]).expect("init() should succeed");

        let r = vm.call_function("shiftLiteralOverflow", &[])
            .expect("shiftLiteralOverflow should execute");

        // 2^150, computed independently via runtime U256 shift (not the
        // buggy constant-folded path) to cross-check the expected value.
        let expected = U256::from(1u32) << U256::from(150u32);

        match r {
            Some(Value::U256(v)) => assert_eq!(v, expected,
                "(2^100) << 50 should equal 2^150, not a u128-truncated value (e.g. 0)"),
            other => panic!("shiftLiteralOverflow unexpected result: {:?}", other),
        }
    }
}
