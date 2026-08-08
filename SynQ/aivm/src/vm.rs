//! AIVM execution engine — stack-based virtual machine
//!
//! Per synq-aivm-execution-spec.md:
//! - Deterministic (no wall-clock, randomness, network I/O)
//! - State overlay with commit/rollback
//! - Gas + PQ-Gas metering
//! - Deploy and call flows

use crate::context::ExecutionContext;
use sha2::Digest;
use crate::errors::{AivmError, TrapCode};
use crate::gas::{GasMeter, PqGasMeter, gas_cost};
use crate::host::{HostFunctions, Value, execute_host_call};
use crate::instructions::{Instruction, Opcode};
use crate::receipt::{EventRecord, Receipt, ReceiptStatus};

/// State overlay — staged writes that commit on success, rollback on trap
#[derive(Debug, Clone)]
pub struct StateOverlay {
    /// Committed state (read from here first)
    committed: std::collections::HashMap<u16, Value>,
    /// Staged writes (uncommitted)
    staged: std::collections::HashMap<u16, Value>,
}

impl StateOverlay {
    pub fn new() -> Self {
        Self {
            committed: std::collections::HashMap::new(),
            staged: std::collections::HashMap::new(),
        }
    }

    pub fn with_state(state: std::collections::HashMap<u16, Value>) -> Self {
        Self {
            committed: state,
            staged: std::collections::HashMap::new(),
        }
    }

    /// Read a state key (checks staged first, then committed)
    pub fn read(&self, key: u16) -> Option<Value> {
        self.staged.get(&key).cloned().or_else(|| self.committed.get(&key).cloned())
    }

    /// Write a state key (staged)
    pub fn write(&mut self, key: u16, value: Value) {
        self.staged.insert(key, value);
    }

    /// Commit staged writes to committed
    pub fn commit(&mut self) {
        for (k, v) in self.staged.drain() {
            self.committed.insert(k, v);
        }
    }

    /// Rollback staged writes
    pub fn rollback(&mut self) {
        self.staged.clear();
    }

    /// Compute state root (SHA-256 of sorted key-value pairs)
    pub fn state_root(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        let mut entries: Vec<(u16, Vec<u8>)> = Vec::new();

        // Collect committed state
        for (k, v) in &self.committed {
            entries.push((*k, v.encode()));
        }
        // Override with staged
        for (k, v) in &self.staged {
            if let Some(pos) = entries.iter().position(|(key, _)| key == k) {
                entries[pos] = (*k, v.encode());
            } else {
                entries.push((*k, v.encode()));
            }
        }
        entries.sort_by_key(|(k, _)| *k);

        for (k, v) in &entries {
            hasher.update(k.to_be_bytes());
            hasher.update(&(v.len() as u32).to_be_bytes());
            hasher.update(v);
        }

        hasher.finalize().into()
    }
}

/// Function table entry — maps function index to instruction offset
#[derive(Debug, Clone)]
pub struct FunctionEntry {
    pub name: String,
    pub instruction_offset: u32,
    pub param_count: u16,
    pub visibility: FunctionVisibility,
    pub mutability: FunctionMutability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionVisibility {
    Public,
    Private,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionMutability {
    View,
    Write,
}

/// AIVM execution result
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub receipt: Receipt,
    pub return_value: Option<Value>,
}

/// Call frame for function calls
#[derive(Debug, Clone)]
struct CallFrame {
    return_pc: u32,
    locals: Vec<Value>,
}

/// The AIVM executor
pub struct Avm {
    instructions: Vec<Instruction>,
    functions: Vec<FunctionEntry>,
    host: HostFunctions,
    /// Stack size limit
    stack_limit: usize,
    /// Call depth limit
    call_depth_limit: usize,
}

impl Avm {
    /// Create a new AIVM executor
    pub fn new(
        instructions: Vec<Instruction>,
        functions: Vec<FunctionEntry>,
        host: HostFunctions,
    ) -> Self {
        Self {
            instructions,
            functions,
            host,
            stack_limit: 1024,
            call_depth_limit: 64,
        }
    }

    /// Execute a function by index
    pub fn execute(
        &self,
        func_index: u32,
        args: Vec<Value>,
        ctx: &ExecutionContext,
        state: &mut StateOverlay,
    ) -> Result<ExecutionResult, AivmError> {
        let func = self.functions.get(func_index as usize)
            .ok_or(AivmError::InvalidFunctionIndex(func_index))?;

        if args.len() != func.param_count as usize {
            return Err(AivmError::AbiArgumentEncodingError(format!(
                "function {} expects {} args, got {}",
                func.name, func.param_count, args.len()
            )));
        }

        let state_root_before = state.state_root();
        let mut gas = GasMeter::new(ctx.gas_limit);
        let mut pq_gas = PqGasMeter::new(ctx.pq_gas_limit);
        let mut events = Vec::new();

        // Set up initial frame with args as locals
        let mut frame = CallFrame {
            return_pc: u32::MAX, // top-level: halt on RET
            locals: args,
        };

        let mut stack: Vec<Value> = Vec::new();
        let mut call_stack: Vec<CallFrame> = Vec::new();
        let mut pc = func.instruction_offset;

        loop {
            if pc as usize >= self.instructions.len() {
                return Err(AivmError::InvalidJumpTarget(pc));
            }

            let instr = &self.instructions[pc as usize];
            pc += 1; // advance past current instruction

            match instr {
                Instruction::Nop => {
                    gas.charge(gas_cost::NOP)?;
                }
                Instruction::PushU64(v) => {
                    gas.charge(gas_cost::PUSH_U64)?;
                    if stack.len() >= self.stack_limit {
                        return Err(AivmError::StackOverflow);
                    }
                    stack.push(Value::U64(*v));
                }
                Instruction::PushBytes(data) => {
                    gas.charge(gas_cost::PUSH_BYTES)?;
                    if stack.len() >= self.stack_limit {
                        return Err(AivmError::StackOverflow);
                    }
                    stack.push(Value::Bytes(data.clone()));
                }
                Instruction::LoadState(key) => {
                    gas.charge(gas_cost::LOAD_STATE)?;
                    let val = state.read(*key).unwrap_or(Value::U64(0));
                    stack.push(val);
                }
                Instruction::StoreState(key) => {
                    gas.charge(gas_cost::STORE_STATE)?;
                    let val = stack.pop().ok_or(AivmError::StackUnderflow)?;
                    state.write(*key, val);
                }
                Instruction::LoadLocal(idx) => {
                    gas.charge(gas_cost::LOAD_LOCAL)?;
                    let val = frame.locals.get(*idx as usize)
                        .cloned()
                        .unwrap_or(Value::U64(0));
                    stack.push(val);
                }
                Instruction::StoreLocal(idx) => {
                    gas.charge(gas_cost::STORE_LOCAL)?;
                    let val = stack.pop().ok_or(AivmError::StackUnderflow)?;
                    if *idx as usize >= frame.locals.len() {
                        frame.locals.resize(*idx as usize + 1, Value::U64(0));
                    }
                    frame.locals[*idx as usize] = val;
                }
                Instruction::AddU64 => {
                    gas.charge(gas_cost::ARITHMETIC)?;
                    let b = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u64()?;
                    let a = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u64()?;
                    let result = a.checked_add(b)
                        .ok_or_else(|| {
                            // Rollback and trap
                            AivmError::ArithmeticOverflow
                        })?;
                    stack.push(Value::U64(result));
                }
                Instruction::SubU64 => {
                    gas.charge(gas_cost::ARITHMETIC)?;
                    let b = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u64()?;
                    let a = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u64()?;
                    let result = a.checked_sub(b)
                        .ok_or(AivmError::ArithmeticUnderflow)?;
                    stack.push(Value::U64(result));
                }
                Instruction::MulU64 => {
                    gas.charge(gas_cost::ARITHMETIC)?;
                    let b = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u64()?;
                    let a = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u64()?;
                    let result = a.checked_mul(b)
                        .ok_or(AivmError::ArithmeticOverflow)?;
                    stack.push(Value::U64(result));
                }
                Instruction::DivU64 => {
                    gas.charge(gas_cost::DIVISION)?;
                    let b = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u64()?;
                    let a = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u64()?;
                    if b == 0 {
                        return Err(AivmError::DivisionByZero);
                    }
                    stack.push(Value::U64(a / b));
                }
                Instruction::Eq => {
                    gas.charge(gas_cost::COMPARISON)?;
                    let b = stack.pop().ok_or(AivmError::StackUnderflow)?;
                    let a = stack.pop().ok_or(AivmError::StackUnderflow)?;
                    stack.push(Value::Bool(a == b));
                }
                Instruction::Lt => {
                    gas.charge(gas_cost::COMPARISON)?;
                    let b = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u64()?;
                    let a = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u64()?;
                    stack.push(Value::Bool(a < b));
                }
                Instruction::Gt => {
                    gas.charge(gas_cost::COMPARISON)?;
                    let b = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u64()?;
                    let a = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u64()?;
                    stack.push(Value::Bool(a > b));
                }
                Instruction::Jmp(target) => {
                    gas.charge(gas_cost::JUMP)?;
                    // Validate jump target
                    if *target as usize >= self.instructions.len() {
                        return Err(AivmError::InvalidJumpTarget(*target));
                    }
                    pc = *target;
                }
                Instruction::JmpIf(target) => {
                    gas.charge(gas_cost::JUMP)?;
                    let cond = stack.pop().ok_or(AivmError::StackUnderflow)?.as_bool()?;
                    if cond {
                        if *target as usize >= self.instructions.len() {
                            return Err(AivmError::InvalidJumpTarget(*target));
                        }
                        pc = *target;
                    }
                }
                Instruction::Call(func_idx) => {
                    gas.charge(gas_cost::CALL)?;
                    if call_stack.len() >= self.call_depth_limit {
                        return Err(AivmError::StackOverflow);
                    }
                    let callee = self.functions.get(*func_idx as usize)
                        .ok_or(AivmError::InvalidFunctionIndex(*func_idx))?;

                    // Pop args from stack
                    let n = callee.param_count as usize;
                    if stack.len() < n {
                        return Err(AivmError::StackUnderflow);
                    }
                    let args: Vec<Value> = stack.split_off(stack.len() - n);

                    // Save current frame
                    let saved_frame = CallFrame {
                        return_pc: pc,
                        locals: frame.locals.clone(),
                    };
                    call_stack.push(saved_frame);

                    // New frame
                    frame = CallFrame {
                        return_pc: pc, // will be overwritten
                        locals: args,
                    };
                    pc = callee.instruction_offset;
                }
                Instruction::Ret => {
                    gas.charge(gas_cost::RET)?;
                    if let Some(saved) = call_stack.pop() {
                        // Return to caller
                        frame = CallFrame {
                            return_pc: saved.return_pc,
                            locals: saved.locals,
                        };
                        pc = saved.return_pc;
                    } else {
                        // Top-level return — done
                        break;
                    }
                }
                Instruction::Emit(event_idx) => {
                    gas.charge(gas_cost::EMIT)?;
                    let data = stack.pop().ok_or(AivmError::StackUnderflow)?;
                    let topic: [u8; 32] = sha2::Sha256::digest(&data.encode()).into();
                    events.push(EventRecord {
                        event_index: *event_idx as u32,
                        topic_hash: topic,
                        data: data.encode(),
                    });
                }
                Instruction::Trap(code) => {
                    gas.charge(gas_cost::TRAP)?;
                    let trap_code = TrapCode::from(*code);
                    state.rollback();
                    let receipt = Receipt::trap(
                        ctx,
                        gas.used,
                        pq_gas.used,
                        state_root_before,
                        *code,
                    );
                    return Ok(ExecutionResult {
                        receipt,
                        return_value: None,
                    });
                }
                Instruction::HostCall(import_idx) => {
                    gas.charge(gas_cost::HOST_CALL)?;
                    execute_host_call(
                        *import_idx,
                        &self.host,
                        ctx,
                        state,
                        &mut stack,
                        &mut events,
                    )?;
                }
            }
        }

        // Success — commit state
        state.commit();
        let return_value = stack.pop();
        let state_root_after = state.state_root();

        let receipt = Receipt::success(
            ctx,
            gas.used,
            pq_gas.used,
            state_root_before,
            state_root_after,
            return_value.as_ref().map(|v| v.encode()).unwrap_or_default(),
            events,
        );

        Ok(ExecutionResult {
            receipt,
            return_value,
        })
    }

    /// Execute a deploy (runs init/constructor if present)
    pub fn deploy(
        &self,
        init_func_index: Option<u32>,
        init_args: Vec<Value>,
        ctx: &ExecutionContext,
        state: &mut StateOverlay,
    ) -> Result<ExecutionResult, AivmError> {
        if let Some(idx) = init_func_index {
            self.execute(idx, init_args, ctx, state)
        } else {
            // No constructor — just compute state root
            let state_root = state.state_root();
            let receipt = Receipt::success(
                ctx,
                0,
                0,
                state_root,
                state_root,
                Vec::new(),
                Vec::new(),
            );
            Ok(ExecutionResult {
                receipt,
                return_value: None,
            })
        }
    }

    /// Find a public function by name
    pub fn find_function(&self, name: &str) -> Option<u32> {
        self.functions.iter()
            .position(|f| f.name == name && f.visibility == FunctionVisibility::Public)
            .map(|i| i as u32)
    }

    /// Get all public function names
    pub fn public_functions(&self) -> Vec<&str> {
        self.functions.iter()
            .filter(|f| f.visibility == FunctionVisibility::Public)
            .map(|f| f.name.as_str())
            .collect()
    }
}
