//! AIVM execution engine — stack-based virtual machine
//!
//! Per synq-aivm-execution-spec.md:
//! - Deterministic (no wall-clock, randomness, network I/O)
//! - State overlay with commit/rollback
//! - Gas + PQ-Gas metering
//! - Deploy and call flows

use crate::context::ExecutionContext;
use sha2::Digest;
use crate::errors::AivmError;
use crate::gas::{GasMeter, PqGasMeter, gas_cost};
use crate::host::{HostFunctions, Value, execute_host_call, AssetLedger};
use crate::instructions::Instruction;
use ruint::aliases::U256;
use crate::receipt::{EventRecord, Receipt};

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

    /// Snapshot of all committed state after execution -- used by callers
    /// (e.g. the estimate-gas dry-run handler) that want to hand the
    /// resulting state back to the client so a *sequence* of dry-runs in
    /// the same UI session (e.g. init() then setCorner()) can chain state
    /// forward without a real deployment. This never touches disk or any
    /// session store -- it is just a read of the in-memory map that is
    /// about to be dropped when this StateOverlay goes out of scope.
    pub fn committed_snapshot(&self) -> &std::collections::HashMap<u16, Value> {
        &self.committed
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
    /// The actual `require(cond, "message")` / `revert Name(...)` text
    /// that caused a `Reverted` status, when the compiler emitted a
    /// `TrapMsg` for it (see that opcode's doc comment). `None` for a
    /// `Success` result, and also `None` for a plain `Trap` with no
    /// attached message (e.g. some host-level/authority reverts that
    /// don't go through `Statement::Require`/`Statement::RevertNamed` --
    /// not yet covered by this mechanism).
    pub revert_message: Option<String>,
}

/// Call frame for function calls
#[derive(Debug, Clone)]
struct CallFrame {
    return_pc: u32,
    locals: Vec<Value>,
}

/// The AIVM executor
/// Construct the "key not found" default value for a `MapGetVal` miss,
/// from the compiler-assigned type tag (see `Opcode::MapGetVal`'s doc
/// comment in instructions.rs for the full, authoritative tag table --
/// this must stay in sync with `map_value_default_tag` in
/// compiler/src/aivm_codegen.rs, which is what actually assigns tags).
/// Any tag this VM doesn't recognise (forward-compat: an older VM given
/// bytecode from a newer compiler) falls back to `Value::U64(0)`, the
/// same default every miss used before this tag existed.
fn map_get_miss_default(tag: u8) -> Value {
    match tag {
        1 => Value::Bool(false),
        2 => Value::String(String::new()),
        3 => Value::Bytes(vec![]),
        4 => Value::Bytes32([0u8; 32]),
        5 => Value::Address([0u8; 41]),
        6 => Value::Map(std::collections::BTreeMap::new()),
        _ => Value::U64(0),
    }
}

pub struct Avm {
    instructions: Vec<Instruction>,
    functions: Vec<FunctionEntry>,
    host: HostFunctions,
    /// Stack size limit
    stack_limit: usize,
    /// Call depth limit
    call_depth_limit: usize,
    /// Handler for `Instruction::ExternCall` (21 Sept 2026 -- real
    /// cross-contract call support). Mirrors the primary IR/VM backend's
    /// `QuantumVM::extern_call_handler` (vm/src/vm.rs) -- `None` by
    /// default (a bare `Avm::new()` behaves exactly as before: any
    /// `extern_call(...)` fails closed with a clear error instead of
    /// silently faking success). A caller that needs real cross-contract
    /// calls (e.g. synq-server's dry-run handler, wiring a per-request
    /// multi-contract workspace) sets this via `set_extern_call_handler`
    /// after construction, same opt-in shape as QuantumVM's mutable
    /// field, but via a setter since this struct's fields are private.
    extern_call_handler: Option<std::sync::Arc<dyn Fn(&str, &str, &[Value]) -> Result<Option<Value>, AivmError> + Send + Sync>>,
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
            extern_call_handler: None,
        }
    }

    /// Wire a real cross-contract call handler for `extern_call(...)` --
    /// see the `extern_call_handler` field doc. Opt-in; a plain `Avm::new`
    /// (no call to this) keeps today's fail-closed "no workspace active"
    /// behavior for any ExternCall instruction.
    pub fn set_extern_call_handler(
        &mut self,
        handler: std::sync::Arc<dyn Fn(&str, &str, &[Value]) -> Result<Option<Value>, AivmError> + Send + Sync>,
    ) {
        self.extern_call_handler = Some(handler);
    }

    /// Execute a function by index. Uses a fresh, throwaway asset ledger --
    /// see `execute_with_assets` if the caller needs asset records to be
    /// seeded from (or read back into) a ledger that outlives this call.
    pub fn execute(
        &self,
        func_index: u32,
        args: Vec<Value>,
        ctx: &ExecutionContext,
        state: &mut StateOverlay,
    ) -> Result<ExecutionResult, AivmError> {
        let mut assets = AssetLedger::new();
        self.execute_with_assets(func_index, args, ctx, state, &mut assets)
    }

    /// Same as `execute`, but takes the asset ledger by reference so the
    /// caller can pre-seed it (asset records carried over from a previous
    /// dry-run call) and read the resulting records back out afterwards --
    /// the same pattern `StateOverlay` already uses for regular state (see
    /// `AssetLedger`'s doc comment).
    pub fn execute_with_assets(
        &self,
        func_index: u32,
        args: Vec<Value>,
        ctx: &ExecutionContext,
        state: &mut StateOverlay,
        assets: &mut AssetLedger,
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
                Instruction::PushString(s) => {
                    gas.charge(gas_cost::PUSH_BYTES)?;
                    if stack.len() >= self.stack_limit {
                        return Err(AivmError::StackOverflow);
                    }
                    stack.push(Value::String(s.clone()));
                }
                Instruction::PushBool(b) => {
                    gas.charge(gas_cost::PUSH_U64)?;
                    if stack.len() >= self.stack_limit {
                        return Err(AivmError::StackOverflow);
                    }
                    stack.push(Value::Bool(*b));
                }
                Instruction::PushU256(bytes) => {
                    gas.charge(gas_cost::PUSH_U64)?;
                    if stack.len() >= self.stack_limit {
                        return Err(AivmError::StackOverflow);
                    }
                    stack.push(Value::U256(U256::from_be_bytes::<32>(*bytes)));
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
                // AddU64/SubU64/MulU64/DivU64/ModU64 (2026-09-09, U256
                // support): despite the "U64" opcode names (kept for
                // bytecode-history/readability reasons -- renaming the
                // opcode enum wasn't needed to fix this), these now widen
                // both operands to U256 via `as_u256()` before computing,
                // then narrow the result back down via
                // `Value::from_u256_shrink` -- U64 if it still fits (the
                // overwhelmingly common case, so ordinary small-number
                // arithmetic keeps producing the exact same Value::U64 and
                // JSON shape it always did), else U128, else a real U256.
                // Before this, `as_u64()` capped every operand at
                // `u64::MAX` and any genuine `u256` arithmetic on a value
                // above that (e.g. a large token amount) hard-errored with
                // TypeMismatch -- even though the value itself could
                // already be loaded/returned/compared fine via
                // Value::U128/U256, just never computed on.
                Instruction::AddU64 => {
                    gas.charge(gas_cost::ARITHMETIC)?;
                    let b = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    let a = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    let result = a.checked_add(b).ok_or(AivmError::ArithmeticOverflow)?;
                    stack.push(Value::from_u256_shrink(result));
                }
                Instruction::SubU64 => {
                    gas.charge(gas_cost::ARITHMETIC)?;
                    let b = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    let a = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    let result = a.checked_sub(b).ok_or(AivmError::ArithmeticUnderflow)?;
                    stack.push(Value::from_u256_shrink(result));
                }
                Instruction::MulU64 => {
                    gas.charge(gas_cost::ARITHMETIC)?;
                    let b = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    let a = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    let result = a.checked_mul(b).ok_or(AivmError::ArithmeticOverflow)?;
                    stack.push(Value::from_u256_shrink(result));
                }
                Instruction::DivU64 => {
                    gas.charge(gas_cost::DIVISION)?;
                    let b = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    let a = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    if b == U256::ZERO {
                        return Err(AivmError::DivisionByZero);
                    }
                    stack.push(Value::from_u256_shrink(a / b));
                }
                Instruction::ModU64 => {
                    gas.charge(gas_cost::DIVISION)?;
                    let b = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    let a = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    if b == U256::ZERO {
                        return Err(AivmError::DivisionByZero);
                    }
                    stack.push(Value::from_u256_shrink(a % b));
                }
                // BitAnd/BitOr/BitXor/Shl/Shr (2026-09-14, bitwise/shift
                // support): AIVM previously had no bitwise/shift opcodes at
                // all -- aivm_codegen.rs hard-errored "not supported on the
                // AIVM backend, use the IR/VM path" for `& | ^ << >>` (and
                // `~`, synthesized by the compiler as `x XOR 0xFF..FF` --
                // see UnaryOperator::BitNot in aivm_codegen.rs, no dedicated
                // opcode needed). Same widen-to-U256-then-narrow pattern as
                // the AddU64/SubU64/etc arithmetic fix: both operands go
                // through as_u256(), the op runs at full 256-bit width via
                // ruint::aliases::U256's own bit ops (the exact same type
                // and operators the IR/VM path already used at
                // vm/src/vm.rs's BitAnd/BitOr/BitXor/Shl/Shr), result
                // narrows back via Value::from_u256_shrink. Shift amounts
                // >= 256 saturate to zero (ruint's Shl/Shr impls already
                // implement this -- no separate check needed here).
                Instruction::BitAnd => {
                    gas.charge(gas_cost::BITWISE)?;
                    let b = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    let a = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    stack.push(Value::from_u256_shrink(a & b));
                }
                Instruction::BitOr => {
                    gas.charge(gas_cost::BITWISE)?;
                    let b = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    let a = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    stack.push(Value::from_u256_shrink(a | b));
                }
                Instruction::BitXor => {
                    gas.charge(gas_cost::BITWISE)?;
                    let b = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    let a = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    stack.push(Value::from_u256_shrink(a ^ b));
                }
                Instruction::Shl => {
                    gas.charge(gas_cost::BITWISE)?;
                    let b = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    let a = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    stack.push(Value::from_u256_shrink(a << b));
                }
                Instruction::Shr => {
                    gas.charge(gas_cost::BITWISE)?;
                    let b = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    let a = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    stack.push(Value::from_u256_shrink(a >> b));
                }
                Instruction::Eq => {
                    gas.charge(gas_cost::COMPARISON)?;
                    let b = stack.pop().ok_or(AivmError::StackUnderflow)?;
                    let a = stack.pop().ok_or(AivmError::StackUnderflow)?;
                    // U256 support (2026-09-09): if both operands are
                    // numeric-widenable, compare numerically -- otherwise
                    // e.g. a Value::U64(3) state var and a Value::U256(3)
                    // arithmetic result (or a literal too big for U64) can
                    // never structurally == each other even though they're
                    // the same number, once U256 exists as a distinct
                    // variant. Falls back to plain structural equality for
                    // non-numeric values (strings/bytes/bools/arrays/maps),
                    // exactly as before.
                    let result = match (a.as_u256(), b.as_u256()) {
                        (Ok(av), Ok(bv)) => av == bv,
                        _ => a == b,
                    };
                    stack.push(Value::Bool(result));
                }
                // Lt/Gt/Ne/Le/Ge use as_u256 (not as_u64) for two reasons
                // (2026-08-25): (1) SynQ's u256 type downcasts to
                // Value::U128 in AIVM's numeric model, so u64 was already
                // too narrow -- two legitimate large token amounts near
                // u128::MAX would wrongly TypeMismatch-error here even
                // though they're valid, comparable numbers. (2) Value::
                // Address (what `caller()` always produces) only has an
                // as_u128 identity projection, not as_u64 -- see
                // host.rs's as_u128 doc comment -- so source like
                // `require(to != caller, ...)` (transfer/revokeAdmin/
                // revokeMinter in ComprehensiveToken.synq) used to crash
                // with TypeMismatch{expected:"u64", got:"address"} on
                // every call, for every caller. as_u64-based comparisons
                // still exist elsewhere (arithmetic opcodes, asset host
                // functions) where u64 range is the deliberate contract;
                // this widening is scoped to just these five comparison
                // opcodes.
                Instruction::Lt => {
                    gas.charge(gas_cost::COMPARISON)?;
                    let b = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    let a = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    stack.push(Value::Bool(a < b));
                }
                Instruction::Gt => {
                    gas.charge(gas_cost::COMPARISON)?;
                    let b = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    let a = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    stack.push(Value::Bool(a > b));
                }
                Instruction::Ne => {
                    gas.charge(gas_cost::COMPARISON)?;
                    let b = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    let a = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    stack.push(Value::Bool(a != b));
                }
                Instruction::Le => {
                    gas.charge(gas_cost::COMPARISON)?;
                    let b = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    let a = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    stack.push(Value::Bool(a <= b));
                }
                Instruction::Ge => {
                    gas.charge(gas_cost::COMPARISON)?;
                    let b = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    let a = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
                    stack.push(Value::Bool(a >= b));
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
                        revert_message: None,
                    });
                }
                Instruction::TrapMsg(code, msg) => {
                    gas.charge(gas_cost::TRAP)?;
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
                        revert_message: Some(msg.clone()),
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
                        assets,
                        &mut pq_gas,
                    )?;
                }
                Instruction::Pack(count) => {
                    // Struct/array construction: pop `count` values (they were
                    // pushed field-by-field in declaration order, so the LAST
                    // push is on TOP of the stack) and repack them into a
                    // single Value::Array in original field order.
                    gas.charge(gas_cost::PACK_BASE + gas_cost::PACK_PER_FIELD * (*count as u64))?;
                    let n = *count as usize;
                    let mut items = Vec::with_capacity(n);
                    for _ in 0..n {
                        items.push(stack.pop().ok_or(AivmError::StackUnderflow)?);
                    }
                    items.reverse();
                    stack.push(Value::Array(items));
                }
                Instruction::ArrayGet(index) => {
                    // Struct field access: pop an array value, push the
                    // element at `index` (the field's position in the
                    // struct's declared field order).
                    gas.charge(gas_cost::ARRAY_GET)?;
                    let top = stack.pop().ok_or(AivmError::StackUnderflow)?;
                    match top {
                        Value::Array(arr) => {
                            let i = *index as usize;
                            if i >= arr.len() {
                                return Err(AivmError::OutOfBoundsAccess { index: i, len: arr.len() });
                            }
                            stack.push(arr[i].clone());
                        }
                        other => {
                            return Err(AivmError::TypeMismatch { expected: "Array", got: other.type_name() });
                        }
                    }
                }
                Instruction::ArraySet(index) => {
                    // Struct field assignment: pop [value, array] (value on
                    // top -- pushed after the array), set array[index] =
                    // value, push the updated array back so the caller can
                    // StoreState/StoreLocal it as a whole.
                    gas.charge(gas_cost::ARRAY_SET)?;
                    let value = stack.pop().ok_or(AivmError::StackUnderflow)?;
                    let top = stack.pop().ok_or(AivmError::StackUnderflow)?;
                    match top {
                        Value::Array(mut arr) => {
                            let i = *index as usize;
                            if i >= arr.len() {
                                return Err(AivmError::OutOfBoundsAccess { index: i, len: arr.len() });
                            }
                            arr[i] = value;
                            stack.push(Value::Array(arr));
                        }
                        other => {
                            return Err(AivmError::TypeMismatch { expected: "Array", got: other.type_name() });
                        }
                    }
                }
                Instruction::MapGetVal(default_tag) => {
                    // `map_value[key]` read. Pop [key, map] (key on top).
                    // If `map` isn't a real Value::Map yet -- e.g. this
                    // state slot was never written, or (for a nested
                    // map[k1][k2] read) the outer map didn't have `k1` --
                    // or the key just isn't present, treat it as an empty
                    // map and return a MISS DEFAULT -- but a type-correct
                    // one, not always `Value::U64(0)` (2026-08-25 fix; see
                    // this opcode's doc comment in instructions.rs for the
                    // full tag table and why a blind U64(0) broke
                    // `map<K,bool>[missing] == false` checks). The tag is
                    // baked in by the compiler from the map's declared
                    // value type, so this is still the *same* MapGetVal
                    // opcode chaining cleanly through arbitrarily nested
                    // map reads -- it just now carries one extra byte of
                    // "what should a miss look like at this level" info.
                    gas.charge(gas_cost::MAP_GET)?;
                    let key = stack.pop().ok_or(AivmError::StackUnderflow)?;
                    let map_val = stack.pop().ok_or(AivmError::StackUnderflow)?;
                    let miss_default = || map_get_miss_default(*default_tag);
                    let result = match map_val {
                        Value::Map(m) => {
                            let k = key.map_key_bytes();
                            m.get(&k).cloned().unwrap_or_else(miss_default)
                        }
                        _ => miss_default(),
                    };
                    stack.push(result);
                }
                Instruction::MapSetVal => {
                    // `map_value[key] = value`. Pop [value, key, map]
                    // (value on top, pushed last), push the *updated* map
                    // back (does not touch state directly -- the caller
                    // chains this into StoreState, or into an outer
                    // MapSetVal for nested writes, exactly mirroring
                    // ArraySet's "push the updated container back" shape).
                    // If the popped `map` value wasn't already a real
                    // Value::Map (never written, or a nested level that
                    // didn't exist yet), auto-initialize an empty map
                    // instead of erroring -- matches this VM's existing
                    // "auto-init on write" philosophy (see StoreLocal's
                    // auto-resize above).
                    gas.charge(gas_cost::MAP_SET)?;
                    let value = stack.pop().ok_or(AivmError::StackUnderflow)?;
                    let key = stack.pop().ok_or(AivmError::StackUnderflow)?;
                    let map_val = stack.pop().ok_or(AivmError::StackUnderflow)?;
                    let mut m = match map_val {
                        Value::Map(m) => m,
                        _ => std::collections::BTreeMap::new(),
                    };
                    m.insert(key.map_key_bytes(), value);
                    stack.push(Value::Map(m));
                }
                Instruction::ExternCall(contract, function, arg_count) => {
                    // Real cross-contract call (21 Sept 2026), ported from
                    // vm/src/vm.rs's OpCode::ExternCall -- see
                    // Instruction::ExternCall's doc and
                    // Avm::extern_call_handler's doc for the full design.
                    gas.charge(gas_cost::EXTERN_CALL)?;
                    let n = *arg_count as usize;
                    if stack.len() < n {
                        return Err(AivmError::StackUnderflow);
                    }
                    let mut args: Vec<Value> = Vec::with_capacity(n);
                    for _ in 0..n {
                        args.push(stack.pop().ok_or(AivmError::StackUnderflow)?);
                    }
                    args.reverse(); // restore original push/source order
                    let result = match &self.extern_call_handler {
                        Some(h) => h(contract, function, &args)?,
                        None => return Err(AivmError::HostFunctionFailed(format!(
                            "extern_call: no workspace active — '{}' not reachable", contract
                        ))),
                    };
                    stack.push(result.unwrap_or(Value::U64(0)));
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
            revert_message: None,
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
                revert_message: None,
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
