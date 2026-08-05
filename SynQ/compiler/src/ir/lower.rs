// ── IR → Bytecode Lowering (Backend) ──────────────────────────────────────────
//
// Lowers the SSA IR to QVM stack bytecode. This is the v7.0 backend that
// IR → bytecode lowering (sole compilation path).
//
// Approach:
//   • Slot-based: each SSA value gets a memory slot (address).
//   • Phi deconstruction: predecessors store phi values to slots before
//     jumping; phi blocks read from slots (phi is a no-op).
//   • Block linearization: DFS order from entry, with jumps for non-fallthrough.
//   • Jump patching: two-pass — emit all blocks, then patch jump targets.
//
// This produces correct but verbose bytecode (Load/Store for every value).
// Future optimization: stack scheduling to reduce Load/Store pairs.

use std::collections::HashMap;
use quantumvm::{Assembler, OpCode};
use crate::ast::{Literal, BinaryOperator, UnaryOperator, SetOpKind};
use super::types::*;
use super::instructions::*;
use super::blocks::*;
use super::function::*;
use super::module::*;

/// Slot base for SSA intermediate values — well above state vars (0-N)
/// and function locals (1024+).
const SSA_SLOT_BASE: u32 = 2048;
/// Maximum SSA value slots per function. Must be large enough for any
/// single function's SSA values (instructions with non-void result_type).
const SSA_SLOTS_PER_FUNC: u32 = 512;

/// IR → bytecode lowerer.
pub struct IrLowerer {
    asm: Assembler,
    /// State var name → memory address.
    state_var_addrs: HashMap<String, u32>,
    /// Parameter name → memory address (per function).
    param_addrs: HashMap<String, u32>,
    /// Local variable name (__local_*) → memory address (per function).
    local_var_addrs: HashMap<String, u32>,
    /// Next available local variable address.
    next_local_addr: u32,
    /// Per-function param addresses saved for dispatch table.
    all_param_addrs: HashMap<String, HashMap<String, u32>>,
    /// SSA value (global ValueId) → memory slot address.
    value_slots: HashMap<ValueId, u32>,
    /// Next available slot address.
    next_slot: u32,
    /// Per-function slot base (incremented by SSA_SLOTS_PER_FUNC per function).
    func_slot_base: u32,
    /// Block ID → code position (for jump patching).
    block_positions: HashMap<BlockId, u32>,
    /// Pending jump patches: (patch_offset, target_block_id).
    pending_jumps: Vec<(usize, BlockId)>,
    /// Function name → entry code position.
    function_entries: HashMap<String, u32>,
    /// Phi stores: for each predecessor block, list of (value_id, phi_slot)
    /// to store before the terminator.
    phi_stores: HashMap<BlockId, Vec<(ValueId, u32)>>,
    /// Pending call patches: (placeholder_offset, callee_name).
    pending_call_patches: Vec<(usize, String)>,
}

impl IrLowerer {
    pub fn new() -> Self {
        Self {
            asm: Assembler::new(),
            state_var_addrs: HashMap::new(),
            param_addrs: HashMap::new(),
            local_var_addrs: HashMap::new(),
            next_local_addr: 0,
            all_param_addrs: HashMap::new(),
            value_slots: HashMap::new(),
            next_slot: SSA_SLOT_BASE,
            func_slot_base: SSA_SLOT_BASE,
            block_positions: HashMap::new(),
            pending_jumps: Vec::new(),
            function_entries: HashMap::new(),
            phi_stores: HashMap::new(),
            pending_call_patches: Vec::new(),
        }
    }

    /// Lower a complete IR module to QVM bytecode.
    pub fn lower(module: &IrModule) -> Result<Vec<u8>, String> {
        let mut lowerer = IrLowerer::new();

        // Register state var addresses
        for (name, _ty, addr) in &module.state_vars {
            lowerer.state_var_addrs.insert(name.clone(), *addr);
        }

        // Collect all function names (for call resolution)
        for func in &module.functions {
            lowerer.function_entries.insert(func.name.clone(), 0); // placeholder
        }

        // Pre-compute param addresses for all functions (for Call arg marshaling)
        {
            const BASE: u32 = 1024;
            const STRIDE: u32 = 16;
            for (fidx, func) in module.functions.iter().enumerate() {
                let mut p_addrs = HashMap::new();
                for (i, (name, _ty)) in func.params.iter().enumerate() {
                    let addr = BASE + (fidx as u32) * STRIDE + i as u32;
                    p_addrs.insert(name.clone(), addr);
                }
                lowerer.all_param_addrs.insert(func.name.clone(), p_addrs);
            }
        }

        // Lower each function
        for func in &module.functions {
            lowerer.lower_function(func, module)?;
        }

        // Patch all pending jumps
        lowerer.patch_jumps()?;

        // Patch all pending call targets (function name → code address)
        lowerer.patch_calls()?;

        // Build function dispatch table in data section
        for func in &module.functions {
            let entry = *lowerer.function_entries.get(&func.name)
                .ok_or_else(|| format!("missing entry for {}", func.name))?;
            let saved_params = lowerer.all_param_addrs.get(&func.name);
            let p_addrs: Vec<u32> = func.params.iter()
                .map(|(name, _)| {
                    saved_params.and_then(|m| m.get(name))
                        .copied()
                        .unwrap_or(SSA_SLOT_BASE)
                })
                .collect();
            lowerer.asm.add_function_entry(
                &func.name,
                entry,
                &p_addrs,
                &vec![false; p_addrs.len()],
                func.return_type.is_some(),
                func.requires_caller,
                &[],
            );
        }

        Ok(lowerer.asm.build())
    }

    fn lower_function(&mut self, func: &IrFunction, module: &IrModule) -> Result<(), String> {
        // Reset per-function state
        self.value_slots.clear();
        // ── Slot aliasing fix ───────────────────────────────────────────
        // Each function must use a DISJOINT slot range. If two functions
        // share the same SSA_SLOT_BASE, a Call from one to the other will
        // overwrite the caller's value slots in VM memory, corrupting the
        // caller's state. This is critical for Call-inside-loop patterns.
        //
        // Allocation: function fidx gets slots starting at
        //   SSA_SLOT_BASE + fidx * SSA_SLOTS_PER_FUNC
        // where SSA_SLOTS_PER_FUNC is large enough for any function.
        self.next_slot = self.func_slot_base;
        self.func_slot_base += SSA_SLOTS_PER_FUNC;
        self.block_positions.clear();
        self.pending_jumps.clear();
        self.param_addrs.clear();
        self.local_var_addrs.clear();
        // Local addresses start after state vars
        self.next_local_addr = self.state_var_addrs.len() as u32;

        // Assign parameter addresses
        // Use pre-computed param addresses (consistent with Call arg marshaling)
        if let Some(precomputed) = self.all_param_addrs.get(&func.name) {
            self.param_addrs = precomputed.clone();
        } else {
            const FUNCTION_LOCAL_BASE: u32 = 1024;
            const FUNCTION_LOCAL_STRIDE: u32 = 16;
            let fidx = module.functions.iter().position(|f| f.name == func.name)
                .unwrap_or(0);
            for (i, (name, _ty)) in func.params.iter().enumerate() {
                let addr = FUNCTION_LOCAL_BASE + (fidx as u32) * FUNCTION_LOCAL_STRIDE + i as u32;
                self.param_addrs.insert(name.clone(), addr);
            }
        }

        // Record function entry position
        let entry_pos = self.asm.current_pos() as u32;
        self.function_entries.insert(func.name.clone(), entry_pos);

        // ── Authority prologue ───────────────────────────────────────────
        self.emit_authority_prologue(func)?;

        // ── Assign slots to all SSA values (global ValueIds) ────────────
        for block in &func.blocks {
            for inst in &block.insts {
                if !inst.result_type.is_void() {
                    self.value_slots.insert(inst.value_id, self.next_slot);
                    self.next_slot += 1;
                }
            }
        }

        // ── Phi deconstruction: record phi stores for predecessors ────────
        self.deconstruct_phis(func);

        // ── Linearize blocks and emit bytecode ───────────────────────────
        let block_order = self.linearize_blocks(func);
        for &block_id in &block_order {
            let block = &func.blocks[block_id as usize];
            self.block_positions.insert(block_id, self.asm.current_pos() as u32);
            self.lower_block(block, func, module)?;
        }

        // Patch jumps within this function
        self.patch_jumps()?;

        // Save param addresses for the dispatch table
        self.all_param_addrs.insert(func.name.clone(), self.param_addrs.clone());

        Ok(())
    }

    /// Emit authority/caller prologue .
    fn emit_authority_prologue(&mut self, func: &IrFunction) -> Result<(), String> {
        let has_attr_public = func.attributes.iter().any(|a| {
            matches!(a, crate::ast::Attribute::Public)
        });

        // `as caller` check
        if func.requires_caller && !has_attr_public {
            const UMA_ANON: [u8; 32] = [0u8; 32];
            self.asm.emit_op(OpCode::LoadCaller);
            self.asm.emit_op(OpCode::LoadImm256);
            self.asm.emit_raw(&UMA_ANON);
            self.asm.emit_op(OpCode::Eq);
            self.asm.emit_op(OpCode::JumpIf);
            let patch_to_revert = self.asm.emit_placeholder_u32();
            self.asm.emit_op(OpCode::Jump);
            let patch_to_body = self.asm.emit_placeholder_u32();
            let revert_pos = self.asm.current_pos() as u32;
            self.asm.patch_u32(patch_to_revert, revert_pos);
            let msg = format!("{}: unauthenticated call", func.name);
            let mb = msg.as_bytes();
            self.asm.emit_op(OpCode::Revert);
            self.asm.emit_raw(&(mb.len() as u32).to_le_bytes());
            self.asm.emit_raw(mb);
            let body_pos = self.asm.current_pos() as u32;
            self.asm.patch_u32(patch_to_body, body_pos);
        }

        // @authority(Scope) check
        for attr in &func.attributes {
            if let crate::ast::Attribute::Authority(scope_name) = attr {
                self.asm.emit_op(OpCode::LoadAuthority);
                let scope_bytes = if scope_name.is_empty() {
                    vec![0u8; 32]
                } else {
                    use sha3::Digest;
                    let mut hasher = sha3::Sha3_256::new();
                    hasher.update(b"SYNQ-AUTHORITY-SCOPE-v1:");
                    hasher.update(scope_name.as_bytes());
                    hasher.finalize().to_vec()
                };
                self.asm.emit_op(OpCode::LoadImm256);
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&scope_bytes);
                self.asm.emit_raw(&bytes);
                self.asm.emit_op(OpCode::AuthRequire);
                self.asm.emit_op(OpCode::JumpIf);
                let patch_to_body = self.asm.emit_placeholder_u32();
                self.asm.emit_op(OpCode::Jump);
                let patch_to_revert = self.asm.emit_placeholder_u32();
                let revert_pos = self.asm.current_pos() as u32;
                self.asm.patch_u32(patch_to_revert, revert_pos);
                let msg = format!("{}: authority scope denied", func.name);
                let mb = msg.as_bytes();
                self.asm.emit_op(OpCode::Revert);
                self.asm.emit_raw(&(mb.len() as u32).to_le_bytes());
                self.asm.emit_raw(mb);
                let body_pos = self.asm.current_pos() as u32;
                self.asm.patch_u32(patch_to_body, body_pos);
            }
        }

        // @governance(Scope) check
        for attr in &func.attributes {
            if let crate::ast::Attribute::Governance(scope_name) = attr {
                self.asm.emit_op(OpCode::LoadAuthority);
                let scope_bytes = if scope_name.is_empty() {
                    vec![0u8; 32]
                } else {
                    use sha3::Digest;
                    let mut hasher = sha3::Sha3_256::new();
                    hasher.update(b"SYNQ-GOVERNANCE-SCOPE-v1:");
                    hasher.update(scope_name.as_bytes());
                    hasher.finalize().to_vec()
                };
                self.asm.emit_op(OpCode::LoadImm256);
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&scope_bytes);
                self.asm.emit_raw(&bytes);
                self.asm.emit_op(OpCode::AuthRequire);
                self.asm.emit_op(OpCode::JumpIf);
                let patch_to_body = self.asm.emit_placeholder_u32();
                self.asm.emit_op(OpCode::Jump);
                let patch_to_revert = self.asm.emit_placeholder_u32();
                let revert_pos = self.asm.current_pos() as u32;
                self.asm.patch_u32(patch_to_revert, revert_pos);
                let msg = format!("{}: governance scope denied", func.name);
                let mb = msg.as_bytes();
                self.asm.emit_op(OpCode::Revert);
                self.asm.emit_raw(&(mb.len() as u32).to_le_bytes());
                self.asm.emit_raw(mb);
                let body_pos = self.asm.current_pos() as u32;
                self.asm.patch_u32(patch_to_body, body_pos);
            }
        }

        Ok(())
    }

    /// Deconstruct phi nodes: record phi stores for each predecessor.
    fn deconstruct_phis(&mut self, func: &IrFunction) {
        self.phi_stores.clear();
        for block in &func.blocks {
            for (i, inst) in block.insts.iter().enumerate() {
                if let IrOp::Phi(pairs) = &inst.op {
                    let phi_slot = self.value_slots[&block.insts[i].value_id];
                    for (pred, val) in pairs {
                        self.phi_stores.entry(*pred)
                            .or_insert_with(Vec::new)
                            .push((*val, phi_slot));
                    }
                }
            }
        }
    }

    /// Linearize blocks in DFS order from entry.
    fn linearize_blocks(&self, func: &IrFunction) -> Vec<BlockId> {
        let mut visited = vec![false; func.blocks.len()];
        let mut order = Vec::new();
        self.dfs_blocks(func, func.entry, &mut visited, &mut order);
        for (i, &v) in visited.iter().enumerate() {
            if !v {
                order.push(i as BlockId);
            }
        }
        order
    }

    fn dfs_blocks(&self, func: &IrFunction, block_id: BlockId, visited: &mut [bool], order: &mut Vec<BlockId>) {
        if visited[block_id as usize] { return; }
        visited[block_id as usize] = true;
        order.push(block_id);
        let succs = func.blocks[block_id as usize].successors();
        for succ in succs {
            self.dfs_blocks(func, succ, visited, order);
        }
    }

    /// Lower a single block.
    fn lower_block(&mut self, block: &BasicBlock, func: &IrFunction, module: &IrModule) -> Result<(), String> {
        // Determine which instructions are terminators
        let n = block.insts.len();
        for (i, inst) in block.insts.iter().enumerate() {
            let is_terminator = inst.is_terminator();

            // Before the terminator, emit phi stores for this block's successors
            if is_terminator {
                self.emit_phi_stores(block.id)?;
            }

            // Phi nodes are no-ops
            if matches!(inst.op, IrOp::Phi(_)) {
                continue;
            }

            self.lower_instruction(inst, block.id, func, module)?;

            // Store result to slot (if value-producing)
            if !inst.result_type.is_void() && !is_terminator {
                let slot = self.value_slots[&inst.value_id];
                self.asm.emit_op(OpCode::Push);
                self.asm.emit_i32(slot as i32);
                self.asm.emit_op(OpCode::Store);
            }
        }

        // If the block has no terminator (shouldn't happen but handle it)
        if n == 0 || !block.insts.last().unwrap().is_terminator() {
            self.asm.emit_op(OpCode::Return);
        }

        Ok(())
    }

    /// Emit phi stores: for each successor block that has phi nodes,
    /// store the phi values from this block to their slots.
    fn emit_phi_stores(&mut self, block_id: BlockId) -> Result<(), String> {
        // ── Parallel copy semantics ─────────────────────────────────────
        // Phi nodes represent parallel assignments: all source values are
        // read simultaneously, then all destinations are written. If we emit
        // sequential load-store pairs, a destination slot that's also a
        // source for another phi can be clobbered before it's read.
        //
        // Fix: Phase 1 — push ALL source values onto the stack.
        //      Phase 2 — pop and store to each destination (reverse order).
        if let Some(stores) = self.phi_stores.get(&block_id).cloned() {
            if stores.is_empty() { return Ok(()); }

            // Phase 1: Load all source values onto the stack
            for (val_id, _phi_slot) in &stores {
                let src_slot = self.value_slots.get(val_id)
                    .ok_or_else(|| format!("missing slot for phi value {}", val_id))?;
                self.asm.emit_op(OpCode::Push);
                self.asm.emit_i32(*src_slot as i32);
                self.asm.emit_op(OpCode::Load);
            }

            // Phase 2: Pop and store to destinations in reverse order
            // (stack is LIFO, so last-pushed is first-popped)
            for (val_id, phi_slot) in stores.iter().rev() {
                let _ = val_id; // unused in this phase
                self.asm.emit_op(OpCode::Push);
                self.asm.emit_i32(*phi_slot as i32);
                self.asm.emit_op(OpCode::Store);
            }
        }
        Ok(())
    }

    /// Lower a single instruction.
    fn lower_instruction(
        &mut self,
        inst: &Instruction,
        block_id: BlockId,
        func: &IrFunction,
        module: &IrModule,
    ) -> Result<(), String> {
        // Helper: load a value from its slot onto the stack
        macro_rules! load_val {
            ($self:expr, $v:expr) => {{
                let slot = $self.value_slots.get(&$v)
                    .ok_or_else(|| format!("missing slot for value {}", $v))?;
                $self.asm.emit_op(OpCode::Push);
                $self.asm.emit_i32(*slot as i32);
                $self.asm.emit_op(OpCode::Load);
            }};
        }

        match &inst.op {
            // ── Constants ──
            IrOp::Const(lit) => {
                self.emit_literal(lit)?;
            }

            // ── Binary operations ──
            IrOp::BinOp(op, a, b) => {
                match op {
                    // Logical AND: (a != 0) * (b != 0)  → 1 only if both non-zero
                    BinaryOperator::And => {
                        load_val!(self, *a);
                        self.asm.emit_op(OpCode::Push);
                        self.asm.emit_i32(0);
                        self.asm.emit_op(OpCode::Ne);
                        load_val!(self, *b);
                        self.asm.emit_op(OpCode::Push);
                        self.asm.emit_i32(0);
                        self.asm.emit_op(OpCode::Ne);
                        self.asm.emit_op(OpCode::Mul);
                    }
                    // Logical OR: (a != 0) + (b != 0) > 0  → 1 if either non-zero
                    BinaryOperator::Or => {
                        load_val!(self, *a);
                        self.asm.emit_op(OpCode::Push);
                        self.asm.emit_i32(0);
                        self.asm.emit_op(OpCode::Ne);
                        load_val!(self, *b);
                        self.asm.emit_op(OpCode::Push);
                        self.asm.emit_i32(0);
                        self.asm.emit_op(OpCode::Ne);
                        self.asm.emit_op(OpCode::Add);
                        self.asm.emit_op(OpCode::Push);
                        self.asm.emit_i32(0);
                        self.asm.emit_op(OpCode::Gt);
                    }
                    // Standard arithmetic / comparison ops
                    _ => {
                        load_val!(self, *a);
                        load_val!(self, *b);
                        let opcode = match op {
                            BinaryOperator::Add => OpCode::Add,
                            BinaryOperator::Sub => OpCode::Sub,
                            BinaryOperator::Mul => OpCode::Mul,
                            BinaryOperator::Div => OpCode::Div,
                            BinaryOperator::Mod => OpCode::Rem,
                            BinaryOperator::Eq => OpCode::Eq,
                            BinaryOperator::Ne => OpCode::Ne,
                            BinaryOperator::Lt => OpCode::Lt,
                            BinaryOperator::Le => OpCode::Le,
                            BinaryOperator::Gt => OpCode::Gt,
                            BinaryOperator::Ge => OpCode::Ge,
                            _ => unreachable!(),
                        };
                        self.asm.emit_op(opcode);
                    }
                }
            }

            // ── Unary operations ──
            IrOp::UnaryOp(op, a) => {
                load_val!(self, *a);
                match op {
                    UnaryOperator::Neg => {
                        self.asm.emit_op(OpCode::Push);
                        self.asm.emit_i32(0);
                        self.asm.emit_op(OpCode::Swap);
                        self.asm.emit_op(OpCode::Sub);
                    }
                    UnaryOperator::Not => {
                        self.asm.emit_op(OpCode::Push);
                        self.asm.emit_i32(1);
                        self.asm.emit_op(OpCode::Eq);
                    }
                }
            }

            // ── Load / Store ──
            IrOp::Load(name) => {
                if let Some(rest) = name.strip_prefix("__param_") {
                    let addr = self.param_addrs.get(rest)
                        .ok_or_else(|| format!("unknown param: {}", rest))?;
                    self.asm.emit_op(OpCode::Push);
                    self.asm.emit_i32(*addr as i32);
                    self.asm.emit_op(OpCode::Load);
                } else if let Some(addr) = self.state_var_addrs.get(name) {
                    self.asm.emit_op(OpCode::Push);
                    self.asm.emit_i32(*addr as i32);
                    self.asm.emit_op(OpCode::Load);
                } else if name.starts_with("__local_") {
                    // Local variable — allocate or reuse address dynamically
                    let addr = *self.local_var_addrs.entry(name.clone())
                        .or_insert_with(|| {
                            let a = self.next_local_addr;
                            self.next_local_addr += 1;
                            a
                        });
                    self.asm.emit_op(OpCode::Push);
                    self.asm.emit_i32(addr as i32);
                    self.asm.emit_op(OpCode::Load);
                } else {
                    return Err(format!("unknown load target: {}", name));
                }
            }

            IrOp::Store(name, val) => {
                load_val!(self, *val);
                if let Some(addr) = self.state_var_addrs.get(name) {
                    self.asm.emit_op(OpCode::Push);
                    self.asm.emit_i32(*addr as i32);
                    self.asm.emit_op(OpCode::Store);
                } else if name.starts_with("__local_") {
                    // Local variable — allocate or reuse address dynamically
                    let addr = *self.local_var_addrs.entry(name.clone())
                        .or_insert_with(|| {
                            let a = self.next_local_addr;
                            self.next_local_addr += 1;
                            a
                        });
                    self.asm.emit_op(OpCode::Push);
                    self.asm.emit_i32(addr as i32);
                    self.asm.emit_op(OpCode::Store);
                } else {
                    return Err(format!("store to unknown var: {}", name));
                }
            }

            IrOp::Caller => {
                self.asm.emit_op(OpCode::LoadCaller);
            }

            IrOp::LoadAuthority => {
                self.asm.emit_op(OpCode::LoadAuthority);
            }

            IrOp::AuthRequire(env, scope) => {
                load_val!(self, *env);
                let scope_bytes = if scope.is_empty() {
                    vec![0u8; 32]
                } else {
                    use sha3::Digest;
                    let mut hasher = sha3::Sha3_256::new();
                    hasher.update(b"SYNQ-AUTHORITY-SCOPE-v1:");
                    hasher.update(scope.as_bytes());
                    hasher.finalize().to_vec()
                };
                self.asm.emit_op(OpCode::LoadImm256);
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&scope_bytes);
                self.asm.emit_raw(&bytes);
                self.asm.emit_op(OpCode::AuthRequire);
            }

            IrOp::AuthIdentity(env) => {
                load_val!(self, *env);
                self.asm.emit_op(OpCode::AuthIdentity);
            }

            // ── Function calls ──
            IrOp::Call(name, args) => {
                // Store args to callee's param memory slots .
                // The VM Call opcode is a plain jump — no register-passing ABI.
                let callee_func = module.functions.iter().find(|f| f.name == *name);
                let callee_params = self.all_param_addrs.get(name);
                for (i, arg) in args.iter().enumerate() {
                    load_val!(self, *arg);
                    let addr = if let (Some(cf), Some(pm)) = (callee_func, callee_params) {
                        // Sort params by declaration order, get i-th address
                        let mut sorted: Vec<(&String, &u32)> = pm.iter().collect();
                        sorted.sort_by_key(|(n, _)| cf.params.iter().position(|(pn, _)| pn == *n).unwrap_or(0));
                        *sorted.get(i).map(|(_, a)| *a).unwrap_or(&(SSA_SLOT_BASE + i as u32))
                    } else {
                        SSA_SLOT_BASE + i as u32
                    };
                    self.asm.emit_op(OpCode::Push);
                    self.asm.emit_i32(addr as i32);
                    self.asm.emit_op(OpCode::Store);
                }
                self.asm.emit_op(OpCode::Call);
                let patch_pos = self.asm.emit_placeholder_u32();
                self.pending_call_patches.push((patch_pos, name.clone()));
            }

            IrOp::ExternCall(contract, fname, args) => {
                for arg in args {
                    load_val!(self, *arg);
                }
                let cb = contract.as_bytes();
                let fb = fname.as_bytes();
                self.asm.emit_op(OpCode::ExternCall);
                self.asm.emit_u32(cb.len() as u32);
                self.asm.emit_raw(cb);
                self.asm.emit_u32(fb.len() as u32);
                self.asm.emit_raw(fb);
                self.asm.emit_raw(&[args.len() as u8]);  // arg_count byte
            }

            // ── Struct / Tuple operations ──
            IrOp::FieldAccess(obj, field_idx) => {
                load_val!(self, *obj);
                self.asm.emit_op(OpCode::Push);
                self.asm.emit_i32(*field_idx as i32);
                self.asm.emit_op(OpCode::TupleGet);
            }

            IrOp::StructLiteral(_name, fields) => {
                for (_, val) in fields {
                    load_val!(self, *val);
                }
                self.asm.emit_op(OpCode::Push);
                self.asm.emit_i32(fields.len() as i32);
                self.asm.emit_op(OpCode::TuplePack);
            }

            IrOp::Tuple(vals) => {
                for v in vals {
                    load_val!(self, *v);
                }
                self.asm.emit_op(OpCode::Push);
                self.asm.emit_i32(vals.len() as i32);
                self.asm.emit_op(OpCode::TuplePack);
            }

            IrOp::TupleSet(t, idx, val) => {
                load_val!(self, *t);
                load_val!(self, *val);
                load_val!(self, *idx);
                self.asm.emit_op(OpCode::TupleSet);
            }

            IrOp::TupleGet(t, idx) => {
                load_val!(self, *t);
                load_val!(self, *idx);
                self.asm.emit_op(OpCode::TupleGet);
            }

            // ── Option / Result ──
            IrOp::Some(v) => {
                load_val!(self, *v);
                self.asm.emit_op(OpCode::OptionSome);
            }
            IrOp::None => {
                self.asm.emit_op(OpCode::OptionNone);
            }
            IrOp::Ok(v) => {
                load_val!(self, *v);
                self.asm.emit_op(OpCode::ResultOk);
            }
            IrOp::Err(v) => {
                load_val!(self, *v);
                self.asm.emit_op(OpCode::ResultErr);
            }
            IrOp::OptionUnwrap(v) => {
                load_val!(self, *v);
                self.asm.emit_op(OpCode::OptionUnwrap);
            }
            IrOp::ResultUnwrap(v) => {
                load_val!(self, *v);
                self.asm.emit_op(OpCode::ResultUnwrap);
            }
            IrOp::IsOk(v) => {
                load_val!(self, *v);
                self.asm.emit_op(OpCode::IsOk);
            }
            IrOp::IsSome(v) => {
                load_val!(self, *v);
                self.asm.emit_op(OpCode::IsSome);
            }

            // ── Enum ──
            IrOp::EnumAccess(enum_name, variant_name) => {
                let enum_def = module.enum_defs.get(enum_name)
                    .ok_or_else(|| format!("unknown enum: {}", enum_name))?;
                let tag = enum_def.variants.iter().position(|v| &v.name == variant_name)
                    .ok_or_else(|| format!("unknown variant: {}", variant_name))?;
                self.asm.emit_op(OpCode::Push);
                self.asm.emit_i32(tag as i32);
            }

            // ── Bech32 ──
            IrOp::AddrEncode(v) => {
                load_val!(self, *v);
                self.asm.emit_op(OpCode::AddrEncode);
            }
            IrOp::AddrDecode(v) => {
                load_val!(self, *v);
                self.asm.emit_op(OpCode::AddrDecode);
            }
            IrOp::ContractAddr(d, n, h) => {
                load_val!(self, *d);
                load_val!(self, *n);
                load_val!(self, *h);
                self.asm.emit_op(OpCode::ContractAddr);
            }

            // ── String operations ──
            IrOp::StrLen(v) => {
                load_val!(self, *v);
                self.asm.emit_op(OpCode::StrLen);
            }
            IrOp::StrConcat(a, b) => {
                load_val!(self, *a);
                load_val!(self, *b);
                self.asm.emit_op(OpCode::StrConcat);
            }
            IrOp::StrEq(a, b) => {
                load_val!(self, *a);
                load_val!(self, *b);
                self.asm.emit_op(OpCode::StrEq);
            }

            // ── PQC / AEG1 ──
            IrOp::AegisCall(args) | IrOp::AegisVerify(args) | IrOp::AegisDecaps(args) => {
                for arg in args {
                    load_val!(self, *arg);
                }
                self.asm.emit_op(OpCode::AegisCall);
            }

            // ── Linear assets ──
            IrOp::AssetCreate(type_name, val) => {
                load_val!(self, *val);
                let mut hash: u32 = 2166136261;
                for b in type_name.bytes() {
                    hash ^= b as u32;
                    hash = hash.wrapping_mul(16777619);
                }
                self.asm.emit_op(OpCode::Push);
                self.asm.emit_i32(hash as i32);
                self.asm.emit_op(OpCode::AssetCreate);
            }
            IrOp::AssetTransfer(id, owner) => {
                // VM pops new_owner (top) then asset_id (below)
                // so push asset_id first, then new_owner on top
                load_val!(self, *id);
                load_val!(self, *owner);
                self.asm.emit_op(OpCode::AssetTransfer);
            }
            IrOp::AssetBurn(id) => {
                load_val!(self, *id);
                self.asm.emit_op(OpCode::AssetBurn);
            }
            IrOp::AssetBalance(id) => {
                load_val!(self, *id);
                self.asm.emit_op(OpCode::AssetBalance);
            }
            IrOp::AssetOwner(id) => {
                load_val!(self, *id);
                self.asm.emit_op(OpCode::AssetOwner);
            }

            // ── Map / Set ──
            IrOp::MapGet(name, key) => {
                let addr = self.state_var_addrs.get(name)
                    .ok_or_else(|| format!("unknown map: {}", name))?;
                // VM MapGet pops addr first (top), then key — push key first, addr last
                load_val!(self, *key);
                self.asm.emit_op(OpCode::Push);
                self.asm.emit_i32(*addr as i32);
                self.asm.emit_op(OpCode::MapGet);
            }
            IrOp::MapSet(name, key, val) => {
                let addr = self.state_var_addrs.get(name)
                    .ok_or_else(|| format!("unknown map: {}", name))?;
                // VM MapSet pops addr first (top), then key, then val — push in reverse
                load_val!(self, *val);
                load_val!(self, *key);
                self.asm.emit_op(OpCode::Push);
                self.asm.emit_i32(*addr as i32);
                self.asm.emit_op(OpCode::MapSet);
            }
            IrOp::SetOp(name, op, val) => {
                let addr = self.state_var_addrs.get(name)
                    .ok_or_else(|| format!("unknown set: {}", name))?;
                // VM SetAdd/SetRemove pops addr first (top), then val — push val first, addr last
                load_val!(self, *val);
                self.asm.emit_op(OpCode::Push);
                self.asm.emit_i32(*addr as i32);
                match op {
                    SetOpKind::Add => self.asm.emit_op(OpCode::SetAdd),
                    SetOpKind::Remove => self.asm.emit_op(OpCode::SetRemove),
                }
            }
            IrOp::MapMethod(name, method, args) => {
                let addr = self.state_var_addrs.get(name)
                    .ok_or_else(|| format!("unknown map: {}", name))?;
                // Push args first, then addr last (VM pops addr from top)
                for arg in args {
                    load_val!(self, *arg);
                }
                self.asm.emit_op(OpCode::Push);
                self.asm.emit_i32(*addr as i32);
                match method.as_str() {
                    "contains" => self.asm.emit_op(OpCode::MapContains),
                    "len" => self.asm.emit_op(OpCode::MapLen),
                    _ => return Err(format!("unknown map method: {}", method)),
                }
            }
            IrOp::SetMethod(name, method, args) => {
                let addr = self.state_var_addrs.get(name)
                    .ok_or_else(|| format!("unknown set: {}", name))?;
                self.asm.emit_op(OpCode::Push);
                self.asm.emit_i32(*addr as i32);
                for arg in args {
                    load_val!(self, *arg);
                }
                match method.as_str() {
                    "contains" => self.asm.emit_op(OpCode::SetContains),
                    "len" => self.asm.emit_op(OpCode::SetLen),
                    _ => return Err(format!("unknown set method: {}", method)),
                }
            }

            // ── Field store ──
            IrOp::FieldStore(obj, _field, val) => {
                load_val!(self, *val);
                let addr = self.state_var_addrs.get(obj)
                    .ok_or_else(|| format!("unknown state var for field store: {}", obj))?;
                self.asm.emit_op(OpCode::Push);
                self.asm.emit_i32(*addr as i32);
                self.asm.emit_op(OpCode::Load);
                self.asm.emit_op(OpCode::Push);
                self.asm.emit_i32(0); // TODO: resolve field index
                self.asm.emit_op(OpCode::TupleSet);
                self.asm.emit_op(OpCode::Push);
                self.asm.emit_i32(*addr as i32);
                self.asm.emit_op(OpCode::Store);
            }

            // ── Effects ──
            IrOp::Emit(name, _args) => {
                let msg = format!("event:{}", name);
                let mb = msg.as_bytes();
                self.asm.emit_op(OpCode::LoadImm);
                self.asm.emit_u32(mb.len() as u32);
                self.asm.emit_raw(mb);
                self.asm.emit_op(OpCode::Print);
            }

            IrOp::Require(cond, msg) => {
                load_val!(self, *cond);
                self.asm.emit_op(OpCode::JumpIf);
                let patch_to_body = self.asm.emit_placeholder_u32();
                self.asm.emit_op(OpCode::Jump);
                let patch_to_revert = self.asm.emit_placeholder_u32();
                let revert_pos = self.asm.current_pos() as u32;
                self.asm.patch_u32(patch_to_revert, revert_pos);
                let mb = msg.as_bytes();
                self.asm.emit_op(OpCode::Revert);
                self.asm.emit_raw(&(mb.len() as u32).to_le_bytes());
                self.asm.emit_raw(mb);
                let body_pos = self.asm.current_pos() as u32;
                self.asm.patch_u32(patch_to_body, body_pos);
            }

            IrOp::Revert(msg) => {
                let mb = msg.as_bytes();
                self.asm.emit_op(OpCode::Revert);
                self.asm.emit_raw(&(mb.len() as u32).to_le_bytes());
                self.asm.emit_raw(mb);
            }

            IrOp::RevertNamed(enum_name, variant_name, args) => {
                let enum_def = module.enum_defs.get(enum_name)
                    .ok_or_else(|| format!("unknown enum: {}", enum_name))?;
                let tag = enum_def.variants.iter().position(|v| &v.name == variant_name)
                    .ok_or_else(|| format!("unknown variant: {}", variant_name))?;
                let msg = if args.is_empty() {
                    format!("{}::{}", enum_name, variant_name)
                } else {
                    format!("{}::{}({} arg(s))", enum_name, variant_name, args.len())
                };
                self.asm.emit_op(OpCode::RevertCode);
                self.asm.emit_u32(tag as u32);
                let mb = msg.as_bytes();
                self.asm.emit_u32(mb.len() as u32);
                self.asm.emit_raw(mb);
            }

            IrOp::Print(v) => {
                load_val!(self, *v);
                self.asm.emit_op(OpCode::Print);
            }

            // ── Control flow ──
            IrOp::Branch(cond, true_block, false_block) => {
                load_val!(self, *cond);
                self.asm.emit_op(OpCode::JumpIf);
                self.pending_jumps.push((self.asm.emit_placeholder_u32(), *true_block));
                self.asm.emit_op(OpCode::Jump);
                self.pending_jumps.push((self.asm.emit_placeholder_u32(), *false_block));
            }

            IrOp::Jump(target) => {
                self.asm.emit_op(OpCode::Jump);
                self.pending_jumps.push((self.asm.emit_placeholder_u32(), *target));
            }

            IrOp::Return(Some(v)) => {
                load_val!(self, *v);
                self.asm.emit_op(OpCode::Return);
            }

            IrOp::Return(None) => {
                self.asm.emit_op(OpCode::Return);
            }

            // ── Phi (no-op in slot-based approach) ──
            IrOp::Phi(_) => {
                // No-op: value is already in its slot, stored by predecessors
            }

            // ── AI (stubbed) ──
            IrOp::AiInfer(_, _) => return Err("AI inference not yet supported".into()),
            IrOp::AiVerifyProof(_) => return Err("AI proof verification not yet supported".into()),
        }

        Ok(())
    }

    /// Emit a literal value as bytecode.
    fn emit_literal(&mut self, lit: &Literal) -> Result<(), String> {
        match lit {
            Literal::Number(n) => {
                let n = *n;
                if n <= i32::MAX as u128 {
                    self.asm.emit_op(OpCode::Push);
                    self.asm.emit_i32(n as i32);
                } else if n <= u128::MAX {
                    self.asm.emit_op(OpCode::LoadImm128);
                    self.asm.emit_u128(n);
                } else {
                    self.asm.emit_op(OpCode::LoadImm256);
                    let bytes = [0u8; 32]; // TODO: proper U256 encoding
                    self.asm.emit_raw(&bytes);
                }
            }
            Literal::Bool(b) => {
                self.asm.emit_op(OpCode::Push);
                self.asm.emit_i32(if *b { 1 } else { 0 });
            }
            Literal::String(s) => {
                self.asm.emit_op(OpCode::LoadImm);
                let sb = s.as_bytes();
                self.asm.emit_u32(sb.len() as u32);
                self.asm.emit_raw(sb);
            }
            Literal::Hex(bytes) => {
                self.asm.emit_op(OpCode::LoadImm);
                self.asm.emit_u32(bytes.len() as u32);
                self.asm.emit_raw(bytes);
            }
            Literal::BigNumber(s) => {
                // Parse decimal string → U256 → 32 big-endian bytes.
                use ruint::aliases::U256;
                let v: U256 = s.parse().map_err(|_| format!("Invalid UInt256 literal: {}", s))?;
                self.asm.emit_op(OpCode::LoadImm256);
                self.asm.emit_raw(&v.to_be_bytes::<32>());
            }
        }
        Ok(())
    }

    /// Patch all pending jump targets.
    fn patch_jumps(&mut self) -> Result<(), String> {
        for (patch_pos, target_block) in self.pending_jumps.drain(..) {
            let target_pos = *self.block_positions.get(&target_block)
                .ok_or_else(|| format!("missing block position for block {}", target_block))?;
            self.asm.patch_u32(patch_pos, target_pos);
        }
        Ok(())
    }

    /// Patch all pending Call targets: resolve function names to code addresses.
    fn patch_calls(&mut self) -> Result<(), String> {
        for (patch_pos, callee_name) in self.pending_call_patches.drain(..) {
            let target = *self.function_entries.get(&callee_name)
                .ok_or_else(|| format!("Call to unknown function '{}'", callee_name))?;
            self.asm.patch_u32(patch_pos, target);
        }
        Ok(())
    }

}
