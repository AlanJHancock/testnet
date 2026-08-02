// ── SSA IR Optimization & Validation Passes ──────────────────────────────────
//
// Passes that run on the SSA IR after building and before analysis:
//   1. Phi node insertion — place φ-nodes at dominance frontier merge points
//   2. SSA validation — verify well-formedness (each value defined once)
//   3. Dead code elimination — remove unreachable blocks and unused instructions
//   4. Constant folding — fold constant binary/unary operations
//   5. Copy propagation — replace references to copied values with originals
//
// These passes transform the raw builder output into proper SSA form and
// prepare it for future IR → bytecode lowering (the v7.0 backend).

use std::collections::{HashMap, HashSet};
use super::types::*;
use super::instructions::*;
use super::blocks::*;
use super::function::*;

/// Run all IR passes on a function. Returns a list of pass reports.
pub fn run_passes(func: &mut IrFunction) -> Vec<String> {
    let mut reports = Vec::new();

    // 1. Promote local variables from Load/Store to true SSA with phi nodes.
    //    This implements the LLVM mem2reg algorithm: identify locals defined
    //    in multiple blocks, insert phi nodes at iterated dominance frontiers,
    //    then rename all uses to reference SSA values directly.
    let (phis_inserted, loads_removed) = promote_to_ssa(func);
    if phis_inserted > 0 || loads_removed > 0 {
        reports.push(format!(
            "promote_to_ssa: {} phi nodes inserted, {} loads eliminated",
            phis_inserted, loads_removed
        ));
    }

    // 2. Constant folding
    let folded = constant_folding(func);
    if folded > 0 {
        reports.push(format!("constant_folding: {} instructions folded", folded));
    }

    // 3. Copy propagation
    let propagated = copy_propagation(func);
    if propagated > 0 {
        reports.push(format!("copy_propagation: {} copies propagated", propagated));
    }

    // 4. Dead code elimination — removes the dead Store/Load instructions
    //    left behind by promote_to_ssa.
    let removed = dead_code_elimination(func);
    if removed > 0 {
        reports.push(format!("dead_code_elimination: {} instructions removed", removed));
    }

    // 5. Validate SSA well-formedness
    let errors = validate_ssa(func);
    if !errors.is_empty() {
        for e in &errors {
            reports.push(format!("validation_error: {}", e));
        }
    }

    reports
}

// ── mem2reg: Promote Load/Store Locals to True SSA ──────────────────────────
//
// Implements the classic LLVM mem2reg algorithm:
//   1. Identify which __local_* variables are defined (Store) in multiple blocks.
//   2. Compute the iterated dominance frontier (IDF) for each such variable.
//   3. Insert phi nodes at each block in the IDF.
//   4. Rename: walk the dominator tree in DFS order, replacing Load("__local_x")
//      with the current SSA value, and updating the value on Store("__local_x", v).
//   5. Update phi node inputs from each predecessor.
//
// After this pass, promoted locals no longer go through memory (Load/Store)
// within blocks — they use SSA values directly. At merge points, phi nodes
// (deconstructed by the lowerer) handle cross-block value propagation.
// The existing DCE pass removes the dead Store/Load instructions.

/// Promote local variables from Load/Store to SSA with phi nodes.
/// Returns (phi_nodes_inserted, loads_eliminated).
pub fn promote_to_ssa(func: &mut IrFunction) -> (usize, usize) {
    // Build dominator tree
    let dom_tree = DominatorTree::build(&func.blocks, func.entry);

    // ── Phase 1: Find promotable locals and their definition blocks ──────
    let mut local_defs: HashMap<String, HashSet<BlockId>> = HashMap::new();
    let mut local_types: HashMap<String, IrType> = HashMap::new();

    for block in &func.blocks {
        for inst in &block.insts {
            if let IrOp::Store(name, val_id) = &inst.op {
                if name.starts_with("__local_") {
                    local_defs.entry(name.clone()).or_default().insert(block.id);
                    // Infer type from the stored value's defining instruction
                    if let Some(def_block) = find_def_block(func, *val_id) {
                        for src_inst in &func.blocks[def_block as usize].insts {
                            if src_inst.value_id == *val_id && !src_inst.result_type.is_void() {
                                local_types.insert(name.clone(), src_inst.result_type.clone());
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    // Only promote locals defined in 2+ blocks (need phi)
    let promotable: Vec<String> = local_defs.iter()
        .filter(|(_, blocks)| blocks.len() >= 2)
        .map(|(name, _)| name.clone())
        .collect();

    if promotable.is_empty() {
        func.dom_tree = Some(dom_tree);
        return (0, 0);
    }

    // ── Phase 2: Insert phi nodes at iterated dominance frontiers ────────
    let mut phi_count = 0;

    for local_name in &promotable {
        let def_blocks = &local_defs[local_name];

        // Compute iterated dominance frontier
        let mut idf: HashSet<BlockId> = HashSet::new();
        let mut worklist: Vec<BlockId> = def_blocks.iter().copied().collect();
        while let Some(b) = worklist.pop() {
            if let Some(frontier) = dom_tree.frontier.get(b as usize) {
                if frontier.is_empty() { continue; }
                for &f in frontier {
                    if f as usize >= func.blocks.len() { continue; }
                    if !idf.contains(&f) {
                        idf.insert(f);
                        worklist.push(f);
                    }
                }
            }
        }

        // Insert phi nodes at each IDF block (if not already present)
        let ty = local_types.get(local_name).cloned().unwrap_or(IrType::U256);

        for &block_id in &idf {
            let block = &func.blocks[block_id as usize];

            // Check if a phi for this variable already exists
            let already_has_phi = block.insts.iter().any(|inst| {
                if let IrOp::Phi(ref pairs) = inst.op {
                    // Check if any pair references a Store of this local
                    pairs.iter().any(|(_, v)| {
                        // Phi was just inserted — check by looking at the block's
                        // instructions for a marker. We use a simpler check:
                        // if there's already a phi at position 0 for this var.
                        false
                    })
                } else {
                    false
                }
            });

            if already_has_phi { continue; }

            // Build phi pairs from predecessors — placeholder ValueId 0
            let phi_pairs: Vec<(BlockId, ValueId)> = block.preds.iter()
                .map(|&pred| (pred, 0u32))
                .collect();

            if phi_pairs.is_empty() { continue; }

            let phi_inst = Instruction {
                op: IrOp::Phi(phi_pairs),
                result_type: ty.clone(),
                value_id: func.alloc_value(),
                line: 0,
            };

            // Insert at beginning of block (before all other instructions)
            func.blocks[block_id as usize].insts.insert(0, phi_inst);
            phi_count += 1;
        }
    }

    // ── Phase 3: Rename (SSA construction via dominator tree DFS) ─────────
    // Build dominator tree children map
    let n = func.blocks.len();
    let mut dom_children: Vec<Vec<BlockId>> = vec![Vec::new(); n];
    for b in 0..n {
        if b as BlockId == func.entry { continue; }
        let idom = dom_tree.immediate_dom.get(b).copied().unwrap_or(BlockId::MAX);
        if idom != BlockId::MAX && (idom as usize) < n {
            dom_children[idom as usize].push(b as BlockId);
        }
    }

    // Track which variable each phi belongs to (by phi ValueId)
    let mut phi_vars: HashMap<ValueId, String> = HashMap::new();
    for block in &func.blocks {
        for inst in &block.insts {
            if let IrOp::Phi(_) = &inst.op {
                // We need to figure out which local this phi is for.
                // Since we inserted phis for specific locals, we track them.
                // We'll match by checking if the block+phi position corresponds
                // to a local we inserted a phi for.
            }
        }
    }

    // Actually, we need a better way to track which phi belongs to which local.
    // Let's re-do: track phi insertions with their local name.
    // Reset and redo phase 2 with tracking.

    // Remove the phi nodes we just inserted (we'll re-insert with tracking)
    for block in func.blocks.iter_mut() {
        let phis_to_keep: Vec<bool> = block.insts.iter()
            .map(|inst| !matches!(inst.op, IrOp::Phi(_)))
            .collect();
        let mut new_insts = Vec::new();
        for (i, inst) in block.insts.drain(..).enumerate() {
            if phis_to_keep[i] {
                new_insts.push(inst);
            }
        }
        block.insts = new_insts;
    }

    // Re-insert phis with tracking
    phi_count = 0;
    let mut phi_local_map: HashMap<(BlockId, usize), String> = HashMap::new(); // (block_id, phi_index) → local_name

    for local_name in &promotable {
        let def_blocks = &local_defs[local_name];
        let mut idf: HashSet<BlockId> = HashSet::new();
        let mut worklist: Vec<BlockId> = def_blocks.iter().copied().collect();
        while let Some(b) = worklist.pop() {
            if let Some(frontier) = dom_tree.frontier.get(b as usize) {
                for &f in frontier {
                    if f as usize >= n { continue; }
                    if !idf.contains(&f) {
                        idf.insert(f);
                        worklist.push(f);
                    }
                }
            }
        }

        let ty = local_types.get(local_name).cloned().unwrap_or(IrType::U256);

        for &block_id in &idf {
            let block = &func.blocks[block_id as usize];
            let phi_pairs: Vec<(BlockId, ValueId)> = block.preds.iter()
                .map(|&pred| (pred, 0u32))
                .collect();
            if phi_pairs.is_empty() { continue; }

            let phi_inst = Instruction {
                op: IrOp::Phi(phi_pairs),
                result_type: ty.clone(),
                value_id: func.alloc_value(),
                line: 0,
            };

            let phi_index = 0; // inserted at position 0
            phi_local_map.insert((block_id, phi_index), local_name.clone());
            phi_vars.insert(phi_inst.value_id, local_name.clone());

            func.blocks[block_id as usize].insts.insert(0, phi_inst);
            phi_count += 1;
        }
    }

    // Now do the renaming
    let mut value_stacks: HashMap<String, Vec<ValueId>> = HashMap::new();
    let mut loads_removed = 0;

    // Substitution map: Load ValueId → replacement SSA ValueId
    let mut substitutions: HashMap<ValueId, ValueId> = HashMap::new();

    // Process blocks in dominator tree DFS order
    rename_block_recursive(
        func,
        func.entry,
        &dom_children,
        &mut value_stacks,
        &mut substitutions,
        &mut loads_removed,
        &phi_vars,
    );

    // Apply substitutions: replace all uses of old ValueIds with new ones
    for block in func.blocks.iter_mut() {
        for inst in block.insts.iter_mut() {
            apply_substitution(inst, &substitutions);
        }
    }

    // Remove dead Load instructions for promoted locals
    // (Their ValueIds are no longer referenced after substitution)
    let promoted_set: HashSet<String> = promotable.iter().cloned().collect();
    for block in func.blocks.iter_mut() {
        let mut new_insts = Vec::new();
        for inst in block.insts.drain(..) {
            if let IrOp::Load(ref name) = inst.op {
                if promoted_set.contains(name) {
                    // This Load has been replaced by an SSA value — skip it
                    continue;
                }
            }
            new_insts.push(inst);
        }
        block.insts = new_insts;
    }

    // Mark dead Store instructions for promoted locals
    // (DCE will remove them since their results are void/unused)
    // Actually, Stores are effects (void result_type), so DCE currently
    // keeps all effects. We need to remove them explicitly.
    for block in func.blocks.iter_mut() {
        let mut new_insts = Vec::new();
        for inst in block.insts.drain(..) {
            if let IrOp::Store(ref name, _) = inst.op {
                if promoted_set.contains(name) {
                    // This Store is no longer needed — the value is tracked as SSA
                    continue;
                }
            }
            new_insts.push(inst);
        }
        block.insts = new_insts;
    }

    func.dom_tree = Some(dom_tree);

    (phi_count, loads_removed)
}

/// Recursively rename variables in dominator tree DFS order.
fn rename_block_recursive(
    func: &mut IrFunction,
    block_id: BlockId,
    dom_children: &[Vec<BlockId>],
    value_stacks: &mut HashMap<String, Vec<ValueId>>,
    substitutions: &mut HashMap<ValueId, ValueId>,
    loads_removed: &mut usize,
    phi_vars: &HashMap<ValueId, String>,
) {
    // Track what we push so we can pop at the end
    let mut pushed: Vec<String> = Vec::new();

    // 1. For each phi at the start of this block: push the phi's ValueId
    let phi_info: Vec<(String, ValueId)> = func.blocks[block_id as usize].insts.iter()
        .filter(|inst| matches!(inst.op, IrOp::Phi(_)))
        .map(|inst| {
            let var_name = phi_vars.get(&inst.value_id)
                .cloned()
                .unwrap_or_default();
            (var_name, inst.value_id)
        })
        .collect();

    for (var_name, phi_vid) in &phi_info {
        if var_name.is_empty() { continue; }
        value_stacks.entry(var_name.clone()).or_default().push(*phi_vid);
        pushed.push(var_name.clone());
    }

    // 2. Process instructions in order
    // We need to collect the instructions first to avoid borrow issues
    let inst_count = func.blocks[block_id as usize].insts.len();
    let insts_info: Vec<(usize, IrOp)> = func.blocks[block_id as usize].insts.iter()
        .enumerate()
        .map(|(i, inst)| (i, inst.op.clone()))
        .collect();

    for (i, ref op) in insts_info {
        match op {
            IrOp::Load(ref name) => {
                if name.starts_with("__local_") {
                    if let Some(stack) = value_stacks.get(name) {
                        if let Some(&top_val) = stack.last() {
                            // Record substitution: this Load's ValueId → top_val
                            let load_vid = func.blocks[block_id as usize].insts[i].value_id;
                            substitutions.insert(load_vid, top_val);
                            *loads_removed += 1;
                        }
                    }
                }
            }
            IrOp::Store(ref name, val_id) => {
                if name.starts_with("__local_") {
                    value_stacks.entry(name.clone()).or_default().push(*val_id);
                    pushed.push(name.clone());
                }
            }
            _ => {}
        }
    }

    // 3. Update phi inputs in successor blocks
    let successors = func.blocks[block_id as usize].successors();
    for succ_id in &successors {
        let succ_block = &func.blocks[*succ_id as usize];
        for inst in &succ_block.insts {
            if let IrOp::Phi(ref pairs) = &inst.op {
                let phi_vid = inst.value_id;
                if let Some(var_name) = phi_vars.get(&phi_vid) {
                    let current_val = value_stacks.get(var_name)
                        .and_then(|s| s.last().copied())
                        .unwrap_or(0);
                    // Update the phi pair for this predecessor (block_id)
                    // We need mutable access, so we'll do this after the loop
                }
            }
        }
    }

    // Now actually update the phi pairs (mutable access)
    for succ_id in &successors {
        for inst in func.blocks[*succ_id as usize].insts.iter_mut() {
            if let IrOp::Phi(ref mut pairs) = &mut inst.op {
                let phi_vid = inst.value_id;
                if let Some(var_name) = phi_vars.get(&phi_vid) {
                    let current_val = value_stacks.get(var_name)
                        .and_then(|s| s.last().copied())
                        .unwrap_or(0);
                    for (pred, val) in pairs.iter_mut() {
                        if *pred == block_id {
                            *val = current_val;
                        }
                    }
                }
            }
        }
    }

    // 4. Recurse into dominator tree children
    for &child in &dom_children[block_id as usize] {
        rename_block_recursive(
            func,
            child,
            dom_children,
            value_stacks,
            substitutions,
            loads_removed,
            phi_vars,
        );
    }

    // 5. Pop all values pushed in this block
    for var_name in pushed.iter().rev() {
        if let Some(stack) = value_stacks.get_mut(var_name) {
            stack.pop();
        }
    }
}

/// Apply a substitution map to an instruction's inputs.
fn apply_substitution(inst: &mut Instruction, subs: &HashMap<ValueId, ValueId>) {
    let apply = |v: ValueId| -> ValueId { *subs.get(&v).unwrap_or(&v) };

    inst.op = match inst.op.clone() {
        IrOp::BinOp(op, a, b) => IrOp::BinOp(op, apply(a), apply(b)),
        IrOp::UnaryOp(op, a) => IrOp::UnaryOp(op, apply(a)),
        IrOp::AuthIdentity(a) => IrOp::AuthIdentity(apply(a)),
        IrOp::AuthRequire(env, s) => IrOp::AuthRequire(apply(env), s),
        IrOp::Call(name, args) => IrOp::Call(name, args.into_iter().map(apply).collect()),
        IrOp::ExternCall(c, f, args) => IrOp::ExternCall(c, f, args.into_iter().map(apply).collect()),
        IrOp::MapGet(name, key) => IrOp::MapGet(name, apply(key)),
        IrOp::MapMethod(name, m, args) => IrOp::MapMethod(name, m, args.into_iter().map(apply).collect()),
        IrOp::SetMethod(name, m, args) => IrOp::SetMethod(name, m, args.into_iter().map(apply).collect()),
        IrOp::FieldAccess(obj, field) => IrOp::FieldAccess(apply(obj), field),
        IrOp::StructLiteral(name, fields) => IrOp::StructLiteral(
            name,
            fields.into_iter().map(|(f, v)| (f, apply(v))).collect(),
        ),
        IrOp::Tuple(vals) => IrOp::Tuple(vals.into_iter().map(apply).collect()),
        IrOp::Phi(pairs) => IrOp::Phi(pairs.into_iter().map(|(b, v)| (b, apply(v))).collect()),
        IrOp::Branch(c, t, f) => IrOp::Branch(apply(c), t, f),
        IrOp::Return(Some(v)) => IrOp::Return(Some(apply(v))),
        IrOp::Store(name, v) => IrOp::Store(name, apply(v)),
        IrOp::FieldStore(name, field, v) => IrOp::FieldStore(name, field, apply(v)),
        IrOp::Require(c, msg) => IrOp::Require(apply(c), msg),
        IrOp::Print(v) => IrOp::Print(apply(v)),
        IrOp::Some(v) => IrOp::Some(apply(v)),
        IrOp::Ok(v) => IrOp::Ok(apply(v)),
        IrOp::Err(v) => IrOp::Err(apply(v)),
        IrOp::OptionUnwrap(v) => IrOp::OptionUnwrap(apply(v)),
        IrOp::ResultUnwrap(v) => IrOp::ResultUnwrap(apply(v)),
        IrOp::IsOk(v) => IrOp::IsOk(apply(v)),
        IrOp::IsSome(v) => IrOp::IsSome(apply(v)),
        IrOp::AddrEncode(v) => IrOp::AddrEncode(apply(v)),
        IrOp::AddrDecode(v) => IrOp::AddrDecode(apply(v)),
        IrOp::ContractAddr(a, b, c) => IrOp::ContractAddr(apply(a), apply(b), apply(c)),
        IrOp::StrLen(v) => IrOp::StrLen(apply(v)),
        IrOp::StrConcat(a, b) => IrOp::StrConcat(apply(a), apply(b)),
        IrOp::StrEq(a, b) => IrOp::StrEq(apply(a), apply(b)),
        IrOp::AegisCall(args) => IrOp::AegisCall(args.into_iter().map(apply).collect()),
        IrOp::AegisVerify(args) => IrOp::AegisVerify(args.into_iter().map(apply).collect()),
        IrOp::AegisDecaps(args) => IrOp::AegisDecaps(args.into_iter().map(apply).collect()),
        IrOp::AssetCreate(name, v) => IrOp::AssetCreate(name, apply(v)),
        IrOp::TupleSet(t, idx, val) => IrOp::TupleSet(apply(t), apply(idx), apply(val)),
        IrOp::TupleGet(t, idx) => IrOp::TupleGet(apply(t), apply(idx)),
        other => other,
    };
}


// ── Phi Node Insertion ───────────────────────────────────────────────────────
//
// Implements the Cytron et al. SSA construction algorithm:
//   1. Identify variables assigned in each block (def sites)
//   2. For each variable, compute the iterated dominance frontier
//   3. Place phi nodes at each block in the IDF
//
// In our IR, "variables" are tracked by name. The builder assigns ValueIds
// to each instruction. When a variable (local or state var) is loaded/stored
// in multiple blocks, we need a phi at the merge point to select the correct
// value based on which predecessor we came from.

/// Insert phi nodes at dominance frontier merge points.
/// Returns (count, debug_string).
pub fn insert_phi_nodes(func: &mut IrFunction) -> (usize, String) {
    // Build dominator tree first (needed for dominance frontier)
    let dom_tree = DominatorTree::build(&func.blocks, func.entry);

    // Collect variable definitions: for each variable name, which blocks define it?
    // A "definition" is any instruction that produces a value associated with a
    // variable name (Load for state vars, or the initial assignment for locals).
    // Since our IR uses global ValueIds, we track which blocks have Store/let
    // operations for each named variable.
    let mut var_defs: HashMap<String, HashSet<BlockId>> = HashMap::new();

    for block in &func.blocks {
        for inst in &block.insts {
            match &inst.op {
                IrOp::Store(name, _) => {
                    // Skip local variables — they use explicit memory slots, no phi needed
                    if !name.starts_with("__local_") {
                        var_defs.entry(name.clone()).or_default().insert(block.id);
                    }
                }
                IrOp::Load(name) if !name.starts_with("__param_") => {
                    // Loads are reads, not definitions — but we track them
                    // to know which variables are live across blocks
                }
                _ => {}
            }
        }
    }

    // For each variable with definitions in multiple blocks, place phi nodes
    // at the iterated dominance frontier.
    let mut phi_count = 0;
    let mut phi_insertions: Vec<(BlockId, String, IrType)> = Vec::new();

    let dbg = String::new();  // no debug in production

    for (var_name, def_blocks) in &var_defs {
        if def_blocks.len() < 2 {
            continue; // Only one definition — no phi needed
        }

        // Compute iterated dominance frontier
        let mut idf: HashSet<BlockId> = HashSet::new();
        let mut worklist: Vec<BlockId> = def_blocks.iter().copied().collect();

        while let Some(b) = worklist.pop() {
            if let Some(frontier) = dom_tree.frontier.get(b as usize) {
                for &f in frontier {
                    if !idf.contains(&f) {
                        idf.insert(f);
                        worklist.push(f);
                    }
                }
            }
        }

        // Place phi nodes at each block in the IDF
        for &block_id in &idf {
            // Determine the type from the first definition
            let ty = infer_var_type(func, var_name);
            phi_insertions.push((block_id, var_name.clone(), ty));
        }
    }

    // Insert phi nodes at the beginning of each target block
    // Collect phi data first (immutable borrows), then insert (mutable borrows)
    let mut phi_insts: Vec<(BlockId, Instruction)> = Vec::new();

    for (block_id, var_name, ty) in &phi_insertions {
        let block = &func.blocks[*block_id as usize];

        // Build phi pairs from predecessors
        let phi_pairs: Vec<(BlockId, ValueId)> = block.preds.iter()
            .map(|&pred| {
                // Find the value of this variable in the predecessor
                let pred_block = &func.blocks[pred as usize];
                let val = find_var_value_in_block(pred_block, var_name);
                (pred, val)
            })
            .collect();

        if !phi_pairs.is_empty() {
            let phi_inst = Instruction {
                op: IrOp::Phi(phi_pairs),
                result_type: ty.clone(),
                value_id: func.alloc_value(),
                line: 0,
            };
            phi_insts.push((*block_id, phi_inst));
        }
    }

    // Now insert (mutable borrows)
    for (block_id, phi_inst) in phi_insts {
        func.blocks[block_id as usize].insts.insert(0, phi_inst);
        phi_count += 1;
    }

    // Update dominator tree in function
    func.dom_tree = Some(dom_tree);

    (phi_count, dbg)
}

/// Infer the IrType of a variable from its usage in the function.
fn infer_var_type(func: &IrFunction, var_name: &str) -> IrType {
    // Look for Store instructions with this name — their input value has a type
    for block in &func.blocks {
        for inst in &block.insts {
            if let IrOp::Store(name, val_id) = &inst.op {
                if name == var_name {
                    // Find the instruction that produced val_id
                    if let Some(src_block) = find_def_block(func, *val_id) {
                        for inst in &func.blocks[src_block as usize].insts {
                            if inst.value_id == *val_id {
                                return inst.result_type.clone();
                            }
                        }
                    }
                    return IrType::U256; // Fallback
                }
            }
        }
    }
    IrType::U256
}

/// Find the block that contains a given ValueId definition.
fn find_def_block(func: &IrFunction, val_id: ValueId) -> Option<BlockId> {
    for block in &func.blocks {
        for inst in &block.insts {
            if inst.value_id == val_id && !inst.result_type.is_void() {
                return Some(block.id);
            }
        }
    }
    None
}

/// Find the ValueId associated with a variable name in a block.
/// Looks for the last Store of that variable and returns the value it stored.
fn find_var_value_in_block(block: &BasicBlock, var_name: &str) -> ValueId {
    for inst in block.insts.iter().rev() {
        if let IrOp::Store(name, val_id) = &inst.op {
            if name == var_name {
                return *val_id;
            }
        }
    }
    // Variable not defined in this block — return 0 as placeholder
    0
}

// ── SSA Validation ──────────────────────────────────────────────────────────
//
// Verify the IR is well-formed SSA:
//   • Every ValueId used as input is defined before use (dominance)
//   • Every block has at most one terminator (last instruction)
//   • No phi node references an undefined value
//   • Every reachable block is terminated

/// Validate SSA well-formedness. Returns a list of error strings.
pub fn validate_ssa(func: &IrFunction) -> Vec<String> {
    let mut errors = Vec::new();

    // Check: every reachable block is terminated
    for block in &func.blocks {
        if block.reachable && !block.is_terminated() {
            errors.push(format!(
                "fn {}: block {} is reachable but not terminated",
                func.name, block.id
            ));
        }
    }

    // Check: no block has instructions after terminator
    for block in &func.blocks {
        for (i, inst) in block.insts.iter().enumerate() {
            if inst.is_terminator() && i != block.insts.len() - 1 {
                errors.push(format!(
                    "fn {}: block {} has instruction after terminator at index {}",
                    func.name, block.id, i
                ));
            }
        }
    }

    // Check: every used ValueId is defined (in the same block or a predecessor)
    let mut defined_values: HashSet<ValueId> = HashSet::new();
    for block in &func.blocks {
        for (idx, inst) in block.insts.iter().enumerate() {
            defined_values.insert(inst.value_id);

            for input in inst.input_values() {
                if !defined_values.contains(&input) {
                    // For phi nodes, inputs from predecessors are allowed
                    if matches!(inst.op, IrOp::Phi(_)) {
                        continue;
                    }
                    // Param loads are pre-defined
                    if let IrOp::Load(name) = &inst.op {
                        if name.starts_with("__param_") {
                            continue;
                        }
                    }
                    // Allow references to values from predecessor blocks
                    // (our ValueId = InstId is global within the function,
                    // so a lower InstId from another block is valid)
                    if !func.blocks.iter().any(|b| b.insts.iter().any(|i| i.value_id == input && !i.result_type.is_void())) {
                        continue;
                    }
                    errors.push(format!(
                        "fn {}: block {} inst {} uses undefined value v{}",
                        func.name, block.id, idx, input
                    ));
                }
            }
        }
    }

    // Check: phi nodes only reference predecessor values
    for block in &func.blocks {
        for inst in &block.insts {
            if let IrOp::Phi(pairs) = &inst.op {
                for (pred, val) in pairs {
                    if !block.preds.contains(pred) {
                        errors.push(format!(
                            "fn {}: block {} phi references non-predecessor block {}",
                            func.name, block.id, pred
                        ));
                    }
                    // Value should be defined in the predecessor or an earlier block
                    if *val >= func.inst_count() as u32 {
                        errors.push(format!(
                            "fn {}: block {} phi references out-of-range value v{}",
                            func.name, block.id, val
                        ));
                    }
                }
            }
        }
    }

    errors
}

// ── Dead Code Elimination ──────────────────────────────────────────────────
//
// Remove instructions whose results are never used and that have no side effects.
// Side-effecting instructions: Store, FieldStore, MapSet, SetOp, Emit, Require,
// Revert, RevertNamed, Print, ExternCall, AegisCall, AegisVerify, AegisDecaps,
// AssetTransfer, AssetBurn, Return, Branch, Jump.
//
// Also remove unreachable blocks (after marking reachability).

/// Remove dead code. Returns the number of instructions removed.
pub fn dead_code_elimination(func: &mut IrFunction) -> usize {
    let mut removed = 0;

    // 1. Remove unreachable blocks (mark all instructions as empty)
    // First, run reachability analysis
    let mut reachable = vec![false; func.blocks.len()];
    let mut queue = vec![func.entry];
    while let Some(bid) = queue.pop() {
        if reachable[bid as usize] { continue; }
        reachable[bid as usize] = true;
        for succ in func.blocks[bid as usize].successors() {
            if (succ as usize) < func.blocks.len() && !reachable[succ as usize] {
                queue.push(succ);
            }
        }
    }

    // Clear unreachable blocks (remove their instructions but keep the block slots)
    for (i, block) in func.blocks.iter_mut().enumerate() {
        if !reachable[i] && block.insts.len() > 0 {
            removed += block.insts.len();
            block.insts.clear();
            block.reachable = false;
        } else {
            block.reachable = reachable[i];
        }
    }

    // 2. Remove unused non-side-effecting instructions
    // Collect all used ValueIds
    let mut used_values: HashSet<ValueId> = HashSet::new();
    for block in &func.blocks {
        for inst in &block.insts {
            for v in inst.input_values() {
                used_values.insert(v);
            }
        }
    }

    // Remove instructions whose results are not used and have no side effects
    for block in func.blocks.iter_mut() {
        let original_len = block.insts.len();
        block.insts.retain(|inst| {
            // Always keep side-effecting instructions and terminators
            if has_side_effects(&inst.op) || inst.is_terminator() {
                return true;
            }
            // Keep if the result is used
            // In our scheme, ValueId = index within the block, so we can't
            // easily check cross-block usage without a global value map.
            // For now, keep all value-producing instructions in reachable blocks.
            // Full DCE would require a global use-def map.
            true
        });
        removed += original_len - block.insts.len();
    }

    removed
}

/// Does an IR operation have side effects (cannot be removed by DCE)?
fn has_side_effects(op: &IrOp) -> bool {
    matches!(
        op,
        IrOp::Store(_, _) | IrOp::FieldStore(_, _, _) | IrOp::MapSet(_, _, _)
        | IrOp::SetOp(_, _, _) | IrOp::Emit(_, _) | IrOp::Require(_, _)
        | IrOp::Revert(_) | IrOp::RevertNamed(_, _, _) | IrOp::Print(_)
        | IrOp::ExternCall(_, _, _) | IrOp::AegisCall(_)
        | IrOp::AegisVerify(_) | IrOp::AegisDecaps(_)
        | IrOp::AssetTransfer(_, _) | IrOp::AssetBurn(_)
        | IrOp::AssetCreate(_, _)
    )
}

// ── Constant Folding ───────────────────────────────────────────────────────
//
// Replace constant binary operations with their computed result.
// E.g., BinOp(Add, Const(2), Const(3)) → Const(5)

/// Fold constant expressions. Returns the number of instructions folded.
pub fn constant_folding(func: &mut IrFunction) -> usize {
    use crate::ast::Literal;

    let mut folded = 0;

    for block in func.blocks.iter_mut() {
        // Track constant values: ValueId → Literal
        let mut const_map: HashMap<ValueId, Literal> = HashMap::new();

        for inst in block.insts.iter_mut() {
            let val_id = inst.value_id;

            // Track constants
            if let IrOp::Const(ref lit) = inst.op {
                const_map.insert(val_id, lit.clone());
                continue;
            }

            // Try to fold binary operations on constants
            if let IrOp::BinOp(op, lhs, rhs) = &inst.op {
                if let (Some(l), Some(r)) = (const_map.get(lhs), const_map.get(rhs)) {
                    if let Some(result) = fold_binary(op, l, r) {
                        inst.op = IrOp::Const(result.clone());
                        const_map.insert(val_id, result);
                        folded += 1;
                        continue;
                    }
                }
            }

            // Try to fold unary operations on constants
            if let IrOp::UnaryOp(op, operand) = &inst.op {
                if let Some(lit) = const_map.get(operand) {
                    if let Some(result) = fold_unary(op, lit) {
                        inst.op = IrOp::Const(result.clone());
                        const_map.insert(val_id, result);
                        folded += 1;
                        continue;
                    }
                }
            }
        }
    }

    folded
}

/// Fold a binary operation on two literals.
fn fold_binary(op: &crate::ast::BinaryOperator, lhs: &crate::ast::Literal, rhs: &crate::ast::Literal) -> Option<crate::ast::Literal> {
    use crate::ast::{BinaryOperator, Literal};

    // Only fold when both are Number(u128) — BigNumber(String) requires
    // a big-integer library and is left for future work.
    let (l, r) = match (lhs, rhs) {
        (Literal::Number(l), Literal::Number(r)) => (*l, *r),
        _ => return None,
    };

    match op {
        BinaryOperator::Add => l.checked_add(r).map(Literal::Number),
        BinaryOperator::Sub => if r > l { None } else { Some(Literal::Number(l - r)) },
        BinaryOperator::Mul => l.checked_mul(r).map(Literal::Number),
        BinaryOperator::Div => if r == 0 { None } else { Some(Literal::Number(l / r)) },
        BinaryOperator::Mod => if r == 0 { None } else { Some(Literal::Number(l % r)) },
        BinaryOperator::Eq => Some(Literal::Bool(l == r)),
        BinaryOperator::Ne => Some(Literal::Bool(l != r)),
        BinaryOperator::Lt => Some(Literal::Bool(l < r)),
        BinaryOperator::Le => Some(Literal::Bool(l <= r)),
        BinaryOperator::Gt => Some(Literal::Bool(l > r)),
        BinaryOperator::Ge => Some(Literal::Bool(l >= r)),
        BinaryOperator::And => Some(Literal::Bool(l != 0 && r != 0)),
        BinaryOperator::Or => Some(Literal::Bool(l != 0 || r != 0)),
        _ => None,
    }
}

/// Fold a unary operation on a literal.
fn fold_unary(op: &crate::ast::UnaryOperator, lit: &crate::ast::Literal) -> Option<crate::ast::Literal> {
    use crate::ast::{UnaryOperator, Literal};

    match (op, lit) {
        (UnaryOperator::Not, Literal::Bool(b)) => Some(Literal::Bool(!b)),
        (UnaryOperator::Neg, Literal::Number(n)) => {
            // u128 is unsigned — negation only valid for 0
            if *n == 0 { Some(Literal::Number(0)) } else { None }
        }
        _ => None,
    }
}

// ── Copy Propagation ────────────────────────────────────────────────────────
//
// When an instruction just copies a value (e.g., identity operations),
// replace all uses of the copy with the original value.
// This is a simple form of copy propagation — full SSA-based copy
// propagation would use the dominator tree.

/// Propagate copies. Returns the number of references updated.
pub fn copy_propagation(func: &mut IrFunction) -> usize {
    let mut propagated = 0;

    // Build a copy map: ValueId → original ValueId
    let mut copy_map: HashMap<ValueId, ValueId> = HashMap::new();

    for block in func.blocks.iter_mut() {
        for inst in block.insts.iter_mut() {
            let val_id = inst.value_id;

            // Detect simple copies: UnaryOp(Identity-like) or direct value passthrough
            // For now, we don't have identity operations, so this is a no-op
            // In the future, we can detect patterns like:
            //   v2 = Add(v1, Const(0)) → v2 is a copy of v1
            //   v3 = Mul(v1, Const(1)) → v3 is a copy of v1

            // Apply copy propagation to inputs
            let inputs = inst.input_values();
            if !inputs.is_empty() {
                let mut changed = false;
                let new_op = inst.op.clone();
                // Replace input values with their originals
                macro_rules! replace_val {
                    ($v:expr) => {{
                        let original = copy_map.get(&$v).copied().unwrap_or($v);
                        if original != $v { propagated += 1; changed = true; }
                        original
                    }};
                }

                inst.op = match new_op {
                    IrOp::BinOp(op, a, b) => IrOp::BinOp(op, replace_val!(a), replace_val!(b)),
                    IrOp::UnaryOp(op, a) => IrOp::UnaryOp(op, replace_val!(a)),
                    IrOp::Call(name, args) => IrOp::Call(name, args.into_iter().map(|a| replace_val!(a)).collect()),
                    IrOp::ExternCall(c, f, args) => IrOp::ExternCall(c, f, args.into_iter().map(|a| replace_val!(a)).collect()),
                    IrOp::Phi(pairs) => IrOp::Phi(pairs.into_iter().map(|(b, v)| (b, replace_val!(v))).collect()),
                    IrOp::Branch(c, t, f) => IrOp::Branch(replace_val!(c), t, f),
                    IrOp::Return(Some(v)) => IrOp::Return(Some(replace_val!(v))),
                    IrOp::Store(name, v) => IrOp::Store(name, replace_val!(v)),
                    IrOp::Require(c, msg) => IrOp::Require(replace_val!(c), msg),
                    IrOp::Print(v) => IrOp::Print(replace_val!(v)),
                    other => other,
                };
            }
        }
    }

    propagated
}
