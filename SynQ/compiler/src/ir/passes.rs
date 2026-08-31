// ── IR Optimization Passes ───────────────────────────────────────────────────
//
// Passes run on the SSA IR before lowering to bytecode:
//   1. promote_to_ssa — mem2reg: promote __local_* from Load/Store to SSA + phi
//   2. constant_folding — fold constant binary/unary operations
//   3. copy_propagation — replace uses of copied values with their source
//   4. dead_code_elimination — remove unreachable blocks + truly dead instructions
//   5. validate_ssa — verify SSA well-formedness (dominance, terminators, phis)
//
// All passes are idempotent and can be run in any order.

use std::collections::{HashMap, HashSet};
use super::instructions::*;
use super::blocks::*;
use super::function::*;
use super::types::*;

// ── Pass Pipeline ────────────────────────────────────────────────────────────

pub fn run_passes(func: &mut IrFunction) -> Vec<String> {
    let mut reports = Vec::new();

    // 1. Promote local variables from Load/Store to true SSA with phi nodes.
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

    // 4. Dead code elimination — removes dead instructions left by promote_to_ssa
    //    and any other pass. Iterates to fixpoint.
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

// ── mem2reg: Promote Load/Store Locals to True SSA ───────────────────────────
//
// Implements the classic LLVM mem2reg algorithm:
//   1. Identify which __local_* variables are defined (Store) in multiple blocks.
//   2. Compute the iterated dominance frontier (IDF) for each such variable.
//   3. Insert phi nodes at each block in the IDF (tracked by variable name).
//   4. Rename: walk the dominator tree in DFS order, replacing Load("__local_x")
//      with the current SSA value, and updating the value on Store("__local_x", v).
//   5. Update phi node inputs from each predecessor.
//
// After this pass, promoted locals no longer go through memory (Load/Store)
// within blocks — they use SSA values directly. At merge points, phi nodes
// (deconstructed by the lowerer) handle cross-block value propagation.
// The DCE pass removes the dead Store/Load instructions.

/// Promote local variables from Load/Store to SSA with phi nodes.
/// Returns (phi_nodes_inserted, loads_eliminated).
pub fn promote_to_ssa(func: &mut IrFunction) -> (usize, usize) {
    let dom_tree = DominatorTree::build(&func.blocks, func.entry);
    let n = func.blocks.len();

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
    // Track which phi belongs to which local variable.
    let mut phi_count = 0;
    let mut phi_vars: HashMap<ValueId, String> = HashMap::new();

    for local_name in &promotable {
        let def_blocks = &local_defs[local_name];

        // Compute iterated dominance frontier
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

            phi_vars.insert(phi_inst.value_id, local_name.clone());
            func.blocks[block_id as usize].insts.insert(0, phi_inst);
            phi_count += 1;
        }
    }

    // ── Phase 3: Rename (SSA construction via dominator tree DFS) ─────────
    let mut dom_children: Vec<Vec<BlockId>> = vec![Vec::new(); n];
    for b in 0..n {
        if b as BlockId == func.entry { continue; }
        let idom = dom_tree.immediate_dom.get(b).copied().unwrap_or(BlockId::MAX);
        if idom != BlockId::MAX && (idom as usize) < n {
            dom_children[idom as usize].push(b as BlockId);
        }
    }

    let mut value_stacks: HashMap<String, Vec<ValueId>> = HashMap::new();
    let mut substitutions: HashMap<ValueId, ValueId> = HashMap::new();
    let mut loads_removed = 0;

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

    // Remove dead Load and Store instructions for promoted locals
    let promoted_set: HashSet<String> = promotable.iter().cloned().collect();
    for block in func.blocks.iter_mut() {
        let mut new_insts = Vec::new();
        for inst in block.insts.drain(..) {
            let is_dead = match &inst.op {
                IrOp::Load(name) | IrOp::Store(name, _) => promoted_set.contains(name),
                _ => false,
            };
            if !is_dead {
                new_insts.push(inst);
            }
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

    // 2. Process instructions in order — record substitutions for Loads,
    //    push new definitions for Stores.
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
        IrOp::FieldStore(name, field, v) => IrOp::FieldStore(name, field, apply(v)),
        IrOp::StructLiteral(name, fields) => IrOp::StructLiteral(
            name,
            fields.into_iter().map(|(f, v)| (f, apply(v))).collect(),
        ),
        IrOp::Tuple(vals) => IrOp::Tuple(vals.into_iter().map(apply).collect()),
        IrOp::Phi(pairs) => IrOp::Phi(pairs.into_iter().map(|(b, v)| (b, apply(v))).collect()),
        IrOp::Branch(c, t, f) => IrOp::Branch(apply(c), t, f),
        IrOp::Return(Some(v)) => IrOp::Return(Some(apply(v))),
        IrOp::Store(name, v) => IrOp::Store(name, apply(v)),
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
        IrOp::AegisVerify(op, alg, args) => IrOp::AegisVerify(op, alg, args.into_iter().map(apply).collect()),
        IrOp::AegisDecaps(op, alg, args) => IrOp::AegisDecaps(op, alg, args.into_iter().map(apply).collect()),
        IrOp::LegacySphincsVerify(args) => IrOp::LegacySphincsVerify(args.into_iter().map(apply).collect()),
        IrOp::PqcUnsupported(name, args) => IrOp::PqcUnsupported(name, args.into_iter().map(apply).collect()),
        IrOp::AssetCreate(name, v) => IrOp::AssetCreate(name, apply(v)),
        IrOp::AssetTransfer(a, b) => IrOp::AssetTransfer(apply(a), apply(b)),
        IrOp::AssetBurn(v) => IrOp::AssetBurn(apply(v)),
        IrOp::AssetBalance(v) => IrOp::AssetBalance(apply(v)),
        IrOp::AssetOwner(v) => IrOp::AssetOwner(apply(v)),
        IrOp::TupleSet(t, idx, val) => IrOp::TupleSet(apply(t), apply(idx), apply(val)),
        IrOp::TupleGet(t, idx) => IrOp::TupleGet(apply(t), apply(idx)),
        IrOp::Emit(name, args) => IrOp::Emit(name, args.into_iter().map(apply).collect()),
        IrOp::MapSet(name, k, v) => IrOp::MapSet(name, apply(k), apply(v)),
        IrOp::SetOp(name, op, v) => IrOp::SetOp(name, op, apply(v)),
        IrOp::RevertNamed(name, tag, args) => IrOp::RevertNamed(name, tag, args.into_iter().map(apply).collect()),
        IrOp::AiInfer(a, b) => IrOp::AiInfer(apply(a), apply(b)),
        IrOp::AiVerifyProof(v) => IrOp::AiVerifyProof(apply(v)),
        other => other,
    };
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

// ── SSA Validation ───────────────────────────────────────────────────────────
//
// Verify the IR is well-formed SSA:
//   • Every block has at most one terminator (last instruction)
//   • Every used ValueId is defined in a dominating block (or is a param/phi)
//   • Phi nodes only reference predecessor blocks
//   • Every reachable block is terminated

pub fn validate_ssa(func: &IrFunction) -> Vec<String> {
    let mut errors = Vec::new();

    // Check: every block has at most one terminator, and it's the last instruction
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

    // Check: every reachable block is terminated
    for block in func.blocks.iter() {
        if !block.insts.is_empty() && !block.is_terminated() {
            // Could be an unreachable block — only flag if it has predecessors
            if !block.preds.is_empty() {
                errors.push(format!(
                    "fn {}: block {} is not terminated but has predecessors",
                    func.name, block.id
                ));
            }
        }
    }

    // Build a set of all defined ValueIds and the block that defines each
    let mut def_map: HashMap<ValueId, BlockId> = HashMap::new();
    for block in &func.blocks {
        for inst in &block.insts {
            if !inst.result_type.is_void() {
                def_map.insert(inst.value_id, block.id);
            }
        }
    }

    // Build dominator tree for proper dominance checking
    let dom_tree = DominatorTree::build(&func.blocks, func.entry);

    // Check: every used ValueId is defined and dominates the use site
    for block in &func.blocks {
        for (idx, inst) in block.insts.iter().enumerate() {
            // Phi inputs are checked separately (they come from predecessors)
            if matches!(inst.op, IrOp::Phi(_)) { continue; }

            for input in inst.input_values() {
                // Param loads are pre-defined
                if let IrOp::Load(name) = &inst.op {
                    if name.starts_with("__param_") { continue; }
                }

                match def_map.get(&input) {
                    None => {
                        // Value might be defined by a phi (which has void result_type
                        // in some configs) — check if it exists at all
                        let exists = func.blocks.iter()
                            .any(|b| b.insts.iter().any(|i| i.value_id == input));
                        if !exists {
                            errors.push(format!(
                                "fn {}: block {} inst {} uses undefined value v{}",
                                func.name, block.id, idx, input
                            ));
                        }
                    }
                    Some(def_block) => {
                        // The defining block must dominate the use block
                        if *def_block != block.id && !dominates(&dom_tree, *def_block, block.id) {
                            errors.push(format!(
                                "fn {}: block {} inst {} uses value v{} from non-dominating block {}",
                                func.name, block.id, idx, input, def_block
                            ));
                        }
                    }
                }
            }
        }
    }

    // Check: phi nodes only reference predecessor blocks
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
                    if *val != 0 && !def_map.contains_key(val) {
                        // val == 0 is a placeholder (not yet renamed)
                        errors.push(format!(
                            "fn {}: block {} phi references undefined value v{}",
                            func.name, block.id, val
                        ));
                    }
                }
            }
        }
    }

    errors
}

/// Check if block `a` dominates block `b` by walking the dominator tree.
fn dominates(dom_tree: &DominatorTree, a: BlockId, b: BlockId) -> bool {
    let mut current = b;
    loop {
        if current == a { return true; }
        let idom = dom_tree.immediate_dom.get(current as usize).copied().unwrap_or(BlockId::MAX);
        if idom == BlockId::MAX || idom == current { return false; }
        current = idom;
    }
}

// ── Dead Code Elimination ────────────────────────────────────────────────────
//
// Two-phase DCE:
//   1. Remove unreachable blocks (blocks not reachable from entry).
//   2. Remove instructions whose results are never used and have no side effects.
//      Uses a global use-def map across all blocks. Iterates to fixpoint.

/// Remove dead code. Returns the number of instructions removed.
pub fn dead_code_elimination(func: &mut IrFunction) -> usize {
    let mut total_removed = 0;

    // Phase 1: Remove unreachable blocks
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

    for (i, block) in func.blocks.iter_mut().enumerate() {
        if !reachable[i] && !block.insts.is_empty() {
            total_removed += block.insts.len();
            block.insts.clear();
            block.reachable = false;
        } else {
            block.reachable = reachable[i];
        }
    }

    // Phase 2: Remove unused non-side-effecting instructions (iterate to fixpoint)
    loop {
        // Build global use map: ValueId → number of uses
        let mut use_count: HashMap<ValueId, usize> = HashMap::new();
        for block in &func.blocks {
            for inst in &block.insts {
                for v in inst.input_values() {
                    *use_count.entry(v).or_insert(0) += 1;
                }
            }
        }

        let mut removed_this_round = 0;
        for block in func.blocks.iter_mut() {
            if !block.reachable { continue; }
            let original_len = block.insts.len();
            block.insts.retain(|inst| {
                // Always keep side-effecting instructions and terminators
                if has_side_effects(&inst.op) || inst.is_terminator() { return true; }
                // Keep phi nodes (they're needed for CFG correctness even if
                // their result appears unused — the lowerer reads them)
                if matches!(inst.op, IrOp::Phi(_)) { return true; }
                // Keep if the result is used by something
                if !inst.result_type.is_void() {
                    return *use_count.get(&inst.value_id).unwrap_or(&0) > 0;
                }
                // Void, non-side-effecting, non-terminator → dead
                false
            });
            removed_this_round += original_len - block.insts.len();
        }

        total_removed += removed_this_round;
        if removed_this_round == 0 { break; }
    }

    total_removed
}

/// Does an IR operation have side effects (cannot be removed by DCE)?
fn has_side_effects(op: &IrOp) -> bool {
    matches!(
        op,
        IrOp::Store(_, _) | IrOp::FieldStore(_, _, _) | IrOp::MapSet(_, _, _)
        | IrOp::SetOp(_, _, _) | IrOp::Emit(_, _) | IrOp::Require(_, _)
        | IrOp::Revert(_) | IrOp::RevertNamed(_, _, _) | IrOp::Print(_)
        | IrOp::ExternCall(_, _, _) | IrOp::AegisCall(_)
        | IrOp::AegisVerify(_, _, _) | IrOp::AegisDecaps(_, _, _) | IrOp::LegacySphincsVerify(_)
        | IrOp::PqcUnsupported(_, _)
        | IrOp::AssetTransfer(_, _) | IrOp::AssetBurn(_)
        | IrOp::AssetCreate(_, _)
    )
}

// ── Constant Folding ────────────────────────────────────────────────────────
//
// Replace constant binary operations with their computed result.
// E.g., BinOp(Add, Const(2), Const(3)) → Const(5)

pub fn constant_folding(func: &mut IrFunction) -> usize {
    use crate::ast::Literal;

    let mut folded = 0;

    for block in func.blocks.iter_mut() {
        let mut const_map: HashMap<ValueId, Literal> = HashMap::new();

        for inst in block.insts.iter_mut() {
            let val_id = inst.value_id;

            if let IrOp::Const(ref lit) = inst.op {
                const_map.insert(val_id, lit.clone());
                continue;
            }

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

            if let IrOp::UnaryOp(op, operand) = &inst.op {
                if let Some(lit) = const_map.get(operand) {
                    if let Some(result) = fold_unary(op, lit) {
                        inst.op = IrOp::Const(result.clone());
                        const_map.insert(val_id, result);
                        folded += 1;
                    }
                }
            }
        }
    }

    folded
}

fn fold_binary(op: &crate::ast::BinaryOperator, lhs: &crate::ast::Literal, rhs: &crate::ast::Literal) -> Option<crate::ast::Literal> {
    use crate::ast::{BinaryOperator, Literal};

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
        BinaryOperator::BitAnd => Some(Literal::Number(l & r)),
        BinaryOperator::BitOr => Some(Literal::Number(l | r)),
        BinaryOperator::BitXor => Some(Literal::Number(l ^ r)),
        // Literal::Number is backed by u128 -- only fold shifts that stay
        // within that width; wider shifts (or ones whose RESULT overflows
        // u128, even though the shift amount itself is < 128) are left for
        // runtime U256 evaluation.
        //
        // Bug this guards against: u128::checked_shl(r) only rejects
        // r >= 128 (the bit width) -- it does NOT check whether the shifted
        // value itself still fits in 128 bits. For r < 128 it always
        // returns Some(...), silently discarding any bits pushed past
        // bit 127. E.g. (2^100) << 50 (a perfectly valid u256 literal
        // expression, correct answer 2^150) has shift amount 50 < 128, so
        // the old "r < 128" guard let it through, and
        // 2u128.pow(100).checked_shl(50) silently truncated to 0 --
        // a folded compile-time CONSTANT of the wrong value with no error
        // at all. Guarding on l.leading_zeros() >= r proves no set bit
        // of l is shifted past bit 127, so the u128 fold is bit-for-bit
        // identical to the true (wider) result before falling back.
        BinaryOperator::Shl => if r < 128 && (l.leading_zeros() as u128) >= r {
            l.checked_shl(r as u32).map(Literal::Number)
        } else { None },
        BinaryOperator::Shr => if r < 128 { Some(Literal::Number(l >> r as u32)) } else { None },
        // No catch-all: BinaryOperator's variants are all covered above, so
        // a trailing `_ => None` was unreachable dead code.
    }
}

fn fold_unary(op: &crate::ast::UnaryOperator, lit: &crate::ast::Literal) -> Option<crate::ast::Literal> {
    use crate::ast::{UnaryOperator, Literal};

    match (op, lit) {
        (UnaryOperator::Not, Literal::Bool(b)) => Some(Literal::Bool(!b)),
        (UnaryOperator::Neg, Literal::Number(n)) => {
            if *n == 0 { Some(Literal::Number(0)) } else { None }
        }
        _ => None,
    }
}

// ── Copy Propagation ─────────────────────────────────────────────────────────
//
// When instruction A produces a value that is just a copy of another value B
// (e.g., identity operations, or A's only input is B and the op is transparent),
// replace all uses of A with B. This is simpler than full copy propagation —
// we only handle cases where an instruction's result is provably equal to one
// of its inputs.

pub fn copy_propagation(func: &mut IrFunction) -> usize {
    let mut propagated = 0;

    // Build copy map: ValueId -> canonical source ValueId
    let copy_map: HashMap<ValueId, ValueId> = HashMap::new();

    // Resolve a value through the copy chain
    let resolve = |map: &HashMap<ValueId, ValueId>, v: ValueId| -> ValueId {
        let mut current = v;
        let mut seen = HashSet::new();
        while let Some(&next) = map.get(&current) {
            if !seen.insert(current) { break; } // cycle detection
            current = next;
        }
        current
    };

    // Helper: resolve a vec of values, return (new_vec, any_changed)
    let resolve_vec = |map: &HashMap<ValueId, ValueId>, args: &[ValueId]| -> (Vec<ValueId>, bool) {
        let new_args: Vec<ValueId> = args.iter().map(|&a| resolve(map, a)).collect();
        let changed = new_args.iter().zip(args.iter()).any(|(n, o)| n != o);
        (new_args, changed)
    };

    for block in func.blocks.iter_mut() {
        for inst in block.insts.iter_mut() {
            let mut changed = false;
            let new_op = match inst.op.clone() {
                IrOp::BinOp(op, a, b) => {
                    let na = resolve(&copy_map, a); let nb = resolve(&copy_map, b);
                    changed = na != a || nb != b;
                    IrOp::BinOp(op, na, nb)
                }
                IrOp::UnaryOp(op, a) => {
                    let na = resolve(&copy_map, a);
                    changed = na != a;
                    IrOp::UnaryOp(op, na)
                }
                IrOp::AuthIdentity(a) => { let na = resolve(&copy_map, a); changed = na != a; IrOp::AuthIdentity(na) }
                IrOp::AuthRequire(env, s) => { let na = resolve(&copy_map, env); changed = na != env; IrOp::AuthRequire(na, s) }
                IrOp::Call(name, args) => {
                    let (new_args, ch) = resolve_vec(&copy_map, &args);
                    changed = ch;
                    IrOp::Call(name, new_args)
                }
                IrOp::ExternCall(c, f, args) => {
                    let (new_args, ch) = resolve_vec(&copy_map, &args);
                    changed = ch;
                    IrOp::ExternCall(c, f, new_args)
                }
                IrOp::MapGet(name, key) => { let na = resolve(&copy_map, key); changed = na != key; IrOp::MapGet(name, na) }
                IrOp::MapMethod(name, m, args) => {
                    let (new_args, ch) = resolve_vec(&copy_map, &args);
                    changed = ch;
                    IrOp::MapMethod(name, m, new_args)
                }
                IrOp::SetMethod(name, m, args) => {
                    let (new_args, ch) = resolve_vec(&copy_map, &args);
                    changed = ch;
                    IrOp::SetMethod(name, m, new_args)
                }
                IrOp::FieldAccess(obj, field) => { let na = resolve(&copy_map, obj); changed = na != obj; IrOp::FieldAccess(na, field) }
                IrOp::FieldStore(name, field, v) => { let na = resolve(&copy_map, v); changed = na != v; IrOp::FieldStore(name, field, na) }
                IrOp::StructLiteral(name, fields) => {
                    let new_fields: Vec<(String, ValueId)> = fields.iter()
                        .map(|(f, v)| (f.clone(), resolve(&copy_map, *v)))
                        .collect();
                    changed = new_fields.iter().zip(fields.iter()).any(|(n, o)| n.1 != o.1);
                    IrOp::StructLiteral(name, new_fields)
                }
                IrOp::Tuple(vals) => {
                    let (new_vals, ch) = resolve_vec(&copy_map, &vals);
                    changed = ch;
                    IrOp::Tuple(new_vals)
                }
                IrOp::Phi(pairs) => {
                    let new_pairs: Vec<(BlockId, ValueId)> = pairs.iter()
                        .map(|(b, v)| (*b, resolve(&copy_map, *v)))
                        .collect();
                    changed = new_pairs.iter().zip(pairs.iter()).any(|(n, o)| n.1 != o.1);
                    IrOp::Phi(new_pairs)
                }
                IrOp::Branch(c, t, f) => { let na = resolve(&copy_map, c); changed = na != c; IrOp::Branch(na, t, f) }
                IrOp::Return(Some(v)) => { let na = resolve(&copy_map, v); changed = na != v; IrOp::Return(Some(na)) }
                IrOp::Store(name, v) => { let na = resolve(&copy_map, v); changed = na != v; IrOp::Store(name, na) }
                IrOp::Require(c, msg) => { let na = resolve(&copy_map, c); changed = na != c; IrOp::Require(na, msg) }
                IrOp::Print(v) => { let na = resolve(&copy_map, v); changed = na != v; IrOp::Print(na) }
                IrOp::Some(v) => { let na = resolve(&copy_map, v); changed = na != v; IrOp::Some(na) }
                IrOp::Ok(v) => { let na = resolve(&copy_map, v); changed = na != v; IrOp::Ok(na) }
                IrOp::Err(v) => { let na = resolve(&copy_map, v); changed = na != v; IrOp::Err(na) }
                IrOp::OptionUnwrap(v) => { let na = resolve(&copy_map, v); changed = na != v; IrOp::OptionUnwrap(na) }
                IrOp::ResultUnwrap(v) => { let na = resolve(&copy_map, v); changed = na != v; IrOp::ResultUnwrap(na) }
                IrOp::IsOk(v) => { let na = resolve(&copy_map, v); changed = na != v; IrOp::IsOk(na) }
                IrOp::IsSome(v) => { let na = resolve(&copy_map, v); changed = na != v; IrOp::IsSome(na) }
                IrOp::AddrEncode(v) => { let na = resolve(&copy_map, v); changed = na != v; IrOp::AddrEncode(na) }
                IrOp::AddrDecode(v) => { let na = resolve(&copy_map, v); changed = na != v; IrOp::AddrDecode(na) }
                IrOp::ContractAddr(a, b, c) => {
                    let na = resolve(&copy_map, a); let nb = resolve(&copy_map, b); let nc = resolve(&copy_map, c);
                    changed = na != a || nb != b || nc != c;
                    IrOp::ContractAddr(na, nb, nc)
                }
                IrOp::StrLen(v) => { let na = resolve(&copy_map, v); changed = na != v; IrOp::StrLen(na) }
                IrOp::StrConcat(a, b) => { let na = resolve(&copy_map, a); let nb = resolve(&copy_map, b); changed = na != a || nb != b; IrOp::StrConcat(na, nb) }
                IrOp::StrEq(a, b) => { let na = resolve(&copy_map, a); let nb = resolve(&copy_map, b); changed = na != a || nb != b; IrOp::StrEq(na, nb) }
                IrOp::AegisCall(args) => {
                    let (new_args, ch) = resolve_vec(&copy_map, &args);
                    changed = ch;
                    IrOp::AegisCall(new_args)
                }
                IrOp::AegisVerify(op, alg, args) => {
                    let (new_args, ch) = resolve_vec(&copy_map, &args);
                    changed = ch;
                    IrOp::AegisVerify(op, alg, new_args)
                }
                IrOp::AegisDecaps(op, alg, args) => {
                    let (new_args, ch) = resolve_vec(&copy_map, &args);
                    changed = ch;
                    IrOp::AegisDecaps(op, alg, new_args)
                }
                IrOp::LegacySphincsVerify(args) => {
                    let (new_args, ch) = resolve_vec(&copy_map, &args);
                    changed = ch;
                    IrOp::LegacySphincsVerify(new_args)
                }
                IrOp::PqcUnsupported(name, args) => {
                    let (new_args, ch) = resolve_vec(&copy_map, &args);
                    changed = ch;
                    IrOp::PqcUnsupported(name, new_args)
                }
                IrOp::AssetCreate(name, v) => { let na = resolve(&copy_map, v); changed = na != v; IrOp::AssetCreate(name, na) }
                IrOp::AssetTransfer(a, b) => { let na = resolve(&copy_map, a); let nb = resolve(&copy_map, b); changed = na != a || nb != b; IrOp::AssetTransfer(na, nb) }
                IrOp::AssetBurn(v) => { let na = resolve(&copy_map, v); changed = na != v; IrOp::AssetBurn(na) }
                IrOp::AssetBalance(v) => { let na = resolve(&copy_map, v); changed = na != v; IrOp::AssetBalance(na) }
                IrOp::AssetOwner(v) => { let na = resolve(&copy_map, v); changed = na != v; IrOp::AssetOwner(na) }
                IrOp::TupleSet(t, idx, val) => {
                    let nt = resolve(&copy_map, t); let ni = resolve(&copy_map, idx); let nv = resolve(&copy_map, val);
                    changed = nt != t || ni != idx || nv != val;
                    IrOp::TupleSet(nt, ni, nv)
                }
                IrOp::TupleGet(t, idx) => {
                    let nt = resolve(&copy_map, t); let ni = resolve(&copy_map, idx);
                    changed = nt != t || ni != idx;
                    IrOp::TupleGet(nt, ni)
                }
                IrOp::Emit(name, args) => {
                    let (new_args, ch) = resolve_vec(&copy_map, &args);
                    changed = ch;
                    IrOp::Emit(name, new_args)
                }
                IrOp::MapSet(name, k, v) => {
                    let nk = resolve(&copy_map, k); let nv = resolve(&copy_map, v);
                    changed = nk != k || nv != v;
                    IrOp::MapSet(name, nk, nv)
                }
                IrOp::SetOp(name, op, v) => { let na = resolve(&copy_map, v); changed = na != v; IrOp::SetOp(name, op, na) }
                IrOp::RevertNamed(name, tag, args) => {
                    let (new_args, ch) = resolve_vec(&copy_map, &args);
                    changed = ch;
                    IrOp::RevertNamed(name, tag, new_args)
                }
                IrOp::AiInfer(a, b) => {
                    let na = resolve(&copy_map, a); let nb = resolve(&copy_map, b);
                    changed = na != a || nb != b;
                    IrOp::AiInfer(na, nb)
                }
                IrOp::AiVerifyProof(v) => { let na = resolve(&copy_map, v); changed = na != v; IrOp::AiVerifyProof(na) }
                other => other,
            };

            inst.op = new_op;
            if changed { propagated += 1; }
        }
    }

    propagated
}
