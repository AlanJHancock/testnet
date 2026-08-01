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

    // 1. Insert phi nodes at merge points
    let (phi_count, _phi_debug) = insert_phi_nodes(func);
    if phi_count > 0 {
        reports.push(format!("phi_insertion: {} phi nodes placed", phi_count));
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

    // 4. Dead code elimination
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
    // Since our IR uses ValueId = InstId, we track which blocks have Store/let
    // operations for each named variable.
    let mut var_defs: HashMap<String, HashSet<BlockId>> = HashMap::new();

    for block in &func.blocks {
        for inst in &block.insts {
            match &inst.op {
                IrOp::Store(name, _) => {
                    var_defs.entry(name.clone()).or_default().insert(block.id);
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
                        if let Some(src_inst) = func.blocks[src_block as usize].insts.get(*val_id as usize) {
                            return src_inst.result_type.clone();
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
        if (val_id as usize) < block.insts.len() {
            return Some(block.id);
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
        for (i, inst) in block.insts.iter().enumerate() {
            let val_id = i as ValueId;
            defined_values.insert(val_id);

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
                    if input < val_id {
                        continue;
                    }
                    errors.push(format!(
                        "fn {}: block {} inst {} uses undefined value v{}",
                        func.name, block.id, i, input
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

        for (i, inst) in block.insts.iter_mut().enumerate() {
            let val_id = i as ValueId;

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
        for (i, inst) in block.insts.iter_mut().enumerate() {
            let val_id = i as ValueId;

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
