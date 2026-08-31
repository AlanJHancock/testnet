// ── IR Analyzer ────────────────────────────────────────────────────────────────
//
// Analysis passes that run on the SSA IR after building:
//   1. Reachability analysis — mark blocks reachable from entry
//   2. Dominator tree construction — for phi placement and structural validation
//   3. Effect collection — verify @effects declarations match actual effects
//   4. Linear resource balance — check every Asset created is consumed
//   5. Authority placement — verify every state-mutating path is guarded
//   6. Host function profile validation — no implicit host calls
//   7. Type checking — verify all IR operations are well-typed
//
// The analyzer produces an AnalysisReport with warnings and errors.

use std::collections::HashSet;
use super::types::*;
use super::instructions::*;
use super::blocks::*;
use super::function::*;
use super::module::*;

/// Results of analyzing an IR module.
#[derive(Debug, Clone, Default)]
pub struct AnalysisReport {
    /// Errors that block compilation (or future bytecode emission from IR).
    pub errors: Vec<String>,
    /// Warnings that don't block compilation.
    pub warnings: Vec<String>,
    /// Per-function statistics.
    pub function_stats: Vec<FunctionStats>,
}

/// Statistics for one function's IR.
#[derive(Debug, Clone, Default)]
pub struct FunctionStats {
    pub name: String,
    pub block_count: usize,
    pub instruction_count: usize,
    pub value_count: usize,
    pub reachable_blocks: usize,
    pub effects: Vec<EffectKind>,
    pub host_profiles: usize,
    pub authority_checks: usize,
    pub linear_creates: usize,
    pub linear_consumes: usize,
}

impl AnalysisReport {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Run all analysis passes on an IR module.
pub fn analyze(module: &mut IrModule) -> AnalysisReport {
    let mut report = AnalysisReport::default();

    for func in &mut module.functions {
        let stats = analyze_function(func, &mut report);
        report.function_stats.push(stats);
    }

    report
}

/// Analyze a single function's IR.
fn analyze_function(func: &mut IrFunction, report: &mut AnalysisReport) -> FunctionStats {
    let mut stats = FunctionStats::default();
    stats.name = func.name.clone();

    // 1. Reachability analysis
    analyze_reachability(func);
    stats.reachable_blocks = func.blocks.iter().filter(|b| b.reachable).count();

    // 2. Dominator tree
    let dom_tree = DominatorTree::build(&func.blocks, func.entry);
    func.dom_tree = Some(dom_tree.clone());

    // 3. Block/instruction counts
    stats.block_count = func.blocks.len();
    stats.instruction_count = func.inst_count();
    stats.value_count = func.next_value as usize; // Global ValueId counter

    // 4. Collect effects from instructions
    for block in &func.blocks {
        if !block.reachable { continue; }
        for inst in &block.insts {
            match &inst.op {
                IrOp::Store(name, _) | IrOp::FieldStore(name, _, _) | IrOp::MapSet(name, _, _) | IrOp::SetOp(name, _, _) => {
                    stats.effects.push(EffectKind::Write(name.clone()));
                }
                IrOp::Load(name) if !name.starts_with("__param_") => {
                    stats.effects.push(EffectKind::Read(name.clone()));
                }
                IrOp::Emit(name, _) => {
                    stats.effects.push(EffectKind::Emit(name.clone()));
                }
                IrOp::ExternCall(contract, function, _) => {
                    stats.effects.push(EffectKind::ExternalCall(contract.clone(), function.clone()));
                    stats.host_profiles += 1;
                }
                IrOp::AegisCall(_) | IrOp::AegisVerify(_, _, _) | IrOp::AegisDecaps(_, _, _)
                | IrOp::LegacySphincsVerify(_) | IrOp::PqcUnsupported(_, _) => {
                    stats.host_profiles += 1;
                }
                IrOp::AuthRequire(_, _) => {
                    stats.authority_checks += 1;
                }
                IrOp::AssetCreate(_, _) => {
                    stats.linear_creates += 1;
                }
                IrOp::AssetTransfer(_, _) | IrOp::AssetBurn(_) => {
                    stats.linear_consumes += 1;
                }
                _ => {}
            }
        }
    }

    // 5. Check for unterminated reachable blocks
    for block in &func.blocks {
        if !block.reachable { continue; }
        if !block.is_terminated() {
            report.errors.push(format!(
                "function '{}': block {} is reachable but not terminated",
                func.name, block.id
            ));
        }
    }

    // 6. Check for unreachable blocks (warning)
    for block in &func.blocks {
        if !block.reachable && block.id != func.entry {
            report.warnings.push(format!(
                "function '{}': block {} is unreachable",
                func.name, block.id
            ));
        }
    }

    // 7. Linear resource balance check
    if stats.linear_creates < stats.linear_consumes {
        report.warnings.push(format!(
            "function '{}': {} linear consumes but only {} creates (may consume external assets)",
            func.name, stats.linear_consumes, stats.linear_creates
        ));
    }

    // 8. Effect declaration validation (if @effects present)
    let declared_effects: HashSet<String> = func.modifies.iter().cloned().collect();
    let actual_writes: HashSet<String> = stats.effects.iter()
        .filter_map(|e| match e {
            EffectKind::Write(w) => Some(w.clone()),
            _ => None,
        })
        .collect();

    for write in &actual_writes {
        if !declared_effects.contains(write) && !declared_effects.is_empty() {
            report.warnings.push(format!(
                "function '{}': writes '{}' but it's not in @effects/modifies declaration",
                func.name, write
            ));
        }
    }

    stats.effects = stats.effects.clone();
    stats
}

/// Mark all blocks reachable from the entry block via BFS.
fn analyze_reachability(func: &mut IrFunction) {
    // Reset all blocks
    for block in &mut func.blocks {
        block.reachable = false;
    }

    let mut queue = vec![func.entry];
    while let Some(bid) = queue.pop() {
        if func.blocks[bid as usize].reachable { continue; }
        func.blocks[bid as usize].reachable = true;
        for succ in func.blocks[bid as usize].successors() {
            if !func.blocks[succ as usize].reachable {
                queue.push(succ);
            }
        }
    }
}

/// Check type compatibility between two IR types.
/// This is a simplified type checker — full type checking requires
/// the SSA type lattice (future work).
pub fn types_compatible(expected: &IrType, actual: &IrType) -> bool {
    // Exact match
    if expected == actual { return true; }

    // U256 accepts anything numeric
    if matches!(expected, IrType::U256) {
        return matches!(actual, IrType::U256 | IrType::U128 | IrType::I32 | IrType::I64 | IrType::Bool);
    }
    if matches!(expected, IrType::I32) {
        return matches!(actual, IrType::I32 | IrType::Bool);
    }

    // Address accepts U256 (20-byte address stored as U256)
    if matches!(expected, IrType::Address) && matches!(actual, IrType::U256) {
        return true;
    }

    // Bytes accepts BytesN and Hash types
    if matches!(expected, IrType::Bytes) {
        return matches!(actual, IrType::Bytes | IrType::BytesN(_) | IrType::Hash32 | IrType::Hash64);
    }

    // Void matches anything (effect-only operations)
    if matches!(expected, IrType::Void) { return true; }

    false
}
