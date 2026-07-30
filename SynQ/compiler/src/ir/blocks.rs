// ── Basic Blocks & Control Flow Graph ──────────────────────────────────────────
//
// A BasicBlock is a maximal sequence of instructions with:
//   • One entry point (no branches target the middle of a block)
//   • One exit point (the terminator: Branch, Jump, or Return)
//
// The CFG is the graph of basic blocks connected by terminator edges.
// Predecessor/successor lists are maintained for dominance analysis and
// phi node placement.

use super::instructions::*;
use super::types::*;

/// A basic block in the CFG.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Unique block ID within the function.
    pub id: BlockId,
    /// Instructions in order. The last instruction must be a terminator
    /// (Branch, Jump, or Return). Non-terminator instructions produce values.
    pub insts: Vec<Instruction>,
    /// Predecessor block IDs (blocks that branch/jump to this one).
    pub preds: Vec<BlockId>,
    /// Whether this block is reachable from the entry block.
    /// Computed by the analyzer during reachability analysis.
    pub reachable: bool,
}

impl BasicBlock {
    /// Create a new empty block.
    pub fn new(id: BlockId) -> Self {
        Self { id, insts: Vec::new(), preds: Vec::new(), reachable: false }
    }

    /// Get the terminator instruction (last instruction), if any.
    pub fn terminator(&self) -> Option<&Instruction> {
        self.insts.last().filter(|i| i.is_terminator())
    }

    /// Get successor block IDs from the terminator.
    pub fn successors(&self) -> Vec<BlockId> {
        self.terminator().map(|t| t.successors()).unwrap_or_default()
    }

    /// Push a value-producing instruction and return its ValueId.
    pub fn push_value(&mut self, inst: Instruction) -> ValueId {
        let id = self.insts.len() as ValueId;
        self.insts.push(inst);
        id
    }

    /// Push a terminator instruction (must be last).
    pub fn set_terminator(&mut self, inst: Instruction) {
        debug_assert!(inst.is_terminator(), "set_terminator called with non-terminator");
        self.insts.push(inst);
    }

    /// Is this block terminated?
    pub fn is_terminated(&self) -> bool {
        self.insts.last().map(|i| i.is_terminator()).unwrap_or(false)
    }
}

/// Dominator tree — computed from the CFG.
/// For each block, records its immediate dominator (the nearest block that
/// dominates it). Used for phi node placement and structural validation.
#[derive(Debug, Clone)]
pub struct DominatorTree {
    /// immediate_dom[block_id] = parent block id in dominator tree
    /// Entry block's immediate dom is itself.
    pub immediate_dom: Vec<BlockId>,
    /// Dominance frontier: blocks where a variable's definition needs a phi.
    /// frontier[block_id] = set of blocks in the dominance frontier
    pub frontier: Vec<Vec<BlockId>>,
}

impl DominatorTree {
    /// Build the dominator tree using the Cooper-Harvey-Kennedy algorithm.
    /// This is a simple iterative dominator computation suitable for small CFGs.
    pub fn build(blocks: &[BasicBlock], entry: BlockId) -> Self {
        let n = blocks.len();
        let mut immediate_dom = vec![BlockId::MAX; n];

        // Build predecessor lists (already in blocks, but let's be explicit)
        let preds: Vec<Vec<BlockId>> = blocks.iter().map(|b| b.preds.clone()).collect();

        // Build post-order traversal of CFG for efficient iteration
        let post_order = Self::post_order(blocks, entry);

        // Map block id → post-order index
        let mut post_index = vec![0u32; n];
        for (i, &b) in post_order.iter().enumerate() {
            post_index[b as usize] = i as u32;
        }

        immediate_dom[entry as usize] = entry;

        let mut changed = true;
        while changed {
            changed = false;
            // Process blocks in reverse post-order (excluding entry)
            for &b in post_order.iter().rev() {
                if b == entry { continue; }
                let mut new_idom = BlockId::MAX;
                for &p in &preds[b as usize] {
                    if immediate_dom[p as usize] == BlockId::MAX { continue; }
                    if new_idom == BlockId::MAX {
                        new_idom = p;
                    } else {
                        new_idom = Self::intersect(new_idom, p, &post_index, &immediate_dom);
                    }
                }
                if new_idom != BlockId::MAX && immediate_dom[b as usize] != new_idom {
                    immediate_dom[b as usize] = new_idom;
                    changed = true;
                }
            }
        }

        // Compute dominance frontier
        let mut frontier = vec![Vec::new(); n];
        for b in 0..n {
            // Skip blocks whose idom is MAX (unreachable or not yet computed)
            if immediate_dom[b] == BlockId::MAX { continue; }
            if preds[b].len() >= 2 {
                for &p in &preds[b] {
                    let mut runner = p;
                    while runner != immediate_dom[b] {
                        if runner == BlockId::MAX || runner as usize >= n { break; }
                        if !frontier[runner as usize].contains(&(b as BlockId)) {
                            frontier[runner as usize].push(b as BlockId);
                        }
                        let next = immediate_dom[runner as usize];
                        if next == BlockId::MAX || next == runner { break; }
                        runner = next;
                    }
                }
            }
        }

        Self { immediate_dom, frontier }
    }

    /// Helper: find the common dominator of two blocks.
    fn intersect(b1: BlockId, b2: BlockId, post_index: &[u32], idom: &[BlockId]) -> BlockId {
        let mut b1 = b1;
        let mut b2 = b2;
        while b1 != b2 {
            // Advance the node with LOWER post_index (deeper in the tree).
            // Higher post_index = later in post-order = closer to root.
            while post_index[b1 as usize] < post_index[b2 as usize] {
                let next = idom[b1 as usize];
                if next == BlockId::MAX || next == b1 { break; }
                b1 = next;
            }
            while post_index[b2 as usize] < post_index[b1 as usize] {
                let next = idom[b2 as usize];
                if next == BlockId::MAX || next == b2 { break; }
                b2 = next;
            }
            // If neither can advance (both at entry or stuck), break to avoid infinite loop
            let prev_b1 = b1;
            let prev_b2 = b2;
            if post_index[b1 as usize] == post_index[b2 as usize] && b1 != b2 {
                // Same rank but different blocks — advance both
                let n1 = idom[b1 as usize];
                let n2 = idom[b2 as usize];
                if n1 != BlockId::MAX && n1 != b1 { b1 = n1; }
                if n2 != BlockId::MAX && n2 != b2 { b2 = n2; }
                if b1 == prev_b1 && b2 == prev_b2 { break; }
            }
        }
        b1
    }

    /// Depth-first post-order traversal of the CFG starting from entry.
    fn post_order(blocks: &[BasicBlock], entry: BlockId) -> Vec<BlockId> {
        let n = blocks.len();
        let mut visited = vec![false; n];
        let mut result = Vec::new();
        Self::dfs_post(blocks, entry, &mut visited, &mut result);
        result
    }

    fn dfs_post(blocks: &[BasicBlock], b: BlockId, visited: &mut [bool], result: &mut Vec<BlockId>) {
        if visited[b as usize] { return; }
        visited[b as usize] = true;
        for succ in blocks[b as usize].successors() {
            Self::dfs_post(blocks, succ, visited, result);
        }
        result.push(b);
    }
}
