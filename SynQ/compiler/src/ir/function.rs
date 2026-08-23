// ── Function-level IR ──────────────────────────────────────────────────────────
//
// An IrFunction holds the complete SSA IR for one function: its CFG (basic blocks),
// parameters, return type, attributes, and metadata (effects, authority, bounds).

use crate::ast::Attribute;
use super::types::*;
use super::blocks::*;

/// IR representation of a single function.
#[derive(Debug, Clone)]
pub struct IrFunction {
    /// Function name.
    pub name: String,
    /// Parameters: (name, type).
    pub params: Vec<(String, IrType)>,
    /// Return type (None for void).
    pub return_type: Option<IrType>,
    /// Basic blocks indexed by BlockId.
    pub blocks: Vec<BasicBlock>,
    /// Entry block ID (always 0).
    pub entry: BlockId,

    // ── Metadata from AST ──────────────────────────────────────────────
    /// `as caller` — requires authenticated caller.
    pub requires_caller: bool,
    /// Parsed `@attribute` declarations.
    pub attributes: Vec<Attribute>,
    /// State variables this function reads (for effect analysis).
    pub requires_state: Vec<String>,
    /// State variables this function modifies (for effect analysis).
    pub modifies: Vec<String>,
    /// Function is public (callable from outside).
    pub is_public: bool,

    // ── SSA bookkeeping ────────────────────────────────────────────────
    /// Next block ID to allocate.
    pub next_block: BlockId,
    /// SSA value counter (not strictly needed since ValueId = InstId,
    /// but kept for future flexibility with separate value numbering).
    pub next_value: ValueId,

    // ── Analysis results (populated by analyzer) ──────────────────────
    /// Effects collected by the analyzer.
    pub collected_effects: Vec<EffectKind>,
    /// Host function profiles declared in this function.
    pub host_profiles: Vec<HostFnProfile>,
    /// Dominator tree (computed by analyzer).
    pub dom_tree: Option<DominatorTree>,
}

impl IrFunction {
    /// Create a new empty function.
    pub fn new(name: &str, params: Vec<(String, IrType)>, return_type: Option<IrType>) -> Self {
        let entry = BasicBlock::new(0);
        Self {
            name: name.to_string(),
            params,
            return_type,
            blocks: vec![entry],
            entry: 0,
            requires_caller: false,
            attributes: Vec::new(),
            requires_state: Vec::new(),
            modifies: Vec::new(),
            is_public: false,
            next_block: 1,
            next_value: 0,
            collected_effects: Vec::new(),
            host_profiles: Vec::new(),
            dom_tree: None,
        }
    }

    /// Allocate a new basic block and return its ID.
    pub fn new_block(&mut self) -> BlockId {
        let id = self.next_block;
        self.next_block += 1;
        self.blocks.push(BasicBlock::new(id));
        id
    }

    /// Allocate a globally-unique ValueId for a new value-producing instruction.
    pub fn alloc_value(&mut self) -> ValueId {
        let id = self.next_value;
        self.next_value += 1;
        id
    }

    /// Get the current (last-allocated, unterminated) block.
    pub fn current_block(&mut self) -> &mut BasicBlock {
        let id = self.next_block - 1;
        &mut self.blocks[id as usize]
    }

    /// Get a block by ID.
    pub fn block(&self, id: BlockId) -> &BasicBlock {
        &self.blocks[id as usize]
    }

    /// Get a mutable block by ID.
    pub fn block_mut(&mut self, id: BlockId) -> &mut BasicBlock {
        &mut self.blocks[id as usize]
    }

    /// Add a predecessor edge (call when connecting blocks).
    pub fn add_pred(&mut self, block: BlockId, pred: BlockId) {
        if !self.blocks[block as usize].preds.contains(&pred) {
            self.blocks[block as usize].preds.push(pred);
        }
    }

    /// Total instruction count across all blocks.
    pub fn inst_count(&self) -> usize {
        self.blocks.iter().map(|b| b.insts.len()).sum()
    }

    /// Pretty-print the function IR for debugging.
    pub fn dump(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("fn {}(", self.name));
        let params: Vec<String> = self.params.iter()
            .map(|(n, t)| format!("{}: {}", n, t.name()))
            .collect();
        out.push_str(&params.join(", "));
        out.push_str(")");
        if let Some(rt) = &self.return_type {
            out.push_str(&format!(" -> {}", rt.name()));
        }

        // Show attributes
        let attrs: Vec<String> = self.attributes.iter()
            .map(|a| format!("{:?}", a))
            .collect();
        if !attrs.is_empty() {
            out.push_str(&format!("  // attrs: {}", attrs.join(", ")));
        }

        out.push_str(" {\n");

        for block in &self.blocks {
            // Skip empty unreachable blocks in dump
            if !block.reachable && block.insts.is_empty() {
                continue;
            }
            out.push_str(&format!("  block_{}:{{\n", block.id));
            // Show predecessors
            if !block.preds.is_empty() {
                let preds: Vec<String> = block.preds.iter().map(|p| format!("block_{}", p)).collect();
                out.push_str(&format!("    // preds: {}\n", preds.join(", ")));
            }
            // Show reachability
            if !block.reachable {
                out.push_str("    // UNREACHABLE\n");
            }
            for inst in &block.insts {
                if inst.result_type.is_void() {
                    out.push_str(&format!("    {} = {:?}", inst.value_id, inst.op));
                } else {
                    out.push_str(&format!("    v{}: {} = {:?}", inst.value_id, inst.result_type.name(), inst.op));
                }
                out.push_str("\n");
            }
            out.push_str("  }\n");
        }
        out.push_str("}\n");
        out
    }
}
