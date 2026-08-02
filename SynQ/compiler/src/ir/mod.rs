// ── SSA IR Module ─────────────────────────────────────────────────────────────
//
// Typed Static Single Assignment (SSA) Intermediate Representation.
// Sits between the AST and the stack bytecode backend.
//
// Pipeline:  Source → Parser → AST → IR Builder → SSA Module → Analyzer → Backend
//
// The IR provides:
//   • Explicit control-flow graph (CFG) with basic blocks
//   • SSA value numbering (every variable assigned exactly once)
//   • Phi (φ) nodes at merge points for path-dependent values
//   • Typed values (IrType) for compile-time type checking
//   • Explicit effect operations (stores, emits, fact consumption)
//   • Authority check nodes (analyzable, not just opcode sequences)
//   • Linear-resource move tracking (compile-time linearity)
//   • Host-function profile declarations (no implicit host calls)
//
// Acronyms:
//   SSA  — Static Single Assignment (every value defined once)
//   IR   — Intermediate Representation (between source and bytecode)
//   CFG  — Control Flow Graph (blocks connected by branch/jump edges)
//   Phi  — φ-node: merges values from multiple CFG predecessors

pub mod types;
pub mod instructions;
pub mod blocks;
pub mod function;
pub mod module;
pub mod builder;
pub mod analyzer;
pub mod passes;
pub mod lower;
pub mod serialize;
pub mod decompile;

pub use types::*;
pub use instructions::*;
pub use blocks::*;
pub use function::*;
pub use module::*;
pub use builder::*;
pub use analyzer::*;
pub use passes::*;
pub use lower::*;
pub use serialize::{serialize, deserialize};
pub use decompile::decompile;
