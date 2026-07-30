// ── Module-level IR ────────────────────────────────────────────────────────────
//
// An IrModule holds the complete SSA IR for one contract: its functions,
// state variable layout, struct/enum definitions, and event declarations.

use std::collections::HashMap;
use crate::ast::{StructDefinition, EnumDefinition, EventDefinition};
use super::function::*;
use super::types::*;

/// IR representation of a complete contract module.
#[derive(Debug, Clone)]
pub struct IrModule {
    /// Contract name.
    pub contract_name: String,
    /// Function IRs indexed by name.
    pub functions: Vec<IrFunction>,
    /// State variables: (name, type, memory_address).
    pub state_vars: Vec<(String, IrType, u32)>,
    /// Struct definitions (name → fields).
    pub struct_defs: HashMap<String, StructDefinition>,
    /// Enum definitions (name → variants).
    pub enum_defs: HashMap<String, EnumDefinition>,
    /// Event definitions.
    pub event_defs: Vec<EventDefinition>,
    /// Contracts referenced via extern_call.
    pub extern_contracts: Vec<String>,
}

impl IrModule {
    /// Create a new empty module.
    pub fn new(contract_name: &str) -> Self {
        Self {
            contract_name: contract_name.to_string(),
            functions: Vec::new(),
            state_vars: Vec::new(),
            struct_defs: HashMap::new(),
            enum_defs: HashMap::new(),
            event_defs: Vec::new(),
            extern_contracts: Vec::new(),
        }
    }

    /// Get a function by name.
    pub fn get_function(&self, name: &str) -> Option<&IrFunction> {
        self.functions.iter().find(|f| f.name == name)
    }

    /// Pretty-print the entire module for debugging.
    pub fn dump(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("module {} {{\n\n", self.contract_name));

        // State vars
        if !self.state_vars.is_empty() {
            out.push_str("  // State variables\n");
            for (name, ty, addr) in &self.state_vars {
                out.push_str(&format!("  {}: {} @ addr={}\n", name, ty.name(), addr));
            }
            out.push_str("\n");
        }

        // Structs
        for (name, def) in &self.struct_defs {
            out.push_str(&format!("  struct {} {{ ", name));
            let fields: Vec<String> = def.fields.iter()
                .map(|f| format!("{}: {:?}", f.name, f.ty))
                .collect();
            out.push_str(&fields.join(", "));
            out.push_str(" }\n");
        }

        // Enums
        for (name, def) in &self.enum_defs {
            out.push_str(&format!("  enum {} {{ ", name));
            let variants: Vec<String> = def.variants.iter()
                .map(|v| v.name.clone())
                .collect();
            out.push_str(&variants.join(", "));
            out.push_str(" }\n");
        }

        out.push_str("\n");

        // Functions
        for func in &self.functions {
            out.push_str(&func.dump());
            out.push_str("\n");
        }

        out.push_str("}\n");
        out
    }
}
