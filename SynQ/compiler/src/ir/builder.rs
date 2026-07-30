// ── IR Builder: AST → SSA IR ──────────────────────────────────────────────────
//
// Walks the parsed AST and constructs the SSA IR module. For each function,
// the builder:
//   1. Creates an entry block with parameter values
//   2. Flattens nested if/while into basic blocks connected by Branch/Jump
//   3. Emits SSA instructions for each statement and expression
//   4. Inserts phi nodes at merge points (deferred to a post-pass)
//   5. Records effects, host profiles, and authority checks
//
// The builder does NOT optimize — it produces a faithful IR representation
// of the source. Optimization passes run later on the IR.

use std::collections::HashMap;
use crate::ast::*;
use super::types::*;
use super::instructions::*;
use super::blocks::*;
use super::function::*;
use super::module::*;

/// Builds SSA IR from the parsed AST.
pub struct IrBuilder {
    /// State variable name → (type, memory address)
    state_vars: HashMap<String, (IrType, u32)>,
    /// Struct definitions
    struct_defs: HashMap<String, StructDefinition>,
    /// Enum definitions
    enum_defs: HashMap<String, EnumDefinition>,
    /// Event definitions
    event_defs: Vec<EventDefinition>,
    /// Next state variable address
    next_state_addr: u32,
    /// Extern call targets collected during building
    extern_contracts: Vec<String>,
}

impl IrBuilder {
    pub fn new() -> Self {
        Self {
            state_vars: HashMap::new(),
            struct_defs: HashMap::new(),
            enum_defs: HashMap::new(),
            event_defs: Vec::new(),
            next_state_addr: 0,
            extern_contracts: Vec::new(),
        }
    }

    /// Build IR for all contracts in the source unit.
    /// Currently handles the first contract (multi-contract support is future work).
    pub fn build(&mut self, units: &[SourceUnit]) -> Result<IrModule, String> {
        // First pass: collect state vars, structs, enums from all contracts
        for unit in units {
            match unit {
                SourceUnit::Contract(c) => {
                    for part in &c.parts {
                        match part {
                            ContractPart::StateVariable(sv) => {
                                let addr = self.next_state_addr;
                                self.next_state_addr += 1;
                                let ir_ty = IrType::from_ast(&sv.ty);
                                self.state_vars.insert(sv.name.clone(), (ir_ty, addr));
                            }
                            ContractPart::Event(ev) => {
                                self.event_defs.push(ev.clone());
                            }
                            _ => {}
                        }
                    }
                    // Collect structs and enums from contract parts
                    for part in &c.parts {
                        if let ContractPart::Function(_) = part {
                            // Structs/enums are declared in state{} or impl{} blocks
                            // They're already in c's metadata or inline
                        }
                    }
                }
                SourceUnit::Struct(s) => {
                    self.struct_defs.insert(s.name.clone(), s.clone());
                }
                SourceUnit::Enum(e) => {
                    self.enum_defs.insert(e.name.clone(), e.clone());
                }
                _ => {}
            }
        }

        // Also scan for struct/enum definitions in contract state blocks
        for unit in units {
            if let SourceUnit::Contract(c) = unit {
                for part in &c.parts {
                    match part {
                        ContractPart::StateVariable(_) => {}
                        ContractPart::Constructor(_) => {}
                        ContractPart::Function(f) => {
                            // Scan for struct/enum defs in state{} — actually
                            // structs and enums are top-level SourceUnits in our grammar
                        }
                        ContractPart::Event(_) => {}
                    }
                }
                // Build IR for each function
                let mut ir_module = IrModule::new(&c.name);
                ir_module.struct_defs = self.struct_defs.clone();
                ir_module.enum_defs = self.enum_defs.clone();
                ir_module.event_defs = self.event_defs.clone();

                // Collect state vars into module
                for (name, (ty, addr)) in &self.state_vars {
                    ir_module.state_vars.push((name.clone(), ty.clone(), *addr));
                }

                // Build each function
                for part in &c.parts {
                    if let ContractPart::Function(f) = part {
                        let ir_fn = self.build_function(f)?;
                        ir_module.functions.push(ir_fn);
                    }
                }

                // Build test functions too
                for f in &c.test_fns {
                    let ir_fn = self.build_function(f)?;
                    ir_module.functions.push(ir_fn);
                }

                ir_module.extern_contracts = self.extern_contracts.clone();
                return Ok(ir_module);
            }
        }

        Ok(IrModule::new("empty"))
    }

    /// Build IR for a single function.
    fn build_function(&mut self, f: &FunctionDefinition) -> Result<IrFunction, String> {
        // Convert params to IR types
        let params: Vec<(String, IrType)> = f.params.iter()
            .map(|p| (p.name.clone(), IrType::from_ast(&p.ty)))
            .collect();
        let return_type = f.returns.as_ref().map(IrType::from_ast);

        let mut ir_fn = IrFunction::new(&f.name, params.clone(), return_type);
        ir_fn.requires_caller = f.requires_caller;
        ir_fn.attributes = f.attributes.clone();
        ir_fn.requires_state = f.requires_state.clone();
        ir_fn.modifies = f.modifies.clone();
        ir_fn.is_public = f.is_public;

        // Entry block: emit param values as Const-like placeholder loads
        // In SSA, parameters are available as predefined values at the entry.
        // We represent them as special "param" instructions.
        let mut param_values: HashMap<String, ValueId> = HashMap::new();
        for (i, (name, ty)) in params.iter().enumerate() {
            // Param values are represented as Load instructions with special names
            // For simplicity, we use the param name as the value identifier
            let inst = Instruction {
                op: IrOp::Load(format!("__param_{}", name)),
                result_type: ty.clone(),
                line: 0,
            };
            let val_id = ir_fn.blocks[0].push_value(inst);
            param_values.insert(name.clone(), val_id);
        }

        // Build the function body
        let mut ctx = BuildContext {
            ir_fn: &mut ir_fn,
            param_values,
            local_values: HashMap::new(),
            state_vars: &self.state_vars,
            struct_defs: &self.struct_defs,
            enum_defs: &self.enum_defs,
            current_block: 0,
            break_targets: Vec::new(),
            continue_targets: Vec::new(),
            extern_contracts: &mut self.extern_contracts,
        };

        for stmt in &f.body.statements {
            ctx.build_statement(stmt)?;
        }

        // Ensure the current block is terminated
        if !ctx.current_block_terminated() {
            // Implicit return
            let ret_inst = Instruction::effect(IrOp::Return(None));
            ctx.ir_fn.block_mut(ctx.current_block).set_terminator(ret_inst);
        }

        Ok(ir_fn)
    }
}

/// Mutable context during function body building.
/// Tracks the current block, local variable SSA values, and loop targets.
struct BuildContext<'a> {
    ir_fn: &'a mut IrFunction,
    /// Parameter name → SSA value ID in entry block
    param_values: HashMap<String, ValueId>,
    /// Local variable (let bindings) → SSA value ID
    local_values: HashMap<String, ValueId>,
    /// State variable name → (type, address)
    state_vars: &'a HashMap<String, (IrType, u32)>,
    /// Struct definitions
    struct_defs: &'a HashMap<String, StructDefinition>,
    /// Enum definitions
    enum_defs: &'a HashMap<String, EnumDefinition>,
    /// Current block ID being built.
    current_block: BlockId,
    /// Stack of break target block IDs (for while loops)
    break_targets: Vec<BlockId>,
    /// Stack of continue target block IDs (for while loops)
    continue_targets: Vec<BlockId>,
    /// Extern call targets collected during building
    extern_contracts: &'a mut Vec<String>,
}

impl<'a> BuildContext<'a> {
    /// Check if the current block is terminated.
    fn current_block_terminated(&self) -> bool {
        self.ir_fn.block(self.current_block).is_terminated()
    }

    /// Push a value-producing instruction and return its ValueId.
    fn push_value(&mut self, op: IrOp, result_type: IrType) -> ValueId {
        let inst = Instruction::value(op, result_type);
        self.ir_fn.block_mut(self.current_block).push_value(inst)
    }

    /// Push an effect-only instruction.
    fn push_effect(&mut self, op: IrOp) {
        let inst = Instruction::effect(op);
        self.ir_fn.block_mut(self.current_block).push_value(inst);
    }

    /// Terminate the current block and create a new one.
    fn terminate_and_new(&mut self, terminator: Instruction) -> BlockId {
        self.ir_fn.block_mut(self.current_block).set_terminator(terminator);
        let new_id = self.ir_fn.new_block();
        // The new block's predecessor is the current block
        let old = self.current_block;
        self.ir_fn.add_pred(new_id, old);
        self.current_block = new_id;
        new_id
    }

    /// Look up a variable name and return its SSA value + type.
    /// Checks locals first, then params, then state vars.
    fn lookup_var(&self, name: &str) -> Result<(ValueId, IrType), String> {
        if let Some(&vid) = self.local_values.get(name) {
            let ty = self.lookup_value_type(vid);
            Ok((vid, ty))
        } else if let Some(&vid) = self.param_values.get(name) {
            let ty = self.lookup_value_type(vid);
            Ok((vid, ty))
        } else if let Some((ty, _addr)) = self.state_vars.get(name) {
            // State variable — we need to emit a Load instruction
            // Return a sentinel: the caller should use build_load instead
            Err(format!("__state_var__{}", name))
        } else {
            Err(format!("undefined variable: {}", name))
        }
    }

    /// Look up the result type of a value by searching all blocks.
    /// ValueId is per-block, so we need to find which block contains it.
    fn lookup_value_type(&self, vid: ValueId) -> IrType {
        // Try block 0 first (params are always there)
        if let Some(inst) = self.ir_fn.block(0).insts.get(vid as usize) {
            return inst.result_type.clone();
        }
        // Search all blocks
        for b in 0..self.ir_fn.blocks.len() {
            if let Some(inst) = self.ir_fn.block(b as BlockId).insts.get(vid as usize) {
                return inst.result_type.clone();
            }
        }
        // Fallback — shouldn't happen but prevents panic
        IrType::U256
    }

    /// Build IR for a statement.
    fn build_statement(&mut self, stmt: &Statement) -> Result<(), String> {
        match stmt {
            Statement::Expression(expr) => {
                self.build_expression(expr)?;
                Ok(())
            }

            Statement::Require(cond, msg) => {
                let cond_val = self.build_expression(cond)?;
                self.push_effect(IrOp::Require(cond_val, msg.clone()));
                Ok(())
            }

            Statement::RevertNamed { error, args } => {
                let arg_vals: Result<Vec<ValueId>, String> = args.iter()
                    .map(|a| self.build_expression(a))
                    .collect();
                let arg_vals = arg_vals?;
                self.push_effect(IrOp::RevertNamed(String::new(), error.clone(), arg_vals));
                Ok(())
            }

            Statement::RevertEnum { enum_name, error, args } => {
                let arg_vals: Result<Vec<ValueId>, String> = args.iter()
                    .map(|a| self.build_expression(a))
                    .collect();
                let arg_vals = arg_vals?;
                self.push_effect(IrOp::RevertNamed(enum_name.clone(), error.clone(), arg_vals));
                Ok(())
            }

            Statement::Assignment(name, expr) => {
                let val = self.build_expression(expr)?;

                // Check if it's a state variable
                if self.state_vars.contains_key(name) {
                    let (ty, _) = self.state_vars[name].clone();
                    self.push_effect(IrOp::Store(name.clone(), val));
                    // Record the write effect
                    self.ir_fn.collected_effects.push(EffectKind::Write(name.clone()));
                } else if let Some(_vid) = self.local_values.get(name) {
                    // Local reassignment — in SSA, this creates a new value
                    // and updates the local_values map.
                    self.local_values.insert(name.clone(), val);
                } else if let Some(_vid) = self.param_values.get(name) {
                    // Param reassignment — same as local
                    self.local_values.insert(name.clone(), val);
                } else {
                    return Err(format!("assignment to undefined variable: {}", name));
                }
                Ok(())
            }

            Statement::FieldAssignment { object, field, value } => {
                let val = self.build_expression(value)?;

                if self.state_vars.contains_key(object) {
                    self.push_effect(IrOp::FieldStore(object.clone(), field.clone(), val));
                    self.ir_fn.collected_effects.push(EffectKind::Write(object.clone()));
                } else {
                    // Local struct field assignment
                    let obj_val = match self.local_values.get(object) {
                        Some(&v) => v,
                        None => match self.param_values.get(object) {
                            Some(&v) => v,
                            None => return Err(format!("field assignment on undefined: {}", object)),
                        }
                    };

                    // Get field index from struct def
                    let field_idx = if let Some(def) = self.struct_defs.get(object) {
                        def.fields.iter().position(|f| f.name == *field)
                            .map(|i| i as u32)
                            .unwrap_or(0)
                    } else {
                        0
                    };

                    let idx_val = self.push_value(IrOp::Const(Literal::Number(field_idx as u128)), IrType::I32);
                    let tuple_ty = self.lookup_value_type(obj_val);
                    let new_tuple = self.push_value(
                        IrOp::TupleSet(obj_val, idx_val, val),
                        tuple_ty,
                    );
                    self.local_values.insert(object.clone(), new_tuple);
                }
                Ok(())
            }

            Statement::MapAssignment { map, key, value } => {
                let key_val = self.build_expression(key)?;
                let val = self.build_expression(value)?;
                self.push_effect(IrOp::MapSet(map.clone(), key_val, val));
                self.ir_fn.collected_effects.push(EffectKind::Write(map.clone()));
                Ok(())
            }

            Statement::SetOp { set, op, value } => {
                let val = self.build_expression(value)?;
                self.push_effect(IrOp::SetOp(set.clone(), op.clone(), val));
                self.ir_fn.collected_effects.push(EffectKind::Write(set.clone()));
                Ok(())
            }

            Statement::Let { name, ty, value } => {
                let val = self.build_expression(value)?;
                // The value's type comes from the expression
                // If a type annotation is given, use it; otherwise infer from the value
                let result_ty = if let Some(t) = ty {
                    IrType::from_ast(t)
                } else {
                    self.lookup_value_type(val)
                };
                self.local_values.insert(name.clone(), val);
                Ok(())
            }

            Statement::Return(expr) => {
                let val = match expr {
                    Some(e) => Some(self.build_expression(e)?),
                    None => None,
                };
                let ret_inst = Instruction::effect(IrOp::Return(val));
                self.ir_fn.block_mut(self.current_block).set_terminator(ret_inst);
                Ok(())
            }

            Statement::ExternCall { contract, function, args } => {
                if !self.extern_contracts.contains(contract) {
                    self.extern_contracts.push(contract.clone());
                }
                let arg_vals: Result<Vec<ValueId>, String> = args.iter()
                    .map(|a| self.build_expression(a))
                    .collect();
                let arg_vals = arg_vals?;
                let ret_ty = IrType::U256; // extern calls return u256 (could be improved with type info)
                let _ = self.push_value(
                    IrOp::ExternCall(contract.clone(), function.clone(), arg_vals),
                    ret_ty.clone(),
                );
                // Record host profile
                self.ir_fn.host_profiles.push(HostFnProfile {
                    kind: HostFnKind::ExternCall,
                    callee: format!("{}.{}", contract, function),
                    arg_types: vec![],
                    return_type: ret_ty,
                });
                Ok(())
            }

            Statement::Emit { event, args } => {
                let arg_vals: Result<Vec<ValueId>, String> = args.iter()
                    .map(|a| self.build_expression(a))
                    .collect();
                let arg_vals = arg_vals?;
                self.push_effect(IrOp::Emit(event.clone(), arg_vals));
                self.ir_fn.collected_effects.push(EffectKind::Emit(event.clone()));
                Ok(())
            }

            Statement::If { condition, then_block, else_block } => {
                let cond_val = self.build_expression(condition)?;

                // Create blocks for then, else (if present), and merge
                let then_block_id = self.ir_fn.new_block();
                let else_block_id = if else_block.is_some() {
                    self.ir_fn.new_block()
                } else {
                    self.ir_fn.new_block() // empty else → just merge
                };
                let merge_block_id = self.ir_fn.new_block();

                // Terminate current block with Branch
                let branch = Instruction::effect(IrOp::Branch(cond_val, then_block_id, else_block_id));
                self.ir_fn.block_mut(self.current_block).set_terminator(branch);

                // Set up predecessor edges
                self.ir_fn.add_pred(then_block_id, self.current_block);
                self.ir_fn.add_pred(else_block_id, self.current_block);

                // Build then block
                self.current_block = then_block_id;
                for stmt in &then_block.statements {
                    self.build_statement(stmt)?;
                }
                if !self.current_block_terminated() {
                    let jump = Instruction::effect(IrOp::Jump(merge_block_id));
                    self.ir_fn.block_mut(self.current_block).set_terminator(jump);
                    self.ir_fn.add_pred(merge_block_id, self.current_block);
                }

                // Build else block
                self.current_block = else_block_id;
                if let Some(eb) = else_block {
                    for stmt in &eb.statements {
                        self.build_statement(stmt)?;
                    }
                }
                if !self.current_block_terminated() {
                    let jump = Instruction::effect(IrOp::Jump(merge_block_id));
                    self.ir_fn.block_mut(self.current_block).set_terminator(jump);
                    self.ir_fn.add_pred(merge_block_id, self.current_block);
                }

                // Continue building in merge block
                self.current_block = merge_block_id;
                Ok(())
            }

            Statement::While { condition, body } => {
                // Create loop header, body, and exit blocks
                let header_id = self.ir_fn.new_block();
                let body_id = self.ir_fn.new_block();
                let exit_id = self.ir_fn.new_block();

                // Jump from current block to header
                let jump = Instruction::effect(IrOp::Jump(header_id));
                self.ir_fn.block_mut(self.current_block).set_terminator(jump);
                self.ir_fn.add_pred(header_id, self.current_block);

                // Header block: evaluate condition, branch to body or exit
                self.current_block = header_id;
                let cond_val = self.build_expression(condition)?;
                let branch = Instruction::effect(IrOp::Branch(cond_val, body_id, exit_id));
                self.ir_fn.block_mut(self.current_block).set_terminator(branch);
                self.ir_fn.add_pred(body_id, header_id);
                self.ir_fn.add_pred(exit_id, header_id);

                // Body block: build loop body
                self.current_block = body_id;
                self.break_targets.push(exit_id);
                self.continue_targets.push(header_id);
                for stmt in &body.statements {
                    self.build_statement(stmt)?;
                }
                self.break_targets.pop();
                self.continue_targets.pop();

                if !self.current_block_terminated() {
                    let jump = Instruction::effect(IrOp::Jump(header_id));
                    self.ir_fn.block_mut(self.current_block).set_terminator(jump);
                    self.ir_fn.add_pred(header_id, self.current_block);
                }

                // Continue in exit block
                self.current_block = exit_id;
                Ok(())
            }

            Statement::Break => {
                if let Some(&target) = self.break_targets.last() {
                    let jump = Instruction::effect(IrOp::Jump(target));
                    self.ir_fn.block_mut(self.current_block).set_terminator(jump);
                    self.ir_fn.add_pred(target, self.current_block);
                    // Create a dead block for any code after break
                    let dead = self.ir_fn.new_block();
                    self.current_block = dead;
                } else {
                    return Err("break outside of loop".into());
                }
                Ok(())
            }

            Statement::Continue => {
                if let Some(&target) = self.continue_targets.last() {
                    let jump = Instruction::effect(IrOp::Jump(target));
                    self.ir_fn.block_mut(self.current_block).set_terminator(jump);
                    self.ir_fn.add_pred(target, self.current_block);
                    let dead = self.ir_fn.new_block();
                    self.current_block = dead;
                } else {
                    return Err("continue outside of loop".into());
                }
                Ok(())
            }
        }
    }

    /// Build IR for an expression and return the resulting SSA ValueId.
    fn build_expression(&mut self, expr: &Expression) -> Result<ValueId, String> {
        match expr {
            Expression::Literal(lit) => {
                let ty = match lit {
                    Literal::Bool(_) => IrType::Bool,
                    Literal::Number(_) => IrType::U256,
                    Literal::BigNumber(_) => IrType::U256,
                    Literal::String(_) => IrType::Str,
                    Literal::Hex(_) => IrType::Bytes,
                };
                Ok(self.push_value(IrOp::Const(lit.clone()), ty))
            }

            Expression::Identifier(name) => {
                match self.lookup_var(name) {
                    Ok((vid, _ty)) => Ok(vid),
                    Err(e) if e.starts_with("__state_var__") => {
                        let var_name = &e["__state_var__".len()..];
                        let (ty, _) = self.state_vars[var_name].clone();
                        Ok(self.push_value(IrOp::Load(var_name.to_string()), ty))
                    }
                    Err(e) => Err(e),
                }
            }

            Expression::BinaryOp(lhs, op, rhs) => {
                let lhs_val = self.build_expression(lhs)?;
                let rhs_val = self.build_expression(rhs)?;
                let result_ty = match op {
                    BinaryOperator::Eq | BinaryOperator::Ne
                    | BinaryOperator::Lt | BinaryOperator::Le
                    | BinaryOperator::Gt | BinaryOperator::Ge
                    | BinaryOperator::And | BinaryOperator::Or => IrType::Bool,
                    _ => IrType::U256,
                };
                Ok(self.push_value(IrOp::BinOp(*op, lhs_val, rhs_val), result_ty))
            }

            Expression::UnaryOp(op, operand) => {
                let val = self.build_expression(operand)?;
                let result_ty = match op {
                    UnaryOperator::Not => IrType::Bool,
                    UnaryOperator::Neg => IrType::U256,
                };
                Ok(self.push_value(IrOp::UnaryOp(*op, val), result_ty))
            }

            Expression::Caller => {
                Ok(self.push_value(IrOp::Caller, IrType::Address))
            }

            Expression::Call(name, args) => {
                let arg_vals: Result<Vec<ValueId>, String> = args.iter()
                    .map(|a| self.build_expression(a))
                    .collect();
                let arg_vals = arg_vals?;

                // Check for builtins
                match name.as_str() {
                    "to_syna" => {
                        Ok(self.push_value(IrOp::AddrEncode(arg_vals[0]), IrType::Str))
                    }
                    "from_syna" | "from_syn" => {
                        Ok(self.push_value(IrOp::AddrDecode(arg_vals[0]), IrType::Address))
                    }
                    "contract_address" => {
                        Ok(self.push_value(IrOp::ContractAddr(arg_vals[0], arg_vals[1], arg_vals[2]), IrType::Str))
                    }
                    "asset_create" => {
                        // type_name is a string literal, value is u256
                        let type_name = match &args[0] {
                            Expression::Literal(Literal::String(s)) => s.clone(),
                            _ => "unknown".to_string(),
                        };
                        Ok(self.push_value(IrOp::AssetCreate(type_name, arg_vals[1]), IrType::U256))
                    }
                    "asset_transfer" => {
                        Ok(self.push_value(IrOp::AssetTransfer(arg_vals[0], arg_vals[1]), IrType::U256))
                    }
                    "asset_burn" => {
                        Ok(self.push_value(IrOp::AssetBurn(arg_vals[0]), IrType::U256))
                    }
                    "asset_balance" => {
                        Ok(self.push_value(IrOp::AssetBalance(arg_vals[0]), IrType::U256))
                    }
                    "asset_owner" => {
                        Ok(self.push_value(IrOp::AssetOwner(arg_vals[0]), IrType::U256))
                    }
                    "aegis_call" | "aegis_verify" | "aegis_decaps" => {
                        let op = if name == "aegis_verify" {
                            IrOp::AegisVerify(arg_vals)
                        } else if name == "aegis_decaps" {
                            IrOp::AegisDecaps(arg_vals)
                        } else {
                            IrOp::AegisCall(arg_vals)
                        };
                        self.ir_fn.host_profiles.push(HostFnProfile {
                            kind: HostFnKind::AegisCall,
                            callee: name.clone(),
                            arg_types: vec![],
                            return_type: IrType::Bool,
                        });
                        Ok(self.push_value(op, IrType::Bool))
                    }
                    "dilithium_verify" | "falcon_verify" | "sphincs_verify" => {
                        self.ir_fn.host_profiles.push(HostFnProfile {
                            kind: HostFnKind::PqcVerify,
                            callee: name.clone(),
                            arg_types: vec![],
                            return_type: IrType::Bool,
                        });
                        Ok(self.push_value(IrOp::AegisVerify(arg_vals), IrType::Bool))
                    }
                    "kyber_encapsulate" | "kyber_decapsulate" | "kyber_decaps"
                    | "mceliece_encapsulate" | "mceliece_decapsulate"
                    | "hqc_encapsulate" | "hqc_decapsulate" => {
                        self.ir_fn.host_profiles.push(HostFnProfile {
                            kind: HostFnKind::PqcKem,
                            callee: name.clone(),
                            arg_types: vec![],
                            return_type: IrType::Bytes,
                        });
                        Ok(self.push_value(IrOp::AegisCall(arg_vals), IrType::Bytes))
                    }
                    _ => {
                        // User-defined function call
                        Ok(self.push_value(IrOp::Call(name.clone(), arg_vals), IrType::U256))
                    }
                }
            }

            Expression::MapIndex(map, key) => {
                let key_val = self.build_expression(key)?;
                let (val_ty, _) = self.state_vars.get(map)
                    .map(|(t, a)| (t.clone(), *a))
                    .unwrap_or((IrType::U256, 0));
                Ok(self.push_value(IrOp::MapGet(map.clone(), key_val), val_ty))
            }

            Expression::MapMethod { map, method, args } => {
                let arg_vals: Result<Vec<ValueId>, String> = args.iter()
                    .map(|a| self.build_expression(a))
                    .collect();
                let arg_vals = arg_vals?;
                let result_ty = match method.as_str() {
                    "contains" => IrType::Bool,
                    "len" => IrType::I32,
                    _ => IrType::U256,
                };
                Ok(self.push_value(IrOp::MapMethod(map.clone(), method.clone(), arg_vals), result_ty))
            }

            Expression::SetMethod { set, method, args } => {
                let arg_vals: Result<Vec<ValueId>, String> = args.iter()
                    .map(|a| self.build_expression(a))
                    .collect();
                let arg_vals = arg_vals?;
                let result_ty = match method.as_str() {
                    "contains" => IrType::Bool,
                    "len" => IrType::I32,
                    _ => IrType::Void,
                };
                Ok(self.push_value(IrOp::SetMethod(set.clone(), method.clone(), arg_vals), result_ty))
            }

            Expression::Tuple(exprs) => {
                let vals: Result<Vec<ValueId>, String> = exprs.iter()
                    .map(|e| self.build_expression(e))
                    .collect();
                let vals = vals?;
                let types: Vec<IrType> = vals.iter()
                    .map(|v| self.ir_fn.block(self.current_block).insts[*v as usize].result_type.clone())
                    .collect();
                Ok(self.push_value(IrOp::Tuple(vals), IrType::Tuple(types)))
            }

            Expression::Some(inner) => {
                let val = self.build_expression(inner)?;
                let inner_ty = self.ir_fn.block(self.current_block).insts[val as usize].result_type.clone();
                Ok(self.push_value(IrOp::Some(val), IrType::Option(Box::new(inner_ty))))
            }

            Expression::None => {
                Ok(self.push_value(IrOp::None, IrType::Option(Box::new(IrType::U256))))
            }

            Expression::Ok(inner) => {
                let val = self.build_expression(inner)?;
                let inner_ty = self.ir_fn.block(self.current_block).insts[val as usize].result_type.clone();
                Ok(self.push_value(IrOp::Ok(val), IrType::Result(Box::new(inner_ty), Box::new(IrType::U256))))
            }

            Expression::Err(inner) => {
                let val = self.build_expression(inner)?;
                let inner_ty = self.ir_fn.block(self.current_block).insts[val as usize].result_type.clone();
                Ok(self.push_value(IrOp::Err(val), IrType::Result(Box::new(IrType::U256), Box::new(inner_ty))))
            }

            Expression::FieldAccess { object, field } => {
                let obj_val = self.build_expression(object)?;
                let field_idx = self.get_field_index(object, field);
                Ok(self.push_value(IrOp::FieldAccess(obj_val, field.clone()), IrType::U256))
            }

            Expression::EnumAccess { enum_name, variant_name } => {
                Ok(self.push_value(IrOp::EnumAccess(enum_name.clone(), variant_name.clone()), IrType::I32))
            }

            Expression::StructLiteral { type_name, fields } => {
                let mut field_vals = Vec::new();
                for (fname, fexpr) in fields {
                    let val = self.build_expression(fexpr)?;
                    field_vals.push((fname.clone(), val));
                }
                Ok(self.push_value(IrOp::StructLiteral(type_name.clone(), field_vals), IrType::Named(type_name.clone())))
            }
        }
    }

    /// Get the field index for a struct field access.
    fn get_field_index(&self, obj: &Expression, field: &str) -> u32 {
        // Try to get the struct type name from the object
        let struct_name = match obj {
            Expression::Identifier(name) => {
                // Check if it's a state var or local with a Named type
                self.state_vars.get(name).map(|(ty, _)| ty.clone())
                    .or_else(|| self.local_values.get(name).and_then(|vid| {
                        let ty = self.lookup_value_type(*vid);
                        if let IrType::Named(n) = ty { Some(IrType::Named(n.clone())) } else { None }
                    }))
                    .and_then(|ty| if let IrType::Named(n) = ty { Some(n) } else { None })
            }
            _ => None,
        };

        if let Some(sname) = struct_name {
            if let Some(def) = self.struct_defs.get(&sname) {
                return def.fields.iter().position(|f| f.name == field)
                    .map(|i| i as u32).unwrap_or(0);
            }
        }
        0
    }
}
