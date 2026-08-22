//! AIVM code generator — lowers SynQ AST to AIVM instructions
//!
//! This is the bridge between the existing SynQ compiler frontend (parser + AST)
//! and the new spec-compliant AIVM execution engine.
//!
//! Mapping:
//! - State variables → LOAD_STATE(key_index) / STORE_STATE(key_index)
//! - Local variables → LOAD_LOCAL(idx) / STORE_LOCAL(idx)
//! - Integer literals → PUSH_U64(value)
//! - Arithmetic → ADD/SUB/MUL/DIV_U64
//! - Comparison → EQ/LT/GT
//! - Control flow → JMP/JMP_IF
//! - Function calls → CALL(func_index) / RET
//! - Events → EMIT(event_index)
//! - Reverts → TRAP(code)
//! - Host functions → HOST_CALL(import_index)

use crate::ast::*;
use std::collections::HashMap;
use aivm::instructions::Instruction;
use aivm::vm::{FunctionEntry, FunctionVisibility, FunctionMutability};
use aivm::abi::{Abi, AbiType, AbiMethod, AbiEvent, AbiError as AbiErrorDef, AbiStateField};

/// AIVM compilation result
#[derive(Debug, Clone)]
pub struct AivmCompileResult {
    pub instructions: Vec<Instruction>,
    pub functions: Vec<FunctionEntry>,
    pub abi: Abi,
    pub state_var_map: Vec<(String, u16)>,
    /// Declared type of each state slot, by index -- lets callers (e.g. the
    /// server's dry-run/estimate-gas handler) build a correctly-shaped zero
    /// default (e.g. Value::Array([0, 0]) for a 2-field struct, not a bare
    /// scalar 0) for any state slot the request didn't explicitly seed.
    pub state_var_types: Vec<(u16, Type)>,
    pub warnings: Vec<String>,
}

/// A function body to compile — either a constructor or a regular function
enum FuncBody<'a> {
    Constructor(&'a ConstructorDefinition),
    Function(&'a FunctionDefinition),
}

impl<'a> FuncBody<'a> {
    fn params(&self) -> &[Parameter] {
        match self {
            FuncBody::Constructor(c) => &c.params,
            FuncBody::Function(f) => &f.params,
        }
    }
    fn body(&self) -> &Block {
        match self {
            FuncBody::Constructor(c) => &c.body,
            FuncBody::Function(f) => &f.body,
        }
    }
    fn name(&self) -> &str {
        match self {
            FuncBody::Constructor(_) => "init",
            FuncBody::Function(f) => &f.name,
        }
    }
    fn is_public(&self) -> bool {
        match self {
            FuncBody::Constructor(_) => true,
            // @public OR `as caller` — both are externally callable
            FuncBody::Function(f) => f.is_public || f.requires_caller,
        }
    }
}

/// Compile a SynQ contract AST to AIVM instructions
pub fn compile_to_aivm(contract: &ContractDefinition, structs: &[StructDefinition]) -> Result<AivmCompileResult, String> {
    let mut warnings = Vec::new();

    // 1. Build state variable map (+ types, for struct field resolution)
    let mut state_var_map: Vec<(String, u16)> = Vec::new();
    let mut state_var_types: HashMap<String, Type> = HashMap::new();
    for part in &contract.parts {
        if let ContractPart::StateVariable(sv) = part {
            let idx = state_var_map.len() as u16;
            state_var_map.push((sv.name.clone(), idx));
            state_var_types.insert(sv.name.clone(), sv.ty.clone());
        }
    }

    // Struct definitions, by name — lets codegen resolve field access
    // (`p.x`, `box_val.origin.x`) to the correct array index instead of
    // guessing. Passed in from the caller (top-level SourceUnit::Struct
    // entries), since ContractDefinition alone doesn't carry them.
    let struct_defs: HashMap<String, &StructDefinition> =
        structs.iter().map(|s| (s.name.clone(), s)).collect();

    // Function return types, by name — lets codegen know that e.g.
    // `makePoint(...)` yields a `Point` so `.x` on its result resolves too.
    let mut func_return_types: HashMap<String, Type> = HashMap::new();
    for part in &contract.parts {
        if let ContractPart::Function(f) = part {
            if let Some(rt) = &f.returns {
                func_return_types.insert(f.name.clone(), rt.clone());
            }
        }
    }

    // 2. Collect function bodies (constructor first, then functions)
    let mut func_bodies: Vec<FuncBody> = Vec::new();
    let mut functions: Vec<FunctionEntry> = Vec::new();

    // Constructor first (if present)
    for part in &contract.parts {
        if let ContractPart::Constructor(c) = part {
            func_bodies.push(FuncBody::Constructor(c));
            functions.push(FunctionEntry {
                name: "init".to_string(),
                instruction_offset: 0, // placeholder
                param_count: c.params.len() as u16,
                visibility: FunctionVisibility::Public,
                mutability: FunctionMutability::Write,
            });
        }
    }

    // Regular functions
    for part in &contract.parts {
        if let ContractPart::Function(f) = part {
            let visibility = if f.is_public || f.requires_caller {
                FunctionVisibility::Public
            } else {
                FunctionVisibility::Private
            };

            let mutability = if function_writes_state(f) {
                FunctionMutability::Write
            } else {
                FunctionMutability::View
            };

            func_bodies.push(FuncBody::Function(f));
            functions.push(FunctionEntry {
                name: f.name.clone(),
                instruction_offset: 0, // placeholder
                param_count: f.params.len() as u16,
                visibility,
                mutability,
            });
        }
    }

    // 3. Build function name -> index map for Call resolution
    let func_name_map: Vec<(String, u32)> = functions.iter()
        .enumerate()
        .map(|(i, f)| (f.name.clone(), i as u32))
        .collect();

    // 4. Generate instructions for each function
    let mut all_instructions: Vec<Instruction> = Vec::new();

    for (fidx, fbody) in func_bodies.iter().enumerate() {
        // Fix up the instruction offset
        let actual_offset = all_instructions.len() as u32;
        functions[fidx].instruction_offset = actual_offset;

        let mut ctx = CodegenContext {
            state_var_map: &state_var_map,
            state_var_types: &state_var_types,
            struct_defs: &struct_defs,
            func_return_types: &func_return_types,
            instructions: &mut all_instructions,
            local_map: std::collections::HashMap::new(),
            local_types: HashMap::new(),
            next_local: 0,
            func_index: fidx as u32,
            warnings: &mut warnings,
            func_name_map: &func_name_map,
            loop_stack: Vec::new(),
        };

        // Map params to local slots (+ types, for struct field resolution)
        for (i, param) in fbody.params().iter().enumerate() {
            ctx.local_map.insert(param.name.clone(), i as u16);
            ctx.local_types.insert(param.name.clone(), param.ty.clone());
        }
        ctx.next_local = fbody.params().len() as u16;

        // Generate body
        for stmt in &fbody.body().statements {
            ctx.gen_statement(stmt)?;
        }

        // Ensure RET at end
        if all_instructions.last() != Some(&Instruction::Ret) {
            all_instructions.push(Instruction::Ret);
        }
    }

    // 4. Resolve function call indices (second pass)
    // Build name → index map
    let func_name_to_index: std::collections::HashMap<String, u32> = functions.iter()
        .enumerate()
        .map(|(i, f)| (f.name.clone(), i as u32))
        .collect();

    for instr in &mut all_instructions {
        if let Instruction::Call(idx) = instr {
            if *idx == 0 && false {
                // This was a placeholder — but we don't have the name here
                // Actually, we stored the name in warnings during first pass
                // This needs a different approach — see below
            }
        }
    }

    // 5. Build ABI
    let abi = build_abi(contract, &state_var_map, &functions)?;

    let state_var_types_out: Vec<(u16, Type)> = state_var_map.iter()
        .filter_map(|(name, idx)| state_var_types.get(name).map(|ty| (*idx, ty.clone())))
        .collect();

    Ok(AivmCompileResult {
        instructions: all_instructions,
        functions,
        abi,
        state_var_map,
        state_var_types: state_var_types_out,
        warnings,
    })
}

/// Check if a function writes state
fn function_writes_state(f: &FunctionDefinition) -> bool {
    fn expr_writes(stmts: &[Statement]) -> bool {
        for s in stmts {
            match s {
                Statement::Assignment(_, _) => return true,
                Statement::FieldAssignment { .. } => return true,
                Statement::MapAssignment { .. } => return true,
                Statement::SetOp { .. } => return true,
                Statement::If { then_block, else_block, .. } => {
                    if expr_writes(&then_block.statements) { return true; }
                    if let Some(eb) = else_block {
                        if expr_writes(&eb.statements) { return true; }
                    }
                }
                Statement::While { body, .. } => {
                    if expr_writes(&body.statements) { return true; }
                }
                _ => {}
            }
        }
        false
    }
    expr_writes(&f.body.statements)
}

/// Codegen context
struct CodegenContext<'a> {
    state_var_map: &'a [(String, u16)],
    state_var_types: &'a HashMap<String, Type>,
    struct_defs: &'a HashMap<String, &'a StructDefinition>,
    func_return_types: &'a HashMap<String, Type>,
    instructions: &'a mut Vec<Instruction>,
    local_map: std::collections::HashMap<String, u16>,
    local_types: HashMap<String, Type>,
    next_local: u16,
    func_index: u32,
    warnings: &'a mut Vec<String>,
    func_name_map: &'a [(String, u32)],
    /// Stack of enclosing while-loops -- (loop_start index, pending Jmp
    /// instruction indices from `break` that need to be patched to the
    /// loop's end once it's known).
    loop_stack: Vec<(u32, Vec<usize>)>,
}

impl<'a> CodegenContext<'a> {
    fn state_index(&self, name: &str) -> Option<u16> {
        self.state_var_map.iter()
            .find(|(n, _)| n == name)
            .map(|(_, idx)| *idx)
    }

    fn func_index(&self, name: &str) -> Option<u32> {
        self.func_name_map.iter()
            .find(|(n, _)| *n == name)
            .map(|(_, idx)| *idx)
    }

    fn local_index(&mut self, name: &str) -> u16 {
        if let Some(idx) = self.local_map.get(name) {
            return *idx;
        }
        let idx = self.next_local;
        self.local_map.insert(name.to_string(), idx);
        self.next_local += 1;
        idx
    }

    /// Look up the struct definition a `Type::Named(...)` refers to, if any.
    fn resolve_struct(&self, ty: &Type) -> Option<&'a StructDefinition> {
        if let Type::Named(name) = ty {
            self.struct_defs.get(name.as_str()).copied()
        } else {
            None
        }
    }

    /// Best-effort static type inference — only needs to be precise enough
    /// to resolve struct field access (`.field`) to the right array index.
    /// Returns None for anything it can't (or doesn't need to) type.
    fn infer_type(&self, expr: &Expression) -> Option<Type> {
        match expr {
            Expression::Identifier(name) => {
                self.local_types.get(name).cloned()
                    .or_else(|| self.state_var_types.get(name).cloned())
            }
            Expression::FieldAccess { object, field } => {
                let obj_ty = self.infer_type(object)?;
                let sdef = self.resolve_struct(&obj_ty)?;
                sdef.fields.iter().find(|f| &f.name == field).map(|f| f.ty.clone())
            }
            Expression::StructLiteral { type_name, .. } => Some(Type::Named(type_name.clone())),
            Expression::Call(name, _) => self.func_return_types.get(name).cloned(),
            Expression::TupleIndex { object, .. } => self.infer_type(object),
            _ => None,
        }
    }

    fn emit(&mut self, instr: Instruction) {
        self.instructions.push(instr);
    }

    fn gen_statement(&mut self, stmt: &Statement) -> Result<(), String> {
        match stmt {
            Statement::Expression(expr) => {
                self.gen_expr(expr)?;
                self.emit(Instruction::StoreLocal(255)); // discard result
            }
            Statement::Require(cond, _msg) => {
                self.gen_expr(cond)?;
                self.emit(Instruction::JmpIf(self.instructions.len() as u32 + 2));
                self.emit(Instruction::Trap(5)); // Unauthorized
            }
            Statement::RevertNamed { .. } | Statement::RevertEnum { .. } => {
                self.emit(Instruction::Trap(0));
            }
            Statement::Assignment(name, expr) => {
                if let Some(idx) = self.state_index(name) {
                    self.gen_expr(expr)?;
                    self.emit(Instruction::StoreState(idx));
                } else {
                    let local_idx = self.local_index(name);
                    self.gen_expr(expr)?;
                    self.emit(Instruction::StoreLocal(local_idx));
                }
            }
            Statement::FieldAssignment { object, field, value } => {
                // `object.field = value;` -- grammar only supports one level
                // (field_assign_statement = IDENT "." IDENT "=" expr ";"),
                // so `object` is always a plain local/state variable name,
                // never a nested path. Resolve `field`'s position in
                // object's struct type and read-modify-write just that slot
                // via ArraySet, instead of clobbering the whole variable
                // with a single field's value.
                let obj_ty = self.state_var_types.get(object).cloned()
                    .or_else(|| self.local_types.get(object).cloned());
                let field_idx = obj_ty.as_ref()
                    .and_then(|t| self.resolve_struct(t))
                    .and_then(|sdef| sdef.fields.iter().position(|f| &f.name == field));

                match field_idx {
                    Some(idx) => {
                        if let Some(sidx) = self.state_index(object) {
                            self.emit(Instruction::LoadState(sidx));
                            self.gen_expr(value)?;
                            self.emit(Instruction::ArraySet(idx as u8));
                            self.emit(Instruction::StoreState(sidx));
                        } else {
                            let lidx = self.local_index(object);
                            self.emit(Instruction::LoadLocal(lidx));
                            self.gen_expr(value)?;
                            self.emit(Instruction::ArraySet(idx as u8));
                            self.emit(Instruction::StoreLocal(lidx));
                        }
                    }
                    None => {
                        // Unknown struct type for `object` -- fall back to
                        // the old (lossy but non-crashing) whole-variable
                        // overwrite rather than failing compilation outright.
                        self.warnings.push(format!(
                            "AIVM codegen: could not resolve field '{}' on '{}' for assignment -- overwriting whole variable",
                            field, object
                        ));
                        if let Some(sidx) = self.state_index(object) {
                            self.gen_expr(value)?;
                            self.emit(Instruction::StoreState(sidx));
                        } else {
                            let lidx = self.local_index(object);
                            self.gen_expr(value)?;
                            self.emit(Instruction::StoreLocal(lidx));
                        }
                    }
                }
            }
            Statement::MapAssignment { map, keys, value } => {
                let idx = self.state_index(map)
                    .ok_or_else(|| format!("unknown state variable: {}", map))?;
                if keys.len() == 1 {
                    self.gen_expr(value)?;
                    self.emit(Instruction::StoreState(idx));
                } else {
                    return Err("nested map assignment not yet supported in AIVM codegen".to_string());
                }
            }
            Statement::SetOp { set, op, value } => {
                let idx = self.state_index(set)
                    .ok_or_else(|| format!("unknown state variable: {}", set))?;
                self.gen_expr(value)?;
                match op {
                    SetOpKind::Add => self.emit(Instruction::StoreState(idx)),
                    SetOpKind::Remove => {
                        self.emit(Instruction::PushU64(0));
                        self.emit(Instruction::StoreState(idx));
                    }
                }
            }
            Statement::Let { name, ty, value } => {
                let local_idx = self.local_index(name);
                let inferred = ty.clone().or_else(|| self.infer_type(value));
                if let Some(t) = inferred {
                    self.local_types.insert(name.clone(), t);
                }
                self.gen_expr(value)?;
                self.emit(Instruction::StoreLocal(local_idx));
            }
            Statement::LetDestructure { names, value } => {
                self.gen_expr(value)?;
                for name in names {
                    let _ = self.local_index(name);
                }
                self.emit(Instruction::StoreLocal(255));
            }
            Statement::Return(expr) => {
                if let Some(e) = expr {
                    self.gen_expr(e)?;
                }
                self.emit(Instruction::Ret);
            }
            Statement::ExternCall { contract, function, args } => {
                for arg in args {
                    self.gen_expr(arg)?;
                }
                self.warnings.push(format!("ExternCall {}.{} — mapped to HostCall(extern.call)", contract, function));
                self.emit(Instruction::HostCall(8));
            }
            Statement::Emit { event, args } => {
                if let Some(arg) = args.first() {
                    self.gen_expr(arg)?;
                } else {
                    self.emit(Instruction::PushU64(0));
                }
                self.emit(Instruction::Emit(0));
            }
            Statement::If { condition, then_block, else_block } => {
                // BUG FIX (2026-08-20): Instruction::JmpIf jumps to its
                // target only when the popped condition is TRUE (see
                // aivm::vm::Avm::execute's JmpIf arm). Emitting JmpIf
                // directly on the raw condition here jumped to else_start
                // whenever the condition was true -- i.e. it skipped the
                // then-block exactly when it should have run it, and fell
                // through into the then-block exactly when it should have
                // skipped to else. Every `if` compiled through this AIVM
                // backend ran its branches inverted. Fix: negate the
                // condition first (same PushU64(1)-then-expr-then-SubU64
                // pattern already used for UnaryOperator::Not below --
                // pushing 1 *before* the expression so SubU64 computes
                // 1 - cond, not cond - 1) so JmpIf fires on "condition was
                // false", the correct time to jump to else_start/end.
                self.emit(Instruction::PushU64(1));
                self.gen_expr(condition)?;
                self.emit(Instruction::SubU64);
                let jmp_if_idx = self.instructions.len();
                self.emit(Instruction::JmpIf(0)); // placeholder
                for s in &then_block.statements {
                    self.gen_statement(s)?;
                }
                let jmp_end_idx = self.instructions.len();
                self.emit(Instruction::Jmp(0)); // placeholder
                let else_start = self.instructions.len() as u32;
                self.instructions[jmp_if_idx] = Instruction::JmpIf(else_start);
                if let Some(eb) = else_block {
                    for s in &eb.statements {
                        self.gen_statement(s)?;
                    }
                }
                let end = self.instructions.len() as u32;
                self.instructions[jmp_end_idx] = Instruction::Jmp(end);
            }
            Statement::While { condition, body } => {
                // Same inverted-JmpIf bug as the If arm above, same fix:
                // negate the condition (1 - cond) before JmpIf so the loop
                // exits when the condition is false instead of when it's
                // true.
                let loop_start = self.instructions.len() as u32;
                self.emit(Instruction::PushU64(1));
                self.gen_expr(condition)?;
                self.emit(Instruction::SubU64);
                let jmp_end_idx = self.instructions.len();
                self.emit(Instruction::JmpIf(0)); // placeholder
                // BUG FIX (2026-08-22): `break`/`continue` inside this body
                // used to compile to an unconditional Ret -- i.e. they
                // returned from the *whole function* instead of affecting
                // just the loop, silently truncating any state/locals set
                // after the loop and (worse) skipping the function's own
                // `return`, which decoded as a null return value. Track this
                // loop's start index + a list of `break` Jmp placeholders so
                // `continue` can jump straight back to the re-check and
                // `break` can be patched to the loop's end once known.
                self.loop_stack.push((loop_start, Vec::new()));
                for s in &body.statements {
                    self.gen_statement(s)?;
                }
                self.emit(Instruction::Jmp(loop_start));
                let end = self.instructions.len() as u32;
                self.instructions[jmp_end_idx] = Instruction::JmpIf(end);
                let (_, break_patches) = self.loop_stack.pop().expect("loop_stack imbalance");
                for idx in break_patches {
                    self.instructions[idx] = Instruction::Jmp(end);
                }
            }
            Statement::Break => {
                match self.loop_stack.last() {
                    Some(_) => {
                        let idx = self.instructions.len();
                        self.emit(Instruction::Jmp(0)); // placeholder, patched to loop end
                        self.loop_stack.last_mut().unwrap().1.push(idx);
                    }
                    None => {
                        self.warnings.push("`break` used outside of a loop -- ignored".to_string());
                    }
                }
            }
            Statement::Continue => {
                match self.loop_stack.last() {
                    Some((loop_start, _)) => {
                        self.emit(Instruction::Jmp(*loop_start));
                    }
                    None => {
                        self.warnings.push("`continue` used outside of a loop -- ignored".to_string());
                    }
                }
            }
        }
        Ok(())
    }

    fn gen_expr(&mut self, expr: &Expression) -> Result<(), String> {
        match expr {
            Expression::Literal(lit) => {
                match lit {
                    Literal::Number(n) => {
                        self.emit(Instruction::PushU64(*n as u64));
                    }
                    Literal::BigNumber(s) => {
                        let n: u64 = s.parse().map_err(|_| format!("big number {} too large for u64", s))?;
                        self.emit(Instruction::PushU64(n));
                    }
                    Literal::Bool(b) => {
                        self.emit(Instruction::PushU64(if *b { 1 } else { 0 }));
                    }
                    Literal::String(s) => {
                        self.emit(Instruction::PushBytes(s.as_bytes().to_vec()));
                    }
                    Literal::Hex(data) => {
                        self.emit(Instruction::PushBytes(data.clone()));
                    }
                }
            }
            Expression::Identifier(name) => {
                if let Some(idx) = self.state_index(name) {
                    self.emit(Instruction::LoadState(idx));
                } else {
                    let local_idx = self.local_index(name);
                    self.emit(Instruction::LoadLocal(local_idx));
                }
            }
            Expression::BinaryOp(lhs, op, rhs) => {
                match op {
                    BinaryOperator::And => {
                        self.gen_expr(lhs)?;
                        self.gen_expr(rhs)?;
                        self.emit(Instruction::MulU64);
                        return Ok(());
                    }
                    BinaryOperator::Or => {
                        self.gen_expr(lhs)?;
                        self.gen_expr(rhs)?;
                        self.emit(Instruction::AddU64);
                        self.emit(Instruction::PushU64(0));
                        self.emit(Instruction::Gt);
                        return Ok(());
                    }
                    _ => {}
                }

                self.gen_expr(lhs)?;
                self.gen_expr(rhs)?;

                match op {
                    BinaryOperator::Add => self.emit(Instruction::AddU64),
                    BinaryOperator::Sub => self.emit(Instruction::SubU64),
                    BinaryOperator::Mul => self.emit(Instruction::MulU64),
                    BinaryOperator::Div => self.emit(Instruction::DivU64),
                    BinaryOperator::Mod => self.emit(Instruction::ModU64),
                    BinaryOperator::Eq => self.emit(Instruction::Eq),
                    BinaryOperator::Ne => self.emit(Instruction::Ne),
                    BinaryOperator::Lt => self.emit(Instruction::Lt),
                    BinaryOperator::Le => self.emit(Instruction::Le),
                    BinaryOperator::Gt => self.emit(Instruction::Gt),
                    BinaryOperator::Ge => self.emit(Instruction::Ge),
                    BinaryOperator::And | BinaryOperator::Or => {} // handled above
                }
            }
            Expression::UnaryOp(op, expr) => {
                match op {
                    UnaryOperator::Neg => {
                        self.emit(Instruction::PushU64(0));
                        self.gen_expr(expr)?;
                        self.emit(Instruction::SubU64);
                    }
                    UnaryOperator::Not => {
                        self.emit(Instruction::PushU64(1));
                        self.gen_expr(expr)?;
                        self.emit(Instruction::SubU64);
                    }
                }
            }
            Expression::Caller => {
                self.emit(Instruction::HostCall(5)); // context.caller
            }
            Expression::CallSender => {
                self.emit(Instruction::HostCall(7)); // context.call_sender (immediate calling contract)
            }
            Expression::Call(name, args) => {
                // ── Builtin functions (map to HostCall) ──
                let host_idx = match name.as_str() {
                    "str_len" => Some(9),       // string.length
                    "str_concat" => Some(10),    // string.concat
                    "str_eq" => Some(11),        // string.eq
                    "asset_create" => Some(12),  // asset.create
                    "asset_transfer" => Some(13), // asset.transfer
                    "asset_burn" => Some(14),    // asset.burn
                    "asset_balance" => Some(15), // asset.balance
                    "asset_owner" => Some(16),   // asset.owner
                    "to_tsynq" | "to_syna" => Some(17), // addr.encode
                    "from_tsynq" | "from_syn" | "from_syna" => Some(18), // addr.decode
                    "contract_address" => Some(19), // addr.contract_address
                    "authority_require" => Some(20), // auth.require
                    "authority_identity" => Some(21), // auth.identity
                    _ => None,
                };
                if let Some(hidx) = host_idx {
                    for arg in args {
                        self.gen_expr(arg)?;
                    }
                    self.emit(Instruction::HostCall(hidx));
                } else {
                    // User-defined function call
                    for arg in args {
                        self.gen_expr(arg)?;
                    }
                    match self.func_index(name) {
                        Some(idx) => self.emit(Instruction::Call(idx)),
                        None => {
                            self.warnings.push(format!("Call to unknown function: {}", name));
                            self.emit(Instruction::Call(0));
                        }
                    }
                }
            }
            Expression::MapIndex(map, _keys) => {
                let idx = self.state_index(map)
                    .ok_or_else(|| format!("unknown state variable: {}", map))?;
                self.emit(Instruction::LoadState(idx));
            }
            Expression::MapMethod { map, method, args: _ } => {
                let idx = self.state_index(map)
                    .ok_or_else(|| format!("unknown state variable: {}", map))?;
                match method.as_str() {
                    "get" => self.emit(Instruction::LoadState(idx)),
                    "contains" => {
                        self.emit(Instruction::LoadState(idx));
                        self.emit(Instruction::PushU64(0));
                        self.emit(Instruction::Gt);
                    }
                    "len" => self.emit(Instruction::LoadState(idx)),
                    _ => return Err(format!("unknown map method: {}", method)),
                }
            }
            Expression::SetMethod { set, method, args: _ } => {
                let idx = self.state_index(set)
                    .ok_or_else(|| format!("unknown state variable: {}", set))?;
                self.emit(Instruction::LoadState(idx));
                if method == "contains" {
                    self.emit(Instruction::PushU64(0));
                    self.emit(Instruction::Gt);
                }
            }
            Expression::Tuple(exprs) => {
                // BUG FIX (2026-08-22): this used to generate code for only
                // the LAST element and silently discard every other element
                // -- a tuple return like `return (id, quantity);` compiled
                // to just `quantity`, dropping `id` entirely with no error
                // or warning. Pack all elements in declared order (mirrors
                // StructLiteral's push-then-Pack(count) pattern) so the
                // result decodes as a proper Value::Array on the way out.
                for e in exprs {
                    self.gen_expr(e)?;
                }
                self.emit(Instruction::Pack(exprs.len() as u8));
            }
            Expression::Some(e) | Expression::Ok(e) => {
                self.gen_expr(e)?;
            }
            Expression::None => {
                self.emit(Instruction::PushU64(0));
            }
            Expression::Err(e) => {
                self.gen_expr(e)?;
            }
            Expression::FieldAccess { object, field } => {
                let field_idx = self.infer_type(object)
                    .as_ref()
                    .and_then(|t| self.resolve_struct(t))
                    .and_then(|sdef| sdef.fields.iter().position(|f| &f.name == field));
                match field_idx {
                    Some(idx) => {
                        self.gen_expr(object)?;
                        self.emit(Instruction::ArrayGet(idx as u8));
                    }
                    None => {
                        self.warnings.push(format!(
                            "AIVM codegen: could not statically resolve field '{}' — defaulting to 0 (struct type unknown)",
                            field
                        ));
                        self.emit(Instruction::PushU64(0));
                    }
                }
            }
            Expression::TupleIndex { object, index } => {
                // BUG FIX (2026-08-22): this ignored `index` entirely and
                // just re-evaluated the whole tuple expression, so `.0`/`.1`
                // access on a destructured tuple always returned element 0
                // (or the pre-fix single-value stand-in). Now that
                // Expression::Tuple packs a real Value::Array, extract the
                // right slot the same way struct field access does.
                self.gen_expr(object)?;
                self.emit(Instruction::ArrayGet(*index as u8));
            }
            Expression::EnumAccess { enum_name: _, variant_name: _ } => {
                self.emit(Instruction::PushU64(0));
            }
            Expression::StructLiteral { type_name, fields } => {
                if let Some(sdef) = self.struct_defs.get(type_name.as_str()).copied() {
                    // Emit fields in the struct's DECLARED order (not the
                    // literal's source order) so ArrayGet(index) — computed
                    // from declared order in infer_type/resolve_struct —
                    // always lines up. Recurses naturally for nested structs
                    // (a field whose value is itself a StructLiteral).
                    for decl_field in &sdef.fields {
                        match fields.iter().find(|(n, _)| n == &decl_field.name) {
                            Some((_, val)) => self.gen_expr(val)?,
                            None => {
                                self.warnings.push(format!(
                                    "AIVM codegen: struct literal '{}' missing field '{}' — defaulting to 0",
                                    type_name, decl_field.name
                                ));
                                self.emit(Instruction::PushU64(0));
                            }
                        }
                    }
                    self.emit(Instruction::Pack(sdef.fields.len() as u8));
                } else {
                    // Unknown struct type (not in scope) — fall back to the
                    // old single-value behavior rather than failing outright.
                    self.warnings.push(format!(
                        "AIVM codegen: unknown struct type '{}' in literal — only first field kept",
                        type_name
                    ));
                    if let Some((_, val)) = fields.first() {
                        self.gen_expr(val)?;
                    } else {
                        self.emit(Instruction::PushU64(0));
                    }
                }
            }
        }
        Ok(())
    }
}

/// Build the ABI from the contract AST
fn build_abi(
    contract: &ContractDefinition,
    state_var_map: &[(String, u16)],
    functions: &[FunctionEntry],
) -> Result<Abi, String> {
    let mut methods = Vec::new();

    for fdef in contract.parts.iter().filter_map(|p| {
        if let ContractPart::Function(f) = p { Some(f) } else { None }
    }) {
        if !fdef.is_public && !fdef.requires_caller { continue; }

        let params: Vec<AbiType> = fdef.params.iter()
            .map(|p| type_to_abi(&p.ty))
            .collect();

        let returns: Vec<AbiType> = match &fdef.returns {
            Some(ty) => vec![type_to_abi(ty)],
            None => vec![],
        };

        let selector = Abi::compute_selector(&fdef.name, &params);
        let mutability = if functions.iter().find(|f| f.name == fdef.name)
            .map(|f| f.mutability)
            == Some(FunctionMutability::View) { "view" } else { "write" };

        methods.push(AbiMethod {
            name: fdef.name.clone(),
            selector: Abi::selector_hex(selector),
            visibility: "public".to_string(),
            mutability: mutability.to_string(),
            params,
            returns,
        });
    }

    let events: Vec<AbiEvent> = contract.event_defs.iter().map(|e| {
        AbiEvent {
            name: e.name.clone(),
            fields: e.params.iter().map(|p| (p.name.clone(), type_to_abi(&p.ty))).collect(),
        }
    }).collect();

    let errors: Vec<AbiErrorDef> = contract.error_defs.iter().map(|e| {
        AbiErrorDef {
            name: e.name.clone(),
            fields: e.params.iter().map(|p| (p.name.clone(), type_to_abi(&p.ty))).collect(),
        }
    }).collect();

    let state_schema: Vec<AbiStateField> = state_var_map.iter().map(|(name, _)| {
        let ty = contract.parts.iter().find_map(|p| {
            if let ContractPart::StateVariable(sv) = p {
                if sv.name == *name { Some(type_to_abi(&sv.ty)) } else { None }
            } else { None }
        }).unwrap_or(AbiType::U64);
        AbiStateField { name: name.clone(), field_type: ty }
    }).collect();

    Ok(Abi {
        abi_version: "0.1".to_string(),
        contract: contract.name.clone(),
        methods,
        events,
        errors,
        state_schema,
        security_requirements: serde_json::json!({}),
    })
}

/// Convert SynQ Type to ABI type
fn type_to_abi(ty: &Type) -> AbiType {
    match ty {
        Type::Bool => AbiType::Bool,
        Type::UInt8 => AbiType::U8,
        Type::UInt16 => AbiType::U16,
        Type::UInt32 => AbiType::U32,
        Type::UInt64 => AbiType::U64,
        Type::UInt128 => AbiType::U128,
        Type::UInt256 => AbiType::U128,
        Type::Int32 => AbiType::I32,
        Type::Int64 => AbiType::I64,
        Type::Bytes | Type::BytesN(_) => AbiType::Bytes,
        Type::Hash32 | Type::BytesN(32) => AbiType::Bytes32,
        Type::Address => AbiType::Address,
        Type::Str => AbiType::String,
        Type::Array(inner) => AbiType::Array(Box::new(type_to_abi(inner))),
        _ => AbiType::Bytes,
    }
}
