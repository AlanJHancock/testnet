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

    // 3b. Build event name -> index map for Emit resolution. Index must match
    // the order events are listed in build_abi() below (contract.event_defs
    // iteration order) so EMIT(idx) lines up with the ABI's event list.
    let event_name_map: Vec<(String, u32)> = contract.event_defs.iter()
        .enumerate()
        .map(|(i, e)| (e.name.clone(), i as u32))
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
            warnings: &mut warnings,
            func_name_map: &func_name_map,
            event_name_map: &event_name_map,
            loop_stack: Vec::new(),
            next_scratch: 0,
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
    warnings: &'a mut Vec<String>,
    func_name_map: &'a [(String, u32)],
    event_name_map: &'a [(String, u32)],
    /// Stack of enclosing while-loops -- (loop_start index, pending Jmp
    /// instruction indices from `break` that need to be patched to the
    /// loop's end once it's known).
    loop_stack: Vec<(u32, Vec<usize>)>,
    /// Counter for synthetic scratch-local names used by nested map
    /// read/write-back codegen (see `scratch_local`) -- guarantees each
    /// callsite gets its own disjoint set of local slots even within the
    /// same function (e.g. two separate nested-map writes in one body).
    next_scratch: u32,
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

    fn event_index(&self, name: &str) -> Option<u32> {
        self.event_name_map.iter()
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

    /// Allocate a fresh, guaranteed-unique local slot for use as scratch
    /// storage in nested map read/write-back codegen (see the
    /// `Statement::MapAssignment` and `Expression::MapIndex` cases below).
    /// `tag` is just for readability if instructions are ever dumped/
    /// disassembled -- uniqueness comes entirely from the counter, so it
    /// can never collide with a real user-declared local (whatever the
    /// user names it) or with another scratch slot from a different
    /// nested-map callsite in the same function.
    fn scratch_local(&mut self, tag: &str) -> u16 {
        let id = self.next_scratch;
        self.next_scratch += 1;
        self.local_index(&format!("__map_scratch_{}_{}", tag, id))
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
                if keys.is_empty() {
                    return Err(format!("map assignment to '{}' has no keys", map));
                } else if keys.len() == 1 {
                    // Single-level `map[key] = value`:
                    //   LoadState(idx)        -- the map (or default if unset)
                    //   <key>
                    //   <value>
                    //   MapSetVal             -- pops value,key,map -> pushes updated map
                    //   StoreState(idx)
                    self.emit(Instruction::LoadState(idx));
                    self.gen_expr(&keys[0])?;
                    self.gen_expr(value)?;
                    self.emit(Instruction::MapSetVal);
                    self.emit(Instruction::StoreState(idx));
                } else {
                    // Nested `map[k1][k2]...[kN] = value` (arbitrary depth,
                    // e.g. DomainRegistry's map<address, map<address,
                    // map<address, u256>>> is 3 levels). A plain stack
                    // machine can't hold "the outer map + k1" while it goes
                    // off and computes "the inner map + k2 + value" and
                    // still have them around afterwards to write the
                    // result back -- there's no Dup/Swap opcode in this
                    // ISA. So instead of juggling the stack, descend while
                    // saving each level's (map, key) pair into its own
                    // scratch local, then walk back up rebuilding each
                    // level's map with MapSetVal from the bottom.
                    let n = keys.len();
                    let map_scratch: Vec<u16> = (0..n).map(|_| self.scratch_local("map")).collect();
                    let key_scratch: Vec<u16> = (0..n).map(|_| self.scratch_local("key")).collect();

                    // Descend: map_scratch[0] = state map; for i in 0..n-1,
                    // map_scratch[i+1] = map_scratch[i][key_scratch[i]]
                    // (each read-forward defaults to an empty map if that
                    // level didn't exist yet, per MapGetVal's semantics).
                    self.emit(Instruction::LoadState(idx));
                    self.emit(Instruction::StoreLocal(map_scratch[0]));
                    for i in 0..n {
                        self.gen_expr(&keys[i])?;
                        self.emit(Instruction::StoreLocal(key_scratch[i]));
                        if i + 1 < n {
                            self.emit(Instruction::LoadLocal(map_scratch[i]));
                            self.emit(Instruction::LoadLocal(key_scratch[i]));
                            // Always an intermediate nesting level here (by
                            // construction: this branch only runs while
                            // i+1 < n, i.e. there's always a further key
                            // to descend into) -- a miss means "no nested
                            // map here yet", so tag 6 (Value::Map, empty).
                            self.emit(Instruction::MapGetVal(6));
                            self.emit(Instruction::StoreLocal(map_scratch[i + 1]));
                        }
                    }

                    // Innermost write: map_scratch[n-1][key_scratch[n-1]] = value
                    self.emit(Instruction::LoadLocal(map_scratch[n - 1]));
                    self.emit(Instruction::LoadLocal(key_scratch[n - 1]));
                    self.gen_expr(value)?;
                    self.emit(Instruction::MapSetVal);
                    // This is the updated innermost map -- reuse map_scratch[n-1]
                    // as the "updated" slot for that level since the stale
                    // pre-update value is no longer needed.
                    self.emit(Instruction::StoreLocal(map_scratch[n - 1]));

                    // Walk back up: for i from n-2 down to 0,
                    // map_scratch[i] = map_scratch[i][key_scratch[i]] = map_scratch[i+1] (updated)
                    for i in (0..n - 1).rev() {
                        self.emit(Instruction::LoadLocal(map_scratch[i]));
                        self.emit(Instruction::LoadLocal(key_scratch[i]));
                        self.emit(Instruction::LoadLocal(map_scratch[i + 1]));
                        self.emit(Instruction::MapSetVal);
                        self.emit(Instruction::StoreLocal(map_scratch[i]));
                    }

                    self.emit(Instruction::LoadLocal(map_scratch[0]));
                    self.emit(Instruction::StoreState(idx));
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
                match self.event_index(event) {
                    Some(idx) => self.emit(Instruction::Emit(idx as u16)),
                    None => {
                        self.warnings.push(format!("Emit of unknown event: {}", event));
                        self.emit(Instruction::Emit(0));
                    }
                }
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
                        // BUG FIX (2026-08-22): bool literals used to compile to
                        // PushU64(0/1), producing a Value::U64 at runtime -- which
                        // JSON-serializes as the raw number 1/0 (see
                        // aivm_value_to_json) instead of true/false. PushBool
                        // preserves the real Value::Bool type end to end, same
                        // fix pattern as the PushString fix just above.
                        self.emit(Instruction::PushBool(*b));
                    }
                    Literal::String(s) => {
                        // BUG FIX (2026-08-22): string literals used to compile to
                        // PushBytes, producing a Value::Bytes at runtime -- which
                        // JSON-serializes as opaque "0x..." hex (see
                        // aivm_value_to_json) instead of readable text. A real
                        // Value::String already existed and already serializes
                        // correctly; it just had no producing opcode. PushString
                        // closes that gap.
                        self.emit(Instruction::PushString(s.clone()));
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
                    BinaryOperator::BitAnd | BinaryOperator::BitOr | BinaryOperator::BitXor
                    | BinaryOperator::Shl | BinaryOperator::Shr => {
                        return Err("Bitwise/shift operators (&, |, ^, <<, >>) are not supported on the AIVM backend (64-bit words only) — use the IR/VM compilation path for u256 bitwise ops".to_string());
                    }
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
                    UnaryOperator::BitNot => {
                        return Err("Bitwise complement (~) is not supported on the AIVM backend (64-bit words only) — use the IR/VM compilation path for u256 bitwise ops".to_string());
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
                    "authority_envelope" => Some(22), // auth.envelope
                    // Phase 5 (30 Aug 2026): previously MISSING from this table entirely,
                    // so dilithium_verify/falcon_verify/kyber_decaps fell through to the
                    // "unknown function" branch below and silently compiled to Call(0) --
                    // i.e. calling the contract's FIRST function and returning ITS result,
                    // completely ignoring the real signature/key arguments. Real PQC
                    // dispatch now lives in aivm/src/host.rs (pqc.dilithium_verify /
                    // pqc.falcon_verify / pqc.kyber_decaps), backed by genuine pqcrypto via
                    // synq-pqc-shims -- same crypto the legacy vm crate's AEG1 path uses.
                    "dilithium_verify" => Some(23), // pqc.dilithium_verify (ML-DSA-65)
                    "falcon_verify" => Some(24),    // pqc.falcon_verify (FN-DSA-512)
                    "kyber_decaps" => Some(25),     // pqc.kyber_decaps (ML-KEM-768, dry-run/off-chain only)
                    // AEG1 protocol slot: 2026-09-01 -- these five have NO
                    // AEG1/ACTS-15 operation at all (only ML-KEM-decapsulate,
                    // ML-DSA-verify, FN-DSA-verify exist). Before this fix they
                    // were entirely absent from this table, so a call fell
                    // through to the "unknown function" branch below and
                    // silently compiled to Call(0) -- i.e. it invoked the
                    // contract's FIRST function and returned ITS result,
                    // completely unrelated to the PQC call. Mirrors the same
                    // dilithium_verify/falcon_verify/kyber_decaps bug fixed
                    // 30 Aug 2026 above, and the native vm crate's
                    // OpCode::PqcUnsupported fix (2026-09-01) -- now dispatch
                    // to host.rs, which hard-reverts with the exact builtin
                    // name (fail-closed, same as an unimplemented host fn).
                    "kyber_encapsulate" => Some(26),     // pqc.kyber_encapsulate -- AEG1: unsupported, hard-reverts
                    "mceliece_encapsulate" => Some(27),  // pqc.mceliece_encapsulate -- AEG1: unsupported, hard-reverts
                    "mceliece_decapsulate" => Some(28),  // pqc.mceliece_decapsulate -- AEG1: unsupported, hard-reverts
                    "hqc_encapsulate" => Some(29),        // pqc.hqc_encapsulate -- AEG1: unsupported, hard-reverts
                    "hqc_decapsulate" => Some(30),        // pqc.hqc_decapsulate -- AEG1: unsupported, hard-reverts
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
            Expression::MapIndex(map, keys) => {
                // `map[k1][k2]...[kN]` read, any depth: load the state map
                // once, then chain MapGetVal per key. Each level's miss
                // default is now type-correct (2026-08-25 fix), not
                // always a blind `Value::U64(0)` -- intermediate levels
                // (more keys still to come) default to an empty map
                // (tag 6); the FINAL level defaults according to the
                // map's actual declared value type (bool -> false,
                // str -> "", etc, via `map_value_default_tag`) -- see
                // Opcode::MapGetVal's doc comment in aivm/src/instructions.rs
                // for the full tag table.
                let idx = self.state_index(map)
                    .ok_or_else(|| format!("unknown state variable: {}", map))?;
                self.emit(Instruction::LoadState(idx));
                let mut cur_ty = self.state_var_types.get(map).cloned();
                let n = keys.len();
                for (i, key) in keys.iter().enumerate() {
                    self.gen_expr(key)?;
                    let value_ty = match &cur_ty {
                        Some(Type::Mapping(_, v)) => Some((**v).clone()),
                        _ => None,
                    };
                    let tag = if i + 1 == n {
                        value_ty.as_ref().map(map_value_default_tag).unwrap_or(0)
                    } else {
                        6 // intermediate level -- a miss is "no nested map yet"
                    };
                    self.emit(Instruction::MapGetVal(tag));
                    cur_ty = value_ty;
                }
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
        // Hash32/BytesN(32) must be checked before the general BytesN(_) catch-all
        // below, otherwise 32-byte values always match the generic Bytes arm and
        // this arm becomes unreachable dead code (same class of bug already
        // fixed once in the primary IR-backend ABI mapper).
        Type::Hash32 | Type::BytesN(32) => AbiType::Bytes32,
        Type::Bytes | Type::BytesN(_) => AbiType::Bytes,
        Type::Address => AbiType::Address,
        Type::Str => AbiType::String,
        Type::Array(inner) => AbiType::Array(Box::new(type_to_abi(inner))),
        _ => AbiType::Bytes,
    }
}

/// Maps a `map<K, V>`'s declared value type `V` to the compact tag
/// `MapGetVal`'s runtime miss-default logic understands (see
/// `Opcode::MapGetVal`'s doc comment in aivm/src/instructions.rs for the
/// authoritative tag table -- this function is what actually assigns
/// them, so it must stay in sync with `map_get_miss_default` in
/// aivm/src/vm.rs). Anything not explicitly listed here (numeric types,
/// `Array`/`Named`/struct-shaped values, etc.) falls back to tag 0
/// (`Value::U64(0)`) -- the same default every map miss used before this
/// tag existed, and still correct for plain numeric types since
/// `as_u64`/`as_u128` treat `U64`/`U128` interchangeably. Struct-shaped
/// map values don't get a precise shaped-zero default this way (that
/// would need the tag to carry a full field layout, not a single byte);
/// this is a deliberate, documented limitation, not an oversight.
fn map_value_default_tag(ty: &Type) -> u8 {
    match ty {
        Type::Bool => 1,
        Type::Str => 2,
        Type::Bytes | Type::BytesN(_) | Type::Hash32 | Type::Hash64
        | Type::DilithiumPublicKey | Type::FalconPublicKey | Type::KyberPublicKey
        | Type::DilithiumSignature | Type::FalconSignature => 3,
        // Tag 4 (Value::Bytes32) has no direct source: `Type::Hash32`
        // (AIVM's only 32-byte-hash type) is already routed to tag 3
        // (Bytes) above, alongside Bytes/BytesN, matching how AIVM's
        // Value::as_bytes-style consumers treat them today. Tag 4 exists
        // in the VM's table for future use if a type ever needs to
        // default specifically to Value::Bytes32 instead of Value::Bytes.
        Type::Address | Type::UMAIdentity => 5,
        Type::Mapping(_, _) => 6,
        _ => 0,
    }
}
