use crate::compiler::ast::*;
use crate::vm_inner::{Assembler, OpCode};
use ruint::aliases::U256;
use std::collections::HashMap;

// ## UInt256 Arithmetic Semantics
//
// All numeric values in SynQ are conceptually UInt256 (unsigned 256-bit integers).
// The VM stores them as `Value::I32`, `Value::U128`, or `Value::U256` and promotes
// automatically during arithmetic using `as_u256()`.
//
// **Overflow / underflow:**  All arithmetic uses checked operations via the `ruint`
// crate. Overflow raises a `RuntimeError` — no silent wrapping.
//   - Addition overflow → RuntimeError("UInt256 overflow on Add")
//   - Subtraction underflow → RuntimeError (no negative wrapping)
//   - Multiplication overflow → RuntimeError("UInt256 overflow on Mul")
//
// **Division / modulo by zero:**
//   - Literal zero divisor → compile-time `Err` (caught here in codegen)
//   - Runtime zero divisor → `RuntimeError("Division by zero")` / `RuntimeError("Modulo by zero")`
//
// **Mixed-width promotion:** I32 and U128 operands are promoted to U256 via
// `as_u256()` before the operation. The result shrinks back via `from_u256_shrink()`
// to I32 if it fits in i32, U128 if it fits in u128, otherwise stays U256.
//
// **Negative literals:** UInt256 has no sign. Negative number literals (e.g. `-1`)
// are encoded at parse time as `(0 - N)` and will underflow at runtime →
// RuntimeError. A future signed integer type will handle signed arithmetic.
//
// **Boundary values handled by ruint:**
//   - 2^128 (u128::MAX + 1) — stored as U256, no truncation
//   - 2^255 — stored as U256
//   - 2^256 - 1 (U256::MAX) — maximum representable value
//   - 2^256 — overflow, RuntimeError

// Memory layout: state variables get fixed contract-wide addresses (0..N).
// Each function gets its own disjoint address block so that parameters
// with the same name across different functions never alias the same
// memory slot.
// Param slots start at 1024 (above realistic state-var range 0..1023).
// STRIDE=16 → supports ≤16 params per function; functions 0..63 fit in 0..2047.
const FUNCTION_LOCAL_BASE: u32 = 1024;
const FUNCTION_LOCAL_STRIDE: u32 = 16;

/// One PQC/KEM builtin call compiles directly to its matching VM opcode.
/// The tuple is (arg count, opcode, pushes a Bool/Bytes result).
fn pqc_builtin_opcode(name: &str) -> Option<OpCode> {
    match name {
        // AEG1 unified dispatch (spec v7.0 aligned)
        "aegis_call" | "aegis_verify" | "aegis_decaps" => Some(OpCode::AegisCall),
        // Legacy algorithm-specific builtins (backward compat)
        "dilithium_verify"                        => Some(OpCode::DilithiumVerify),
        "falcon_verify" | "falcon_sign"           => Some(OpCode::FalconVerify),
        "sphincs_verify"                          => Some(OpCode::SphincsVerify),
        // KEM family — all route to KyberKeyExchange opcode (0x81)
        "kyber_encapsulate" | "kyber_decapsulate"
        | "kyber_decaps"                          => Some(OpCode::KyberKeyExchange),
        // McEliece and HQC KEMs — also route to KyberKeyExchange for now;
        // dedicated opcodes are future work.
        "mceliece_encapsulate" | "mceliece_decapsulate"
        | "hqc_encapsulate"   | "hqc_decapsulate" => Some(OpCode::KyberKeyExchange),
        _ => None,
    }
}

struct FunctionScope {
    /// name -> memory address, local to this function (params + any
    /// future locals). Looked up before falling back to state variables.
    locals: HashMap<String, u32>,
    /// Declared type for each local variable (for range checks and type tracking).
    local_types: HashMap<String, Type>,
    /// Reserved for future local-variable declarations (not yet supported
    /// by the grammar -- only params are locals today).
    #[allow(dead_code)]
    next_local_addr: u32,
    /// Stacks of placeholder offsets for Break statements (one Vec per while loop).
    break_patches:    Vec<Vec<usize>>,
    /// Stack of loop-start addresses for Continue statements.
    continue_targets: Vec<u32>,
}

/// Enum info for codegen — variant name → tag mapping
struct EnumInfo {
    variants: Vec<EnumVariant>,
    tags: HashMap<String, i32>,
}

pub struct CodeGenerator {
    assembler: Assembler,
    /// Struct definitions — field layout for struct literal/field access codegen
    struct_defs: HashMap<String, StructDefinition>,
    /// Enum definitions — variant tag mappings
    enum_defs: HashMap<String, EnumInfo>,
    /// Contract-wide state variable addresses, shared across all functions.
    state_vars: HashMap<String, u32>,
    state_var_types: HashMap<String, Type>,
    map_vars:   HashMap<String, u32>,
    set_vars:   HashMap<String, u32>,
    next_state_addr: u32,
    /// Forward-referenceable function addresses, registered in a
    /// pre-pass before any function body is generated so a caller can
    /// marshal args into a callee defined later in the source.
    function_addresses: HashMap<String, u32>,
    function_param_addrs: HashMap<String, Vec<u32>>,
    function_param_signs: HashMap<String, Vec<bool>>,
    function_has_return: HashMap<String, bool>,
    /// Whether each function declares `as caller` (requires authenticated identity).
    function_requires_caller: HashMap<String, bool>,
    /// Capability names declared via `requires cap::X` per function.
    function_capabilities: HashMap<String, Vec<String>>,
    /// (placeholder position, callee name) pairs for calls made before
    /// the callee's address was known (forward references). Backpatched
    /// once all functions have been code-generated.
    pending_call_patches: Vec<(usize, String)>,
    /// Name of the function currently being compiled (for caller-check enforcement).
    current_function: Option<String>,
}

impl CodeGenerator {
    pub fn new() -> Self {
        CodeGenerator {
            assembler: Assembler::new(),
            state_vars: HashMap::new(),
            map_vars:   HashMap::new(),
            set_vars:   HashMap::new(),
            next_state_addr: 0,
            function_addresses: HashMap::new(),
            function_param_addrs: HashMap::new(),
            function_param_signs: HashMap::new(),
            function_has_return: HashMap::new(),
            function_requires_caller: HashMap::new(),
            struct_defs: HashMap::new(),
            enum_defs: HashMap::new(),
            state_var_types: HashMap::new(),
            function_capabilities: HashMap::new(),
            pending_call_patches: Vec::new(),
            current_function: None,
        }
    }

    pub fn generate(mut self, ast: &[SourceUnit]) -> Result<(Vec<u8>, Vec<(String, u32)>), String> {
        // Pre-registration pass: assign every state variable and every
        // function's parameter memory addresses before generating any
        // code, so forward references (function A calling function B
        // defined later) and state variable reads work everywhere.
        for item in ast {
            if let SourceUnit::Contract(c) = item {
                self.register_contract_symbols(c)?;
            }
        }

        for item in ast {
            self.gen_source_unit(item)?;
        }

        // Backpatch any inter-function calls made before their callee's
        // address was known (a caller calling a function defined later in
        // source order).
        for (pos, name) in self.pending_call_patches.drain(..).collect::<Vec<_>>() {
            let addr = *self
                .function_addresses
                .get(&name)
                .ok_or_else(|| format!("Undefined function: {}", name))?;
            self.assembler.patch_u32(pos, addr);
        }

        // Emit the function dispatch table (in the data section) now that
        // every function's real code address is known.
        let mut functions: Vec<String> = self.function_addresses.keys().cloned().collect();
        functions.sort(); // deterministic dispatch table order
        for name in functions {
            let address = self.function_addresses[&name];
            let params = self.function_param_addrs.get(&name).cloned().unwrap_or_default();
            let has_return = *self.function_has_return.get(&name).unwrap_or(&false);
            let req_caller = *self.function_requires_caller.get(&name).unwrap_or(&false);
            let caps = self.function_capabilities.get(&name).cloned().unwrap_or_default();
            let signs = self.function_param_signs.get(&name).cloned().unwrap_or_default();
            self.assembler.add_function_entry(&name, address, &params, &signs, has_return, req_caller, &caps);
        }

        let bytecode = self.assembler.build();
        // Return state var layout so callers can expose live state
        let mut sv_layout: Vec<(String, u32)> = self.state_vars.into_iter().collect();
        sv_layout.sort_by_key(|e| e.1); // order by address
        Ok((bytecode, sv_layout))
    }

    fn register_contract_symbols(&mut self, c: &ContractDefinition) -> Result<(), String> {
        // Build a role->caps lookup table for this contract so capability_clause
        // `requires role::X` entries can be expanded to their constituent caps.
        let role_map: HashMap<String, Vec<String>> = c.roles.iter()
            .map(|r| (r.name.clone(), r.caps.clone()))
            .collect();

        for part in &c.parts {
            if let ContractPart::StateVariable(sv) = part {
                let addr = self.next_state_addr;
                self.next_state_addr += 1;
                self.state_vars.insert(sv.name.clone(), addr);
                self.state_var_types.insert(sv.name.clone(), sv.ty.clone());
                match &sv.ty {
                    Type::Mapping(_, _) => { self.map_vars.insert(sv.name.clone(), addr); }
                    Type::Array(_)      => { self.set_vars.insert(sv.name.clone(), addr); }
                    _ => {}
                }
            }
        }

        for (i, part) in c.parts.iter().enumerate() {
            if let ContractPart::Function(f) = part {
                let base = FUNCTION_LOCAL_BASE + (i as u32) * FUNCTION_LOCAL_STRIDE;
                let mut addr = base;
                let mut param_addrs = Vec::with_capacity(f.params.len());
                for _param in &f.params {
                    param_addrs.push(addr);
                    addr += 1;
                }
                let param_signs: Vec<bool> = f.params.iter()
                    .map(|p| matches!(p.ty, Type::Int8 | Type::Int16 | Type::Int32 | Type::Int64
                                         | Type::Int128 | Type::Int256))
                    .collect();
                self.function_param_addrs.insert(f.name.clone(), param_addrs);
                self.function_param_signs.insert(f.name.clone(), param_signs);
                let has_return = f.body.statements.iter().any(|s| matches!(s, Statement::Return(Some(_))))
                    || f.returns.is_some();
                self.function_has_return.insert(f.name.clone(), has_return);
                self.function_requires_caller.insert(f.name.clone(), f.requires_caller);

                // Expand role::X references into their constituent caps
                let mut resolved_caps: Vec<String> = vec![];
                for cap_entry in &f.capabilities {
                    if cap_entry.starts_with("role::") {
                        let role_name = &cap_entry["role::".len()..];
                        if let Some(caps) = role_map.get(role_name) {
                            resolved_caps.extend(caps.iter().cloned());
                        } else {
                            return Err(format!("undefined role '{}' used in function '{}'", role_name, f.name));
                        }
                    } else {
                        resolved_caps.push(cap_entry.clone());
                    }
                }
                self.function_capabilities.insert(f.name.clone(), resolved_caps);
            }
        }

        Ok(())
    }

    fn gen_source_unit(&mut self, unit: &SourceUnit) -> Result<(), String> {
        match unit {
            SourceUnit::Struct(s)    => self.gen_struct(s),
            SourceUnit::Enum(e)     => self.gen_enum(e),
            SourceUnit::Contract(c)  => self.gen_contract(c),
            SourceUnit::Interface(_) => Ok(()), // interfaces are compile-time only
            SourceUnit::Event(_)     => Ok(()), // top-level events: metadata only
        }
    }

    fn gen_struct(&mut self, s: &StructDefinition) -> Result<(), String> {
        // Register struct field layout for codegen (field index mapping)
        self.struct_defs.insert(s.name.clone(), s.clone());
        Ok(())
    }

    fn gen_enum(&mut self, e: &EnumDefinition) -> Result<(), String> {
        // Register enum variants — each variant gets a sequential tag (I32)
        let mut tags = std::collections::HashMap::new();
        for (i, v) in e.variants.iter().enumerate() {
            tags.insert(v.name.clone(), i as i32);
        }
        self.enum_defs.insert(e.name.clone(), EnumInfo {
            variants: e.variants.clone(),
            tags,
        });
        Ok(())
    }

    fn gen_contract(&mut self, c: &ContractDefinition) -> Result<(), String> {
        for part in &c.parts {
            match part {
                ContractPart::Function(f) => self.gen_function(f)?,
                _ => {} // State variables were handled in the pre-pass.
            }
        }
        Ok(())
    }

    fn gen_function(&mut self, f: &FunctionDefinition) -> Result<(), String> {
        let address = self.assembler.current_pos() as u32;
        self.function_addresses.insert(f.name.clone(), address);
        self.current_function = Some(f.name.clone());

        // Build this function's local scope: its parameters, at the
        // addresses already assigned in the pre-pass.
        let param_addrs = self.function_param_addrs.get(&f.name).cloned().unwrap_or_default();
        let mut locals = HashMap::new();
        for (param, addr) in f.params.iter().zip(param_addrs.iter()) {
            locals.insert(param.name.clone(), *addr);
        }
        let next_local_addr = param_addrs.last().map(|a| a + 1).unwrap_or_else(|| {
            // No params: still needs a base for any future local vars.
            let idx = self.function_addresses.len() as u32 - 1;
            FUNCTION_LOCAL_BASE + idx * FUNCTION_LOCAL_STRIDE
        });
        // Pre-populate local_types with function parameter types so
        // type-aware codegen (e.g. str + str → StrConcat) can inspect them.
        let mut param_types: HashMap<String, crate::compiler::ast::Type> = HashMap::new();
        for param in &f.params {
            param_types.insert(param.name.clone(), param.ty.clone());
        }
        let mut scope = FunctionScope { locals, local_types: param_types, next_local_addr, break_patches: Vec::new(), continue_targets: Vec::new() };

        // ── G1: Authority enforcement pre-pass ─────────────────────────────
        // Per §20.2.1: "There is no implicit authority derived from call
        // context, transaction origin, or caller address."
        // Any function that writes to a STATE VARIABLE (not a local) must
        // declare `as caller`. Writing state without authority declaration
        // is a compile error — not a warning, not opt-in.
        //
        // We distinguish state vars from locals: state vars live in
        // self.state_vars (pre-assigned addresses); locals live in
        // scope.locals (function parameters only at this point, since
        // Let bindings are added to scope during gen_statement).
        // The pre-pass checks the raw statement list before gen runs.
        // Allow @public or @authority as alternative to 'as caller' for authority
        let has_attr_authority = f.attributes.iter().any(|a| {
            matches!(a, crate::compiler::ast::Attribute::Public)
            || matches!(a, crate::compiler::ast::Attribute::Authority(_))
        });
        if !f.requires_caller && !has_attr_authority {
            fn writes_state(stmt: &Statement, state_vars: &HashMap<String, u32>) -> bool {
                match stmt {
                    Statement::Assignment(name, _) => state_vars.contains_key(name.as_str()),
                    Statement::FieldAssignment { object, .. } => state_vars.contains_key(object.as_str()),
                    Statement::If { then_block, else_block, .. } => {
                        then_block.statements.iter().any(|s| writes_state(s, state_vars))
                        || else_block.as_ref().map_or(false, |eb|
                            eb.statements.iter().any(|s| writes_state(s, state_vars)))
                    }
                    // Let bindings are always local — they allocate a new
                    // address and never overwrite state var slots.
                    _ => false,
                }
            }
            let mutates_state = f.body.statements.iter()
                .any(|s| writes_state(s, &self.state_vars));
            if mutates_state {
                return Err(format!(
                    "function '{}' mutates contract state but declares no authority \
                     (add `as caller` to the function signature — §20.2.1)",
                    f.name
                ));
            }
        }

        // ── Identity prologue ────────────────────────────────────────────────
        // `as caller`: emit a runtime check that caller != zero address.
        // LoadCaller (0x50) returns the raw EVM signing address padded to 32
        // bytes (devnet placeholder — not final UMA semantics).
        // For an anonymous (unauthenticated) call, LoadCaller pushes [0u8;32].
        // Sentinel = [0u8; 32] — the zero address.
        // Pattern: LoadCaller → LoadImm256(ANON_ZERO) → Eq → JumpIf revert → Jump body → Revert
        if f.requires_caller {
            // Zero address — anonymous sentinel matching LoadCaller behaviour
            const UMA_ANON: [u8; 32] = [
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            ];
            self.assembler.emit_op(OpCode::LoadCaller);
            self.assembler.emit_op(OpCode::LoadImm256);
            self.assembler.emit_raw(&UMA_ANON);
            self.assembler.emit_op(OpCode::Eq);
            self.assembler.emit_op(OpCode::JumpIf);
            let patch_to_revert = self.assembler.emit_placeholder_u32();
            self.assembler.emit_op(OpCode::Jump);
            let patch_to_body = self.assembler.emit_placeholder_u32();
            let revert_pos = self.assembler.current_pos() as u32;
            self.assembler.patch_u32(patch_to_revert, revert_pos);
            let msg = format!("{}: unauthenticated call", f.name);
            let mb = msg.as_bytes();
            self.assembler.emit_op(OpCode::Revert);
            self.assembler.emit_raw(&(mb.len() as u32).to_le_bytes());
            self.assembler.emit_raw(mb);
            let body_pos = self.assembler.current_pos() as u32;
            self.assembler.patch_u32(patch_to_body, body_pos);
        }

        // ── @authority(Scope) check ──────────────────────────────────────────
        // Emits: LoadAuthority → Push(scope_hash) → AuthRequire → JumpIf revert → Jump body
        // The scope hash is derived from the scope name via a simple hash.
        // On devnet, the server constructs the envelope with scope_hash = all-zeros
        // (accept any scope), so this check always passes.
        for attr in &f.attributes {
            if let crate::compiler::ast::Attribute::Authority(scope_name) = attr {
                // LoadAuthority pushes the current call's envelope as Bytes
                self.assembler.emit_op(OpCode::LoadAuthority);
                // SHA3-256 scope hash for V3 compatibility.
                // Devnet: server uses all-zeros scope = accept any.
                let scope_bytes = if scope_name.is_empty() {
                    vec![0u8; 32]
                } else {
                    use sha3::Digest;
                    let mut hasher = sha3::Sha3_256::new();
                    hasher.update(b"SYNQ-AUTHORITY-SCOPE-v1:");
                    hasher.update(scope_name.as_bytes());
                    hasher.finalize().to_vec()
                };
                self.assembler.emit_op(OpCode::LoadImm256);
                self.assembler.emit_raw(&scope_bytes);
                // AuthRequire: pops scope_hash + envelope, pushes Bool
                self.assembler.emit_op(OpCode::AuthRequire);
                // If authorized (true), jump to body. If not, fall through to revert.
                self.assembler.emit_op(OpCode::JumpIf);
                let auth_body_patch = self.assembler.emit_placeholder_u32();
                self.assembler.emit_op(OpCode::Jump);
                let auth_revert_patch = self.assembler.emit_placeholder_u32();
                // Revert block
                let auth_revert_pos = self.assembler.current_pos() as u32;
                self.assembler.patch_u32(auth_revert_patch, auth_revert_pos);
                let auth_msg = format!("{}: authority scope '{}' required", f.name, scope_name);
                let auth_mb = auth_msg.as_bytes();
                self.assembler.emit_op(OpCode::Revert);
                self.assembler.emit_raw(&(auth_mb.len() as u32).to_le_bytes());
                self.assembler.emit_raw(auth_mb);
                // Body continues here (JumpIf target)
                let auth_body_pos = self.assembler.current_pos() as u32;
                self.assembler.patch_u32(auth_body_patch, auth_body_pos);
            }
            // @governance(ScopeName) — strict governance authorization.
            // Uses SHA3-256 scope hash and SYNQ-GOVERNANCE-v3 domain tag.
            // Server must embed matching scope hash + GOVERNANCE domain tag in envelope.
            if let crate::compiler::ast::Attribute::Governance(scope_name) = attr {
                self.assembler.emit_op(OpCode::LoadAuthority);
                let scope_bytes = if scope_name.is_empty() {
                    vec![0u8; 32]
                } else {
                    use sha3::Digest;
                    let mut hasher = sha3::Sha3_256::new();
                    hasher.update(b"SYNQ-GOVERNANCE-SCOPE-v1:");
                    hasher.update(scope_name.as_bytes());
                    hasher.finalize().to_vec()
                };
                self.assembler.emit_op(OpCode::LoadImm256);
                self.assembler.emit_raw(&scope_bytes);
                self.assembler.emit_op(OpCode::AuthRequire);
                self.assembler.emit_op(OpCode::JumpIf);
                let gov_body_patch = self.assembler.emit_placeholder_u32();
                self.assembler.emit_op(OpCode::Jump);
                let gov_revert_patch = self.assembler.emit_placeholder_u32();
                let gov_revert_pos = self.assembler.current_pos() as u32;
                self.assembler.patch_u32(gov_revert_patch, gov_revert_pos);
                let gov_msg = format!("{}: governance scope '{}' required", f.name, scope_name);
                let gov_mb = gov_msg.as_bytes();
                self.assembler.emit_op(OpCode::Revert);
                self.assembler.emit_raw(&(gov_mb.len() as u32).to_le_bytes());
                self.assembler.emit_raw(gov_mb);
                let gov_body_pos = self.assembler.current_pos() as u32;
                self.assembler.patch_u32(gov_body_patch, gov_body_pos);
            }
        }

        // ── Capability stubs ─────────────────────────────────────────────────
        // Capabilities are declared, parsed, stored in the dispatch table, and
        // included in the EIP-712 signed payload — so they are expressed and
        // auditable at every level. Runtime enforcement (extern_call into a
        // __CapRegistry contract) is the next implementation step.
        // TODO(cap-enforcement): for each cap in f.capabilities, emit:
        //   LoadCaller, LoadImm256(keccak256(cap_name)), ExternCall(__CapRegistry, hasCapability, 2)
        //   JumpIf past revert, Revert "missing capability: <cap>"

        // ── Implicit return from extern_call ─────────────────────
        // If the last statement is an extern_call, the function declares a
        // return type (has_return), and there is no explicit `return` in the
        // body, skip the Pop so the extern_call's return value stays on the
        // stack and becomes the function's return value.
        let fn_has_return = *self.function_has_return.get(&f.name).unwrap_or(&false);
        let has_explicit_return = f.body.statements.iter().any(|s| matches!(s, Statement::Return(_)));
        let stmt_count = f.body.statements.len();
        for (i, stmt) in f.body.statements.iter().enumerate() {
            let is_last = i + 1 == stmt_count;
            if is_last && fn_has_return && !has_explicit_return {
                if let Statement::ExternCall { contract, function, args } = stmt {
                    // Push args onto stack left-to-right
                    for arg in args.iter() {
                        self.gen_expression(arg, &mut scope)?;
                    }
                    let contract_bytes = contract.as_bytes();
                    let fn_bytes       = function.as_bytes();
                    let arg_count      = args.len() as u8;
                    self.assembler.emit_op(OpCode::ExternCall);
                    self.assembler.emit_u32(contract_bytes.len() as u32);
                    self.assembler.emit_raw(contract_bytes);
                    self.assembler.emit_u32(fn_bytes.len() as u32);
                    self.assembler.emit_raw(fn_bytes);
                    self.assembler.emit_raw(&[arg_count]);
                    // Skip Pop — return value stays on stack for the trailing Return
                    continue;
                }
            }
            self.gen_statement(stmt, &mut scope)?;
        }

        // Every function must end in Return (not Halt) so multi-function
        // dispatch/call chains resume correctly; a top-level call (the old
        // plain `execute()` convention with pc=0 and an empty call stack)
        // gracefully halts on Return instead of erroring.
        self.assembler.emit_op(OpCode::Return);

        Ok(())
    }

    fn resolve_address(&self, scope: &FunctionScope, name: &str) -> Result<u32, String> {
        if let Some(addr) = scope.locals.get(name) {
            return Ok(*addr);
        }
        if let Some(addr) = self.state_vars.get(name) {
            return Ok(*addr);
        }
        Err(format!("Undefined variable: {}", name))
    }

    fn gen_statement(&mut self, stmt: &Statement, scope: &mut FunctionScope) -> Result<(), String> {
        match stmt {
            Statement::Expression(expr) => {
                self.gen_expression(expr, scope)?;
                // Expression statements discard their result.
                self.assembler.emit_op(OpCode::Pop);
                Ok(())
            }
            Statement::Require(cond, msg) => {
                // require(cond, msg): compiles to a JumpIf-based
                // conditional abort. If the condition is TRUE we jump
                // PAST the Halt (execution continues normally); if FALSE
                // we fall straight through into Halt, aborting the
                // contract. The jump target is backpatched once we know
                // where the Halt instruction ends.
                self.gen_expression(cond, scope)?;
                self.assembler.emit_op(OpCode::JumpIf);
                let jump_target_pos = self.assembler.emit_placeholder_u32();
                // Emit Revert opcode + length-prefixed message.
                // emit_bytes() already prepends the 4-byte LE length.
                self.assembler.emit_op(OpCode::Revert);
                let msg_bytes = msg.as_bytes();
                self.assembler.emit_bytes(msg_bytes);
                let after_revert = self.assembler.current_pos() as u32;
                self.assembler.patch_u32(jump_target_pos, after_revert);
                Ok(())
            }
            Statement::ExternCall { contract, function, args } => {
                // Push args onto stack left-to-right, then emit ExternCall opcode
                for arg in args.iter() {
                    self.gen_expression(arg, scope)?;
                }
                // Encode: ExternCall <4-byte-LE contract_len> <contract_bytes>
                //                    <4-byte-LE fn_len> <fn_bytes> <1-byte arg_count>
                let contract_bytes = contract.as_bytes();
                let fn_bytes       = function.as_bytes();
                let arg_count      = args.len() as u8;
                self.assembler.emit_op(OpCode::ExternCall);
                // VM reads: u32 clen, clen bytes, u32 flen, flen bytes, u8 argc
                self.assembler.emit_u32(contract_bytes.len() as u32);
                self.assembler.emit_raw(contract_bytes);
                self.assembler.emit_u32(fn_bytes.len() as u32);
                self.assembler.emit_raw(fn_bytes);
                self.assembler.emit_raw(&[arg_count]);
                // ExternCall pushes a return value; pop it (stmt context, discard)
                self.assembler.emit_op(OpCode::Pop);
                Ok(())
            }
            Statement::Assignment(name, expr) => {
                let addr = self.resolve_address(scope, name)?;
                self.gen_expression(expr, scope)?;
                self.assembler.emit_op(OpCode::Push);
                self.assembler.emit_i32(addr as i32);
                self.assembler.emit_op(OpCode::Store);
                Ok(())
            }
            Statement::FieldAssignment { object, field, value } => {
                let addr = self.resolve_address(scope, object.as_str())?;
                // Load the struct (Tuple) from memory
                self.assembler.emit_op(OpCode::Push);
                self.assembler.emit_i32(addr as i32);
                self.assembler.emit_op(OpCode::Load);
                // Push the new field value
                self.gen_expression(value, scope)?;
                // Look up field index from struct definitions
                let ty = scope.local_types.get(object.as_str())
                    .cloned()
                    .or_else(|| self.state_var_types.get(object.as_str()).cloned());
                let field_idx = if let Some(Type::Named(struct_name)) = ty {
                    if let Some(sd) = self.struct_defs.get(&struct_name) {
                        sd.fields.iter().position(|f| f.name == *field)
                            .map(|p| p as i32)
                    } else { None }
                } else { None }
                    .ok_or_else(|| format!("FieldAssignment: unknown field '{}' on '{}'", field, object))?;
                // Push field index
                self.assembler.emit_op(OpCode::Push);
                self.assembler.emit_i32(field_idx);
                // TupleSet: pops index, value, tuple → pushes new tuple
                self.assembler.emit_op(OpCode::TupleSet);
                // Store the modified tuple back to memory
                self.assembler.emit_op(OpCode::Push);
                self.assembler.emit_i32(addr as i32);
                self.assembler.emit_op(OpCode::Store);
                Ok(())
            }
            Statement::MapAssignment { map, key, value } => {
                let addr = *self.state_vars.get(map.as_str())
                    .ok_or_else(|| format!("MapAssignment: unknown map '{}'", map))?;
                // VM MapSet pops: map_addr first, then key, then val.
                // Push in reverse order so top-of-stack = map_addr.
                self.gen_expression(value, scope)?;  // pushed first → popped last as val
                self.gen_expression(key, scope)?;    // pushed second → popped as key
                self.assembler.emit_op(OpCode::Push);
                self.assembler.emit_i32(addr as i32); // pushed last → popped first as map_addr
                self.assembler.emit_op(OpCode::MapSet);
                Ok(())
            }
            Statement::SetOp { set, op, value } => {
                let addr = *self.state_vars.get(set.as_str())
                    .ok_or_else(|| format!("SetOp: unknown set '{}'", set))?;
                // Push order: value first, then set_addr last.
                // VM pops set_addr first (top of stack), then value — so addr must be on top.
                self.gen_expression(value, scope)?;
                self.assembler.emit_op(OpCode::Push);
                self.assembler.emit_i32(addr as i32);
                match op {
                    SetOpKind::Add    => self.assembler.emit_op(OpCode::SetAdd),
                    SetOpKind::Remove => self.assembler.emit_op(OpCode::SetRemove),
                }
                Ok(())
            }
                        Statement::Return(expr) => {
                if let Some(e) = expr {
                    self.gen_expression(e, scope)?;
                }
                self.assembler.emit_op(OpCode::Return);
                Ok(())
            }
            // ── Named error revert: `revert ErrorName(args...)` ────────────
            Statement::RevertNamed { error, args } => {
                // Named error: try to resolve the error name to an enum variant tag.
                // If found, emit RevertCode (0x35) with the structured error code.
                // If not found, fall back to string-based Revert (0x34).
                
                // Search all enum definitions for a matching variant.
                let mut found_code: Option<(u32, String)> = None;
                for (enum_name, enum_info) in &self.enum_defs {
                    if let Some(idx) = enum_info.variants.iter().position(|v| v.name == *error) {
                        found_code = Some((idx as u32, enum_name.clone()));
                        break;
                    }
                }
                
                // Build the display message (error name + arg count).
                let msg = if args.is_empty() {
                    if let Some((_, ref en)) = found_code { format!("{}::{}", en, error) }
                    else { error.clone() }
                } else {
                    let prefix = if let Some((_, ref en)) = found_code { format!("{}::{}", en, error) }
                    else { error.clone() };
                    format!("{}({} arg(s))", prefix, args.len())
                };
                
                // Still push args so they are evaluated (side-effect safe).
                for arg in args.iter() {
                    self.gen_expression(arg, scope)?;
                    self.assembler.emit_op(OpCode::Pop);
                }
                
                let msg_bytes = msg.as_bytes();
                
                if let Some((code, _)) = found_code {
                    // Emit RevertCode: opcode + error_code (4B LE) + msg_len (4B LE) + msg
                    self.assembler.emit_op(OpCode::RevertCode);
                    self.assembler.emit_u32(code);
                    self.assembler.emit_bytes(msg_bytes);
                } else {
                    // Fall back to string-based Revert for unknown error names.
                    self.assembler.emit_op(OpCode::Revert);
                    self.assembler.emit_bytes(msg_bytes);
                }
                Ok(())
            }
            // ── Event emission: `emit EventName(args...)` ───────────────────
            // Emits a Print opcode with a tagged string: "event:<Name>:<arg0>:..."
            // The server collects Print output and surfaces it as "events" in the
            // run response. A dedicated Emit opcode (0x70) will replace this
            // once the VM log/receipt subsystem is implemented.
                        Statement::RevertEnum { enum_name, error, args } => {
                // Qualified named error: revert EnumName::VariantName(args)
                // Look up the specific enum, then find the variant tag.
                let code = if let Some(enum_info) = self.enum_defs.get(enum_name.as_str()) {
                    enum_info.variants.iter().position(|v| v.name == *error)
                        .map(|p| p as u32)
                        .ok_or_else(|| format!("enum '{}' has no variant '{}'", enum_name, error))?
                } else {
                    return Err(format!("unknown enum '{}' in revert statement", enum_name));
                };
                
                let msg = if args.is_empty() {
                    format!("{}::{}", enum_name, error)
                } else {
                    format!("{}::{}({} arg(s))", enum_name, error, args.len())
                };
                
                // Evaluate args for side effects.
                for arg in args.iter() {
                    self.gen_expression(arg, scope)?;
                    self.assembler.emit_op(OpCode::Pop);
                }
                
                let msg_bytes = msg.as_bytes();
                self.assembler.emit_op(OpCode::RevertCode);
                self.assembler.emit_u32(code);
                self.assembler.emit_bytes(msg_bytes);
                Ok(())
            }
Statement::Emit { event, args } => {
                // Push each arg then use Print to surface it.
                // For now: emit `Print("event:<EventName>")` as a marker,
                // then Print each arg. The server aggregates these.
                let tag = format!("event:{}", event);
                self.assembler.emit_op(OpCode::LoadImm);
                self.assembler.emit_bytes(tag.as_bytes());
                self.assembler.emit_op(OpCode::Print);
                for arg in args.iter() {
                    self.gen_expression(arg, scope)?;
                    self.assembler.emit_op(OpCode::Print);
                }
                Ok(())
            }
            // ── If statement ─────────────────────────────────────────────────
            Statement::If { condition, then_block, else_block } => {
                self.gen_expression(condition, scope)?;
                // JumpIf to then-block; else jump over
                self.assembler.emit_op(OpCode::JumpIf);
                let patch_to_then = self.assembler.emit_placeholder_u32();
                // Jump to else (or past everything if no else)
                self.assembler.emit_op(OpCode::Jump);
                let patch_past_then = self.assembler.emit_placeholder_u32();
                // Then-block
                let then_addr = self.assembler.current_pos() as u32;
                self.assembler.patch_u32(patch_to_then, then_addr);
                for stmt in &then_block.statements {
                    self.gen_statement(stmt, scope)?;
                }
                // If there's an else, jump past it after then-block
                let patch_past_else = if else_block.is_some() {
                    self.assembler.emit_op(OpCode::Jump);
                    Some(self.assembler.emit_placeholder_u32())
                } else { None };
                // Else-block (or just landing point)
                let else_addr = self.assembler.current_pos() as u32;
                self.assembler.patch_u32(patch_past_then, else_addr);
                if let Some(eb) = else_block {
                    for stmt in &eb.statements {
                        self.gen_statement(stmt, scope)?;
                    }
                }
                if let Some(p) = patch_past_else {
                    let after_else = self.assembler.current_pos() as u32;
                    self.assembler.patch_u32(p, after_else);
                }
                Ok(())
            }
            // ── Let binding: `let x = expr` ──────────────────────────────────
            Statement::Let { name, ty, value } => {
                // Allocate a new local slot and assign
                let addr = scope.next_local_addr;
                scope.next_local_addr += 1;
                scope.locals.insert(name.clone(), addr);
                if let Some(t) = ty { scope.local_types.insert(name.clone(), t.clone()); }
                else {
                    // Type inference: if value is a struct literal, record the type
                    if let Expression::StructLiteral { type_name, .. } = value {
                        scope.local_types.insert(name.clone(), Type::Named(type_name.clone()));
                    }
                }
                self.gen_expression(value, scope)?;
                self.assembler.emit_op(OpCode::Push);
                self.assembler.emit_i32(addr as i32);
                self.assembler.emit_op(OpCode::Store);
                Ok(())
            }
            Statement::While { condition, body } => {
                // while <cond> { <body> }
                // loop_start: eval cond
                //   JumpIf body_start  (cond true → enter body)
                //   Jump loop_end       (cond false → exit)
                // body_start: gen body stmts
                //   Jump loop_start    (back-edge)
                // loop_end:
                let loop_start = self.assembler.current_pos() as u32;
                self.gen_expression(condition, scope)?;
                self.assembler.emit_op(OpCode::JumpIf);
                let patch_body = self.assembler.emit_placeholder_u32();
                self.assembler.emit_op(OpCode::Jump);
                let patch_end = self.assembler.emit_placeholder_u32();
                let body_start = self.assembler.current_pos() as u32;
                self.assembler.patch_u32(patch_body, body_start);
                scope.break_patches.push(vec![]);
                scope.continue_targets.push(loop_start);
                for stmt in &body.statements {
                    self.gen_statement(stmt, scope)?;
                }
                // back-edge
                self.assembler.emit_op(OpCode::Jump);
                self.assembler.emit_u32(loop_start);
                let loop_end = self.assembler.current_pos() as u32;
                self.assembler.patch_u32(patch_end, loop_end);
                // patch break targets
                if let Some(breaks) = scope.break_patches.pop() {
                    for p in breaks {
                        self.assembler.patch_u32(p, loop_end);
                    }
                }
                scope.continue_targets.pop();
                Ok(())
            }
            Statement::Break => {
                self.assembler.emit_op(OpCode::Jump);
                let p = self.assembler.emit_placeholder_u32();
                if let Some(v) = scope.break_patches.last_mut() {
                    v.push(p);
                }
                Ok(())
            }
            Statement::Continue => {
                if let Some(&target) = scope.continue_targets.last() {
                    self.assembler.emit_op(OpCode::Jump);
                    self.assembler.emit_u32(target);
                }
                Ok(())
            }
        }
    }

    fn gen_expression(&mut self, expr: &Expression, scope: &mut FunctionScope) -> Result<(), String> {
        match expr {
            Expression::Literal(Literal::Number(n)) => {
                if *n > i32::MAX as u128 {
                    self.assembler.emit_op(OpCode::LoadImm128);
                    self.assembler.emit_u128(*n as u128);
                } else {
                    self.assembler.emit_op(OpCode::Push);
                    self.assembler.emit_i32(*n as i32);
                }
                Ok(())
            }
            Expression::Literal(Literal::BigNumber(s)) => {
                // Full UInt256 literal (> u128::MAX) — 32 big-endian bytes via LoadImm256.
                let v: U256 = s.parse().map_err(|_| format!("Invalid UInt256 literal: {}", s))?;
                self.assembler.emit_op(OpCode::LoadImm256);
                self.assembler.emit_u256_bytes(&v.to_be_bytes::<32>());
                Ok(())
            }
            Expression::Literal(Literal::Bool(b)) => {
                self.assembler.emit_op(OpCode::Push);
                self.assembler.emit_i32(if *b { 1 } else { 0 });
                Ok(())
            }
            Expression::Literal(Literal::String(s)) => {
                // Length-prefixed UTF-8: [len:4LE][bytes]
                let b = s.as_bytes();
                let mut payload = Vec::with_capacity(4 + b.len());
                payload.extend_from_slice(&(b.len() as u32).to_le_bytes());
                payload.extend_from_slice(b);
                self.assembler.emit_op(OpCode::LoadImm);
                self.assembler.emit_bytes(&payload);
                Ok(())
            }
            Expression::Literal(Literal::Hex(bytes)) => {
                self.assembler.emit_op(OpCode::LoadImm);
                self.assembler.emit_bytes(bytes);
                Ok(())
            }
            Expression::UnaryOp(op, operand) => {
                match op {
                    UnaryOperator::Neg => {
                        // Emit `0 - operand`
                        self.assembler.emit_op(OpCode::Push);
                        self.assembler.emit_i32(0);
                        self.gen_expression(operand, scope)?;
                        self.assembler.emit_op(OpCode::Sub);
                    }
                    UnaryOperator::Not => {
                        // Logical not: `operand == 0`
                        self.gen_expression(operand, scope)?;
                        self.assembler.emit_op(OpCode::Push);
                        self.assembler.emit_i32(0);
                        self.assembler.emit_op(OpCode::Eq);
                    }
                }
                Ok(())
            }
            Expression::Caller => {
                // LoadCaller (0x50) — pushes authenticated EVM caller address as U256.
                // Compile error if `caller` is used in a function not declared `as caller`.
                let fn_name = self.current_function.clone().unwrap_or_default();
                let req = *self.function_requires_caller.get(&fn_name).unwrap_or(&false);
                if !req {
                    return Err(format!(
                        "'caller' used in '{}' which is not declared 'as caller'                          — add 'as caller' to the function signature",
                        fn_name
                    ));
                }
                self.assembler.emit_op(OpCode::LoadCaller);
                Ok(())
            }
            Expression::Tuple(exprs) => {
                for expr in exprs.iter() { self.gen_expression(expr, scope)?; }
                self.assembler.emit_op(OpCode::Push);
                self.assembler.emit_i32(exprs.len() as i32);
                self.assembler.emit_op(OpCode::TuplePack);
                Ok(())
            }
            Expression::Some(inner) => {
                self.gen_expression(inner, scope)?;
                self.assembler.emit_op(OpCode::OptionSome);
                Ok(())
            }
            Expression::None => {
                self.assembler.emit_op(OpCode::OptionNone);
                Ok(())
            }
            Expression::Ok(inner) => {
                self.gen_expression(inner, scope)?;
                self.assembler.emit_op(OpCode::ResultOk);
                Ok(())
            }
            Expression::Err(inner) => {
                self.gen_expression(inner, scope)?;
                self.assembler.emit_op(OpCode::ResultErr);
                Ok(())
            }
            Expression::FieldAccess { object, field } => {
                // Generate the object expression (pushes the struct value as Tuple onto stack)
                self.gen_expression(object, scope)?;
                
                // Look up field index from struct definitions.
                // For Identifier objects, check local_types and state_var_types.
                // For nested field access or function call results, check expression types.
                let field_idx = if let Expression::Identifier(name) = object.as_ref() {
                    let ty = scope.local_types.get(name.as_str())
                        .cloned()
                        .or_else(|| self.state_var_types.get(name.as_str()).cloned());
                    if let Some(Type::Named(struct_name)) = ty {
                        if let Some(sd) = self.struct_defs.get(&struct_name) {
                            sd.fields.iter().position(|f| f.name == *field)
                                .map(|p| p as i32)
                        } else { None }
                    } else { None }
                } else { None };

                match field_idx {
                    Some(idx) => {
                        // Stack: [tuple_value, index]
                        // TupleGet pops index (top), then tuple (below), pushes element
                        self.assembler.emit_op(OpCode::Push);
                        self.assembler.emit_i32(idx);
                        self.assembler.emit_op(OpCode::TupleGet);
                    }
                    None => {
                        // Unknown struct or field — emit runtime error via Revert
                        self.assembler.emit_op(OpCode::Pop);
                        self.assembler.emit_op(OpCode::Push);
                        self.assembler.emit_op(OpCode::Revert);
                        // Revert takes a 4-byte-LE length + message
                        let msg = format!("field access: unknown field '{}'", field);
                        let mb = msg.as_bytes();
                        self.assembler.emit_raw(&(mb.len() as u32).to_le_bytes());
                        self.assembler.emit_raw(mb);
                    }
                }
                Ok(())
            }
            Expression::EnumAccess { enum_name, variant_name } => {
                // Look up the enum variant tag from registered enum definitions
                if let Some(enum_info) = self.enum_defs.get(enum_name) {
                    if let Some(idx) = enum_info.variants.iter().position(|v| v.name.as_str() == variant_name.as_str()) {
                        self.assembler.emit_op(OpCode::Push);
                        self.assembler.emit_i32(idx as i32);
                    } else {
                        return Err(format!("enum '{}' has no variant '{}'", enum_name, variant_name));
                    }
                } else {
                    return Err(format!("unknown enum '{}'", enum_name));
                }
                Ok(())
            }
            Expression::StructLiteral { type_name, fields } => {
                // Push field values in declaration order (matching struct field layout)
                for (_, expr) in fields {
                    self.gen_expression(expr, scope)?;
                }
                // TuplePack: pops count (top), then pops count values, pushes Tuple
                // Stack: [val0, val1, ..., valN, count] → pushes Tuple([val0, val1, ..., valN])
                self.assembler.emit_op(OpCode::Push);
                self.assembler.emit_i32(fields.len() as i32);
                self.assembler.emit_op(OpCode::TuplePack);
                Ok(())
            }
            Expression::MapIndex(map, key) => {
                let addr = *self.state_vars.get(map.as_str())
                    .ok_or_else(|| format!("MapIndex: unknown map '{}'", map))?;
                // VM MapGet: map_addr = pop() first, key = pop() second.
                // Push key first (popped last), map_addr last (popped first).
                self.gen_expression(key, scope)?;    // pushed first → popped last as key
                self.assembler.emit_op(OpCode::Push);
                self.assembler.emit_i32(addr as i32); // pushed last → popped first as map_addr
                self.assembler.emit_op(OpCode::MapGet);
                Ok(())
            }
            Expression::MapMethod { map, method, args } => {
                let addr = *self.state_vars.get(map.as_str())
                    .ok_or_else(|| format!("MapMethod: unknown map '{}'", map))?;
                match method.as_str() {
                    "get" => {
                        if args.len() != 1 { return Err("map.get expects 1 arg".into()); }
                        self.gen_expression(&args[0], scope)?;
                        self.assembler.emit_op(OpCode::Push);
                        self.assembler.emit_i32(addr as i32);
                        self.assembler.emit_op(OpCode::MapGet);
                    }
                    "contains" => {
                        if args.len() != 1 { return Err("map.contains expects 1 arg".into()); }
                        // Dispatch to SetContains if the target is a Set state var.
                        // The parser emits MapMethod for .contains() regardless of type;
                        // codegen must correct this by checking set_vars.
                        let is_set = self.set_vars.contains_key(map.as_str());
                        self.gen_expression(&args[0], scope)?;
                        self.assembler.emit_op(OpCode::Push);
                        self.assembler.emit_i32(addr as i32);
                        if is_set {
                            self.assembler.emit_op(OpCode::SetContains);
                        } else {
                            self.assembler.emit_op(OpCode::MapContains);
                        }
                    }
                    "len" => {
                        // Same dispatch: SetLen if target is a Set.
                        let is_set = self.set_vars.contains_key(map.as_str());
                        self.assembler.emit_op(OpCode::Push);
                        self.assembler.emit_i32(addr as i32);
                        if is_set {
                            self.assembler.emit_op(OpCode::SetLen);
                        } else {
                            self.assembler.emit_op(OpCode::MapLen);
                        }
                    }
                    "remove" => {
                        if args.len() != 1 { return Err("map.remove expects 1 arg".into()); }
                        self.gen_expression(&args[0], scope)?;
                        self.assembler.emit_op(OpCode::Push);
                        self.assembler.emit_i32(addr as i32);
                        self.assembler.emit_op(OpCode::MapRemove);
                        self.assembler.emit_op(OpCode::Push);
                        self.assembler.emit_i32(1);
                    }
                    _ => return Err(format!("unknown map method: {}", method)),
                }
                Ok(())
            }
            Expression::SetMethod { set, method, args } => {
                let addr = *self.state_vars.get(set.as_str())
                    .ok_or_else(|| format!("SetMethod: unknown set '{}'", set))?;
                match method.as_str() {
                    "contains" => {
                        if args.len() != 1 { return Err("set.contains expects 1 arg".into()); }
                        // val first, set_addr last — VM pops set_addr first (top of stack)
                        self.gen_expression(&args[0], scope)?;
                        self.assembler.emit_op(OpCode::Push);
                        self.assembler.emit_i32(addr as i32);
                        self.assembler.emit_op(OpCode::SetContains);
                    }
                    "len" => {
                        self.assembler.emit_op(OpCode::Push);
                        self.assembler.emit_i32(addr as i32);
                        self.assembler.emit_op(OpCode::SetLen);
                    }
                    _ => return Err(format!("unknown set method: {}", method)),
                }
                Ok(())
            }
            Expression::Identifier(name) => {
                let addr = self.resolve_address(scope, name)?;
                self.assembler.emit_op(OpCode::Push);
                self.assembler.emit_i32(addr as i32);
                self.assembler.emit_op(OpCode::Load);
                Ok(())
            }
            Expression::BinaryOp(lhs, op, rhs) => {
                // Compile-time divide/modulo by zero detection
                if matches!(op, BinaryOperator::Div | BinaryOperator::Mod) {
                    match rhs.as_ref() {
                        Expression::Literal(Literal::Number(0)) =>
                            return Err(format!("{} by zero (compile-time literal)",
                                if matches!(op, BinaryOperator::Div) { "Division" } else { "Modulo" })),
                        Expression::Literal(Literal::BigNumber(s)) if s == "0" =>
                            return Err(format!("{} by zero (compile-time literal)",
                                if matches!(op, BinaryOperator::Div) { "Division" } else { "Modulo" })),
                        _ => {}
                    }
                }
                self.gen_expression(lhs, scope)?;
                self.gen_expression(rhs, scope)?;
                // If either operand is a str literal or str-typed local, use StrConcat
                let str_lhs = Self::expr_is_str(lhs, scope);
                let str_rhs = Self::expr_is_str(rhs, scope);
                if matches!(op, BinaryOperator::Add) && (str_lhs || str_rhs) {
                    // Ensure both sides are on the stack (already emitted above)
                    self.assembler.emit_op(OpCode::StrConcat);
                    return Ok(());
                }
                let opcode = match op {
                    BinaryOperator::Add => OpCode::Add,
                    BinaryOperator::Sub => OpCode::Sub,
                    BinaryOperator::Mul => OpCode::Mul,
                    BinaryOperator::Div => OpCode::Div,
                    BinaryOperator::Mod => OpCode::Rem,
                    BinaryOperator::Eq => OpCode::Eq,
                    BinaryOperator::Ne => OpCode::Ne,
                    BinaryOperator::Lt => OpCode::Lt,
                    BinaryOperator::Le => OpCode::Le,
                    BinaryOperator::Gt => OpCode::Gt,
                    BinaryOperator::Ge  => OpCode::Ge,
                    // Logical operators: emit both sides then combine
                    // && → Mul (1*1=1, 0*x=0 — correct for boolean 0/1 operands)
                    BinaryOperator::And => OpCode::Mul,
                    // || → Add (0+0=0, any non-zero is truthy in require conditions)
                    BinaryOperator::Or  => OpCode::Add,
                };
                self.assembler.emit_op(opcode);
                Ok(())
            }
            Expression::Call(name, args) => self.gen_call(name, args, scope),
        }
    }


    /// Returns true if `expr` is a string literal or a local variable declared as `str`.
    fn expr_is_str(expr: &Expression, scope: &FunctionScope) -> bool {
        match expr {
            Expression::Literal(Literal::String(_)) => true,
            Expression::Identifier(name) => {
                // Check function parameter types
                scope.local_types.get(name).map_or(false, |t| matches!(t, crate::compiler::ast::Type::Str))
            }
            _ => false,
        }
    }

    fn gen_call(&mut self, name: &str, args: &[Expression], scope: &mut FunctionScope) -> Result<(), String> {
        // ── String builtins ───────────────────────────────────────────────────
        if name == "str_concat" && args.len() == 2 {
            self.gen_expression(&args[0], scope)?;
            self.gen_expression(&args[1], scope)?;
            self.assembler.emit_op(OpCode::StrConcat);
            return Ok(());
        }
        if name == "str_len" && args.len() == 1 {
            self.gen_expression(&args[0], scope)?;
            self.assembler.emit_op(OpCode::StrLen);
            return Ok(());
        }
        if name == "str_eq" && args.len() == 2 {
            self.gen_expression(&args[0], scope)?;
            self.gen_expression(&args[1], scope)?;
            self.assembler.emit_op(OpCode::StrEq);
            return Ok(());
        }
        // ── Asset builtins ─────────────────────────────────────────────────────
        if name == "asset_create" && args.len() == 2 {
            // asset_create(type_name: str, value: u256) -> u256 (asset_id)
            // Hash the type_name to a u32 type_tag using FNV-1a.
            self.gen_expression(&args[1], scope)?;  // push value
            if let crate::compiler::ast::Expression::Literal(crate::compiler::ast::Literal::String(ref tn)) = args[0] {
                let mut hash: u32 = 2166136261;
                for byte in tn.bytes() {
                    hash ^= byte as u32;
                    hash = hash.wrapping_mul(16777619);
                }
                self.assembler.emit_op(OpCode::Push);
                self.assembler.emit_i32(hash as i32);
            } else {
                return Err("asset_create: type_name must be a string literal".into());
            }
            self.assembler.emit_op(OpCode::AssetCreate);
            return Ok(());
        }
        if name == "asset_transfer" && args.len() == 2 {
            // asset_transfer(asset_id: u256, to: u256) -> u256 (new_asset_id)
            self.gen_expression(&args[0], scope)?;  // push asset_id
            self.gen_expression(&args[1], scope)?;  // push new_owner
            self.assembler.emit_op(OpCode::AssetTransfer);
            return Ok(());
        }
        if name == "asset_burn" && args.len() == 1 {
            // asset_burn(asset_id: u256) -> u256 (burned value)
            self.gen_expression(&args[0], scope)?;
            self.assembler.emit_op(OpCode::AssetBurn);
            return Ok(());
        }
        if name == "asset_balance" && args.len() == 1 {
            // asset_balance(asset_id: u256) -> u256
            self.gen_expression(&args[0], scope)?;
            self.assembler.emit_op(OpCode::AssetBalance);
            return Ok(());
        }
        if name == "asset_owner" && args.len() == 1 {
            // asset_owner(asset_id: u256) -> u256
            self.gen_expression(&args[0], scope)?;
            self.assembler.emit_op(OpCode::AssetOwner);
            return Ok(());
        }

        // ── End string builtins ───────────────────────────────────────────────
        // ── Authority builtins (spec v7.0 authority model) ───────────────
        match name {
            "authority_envelope" => {
                // No args — pushes the current call's authority envelope as Bytes
                self.assembler.emit_op(OpCode::LoadAuthority);
                return Ok(());
            }
            "authority_require" => {
                // (envelope: Bytes, scope_hash: Bytes) → Bool
                if args.len() != 2 {
                    return Err("authority_require expects 2 arguments (envelope, scope_hash)".into());
                }
                // Push order reversed: scope_hash pushed last (popped first)
                self.gen_expression(&args[0], scope)?;  // envelope
                self.gen_expression(&args[1], scope)?;  // scope_hash
                self.assembler.emit_op(OpCode::AuthRequire);
                return Ok(());
            }
            "authority_identity" => {
                // (envelope: Bytes) → U256 (UMA identity)
                if args.len() != 1 {
                    return Err("authority_identity expects 1 argument (envelope)".into());
                }
                self.gen_expression(&args[0], scope)?;
                self.assembler.emit_op(OpCode::AuthIdentity);
                return Ok(());
            }
            // ── Address builtins (V3 Bech32 address model) ──────────────────
            "to_syna" => {
                // to_syna(address) → syna... Bech32 string as Bytes
                if args.len() != 1 {
                    return Err("to_syna expects 1 argument (20-byte address)".into());
                }
                self.gen_expression(&args[0], scope)?;
                self.assembler.emit_op(OpCode::AddrEncode);
                return Ok(());
            }
            "from_syna" => {
                // from_syna(s) → 20-byte value as U256
                if args.len() != 1 {
                    return Err("from_syna expects 1 argument (Bech32 string)".into());
                }
                self.gen_expression(&args[0], scope)?;
                self.assembler.emit_op(OpCode::AddrDecode);
                return Ok(());
            }
            "contract_address" => {
                // contract_address(deployer, nonce, artifact_hash) → sync... Bech32 string
                if args.len() != 3 {
                    return Err("contract_address expects 3 arguments (deployer, nonce, artifact_hash)".into());
                }
                // Stack order: artifact_hash (bottom), nonce, deployer (top)
                self.gen_expression(&args[2], scope)?;  // artifact_hash
                self.gen_expression(&args[1], scope)?;  // nonce
                self.gen_expression(&args[0], scope)?;  // deployer (top of stack)
                self.assembler.emit_op(OpCode::ContractAddr);
                return Ok(());
            }
            _ => {}
        }

        if let Some(opcode) = pqc_builtin_opcode(name) {
            // PQC/KEM builtins: argument push order matches the VM
            // opcode handler's pop order exactly (see vm.rs), which is
            // the reverse of natural source-code argument order for
            // these specific ops.
            match name {
                "aegis_call" | "aegis_verify" | "aegis_decaps" => {
                    // AEG1: single Bytes argument (the pre-encoded AEG1 frame).
                    // The VM pops the frame and dispatches it via aeg1::process_frame.
                    if args.len() != 1 {
                        return Err(format!("{} expects 1 argument (AEG1 frame)", name));
                    }
                    self.gen_expression(&args[0], scope)?;
                }
                "dilithium_verify" | "falcon_verify" | "sphincs_verify" => {
                    // Source order: (message, signature, public_key).
                    // VM pops: public_key, then message, then signature.
                    // So push order must be: signature, message, public_key.
                    if args.len() != 3 {
                        return Err(format!("{} expects 3 arguments", name));
                    }
                    self.gen_expression(&args[1], scope)?; // signature
                    self.gen_expression(&args[0], scope)?; // message
                    self.gen_expression(&args[2], scope)?; // public_key
                }
                "kyber_decaps" | "kyber_decapsulate"
                | "mceliece_decapsulate" | "hqc_decapsulate" => {
                    // KEM decapsulate: (ciphertext, private_key) → 2 args
                    if args.len() != 2 {
                        return Err(format!("{} expects 2 arguments", name));
                    }
                    self.gen_expression(&args[0], scope)?; // ciphertext
                    self.gen_expression(&args[1], scope)?; // private_key
                }
                "kyber_encapsulate" | "mceliece_encapsulate" | "hqc_encapsulate" => {
                    // KEM encapsulate: (public_key) → 1 arg
                    if args.len() != 1 {
                        return Err(format!("{} expects 1 argument", name));
                    }
                    self.gen_expression(&args[0], scope)?; // public_key
                }
                "falcon_sign" => {
                    // falcon_sign(message, private_key) → 2 args
                    if args.len() != 2 {
                        return Err(format!("{} expects 2 arguments", name));
                    }
                    self.gen_expression(&args[0], scope)?; // message
                    self.gen_expression(&args[1], scope)?; // private_key
                }
                _ => unreachable!(),
            }
            self.assembler.emit_op(opcode);
            return Ok(());
        }

        // Inter-function call: push args in source order into the
        // callee's known parameter slots isn't how the VM's Call opcode
        // works (Call is a plain code jump with a call-stack return
        // address) — argument marshaling for a same-VM `Call` happens by
        // storing directly into the callee's fixed local addresses
        // before jumping, since the VM has no register-passing ABI.
        let param_addrs = self
            .function_param_addrs
            .get(name)
            .cloned()
            .ok_or_else(|| format!("Undefined function: {}", name))?;

        if args.len() != param_addrs.len() {
            return Err(format!(
                "Function '{}' expects {} argument(s), got {}",
                name,
                param_addrs.len(),
                args.len()
            ));
        }

        for (arg, addr) in args.iter().zip(param_addrs.iter()) {
            self.gen_expression(arg, scope)?;
            self.assembler.emit_op(OpCode::Push);
            self.assembler.emit_i32(*addr as i32);
            self.assembler.emit_op(OpCode::Store);
        }

        // Forward-reference safe: address is patched even if the target
        // function hasn't been code-generated yet, because we backpatch
        // using the function_addresses map filled in during codegen. If
        // the callee comes AFTER this call site in source order, we defer
        // patching via a placeholder resolved once the whole contract has
        // been generated (see generate()'s final backpatch pass)... 
        self.assembler.emit_op(OpCode::Call);
        if let Some(&addr) = self.function_addresses.get(name) {
            self.assembler.emit_u32(addr);
        } else {
            // Callee not yet generated (forward reference): emit a
            // placeholder and record it for a final backpatch pass.
            let pos = self.assembler.emit_placeholder_u32();
            self.pending_call_patches.push((pos, name.to_string()));
        }

        // The callee leaves its return value (if any) on the stack; if it
        // has no return value the caller treats the call as a statement
        // and the surrounding gen_statement's Pop handles cleanup. To keep
        // the stack balanced for void calls used as expressions, push a
        // dummy 0 when the function has no return value.
        let has_return = *self.function_has_return.get(name).unwrap_or(&false);
        if !has_return {
            self.assembler.emit_op(OpCode::Push);
            self.assembler.emit_i32(0);
        }

        Ok(())
    }
}
