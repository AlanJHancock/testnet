// ── SynQ WASM Compiler — uses synq-compiler crate IR backend ──────────────────
// v0.2: Uses compile_ir() from the compiler crate for bytecode consistency
//       with the native server. Eliminates vendored compiler duplication.

use wasm_bindgen::prelude::*;
use synq_compiler::{self, ast::*, parser};
use synq_compiler::ast::{SourceUnit, ContractPart, Statement, Expression, Type};
use synq_compiler::transpile_solidity;

// ── Vendored VM for browser-side execution (not used for compilation) ────────
mod vm_inner {
    pub mod pqc_shims {
        pub mod dilithium {
            pub fn verify(_msg: &[u8], _sig: &[u8], _pk: &[u8]) -> bool { false }
        }
        pub mod kyber {
            pub fn keygen() -> Result<(Vec<u8>, Vec<u8>), String> { Ok((vec![0;32], vec![0;32])) }
            pub fn encaps(_pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> { Ok((vec![0;32], vec![0;32])) }
            pub fn decaps(_ct: &[u8], _sk: &[u8]) -> Result<Vec<u8>, String> { Ok(vec![0;32]) }
        }
        pub mod falcon {
            pub fn verify(_msg: &[u8], _sig: &[u8], _pk: &[u8]) -> bool { false }
        }
        pub mod sphincs {
            pub fn verify(_msg: &[u8], _sig: &[u8], _pk: &[u8]) -> bool { false }
        }
    }
    pub mod opcode;
    pub mod assembler;
    pub mod vm;
    pub use vm::QuantumVM;
    pub use opcode::{OpCode, VMError};
    pub use assembler::Assembler;
}

// ── Types we re-export for external use ───────────────────────────────────────
pub use vm_inner::QuantumVM;

// ── WASM CompileResult for the browser IDE ───────────────────────────────────
// This wraps the compiler crate's CompileResult, adding IDE-specific metadata.

/// Helper: convert AST Type to the string the IDE expects.
///
/// `struct_names` is the set of struct names declared in the source unit --
/// `Type::Named(name)` covers BOTH struct and enum references (see ast.rs),
/// so this only formats as "struct<Name>" when `name` is a known struct;
/// enum/unknown named types keep the pre-existing "u256" scalar-encoding
/// behavior to avoid changing enum ABI shape.
///
/// Every OTHER `Type` variant is now matched explicitly, mirroring
/// synq-server's own `type_name()` in main.rs byte-for-byte (same string
/// per variant) so the in-browser WASM-compiled ABI and the real
/// server-compile ABI never disagree on a concrete type's wire name.
/// This used to fall through a catch-all `_ => "u256"` for anything not
/// in the short explicit list above -- silently mis-typing Hash32,
/// Hash64, UMAIdentity, Height, ModelId, BytesN, the PQC key/sig types,
/// Int*, Option/Result/Tuple/Mapping/Array as "u256" in the ABI. That in
/// turn made Forge's Run & Debug / scenario-test arg coercion (which
/// trusts the ABI type string) treat a full 32-byte Hash32 hex argument
/// as a plain decimal-ish number, `Number()`-coerce it into a lossy
/// float (e.g. 7.71947261582108e+75), and send THAT as the JSON arg --
/// which the server then rejects with "unsupported number: <float>"
/// since it doesn't fit u64. Removing the wildcard arm also means this
/// match is exhaustive: a future new `Type` variant will fail to compile
/// here instead of silently inheriting the old "u256" mis-mapping.
fn type_name(ty: &Type, struct_names: &std::collections::HashSet<String>) -> String {
    match ty {
        Type::Bool    => "bool".to_string(),
        Type::Str     => "str".to_string(),
        Type::Address => "address".to_string(),
        Type::UInt8   => "u8".to_string(),
        Type::UInt16  => "u16".to_string(),
        Type::UInt32  => "u32".to_string(),
        Type::UInt64  => "u64".to_string(),
        Type::UInt128 => "u128".to_string(),
        Type::UInt256 => "u256".to_string(),
        Type::Int8 | Type::Int16 | Type::Int32 | Type::Int64 | Type::Int128 | Type::Int256 => {
            "i256".to_string()
        }
        Type::Bytes              => "bytes".to_string(),
        Type::DilithiumPublicKey => "dilithium_pubkey".to_string(),
        Type::FalconPublicKey    => "falcon_pubkey".to_string(),
        Type::KyberPublicKey     => "kyber_pubkey".to_string(),
        Type::DilithiumSignature => "dilithium_sig".to_string(),
        Type::FalconSignature    => "falcon_sig".to_string(),
        Type::Hash32             => "hash32".to_string(),
        Type::Hash64             => "hash64".to_string(),
        Type::UMAIdentity        => "uma_identity".to_string(),
        Type::Height             => "height".to_string(),
        Type::ModelId            => "model_id".to_string(),
        Type::BytesN(n)          => format!("bytes{}", n),
        Type::Asset(inner)       => format!("Asset<{}>", type_name(inner, struct_names)),
        Type::Option(inner)      => format!("option<{}>", type_name(inner, struct_names)),
        Type::Result(ok, err) => {
            format!("result<{}, {}>", type_name(ok, struct_names), type_name(err, struct_names))
        }
        Type::Tuple(types) => {
            let parts: Vec<String> = types.iter().map(|t| type_name(t, struct_names)).collect();
            format!("({})", parts.join(", "))
        }
        Type::Mapping(k, v) => {
            format!("mapping<{}, {}>", type_name(k, struct_names), type_name(v, struct_names))
        }
        Type::Array(inner) => format!("[{}]", type_name(inner, struct_names)),
        Type::Named(name) if struct_names.contains(name) => format!("struct<{}>", name),
        Type::Named(_) => "u256".to_string(),
    }
}

/// Result of compiling a SynQ source file for the WASM IDE.
#[derive(Debug)]
struct WasmCompileResult {
    pub bytecode:          Option<String>,
    pub state_vars:        Vec<(String, u32)>,
    pub warnings:          Vec<String>,
    pub errors:            Vec<String>,
    pub extern_contracts:  Vec<String>,
}

/// Walk a statement and collect unique extern_call target contract names.
fn wasm_collect_extern_contracts(stmt: &Statement, out: &mut Vec<String>) {
    match stmt {
        Statement::ExternCall { contract, .. } => {
            if !out.contains(contract) { out.push(contract.clone()); }
        }
        Statement::If { then_block, else_block, .. } => {
            for s in &then_block.statements { wasm_collect_extern_contracts(s, out); }
            if let Some(eb) = else_block {
                for s in &eb.statements { wasm_collect_extern_contracts(s, out); }
            }
        }
        _ => {}
    }
}

/// Walk a statement (recursing into if/while) checking whether it writes to
/// any name in . Used to derive ABI method mutability honestly
/// from the actual function body instead of relying on the opt-in
///  attribute, which most contracts don't declare.
fn wasm_stmt_writes_state(stmt: &Statement, state_names: &[String], out: &mut bool) {
    if *out { return; }
    match stmt {
        Statement::Assignment(name, _) => {
            if state_names.iter().any(|s| s == name) { *out = true; }
        }
        Statement::FieldAssignment { object, .. } => {
            if state_names.iter().any(|s| s == object) { *out = true; }
        }
        Statement::MapAssignment { map, .. } => {
            if state_names.iter().any(|s| s == map) { *out = true; }
        }
        Statement::SetOp { set, .. } => {
            if state_names.iter().any(|s| s == set) { *out = true; }
        }
        Statement::ExternCall { .. } => { *out = true; }
        Statement::If { then_block, else_block, .. } => {
            for s in &then_block.statements { wasm_stmt_writes_state(s, state_names, out); }
            if let Some(eb) = else_block {
                for s in &eb.statements { wasm_stmt_writes_state(s, state_names, out); }
            }
        }
        Statement::While { body, .. } => {
            for s in &body.statements { wasm_stmt_writes_state(s, state_names, out); }
        }
        _ => {}
    }
}

/// Finds PQC-builtin calls anywhere in the contract (including inside
/// if/while bodies -- recursed via scan_block) and returns one
/// (message, span) pair per call site, so WASM-mode callers get a real
/// warning per occurrence instead of a single warning for the whole file.
///
/// `span` is `Some` with the real (line, column) of the statement
/// containing the call, sourced from `Block.spans` (populated by the
/// parser via pest's own span tracking -- see ast::Block/ast::Span doc
/// comments). It is `None` only for a block with no position info at all
/// (synthetic/programmatic AST construction, not real parsed source --
/// doesn't happen today since the parser is Block's sole constructor, but
/// handled defensively rather than assumed away).
fn collect_pqc_warnings(ast: &[SourceUnit]) -> Vec<(String, Option<Span>)> {
    const PQC_BUILTINS_WARN: &[&str] = &[
        "dilithium_verify", "falcon_verify", "sphincs_verify",
        "kyber_encapsulate", "kyber_decapsulate", "kyber_decaps",
        "falcon_sign", "mceliece_encapsulate", "mceliece_decapsulate",
        "hqc_encapsulate", "hqc_decapsulate",
    ];

    fn scan_block(block: &Block, out: &mut Vec<(String, Option<Span>)>) {
        for (idx, stmt) in block.statements.iter().enumerate() {
            let span = block.spans.get(idx).copied().filter(|s| *s != Span::default());
            let exprs: Vec<&Expression> = match stmt {
                Statement::Expression(e) => vec![e],
                Statement::Return(Some(e)) => vec![e],
                Statement::Assignment(_, e) => vec![e],
                Statement::Require(e, _) => vec![e],
                Statement::Let { value, .. } => vec![value],
                Statement::LetDestructure { value, .. } => vec![value.as_ref()],
                _ => vec![],
            };
            for expr in exprs {
                if let Expression::Call(name, _) = expr {
                    if PQC_BUILTINS_WARN.contains(&name.as_str()) {
                        out.push((
                            format!(
                                "PQC builtin '{}' will throw a RuntimeError in browser (WASM) mode. \
                                 Deploy to synq-server for real PQC verification.",
                                name
                            ),
                            span,
                        ));
                    }
                }
            }
            // Recurse so a call nested in an if/while body is still found
            // -- and reports ITS OWN block's span, not the enclosing
            // statement's.
            match stmt {
                Statement::If { then_block, else_block, .. } => {
                    scan_block(then_block, out);
                    if let Some(eb) = else_block {
                        scan_block(eb, out);
                    }
                }
                Statement::While { body, .. } => scan_block(body, out),
                _ => {}
            }
        }
    }

    let mut out = Vec::new();
    for unit in ast {
        if let SourceUnit::Contract(c) = unit {
            for part in &c.parts {
                if let ContractPart::Function(f) = part {
                    scan_block(&f.body, &mut out);
                }
            }
        }
    }
    out
}

// ── WASM-bindgen exports for browser IDE ─────────────────────────────────────

#[derive(serde::Serialize)]
struct WasmParamInfo {
    name: String,
    ty: String,
}

#[derive(serde::Serialize)]
struct WasmFunctionInfo {
    name: String,
    params: Vec<WasmParamInfo>,
    return_type: Option<String>,
    argc: usize,
}

#[derive(serde::Serialize)]
struct WasmCompileResultJson {
    success: bool,
    bytecode: Option<String>,
    state_vars: Vec<(String, u32)>,
    warnings: Vec<String>,
    errors: Vec<String>,
    extern_contracts: Vec<String>,
    functions: Vec<WasmFunctionInfo>,
    state_var_types: std::collections::HashMap<String, String>,
}

/// Compile using the IR backend (same as native server) for bytecode consistency.
#[wasm_bindgen]
pub fn compile_synq(source: &str) -> String {
    let ast = parser::parse(source).unwrap_or_default();

    let result = match synq_compiler::compile_ir(source) {
        Ok(cr) => {
            let mut warnings = cr.warnings.clone();
            warnings.extend(collect_pqc_warnings(&ast).into_iter().map(|(msg, span)| {
                match span {
                    Some(s) => format!("{} (line {}, column {})", msg, s.line, s.column),
                    None => msg,
                }
            }));

            // Collect extern_call targets from AST (for IDE cross-check)
            let mut extern_contracts: Vec<String> = Vec::new();
            for unit in &ast {
                if let SourceUnit::Contract(c) = unit {
                    for part in &c.parts {
                        if let ContractPart::Function(f) = part {
                            for stmt in &f.body.statements {
                                wasm_collect_extern_contracts(stmt, &mut extern_contracts);
                            }
                        }
                    }
                }
            }

            // Extract function metadata from AST for IDE
            let struct_names: std::collections::HashSet<String> = ast.iter()
                .filter_map(|u| match u {
                    SourceUnit::Struct(sd) => Some(sd.name.clone()),
                    _ => None,
                })
                .collect();
            let mut functions: Vec<WasmFunctionInfo> = Vec::new();
            let mut state_var_types: std::collections::HashMap<String, String> = std::collections::HashMap::new();
            for unit in &ast {
                if let SourceUnit::Contract(c) = unit {
                    for part in &c.parts {
                        if let ContractPart::Function(f) = part {
                            let params: Vec<WasmParamInfo> = f.params.iter().map(|p| WasmParamInfo {
                                name: p.name.clone(),
                                ty: type_name(&p.ty, &struct_names),
                            }).collect();
                            let argc = params.len();
                            functions.push(WasmFunctionInfo {
                                name: f.name.clone(),
                                params,
                                return_type: f.returns.as_ref().map(|t| type_name(t, &struct_names)),
                                argc,
                            });
                        }
                        if let ContractPart::StateVariable(sv) = part {
                            state_var_types.insert(sv.name.clone(), type_name(&sv.ty, &struct_names));
                        }
                    }
                }
            }

            WasmCompileResultJson {
                success: true,
                bytecode: Some(hex::encode(&cr.bytecode)),
                state_vars: cr.state_vars,
                warnings,
                errors: vec![],
                extern_contracts,
                functions,
                state_var_types,
            }
        },
        Err(e) => WasmCompileResultJson {
            success: false,
            bytecode: None,
            state_vars: vec![],
            warnings: vec![],
            errors: vec![e],
            extern_contracts: vec![],
            functions: vec![],
            state_var_types: std::collections::HashMap::new(),
        },
    };
    serde_json::to_string(&result)
        .unwrap_or_else(|e| format!("{{\"success\":false,\"errors\":[\"serialisation error: {}\"]}}", e))
}

/// Compiler version string.
#[wasm_bindgen]
pub fn synq_version() -> String { "0.2.0-wasm".to_string() }


// ── C-ABI export for server-side wasmtime execution ──────────────────────────
#[no_mangle]
pub unsafe extern "C" fn compile_synq_c(src_ptr: *const u8, src_len: usize, out_ptr: *mut u8, out_len: usize) -> i32 {
    let source = match std::slice::from_raw_parts(src_ptr, src_len) {
        s => match std::str::from_utf8(s) {
            Ok(st) => st,
            Err(_) => return -1,
        }
    };

    let result_json = compile_synq(source);
    let result_bytes = result_json.as_bytes();
    let written = result_bytes.len();
    if written > out_len {
        return -1;
    }
    std::ptr::copy_nonoverlapping(result_bytes.as_ptr(), out_ptr, written);
    written as i32
}

// ── Memory allocator for server-side wasmtime C-ABI calls ────────────────────
// ── ForgeIDE-facing compile entry point ───────────────────────────────────────
// forge-v3 (app/lib/ide/compiler.ts) imports this WASM module and calls
// `compiler.compileSynq(source)` expecting a plain JS object shaped exactly
// like the TS `RawCompileResult` / `SynqArtifacts` / `ForgeDiagnostic` types
// in app/lib/ide/types.ts. Everything below is real: bytecode + Solidity
// transpilation come straight from the same IR backend / transpiler the
// native server uses, and every hash is a real SHA3-256 of the actual bytes
// produced — nothing here is fabricated placeholder data. The `manifest`
// field is explicitly a compiler-local *preview* manifest (unsigned) — it is
// not the ML-DSA-87-signed on-chain manifest the server produces, and is
// labelled as such so ForgeIDE never implies an on-chain guarantee it can't
// back up client-side.
#[wasm_bindgen(js_name = compileSynq)]
pub fn compile_synq_ide(source: &str) -> JsValue {
    use sha3::{Digest, Sha3_256};

    fn sha3_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    fn selector_hex(name: &str, param_types: &[String]) -> String {
        let sig = format!("{}({})", name, param_types.join(","));
        let full = sha3_hex(sig.as_bytes());
        format!("0x{}", &full[..8])
    }

    let ast = parser::parse(source).unwrap_or_default();

    let mut diagnostics: Vec<serde_json::Value> = Vec::new();
    let mut artifacts: Option<serde_json::Value> = None;
    let ok;

    // Parse once up front, ahead of compile_ir(), and treat a parse
    // failure as EXACTLY one diagnostic -- mirrors synq-server's
    // compile_handler (main.rs), which does this same explicit
    // pre-parse for the identical reason. A parse error's own Display
    // already spans several lines (span marker, source snippet,
    // "= expected ..."), unlike compile_ir()'s Err(e) in the semantic-
    // check case below, where `e` is `semantic_errors.join("\n")` --
    // each LINE there really is an independent error, safe to split.
    // Before this check, a parse error (e.g. one missing brace) fell
    // through to that same `for line in e.lines()` splitter and got
    // shredded into 5-6 garbage diagnostics (one per line of pest's
    // ASCII-art output), inflating/overriding the real error count and
    // burying whatever the file's actual errors were once the brace
    // was fixed and recompiled.
    if let Err(e) = parser::parse(source) {
        ok = false;
        let message = format!("Parse error: {}", e);
        let pos = message.find(" --> ").and_then(|i| {
            let rest = &message[i + 5..];
            let end = rest.find('\n').unwrap_or(rest.len());
            rest[..end].split_once(':').and_then(|(l, c)| {
                match (l.trim().parse::<u64>(), c.trim().parse::<u64>()) {
                    (Ok(l), Ok(c)) => Some((l, c)),
                    _ => None,
                }
            })
        });
        diagnostics.push(serde_json::json!({
            "severity": "error",
            "message": message,
            "line": pos.map(|(l, _)| l),
            "column": pos.map(|(_, c)| c),
            "source": "synq-compiler",
        }));
    } else {
    match synq_compiler::compile_ir(source) {
        Ok(cr) => {
            ok = true;

            for w in &cr.warnings {
                // IR pipeline stats ("[IR] fn foo: N blocks, ...") are
                // per-function diagnostic telemetry, not something the
                // developer needs to act on - keep them out of the
                // Problems panel by tagging them "info" instead of
                // "warning". Real compiler warnings keep severity "warning".
                let severity = if w.starts_with("[IR] fn ") { "info" } else { "warning" };
                diagnostics.push(serde_json::json!({
                    "severity": severity,
                    "message": w,
                    "line": null,
                    "column": null,
                    "source": "synq-compiler",
                }));
            }
            for (message, span) in collect_pqc_warnings(&ast) {
                diagnostics.push(serde_json::json!({
                    "severity": "warning",
                    "message": message,
                    "line": span.map(|s| s.line),
                    "column": span.map(|s| s.column),
                    "source": "synq-compiler",
                }));
            }

            let contract_name = ast.iter().find_map(|u| match u {
                SourceUnit::Contract(c) => Some(c.name.clone()),
                _ => None,
            }).unwrap_or_else(|| "Contract".to_string());

            // ── ABI methods (real signatures, real selectors) ──────────────
            // First pass: collect state variable names so mutability can be
            // derived from real body analysis (see wasm_stmt_writes_state),
            // not just the opt-in @effects(modifies:) attribute.
            let mut state_var_names: Vec<String> = Vec::new();
            for unit in &ast {
                if let SourceUnit::Contract(c) = unit {
                    for part in &c.parts {
                        if let ContractPart::StateVariable(sv) = part {
                            state_var_names.push(sv.name.clone());
                        }
                    }
                }
            }

            // Collect declared struct names up-front so type_name() can tell
            // a struct-typed Named("Point") apart from an enum-typed
            // Named("Color") -- both use the same AST variant.
            let struct_names: std::collections::HashSet<String> = ast.iter()
                .filter_map(|u| match u {
                    SourceUnit::Struct(sd) => Some(sd.name.clone()),
                    _ => None,
                })
                .collect();

            let mut methods: Vec<serde_json::Value> = Vec::new();
            let mut state_schema: Vec<serde_json::Value> = Vec::new();

            for unit in &ast {
                if let SourceUnit::Contract(c) = unit {
                    for part in &c.parts {
                        match part {
                            // Inclusion gate for "does this function belong in the
                            // ABI's methods list at all" (externally callable in
                            // SOME form), NOT the narrower `f.is_public` ("no
                            // authority required, callable by anyone" per the
                            // spec's attribute table). Those are different
                            // questions: @authority(Scope)/@governance(Scope) are
                            // documented as alternate "callable from outside"
                            // gates with their own enforcement, not "internal
                            // only" -- a devnet admin setter like
                            // `@authority(AdminScope) function setValue(...) as
                            // caller` is meant to be externally invokable (with
                            // an authority envelope), just not by ANYONE the way
                            // @public is. The old bare `f.is_public` filter here
                            // silently dropped every such function from the ABI
                            // entirely, which is what made Forge's scenario-test
                            // runner report "setValue is not a published method
                            // on this contract's ABI" even though the real
                            // server-side dry-run endpoint executes it fine.
                            // aivm_codegen.rs's own manifest-function filter
                            // already ORs in `f.requires_caller` for exactly this
                            // reason (see `if !fdef.is_public &&
                            // !fdef.requires_caller { continue; }`) -- mirrored
                            // here, plus an explicit Authority/Governance check
                            // so a function gated ONLY by @authority/@governance
                            // (no `as caller` clause) is still included.
                            ContractPart::Function(f)
                                if f.is_public
                                    || f.requires_caller
                                    || f.attributes.iter().any(|a| {
                                        matches!(
                                            a,
                                            Attribute::Authority(_) | Attribute::Governance(_)
                                        )
                                    }) =>
                            {
                                let param_types: Vec<String> =
                                    f.params.iter().map(|p| type_name(&p.ty, &struct_names)).collect();
                                let params: Vec<serde_json::Value> = f.params.iter().map(|p| {
                                    serde_json::json!({ "name": p.name, "type": type_name(&p.ty, &struct_names) })
                                }).collect();
                                let returns: Vec<String> = match &f.returns {
                                    Some(t) => vec![type_name(t, &struct_names)],
                                    None => vec![],
                                };
                                let mut writes = !f.modifies.is_empty();
                                for stmt in &f.body.statements {
                                    wasm_stmt_writes_state(stmt, &state_var_names, &mut writes);
                                }
                                let mutability = if writes { "write" } else { "read" };
                                methods.push(serde_json::json!({
                                    "mutability": mutability,
                                    "name": f.name,
                                    "params": params,
                                    "returns": returns,
                                    "selector": selector_hex(&f.name, &param_types),
                                    "visibility": "public",
                                }));
                            }
                            ContractPart::StateVariable(sv) => {
                                state_schema.push(serde_json::json!({
                                    "name": sv.name,
                                    "type": type_name(&sv.ty, &struct_names),
                                    "visibility": "internal",
                                }));
                            }
                            _ => {}
                        }
                    }
                }
            }

            let mut struct_defs: Vec<serde_json::Value> = Vec::new();
            for unit in &ast {
                if let SourceUnit::Struct(sd) = unit {
                    let fields: Vec<serde_json::Value> = sd.fields.iter().map(|p| {
                        serde_json::json!({ "name": p.name, "type": type_name(&p.ty, &struct_names) })
                    }).collect();
                    struct_defs.push(serde_json::json!({ "name": sd.name, "fields": fields }));
                }
            }

            let abi = serde_json::json!({
                "abi_version": "synq-v3-preview-1",
                "contract": contract_name,
                "methods": methods,
                "events": [],
                "errors": [],
                "security_requirements": {},
                "state_schema": state_schema,
                "structs": struct_defs,
            });

            let bytecode_hex = hex::encode(&cr.bytecode);
            let solidity_compatibility = transpile_solidity::transpile_to_solidity(&ast);

            let manifest = serde_json::json!({
                "kind": "compiler-local-preview",
                "signed": false,
                "note": "Unsigned client-side preview manifest. Not the ML-DSA-87-signed on-chain manifest produced by the SynQ server.",
                "contract": contract_name,
                "compilerVersion": synq_version(),
            });

            let abi_json = serde_json::to_vec(&abi).unwrap_or_default();
            let manifest_json = serde_json::to_vec(&manifest).unwrap_or_default();
            let storage_schema_json = serde_json::to_vec(&state_schema).unwrap_or_default();

            let hashes = serde_json::json!({
                "abi": sha3_hex(&abi_json),
                "bytecode": sha3_hex(&cr.bytecode),
                "manifest": sha3_hex(&manifest_json),
                "source": sha3_hex(source.as_bytes()),
                "storageSchema": sha3_hex(&storage_schema_json),
            });

            artifacts = Some(serde_json::json!({
                "abi": abi,
                "manifest": manifest,
                "bytecodeHex": bytecode_hex,
                "solidityCompatibility": solidity_compatibility,
                "hashes": hashes,
            }));
        }
        Err(e) => {
            ok = false;
            // compile_ir() joins every accumulated error with '\n', one
            // "<message> --> <line>:<column>" (or a bare message with no
            // position) per line -- see check_undefined_refs in
            // SynQ/compiler/src/lib.rs. This used to be pushed as ONE
            // diagnostic with the whole multi-line string as its message
            // and line/column hardcoded to null, which meant: (1) two+
            // real errors in one compile always collapsed into a single
            // diagnostic entry (the "count" looked wrong), and (2) any
            // jump-to-source link had nothing to jump to (the "position"
            // looked wrong) even though the message text itself already
            // carried a real "--> line:col" suffix per error. Split on
            // newline and parse that suffix per line so every error the
            // IR backend found becomes its own diagnostic with a real
            // position, matching the native /compile server path.
            for line in e.lines().filter(|l| !l.is_empty()) {
                let (message, pos) = match line.rfind(" --> ") {
                    Some(idx) => {
                        let (msg, rest) = (&line[..idx], &line[idx + 5..]);
                        match rest.split_once(':') {
                            Some((l, c)) => {
                                match (l.trim().parse::<u64>(), c.trim().parse::<u64>()) {
                                    (Ok(l), Ok(c)) => (msg.to_string(), Some((l, c))),
                                    _ => (line.to_string(), None),
                                }
                            }
                            None => (line.to_string(), None),
                        }
                    }
                    None => (line.to_string(), None),
                };
                diagnostics.push(serde_json::json!({
                    "severity": "error",
                    "message": message,
                    "line": pos.map(|(l, _)| l),
                    "column": pos.map(|(_, c)| c),
                    "source": "synq-compiler",
                }));
            }
        }
    }

    }

    let result = serde_json::json!({
        "ok": ok,
        "compilerVersion": format!("{} (Intermediate Representation backend, sole path)", synq_version()),
        "diagnostics": diagnostics,
        "artifacts": artifacts,
    });

    let serializer = serde_wasm_bindgen::Serializer::json_compatible();
    serde::Serialize::serialize(&result, &serializer).unwrap_or_else(|e| {
        let fallback = serde_json::json!({
            "ok": false,
            "compilerVersion": "unavailable",
            "diagnostics": [{
                "severity": "error",
                "message": format!("serialisation error: {}", e),
                "line": null,
                "column": null,
                "source": "synq-compiler",
            }],
            "artifacts": null,
        });
        serde::Serialize::serialize(&fallback, &serde_wasm_bindgen::Serializer::json_compatible()).unwrap_or(JsValue::NULL)
    })
}

// The server's wasm_compiler.rs calls synq_wasm_alloc(size) to get a pointer
// into WASM linear memory, writes the source string there, then calls
// compile_synq_c. We use Rust's global allocator (dlmalloc via wasm-bindgen)
// to avoid corrupting heap metadata — a custom bump allocator at a fixed
// offset would overwrite dlmalloc's free list.

use std::alloc::{alloc, Layout};

#[no_mangle]
pub unsafe extern "C" fn synq_wasm_alloc(size: i32) -> i32 {
    if size <= 0 { return 0; }
    let layout = match Layout::from_size_align(size as usize, 1) {
        Ok(l) => l,
        Err(_) => return 0,
    };
    let ptr = alloc(layout);
    if ptr.is_null() { return 0; }
    ptr as i32
}

