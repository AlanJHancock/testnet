// ── SynQ → Solidity Transpiler ─────────────────────────────────────────────────
//
// Transpiles SynQ AST to Solidity source for EVM deployment via SXCP.
// Both QVM bytecode and Solidity derive from the same AST → same SQB signature
// attests their semantic equivalence.
//
// Limitations: PQC ops (Aegis, authority envelopes), governance scopes, and
// asset builtins are emitted as comments/stubs — the common subset (state,
// functions, arithmetic, branching, loops, maps, structs, enums, events)
// maps directly to Solidity.

use std::fmt::Write;
use crate::ast::*;

/// Transpile a parsed SynQ contract AST to Solidity source.
pub fn transpile_to_solidity(units: &[SourceUnit]) -> String {
    // Find the contract definition
    let contract = units.iter().find_map(|u| {
        if let SourceUnit::Contract(c) = u { Some(c) } else { None }
    });
    let contract = match contract {
        Some(c) => c,
        None => return String::new(),
    };
    let mut out = String::new();

    // Header
    writeln!(out, "// ═════════════════════════════════════════════════════════════════").unwrap();
    writeln!(out, "//  Auto-transpiled from SynQ → Solidity for EVM deployment (SXCP)").unwrap();
    writeln!(out, "//  Contract: {}", contract.name).unwrap();
    writeln!(out, "//").unwrap();
    writeln!(out, "//  This Solidity was generated from the same SynQ AST that produced").unwrap();
    writeln!(out, "//  the QVM bytecode in this SQB artifact. The ML-DSA-87 signature").unwrap();
    writeln!(out, "//  on the SQB attests that both targets derive from the same source.").unwrap();
    writeln!(out, "//").unwrap();
    writeln!(out, "//  NOTE: PQC operations, authority scopes, and asset builtins are").unwrap();
    writeln!(out, "//  emitted as comments — they require SXCP bridge precompiles on EVM.").unwrap();
    writeln!(out, "// ═════════════════════════════════════════════════════════════════").unwrap();
    writeln!(out, "// SPDX-License-Identifier: MIT").unwrap();
    writeln!(out, "pragma solidity ^0.8.20;").unwrap();
    writeln!(out).unwrap();

    // Struct definitions (top-level)
    for unit in units {
        if let SourceUnit::Struct(sd) = unit {
            writeln!(out, "struct {} {{", sd.name).unwrap();
            for field in &sd.fields {
                let mut ty_str = ty_to_sol(&field.ty);
                // Struct types need "memory" for local vars, but not in struct definitions
                // Just use the type name directly
                if ty_str.contains(" memory") { ty_str = ty_str.replace(" memory", ""); }
                writeln!(out, "    {} {};", ty_str, field.name).unwrap();
            }
            writeln!(out, "}}").unwrap();
            writeln!(out).unwrap();
        }
    }

    // Enums
    for ed in &contract.enums {
        writeln!(out, "enum {} {{", ed.name).unwrap();
        for variant in &ed.variants {
            if variant.fields.is_empty() {
                writeln!(out, "    {},", variant.name).unwrap();
            } else {
                // Algebraic enums don't exist in Solidity — emit as comment + plain enum
                writeln!(out, "    {}, // SynQ algebraic variant — fields: {:?}", variant.name,
                    variant.fields.iter().map(|f| format!("{}: {:?}", f.name, f.ty)).collect::<Vec<_>>()
                ).unwrap();
            }
        }
        writeln!(out, "}}").unwrap();
        writeln!(out).unwrap();
    }

    // Events
    for ev in &contract.event_defs {
        let params: Vec<String> = ev.params.iter()
            .map(|p| {
                let ty_str = ty_to_sol(&p.ty);
                // Events use "memory" for reference types
                let needs_memory = matches!(p.ty, Type::Named(_) | Type::Str | Type::Bytes);
                let mem = if needs_memory { " memory" } else { "" };
                format!("{}{}{} {}", ty_str, mem, if p.is_indexed { " indexed" } else { "" }, p.name)
            })
            .collect();
        writeln!(out, "event {}({});", ev.name, params.join(", ")).unwrap();
    }
    if !contract.event_defs.is_empty() { writeln!(out).unwrap(); }

    // Named errors
    for err in &contract.error_defs {
        let params: Vec<String> = err.params.iter()
            .map(|p| {
                let ty_str = ty_to_sol(&p.ty);
                let needs_memory = matches!(p.ty, Type::Named(_) | Type::Str | Type::Bytes);
                if needs_memory {
                    format!("{} memory {}", ty_str, p.name)
                } else {
                    format!("{} {}", ty_str, p.name)
                }
            }).collect();
        writeln!(out, "error {}({});", err.name, params.join(", ")).unwrap();
    }
    if !contract.error_defs.is_empty() { writeln!(out).unwrap(); }

    // Contract body
    writeln!(out, "contract {} {{", contract.name).unwrap();
    writeln!(out).unwrap();

    // State variables
    let mut has_state = false;
    for part in &contract.parts {
        if let ContractPart::StateVariable(sv) = part {
            let vis = if sv.is_public { "public" } else { "internal" };
            writeln!(out, "    {} {} {};", ty_to_sol(&sv.ty), vis, sv.name).unwrap();
            has_state = true;
        }
    }
    if has_state { writeln!(out).unwrap(); }

    // Constructor
    for part in &contract.parts {
        if let ContractPart::Constructor(c) = part {
            let params: Vec<String> = c.params.iter()
                .map(|p| {
                    let ty_str = ty_to_sol(&p.ty);
                    let needs_memory = matches!(p.ty, Type::Named(_) | Type::Str | Type::Bytes);
                    if needs_memory {
                        format!("{} memory {}", ty_str, p.name)
                    } else {
                        format!("{} {}", ty_str, p.name)
                    }
                }).collect();
            writeln!(out, "    constructor({}) {{", params.join(", ")).unwrap();
            transpile_block(&mut out, &c.body, 2);
            writeln!(out, "    }}").unwrap();
            writeln!(out).unwrap();
        }
    }

    // Functions
    let mut first_func = true;
    for part in &contract.parts {
        if let ContractPart::Function(f) = part {
            if !first_func { writeln!(out).unwrap(); }
            first_func = false;
            transpile_function(&mut out, f);
        }
    }

    writeln!(out, "}}").unwrap();
    out
}

fn transpile_function(out: &mut String, f: &FunctionDefinition) {
    let vis = if f.is_public { "public" } else { "internal" };

    // Map attributes to Solidity modifiers/comments
    let mut modifiers = Vec::new();
    for attr in &f.attributes {
        match attr {
            Attribute::Authority(scope) => {
                modifiers.push(format!("// @authority(\"{}\") — requires SXCP authority bridge", scope));
            }
            Attribute::Governance(scope) => {
                modifiers.push(format!("// @governance(\"{}\") — requires SXCP governance bridge", scope));
            }
            Attribute::Effects(vs) => {
                modifiers.push(format!("// @effects({})", vs.join(", ")));
            }
            Attribute::Requires(e) => {
                modifiers.push(format!("// @requires({})", e));
            }
            Attribute::Ensures(e) => {
                modifiers.push(format!("// @ensures({})", e));
            }
            Attribute::Fails(n) => {
                modifiers.push(format!("// @fails({})", n));
            }
            Attribute::Bounded(b) => {
                modifiers.push(format!("// @bounded({})", b));
            }
            Attribute::Manifest => {
                modifiers.push("// @manifest".to_string());
            }
            Attribute::Ai => {
                modifiers.push("// @ai — requires SXCP AI inference bridge".to_string());
            }
            Attribute::Public => {}
        }
    }

    let params: Vec<String> = f.params.iter()
        .map(|p| {
            let ty_str = ty_to_sol(&p.ty);
            let needs_memory = matches!(p.ty, Type::Named(_) | Type::Str | Type::Bytes);
            if needs_memory {
                format!("{} memory {}", ty_str, p.name)
            } else {
                format!("{} {}", ty_str, p.name)
            }
        }).collect();

    let returns = match &f.returns {
        Some(ty) => {
            let ty_str = ty_to_sol(ty);
            if matches!(ty, Type::Named(_) | Type::Str | Type::Bytes) {
                format!(" returns ({} memory)", ty_str)
            } else {
                format!(" returns ({})", ty_str)
            }
        }
        None => String::new(),
    };

    let mut sig = format!("    function {}({}) {}{}", f.name, params.join(", "), vis, returns);
    if f.requires_caller {
        sig.push_str(" /* as caller */");
    }

    for m in &modifiers {
        writeln!(out, "{}", m).unwrap();
    }
    writeln!(out, "{} {{", sig).unwrap();

    if !f.requires_state.is_empty() {
        writeln!(out, "        // requires: {}", f.requires_state.join(", ")).unwrap();
    }
    if !f.modifies.is_empty() {
        writeln!(out, "        // modifies: {}", f.modifies.join(", ")).unwrap();
    }

    transpile_block(out, &f.body, 2);
    writeln!(out, "    }}").unwrap();
}

fn transpile_block(out: &mut String, block: &Block, indent: usize) {
    let pad = "    ".repeat(indent);
    for stmt in &block.statements {
        transpile_statement(out, stmt, indent);
        let _ = pad; // suppress unused warning
    }
}

fn transpile_statement(out: &mut String, stmt: &Statement, indent: usize) {
    let pad = "    ".repeat(indent);
    match stmt {
        Statement::Expression(expr) => {
            writeln!(out, "{}{};", pad, transpile_expr(expr)).unwrap();
        }
        Statement::Require(cond, msg) => {
            writeln!(out, "{}require({}, \"{}\");", pad, transpile_expr(cond), msg).unwrap();
        }
        Statement::RevertNamed { error, args } => {
            let a: Vec<String> = args.iter().map(transpile_expr).collect();
            writeln!(out, "{}revert {}({});", pad, error, a.join(", ")).unwrap();
        }
        Statement::RevertEnum { enum_name, error, args } => {
            let a: Vec<String> = args.iter().map(transpile_expr).collect();
            writeln!(out, "{}revert {}::{}({});", pad, enum_name, error, a.join(", ")).unwrap();
        }
        Statement::Assignment(name, expr) => {
            writeln!(out, "{}{} = {};", pad, name, transpile_expr(expr)).unwrap();
        }
        Statement::FieldAssignment { object, field, value } => {
            writeln!(out, "{}{}.{} = {};", pad, object, field, transpile_expr(value)).unwrap();
        }
        Statement::MapAssignment { map, key, value } => {
            writeln!(out, "{}{}[{}] = {};", pad, map, transpile_expr(key), transpile_expr(value)).unwrap();
        }
        Statement::SetOp { set, op, value } => {
            let method = match op { SetOpKind::Add => "add", SetOpKind::Remove => "remove" };
            writeln!(out, "{}{}.{}({});", pad, set, method, transpile_expr(value)).unwrap();
        }
        Statement::Let { name, ty, value } => {
            // Infer type from explicit annotation or from the expression
            let (ty_str, is_struct) = if let Some(t) = ty {
                let needs_memory = matches!(t, Type::Named(_) | Type::Str | Type::Bytes);
                (ty_to_sol(t), needs_memory)
            } else {
                // Infer from expression
                match value {
                    Expression::StructLiteral { type_name, .. } => {
                        (type_name.clone(), true)
                    }
                    _ => ("uint256".to_string(), false)
                }
            };
            if is_struct {
                writeln!(out, "{}{} memory {} = {};", pad, ty_str, name, transpile_expr(value)).unwrap();
            } else {
                writeln!(out, "{}{} {} = {};", pad, ty_str, name, transpile_expr(value)).unwrap();
            }
        }
        Statement::LetDestructure { names, value } => {
            let vars: Vec<String> = names.iter().map(|n| format!("var {}", n)).collect();
            writeln!(out, "{}({}) = {};", pad, vars.join(", "), transpile_expr(value)).unwrap();
        }
        Statement::Return(None) => {
            writeln!(out, "{}return;", pad).unwrap();
        }
        Statement::Return(Some(expr)) => {
            writeln!(out, "{}return {};", pad, transpile_expr(expr)).unwrap();
        }
        Statement::ExternCall { contract, function, args } => {
            let a: Vec<String> = args.iter().map(transpile_expr).collect();
            writeln!(out, "{}// extern_call {}.{}({}) — requires SXCP cross-contract bridge", pad, contract, function, a.join(", ")).unwrap();
        }
        Statement::Emit { event, args } => {
            let a: Vec<String> = args.iter().map(transpile_expr).collect();
            writeln!(out, "{}emit {}({});", pad, event, a.join(", ")).unwrap();
        }
        Statement::If { condition, then_block, else_block } => {
            writeln!(out, "{}if ({}) {{", pad, transpile_expr(condition)).unwrap();
            transpile_block(out, then_block, indent + 1);
            if let Some(eb) = else_block {
                writeln!(out, "{}}} else {{", pad).unwrap();
                transpile_block(out, eb, indent + 1);
            }
            writeln!(out, "{}}}", pad).unwrap();
        }
        Statement::While { condition, body } => {
            writeln!(out, "{}while ({}) {{", pad, transpile_expr(condition)).unwrap();
            transpile_block(out, body, indent + 1);
            writeln!(out, "{}}}", pad).unwrap();
        }
        Statement::Break => {
            writeln!(out, "{}break;", pad).unwrap();
        }
        Statement::Continue => {
            writeln!(out, "{}continue;", pad).unwrap();
        }
    }
}

fn transpile_expr(expr: &Expression) -> String {
    match expr {
        Expression::Call(name, args) => {
            let a: Vec<String> = args.iter().map(transpile_expr).collect();
            // Map SynQ builtins to Solidity equivalents
            match name.as_str() {
                "to_syna" => format!("address({})", transpile_expr(&args[0])),
                "from_syna" => format!("uint256(uint160({}))", transpile_expr(&args[0])),
                "contract_address" => format!("address(this)"),
                "str_len" => format!("bytes({}).length", transpile_expr(&args[0])),
                "str_concat" => format!("string.concat({})", a.join(", ")),
                "str_eq" => format!("(keccak256(bytes({})) == keccak256(bytes({})))", transpile_expr(&args[0]), transpile_expr(&args[1])),
                "asset_create" | "asset_transfer" | "asset_burn" | "asset_balance" | "asset_owner" =>
                    format!("/* SXCP asset bridge: {}({}) */", name, a.join(", ")),
                "aegis_call" | "aegis_verify" | "aegis_decaps" =>
                    format!("/* SXCP PQC bridge: {}({}) */", name, a.join(", ")),
                "ai_verify_proof" | "ai_infer" =>
                    format!("/* SXCP AI bridge: {}({}) */", name, a.join(", ")),
                _ => format!("{}({})", name, a.join(", ")),
            }
        }
        Expression::Literal(lit) => literal_to_sol(lit),
        Expression::Identifier(name) => name.clone(),
        Expression::BinaryOp(l, op, r) => {
            format!("({} {} {})", transpile_expr(l), binop_to_sol(op), transpile_expr(r))
        }
        Expression::UnaryOp(op, val) => {
            format!("{}{}", unop_to_sol(op), transpile_expr(val))
        }
        Expression::Caller => "uint256(uint160(msg.sender))".to_string(),
        Expression::MapIndex(map, key) => {
            format!("{}[{}]", map, transpile_expr(key))
        }
        Expression::MapMethod { map, method, args } => {
            let a: Vec<String> = args.iter().map(transpile_expr).collect();
            match method.as_str() {
                "get" => format!("{}[{}]", map, a.join(", ")),
                "contains" => format!("({}[{}] != address(0))", map, a.join(", ")),
                "len" => format!("/* {}.len() — no native Solidity equivalent */", map),
                _ => format!("{}.{}({})", map, method, a.join(", ")),
            }
        }
        Expression::SetMethod { set, method, args } => {
            let a: Vec<String> = args.iter().map(transpile_expr).collect();
            match method.as_str() {
                "contains" => format!("{}Map[{}]", set, a.join(", ")),
                "len" => format!("/* {}.len() — use counter */", set),
                _ => format!("{}.{}({})", set, method, a.join(", ")),
            }
        }
        Expression::Tuple(exprs) => {
            let items: Vec<String> = exprs.iter().map(transpile_expr).collect();
            format!("({})", items.join(", "))
        }
        Expression::Some(val) => format!("({})", transpile_expr(val)), // Solidity has no Option — unwrap directly
        Expression::None => "address(0)".to_string(), // Best-effort mapping
        Expression::Ok(val) => transpile_expr(val), // Unwrap Result to value
        Expression::Err(val) => format!("revert({})", transpile_expr(val)),
        Expression::FieldAccess { object, field } => {
            format!("{}.{}", transpile_expr(object), field)
        }
        Expression::TupleIndex { object, index } => {
            format!("{}.{}", transpile_expr(object), index) // Solidity tuple access
        }
        Expression::EnumAccess { enum_name, variant_name } => {
            format!("{}.{}", enum_name, variant_name)
        }
        Expression::StructLiteral { type_name, fields } => {
            let fs: Vec<String> = fields.iter()
                .map(|(n, v)| format!("{}: {}", n, transpile_expr(v))).collect();
            format!("{}({{{}}})", type_name, fs.join(", "))
        }
    }
}

fn ty_to_sol(ty: &Type) -> String {
    match ty {
        Type::Bool => "bool".into(),
        Type::UInt8 => "uint8".into(),
        Type::UInt16 => "uint16".into(),
        Type::UInt32 => "uint32".into(),
        Type::UInt64 => "uint64".into(),
        Type::UInt128 => "uint128".into(),
        Type::UInt256 => "uint256".into(),
        Type::Int8 => "int8".into(),
        Type::Int16 => "int16".into(),
        Type::Int32 => "int32".into(),
        Type::Int64 => "int64".into(),
        Type::Int128 => "int128".into(),
        Type::Int256 => "int256".into(),
        Type::Bytes => "bytes".into(),
        Type::Str => "string".into(),
        Type::Address => "address".into(),
        Type::Mapping(k, v) => format!("mapping({} => {})", ty_to_sol(k), ty_to_sol(v)),
        Type::Array(t) => format!("{}[]", ty_to_sol(t)),
        Type::Option(t) => ty_to_sol(t), // No Solidity Option — use the inner type + null check
        Type::Result(o, _) => ty_to_sol(o), // No Solidity Result — use the Ok type + revert on Err
        Type::Tuple(ts) => {
            let items: Vec<String> = ts.iter().map(ty_to_sol).collect();
            format!("({})", items.join(", "))
        }
        Type::Named(s) => s.clone(),
        Type::BytesN(n) => format!("bytes{}", n),
        Type::DilithiumPublicKey | Type::FalconPublicKey | Type::KyberPublicKey =>
            "bytes memory /* PQC pubkey — SXCP bridge */".into(),
        Type::DilithiumSignature | Type::FalconSignature =>
            "bytes memory /* PQC signature — SXCP bridge */".into(),
        Type::Asset(_) => "address /* asset — SXCP bridge */".into(),
        Type::Hash32 => "bytes32".into(),
        Type::Hash64 => "bytes64".into(),
        Type::UMAIdentity => "address /* UMA identity — SXCP bridge */".into(),
        Type::Height => "uint256 /* block height */".into(),
        Type::ModelId => "uint256 /* AI model ID */".into(),
    }
}

fn binop_to_sol(op: &BinaryOperator) -> &'static str {
    match op {
        BinaryOperator::Add => "+", BinaryOperator::Sub => "-",
        BinaryOperator::Mul => "*", BinaryOperator::Div => "/",
        BinaryOperator::Mod => "%", BinaryOperator::Eq => "==",
        BinaryOperator::Ne => "!=", BinaryOperator::Lt => "<",
        BinaryOperator::Le => "<=", BinaryOperator::Gt => ">",
        BinaryOperator::Ge => ">=", BinaryOperator::And => "&&",
        BinaryOperator::Or => "||",
    }
}

fn unop_to_sol(op: &UnaryOperator) -> &'static str {
    match op { UnaryOperator::Neg => "-", UnaryOperator::Not => "!" }
}

fn literal_to_sol(lit: &Literal) -> String {
    match lit {
        Literal::String(s) => format!("\"{}\"", s),
        Literal::Number(n) => n.to_string(),
        Literal::BigNumber(s) => s.clone(),
        Literal::Hex(bytes) => format!("hex\"{}\"", bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()),
        Literal::Bool(b) => b.to_string(),
    }
}
