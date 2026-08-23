// ── IR Decompiler ─────────────────────────────────────────────────────────────
//
// Reconstructs readable pseudo-SynQ source from a deserialized SIR1 IR module.
// NOT a perfect round-trip — SSA loses source-level structure (names, nesting).
// Output is "pseudo-SynQ": syntactically suggestive, for audit/inspection.
//
// Purpose: auditability, debugging, transparency — inspect SQB artifacts.

use std::fmt::Write;
use crate::ast::{BinaryOperator, UnaryOperator, Literal, Attribute, SetOpKind, Type as AstType};
use super::types::*;
use super::function::IrFunction;
use super::instructions::*;
use super::module::*;

/// Decompile an IR module into pseudo-SynQ source.
pub fn decompile(module: &IrModule) -> String {
    let mut out = String::new();
    writeln!(out, "// ═════════════════════════════════════════════════════════════════").unwrap();
    writeln!(out, "//  Decompiled from SIR1 IR (SynQ Intermediate Representation v1)").unwrap();
    writeln!(out, "//  Source: SQB binary artifact — PQC-resistant (ML-DSA-87 signed)").unwrap();
    writeln!(out, "//  Contract: {}", module.contract_name).unwrap();
    writeln!(out, "//").unwrap();
    writeln!(out, "//  This is decompiled pseudo-source generated from the SSA IR").unwrap();
    writeln!(out, "//  embedded in an SQB artifact. It is NOT the original source code.").unwrap();
    writeln!(out, "//  SSA value IDs (v0, v1, ...) map to single-assignment temporaries.").unwrap();
    writeln!(out, "//  Block labels (bb0:, bb1:, ...) map to CFG basic blocks.").unwrap();
    writeln!(out, "//  This output is for audit/inspection — it may not compile directly.").unwrap();
    writeln!(out, "// ═════════════════════════════════════════════════════════════════").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "pragma synq ^0.9;").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "contract {} {{", module.contract_name).unwrap();

    if !module.state_vars.is_empty() {
        writeln!(out, "  // ── State Variables (from STATE_LAYOUT) ──").unwrap();
        writeln!(out, "  state {{").unwrap();
        for (name, ty, addr) in &module.state_vars {
            writeln!(out, "    {}: {};  // slot {}", name, ir_type_to_synq(ty), addr).unwrap();
        }
        writeln!(out, "  }}").unwrap();
        writeln!(out).unwrap();
    }

    if !module.struct_defs.is_empty() {
        let mut sorted: Vec<_> = module.struct_defs.iter().collect();
        sorted.sort_by(|(a, _), (b, _)| a.cmp(b));
        writeln!(out, "  // ── Struct Definitions ──").unwrap();
        for (name, def) in sorted {
            writeln!(out, "  struct {} {{", name).unwrap();
            for field in &def.fields {
                writeln!(out, "    {}: {};", field.name, ast_type_to_synq(&field.ty)).unwrap();
            }
            writeln!(out, "  }}").unwrap();
            writeln!(out).unwrap();
        }
    }

    if !module.enum_defs.is_empty() {
        let mut sorted: Vec<_> = module.enum_defs.iter().collect();
        sorted.sort_by(|(a, _), (b, _)| a.cmp(b));
        writeln!(out, "  // ── Enum Definitions ──").unwrap();
        for (name, def) in sorted {
            writeln!(out, "  enum {} {{", name).unwrap();
            for variant in &def.variants {
                if variant.fields.is_empty() {
                    writeln!(out, "    {},", variant.name).unwrap();
                } else {
                    let fields: Vec<String> = variant.fields.iter()
                        .map(|p| format!("{}: {}", p.name, ast_type_to_synq(&p.ty))).collect();
                    writeln!(out, "    {}({}),", variant.name, fields.join(", ")).unwrap();
                }
            }
            writeln!(out, "  }}").unwrap();
            writeln!(out).unwrap();
        }
    }

    if !module.event_defs.is_empty() {
        writeln!(out, "  // ── Events ──").unwrap();
        for ev in &module.event_defs {
            let fields: Vec<String> = ev.params.iter()
                .map(|p| format!("{}: {}{}", p.name, ast_type_to_synq(&p.ty), if p.is_indexed { " [indexed]" } else { "" })).collect();
            writeln!(out, "  event {}({});", ev.name, fields.join(", ")).unwrap();
        }
        writeln!(out).unwrap();
    }

    if !module.extern_contracts.is_empty() {
        writeln!(out, "  // ── Extern Contracts ──").unwrap();
        for c in &module.extern_contracts {
            writeln!(out, "  extern contract {} {{ ... }}", c).unwrap();
        }
        writeln!(out).unwrap();
    }

    for (i, func) in module.functions.iter().enumerate() {
        if i > 0 || !module.state_vars.is_empty() || !module.struct_defs.is_empty() {
            writeln!(out).unwrap();
        }
        decompile_function(&mut out, func);
    }

    writeln!(out, "}}").unwrap();
    out
}

fn decompile_function(out: &mut String, func: &IrFunction) {
    let mut attrs = Vec::new();
    for attr in &func.attributes { attrs.push(format!("    {}", attr_to_synq(attr))); }
    if func.is_public && !func.attributes.iter().any(|a| matches!(a, Attribute::Public)) {
        attrs.push("    @public".to_string());
    }
    let params: Vec<String> = func.params.iter()
        .map(|(name, ty)| format!("{}: {}", name, ir_type_to_synq(ty))).collect();
    let return_ty = match &func.return_type {
        Some(ty) => format!(" -> {}", ir_type_to_synq(ty)),
        None => String::new(),
    };
    let caller_attr = if func.requires_caller { " as caller" } else { "" };
    for a in &attrs { writeln!(out, "{}", a).unwrap(); }
    writeln!(out, "  function {}({}){}{} {{", func.name, params.join(", "), return_ty, caller_attr).unwrap();
    if !func.requires_state.is_empty() { writeln!(out, "    // reads: {}", func.requires_state.join(", ")).unwrap(); }
    if !func.modifies.is_empty() { writeln!(out, "    // modifies: {}", func.modifies.join(", ")).unwrap(); }

    let vn = build_value_names(func);
    for (bi, block) in func.blocks.iter().enumerate() {
        if bi > 0 { writeln!(out).unwrap(); }
        let tag = if block.reachable { "" } else { " // unreachable" };
        writeln!(out, "    bb{}:{}", block.id, tag).unwrap();
        if !block.preds.is_empty() {
            writeln!(out, "      // preds: {}", block.preds.iter().map(|p| format!("bb{}", p)).collect::<Vec<_>>().join(", ")).unwrap();
        }
        for inst in &block.insts {
            writeln!(out, "      {}", decompile_instruction(inst, &vn)).unwrap();
        }
    }
    writeln!(out, "  }}").unwrap();
}

fn build_value_names(func: &IrFunction) -> Vec<String> {
    let max_vid = func.blocks.iter().flat_map(|b| b.insts.iter()).map(|i| i.value_id).max().unwrap_or(0);
    (0..=max_vid).map(|i| format!("v{}", i)).collect()
}

fn v(names: &[String], vid: ValueId) -> String {
    if (vid as usize) < names.len() { names[vid as usize].clone() } else { format!("v{}", vid) }
}

fn decompile_instruction(inst: &Instruction, names: &[String]) -> String {
    let r = if matches!(inst.result_type, IrType::Void) { String::new() } else { format!("{} = ", v(names, inst.value_id)) };
    match &inst.op {
        IrOp::Const(lit) => format!("{}{}", r, literal_to_synq(lit)),
        IrOp::BinOp(op, l, r2) => format!("{}{} {} {}", r, v(names, *l), binop_to_synq(op), v(names, *r2)),
        IrOp::UnaryOp(op, val) => format!("{}{}{}", r, unop_to_synq(op), v(names, *val)),
        IrOp::Load(n) => format!("{}load {}", r, n),
        IrOp::Store(n, val) => format!("store {} = {}", n, v(names, *val)),
        IrOp::Caller => format!("{}caller", r),
        IrOp::CallSender => format!("{}call_sender", r),
        IrOp::LoadAuthority => format!("{}authority_envelope", r),
        IrOp::AuthIdentity(val) => format!("{}uma_identity({})", r, v(names, *val)),
        IrOp::AuthRequire(val, s) => format!("{}auth_require({}, \"{}\")", r, v(names, *val), s),
        IrOp::Call(n, args) => format!("{}call {}({})", r, n, args.iter().map(|a| v(names, *a)).collect::<Vec<_>>().join(", ")),
        IrOp::ExternCall(c, f, args) => format!("{}extern_call {}.{}({})", r, c, f, args.iter().map(|a| v(names, *a)).collect::<Vec<_>>().join(", ")),
        IrOp::MapGet(n, key) => format!("{}map_get {}[{}]", r, n, v(names, *key)),
        IrOp::MapGetVal(m, key) => format!("{}map_get_val %{}[{}]", r, m, v(names, *key)),
        IrOp::MapSetVal(m, k, val) => format!("{}map_set_val %{}[%{}] = {}", r, m, k, v(names, *val)),
        IrOp::MapMethod(n, m, args) => format!("{}map_{}.{}({})", r, n, m, args.iter().map(|a| v(names, *a)).collect::<Vec<_>>().join(", ")),
        IrOp::SetMethod(n, m, args) => format!("{}set_{}.{}({})", r, n, m, args.iter().map(|a| v(names, *a)).collect::<Vec<_>>().join(", ")),
        IrOp::FieldAccess(o, idx) => format!("{}.field_{}", v(names, *o), idx),
        IrOp::EnumAccess(e, var) => format!("{}{}::{}", r, e, var),
        IrOp::StructLiteral(n, fields) => {
            let fs: Vec<String> = fields.iter().map(|(n, val)| format!("{}: {}", n, v(names, *val))).collect();
            format!("{}{} {{ {} }}", r, n, fs.join(", "))
        }
        IrOp::Tuple(vals) => format!("{}({})", r, vals.iter().map(|x| v(names, *x)).collect::<Vec<_>>().join(", ")),
        IrOp::TupleSet(t, idx, val) => format!("{}tuple_set {}[{}] = {}", r, v(names, *t), v(names, *idx), v(names, *val)),
        IrOp::TupleGet(t, idx) => format!("{}tuple_get {}[{}]", r, v(names, *t), v(names, *idx)),
        IrOp::Some(val) => format!("{}Some({})", r, v(names, *val)),
        IrOp::None => format!("{}None", r),
        IrOp::Ok(val) => format!("{}Ok({})", r, v(names, *val)),
        IrOp::Err(val) => format!("{}Err({})", r, v(names, *val)),
        IrOp::OptionUnwrap(val) => format!("{}{}.unwrap()", r, v(names, *val)),
        IrOp::ResultUnwrap(val) => format!("{}{}.unwrap()", r, v(names, *val)),
        IrOp::IsOk(val) => format!("{}{}.is_ok()", r, v(names, *val)),
        IrOp::IsSome(val) => format!("{}{}.is_some()", r, v(names, *val)),
        IrOp::AddrEncode(val) => format!("{}to_tsynq({})", r, v(names, *val)),
        IrOp::AddrDecode(val) => format!("{}from_tsynq({})", r, v(names, *val)),
        IrOp::ContractAddr(d, n, h) => format!("{}contract_addr({}, {}, {})", r, v(names, *d), v(names, *n), v(names, *h)),
        IrOp::StrLen(val) => format!("{}.len()", v(names, *val)),
        IrOp::StrConcat(a, b) => format!("{}{} + {}", r, v(names, *a), v(names, *b)),
        IrOp::StrEq(a, b) => format!("{}{} == {}", r, v(names, *a), v(names, *b)),
        IrOp::AegisCall(args) => format!("{}aegis_call({})", r, args.iter().map(|a| v(names, *a)).collect::<Vec<_>>().join(", ")),
        IrOp::AegisVerify(args) => format!("{}aegis_verify({})", r, args.iter().map(|a| v(names, *a)).collect::<Vec<_>>().join(", ")),
        IrOp::AegisDecaps(args) => format!("{}aegis_decaps({})", r, args.iter().map(|a| v(names, *a)).collect::<Vec<_>>().join(", ")),
        IrOp::AssetCreate(t, val) => format!("{}asset_create(\"{}\", {})", r, t, v(names, *val)),
        IrOp::AssetTransfer(a, o) => format!("{}asset_transfer({}, {})", r, v(names, *a), v(names, *o)),
        IrOp::AssetBurn(a) => format!("{}asset_burn({})", r, v(names, *a)),
        IrOp::AssetBalance(a) => format!("{}asset_balance({})", r, v(names, *a)),
        IrOp::AssetOwner(a) => format!("{}asset_owner({})", r, v(names, *a)),
        IrOp::FieldStore(o, f, val) => format!("{}.{} = {}", o, f, v(names, *val)),
        IrOp::MapSet(n, key, val) => format!("map_set {}[{}] = {}", n, v(names, *key), v(names, *val)),
        IrOp::SetOp(n, kind, val) => {
            let op = match kind { SetOpKind::Add => "add", SetOpKind::Remove => "remove" };
            format!("set_{} {} {}", op, n, v(names, *val))
        }
        IrOp::Emit(n, args) => format!("emit {}({})", n, args.iter().map(|a| v(names, *a)).collect::<Vec<_>>().join(", ")),
        IrOp::Require(val, msg) => format!("require({}, \"{}\")", v(names, *val), msg),
        IrOp::Revert(msg) => format!("revert \"{}\"", msg),
        IrOp::RevertNamed(e, var, args) => format!("revert {}::{}({})", e, var, args.iter().map(|a| v(names, *a)).collect::<Vec<_>>().join(", ")),
        IrOp::Print(val) => format!("print({})", v(names, *val)),
        IrOp::Phi(pairs) => {
            let ps: Vec<String> = pairs.iter().map(|(blk, val)| format!("bb{}: {}", blk, v(names, *val))).collect();
            format!("{}phi({})", r, ps.join(", "))
        }
        IrOp::AiVerifyProof(val) => format!("{}ai_verify_proof({})", r, v(names, *val)),
        IrOp::AiInfer(model, input) => format!("{}ai_infer({}, {})", r, v(names, *model), v(names, *input)),
        IrOp::Branch(c, t, e) => format!("if {} → bb{} else → bb{}", v(names, *c), t, e),
        IrOp::Jump(t) => format!("goto bb{}", t),
        IrOp::Return(None) => "return".to_string(),
        IrOp::Return(Some(val)) => format!("return {}", v(names, *val)),
    }
}

fn ir_type_to_synq(ty: &IrType) -> String {
    match ty {
        IrType::Bool => "bool".into(), IrType::I32 => "i32".into(), IrType::I64 => "i64".into(),
        IrType::U128 => "u128".into(), IrType::U256 => "u256".into(), IrType::Bytes => "bytes".into(),
        IrType::Str => "str".into(), IrType::Address => "address".into(),
        IrType::BytesN(n) => format!("bytes{}", n),
        IrType::Hash32 => "hash32".into(), IrType::Hash64 => "hash64".into(),
        IrType::Void => "()".into(),
        IrType::Authority => "authority".into(), IrType::UMAIdentity => "uma_identity".into(),
        IrType::ModelId => "model_id".into(), IrType::Height => "height".into(),
        IrType::EffectToken => "effect_token".into(),
        IrType::Option(t) => format!("Option<{}>", ir_type_to_synq(t)),
        IrType::Result(o, e) => format!("Result<{}, {}>", ir_type_to_synq(o), ir_type_to_synq(e)),
        IrType::Tuple(ts) => format!("({})", ts.iter().map(ir_type_to_synq).collect::<Vec<_>>().join(", ")),
        IrType::Map(k, v) => format!("Map<{}, {}>", ir_type_to_synq(k), ir_type_to_synq(v)),
        IrType::Set(t) => format!("Set<{}>", ir_type_to_synq(t)),
        IrType::Named(s) => s.clone(),
        IrType::Asset(t) => format!("Asset<{}>", ir_type_to_synq(t)),
    }
}

fn ast_type_to_synq(ty: &AstType) -> String {
    match ty {
        AstType::Bool => "bool".into(), AstType::UInt8 => "u8".into(), AstType::UInt16 => "u16".into(),
        AstType::UInt32 => "u32".into(), AstType::UInt64 => "u64".into(), AstType::UInt128 => "u128".into(),
        AstType::UInt256 => "u256".into(), AstType::Int8 => "i8".into(), AstType::Int16 => "i16".into(),
        AstType::Int32 => "i32".into(), AstType::Int64 => "i64".into(), AstType::Int128 => "i128".into(),
        AstType::Int256 => "i256".into(), AstType::Bytes => "bytes".into(), AstType::Str => "str".into(),
        AstType::Address => "address".into(),
        AstType::DilithiumPublicKey => "dilithium_pubkey".into(),
        AstType::FalconPublicKey => "falcon_pubkey".into(),
        AstType::KyberPublicKey => "kyber_pubkey".into(),
        AstType::DilithiumSignature => "dilithium_sig".into(),
        AstType::FalconSignature => "falcon_sig".into(),
        AstType::Option(t) => format!("Option<{}>", ast_type_to_synq(t)),
        AstType::Result(o, e) => format!("Result<{}, {}>", ast_type_to_synq(o), ast_type_to_synq(e)),
        AstType::Tuple(ts) => format!("({})", ts.iter().map(ast_type_to_synq).collect::<Vec<_>>().join(", ")),
        AstType::Mapping(k, v) => format!("Mapping<{}, {}>", ast_type_to_synq(k), ast_type_to_synq(v)),
        AstType::Array(t) => format!("[{}]", ast_type_to_synq(t)),
        AstType::Named(s) => s.clone(),
        AstType::BytesN(n) => format!("bytes{}", n),
        AstType::Asset(t) => format!("Asset<{}>", ast_type_to_synq(t)),
        AstType::Hash32 => "hash32".into(), AstType::Hash64 => "hash64".into(),
        AstType::UMAIdentity => "uma_identity".into(), AstType::Height => "height".into(),
        AstType::ModelId => "model_id".into(),
    }
}

fn binop_to_synq(op: &BinaryOperator) -> &'static str {
    match op { BinaryOperator::Add => "+", BinaryOperator::Sub => "-", BinaryOperator::Mul => "*",
    BinaryOperator::Div => "/", BinaryOperator::Mod => "%", BinaryOperator::Eq => "==",
    BinaryOperator::Ne => "!=", BinaryOperator::Lt => "<", BinaryOperator::Le => "<=",
    BinaryOperator::Gt => ">", BinaryOperator::Ge => ">=", BinaryOperator::And => "&&",
    BinaryOperator::Or => "||" }
}

fn unop_to_synq(op: &UnaryOperator) -> &'static str {
    match op { UnaryOperator::Neg => "-", UnaryOperator::Not => "!" }
}

fn literal_to_synq(lit: &Literal) -> String {
    match lit {
        Literal::String(s) => format!("{:?}", s),
        Literal::Number(n) => n.to_string(),
        Literal::BigNumber(s) => s.clone(),
        Literal::Hex(bytes) => format!("0x{}", bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()),
        Literal::Bool(b) => b.to_string(),
    }
}

fn attr_to_synq(attr: &Attribute) -> String {
    match attr {
        Attribute::Public => "@public".into(),
        Attribute::Authority(s) => format!("@authority(\"{}\")", s),
        Attribute::Effects(vs) => format!("@effects({})", vs.join(", ")),
        Attribute::Requires(e) => format!("@requires(\"{}\")", e),
        Attribute::Ensures(e) => format!("@ensures(\"{}\")", e),
        Attribute::Fails(n) => format!("@fails(\"{}\")", n),
        Attribute::Bounded(b) => format!("@bounded(\"{}\")", b),
        Attribute::Manifest => "@manifest".into(),
        Attribute::Ai => "@ai".into(),
        Attribute::Governance(s) => format!("@governance(\"{}\")", s),
    }
}
