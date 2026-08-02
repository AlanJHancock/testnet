// ── IR Binary Serialization ───────────────────────────────────────────────────
//
// Serializes the SSA IR module to a compact binary format for the SQB IR section.
// This replaces the text dump with a machine-readable, deterministic encoding
// that can be deserialized by debuggers, analyzers, and the AIVM layer.
//
// Format version: SIR1 (SynQ IR v1)
//
// Wire format:
//   Magic:   "SIR1" (4 bytes)
//   Version: u8 (1)
//
//   Module:
//     contract_name:    str (u32 LE len + UTF-8)
//     state_vars:       u32 LE count + [(str, type, u32 LE addr)]...
//     struct_defs:      u32 LE count + [(str, [(str, type)]...)]...
//     enum_defs:        u32 LE count + [(str, [(str, [(str, type)]...)]...)]...
//     event_defs:       u32 LE count + [(str, [(str, type, bool)]...)]...
//     extern_contracts: u32 LE count + [str]...
//     functions:        u32 LE count + [function]...
//
//   Function:
//     name:            str
//     params:           u32 LE count + [(str, type)]...
//     return_type:       u8 (0=none, 1=present) + type (if present)
//     is_public:        u8
//     requires_caller:  u8
//     attributes:        u32 LE count + [attribute]...
//     requires_state:   u32 LE count + [str]...
//     modifies:          u32 LE count + [str]...
//     effects:           u32 LE count + [effect_kind]...
//     host_profiles:     u32 LE count + [host_fn_profile]...
//     blocks:            u32 LE count + [block]...
//
//   Block:
//     id:               u32 LE
//     reachable:        u8
//     preds:             u32 LE count + [u32 LE]...
//     insts:             u32 LE count + [instruction]...
//
//   Instruction:
//     op:               ir_op
//     result_type:       type
//     value_id:          u32 LE
//     line:              u32 LE
//
// Note: dom_tree is NOT serialized — it's recomputed from the CFG on load.

use std::collections::HashMap;
use std::io::{self, Read, Write};

use crate::ast::{
    Literal, BinaryOperator, UnaryOperator, SetOpKind,
    Attribute, Type as AstType, StructDefinition, EnumDefinition,
    EventDefinition, Parameter, EnumVariant, EventParam,
};

use super::types::*;
use super::instructions::*;
use super::blocks::*;
use super::function::*;
use super::module::*;

// ── Constants ────────────────────────────────────────────────────────────────

pub const IR_MAGIC: &[u8; 4] = b"SIR1";
pub const IR_VERSION: u8 = 1;

// ── Error type ─────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum IrSerError {
    Io(io::Error),
    BadMagic,
    UnsupportedVersion(u8),
    InvalidTag(u8),
    Truncated(String),
    Utf8(std::string::FromUtf8Error),
}

impl std::fmt::Display for IrSerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IR ser: IO error: {}", e),
            Self::BadMagic => write!(f, "IR ser: bad magic (expected SIR1)"),
            Self::UnsupportedVersion(v) => write!(f, "IR ser: unsupported version {}", v),
            Self::InvalidTag(t) => write!(f, "IR ser: invalid tag 0x{:02x}", t),
            Self::Truncated(msg) => write!(f, "IR ser: truncated — {}", msg),
            Self::Utf8(e) => write!(f, "IR ser: UTF-8 error: {}", e),
        }
    }
}

impl std::error::Error for IrSerError {}

impl From<io::Error> for IrSerError {
    fn from(e: io::Error) -> Self { Self::Io(e) }
}
impl From<std::string::FromUtf8Error> for IrSerError {
    fn from(e: std::string::FromUtf8Error) -> Self { Self::Utf8(e) }
}

// ── Writer helpers ────────────────────────────────────────────────────────────

struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn new() -> Self { Self { buf: Vec::new() } }

    fn u8(&mut self, v: u8) { self.buf.push(v); }
    fn u32(&mut self, v: u32) { self.buf.extend_from_slice(&v.to_le_bytes()); }
    fn u128(&mut self, v: u128) { self.buf.extend_from_slice(&v.to_le_bytes()); }
    fn bool(&mut self, v: bool) { self.buf.push(if v { 1 } else { 0 }); }

    fn str(&mut self, s: &str) {
        let bytes = s.as_bytes();
        self.u32(bytes.len() as u32);
        self.buf.extend_from_slice(bytes);
    }

    fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.buf.extend_from_slice(b);
    }

    fn opt_str(&mut self, s: &Option<String>) {
        match s {
            None => self.u8(0),
            Some(s) => { self.u8(1); self.str(s); }
        }
    }

    fn opt_type(&mut self, t: &Option<IrType>) {
        match t {
            None => self.u8(0),
            Some(t) => { self.u8(1); self.type_(t); }
        }
    }

    fn vec_strs(&mut self, v: &[String]) {
        self.u32(v.len() as u32);
        for s in v { self.str(s); }
    }

    // ── Type serialization ──────────────────────────────────────────────────
    fn type_(&mut self, t: &IrType) {
        match t {
            IrType::Bool        => self.u8(0x01),
            IrType::I32         => self.u8(0x02),
            IrType::I64         => self.u8(0x03),
            IrType::U128        => self.u8(0x04),
            IrType::U256        => self.u8(0x05),
            IrType::Bytes       => self.u8(0x06),
            IrType::Str         => self.u8(0x07),
            IrType::Address     => self.u8(0x08),
            IrType::BytesN(n)   => { self.u8(0x09); self.u32(*n as u32); }
            IrType::Hash32      => self.u8(0x0A),
            IrType::Hash64      => self.u8(0x0B),
            IrType::Option(t)   => { self.u8(0x0C); self.type_(t); }
            IrType::Result(o, e)=> { self.u8(0x0D); self.type_(o); self.type_(e); }
            IrType::Tuple(ts)   => {
                self.u8(0x0E);
                self.u32(ts.len() as u32);
                for t in ts { self.type_(t); }
            }
            IrType::Map(k, v)   => { self.u8(0x0F); self.type_(k); self.type_(v); }
            IrType::Set(t)      => { self.u8(0x10); self.type_(t); }
            IrType::Named(s)    => { self.u8(0x11); self.str(s); }
            IrType::Asset(t)    => { self.u8(0x12); self.type_(t); }
            IrType::Authority   => self.u8(0x13),
            IrType::UMAIdentity  => self.u8(0x14),
            IrType::ModelId     => self.u8(0x15),
            IrType::Height      => self.u8(0x16),
            IrType::EffectToken => self.u8(0x17),
            IrType::Void        => self.u8(0x18),
        }
    }

    // ── Literal serialization ───────────────────────────────────────────────
    fn literal(&mut self, lit: &Literal) {
        match lit {
            Literal::String(s) => { self.u8(0x01); self.str(s); }
            Literal::Number(n) => { self.u8(0x02); self.u128(*n); }
            Literal::BigNumber(s) => { self.u8(0x03); self.str(s); }
            Literal::Hex(b) => { self.u8(0x04); self.bytes(b); }
            Literal::Bool(b) => { self.u8(0x05); self.bool(*b); }
        }
    }

    // ── BinaryOperator ──────────────────────────────────────────────────────
    fn binop(&mut self, op: &BinaryOperator) {
        let tag = match op {
            BinaryOperator::Add => 0x01, BinaryOperator::Sub => 0x02,
            BinaryOperator::Mul => 0x03, BinaryOperator::Div => 0x04,
            BinaryOperator::Mod => 0x05, BinaryOperator::Eq  => 0x06,
            BinaryOperator::Ne  => 0x07, BinaryOperator::Lt  => 0x08,
            BinaryOperator::Le  => 0x09, BinaryOperator::Gt  => 0x0A,
            BinaryOperator::Ge  => 0x0B, BinaryOperator::And => 0x0C,
            BinaryOperator::Or  => 0x0D,
        };
        self.u8(tag);
    }

    // ── UnaryOperator ──────────────────────────────────────────────────────
    fn unop(&mut self, op: &UnaryOperator) {
        let tag = match op {
            UnaryOperator::Neg => 0x01,
            UnaryOperator::Not => 0x02,
        };
        self.u8(tag);
    }

    // ── SetOpKind ────────────────────────────────────────────────────────────
    fn setop(&mut self, op: &SetOpKind) {
        let tag = match op {
            SetOpKind::Add    => 0x01,
            SetOpKind::Remove => 0x02,
        };
        self.u8(tag);
    }

    // ── Attribute ────────────────────────────────────────────────────────────
    fn attribute(&mut self, attr: &Attribute) {
        match attr {
            Attribute::Public => self.u8(0x01),
            Attribute::Authority(s) => { self.u8(0x02); self.str(s); }
            Attribute::Effects(v) => { self.u8(0x03); self.vec_strs(v); }
            Attribute::Requires(s) => { self.u8(0x04); self.str(s); }
            Attribute::Ensures(s) => { self.u8(0x05); self.str(s); }
            Attribute::Fails(s) => { self.u8(0x06); self.str(s); }
            Attribute::Bounded(s) => { self.u8(0x07); self.str(s); }
            Attribute::Manifest => self.u8(0x08),
            Attribute::Ai => self.u8(0x09),
            Attribute::Governance(s) => { self.u8(0x0A); self.str(s); }
        }
    }

    // ── EffectKind ───────────────────────────────────────────────────────────
    fn effect_kind(&mut self, e: &EffectKind) {
        match e {
            EffectKind::Read(s)     => { self.u8(0x01); self.str(s); }
            EffectKind::Write(s)    => { self.u8(0x02); self.str(s); }
            EffectKind::Emit(s)     => { self.u8(0x03); self.str(s); }
            EffectKind::FactConsume(s) => { self.u8(0x04); self.str(s); }
            EffectKind::ModelUse(s) => { self.u8(0x05); self.str(s); }
            EffectKind::ExternalCall(c, f) => { self.u8(0x06); self.str(c); self.str(f); }
        }
    }

    // ── HostFnProfile ─────────────────────────────────────────────────────────
    fn host_fn_profile(&mut self, p: &HostFnProfile) {
        let kind_tag = match p.kind {
            HostFnKind::ExternCall => 0x01,
            HostFnKind::PqcVerify  => 0x02,
            HostFnKind::PqcKem     => 0x03,
            HostFnKind::AegisCall  => 0x04,
            HostFnKind::AiInfer    => 0x05,
            HostFnKind::AiVerify   => 0x06,
        };
        self.u8(kind_tag);
        self.str(&p.callee);
        self.u32(p.arg_types.len() as u32);
        for t in &p.arg_types { self.type_(t); }
        self.type_(&p.return_type);
    }

    // ── IrOp serialization ─────────────────────────────────────────────────
    fn ir_op(&mut self, op: &IrOp) {
        match op {
            // Value-producing
            IrOp::Const(lit) => { self.u8(0x01); self.literal(lit); }
            IrOp::BinOp(op, a, b) => { self.u8(0x02); self.binop(op); self.u32(*a); self.u32(*b); }
            IrOp::UnaryOp(op, a) => { self.u8(0x03); self.unop(op); self.u32(*a); }
            IrOp::Load(name) => { self.u8(0x04); self.str(name); }
            IrOp::Store(name, v) => { self.u8(0x05); self.str(name); self.u32(*v); }
            IrOp::Caller => self.u8(0x06),
            IrOp::LoadAuthority => self.u8(0x07),
            IrOp::AuthIdentity(a) => { self.u8(0x08); self.u32(*a); }
            IrOp::AuthRequire(env, scope) => { self.u8(0x09); self.u32(*env); self.str(scope); }
            IrOp::Call(name, args) => {
                self.u8(0x0A); self.str(name);
                self.u32(args.len() as u32);
                for a in args { self.u32(*a); }
            }
            IrOp::ExternCall(contract, fname, args) => {
                self.u8(0x0B); self.str(contract); self.str(fname);
                self.u32(args.len() as u32);
                for a in args { self.u32(*a); }
            }
            IrOp::MapGet(name, key) => { self.u8(0x0C); self.str(name); self.u32(*key); }
            IrOp::MapSet(name, k, v) => { self.u8(0x0D); self.str(name); self.u32(*k); self.u32(*v); }
            IrOp::MapMethod(name, method, args) => {
                self.u8(0x0E); self.str(name); self.str(method);
                self.u32(args.len() as u32);
                for a in args { self.u32(*a); }
            }
            IrOp::SetMethod(name, method, args) => {
                self.u8(0x0F); self.str(name); self.str(method);
                self.u32(args.len() as u32);
                for a in args { self.u32(*a); }
            }
            IrOp::SetOp(name, op, v) => { self.u8(0x10); self.str(name); self.setop(op); self.u32(*v); }
            IrOp::FieldAccess(obj, idx) => { self.u8(0x11); self.u32(*obj); self.u32(*idx); }
            IrOp::FieldStore(struct_name, field_name, v) => { self.u8(0x12); self.str(struct_name); self.str(field_name); self.u32(*v); }
            IrOp::EnumAccess(enum_name, variant) => { self.u8(0x13); self.str(enum_name); self.str(variant); }
            IrOp::StructLiteral(name, fields) => {
                self.u8(0x14); self.str(name);
                self.u32(fields.len() as u32);
                for (fname, v) in fields { self.str(fname); self.u32(*v); }
            }
            IrOp::Tuple(vals) => {
                self.u8(0x15);
                self.u32(vals.len() as u32);
                for v in vals { self.u32(*v); }
            }
            IrOp::TupleGet(t, idx) => { self.u8(0x16); self.u32(*t); self.u32(*idx); }
            IrOp::TupleSet(t, idx, v) => { self.u8(0x17); self.u32(*t); self.u32(*idx); self.u32(*v); }
            IrOp::Phi(pairs) => {
                self.u8(0x18);
                self.u32(pairs.len() as u32);
                for (bid, vid) in pairs { self.u32(*bid); self.u32(*vid); }
            }
            IrOp::AddrEncode(v) => { self.u8(0x19); self.u32(*v); }
            IrOp::AddrDecode(v) => { self.u8(0x1A); self.u32(*v); }
            IrOp::ContractAddr(a, b, c) => { self.u8(0x1B); self.u32(*a); self.u32(*b); self.u32(*c); }
            IrOp::AssetCreate(tag, v) => { self.u8(0x1C); self.str(tag); self.u32(*v); }
            IrOp::AssetTransfer(a, b) => { self.u8(0x1D); self.u32(*a); self.u32(*b); }
            IrOp::AssetBurn(v) => { self.u8(0x1E); self.u32(*v); }
            IrOp::AssetBalance(v) => { self.u8(0x1F); self.u32(*v); }
            IrOp::AssetOwner(v) => { self.u8(0x20); self.u32(*v); }
            IrOp::AegisCall(args) => {
                self.u8(0x21);
                self.u32(args.len() as u32);
                for a in args { self.u32(*a); }
            }
            IrOp::AegisVerify(args) => {
                self.u8(0x22);
                self.u32(args.len() as u32);
                for a in args { self.u32(*a); }
            }
            IrOp::AegisDecaps(args) => {
                self.u8(0x23);
                self.u32(args.len() as u32);
                for a in args { self.u32(*a); }
            }
            IrOp::Emit(name, args) => {
                self.u8(0x24); self.str(name);
                self.u32(args.len() as u32);
                for a in args { self.u32(*a); }
            }
            IrOp::Print(v) => { self.u8(0x25); self.u32(*v); }
            IrOp::Require(cond, msg) => { self.u8(0x26); self.u32(*cond); self.str(msg); }
            IrOp::Revert(msg) => { self.u8(0x27); self.str(msg); }
            IrOp::RevertNamed(enum_name, variant, args) => {
                self.u8(0x28); self.str(enum_name); self.str(variant);
                self.u32(args.len() as u32);
                for a in args { self.u32(*a); }
            }
            IrOp::Return(Some(v)) => { self.u8(0x29); self.u8(1); self.u32(*v); }
            IrOp::Return(None) => { self.u8(0x29); self.u8(0); }
            IrOp::Branch(cond, t, f) => { self.u8(0x2A); self.u32(*cond); self.u32(*t); self.u32(*f); }
            IrOp::Jump(target) => { self.u8(0x2B); self.u32(*target); }
            IrOp::StrLen(v) => { self.u8(0x2C); self.u32(*v); }
            IrOp::StrConcat(a, b) => { self.u8(0x2D); self.u32(*a); self.u32(*b); }
            IrOp::StrEq(a, b) => { self.u8(0x2E); self.u32(*a); self.u32(*b); }
            IrOp::None => self.u8(0x2F),
            IrOp::Some(v) => { self.u8(0x30); self.u32(*v); }
            IrOp::Ok(v) => { self.u8(0x31); self.u32(*v); }
            IrOp::Err(v) => { self.u8(0x32); self.u32(*v); }
            IrOp::OptionUnwrap(v) => { self.u8(0x33); self.u32(*v); }
            IrOp::ResultUnwrap(v) => { self.u8(0x34); self.u32(*v); }
            IrOp::IsOk(v) => { self.u8(0x35); self.u32(*v); }
            IrOp::IsSome(v) => { self.u8(0x36); self.u32(*v); }
            IrOp::AiInfer(model, input) => { self.u8(0x37); self.u32(*model); self.u32(*input); }
            IrOp::AiVerifyProof(receipt) => { self.u8(0x38); self.u32(*receipt); }
        }
    }

    // ── Instruction ─────────────────────────────────────────────────────────
    fn instruction(&mut self, inst: &Instruction) {
        self.ir_op(&inst.op);
        self.type_(&inst.result_type);
        self.u32(inst.value_id);
        self.u32(inst.line);
    }

    // ── BasicBlock ──────────────────────────────────────────────────────────
    fn block(&mut self, b: &BasicBlock) {
        self.u32(b.id);
        self.bool(b.reachable);
        self.u32(b.preds.len() as u32);
        for p in &b.preds { self.u32(*p); }
        self.u32(b.insts.len() as u32);
        for inst in &b.insts { self.instruction(inst); }
    }

    // ── Function ────────────────────────────────────────────────────────────
    fn function(&mut self, f: &IrFunction) {
        self.str(&f.name);
        // Params
        self.u32(f.params.len() as u32);
        for (name, ty) in &f.params { self.str(name); self.type_(ty); }
        // Return type
        self.opt_type(&f.return_type);
        // Flags
        self.bool(f.is_public);
        self.bool(f.requires_caller);
        // Attributes
        self.u32(f.attributes.len() as u32);
        for a in &f.attributes { self.attribute(a); }
        // Requires_state / modifies
        self.vec_strs(&f.requires_state);
        self.vec_strs(&f.modifies);
        // Effects
        self.u32(f.collected_effects.len() as u32);
        for e in &f.collected_effects { self.effect_kind(e); }
        // Host profiles
        self.u32(f.host_profiles.len() as u32);
        for p in &f.host_profiles { self.host_fn_profile(p); }
        // Blocks
        self.u32(f.blocks.len() as u32);
        for b in &f.blocks { self.block(b); }
    }

    // ── AST types (for struct/enum/event defs) ──────────────────────────────
    fn ast_type(&mut self, t: &AstType) {
        match t {
            AstType::UInt8   => self.u8(0x01), AstType::UInt16  => self.u8(0x02),
            AstType::UInt32  => self.u8(0x03), AstType::UInt64  => self.u8(0x04),
            AstType::UInt128 => self.u8(0x05), AstType::UInt256 => self.u8(0x06),
            AstType::Int8    => self.u8(0x07), AstType::Int16   => self.u8(0x08),
            AstType::Int32   => self.u8(0x09), AstType::Int64   => self.u8(0x0A),
            AstType::Int128  => self.u8(0x0B), AstType::Int256  => self.u8(0x0C),
            AstType::Bool    => self.u8(0x0D), AstType::Bytes   => self.u8(0x0E),
            AstType::Address => self.u8(0x0F), AstType::Str     => self.u8(0x10),
            AstType::DilithiumPublicKey => self.u8(0x11),
            AstType::FalconPublicKey => self.u8(0x12),
            AstType::KyberPublicKey => self.u8(0x13),
            AstType::DilithiumSignature => self.u8(0x14),
            AstType::FalconSignature => self.u8(0x15),
            AstType::BytesN(n) => { self.u8(0x16); self.u32(*n as u32); }
            AstType::Hash32  => self.u8(0x17), AstType::Hash64 => self.u8(0x18),
            AstType::UMAIdentity => self.u8(0x19), AstType::ModelId => self.u8(0x1A),
            AstType::Height  => self.u8(0x1B),
            AstType::Option(t) => { self.u8(0x1C); self.ast_type(t); }
            AstType::Result(o, e) => { self.u8(0x1D); self.ast_type(o); self.ast_type(e); }
            AstType::Tuple(ts) => {
                self.u8(0x1E);
                self.u32(ts.len() as u32);
                for t in ts { self.ast_type(t); }
            }
            AstType::Mapping(k, v) => { self.u8(0x1F); self.ast_type(k); self.ast_type(v); }
            AstType::Array(t) => { self.u8(0x20); self.ast_type(t); }
            AstType::Named(s) => { self.u8(0x21); self.str(s); }
            AstType::Asset(t) => { self.u8(0x22); self.ast_type(t); }
        }
    }

    fn parameter(&mut self, p: &Parameter) {
        self.str(&p.name);
        self.ast_type(&p.ty);
        self.bool(p.is_indexed);
    }

    fn struct_def(&mut self, s: &StructDefinition) {
        self.str(&s.name);
        self.u32(s.fields.len() as u32);
        for f in &s.fields { self.parameter(f); }
    }

    fn enum_variant(&mut self, v: &EnumVariant) {
        self.str(&v.name);
        self.u32(v.fields.len() as u32);
        for f in &v.fields { self.parameter(f); }
    }

    fn enum_def(&mut self, e: &EnumDefinition) {
        self.str(&e.name);
        self.u32(e.variants.len() as u32);
        for v in &e.variants { self.enum_variant(v); }
    }

    fn event_param(&mut self, p: &EventParam) {
        self.str(&p.name);
        self.ast_type(&p.ty);
        self.bool(p.is_indexed);
    }

    fn event_def(&mut self, e: &EventDefinition) {
        self.str(&e.name);
        self.u32(e.params.len() as u32);
        for p in &e.params { self.event_param(p); }
    }

    // ── Module ────────────────────────────────────────────────────────────────
    fn module(&mut self, m: &IrModule) {
        // Header
        self.buf.extend_from_slice(IR_MAGIC);
        self.u8(IR_VERSION);

        // Contract name
        self.str(&m.contract_name);

        // State vars (sorted for determinism)
        let mut state_vars = m.state_vars.clone();
        state_vars.sort_by(|a, b| a.0.cmp(&b.0));
        self.u32(state_vars.len() as u32);
        for (name, ty, addr) in &state_vars {
            self.str(name);
            self.type_(ty);
            self.u32(*addr);
        }

        // Struct defs (sorted by name)
        let mut structs: Vec<_> = m.struct_defs.iter().collect();
        structs.sort_by(|a, b| a.0.cmp(&b.0));
        self.u32(structs.len() as u32);
        for (_, s) in &structs { self.struct_def(s); }

        // Enum defs (sorted by name)
        let mut enums: Vec<_> = m.enum_defs.iter().collect();
        enums.sort_by(|a, b| a.0.cmp(&b.0));
        self.u32(enums.len() as u32);
        for (_, e) in &enums { self.enum_def(e); }

        // Event defs
        self.u32(m.event_defs.len() as u32);
        for e in &m.event_defs { self.event_def(e); }

        // Extern contracts
        self.vec_strs(&m.extern_contracts);

        // Functions
        self.u32(m.functions.len() as u32);
        for f in &m.functions { self.function(f); }
    }
}

// ── Reader helpers ────────────────────────────────────────────────────────────

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self { Self { buf, pos: 0 } }

    fn remaining(&self) -> usize { self.buf.len() - self.pos }

    fn u8(&mut self) -> Result<u8, IrSerError> {
        if self.pos >= self.buf.len() { return Err(IrSerError::Truncated("u8".into())); }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn u32(&mut self) -> Result<u32, IrSerError> {
        if self.pos + 4 > self.buf.len() { return Err(IrSerError::Truncated("u32".into())); }
        let v = u32::from_le_bytes([
            self.buf[self.pos], self.buf[self.pos+1],
            self.buf[self.pos+2], self.buf[self.pos+3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn u128(&mut self) -> Result<u128, IrSerError> {
        if self.pos + 16 > self.buf.len() { return Err(IrSerError::Truncated("u128".into())); }
        let bytes: [u8; 16] = self.buf[self.pos..self.pos+16].try_into().unwrap();
        self.pos += 16;
        Ok(u128::from_le_bytes(bytes))
    }

    fn bool(&mut self) -> Result<bool, IrSerError> { Ok(self.u8()? != 0) }

    fn str(&mut self) -> Result<String, IrSerError> {
        let len = self.u32()? as usize;
        if self.pos + len > self.buf.len() { return Err(IrSerError::Truncated("str".into())); }
        let s = String::from_utf8(self.buf[self.pos..self.pos+len].to_vec())?;
        self.pos += len;
        Ok(s)
    }

    fn bytes(&mut self) -> Result<Vec<u8>, IrSerError> {
        let len = self.u32()? as usize;
        if self.pos + len > self.buf.len() { return Err(IrSerError::Truncated("bytes".into())); }
        let v = self.buf[self.pos..self.pos+len].to_vec();
        self.pos += len;
        Ok(v)
    }

    fn opt_type(&mut self) -> Result<Option<IrType>, IrSerError> {
        let tag = self.u8()?;
        if tag == 0 { Ok(None) }
        else { Ok(Some(self.type_()?)) }
    }

    fn vec_strs(&mut self) -> Result<Vec<String>, IrSerError> {
        let count = self.u32()? as usize;
        let mut v = Vec::with_capacity(count);
        for _ in 0..count { v.push(self.str()?); }
        Ok(v)
    }

    fn type_(&mut self) -> Result<IrType, IrSerError> {
        let tag = self.u8()?;
        match tag {
            0x01 => Ok(IrType::Bool),
            0x02 => Ok(IrType::I32),
            0x03 => Ok(IrType::I64),
            0x04 => Ok(IrType::U128),
            0x05 => Ok(IrType::U256),
            0x06 => Ok(IrType::Bytes),
            0x07 => Ok(IrType::Str),
            0x08 => Ok(IrType::Address),
            0x09 => { let n = self.u32()? as usize; Ok(IrType::BytesN(n)) }
            0x0A => Ok(IrType::Hash32),
            0x0B => Ok(IrType::Hash64),
            0x0C => { let t = self.type_()?; Ok(IrType::Option(Box::new(t))) }
            0x0D => { let o = self.type_()?; let e = self.type_()?; Ok(IrType::Result(Box::new(o), Box::new(e))) }
            0x0E => {
                let count = self.u32()? as usize;
                let mut ts = Vec::with_capacity(count);
                for _ in 0..count { ts.push(self.type_()?); }
                Ok(IrType::Tuple(ts))
            }
            0x0F => { let k = self.type_()?; let v = self.type_()?; Ok(IrType::Map(Box::new(k), Box::new(v))) }
            0x10 => { let t = self.type_()?; Ok(IrType::Set(Box::new(t))) }
            0x11 => { let s = self.str()?; Ok(IrType::Named(s)) }
            0x12 => { let t = self.type_()?; Ok(IrType::Asset(Box::new(t))) }
            0x13 => Ok(IrType::Authority),
            0x14 => Ok(IrType::UMAIdentity),
            0x15 => Ok(IrType::ModelId),
            0x16 => Ok(IrType::Height),
            0x17 => Ok(IrType::EffectToken),
            0x18 => Ok(IrType::Void),
            _ => Err(IrSerError::InvalidTag(tag)),
        }
    }

    fn literal(&mut self) -> Result<Literal, IrSerError> {
        let tag = self.u8()?;
        match tag {
            0x01 => Ok(Literal::String(self.str()?)),
            0x02 => Ok(Literal::Number(self.u128()?)),
            0x03 => Ok(Literal::BigNumber(self.str()?)),
            0x04 => Ok(Literal::Hex(self.bytes()?)),
            0x05 => Ok(Literal::Bool(self.bool()?)),
            _ => Err(IrSerError::InvalidTag(tag)),
        }
    }

    fn binop(&mut self) -> Result<BinaryOperator, IrSerError> {
        let tag = self.u8()?;
        match tag {
            0x01 => Ok(BinaryOperator::Add), 0x02 => Ok(BinaryOperator::Sub),
            0x03 => Ok(BinaryOperator::Mul), 0x04 => Ok(BinaryOperator::Div),
            0x05 => Ok(BinaryOperator::Mod),  0x06 => Ok(BinaryOperator::Eq),
            0x07 => Ok(BinaryOperator::Ne),   0x08 => Ok(BinaryOperator::Lt),
            0x09 => Ok(BinaryOperator::Le),   0x0A => Ok(BinaryOperator::Gt),
            0x0B => Ok(BinaryOperator::Ge),   0x0C => Ok(BinaryOperator::And),
            0x0D => Ok(BinaryOperator::Or),
            _ => Err(IrSerError::InvalidTag(tag)),
        }
    }

    fn unop(&mut self) -> Result<UnaryOperator, IrSerError> {
        let tag = self.u8()?;
        match tag {
            0x01 => Ok(UnaryOperator::Neg),
            0x02 => Ok(UnaryOperator::Not),
            _ => Err(IrSerError::InvalidTag(tag)),
        }
    }

    fn setop(&mut self) -> Result<SetOpKind, IrSerError> {
        let tag = self.u8()?;
        match tag {
            0x01 => Ok(SetOpKind::Add),
            0x02 => Ok(SetOpKind::Remove),
            _ => Err(IrSerError::InvalidTag(tag)),
        }
    }

    fn attribute(&mut self) -> Result<Attribute, IrSerError> {
        let tag = self.u8()?;
        match tag {
            0x01 => Ok(Attribute::Public),
            0x02 => Ok(Attribute::Authority(self.str()?)),
            0x03 => Ok(Attribute::Effects(self.vec_strs()?)),
            0x04 => Ok(Attribute::Requires(self.str()?)),
            0x05 => Ok(Attribute::Ensures(self.str()?)),
            0x06 => Ok(Attribute::Fails(self.str()?)),
            0x07 => Ok(Attribute::Bounded(self.str()?)),
            0x08 => Ok(Attribute::Manifest),
            0x09 => Ok(Attribute::Ai),
            0x0A => Ok(Attribute::Governance(self.str()?)),
            _ => Err(IrSerError::InvalidTag(tag)),
        }
    }

    fn effect_kind(&mut self) -> Result<EffectKind, IrSerError> {
        let tag = self.u8()?;
        match tag {
            0x01 => Ok(EffectKind::Read(self.str()?)),
            0x02 => Ok(EffectKind::Write(self.str()?)),
            0x03 => Ok(EffectKind::Emit(self.str()?)),
            0x04 => Ok(EffectKind::FactConsume(self.str()?)),
            0x05 => Ok(EffectKind::ModelUse(self.str()?)),
            0x06 => { let c = self.str()?; let f = self.str()?; Ok(EffectKind::ExternalCall(c, f)) }
            _ => Err(IrSerError::InvalidTag(tag)),
        }
    }

    fn host_fn_profile(&mut self) -> Result<HostFnProfile, IrSerError> {
        let kind_tag = self.u8()?;
        let kind = match kind_tag {
            0x01 => HostFnKind::ExternCall, 0x02 => HostFnKind::PqcVerify,
            0x03 => HostFnKind::PqcKem,     0x04 => HostFnKind::AegisCall,
            0x05 => HostFnKind::AiInfer,    0x06 => HostFnKind::AiVerify,
            _ => return Err(IrSerError::InvalidTag(kind_tag)),
        };
        let callee = self.str()?;
        let arg_count = self.u32()? as usize;
        let mut arg_types = Vec::with_capacity(arg_count);
        for _ in 0..arg_count { arg_types.push(self.type_()?); }
        let return_type = self.type_()?;
        Ok(HostFnProfile { kind, callee, arg_types, return_type })
    }

    fn ir_op(&mut self) -> Result<IrOp, IrSerError> {
        let tag = self.u8()?;
        match tag {
            0x01 => Ok(IrOp::Const(self.literal()?)),
            0x02 => { let op = self.binop()?; let a = self.u32()?; let b = self.u32()?; Ok(IrOp::BinOp(op, a, b)) }
            0x03 => { let op = self.unop()?; let a = self.u32()?; Ok(IrOp::UnaryOp(op, a)) }
            0x04 => Ok(IrOp::Load(self.str()?)),
            0x05 => { let name = self.str()?; let v = self.u32()?; Ok(IrOp::Store(name, v)) }
            0x06 => Ok(IrOp::Caller),
            0x07 => Ok(IrOp::LoadAuthority),
            0x08 => { let a = self.u32()?; Ok(IrOp::AuthIdentity(a)) }
            0x09 => { let env = self.u32()?; let scope = self.str()?; Ok(IrOp::AuthRequire(env, scope)) }
            0x0A => {
                let name = self.str()?;
                let count = self.u32()? as usize;
                let mut args = Vec::with_capacity(count);
                for _ in 0..count { args.push(self.u32()?); }
                Ok(IrOp::Call(name, args))
            }
            0x0B => {
                let contract = self.str()?; let fname = self.str()?;
                let count = self.u32()? as usize;
                let mut args = Vec::with_capacity(count);
                for _ in 0..count { args.push(self.u32()?); }
                Ok(IrOp::ExternCall(contract, fname, args))
            }
            0x0C => { let name = self.str()?; let key = self.u32()?; Ok(IrOp::MapGet(name, key)) }
            0x0D => { let name = self.str()?; let k = self.u32()?; let v = self.u32()?; Ok(IrOp::MapSet(name, k, v)) }
            0x0E => {
                let name = self.str()?; let method = self.str()?;
                let count = self.u32()? as usize;
                let mut args = Vec::with_capacity(count);
                for _ in 0..count { args.push(self.u32()?); }
                Ok(IrOp::MapMethod(name, method, args))
            }
            0x0F => {
                let name = self.str()?; let method = self.str()?;
                let count = self.u32()? as usize;
                let mut args = Vec::with_capacity(count);
                for _ in 0..count { args.push(self.u32()?); }
                Ok(IrOp::SetMethod(name, method, args))
            }
            0x10 => { let name = self.str()?; let op = self.setop()?; let v = self.u32()?; Ok(IrOp::SetOp(name, op, v)) }
            0x11 => { let obj = self.u32()?; let idx = self.u32()?; Ok(IrOp::FieldAccess(obj, idx)) }
            0x12 => { let struct_name = self.str()?; let field_name = self.str()?; let v = self.u32()?; Ok(IrOp::FieldStore(struct_name, field_name, v)) }
            0x13 => { let e = self.str()?; let v = self.str()?; Ok(IrOp::EnumAccess(e, v)) }
            0x14 => {
                let name = self.str()?;
                let count = self.u32()? as usize;
                let mut fields = Vec::with_capacity(count);
                for _ in 0..count { let fname = self.str()?; let v = self.u32()?; fields.push((fname, v)); }
                Ok(IrOp::StructLiteral(name, fields))
            }
            0x15 => {
                let count = self.u32()? as usize;
                let mut vals = Vec::with_capacity(count);
                for _ in 0..count { vals.push(self.u32()?); }
                Ok(IrOp::Tuple(vals))
            }
            0x16 => { let t = self.u32()?; let idx = self.u32()?; Ok(IrOp::TupleGet(t, idx)) }
            0x17 => { let t = self.u32()?; let idx = self.u32()?; let v = self.u32()?; Ok(IrOp::TupleSet(t, idx, v)) }
            0x18 => {
                let count = self.u32()? as usize;
                let mut pairs = Vec::with_capacity(count);
                for _ in 0..count { let bid = self.u32()?; let vid = self.u32()?; pairs.push((bid, vid)); }
                Ok(IrOp::Phi(pairs))
            }
            0x19 => { let v = self.u32()?; Ok(IrOp::AddrEncode(v)) }
            0x1A => { let v = self.u32()?; Ok(IrOp::AddrDecode(v)) }
            0x1B => { let a = self.u32()?; let b = self.u32()?; let c = self.u32()?; Ok(IrOp::ContractAddr(a, b, c)) }
            0x1C => { let tag = self.str()?; let v = self.u32()?; Ok(IrOp::AssetCreate(tag, v)) }
            0x1D => { let a = self.u32()?; let b = self.u32()?; Ok(IrOp::AssetTransfer(a, b)) }
            0x1E => { let v = self.u32()?; Ok(IrOp::AssetBurn(v)) }
            0x1F => { let v = self.u32()?; Ok(IrOp::AssetBalance(v)) }
            0x20 => { let v = self.u32()?; Ok(IrOp::AssetOwner(v)) }
            0x21 => {
                let count = self.u32()? as usize;
                let mut args = Vec::with_capacity(count);
                for _ in 0..count { args.push(self.u32()?); }
                Ok(IrOp::AegisCall(args))
            }
            0x22 => {
                let count = self.u32()? as usize;
                let mut args = Vec::with_capacity(count);
                for _ in 0..count { args.push(self.u32()?); }
                Ok(IrOp::AegisVerify(args))
            }
            0x23 => {
                let count = self.u32()? as usize;
                let mut args = Vec::with_capacity(count);
                for _ in 0..count { args.push(self.u32()?); }
                Ok(IrOp::AegisDecaps(args))
            }
            0x24 => {
                let name = self.str()?;
                let count = self.u32()? as usize;
                let mut args = Vec::with_capacity(count);
                for _ in 0..count { args.push(self.u32()?); }
                Ok(IrOp::Emit(name, args))
            }
            0x25 => { let v = self.u32()?; Ok(IrOp::Print(v)) }
            0x26 => { let cond = self.u32()?; let msg = self.str()?; Ok(IrOp::Require(cond, msg)) }
            0x27 => { let msg = self.str()?; Ok(IrOp::Revert(msg)) }
            0x28 => {
                let enum_name = self.str()?; let variant = self.str()?;
                let count = self.u32()? as usize;
                let mut args = Vec::with_capacity(count);
                for _ in 0..count { args.push(self.u32()?); }
                Ok(IrOp::RevertNamed(enum_name, variant, args))
            }
            0x29 => {
                let has_val = self.u8()?;
                if has_val != 0 { let v = self.u32()?; Ok(IrOp::Return(Some(v))) }
                else { Ok(IrOp::Return(None)) }
            }
            0x2A => { let cond = self.u32()?; let t = self.u32()?; let f = self.u32()?; Ok(IrOp::Branch(cond, t, f)) }
            0x2B => { let target = self.u32()?; Ok(IrOp::Jump(target)) }
            0x2C => { let v = self.u32()?; Ok(IrOp::StrLen(v)) }
            0x2D => { let a = self.u32()?; let b = self.u32()?; Ok(IrOp::StrConcat(a, b)) }
            0x2E => { let a = self.u32()?; let b = self.u32()?; Ok(IrOp::StrEq(a, b)) }
            0x2F => Ok(IrOp::None),
            0x30 => { let v = self.u32()?; Ok(IrOp::Some(v)) }
            0x31 => { let v = self.u32()?; Ok(IrOp::Ok(v)) }
            0x32 => { let v = self.u32()?; Ok(IrOp::Err(v)) }
            0x33 => { let v = self.u32()?; Ok(IrOp::OptionUnwrap(v)) }
            0x34 => { let v = self.u32()?; Ok(IrOp::ResultUnwrap(v)) }
            0x35 => { let v = self.u32()?; Ok(IrOp::IsOk(v)) }
            0x36 => { let v = self.u32()?; Ok(IrOp::IsSome(v)) }
            0x37 => { let model = self.u32()?; let input = self.u32()?; Ok(IrOp::AiInfer(model, input)) }
            0x38 => { let receipt = self.u32()?; Ok(IrOp::AiVerifyProof(receipt)) }
            _ => Err(IrSerError::InvalidTag(tag)),
        }
    }

    fn instruction(&mut self) -> Result<Instruction, IrSerError> {
        let op = self.ir_op()?;
        let result_type = self.type_()?;
        let value_id = self.u32()?;
        let line = self.u32()?;
        Ok(Instruction { op, result_type, value_id, line })
    }

    fn block(&mut self) -> Result<BasicBlock, IrSerError> {
        let id = self.u32()?;
        let reachable = self.bool()?;
        let pred_count = self.u32()? as usize;
        let mut preds = Vec::with_capacity(pred_count);
        for _ in 0..pred_count { preds.push(self.u32()?); }
        let inst_count = self.u32()? as usize;
        let mut insts = Vec::with_capacity(inst_count);
        for _ in 0..inst_count { insts.push(self.instruction()?); }
        Ok(BasicBlock { id, insts, preds, reachable })
    }

    fn function(&mut self) -> Result<IrFunction, IrSerError> {
        let name = self.str()?;
        let param_count = self.u32()? as usize;
        let mut params = Vec::with_capacity(param_count);
        for _ in 0..param_count { let n = self.str()?; let t = self.type_()?; params.push((n, t)); }
        let return_type = self.opt_type()?;
        let is_public = self.bool()?;
        let requires_caller = self.bool()?;
        let attr_count = self.u32()? as usize;
        let mut attributes = Vec::with_capacity(attr_count);
        for _ in 0..attr_count { attributes.push(self.attribute()?); }
        let requires_state = self.vec_strs()?;
        let modifies = self.vec_strs()?;
        let effect_count = self.u32()? as usize;
        let mut collected_effects = Vec::with_capacity(effect_count);
        for _ in 0..effect_count { collected_effects.push(self.effect_kind()?); }
        let profile_count = self.u32()? as usize;
        let mut host_profiles = Vec::with_capacity(profile_count);
        for _ in 0..profile_count { host_profiles.push(self.host_fn_profile()?); }
        let block_count = self.u32()? as usize;
        let mut blocks = Vec::with_capacity(block_count);
        for _ in 0..block_count { blocks.push(self.block()?); }

        let entry = blocks.first().map(|b| b.id).unwrap_or(0);
        let next_block = blocks.last().map(|b| b.id + 1).unwrap_or(1);
        let next_value = blocks.iter()
            .flat_map(|b| b.insts.iter().map(|i| i.value_id + 1))
            .max().unwrap_or(0);

        Ok(IrFunction {
            name, params, return_type, blocks, entry,
            requires_caller, attributes, requires_state, modifies, is_public,
            next_block, next_value,
            collected_effects, host_profiles,
            dom_tree: None, // recomputed on demand
        })
    }

    // ── AST type deserialization ──────────────────────────────────────────────
    fn ast_type(&mut self) -> Result<AstType, IrSerError> {
        let tag = self.u8()?;
        match tag {
            0x01 => Ok(AstType::UInt8),   0x02 => Ok(AstType::UInt16),
            0x03 => Ok(AstType::UInt32),  0x04 => Ok(AstType::UInt64),
            0x05 => Ok(AstType::UInt128), 0x06 => Ok(AstType::UInt256),
            0x07 => Ok(AstType::Int8),    0x08 => Ok(AstType::Int16),
            0x09 => Ok(AstType::Int32),   0x0A => Ok(AstType::Int64),
            0x0B => Ok(AstType::Int128),   0x0C => Ok(AstType::Int256),
            0x0D => Ok(AstType::Bool),    0x0E => Ok(AstType::Bytes),
            0x0F => Ok(AstType::Address), 0x10 => Ok(AstType::Str),
            0x11 => Ok(AstType::DilithiumPublicKey),
            0x12 => Ok(AstType::FalconPublicKey),
            0x13 => Ok(AstType::KyberPublicKey),
            0x14 => Ok(AstType::DilithiumSignature),
            0x15 => Ok(AstType::FalconSignature),
            0x16 => { let n = self.u32()? as usize; Ok(AstType::BytesN(n)) }
            0x17 => Ok(AstType::Hash32), 0x18 => Ok(AstType::Hash64),
            0x19 => Ok(AstType::UMAIdentity), 0x1A => Ok(AstType::ModelId),
            0x1B => Ok(AstType::Height),
            0x1C => { let t = self.ast_type()?; Ok(AstType::Option(Box::new(t))) }
            0x1D => { let o = self.ast_type()?; let e = self.ast_type()?; Ok(AstType::Result(Box::new(o), Box::new(e))) }
            0x1E => {
                let count = self.u32()? as usize;
                let mut ts = Vec::with_capacity(count);
                for _ in 0..count { ts.push(self.ast_type()?); }
                Ok(AstType::Tuple(ts))
            }
            0x1F => { let k = self.ast_type()?; let v = self.ast_type()?; Ok(AstType::Mapping(Box::new(k), Box::new(v))) }
            0x20 => { let t = self.ast_type()?; Ok(AstType::Array(Box::new(t))) }
            0x21 => { let s = self.str()?; Ok(AstType::Named(s)) }
            0x22 => { let t = self.ast_type()?; Ok(AstType::Asset(Box::new(t))) }
            _ => Err(IrSerError::InvalidTag(tag)),
        }
    }

    fn parameter(&mut self) -> Result<Parameter, IrSerError> {
        let name = self.str()?;
        let ty = self.ast_type()?;
        let is_indexed = self.bool()?;
        Ok(Parameter { name, ty, is_indexed })
    }

    fn struct_def(&mut self) -> Result<StructDefinition, IrSerError> {
        let name = self.str()?;
        let count = self.u32()? as usize;
        let mut fields = Vec::with_capacity(count);
        for _ in 0..count { fields.push(self.parameter()?); }
        Ok(StructDefinition { name, fields })
    }

    fn enum_variant(&mut self) -> Result<EnumVariant, IrSerError> {
        let name = self.str()?;
        let count = self.u32()? as usize;
        let mut fields = Vec::with_capacity(count);
        for _ in 0..count { fields.push(self.parameter()?); }
        Ok(EnumVariant { name, fields })
    }

    fn enum_def(&mut self) -> Result<EnumDefinition, IrSerError> {
        let name = self.str()?;
        let count = self.u32()? as usize;
        let mut variants = Vec::with_capacity(count);
        for _ in 0..count { variants.push(self.enum_variant()?); }
        Ok(EnumDefinition { name, variants })
    }

    fn event_param(&mut self) -> Result<EventParam, IrSerError> {
        let name = self.str()?;
        let ty = self.ast_type()?;
        let is_indexed = self.bool()?;
        Ok(EventParam { name, ty, is_indexed })
    }

    fn event_def(&mut self) -> Result<EventDefinition, IrSerError> {
        let name = self.str()?;
        let count = self.u32()? as usize;
        let mut params = Vec::with_capacity(count);
        for _ in 0..count { params.push(self.event_param()?); }
        Ok(EventDefinition { name, params })
    }

    fn module(&mut self) -> Result<IrModule, IrSerError> {
        // Header
        if self.remaining() < 5 { return Err(IrSerError::Truncated("header".into())); }
        if &self.buf[0..4] != IR_MAGIC { return Err(IrSerError::BadMagic); }
        self.pos += 4;
        let version = self.u8()?;
        if version != IR_VERSION { return Err(IrSerError::UnsupportedVersion(version)); }

        let contract_name = self.str()?;

        let sv_count = self.u32()? as usize;
        let mut state_vars = Vec::with_capacity(sv_count);
        for _ in 0..sv_count {
            let name = self.str()?;
            let ty = self.type_()?;
            let addr = self.u32()?;
            state_vars.push((name, ty, addr));
        }

        let struct_count = self.u32()? as usize;
        let mut struct_defs = HashMap::new();
        for _ in 0..struct_count {
            let s = self.struct_def()?;
            struct_defs.insert(s.name.clone(), s);
        }

        let enum_count = self.u32()? as usize;
        let mut enum_defs = HashMap::new();
        for _ in 0..enum_count {
            let e = self.enum_def()?;
            enum_defs.insert(e.name.clone(), e);
        }

        let event_count = self.u32()? as usize;
        let mut event_defs = Vec::with_capacity(event_count);
        for _ in 0..event_count { event_defs.push(self.event_def()?); }

        let extern_contracts = self.vec_strs()?;

        let func_count = self.u32()? as usize;
        let mut functions = Vec::with_capacity(func_count);
        for _ in 0..func_count { functions.push(self.function()?); }

        Ok(IrModule {
            contract_name, functions, state_vars,
            struct_defs, enum_defs, event_defs, extern_contracts,
        })
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Serialize an IrModule to compact binary format (SIR1).
pub fn serialize(module: &IrModule) -> Vec<u8> {
    let mut w = Writer::new();
    w.module(module);
    w.buf
}

/// Deserialize an IrModule from SIR1 binary format.
pub fn deserialize(buf: &[u8]) -> Result<IrModule, IrSerError> {
    let mut r = Reader::new(buf);
    r.module()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    
    fn roundtrip(source: &str) -> (IrModule, IrModule) {
        let ast = crate::parser::parse(source).expect("parse failed");
        let mut builder = crate::ir::IrBuilder::new();
        let module = builder.build(&ast).expect("IR build failed");
        let serialized = serialize(&module);
        let deserialized = deserialize(&serialized).expect("deserialize failed");
        (module, deserialized)
    }

    fn assert_modules_eq(a: &IrModule, b: &IrModule) {
        assert_eq!(a.contract_name, b.contract_name, "contract name mismatch");
        assert_eq!(a.state_vars.len(), b.state_vars.len(), "state var count");
        let mut sv_a = a.state_vars.clone();
        let mut sv_b = b.state_vars.clone();
        sv_a.sort_by(|x, y| x.0.cmp(&y.0));
        sv_b.sort_by(|x, y| x.0.cmp(&y.0));
        for (i, ((n1, t1, addr1), (n2, t2, addr2))) in sv_a.iter().zip(sv_b.iter()).enumerate() {
            assert_eq!(n1, n2, "state var {} name", i);
            assert_eq!(t1, t2, "state var {} type", i);
            assert_eq!(addr1, addr2, "state var {} addr", i);
        }
        assert_eq!(a.functions.len(), b.functions.len(), "function count");
        for (i, (f1, f2)) in a.functions.iter().zip(b.functions.iter()).enumerate() {
            assert_eq!(f1.name, f2.name, "function {} name", i);
            assert_eq!(f1.params.len(), f2.params.len(), "function {} param count", i);
            assert_eq!(f1.blocks.len(), f2.blocks.len(), "function {} block count: {} vs {}", i, f1.blocks.len(), f2.blocks.len());
            for (j, (b1, b2)) in f1.blocks.iter().zip(f2.blocks.iter()).enumerate() {
                assert_eq!(b1.id, b2.id, "function {} block {} id", i, j);
                assert_eq!(b1.insts.len(), b2.insts.len(), "function {} block {} inst count", i, j);
                assert_eq!(b1.preds, b2.preds, "function {} block {} preds", i, j);
                assert_eq!(b1.reachable, b2.reachable, "function {} block {} reachable", i, j);
                for (k, (inst1, inst2)) in b1.insts.iter().zip(b2.insts.iter()).enumerate() {
                    assert_eq!(inst1.value_id, inst2.value_id, "function {} block {} inst {} value_id", i, j, k);
                    assert_eq!(inst1.result_type, inst2.result_type, "function {} block {} inst {} result_type", i, j, k);
                    assert_eq!(inst1.line, inst2.line, "function {} block {} inst {} line", i, j, k);
                    // Compare op (debug format is sufficient for roundtrip validation)
                    assert_eq!(format!("{:?}", inst1.op), format!("{:?}", inst2.op),
                        "function {} block {} inst {} op mismatch", i, j, k);
                }
            }
        }
        assert_eq!(a.extern_contracts, b.extern_contracts, "extern contracts");
    }

    #[test]
    fn test_ser_simple_contract() {
        let source = r#"
pragma synq ^0.9;
contract Test {
    state { initialised: bool; counter: u256; }
    @public
    function init() -> bool { initialised = true; return true; }
    @public
    function increment() -> u256 { counter = counter + 1; return counter; }
}"#;
        let (orig, deser) = roundtrip(source);
        assert_modules_eq(&orig, &deser);
    }

    #[test]
    fn test_ser_with_loops_and_calls() {
        let source = r#"
pragma synq ^0.9;
contract Test {
    state { initialised: bool; }
    @public
    function init() -> bool { initialised = true; return true; }
    @public
    function double(x: u256) -> u256 { return x * 2; }
    @public
    function sumDoubles(n: u256) -> u256 {
        let i: u256 = 0;
        let total: u256 = 0;
        while (i < n) { total = total + double(i); i = i + 1; }
        return total;
    }
}"#;
        let (orig, deser) = roundtrip(source);
        assert_modules_eq(&orig, &deser);
    }

    #[test]
    fn test_ser_with_if_else() {
        let source = r#"
pragma synq ^0.9;
contract Test {
    state { initialised: bool; }
    @public
    function init() -> bool { initialised = true; return true; }
    @public
    function classify(n: u256) -> u256 {
        if (n < 10) { return 0; }
        else { if (n < 100) { return 1; } else { return 2; } }
    }
}"#;
        let (orig, deser) = roundtrip(source);
        assert_modules_eq(&orig, &deser);
    }

    #[test]
    fn test_ser_with_struct() {
        let source = r#"
pragma synq ^0.9;
struct Point { x: u256; y: u256; }
contract Test {
    state { initialised: bool; }
    @public
    function init() -> bool { initialised = true; return true; }
    @public
    function translate(p: Point, dx: u256, dy: u256) -> Point {
        let result = Point { x: p.x + dx, y: p.y + dy };
        return result;
    }
}"#;
        let (orig, deser) = roundtrip(source);
        assert_modules_eq(&orig, &deser);
        // Verify struct defs survived
        assert!(deser.struct_defs.contains_key("Point"), "struct Point not found");
    }

    #[test]
    fn test_ser_serialized_size_compact() {
        let source = r#"
pragma synq ^0.9;
contract Test {
    state { initialised: bool; }
    @public
    function init() -> bool { initialised = true; return true; }
    @public
    function double(x: u256) -> u256 { return x * 2; }
    @public
    function sumDoubles(n: u256) -> u256 {
        let i: u256 = 0;
        let total: u256 = 0;
        while (i < n) { total = total + double(i); i = i + 1; }
        return total;
    }
}"#;
        let (orig, _) = roundtrip(source);
        let serialized = serialize(&orig);
        let text_dump = orig.dump();
        println!("Binary IR: {} bytes, Text dump: {} bytes", serialized.len(), text_dump.len());
        // Binary should be significantly smaller than text
        assert!(serialized.len() < text_dump.len(),
            "binary ({}) should be smaller than text ({})", serialized.len(), text_dump.len());
    }
}
