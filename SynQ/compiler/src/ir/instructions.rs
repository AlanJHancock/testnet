// ── IR Instructions ──────────────────────────────────────────────────────────
//
// Each instruction produces at most one SSA value (identified by InstId).
// Instructions that produce no value (Store, Emit, Require) have Void type.
// The terminator (last instruction in a block) is always a control-flow op.

use crate::ast::{Literal, BinaryOperator, UnaryOperator, SetOpKind};
use super::types::*;

/// An IR instruction. Every instruction has a result type (Void for effect-only ops)
/// and produces a ValueId equal to its InstId (instruction index within the function).
#[derive(Debug, Clone)]
pub struct Instruction {
    pub op: IrOp,
    pub result_type: IrType,
    /// Globally-unique value ID (assigned by push_value across the function).
    /// For effect-only (Void) instructions, this is the local instruction index
    /// and is not used for slot lookup.
    pub value_id: ValueId,
    /// Source line for diagnostics (0 if unknown).
    pub line: u32,
}

/// The operation carried by an instruction. Each variant either produces a value
/// (result_type != Void) or performs a side effect (result_type == Void).
#[derive(Debug, Clone)]
pub enum IrOp {
    // ── Value-producing operations ──────────────────────────────────────
    /// Constant literal value.
    Const(Literal),
    /// Binary arithmetic/logic: result = lhs OP rhs
    BinOp(BinaryOperator, ValueId, ValueId),
    /// Unary operation: result = OP operand
    UnaryOp(UnaryOperator, ValueId),
    /// Load a state variable by name → produces its value.
    Load(String),
    /// Load the authenticated caller address.
    Caller,
    CallSender,
    /// Load the authority envelope for this call.
    LoadAuthority,
    /// Load the UMA identity from the authority envelope.
    AuthIdentity(ValueId),
    /// Check authority scope: push Bool (true if authorized).
    /// ValueId is the authority envelope; String is the scope name.
    AuthRequire(ValueId, String),
    /// Internal function call: result = fn(args).
    Call(String, Vec<ValueId>),
    /// Cross-contract call: result = contract.function(args).
    /// Records a HostFnProfile (no implicit host calls in IR).
    ExternCall(String, String, Vec<ValueId>),
    /// Map read: result = map[key].
    MapGet(String, ValueId),
    /// Map method: result = map.method(args).
    MapMethod(String, String, Vec<ValueId>),
    /// Set method: result = set.method(args).
    SetMethod(String, String, Vec<ValueId>),
    /// Struct field read: result = obj.field.
    FieldAccess(ValueId, u32),
    /// Enum variant access: result = Enum::Variant (integer tag).
    EnumAccess(String, String),
    /// Struct literal: result = Type { field: val, ... }.
    StructLiteral(String, Vec<(String, ValueId)>),
    /// Tuple construction: result = (v1, v2, ...).
    Tuple(Vec<ValueId>),
    /// Struct tuple set: result = tuple with element at index replaced.
    TupleSet(ValueId, ValueId, ValueId), // tuple, index, value
    /// Struct tuple get: result = tuple[index].
    TupleGet(ValueId, ValueId), // tuple, index
    /// Option::Some(value).
    Some(ValueId),
    /// Option::None.
    None,
    /// Result::Ok(value).
    Ok(ValueId),
    /// Result::Err(value).
    Err(ValueId),
    /// Option unwrap: result = option.unwrap() (panics if None).
    OptionUnwrap(ValueId),
    /// Result unwrap: result = result.unwrap() (panics if Err).
    ResultUnwrap(ValueId),
    /// IsOk check: result = result.is_ok().
    IsOk(ValueId),
    /// IsSome check: result = option.is_some().
    IsSome(ValueId),
    /// Bech32 encode: result = to_tsynq(address).
    AddrEncode(ValueId),
    /// Bech32 decode: result = from_tsynq(string).
    AddrDecode(ValueId),
    /// Contract address derivation.
    ContractAddr(ValueId, ValueId, ValueId), // deployer, nonce, artifact_hash
    /// String length.
    StrLen(ValueId),
    /// String concatenation: result = a + b.
    StrConcat(ValueId, ValueId),
    /// String equality: result = (a == b).
    StrEq(ValueId, ValueId),

    // ── PQC / AEG1 operations ───────────────────────────────────────────
    /// Unified AEG1 dispatch: result = aegis_call(op, alg, args).
    AegisCall(Vec<ValueId>),
    AegisVerify(Vec<ValueId>),
    AegisDecaps(Vec<ValueId>),

    // ── Linear asset operations ────────────────────────────────────────
    /// Create asset: result = asset_id. type_tag from string hash.
    AssetCreate(String, ValueId), // type_name, value
    /// Transfer asset: result = new_asset_id.
    AssetTransfer(ValueId, ValueId), // asset_id, new_owner
    /// Burn asset: result = burned value.
    AssetBurn(ValueId),
    /// Check asset balance: result = value.
    AssetBalance(ValueId),
    /// Check asset owner: result = owner.
    AssetOwner(ValueId),

    // ── Effect operations (produce Void) ───────────────────────────────
    /// Store to state variable: state_var = value.
    Store(String, ValueId),
    /// Store to struct field: obj.field = value (via TupleSet + Store).
    FieldStore(String, String, ValueId),
    /// Map assignment: map[key] = value.
    MapSet(String, ValueId, ValueId),
    /// Nested map read: takes a map Value (from previous MapGet) + key -> result
    MapGetVal(ValueId, ValueId),
    /// Nested map write: takes a map Value + key + val -> modified map Value
    MapSetVal(ValueId, ValueId, ValueId),
    /// Set operation: set.add(value) / set.remove(value).
    SetOp(String, SetOpKind, ValueId),
    /// Emit event: emit EventName(args).
    Emit(String, Vec<ValueId>),
    /// Require: if !cond, revert with message.
    Require(ValueId, String),
    /// Revert with message string.
    Revert(String),
    /// Revert with named error: revert EnumName::Variant(args).
    RevertNamed(String, String, Vec<ValueId>),
    /// Print (debug output).
    Print(ValueId),

    // ── Control flow (block terminators) ─────────────────────────────────
    /// Conditional branch: if cond goto true_block else goto false_block.
    Branch(ValueId, BlockId, BlockId),
    /// Unconditional jump: goto target.
    Jump(BlockId),
    /// Return from function with optional value.
    Return(Option<ValueId>),

    // ── SSA-specific ────────────────────────────────────────────────────
    /// Phi (φ) node: merges values from predecessor blocks.
    /// result = φ((pred1, val1), (pred2, val2), ...)
    /// The value is val1 if control came from pred1, val2 from pred2, etc.
    Phi(Vec<(BlockId, ValueId)>),

    // ── AI operations (stubbed — Phase 4) ──────────────────────────────
    /// AI inference: result = ai::infer_native(model, input).
    AiInfer(ValueId, ValueId), // model_id, input
    /// AI proof verification: result = ai::verify_proof(receipt).
    AiVerifyProof(ValueId),
}

impl Instruction {
    /// Create a value-producing instruction.
    pub fn value(op: IrOp, result_type: IrType) -> Self {
        Self { op, result_type, value_id: 0, line: 0 }
    }

    /// Create an effect-only instruction (Void result).
    pub fn effect(op: IrOp) -> Self {
        Self { op, result_type: IrType::Void, value_id: 0, line: 0 }
    }

    /// Is this a terminator (Branch, Jump, or Return)?
    pub fn is_terminator(&self) -> bool {
        matches!(self.op, IrOp::Branch(_, _, _) | IrOp::Jump(_) | IrOp::Return(_))
    }

    /// Get all ValueIds this instruction references as inputs.
    pub fn input_values(&self) -> Vec<ValueId> {
        match &self.op {
            IrOp::Const(_) | IrOp::Load(_) | IrOp::Caller | IrOp::CallSender | IrOp::LoadAuthority
            | IrOp::EnumAccess(_, _) | IrOp::None | IrOp::Jump(_)
            | IrOp::Revert(_) => vec![],
            IrOp::BinOp(_, a, b) => vec![*a, *b],
            IrOp::UnaryOp(_, a) => vec![*a],
            IrOp::AuthIdentity(a) => vec![*a],
            IrOp::UnaryOp(_, a) => vec![*a],
            IrOp::AuthRequire(env, _) => vec![*env],
            IrOp::Call(_, args) | IrOp::AegisCall(args) | IrOp::AegisVerify(args) | IrOp::AegisDecaps(args) => args.clone(),
            IrOp::ExternCall(_, _, args) => args.clone(),
            IrOp::MapGet(_, key) => vec![*key],
            IrOp::MapMethod(_, _, args) | IrOp::SetMethod(_, _, args) => args.clone(),
            IrOp::FieldAccess(obj, _) => vec![*obj],  // idx is not a ValueId
            IrOp::StructLiteral(_, fields) => fields.iter().map(|(_, v)| *v).collect(),
            IrOp::Tuple(vals) => vals.clone(),
            IrOp::Phi(pairs) => pairs.iter().map(|(_, v)| *v).collect(),
            IrOp::TupleSet(t, idx, val) => vec![*t, *idx, *val],
            IrOp::TupleGet(t, idx) => vec![*t, *idx],
            IrOp::Some(v) | IrOp::Ok(v) | IrOp::Err(v) | IrOp::OptionUnwrap(v)
            | IrOp::ResultUnwrap(v) | IrOp::IsOk(v) | IrOp::IsSome(v)
            | IrOp::AddrEncode(v) | IrOp::AddrDecode(v) | IrOp::StrLen(v)
            | IrOp::AssetBurn(v) | IrOp::AssetBalance(v) | IrOp::AssetOwner(v)
            | IrOp::Print(v) | IrOp::AiVerifyProof(v) => vec![*v],
            IrOp::StrConcat(a, b) | IrOp::StrEq(a, b) | IrOp::AssetTransfer(a, b) | IrOp::AiInfer(a, b) => vec![*a, *b],
            IrOp::Store(_, v) | IrOp::FieldStore(_, _, v) => vec![*v],
            IrOp::Emit(_, args) => args.clone(),
            IrOp::MapSet(_, k, v) => vec![*k, *v],
            IrOp::MapGetVal(map, key) => vec![*map, *key],
            IrOp::MapSetVal(map, k, v) => vec![*map, *k, *v],
            IrOp::SetOp(_, _, v) => vec![*v],
            IrOp::Require(cond, _) => vec![*cond],
            IrOp::RevertNamed(_, _, args) => args.clone(),
            IrOp::Return(Some(v)) => vec![*v],
            IrOp::Return(None) => vec![],
            IrOp::Branch(cond, _, _) => vec![*cond],
            IrOp::AssetCreate(_, v) => vec![*v],
            IrOp::ContractAddr(a, b, c) => vec![*a, *b, *c],
            // Fallback: no inputs
            _ => vec![],
        }
    }

    /// Get successor block IDs if this is a terminator.
    pub fn successors(&self) -> Vec<BlockId> {
        match &self.op {
            IrOp::Branch(_, t, f) => vec![*t, *f],
            IrOp::Jump(t) => vec![*t],
            IrOp::Return(_) => vec![],
            _ => vec![],
        }
    }
}
