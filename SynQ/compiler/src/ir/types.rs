// ── IR Type System ────────────────────────────────────────────────────────────
//
// IrType is the type carried by every SSA value. It mirrors the AST Type enum
// but is simplified for analysis — no parsing concerns, no source-level sugar.

use crate::ast::{Type as AstType, BinaryOperator};

/// A value reference — unique within a function. In SSA, each value is assigned
/// exactly once, so a ValueId uniquely identifies a definition point.
pub type ValueId = u32;

/// A basic block reference — index into IrFunction::blocks.
pub type BlockId = u32;

/// An instruction reference — index into BasicBlock::insts.
pub type InstId = u32;

/// IR-level types. These are richer than VM Value types — the VM only
/// distinguishes I32/U128/U256/Bytes/Bool/Map/Set/Str/Tuple, but the IR
/// carries full type information for static analysis.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IrType {
    // ── Primitives ──
    Bool,
    I32,
    I64,
    U128,
    U256,
    Bytes,
    Str,
    Address,       // 20-byte address (syna/sync)

    // ── Fixed-size types ──
    BytesN(usize),  // Bytes<N>
    Hash32,        // 32-byte hash
    Hash64,        // 64-byte hash

    // ── Higher-order ──
    Option(Box<IrType>),
    Result(Box<IrType>, Box<IrType>),
    Tuple(Vec<IrType>),

    // ── Maps/Sets ──
    Map(Box<IrType>, Box<IrType>),
    Set(Box<IrType>),

    // ── User-defined ──
    Named(String),          // struct or enum name
    Asset(Box<IrType>),      // linear asset wrapper
    Authority,              // authority envelope (104 bytes)
    UMAIdentity,             // 32-byte UMA identity
    ModelId,                 // AI model identifier
    Height,                  // block height

    // ── Effect tokens ──
    /// An effect token — produced by effect operations, consumed by
    /// subsequent operations. Enables compile-time effect tracking.
    EffectToken,

    // ── Void ──
    /// No value — for instructions that produce no result (Store, Emit, etc.)
    Void,
}

impl IrType {
    /// Convert an AST Type to an IR Type.
    pub fn from_ast(t: &AstType) -> IrType {
        match t {
            AstType::Bool => IrType::Bool,
            AstType::UInt8 | AstType::UInt16 | AstType::UInt32 => IrType::I32,
            AstType::UInt64 => IrType::I64,
            AstType::UInt128 => IrType::U128,
            AstType::UInt256 => IrType::U256,
            AstType::Int8 | AstType::Int16 | AstType::Int32 => IrType::I32,
            AstType::Int64 => IrType::I64,
            AstType::Int128 => IrType::I64,
            AstType::Int256 => IrType::U256,
            AstType::Bytes => IrType::Bytes,
            AstType::Str => IrType::Str,
            AstType::Address => IrType::Address,
            AstType::BytesN(n) => IrType::BytesN(*n),
            AstType::Hash32 => IrType::Hash32,
            AstType::Hash64 => IrType::Hash64,
            AstType::UMAIdentity => IrType::UMAIdentity,
            AstType::ModelId => IrType::ModelId,
            AstType::Height => IrType::Height,
            AstType::Option(inner) => IrType::Option(Box::new(IrType::from_ast(inner))),
            AstType::Result(ok, err) => IrType::Result(
                Box::new(IrType::from_ast(ok)),
                Box::new(IrType::from_ast(err)),
            ),
            AstType::Tuple(types) => IrType::Tuple(types.iter().map(IrType::from_ast).collect()),
            AstType::Mapping(k, v) => IrType::Map(Box::new(IrType::from_ast(k)), Box::new(IrType::from_ast(v))),
            AstType::Array(inner) => IrType::Set(Box::new(IrType::from_ast(inner))),
            AstType::Named(name) => IrType::Named(name.clone()),
            AstType::Asset(inner) => IrType::Asset(Box::new(IrType::from_ast(inner))),
            // PQC types map to Bytes (opaque blobs in the VM)
            AstType::DilithiumPublicKey | AstType::FalconPublicKey | AstType::KyberPublicKey
            | AstType::DilithiumSignature | AstType::FalconSignature => IrType::Bytes,
        }
    }

    /// Does this type produce a value on the stack?
    pub fn is_void(&self) -> bool {
        matches!(self, IrType::Void)
    }

    /// Is this a linear type (must be consumed exactly once)?
    pub fn is_linear(&self) -> bool {
        matches!(self, IrType::Asset(_))
    }

    /// Human-readable name for diagnostics.
    pub fn name(&self) -> String {
        match self {
            IrType::Bool => "bool".into(),
            IrType::I32 => "i32".into(),
            IrType::I64 => "i64".into(),
            IrType::U128 => "u128".into(),
            IrType::U256 => "u256".into(),
            IrType::Bytes => "bytes".into(),
            IrType::Str => "string".into(),
            IrType::Address => "address".into(),
            IrType::BytesN(n) => format!("Bytes<{}>", n),
            IrType::Hash32 => "Hash32".into(),
            IrType::Hash64 => "Hash64".into(),
            IrType::Option(t) => format!("Option<{}>", t.name()),
            IrType::Result(o, e) => format!("Result<{}, {}>", o.name(), e.name()),
            IrType::Tuple(types) => {
                let parts: Vec<_> = types.iter().map(|t| t.name()).collect();
                format!("({})", parts.join(", "))
            }
            IrType::Map(k, v) => format!("map<{}, {}>", k.name(), v.name()),
            IrType::Set(t) => format!("set<{}>", t.name()),
            IrType::Named(n) => n.clone(),
            IrType::Asset(t) => format!("Asset<{}>", t.name()),
            IrType::Authority => "Authority".into(),
            IrType::UMAIdentity => "UMAIdentity".into(),
            IrType::ModelId => "ModelId".into(),
            IrType::Height => "Height".into(),
            IrType::EffectToken => "EffectToken".into(),
            IrType::Void => "void".into(),
        }
    }
}

/// Describes the effect kind for an IR operation.
/// Used by the effect analyzer to validate @effects declarations.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EffectKind {
    Read(String),       // read state variable by name
    Write(String),     // write state variable by name
    Emit(String),       // emit event by name
    FactConsume(String), // consume a verified fact
    ModelUse(String),    // use an AI model
    ExternalCall(String, String), // contract.function
}

/// A host-function profile — declared for every operation that touches
/// the host environment (extern_call, PQC, AI inference).
#[derive(Debug, Clone)]
pub struct HostFnProfile {
    pub kind: HostFnKind,
    pub callee: String,         // function name or contract.function
    pub arg_types: Vec<IrType>,
    pub return_type: IrType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostFnKind {
    ExternCall,     // cross-contract call
    PqcVerify,      // PQC signature verification
    PqcKem,         // PQC key encapsulation
    AegisCall,     // unified PQC dispatch
    AiInfer,        // AI inference (future)
    AiVerify,       // AI proof verification (future)
}
