//! Abstract Syntax Tree for the SynQ language.
//! Spec: modules, rich types, events, named errors, roles, interfaces, upgrades.

#[derive(Debug, PartialEq, Clone)]
pub enum SourceUnit {
    Contract(ContractDefinition),
    Struct(StructDefinition),
    Enum(EnumDefinition),
    Interface(InterfaceDefinition),
    Event(EventDefinition),
}


// ── Enum ───────────────────────────────────────────────────────────────────────
#[derive(Debug, PartialEq, Clone)]
pub struct EnumDefinition {
    pub name:     String,
    pub variants: Vec<EnumVariant>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct EnumVariant {
    pub name:   String,
    pub fields: Vec<Parameter>,  // empty for simple C-style enum
}

// ── Interface ────────────────────────────────────────────────────────────────
#[derive(Debug, PartialEq, Clone)]
pub struct InterfaceDefinition {
    pub name:      String,
    pub functions: Vec<InterfaceFunction>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct InterfaceFunction {
    pub name:    String,
    pub params:  Vec<Parameter>,
    pub returns: Option<Type>,
}

// ── Contract ─────────────────────────────────────────────────────────────────
#[derive(Debug, PartialEq, Clone)]
pub struct ContractDefinition {
    pub name:       String,
    pub implements: Vec<String>,  // interface names
    pub parts:      Vec<ContractPart>,
    pub metadata:   Vec<MetadataEntry>,
    pub roles:      Vec<RoleDefinition>,
    pub error_defs: Vec<ErrorDefinition>,
    pub enums: Vec<EnumDefinition>,
    pub event_defs: Vec<EventDefinition>,
    /// Functions in the `tests { }` section — compiled but not deployed.
    pub test_fns:   Vec<FunctionDefinition>,
}

#[derive(Debug, PartialEq, Clone)]
pub enum ContractPart {
    StateVariable(StateVariableDeclaration),
    Constructor(ConstructorDefinition),
    Function(FunctionDefinition),
    Event(EventDefinition),
}

// ── Metadata ─────────────────────────────────────────────────────────────────
#[derive(Debug, PartialEq, Clone)]
pub struct MetadataEntry {
    pub key:   String,
    pub value: MetadataValue,
}

#[derive(Debug, PartialEq, Clone)]
pub enum MetadataValue {
    Str(String),
    Num(u128),
}

// ── Roles ────────────────────────────────────────────────────────────────────
/// `role Admin = cap::Minter + cap::Burner;`
/// Desugars to `requires cap::Minter, cap::Burner`.
#[derive(Debug, PartialEq, Clone)]
pub struct RoleDefinition {
    pub name: String,
    pub caps: Vec<String>,  // capability names
}

// ── Named errors ─────────────────────────────────────────────────────────────
/// `error InsufficientFunds(needed: UInt256);`
#[derive(Debug, PartialEq, Clone)]
pub struct ErrorDefinition {
    pub name:   String,
    pub params: Vec<Parameter>,
}

// ── State variables ───────────────────────────────────────────────────────────
#[derive(Debug, PartialEq, Clone)]
pub struct StateVariableDeclaration {
    pub name:      String,
    pub ty:        Type,
    pub is_public: bool,
}

#[derive(Debug, PartialEq, Clone)]
pub struct ConstructorDefinition {
    pub params: Vec<Parameter>,
    pub body:   Block,
}

// ── Functions ────────────────────────────────────────────────────────────────
#[derive(Debug, PartialEq, Clone)]
pub struct FunctionDefinition {
    pub name:            String,
    pub params:          Vec<Parameter>,
    pub returns:         Option<Type>,
    pub body:            Block,
    pub is_public:       bool,
    /// `as caller` — requires authenticated (non-zero) caller.
    pub requires_caller: bool,
    /// Resolved capability names (caps from `requires cap::X` + expanded from `requires role::X`).
    pub capabilities:    Vec<String>,
    /// State precondition expressions as raw strings: e.g. "balance_of[caller] >= amount"
    /// Parsed for metadata/test-harness use — NOT compiled to bytecode (runtime guards stay in body).
    pub requires_state:  Vec<String>,
    /// State variables this function modifies: e.g. "balance_of[caller]", "registered[who]"
    pub modifies:        Vec<String>,
    /// Parsed `@attribute` declarations (spec v7.0)
    pub attributes:      Vec<Attribute>,
}


// ── Attributes (spec v7.0) ─────────────────────────────────────────────────────
/// Parsed attributes from `@name(args)` syntax before function definitions.
#[derive(Debug, PartialEq, Clone)]
pub enum Attribute {
    /// `@public` — function is callable from outside the contract
    Public,
    /// `@authority(ScopeName)` — requires caller to hold the named authority scope
    Authority(String),
    /// `@effects(var1, var2, ...)` — declares state variables this function modifies
    Effects(Vec<String>),
    /// `@requires(expr)` — state precondition (metadata, not compiled)
    Requires(String),
    /// `@ensures(expr)` — state postcondition (metadata, not compiled)
    Ensures(String),
    /// `@fails(ErrorName)` — declares a named error this function may revert with
    Fails(String),
    /// `@bounded(n)` — declares a step/fuel bound for this function
    Bounded(String),
    /// `@manifest` — function appears in the contract's public manifest
    Manifest,
    /// `@ai` — function may perform AI inference (requires cap::AI)
    Ai,
    /// `@governance(ScopeName)` — requires governance authorization for the named scope.
    /// Unlike @authority (devnet convenience, all-zeros scope accepted), @governance
    /// enforces a strict SHA3-256 scope hash match and uses the SYNQ-GOVERNANCE-v3 domain tag.
    Governance(String),
}

// ── Events ───────────────────────────────────────────────────────────────────
#[derive(Debug, PartialEq, Clone)]
pub struct EventDefinition {
    pub name:   String,
    pub params: Vec<EventParam>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct EventParam {
    pub name:       String,
    pub ty:         Type,
    pub is_indexed: bool,
}

// ── Struct ───────────────────────────────────────────────────────────────────
#[derive(Debug, PartialEq, Clone)]
pub struct StructDefinition {
    pub name:   String,
    pub fields: Vec<Parameter>,
}

// ── Shared ───────────────────────────────────────────────────────────────────
#[derive(Debug, PartialEq, Clone)]
pub struct Parameter {
    pub name:       String,
    pub ty:         Type,
    pub is_indexed: bool,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Block {
    pub statements: Vec<Statement>,
}

// ── Statements ───────────────────────────────────────────────────────────────
#[derive(Debug, PartialEq, Clone)]
pub enum Statement {
    Expression(Expression),
    Require(Expression, String),
    /// `revert ErrorName(args...)` — named error revert
    RevertNamed { error: String, args: Vec<Expression> },
    /// `revert EnumName::VariantName(args);` — qualified named error revert
    RevertEnum { enum_name: String, error: String, args: Vec<Expression> },
    Assignment(String, Expression),
    /// `obj.field = value` — struct field assignment
    FieldAssignment { object: String, field: String, value: Expression },
    /// `map[key] = value`
    MapAssignment { map: String, keys: Vec<Expression>, value: Expression },
    /// `set.add(value)` / `set.remove(value)` as statements
    SetOp { set: String, op: SetOpKind, value: Expression },
    /// `let x = expr` or `let x: T = expr` — local variable binding
    Let { name: String, ty: Option<Type>, value: Expression },
    LetDestructure { names: Vec<String>, value: Box<Expression> },
    Return(Option<Expression>),
    ExternCall { contract: String, function: String, args: Vec<Expression> },
    /// `emit EventName(args...)` — event emission
    Emit { event: String, args: Vec<Expression> },
    /// `if (cond) { ... } else { ... }`
    If { condition: Expression, then_block: Block, else_block: Option<Block> },
    While  { condition: Expression, body: Block },
    Break,
    Continue,
}

// ── Expressions ──────────────────────────────────────────────────────────────
#[derive(Debug, PartialEq, Clone)]
pub enum Expression {
    Call(String, Vec<Expression>),
    Literal(Literal),
    Identifier(String),
    BinaryOp(Box<Expression>, BinaryOperator, Box<Expression>),
    UnaryOp(UnaryOperator, Box<Expression>),
    Caller,   // `caller` builtin — authenticated EVM address
    CallSender, // `call_sender` builtin — immediate calling contract address (0 for direct calls)
    /// `map[key]` — indexed read from a map state variable
    MapIndex(String, Vec<Expression>),
    /// `map.get(key)` / `map.contains(key)` / `map.len()` method calls
    MapMethod { map: String, method: String, args: Vec<Expression> },
    /// `set.contains(v)` / `set.len()` method calls
    SetMethod { set: String, method: String, args: Vec<Expression> },
    Tuple(Vec<Expression>),
    Some(Box<Expression>),
    None,
    Ok(Box<Expression>),
    Err(Box<Expression>),
    /// `expr.field` — access a struct field
    FieldAccess { object: Box<Expression>, field: String },
    TupleIndex { object: Box<Expression>, index: usize },
    EnumAccess { enum_name: String, variant_name: String },
    /// `TypeName { field1: val1, field2: val2 }` — struct literal
    StructLiteral { type_name: String, fields: Vec<(String, Expression)> },
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum BinaryOperator {
    Add, Sub, Mul, Div, Mod,
    Eq, Ne, Lt, Le, Gt, Ge,
    And, Or,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum UnaryOperator {
    Neg,   // `-`
    Not,   // `!`
}

// ── Types ────────────────────────────────────────────────────────────────────
#[derive(Debug, PartialEq, Clone)]
pub enum Type {
    // Unsigned integers
    UInt8, UInt16, UInt32, UInt64, UInt128, UInt256,
    // Signed integers
    Int8, Int16, Int32, Int64, Int128, Int256,
    // Other primitives
    Bool, Bytes, Address, Str,
    // PQC key/sig types
    DilithiumPublicKey, FalconPublicKey, KyberPublicKey,
    DilithiumSignature, FalconSignature,
    // Higher-order
    Option(Box<Type>),
    Result(Box<Type>, Box<Type>),
    Tuple(Vec<Type>),
    Mapping(Box<Type>, Box<Type>),
    Array(Box<Type>),
    // User-defined (struct/enum name)
    Named(String),
    // ── New primitive types (spec v7.0) ──
    /// Fixed-size byte array: Bytes<N>
    BytesN(usize),
    /// Linear asset wrapper: Asset<T>
    Asset(Box<Type>),
    /// 32-byte hash (alias for Bytes<32>)
    Hash32,
    /// 64-byte hash
    Hash64,
    /// UMA identity (32-byte)
    UMAIdentity,
    /// Block height
    Height,
    /// AI model identifier
    ModelId,
}

// ── Literals ─────────────────────────────────────────────────────────────────
#[derive(Debug, PartialEq, Clone)]
pub enum Literal {
    String(String),
    Number(u128),
    BigNumber(String), // decimal string > u128::MAX
    Hex(Vec<u8>),      // 0x... hex literal → bytes
    Bool(bool),
}

// ── Map/Set operation kinds ───────────────────────────────────────────────────
#[derive(Debug, PartialEq, Clone)]
pub enum SetOpKind { Add, Remove }
