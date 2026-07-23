//! Abstract Syntax Tree for the SynQ language.
//! Spec: modules, rich types, events, named errors, roles, interfaces, upgrades.

#[derive(Debug, PartialEq, Clone)]
pub enum SourceUnit {
    Contract(ContractDefinition),
    Struct(StructDefinition),
    Interface(InterfaceDefinition),
    Event(EventDefinition),
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
/// Desugars to `requires cap::Minter, cap::Burner` at codegen.
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
    Assignment(String, Expression),
    /// `map[key] = value`
    MapAssignment { map: String, key: Expression, value: Expression },
    /// `set.add(value)` / `set.remove(value)` as statements
    SetOp { set: String, op: SetOpKind, value: Expression },
    /// `let x = expr` or `let x: T = expr` — local variable binding
    Let { name: String, ty: Option<Type>, value: Expression },
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
    /// `map[key]` — indexed read from a map state variable
    MapIndex(String, Box<Expression>),
    /// `map.get(key)` / `map.contains(key)` / `map.len()` method calls
    MapMethod { map: String, method: String, args: Vec<Expression> },
    /// `set.contains(v)` / `set.len()` method calls
    SetMethod { set: String, method: String, args: Vec<Expression> },
    Tuple(Vec<Expression>),
    Some(Box<Expression>),
    None,
    Ok(Box<Expression>),
    Err(Box<Expression>),
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
    // User-defined (struct name)
    Named(String),
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
