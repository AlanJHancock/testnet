use std::fmt;

// Error types
#[derive(Debug, Clone)]
pub enum VMError {
    InvalidBytecode(String),
    StackUnderflow,
    StackOverflow,
    InvalidInstruction(u8),
    InvalidAddress(usize),
    CryptoError(String),
    RuntimeError(String),
    Reverted(String),          // require() failure — carries the require message
    RevertedNamed { code: u32, message: String }, // named error revert — carries enum variant tag + display message
    StepLimitExceeded(usize),  // PR-B: infinite-loop / gas guard
    FuelExhausted { cost: u64, remaining: u64 },  // ACTS-VM-005: PQC cost budget
}

impl fmt::Display for VMError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VMError::InvalidBytecode(msg)    => write!(f, "Invalid bytecode: {}", msg),
            VMError::StackUnderflow          => write!(f, "Stack underflow"),
            VMError::StackOverflow           => write!(f, "Stack overflow"),
            VMError::InvalidInstruction(op)  => write!(f, "Invalid instruction: 0x{:02x}", op),
            VMError::InvalidAddress(addr)    => write!(f, "Invalid address: {}", addr),
            VMError::CryptoError(msg)        => write!(f, "Crypto error: {}", msg),
            VMError::RuntimeError(msg)       => write!(f, "Runtime error: {}", msg),
            VMError::Reverted(msg)           => write!(f, "require failed: {}", msg),
            VMError::RevertedNamed { code, message } => write!(f, "revert: {} (code {})", message, code),
            VMError::StepLimitExceeded(n)    => write!(f, "step limit exceeded ({} steps): possible infinite loop", n),
            VMError::FuelExhausted { cost, remaining } => write!(f, "fuel exhausted: needed {} but only {} remaining", cost, remaining),
        }
    }
}

impl std::error::Error for VMError {}

// Instruction opcodes
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum OpCode {
    // Stack operations
    Push   = 0x01,
    Pop    = 0x02,
    Dup    = 0x03,
    Swap   = 0x04,

    // Arithmetic operations
    Add = 0x10,
    Sub = 0x11,
    Mul = 0x12,
    Div = 0x13,
    Rem = 0x14,

    // Comparison operations
    Eq = 0x20,
    Ne = 0x21,
    Lt = 0x22,
    Le = 0x23,
    Gt = 0x24,
    Ge = 0x25,

    // Control flow
    Jump   = 0x30,
    JumpIf = 0x31,
    Call   = 0x32,
    Return = 0x33,
    Revert = 0x34,  // require() failure — followed by 4-byte LE len + message bytes
    RevertCode = 0x35, // named error revert — followed by error_code(4B LE) + msg_len(4B LE) + msg
    RevertCodeDyn = 0x36, // named error revert — error_code(4B LE) inline, pops Str/Bytes msg from stack

    // Memory operations
    Load       = 0x40,
    Store      = 0x41,
    LoadImm    = 0x42,   // push raw bytes (strings / PQC keys)
    LoadImm128 = 0x43,   // push a 16-byte big-endian u128 (UInt256 values ≤ 2^128)
    LoadImm256 = 0x44,   // push a 32-byte big-endian U256 (full Ethereum address / real UInt256)
    LoadCaller = 0x50,   // push authenticated EVM caller address as U256 (zero if unauthenticated)
    // Authority model opcodes (spec v7.0 alignment)
    LoadAuthority = 0x51,  // push current call's AuthorityEnvelope as Bytes
    AuthRequire   = 0x52,  // pop envelope + scope_hash → push Bool (validated)
    AuthIdentity  = 0x53,  // pop envelope → push UMA identity (U256)
    AddrEncode   = 0x54,  // pop 20-byte value → push tsynq... Bech32m string as Bytes
    AddrDecode   = 0x55,  // pop Bech32m string (Bytes) → push 20-byte value as U256
    ContractAddr = 0x56,  // pop deployer(U256) + nonce(U256) + artifact_hash(Bytes32) → push tsynq... Bech32m string
    // ── Linear asset tracking (0x57-0x5B) ──────────────────────────────
    AssetCreate   = 0x57,  // pop type_tag(I32) + value(U256) → push asset_id(U256)
    AssetTransfer = 0x58,  // pop new_owner(U256) + asset_id(U256) → push new_asset_id(U256)
    AssetBurn     = 0x59,  // pop asset_id(U256) → push value(U256)
    AssetBalance  = 0x5A,  // pop asset_id(U256) → push value(U256)
    AssetOwner    = 0x5B,  // pop asset_id(U256) → push owner(U256)
    LoadCallSender = 0x5C,  // push immediate calling contract address as U256 (zero for direct calls)
    ExternCall = 0x60,   // call a function on another contract in the same workspace

    // Map operations (0x90-0x96)
    MapNew      = 0x90,   // MapNew  <4-byte-LE name_len> <name_bytes> — init map slot, push handle (addr)
    MapGet      = 0x91,   // pops key, pops map_addr → pushes value (or I32(0) if missing)
    MapSet      = 0x92,   // pops value, pops key, pops map_addr → stores entry
    MapContains = 0x93,   // pops key, pops map_addr → pushes Bool
    MapRemove   = 0x94,   // pops key, pops map_addr → removes entry
    MapLen      = 0x95,   // pops map_addr → pushes I32(count)

    // Set operations (0x97-0x9B)
    SetNew      = 0x97,   // SetNew <4-byte-LE name_len> <name_bytes> — init set slot, push handle
    SetAdd      = 0x98,   // pops value, pops set_addr → inserts
    SetContains = 0x99,   // pops value, pops set_addr → pushes Bool
    SetRemove   = 0x9A,   // pops value, pops set_addr → removes
    SetLen      = 0x9B,   // pops set_addr → pushes I32(count)

    // String operations (0x9C-0x9E)
    StrLen      = 0x9C,   // pops Bytes/string addr → pushes I32(len)
    StrConcat   = 0x9D,   // pops b, pops a → pushes Bytes(a+b)
    StrEq       = 0x9E,   // pops b, pops a → pushes Bool
    ToString    = 0x9F,   // pops value -> pushes Str (runtime display)

    // Compound type constructors (0xA0-0xAA)
    TuplePack    = 0xA0,
    TupleUnpack  = 0xA1,
    TupleGet     = 0xA2,
    OptionSome   = 0xA3,
    OptionNone   = 0xA4,
    OptionUnwrap = 0xA5,
    ResultOk     = 0xA6,
    ResultErr    = 0xA7,
    ResultUnwrap = 0xA8,
    IsOk         = 0xA9,
    IsSome       = 0xAA,
    TupleSet     = 0xAB,   // pops index, value, tuple → pushes new tuple with element replaced

    // PQC operations — legacy algorithm-specific opcodes (backward compat)
    DilithiumVerify  = 0x80,
    KyberKeyExchange = 0x81,
    FalconVerify     = 0x82,
    SphincsVerify    = 0x83,
    // AEG1 unified dispatch — preferred for spec v7.0 alignment
    AegisCall        = 0x8F,

    // Utility
    Print = 0xF0,
    Halt  = 0xFF,
}

impl TryFrom<u8> for OpCode {
    type Error = VMError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(OpCode::Push),
            0x02 => Ok(OpCode::Pop),
            0x03 => Ok(OpCode::Dup),
            0x04 => Ok(OpCode::Swap),
            0x10 => Ok(OpCode::Add),
            0x11 => Ok(OpCode::Sub),
            0x12 => Ok(OpCode::Mul),
            0x13 => Ok(OpCode::Div),
            0x14 => Ok(OpCode::Rem),
            0x20 => Ok(OpCode::Eq),
            0x21 => Ok(OpCode::Ne),
            0x22 => Ok(OpCode::Lt),
            0x23 => Ok(OpCode::Le),
            0x24 => Ok(OpCode::Gt),
            0x25 => Ok(OpCode::Ge),
            0x30 => Ok(OpCode::Jump),
            0x31 => Ok(OpCode::JumpIf),
            0x32 => Ok(OpCode::Call),
            0x33 => Ok(OpCode::Return),
            0x34 => Ok(OpCode::Revert),
            0x35 => Ok(OpCode::RevertCode),
            0x36 => Ok(OpCode::RevertCodeDyn),
            0x40 => Ok(OpCode::Load),
            0x41 => Ok(OpCode::Store),
            0x42 => Ok(OpCode::LoadImm),
            0x43 => Ok(OpCode::LoadImm128),
            0x44 => Ok(OpCode::LoadImm256),
            0x50 => Ok(OpCode::LoadCaller),
            0x51 => Ok(OpCode::LoadAuthority),
            0x52 => Ok(OpCode::AuthRequire),
            0x53 => Ok(OpCode::AuthIdentity),
            0x54 => Ok(OpCode::AddrEncode),
            0x55 => Ok(OpCode::AddrDecode),
            0x56 => Ok(OpCode::ContractAddr),
            0x57 => Ok(OpCode::AssetCreate),
            0x58 => Ok(OpCode::AssetTransfer),
            0x59 => Ok(OpCode::AssetBurn),
            0x5A => Ok(OpCode::AssetBalance),
            0x5B => Ok(OpCode::AssetOwner),
            0x5C => Ok(OpCode::LoadCallSender),
            0x60 => Ok(OpCode::ExternCall),
            // Map ops
            0x90 => Ok(OpCode::MapNew),
            0x91 => Ok(OpCode::MapGet),
            0x92 => Ok(OpCode::MapSet),
            0x93 => Ok(OpCode::MapContains),
            0x94 => Ok(OpCode::MapRemove),
            0x95 => Ok(OpCode::MapLen),
            // Set ops
            0x97 => Ok(OpCode::SetNew),
            0x98 => Ok(OpCode::SetAdd),
            0x99 => Ok(OpCode::SetContains),
            0x9A => Ok(OpCode::SetRemove),
            0x9B => Ok(OpCode::SetLen),
            // String ops
            0x9C => Ok(OpCode::StrLen),
            0x9D => Ok(OpCode::StrConcat),
            0x9E => Ok(OpCode::StrEq),
            0x9F => Ok(OpCode::ToString),
            0xA0 => Ok(OpCode::TuplePack),
            0xA1 => Ok(OpCode::TupleUnpack),
            0xA2 => Ok(OpCode::TupleGet),
            0xA3 => Ok(OpCode::OptionSome),
            0xA4 => Ok(OpCode::OptionNone),
            0xA5 => Ok(OpCode::OptionUnwrap),
            0xA6 => Ok(OpCode::ResultOk),
            0xA7 => Ok(OpCode::ResultErr),
            0xA8 => Ok(OpCode::ResultUnwrap),
            0xA9 => Ok(OpCode::IsOk),
            0xAA => Ok(OpCode::IsSome),
            0xAB => Ok(OpCode::TupleSet),
            0x80 => Ok(OpCode::DilithiumVerify),
            0x81 => Ok(OpCode::KyberKeyExchange),
            0x82 => Ok(OpCode::FalconVerify),
            0x83 => Ok(OpCode::SphincsVerify),
            0x8F => Ok(OpCode::AegisCall),
            0xF0 => Ok(OpCode::Print),
            0xFF => Ok(OpCode::Halt),
            _    => Err(VMError::InvalidInstruction(value)),
        }
    }
}
