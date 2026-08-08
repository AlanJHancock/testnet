//! AIVM error families per synq-aivm-execution-spec.md

use std::fmt;

/// All AIVM error families
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AivmError {
    // BytecodeError
    BadMagic,
    UnsupportedBytecodeVersion(u16),
    UnsupportedAivmVersion(u16),
    MalformedSection { section_type: u16, reason: String },
    DuplicateSection(u16),
    JumpTargetOutOfBounds(u32),
    OperandOutOfBounds { offset: usize, needed: usize, available: usize },
    AbiHashMismatch,
    ManifestHashMismatch,
    CodeHashMismatch,
    TruncatedBytecode,

    // ManifestError
    ManifestMissing,
    ManifestMalformed(String),
    ManifestChainIdMismatch { expected: u64, got: u64 },
    ManifestNetworkIdMismatch { expected: String, got: String },
    ManifestAlgorithmNotAllowed(String),
    ManifestHostFunctionNotSupported(String),
    StorageSchemaHashMissing,

    // AbiError
    AbiMissing,
    AbiMalformed(String),
    AbiSelectorNotFound(u32),
    AbiArgumentEncodingError(String),
    AbiReturnEncodingError(String),

    // VerificationError
    VerificationFailed(String),
    SignatureInvalid,
    SignatureMissing,
    AddressMismatch,

    // GasError
    GasExhausted { used: u64, limit: u64 },
    GasEstimateFailed(String),

    // PqGasError
    PqGasExhausted { used: u64, limit: u64 },

    // RuntimeTrap
    Trap { code: u16, message: String },
    ArithmeticOverflow,
    ArithmeticUnderflow,
    DivisionByZero,
    StackOverflow,
    StackUnderflow,
    InvalidJumpTarget(u32),
    InvalidFunctionIndex(u32),
    InvalidEventIndex(u16),
    InvalidImportIndex(u16),
    InvalidKeyIndex(u16),
    InvalidLocalIndex(u16),
    TypeMismatch { expected: &'static str, got: &'static str },
    OutOfBoundsAccess { index: usize, len: usize },

    // StateError
    StateKeyNotFound(u16),
    StateWriteToImmutable(u16),
    StateSerializationError(String),

    // HostFunctionError
    HostFunctionNotDeclared(String),
    HostFunctionFailed(String),

    // ReceiptError
    ReceiptSerializationError(String),

    // InternalInvariantError
    InternalError(String),
}

impl fmt::Display for AivmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AivmError::BadMagic => write!(f, "BytecodeError: bad magic"),
            AivmError::UnsupportedBytecodeVersion(v) => write!(f, "BytecodeError: unsupported bytecode version {}", v),
            AivmError::UnsupportedAivmVersion(v) => write!(f, "BytecodeError: unsupported AIVM version {}", v),
            AivmError::MalformedSection { section_type, reason } => write!(f, "BytecodeError: malformed section {}: {}", section_type, reason),
            AivmError::DuplicateSection(t) => write!(f, "BytecodeError: duplicate section {}", t),
            AivmError::JumpTargetOutOfBounds(t) => write!(f, "BytecodeError: jump target {} out of bounds", t),
            AivmError::OperandOutOfBounds { offset, needed, available } => write!(f, "BytecodeError: operand out of bounds at {} (need {} have {})", offset, needed, available),
            AivmError::AbiHashMismatch => write!(f, "BytecodeError: ABI hash mismatch"),
            AivmError::ManifestHashMismatch => write!(f, "BytecodeError: manifest hash mismatch"),
            AivmError::CodeHashMismatch => write!(f, "BytecodeError: code hash mismatch"),
            AivmError::TruncatedBytecode => write!(f, "BytecodeError: truncated bytecode"),
            AivmError::Trap { code, message } => write!(f, "RuntimeTrap: trap code {} - {}", code, message),
            AivmError::GasExhausted { used, limit } => write!(f, "GasError: exhausted {} / {}", used, limit),
            AivmError::PqGasExhausted { used, limit } => write!(f, "PqGasError: exhausted {} / {}", used, limit),
            other => write!(f, "{:?}", other),
        }
    }
}

impl std::error::Error for AivmError {}

/// Trap codes per spec (0x70 TRAP operand)
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrapCode {
    Generic = 0,
    Overflow = 1,
    Underflow = 2,
    DivisionByZero = 3,
    OutOfBounds = 4,
    Unauthorized = 5,
    InvalidInput = 6,
    StateError = 7,
    HostFunctionError = 8,
    UserTrap = 0xFFFF,
}

impl From<u16> for TrapCode {
    fn from(code: u16) -> Self {
        match code {
            0 => TrapCode::Generic,
            1 => TrapCode::Overflow,
            2 => TrapCode::Underflow,
            3 => TrapCode::DivisionByZero,
            4 => TrapCode::OutOfBounds,
            5 => TrapCode::Unauthorized,
            6 => TrapCode::InvalidInput,
            7 => TrapCode::StateError,
            8 => TrapCode::HostFunctionError,
            _ => TrapCode::UserTrap,
        }
    }
}
