pub mod opcode;
pub mod bech32;
pub mod vm;
pub mod assembler;

// Re-export for convenience
pub use opcode::{OpCode, VMError};
pub use vm::{QuantumVM, Value, CallContext};
pub use assembler::Assembler;
pub mod uma;
pub mod verify;

pub use verify::{verify, VerificationReport};
