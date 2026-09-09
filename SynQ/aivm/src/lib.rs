//! AIVM — Abstract Instruction Virtual Machine
//!
//! Spec-compliant SynQ execution engine per:
//! - synq-bytecode-spec.md
//! - synq-aivm-execution-spec.md
//! - synq-abi-spec.md
//! - synq-manifest-spec.md
//! - synq-signing-payload-spec.md
//! - synq-receipt-spec.md
//! - synq-pq-gas-spec.md
//! - synq-security-policy-spec.md
//! - synq-chain-1264-integration-spec.md

pub mod errors;
pub mod context;
pub mod bytecode;
pub mod instructions;
pub mod abi;
pub mod manifest;
pub mod signing;
pub mod receipt;
pub mod gas;
pub mod addr;
pub mod host;
pub mod vm;

pub use errors::AivmError;
pub use context::ExecutionContext;
pub use bytecode::{BytecodeArtifact, BytecodeHeader, Section};
pub use instructions::{Instruction, Opcode};
pub use abi::Abi;
pub use manifest::Manifest;
pub use signing::SigningPayload;
pub use receipt::{Receipt, ReceiptStatus, EventRecord};
pub use gas::{GasMeter, PqGasMeter};
pub use host::{HostFunctions, Value};
pub use vm::{Avm, StateOverlay, ExecutionResult, FunctionEntry, FunctionVisibility, FunctionMutability};
