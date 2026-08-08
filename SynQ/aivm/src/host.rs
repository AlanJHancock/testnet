//! Host functions per synq-language-spec.md
//!
//! v0.1 host ABI names:
//!   state.read, state.write, event.emit,
//!   context.chain_id, context.network_id,
//!   context.caller, context.contract_address

use crate::context::ExecutionContext;
use crate::errors::AivmError;
use crate::receipt::EventRecord;
use sha2::{Digest, Sha256};

/// Host function import index → name mapping
/// Per spec, imports are manifest-declared host functions.
#[derive(Debug, Clone)]
pub struct HostFunctions {
    /// Map from import index to host function name
    pub imports: Vec<String>,
}

impl HostFunctions {
    /// Default host functions for v0.1
    pub fn default_v01() -> Self {
        Self {
            imports: vec![
                "state.read".to_string(),
                "state.write".to_string(),
                "event.emit".to_string(),
                "context.chain_id".to_string(),
                "context.network_id".to_string(),
                "context.caller".to_string(),
                "context.contract_address".to_string(),
            ],
        }
    }

    /// Look up import by index
    pub fn get(&self, index: u16) -> Result<&str, AivmError> {
        self.imports
            .get(index as usize)
            .map(|s| s.as_str())
            .ok_or(AivmError::InvalidImportIndex(index))
    }

    /// Find the import index for a given function name
    pub fn find(&self, name: &str) -> Option<u16> {
        self.imports.iter().position(|s| s == name).map(|i| i as u16)
    }
}

/// AVM stack value — the spec uses u64 as the primary integer type
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    U64(u64),
    U128(u128),
    I64(i64),
    Bool(bool),
    Bytes(Vec<u8>),
    Bytes32([u8; 32]),
    Address([u8; 41]),
    String(String),
    Array(Vec<Value>),
}

impl Value {
    /// Convert to u64
    pub fn as_u64(&self) -> Result<u64, AivmError> {
        match self {
            Value::U64(v) => Ok(*v),
            Value::U128(v) => {
                if *v > u64::MAX as u128 {
                    Err(AivmError::TypeMismatch { expected: "u64", got: "u128_overflow" })
                } else {
                    Ok(*v as u64)
                }
            }
            Value::I64(v) => {
                if *v < 0 {
                    Err(AivmError::TypeMismatch { expected: "u64", got: "i64_negative" })
                } else {
                    Ok(*v as u64)
                }
            }
            Value::Bool(b) => Ok(if *b { 1 } else { 0 }),
            other => Err(AivmError::TypeMismatch { expected: "u64", got: other.type_name() }),
        }
    }

    /// Convert to bool
    pub fn as_bool(&self) -> Result<bool, AivmError> {
        match self {
            Value::Bool(b) => Ok(*b),
            Value::U64(v) => Ok(*v != 0),
            Value::U128(v) => Ok(*v != 0),
            Value::I64(v) => Ok(*v != 0),
            other => Err(AivmError::TypeMismatch { expected: "bool", got: other.type_name() }),
        }
    }

    /// Get type name for error messages
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::U64(_) => "u64",
            Value::U128(_) => "u128",
            Value::I64(_) => "i64",
            Value::Bool(_) => "bool",
            Value::Bytes(_) => "bytes",
            Value::Bytes32(_) => "bytes32",
            Value::Address(_) => "address",
            Value::String(_) => "string",
            Value::Array(_) => "array",
        }
    }

    /// Encode value to bytes per ABI type encoding spec
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Value::Bool(b) => vec![if *b { 1 } else { 0 }],
            Value::U64(v) => v.to_be_bytes().to_vec(),
            Value::U128(v) => v.to_be_bytes().to_vec(),
            Value::I64(v) => v.to_be_bytes().to_vec(),
            Value::Bytes(_) | Value::String(_) => {
                let data = match self {
                    Value::String(s) => s.as_bytes().to_vec(),
                    Value::Bytes(d) => d.clone(),
                    _ => unreachable!(),
                };
                let mut buf = (data.len() as u32).to_be_bytes().to_vec();
                buf.extend(data);
                buf
            }
            Value::Bytes32(data) => data.to_vec(),
            Value::Address(data) => data.to_vec(),
            Value::Array(items) => {
                let mut buf = (items.len() as u32).to_be_bytes().to_vec();
                for item in items {
                    buf.extend(item.encode());
                }
                buf
            }
        }
    }
}

/// Execute a host function call
pub fn execute_host_call(
    import_index: u16,
    host: &HostFunctions,
    ctx: &ExecutionContext,
    state: &mut crate::vm::StateOverlay,
    stack: &mut Vec<Value>,
    events: &mut Vec<EventRecord>,
) -> Result<(), AivmError> {
    let name = host.get(import_index)?;

    match name {
        "state.read" => {
            // Pop key index from stack, push value
            let key = stack.pop()
                .ok_or(AivmError::StackUnderflow)?
                .as_u64()?;
            let val = state.read(key as u16).unwrap_or(Value::U64(0));
            stack.push(val);
        }
        "state.write" => {
            // Pop value and key index from stack
            let val = stack.pop().ok_or(AivmError::StackUnderflow)?;
            let key = stack.pop()
                .ok_or(AivmError::StackUnderflow)?
                .as_u64()?;
            state.write(key as u16, val);
        }
        "event.emit" => {
            // Pop event index and data from stack
            let data = stack.pop().ok_or(AivmError::StackUnderflow)?;
            let event_idx = stack.pop()
                .ok_or(AivmError::StackUnderflow)?
                .as_u64()? as u32;
            let topic: [u8; 32] = Sha256::digest(&data.encode()).into();
            events.push(EventRecord {
                event_index: event_idx,
                topic_hash: topic,
                data: data.encode(),
            });
        }
        "context.chain_id" => {
            stack.push(Value::U64(ctx.chain_id));
        }
        "context.network_id" => {
            stack.push(Value::String(ctx.network_id.clone()));
        }
        "context.caller" => {
            stack.push(Value::Address(ctx.caller));
        }
        "context.contract_address" => {
            stack.push(Value::Address(ctx.contract_address));
        }
        other => {
            return Err(AivmError::HostFunctionNotDeclared(other.to_string()));
        }
    }

    Ok(())
}
