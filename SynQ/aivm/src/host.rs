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
use std::collections::HashMap;

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
                "state.read".to_string(),           // 0
                "state.write".to_string(),          // 1
                "event.emit".to_string(),           // 2
                "context.chain_id".to_string(),     // 3
                "context.network_id".to_string(),   // 4
                "context.caller".to_string(),       // 5
                "context.contract_address".to_string(), // 6
                "context.call_sender".to_string(),  // 7
                "extern.call".to_string(),           // 8
                "string.length".to_string(),        // 9
                "string.concat".to_string(),        // 10
                "string.eq".to_string(),            // 11
                "asset.create".to_string(),         // 12
                "asset.transfer".to_string(),       // 13
                "asset.burn".to_string(),           // 14
                "asset.balance".to_string(),        // 15
                "asset.owner".to_string(),          // 16
                "addr.encode".to_string(),           // 17
                "addr.decode".to_string(),           // 18
                "addr.contract_address".to_string(), // 19
                "auth.require".to_string(),          // 20
                "auth.identity".to_string(),          // 21
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

    /// Convert to u128 (widest native integer AIVM carries -- used for
    /// asset owner/recipient identifiers, which are u256 at the SynQ
    /// language level but truncated to u128 in AIVM's simplified numeric
    /// model, matching the existing u256 -> u128 downcast convention).
    pub fn as_u128(&self) -> Result<u128, AivmError> {
        match self {
            Value::U128(v) => Ok(*v),
            Value::U64(v) => Ok(*v as u128),
            Value::I64(v) => {
                if *v < 0 {
                    Err(AivmError::TypeMismatch { expected: "u128", got: "i64_negative" })
                } else {
                    Ok(*v as u128)
                }
            }
            Value::Bool(b) => Ok(if *b { 1 } else { 0 }),
            Value::Address(bytes) => {
                let mut buf = [0u8; 16];
                buf.copy_from_slice(&bytes[25..41]);
                Ok(u128::from_be_bytes(buf))
            }
            other => Err(AivmError::TypeMismatch { expected: "u128", got: other.type_name() }),
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

/// A single tracked asset (per synq-language-spec.md linear asset model).
/// Mirrors the QVM's AssetRecord (vm/src/vm.rs) semantics: assets are
/// consumed-and-reissued on transfer (old id deactivated, new id minted),
/// and burn/balance/owner all read as zero/inactive once burned.
#[derive(Debug, Clone)]
pub struct AssetRecord {
    pub owner: u128,
    pub value: u64,
    pub type_tag: String,
    pub active: bool,
}

/// Asset ledger for a single `Avm::execute`/`execute_with_assets` call.
/// `execute()` always starts from an empty ledger (true one-shot dry run).
/// `execute_with_assets()` takes the ledger by reference so a caller that
/// wants asset records to persist across separate dry-run calls the same
/// way declared state does can seed it via `with_records` beforehand and
/// read it back via `snapshot` afterwards (see synq-server's
/// aivm_handler.rs, which does exactly this alongside StateOverlay's
/// existing committed_snapshot chaining -- fixed 2026-08-22, see
/// asset_ledger_persists_across_chained_dry_runs below).
#[derive(Debug, Clone)]
pub struct AssetLedger {
    records: HashMap<u64, AssetRecord>,
    next_id: u64,
}

impl AssetLedger {
    pub fn new() -> Self {
        Self { records: HashMap::new(), next_id: 1 }
    }

    /// Rebuild a ledger from records + the next-id counter carried over from
    /// a previous `Avm::execute_with_assets` call -- the asset-lifecycle
    /// counterpart of `StateOverlay::with_state`. `next_id` must be passed
    /// explicitly (not inferred as max(records)+1) so ids stay monotonic
    /// even across a burn/transfer that deactivated the highest id.
    pub fn with_records(records: HashMap<u64, AssetRecord>, next_id: u64) -> Self {
        Self { records, next_id: next_id.max(1) }
    }

    /// Snapshot every record for carrying forward into the next dry-run
    /// call, alongside the next-id counter -- the asset-lifecycle
    /// counterpart of `StateOverlay::committed_snapshot`.
    pub fn snapshot(&self) -> (&HashMap<u64, AssetRecord>, u64) {
        (&self.records, self.next_id)
    }
}

impl Default for AssetLedger {
    fn default() -> Self {
        Self::new()
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
    assets: &mut AssetLedger,
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
        "context.call_sender" => {
            stack.push(Value::Address(ctx.caller)); // For now, same as caller
        }
        "extern.call" => {
            // Stub — real cross-contract calls need host runtime support
            let _ = stack.pop();
            stack.push(Value::U64(0));
        }
        // Linear asset model — see docs/SynQ-Language-Specification.md:
        //   asset_create(type_name: string, value: u256) -> u256
        //   asset_transfer(asset_id: u256, to: u256) -> u256 (new asset_id)
        //   asset_burn(asset_id: u256) -> u256 (burned value)
        //   asset_balance(asset_id: u256) -> u256
        //   asset_owner(asset_id: u256) -> u256
        // Args are pushed by aivm_codegen.rs in source-written order, so the
        // LAST-listed parameter ends up on top of the stack (popped first).
        "asset.create" => {
            let value = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u64()?;
            let type_tag_val = stack.pop().ok_or(AivmError::StackUnderflow)?;
            let type_tag = match &type_tag_val {
                Value::String(s) => s.clone(),
                Value::Bytes(b) => String::from_utf8_lossy(b).to_string(),
                other => other.type_name().to_string(),
            };
            let owner = {
                let mut buf = [0u8; 16];
                buf.copy_from_slice(&ctx.caller[25..41]);
                u128::from_be_bytes(buf)
            };
            let id = assets.next_id;
            assets.next_id += 1;
            assets.records.insert(id, AssetRecord { owner, value, type_tag, active: true });
            stack.push(Value::U64(id));
        }
        "asset.transfer" => {
            let to = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u128()?;
            let asset_id = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u64()?;
            let record = assets.records.get(&asset_id)
                .filter(|r| r.active)
                .ok_or_else(|| AivmError::HostFunctionFailed(format!("asset.transfer: asset {} not found or inactive", asset_id)))?
                .clone();
            if let Some(existing) = assets.records.get_mut(&asset_id) {
                existing.active = false;
            }
            let new_id = assets.next_id;
            assets.next_id += 1;
            assets.records.insert(new_id, AssetRecord { owner: to, value: record.value, type_tag: record.type_tag, active: true });
            stack.push(Value::U64(new_id));
        }
        "asset.burn" => {
            let asset_id = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u64()?;
            let record = assets.records.get(&asset_id)
                .filter(|r| r.active)
                .ok_or_else(|| AivmError::HostFunctionFailed(format!("asset.burn: asset {} not found or inactive", asset_id)))?
                .clone();
            if let Some(existing) = assets.records.get_mut(&asset_id) {
                existing.active = false;
            }
            stack.push(Value::U64(record.value));
        }
        "asset.balance" => {
            let asset_id = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u64()?;
            let value = assets.records.get(&asset_id).filter(|r| r.active).map(|r| r.value).unwrap_or(0);
            stack.push(Value::U64(value));
        }
        "asset.owner" => {
            let asset_id = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u64()?;
            let owner = assets.records.get(&asset_id).filter(|r| r.active).map(|r| r.owner).unwrap_or(0);
            stack.push(Value::U128(owner));
        }
        other => {
            return Err(AivmError::HostFunctionNotDeclared(other.to_string()));
        }
    }

    Ok(())
}
