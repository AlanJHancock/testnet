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
    /// Keyed map state (`map<K, V>`, including nested `map<K, map<K, V>>`).
    /// Keyed by a canonical byte encoding of the key value (see
    /// `Value::map_key_bytes`) rather than by the raw `Value` itself, so a
    /// logical key (e.g. the u256 `55`) always lands in the same bucket
    /// regardless of which numeric `Value` variant (`U64`/`U128`) decoded
    /// it -- ints and bools share one canonicalized numeric encoding
    /// (see `map_key_bytes`), while bytes/address/string keys keep their
    /// own tagged encoding so distinct types never collide.
    Map(std::collections::BTreeMap<Vec<u8>, Value>),
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
    /// plain numeric values that happen to be u256 at the SynQ language
    /// level but truncated to u128 in AIVM's simplified numeric model,
    /// matching the existing u256 -> u128 downcast convention).
    ///
    /// NOTE: identity/address values (asset owner/recipient) should go
    /// through `as_address` instead -- this used to also handle
    /// `Value::Address` by reading `bytes[25..41]`, which is that
    /// address's zero-padding + 4-byte checksum, not its actual identity
    /// (same root bug fixed in `as_address` and `asset.create` below).
    /// Address is deliberately no longer accepted here so a caller can't
    /// silently get a checksum-derived number again by mistake.
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
            other => Err(AivmError::TypeMismatch { expected: "u128", got: other.type_name() }),
        }
    }

    /// Convert to a full 41-byte SynqAddress-shaped identity value --
    /// the non-lossy counterpart of `as_u128` for asset owner/recipient
    /// identifiers. `Value::Address` (what `caller()`/`call_sender()`
    /// actually produce) passes through byte-for-byte, so
    /// `asset_owner(id) == caller()` and `asset_transfer(id, caller())`
    /// compare/store the *exact* identity with no truncation.
    ///
    /// A plain number (e.g. a literal passed where an address is
    /// expected) is right-aligned into the same byte range a real
    /// SynqAddress keeps its identity in (`[5..21]`, see
    /// `vm::bech32::SynqAddress::to_bytes`/`from_20_bytes`), zero
    /// elsewhere, so repeated reads of that same value stay internally
    /// consistent even though it isn't a real wallet address.
    pub fn as_address(&self) -> Result<[u8; 41], AivmError> {
        match self {
            Value::Address(bytes) => Ok(*bytes),
            Value::U128(v) => {
                let mut buf = [0u8; 41];
                buf[5..21].copy_from_slice(&v.to_be_bytes());
                Ok(buf)
            }
            Value::U64(v) => {
                let mut buf = [0u8; 41];
                buf[13..21].copy_from_slice(&v.to_be_bytes());
                Ok(buf)
            }
            other => Err(AivmError::TypeMismatch { expected: "address", got: other.type_name() }),
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
            Value::Map(_) => "map",
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
            Value::Map(entries) => {
                let mut buf = (entries.len() as u32).to_be_bytes().to_vec();
                for (k, v) in entries {
                    buf.extend((k.len() as u32).to_be_bytes());
                    buf.extend(k);
                    buf.extend(v.encode());
                }
                buf
            }
        }
    }

    /// Canonicalize a `Value` used as a map key into bytes suitable for a
    /// `BTreeMap<Vec<u8>, Value>` lookup. Every integer-ish variant
    /// (`U64`/`U128`/`I64`/`Bool`) shares ONE tag + a fixed 16-byte
    /// big-endian body, so `map[55]` finds the same bucket whether `55`
    /// arrived as `Value::U64(55)` or `Value::U128(55)` -- this is what a
    /// SynQ `u256` map key is supposed to mean regardless of which AIVM
    /// scalar variant the wire decoder happened to pick. Byte-shaped
    /// variants (`Bytes`/`Bytes32`/`Address`/`String`) get their own
    /// distinct tag so two different types never collide even if their
    /// raw bytes happen to match.
    pub fn map_key_bytes(&self) -> Vec<u8> {
        match self {
            Value::U64(n) => {
                let mut b = vec![0u8];
                b.extend_from_slice(&(*n as u128).to_be_bytes());
                b
            }
            Value::U128(n) => {
                let mut b = vec![0u8];
                b.extend_from_slice(&n.to_be_bytes());
                b
            }
            Value::I64(n) => {
                let mut b = vec![0u8];
                b.extend_from_slice(&((*n as i128) as u128).to_be_bytes());
                b
            }
            Value::Bool(v) => vec![0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, if *v { 1 } else { 0 }],
            Value::Bytes(d) => {
                let mut b = vec![1u8];
                b.extend_from_slice(d);
                b
            }
            Value::Bytes32(d) => {
                let mut b = vec![2u8];
                b.extend_from_slice(d);
                b
            }
            Value::Address(d) => {
                let mut b = vec![3u8];
                b.extend_from_slice(d);
                b
            }
            Value::String(s) => {
                let mut b = vec![4u8];
                b.extend_from_slice(s.as_bytes());
                b
            }
            // Arrays/maps aren't valid map keys in SynQ's type system --
            // degrade to a fixed marker rather than panicking, matching
            // this VM's overall philosophy of failing soft on state ops.
            Value::Array(_) | Value::Map(_) => vec![5u8],
        }
    }
}

/// A single tracked asset (per synq-language-spec.md linear asset model).
/// Mirrors the QVM's AssetRecord (vm/src/vm.rs) semantics: assets are
/// consumed-and-reissued on transfer (old id deactivated, new id minted),
/// and burn/balance/owner all read as zero/inactive once burned.
#[derive(Debug, Clone)]
pub struct AssetRecord {
    /// Full 41-byte SynqAddress bytes -- same representation
    /// `context.caller`/`context.call_sender` push as `Value::Address`, so
    /// `asset_owner(id) == caller()` compares byte-for-byte with zero
    /// truncation (see `Value::as_address` doc comment for the history of
    /// why this used to be a lossy `u128`).
    pub owner: [u8; 41],
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
            // Owner is ctx.caller verbatim -- the exact same 41-byte
            // Value::Address bytes context.caller()/context.call_sender()
            // push onto the stack. No slicing, no truncation: this used
            // to extract a lossy u128 out of the wrong byte range
            // (caller[25..41], the address's zero-padding + 4-byte
            // checksum -- see git history), which meant checkOwner()
            // could never equal caller() and every asset ended up
            // "owned" by a small checksum-derived number unrelated to
            // the connected wallet. Storing the full address makes
            // `asset_owner(id) == caller()` compare byte-for-byte, and
            // asset_owner() now returns the same Value::Address type
            // caller()/call_sender() already return, so both sides of
            // that comparison are the same variant for the first time.
            let owner = ctx.caller;
            let id = assets.next_id;
            assets.next_id += 1;
            assets.records.insert(id, AssetRecord { owner, value, type_tag, active: true });
            stack.push(Value::U64(id));
        }
        "asset.transfer" => {
            // as_address (not as_u128): `to` is normally caller() (a
            // Value::Address) when a contract does asset_transfer(id,
            // caller()) to reclaim/reassign an asset -- as_address passes
            // that through byte-for-byte instead of truncating it into a
            // checksum-derived number the way the old as_u128 path did.
            let to = stack.pop().ok_or(AivmError::StackUnderflow)?.as_address()?;
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
            // Value::Address, matching what caller()/call_sender() push --
            // was Value::U128(owner) reading a lossy truncated number,
            // which also meant this could never structurally equal
            // caller() in a require(asset_owner(id) == caller()) check
            // (different enum variants never compare equal). Zero address
            // (not 0u128) for the "no such active asset" case, consistent
            // with the real type.
            let owner = assets.records.get(&asset_id).filter(|r| r.active).map(|r| r.owner).unwrap_or([0u8; 41]);
            stack.push(Value::Address(owner));
        }
        other => {
            return Err(AivmError::HostFunctionNotDeclared(other.to_string()));
        }
    }

    Ok(())
}
