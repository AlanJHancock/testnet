//! Host functions per synq-language-spec.md
//!
//! v0.1 host ABI names:
//!   state.read, state.write, event.emit,
//!   context.chain_id, context.network_id,
//!   context.caller, context.contract_address

use crate::context::ExecutionContext;
use crate::errors::AivmError;
use crate::gas::{pq_gas_cost, PqGasMeter};
use crate::receipt::EventRecord;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
// Real AEG1 frame decode/dispatch -- the SAME `aeg1` submodule the native vm
// crate already uses (`use pqc_shims::aeg1;` in vm/src/vm.rs). It lives
// inside the synq-pqc-shims crate aivm already depends on for
// dilithium/falcon/kyber/sphincs, so no new Cargo dependency is needed.
use synq_pqc_shims::aeg1;
use ruint::aliases::U256;

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
                "auth.envelope".to_string(),          // 22
                "pqc.dilithium_verify".to_string(), // 23 -- ML-DSA-65, real pqcrypto verify, PQ-gas metered per synq-pq-gas-spec.md
                "pqc.falcon_verify".to_string(),     // 24 -- FN-DSA-512, real pqcrypto verify. PQ-gas cost NOT YET in synq-pq-gas-spec.md (v0.1 only covers ML-DSA-65) -- flagged for Justin, metered as ordinary HOST_CALL gas only until the spec is extended.
                "pqc.kyber_decaps".to_string(),      // 25 -- ML-KEM-768 decapsulate. Dry-run/off-chain sandbox ONLY (see aegis-pqvm README + legacy vm crate's ACTS-15 §3 comment): takes a raw secret key as an argument, which must never be deterministic on-chain calldata. Same gas caveat as falcon_verify.
                "pqc.kyber_encapsulate".to_string(),    // 26 -- AEG1 protocol has no KEM-encapsulate slot; hard-reverts (see execute_host_call arm)
                "pqc.mceliece_encapsulate".to_string(), // 27 -- AEG1 protocol has no McEliece slot; hard-reverts
                "pqc.mceliece_decapsulate".to_string(), // 28 -- AEG1 protocol has no McEliece slot; hard-reverts
                "pqc.hqc_encapsulate".to_string(),      // 29 -- AEG1 protocol has no HQC slot; hard-reverts
                "pqc.hqc_decapsulate".to_string(),      // 30 -- AEG1 protocol has no HQC slot; hard-reverts
                "pqc.aegis_call".to_string(),      // 31 -- generic AEG1 frame dispatch (aegis_call/aegis_verify/aegis_decaps synonyms)
                "pqc.sphincs_verify".to_string(),  // 32 -- SLH-DSA-SHAKE-128s, real pqcrypto verify (legacy pre-AEG1 path -- no AEG1 op slot exists for SPHINCS+)
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
    /// Full 256-bit unsigned integer (2026-09-09, U256 support) -- SynQ's
    /// `u256` type was previously truncated to `Value::U128` end to end
    /// (compiler literal parsing, ABI mapping, arg decoding, and every
    /// arithmetic opcode), silently capping every `u256`-declared value at
    /// `u128::MAX` (~3.4e38). This variant is the real thing: backed by
    /// the SAME `ruint::aliases::U256` the native `vm` crate already uses,
    /// so both execution engines share identical 256-bit semantics.
    /// Values that fit comfortably in `u64`/`u128` still use those
    /// variants (see `from_u256_shrink`) -- this exists specifically for
    /// the numbers that don't.
    U256(U256),
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
    /// Convert to u64. See `as_u128`'s doc comment for the `Value::Address`
    /// case -- this just further downcasts that same identity number,
    /// with the same overflow-checked-downcast behaviour `Value::U128`
    /// already had (a real address's identity slot is almost always
    /// bigger than `u64::MAX`, so this arm exists for completeness/
    /// consistency with other u64 call sites, not because comparisons
    /// should rely on it -- see the `Ne`/`Lt`/`Gt`/`Le`/`Ge` opcodes in
    /// `vm.rs`, which use `as_u128` precisely to avoid this overflow).
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
            Value::U256(v) => {
                if *v > U256::from(u64::MAX) {
                    Err(AivmError::TypeMismatch { expected: "u64", got: "u256_overflow" })
                } else {
                    Ok(v.wrapping_to::<u64>())
                }
            }
            Value::Address(_) => {
                let v = self.as_u128()?;
                if v > u64::MAX as u128 {
                    Err(AivmError::TypeMismatch { expected: "u64", got: "address_identity_overflow" })
                } else {
                    Ok(v as u64)
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
    /// `Value::Address` support (2026-08-25): reads the SAME 16-byte
    /// identity slot `bytes[5..21]` that `as_address()` below writes a
    /// plain number INTO -- this is that conversion's true inverse, not
    /// a repeat of the earlier asset-ownership bug (commit d544966,
    /// "AIVM asset ownership: widen owner/recipient from truncated u128
    /// to full address"). That bug read `bytes[25..41]` -- the address's
    /// zero-padding + 4-byte checksum tail, which is NOT the identity --
    /// so `asset_owner(id) == caller()` could never compare equal. This
    /// is a different call site with a different fix: asset ownership
    /// needs exact, non-lossy identity equality, so it correctly goes
    /// through `as_address()` (full 41-byte, byte-for-byte, via `Eq`)
    /// and MUST NOT use this method. This method exists so `Ne`/`Lt`/
    /// `Gt`/`Le`/`Ge` (see `vm.rs`) can evaluate SynQ source like
    /// `require(to != caller, ...)` -- a plain u256 compared against the
    /// caller's identity -- without crashing with `TypeMismatch`. Reading
    /// the correct `[5..21]` slot means this is the exact round-trip of
    /// `as_address()`'s own numeric-literal encoding, so a caller
    /// synthesized from a plain number reads back as that same number,
    /// and a real wallet address reads back as a stable (if not
    /// intrinsically meaningful) 128-bit number -- sufficient for the
    /// only thing `!=`/`==`-style checks against `caller` need: a
    /// consistent, deterministic value to compare, not a legitimate
    /// numeric quantity.
    pub fn as_u128(&self) -> Result<u128, AivmError> {
        match self {
            Value::U128(v) => Ok(*v),
            Value::U64(v) => Ok(*v as u128),
            Value::U256(v) => {
                if *v > U256::from(u128::MAX) {
                    Err(AivmError::TypeMismatch { expected: "u128", got: "u256_overflow" })
                } else {
                    Ok(v.wrapping_to::<u128>())
                }
            }
            Value::Address(bytes) => {
                let mut buf = [0u8; 16];
                buf.copy_from_slice(&bytes[5..21]);
                Ok(u128::from_be_bytes(buf))
            }
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
    ///
    /// `Value::Bytes`/`Value::Bytes32` support (2026-09-09): a SynQ
    /// `Bytes<20>` state var (the demo `V3Types.owner` pattern -- see
    /// `getOwnerSyna()`) defaults to a zero-length-20 `Value::Bytes`
    /// when never explicitly assigned, NOT a `Value::Address` -- so
    /// `to_tsynq(owner)` on a fresh/uninitialised contract reverted with
    /// `TypeMismatch { expected: "address", got: "bytes" }` even though
    /// the exact same call succeeds in a Live QVM session, because
    /// `vm::vm.rs`'s native `OpCode::AddrEncode` has always accepted
    /// `Value::Bytes` of any length (see its match arms) while this
    /// method -- `addr.encode`'s AIVM-side equivalent, via
    /// `execute_host_call`'s `"addr.encode"` arm -- only accepted
    /// `Address`/`U128`/`U64`. Placement into the 20-byte identity slot
    /// `[5..25]` mirrors `vm.rs`'s `AddrEncode` byte-for-byte (left-pad
    /// if under 20 bytes, keep the last 20 if 21..=32 bytes, reject
    /// anything longer exactly as `vm.rs` does by falling through to its
    /// own `_ => Err` arm) so a `Bytes<20>` identity encodes to the
    /// identical `synw...` string in both execution modes.
    pub fn as_address(&self) -> Result<[u8; 41], AivmError> {
        match self {
            Value::Address(bytes) => Ok(*bytes),
            Value::Bytes(b) => {
                let mut buf = [0u8; 41];
                buf[5..25].copy_from_slice(&Self::bytes_to_id20(b)?);
                Ok(buf)
            }
            Value::Bytes32(b) => {
                let mut buf = [0u8; 41];
                buf[5..25].copy_from_slice(&Self::bytes_to_id20(b)?);
                Ok(buf)
            }
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
            // U256 support (2026-09-09): a value that fits u128 mirrors the
            // U128 arm exactly (byte-identical -- same slot, same numeric
            // meaning, just a wider carrier type), so nothing that already
            // worked changes. A genuinely oversized value (>u128::MAX) has
            // no room in that 16-byte slot, so it falls back to the same
            // 20-byte identity slot [5..25] the Bytes/Bytes32 arms above
            // use (via bytes_to_id20 on its big-endian representation) --
            // consistent placement, not a third convention.
            Value::U256(v) => {
                let mut buf = [0u8; 41];
                if *v <= U256::from(u128::MAX) {
                    buf[5..21].copy_from_slice(&v.wrapping_to::<u128>().to_be_bytes());
                } else {
                    buf[5..25].copy_from_slice(&Self::bytes_to_id20(&v.to_be_bytes::<32>())?);
                }
                Ok(buf)
            }
            other => Err(AivmError::TypeMismatch { expected: "address", got: other.type_name() }),
        }
    }

    /// Normalize an arbitrary-length byte slice into a 20-byte identity,
    /// byte-for-byte matching `vm::vm.rs`'s native `OpCode::AddrEncode`
    /// match arms: left-pad if under 20 bytes, take the last 20 if
    /// 21..=32 bytes, reject (rather than silently truncate) anything
    /// longer than 32 -- `vm.rs` has no arm past 32 bytes either.
    fn bytes_to_id20(b: &[u8]) -> Result<[u8; 20], AivmError> {
        if b.len() == 20 {
            let mut a = [0u8; 20];
            a.copy_from_slice(b);
            Ok(a)
        } else if b.len() < 20 {
            let mut a = [0u8; 20];
            a[20 - b.len()..].copy_from_slice(b);
            Ok(a)
        } else if b.len() <= 32 {
            let mut a = [0u8; 20];
            a.copy_from_slice(&b[b.len() - 20..]);
            Ok(a)
        } else {
            Err(AivmError::TypeMismatch { expected: "address (<=32 bytes)", got: "bytes_too_long" })
        }
    }

    /// Convert to bool
    pub fn as_bool(&self) -> Result<bool, AivmError> {
        match self {
            Value::Bool(b) => Ok(*b),
            Value::U64(v) => Ok(*v != 0),
            Value::U128(v) => Ok(*v != 0),
            Value::U256(v) => Ok(*v != U256::ZERO),
            Value::I64(v) => Ok(*v != 0),
            other => Err(AivmError::TypeMismatch { expected: "bool", got: other.type_name() }),
        }
    }

    /// Widen ANY numeric-like value (or a fixed-size byte string, or a
    /// bool) to a full 256-bit unsigned integer -- the lossless superset
    /// of `as_u128`, used by the arithmetic opcodes (`AddU64`/`SubU64`/...
    /// in `vm.rs`, despite their legacy "U64" names -- see their doc
    /// comments) and by `Eq`/`Lt`/`Gt`/`Ne`/`Le`/`Ge` so any two
    /// numeric-shaped operands compare/compute correctly regardless of
    /// which width they happen to be carried in. Mirrors the native `vm`
    /// crate's `Value::as_u256` byte-for-byte (same address identity
    /// slot, same byte-string padding rule) so both execution engines
    /// widen identically.
    pub fn as_u256(&self) -> Result<U256, AivmError> {
        match self {
            Value::U256(v) => Ok(*v),
            Value::U128(v) => Ok(U256::from(*v)),
            Value::U64(v) => Ok(U256::from(*v)),
            Value::I64(v) => {
                if *v < 0 {
                    Err(AivmError::TypeMismatch { expected: "u256", got: "i64_negative" })
                } else {
                    Ok(U256::from(*v as u64))
                }
            }
            Value::Bool(b) => Ok(if *b { U256::from(1u8) } else { U256::ZERO }),
            Value::Address(bytes) => {
                // Same [5..21] identity-literal slot as_u128 already reads
                // -- widening, not a new convention (see as_u128's doc
                // comment for why this slot, not the real 20-byte pk_hash
                // window, is the right one for numeric-literal round-trips).
                let mut buf = [0u8; 16];
                buf.copy_from_slice(&bytes[5..21]);
                Ok(U256::from(u128::from_be_bytes(buf)))
            }
            Value::Bytes(b) if b.len() <= 32 => {
                let mut arr = [0u8; 32];
                arr[32 - b.len()..].copy_from_slice(b);
                Ok(U256::from_be_bytes::<32>(arr))
            }
            Value::Bytes32(b) => Ok(U256::from_be_bytes::<32>(*b)),
            other => Err(AivmError::TypeMismatch { expected: "u256", got: other.type_name() }),
        }
    }

    /// Narrow a computed U256 result back down to the smallest Value
    /// variant that still holds it exactly -- U64 for anything fitting in
    /// 64 bits, U128 for anything fitting in 128, U256 only when it
    /// genuinely needs the full width. Keeps arithmetic on ordinary small
    /// numbers producing the SAME Value::U64 (and same bare-number JSON
    /// shape via aivm_value_to_json) it always did; only values that
    /// actually exceed u128::MAX start round-tripping as U256 (JSON
    /// decimal string, matching the existing U128 convention).
    pub fn from_u256_shrink(v: U256) -> Value {
        if v <= U256::from(u64::MAX) {
            Value::U64(v.wrapping_to::<u64>())
        } else if v <= U256::from(u128::MAX) {
            Value::U128(v.wrapping_to::<u128>())
        } else {
            Value::U256(v)
        }
    }

    /// Get type name for error messages
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::U64(_) => "u64",
            Value::U128(_) => "u128",
            Value::U256(_) => "u256",
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
            Value::U256(v) => v.to_be_bytes::<32>().to_vec(),
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
            Value::U256(n) => {
                let mut b = vec![0u8];
                if *n <= U256::from(u128::MAX) {
                    b.extend_from_slice(&n.wrapping_to::<u128>().to_be_bytes());
                } else {
                    b.extend_from_slice(&n.to_be_bytes::<32>());
                }
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
            // 2026-08-25: Address keys now canonicalize into the SAME
            // tag-0 numeric bucket as U64/U128/I64/Bool, using the
            // address's 16-byte identity slot [5..21] -- the exact slot
            // as_u128() already reads for the Ne/Lt/Gt/Le/Ge comparison
            // opcodes (see that method's doc comment for why [5..21] is
            // the address's true identity, not [25..41]). Without this,
            // admin_role[caller] = true (write, Address-tagged) and
            // admin_role[1] (read, u256-literal-tagged) landed in
            // DIFFERENT map buckets for the identical numeric identity,
            // even though every comparison operator already treated them
            // as equal. Confirmed live via ComprehensiveToken: isAdmin(1)
            // returned false right after init() made that same address
            // an admin via caller, and delegated roles / transfer()
            // were broken the same way in the other direction. See
            // aivm-scenario-testing-backlog.md item 7 for the full repro.
            // Tag 3 is retired from map keys as a result -- Address no
            // longer gets its own tag, it folds into tag 0 like every
            // other numeric-identity variant.
            Value::Address(d) => {
                let mut b = vec![0u8];
                b.extend_from_slice(&d[5..21]);
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
    /// Full 256-bit value (2026-09-10: widened from `u64`, matching the
    /// language spec's `value: u256` / `asset_balance(...) -> u256`
    /// signature above -- a `u64` cap silently broke any realistic
    /// 18-decimal token amount, the same class of bug as the state-var
    /// u256 arithmetic gap fixed in `vm.rs`'s Add/Sub/Mul/Div/Mod).
    pub value: U256,
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
/// Extract the UTF-8 string content of a `str`-typed `Value` for the
/// string builtins (str_len/str_concat/str_eq). Accepts both
/// `Value::String` (the normal case -- string literals and str-typed
/// state/params all decode to this) and `Value::Bytes` (lenient fallback,
/// consistent with `Value::encode()` treating String/Bytes the same way)
/// so a str-typed value that somehow arrived as raw bytes still works
/// instead of hard-erroring.
fn value_as_str(v: &Value) -> Result<String, AivmError> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Bytes(b) => Ok(String::from_utf8_lossy(b).to_string()),
        other => Err(AivmError::TypeMismatch { expected: "string", got: other.type_name() }),
    }
}

/// Coerce a stack value into raw bytes for PQC host functions
/// (dilithium_verify/falcon_verify/kyber_decaps all take bytes params).
/// Permissive by design -- SynQ bytes args can arrive as a genuine
/// Value::Bytes/Bytes32 (from a previous dry-run's final_state round-trip,
/// or a 32-byte hex literal upgraded to Bytes32 by json_to_aivm_value), or
/// as a Value::String hex literal (with or without the "0x" prefix --
/// SNTS-07 mandates NO prefix, but json_to_aivm_value currently only
/// hex-decodes the 0x-prefixed form, so a bare-hex string still lands here
/// as Value::String and must be decoded, not treated as literal UTF-8).
/// Malformed hex falls back to raw UTF-8 bytes rather than erroring --
/// the downstream pqcrypto verify/decaps calls already fail closed
/// (return false / Err) on structurally invalid input, so there is no
/// safety reason to reject early here.
fn value_as_bytes(v: &Value) -> Vec<u8> {
    match v {
        Value::Bytes(b) => b.clone(),
        Value::Bytes32(b) => b.to_vec(),
        Value::Address(a) => a.to_vec(),
        Value::String(s) => {
            let hex_str = s.strip_prefix("0x").unwrap_or(s);
            hex::decode(hex_str).unwrap_or_else(|_| s.as_bytes().to_vec())
        }
        other => other.encode(),
    }
}

pub fn execute_host_call(
    import_index: u16,
    host: &HostFunctions,
    ctx: &ExecutionContext,
    state: &mut crate::vm::StateOverlay,
    stack: &mut Vec<Value>,
    events: &mut Vec<EventRecord>,
    assets: &mut AssetLedger,
    pq_gas: &mut PqGasMeter,
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
        // ── Post-quantum verification (Phase 5: Quantum-Safe Runtime) ──────
        // Real pqcrypto-backed implementations via synq-pqc-shims (the same
        // crate the legacy vm crate's AEG1 dispatcher and the SSA IR backend
        // already use). Previously dilithium_verify/falcon_verify/kyber_decaps
        // had NO entry in aivm_codegen.rs's host_idx table at all, so calls
        // silently fell through to "unknown function -> Call(0)" and
        // returned whatever the contract's FIRST function returned --
        // completely ignoring the actual signature/key. Fixed 30 Aug 2026.
        "pqc.dilithium_verify" => {
            // dilithium_verify(message: bytes, signature: bytes, publicKey: bytes) -> bool
            // Args pushed in source order -> popped in reverse (publicKey, signature, message).
            let public_key = value_as_bytes(&stack.pop().ok_or(AivmError::StackUnderflow)?);
            let signature  = value_as_bytes(&stack.pop().ok_or(AivmError::StackUnderflow)?);
            let message    = value_as_bytes(&stack.pop().ok_or(AivmError::StackUnderflow)?);

            // synq-pq-gas-spec.md v0.1 "Failure Semantics": malformed keys/
            // signatures are charged parse costs before failure; a full
            // verification attempt (valid or invalid signature) is charged
            // the full verify cost. Parse costs are charged unconditionally
            // (they represent real work the shim does regardless of outcome).
            pq_gas.charge(pq_gas_cost::PARSE_ML_DSA_65_PUBKEY)?;
            pq_gas.charge(pq_gas_cost::PARSE_ML_DSA_65_SIGNATURE)?;
            pq_gas.charge(pq_gas_cost::VERIFY_ML_DSA_65)?;

            let ok = synq_pqc_shims::dilithium::verify(&message, &signature, &public_key);
            stack.push(Value::Bool(ok));
        }
        "pqc.falcon_verify" => {
            // falcon_verify(message: bytes, signature: bytes, publicKey: bytes) -> bool
            // FN-DSA-512, real pqcrypto verify (synq_pqc_shims::falcon).
            // NOTE: synq-pq-gas-spec.md v0.1 only defines PQ-Gas costs for
            // ML-DSA-65 -- there is no protocol-defined FN-DSA cost yet.
            // Per standing policy (never fabricate a PQ-Gas number), this
            // charges NO pq_gas; it relies solely on the flat ordinary
            // gas_cost::HOST_CALL charge the VM already applies to every
            // HostCall before dispatch. Flagged for Justin to extend the
            // spec before this is load-bearing for anything security-critical.
            let public_key = value_as_bytes(&stack.pop().ok_or(AivmError::StackUnderflow)?);
            let signature  = value_as_bytes(&stack.pop().ok_or(AivmError::StackUnderflow)?);
            let message    = value_as_bytes(&stack.pop().ok_or(AivmError::StackUnderflow)?);
            let ok = synq_pqc_shims::falcon::verify(&message, &signature, &public_key);
            stack.push(Value::Bool(ok));
        }
        "pqc.kyber_decaps" => {
            // kyber_decaps(ciphertext: bytes, secretKey: bytes) -> bytes
            // ML-KEM-768 decapsulate, real pqcrypto (synq_pqc_shims::kyber).
            // SECURITY BOUNDARY (matches legacy vm crate's ACTS-15 §3 note
            // and aegis-pqvm's own README scope statement): decapsulation
            // takes a raw secret key as an argument. This is only safe in a
            // throwaway dry-run sandbox (StateOverlay never persists, no
            // real chain attached) -- it must NEVER be reachable from
            // deterministic on-chain/consensus execution, where the
            // "argument" would be public calldata. Same PQ-gas caveat as
            // falcon_verify: no protocol-defined cost yet, ordinary
            // HOST_CALL gas only.
            let secret_key = value_as_bytes(&stack.pop().ok_or(AivmError::StackUnderflow)?);
            let ciphertext = value_as_bytes(&stack.pop().ok_or(AivmError::StackUnderflow)?);
            match synq_pqc_shims::kyber::decaps(&ciphertext, &secret_key) {
                Ok(shared_secret) => stack.push(Value::Bytes(shared_secret)),
                Err(_) => stack.push(Value::Bytes(vec![])),
            }
        }
        // ── AEG1 generic frame dispatch (2026-09-01 follow-up) ─────────────
        // aegis_call/aegis_verify/aegis_decaps: the caller passes an already
        // AEG1-framed byte blob (built by/for the low-level frame ABI -- see
        // pqc-shims/src/aeg1.rs's module doc for the wire format) as the
        // single arg; all three names are synonyms, matching the IR
        // backend's IrOp::AegisCall (compiler/src/ir/builder.rs) and the
        // native VM's OpCode::AegisCall (0x8F, vm.rs). This mirrors that
        // exact native opcode: dispatch via `aeg1::process_frame_deterministic`
        // (NOT the permissive off-chain `aeg1::process_frame`), so ML-KEM
        // decapsulate is correctly REJECTED through this generic path even
        // though AIVM is itself a dry-run sandbox -- `aegis_call` means "do
        // exactly what the deterministic on-chain VM would do with this
        // frame", unlike the separate typed `kyber_decaps` convenience
        // builtin above, which is intentionally documented as an off-chain-
        // only escape hatch. Before this fix, this name had no AIVM host
        // binding at all and fell through to Call(0).
        //
        // PQ-gas: per standing policy (never fabricate a PQ-gas number),
        // this charges the SAME real, already-established per-operation
        // costs as the equivalent typed builtins above -- PARSE_ML_DSA_65_*
        // + VERIFY_ML_DSA_65 for an ML-DSA-65 request, exactly like
        // dilithium_verify -- and charges nothing extra (ordinary HOST_CALL
        // gas only) for FN-DSA / other algorithms / malformed frames /
        // rejected ML-KEM requests, exactly like falcon_verify's documented
        // policy, since synq-pq-gas-spec.md v0.1 only defines a cost for
        // ML-DSA-65. It deliberately does NOT use aeg1::compute_cost() --
        // that's the native VM's own internal ACTS-15 §4 fuel model, a
        // different metering axis, not a "PQ-gas" number this spec defines.
        "pqc.aegis_call" => {
            let frame = value_as_bytes(&stack.pop().ok_or(AivmError::StackUnderflow)?);

            if let Ok(req) = aeg1::Aeg1Request::decode(&frame) {
                if req.operation == aeg1::Operation::MlDsaVerify
                    && req.algorithm == aeg1::Algorithm::MlDsa65
                {
                    pq_gas.charge(pq_gas_cost::PARSE_ML_DSA_65_PUBKEY)?;
                    pq_gas.charge(pq_gas_cost::PARSE_ML_DSA_65_SIGNATURE)?;
                    pq_gas.charge(pq_gas_cost::VERIFY_ML_DSA_65)?;
                }
            }

            match aeg1::process_frame_deterministic(&frame) {
                Ok(response_frame) => match aeg1::Aeg1Response::decode(&response_frame) {
                    Ok(aeg1::Aeg1Response::Ok(result)) => {
                        if result.is_empty() {
                            stack.push(Value::Bool(true)); // verify ops: empty body = verified
                        } else {
                            stack.push(Value::Bytes(result)); // decaps ops: shared secret
                        }
                    }
                    Ok(aeg1::Aeg1Response::Error(_, _)) | Err(_) => {
                        stack.push(Value::Bool(false));
                    }
                },
                Err(_) => stack.push(Value::Bool(false)),
            }
        }
        // sphincs_verify: SPHINCS+ (SLH-DSA-SHAKE-128s) has NO AEG1 operation
        // slot at all (AEG1/ACTS-15 covers only ML-KEM/ML-DSA/FN-DSA) -- same
        // as the native VM and the IR backend, this routes to the pre-AEG1
        // legacy verification path, calling synq_pqc_shims::sphincs::verify
        // directly (real pqcrypto-sphincsplus, not a stub) rather than going
        // through any AEG1 frame at all. No arg-order quirk to correct here
        // (unlike the native VM's legacy 0x83 opcode, which has its own
        // fixed internal pop order) -- this calls the shim function
        // directly with args in natural (message, signature, publicKey)
        // order. No PQ-gas cost defined for SPHINCS+ in synq-pq-gas-spec.md
        // v0.1 (same documented gap as falcon_verify) -- ordinary HOST_CALL
        // gas only.
        "pqc.sphincs_verify" => {
            let public_key = value_as_bytes(&stack.pop().ok_or(AivmError::StackUnderflow)?);
            let signature  = value_as_bytes(&stack.pop().ok_or(AivmError::StackUnderflow)?);
            let message    = value_as_bytes(&stack.pop().ok_or(AivmError::StackUnderflow)?);
            let ok = synq_pqc_shims::sphincs::verify(&message, &signature, &public_key);
            stack.push(Value::Bool(ok));
        }
        // ── AEG1-unsupported PQC builtins (2026-09-01) ──────────────────
        // kyber_encapsulate, mceliece_encapsulate/decapsulate,
        // hqc_encapsulate/decapsulate. AEG1/ACTS-15 defines only
        // ML-KEM-decapsulate, ML-DSA-verify, and FN-DSA-verify -- there is
        // no KEM-encapsulate op and no McEliece/HQC algorithm in the
        // protocol at all. Before this fix these five names had no entry
        // anywhere in this dispatch table (in fact no entry in
        // aivm_codegen.rs's host_idx table either), so a call compiled to
        // Call(0) and silently ran the contract's first function instead,
        // returning unrelated "success" data. Fail closed here exactly
        // like an unimplemented host function, naming the exact builtin --
        // mirrors the native vm crate's OpCode::PqcUnsupported message.
        "pqc.kyber_encapsulate" | "pqc.mceliece_encapsulate" |
        "pqc.mceliece_decapsulate" | "pqc.hqc_encapsulate" |
        "pqc.hqc_decapsulate" => {
            let builtin = name.strip_prefix("pqc.").unwrap_or(name);
            return Err(AivmError::HostFunctionFailed(format!(
                "{}: not supported by the AEG1 protocol (ACTS-15 defines only \
ML-KEM-decapsulate, ML-DSA-verify, and FN-DSA-verify -- no KEM-encapsulate, \
McEliece, or HQC operation slot exists yet)", builtin
            )));
        }
        // String builtins — str_len/str_concat/str_eq (see
        // synq-language-spec.md's str type + these three builtins).
        // These were declared in HostFunctions::default_v01()'s import
        // table (indices 9-11) from the start, and aivm_codegen.rs has
        // always compiled str_len/str_concat/str_eq calls to
        // HostCall(9)/HostCall(10)/HostCall(11) -- but this dispatch
        // match had no arms for "string.length"/"string.concat"/
        // "string.eq", so every call fell through to the `other` catch-
        // all below and returned HostFunctionNotDeclared. This is the
        // ComprehensiveToken blocker: its init()/setTokenName()/
        // setTokenSymbol()/setLabel() all gate on str_len(...) checks,
        // and tokenInfo()/isSymbol() use str_concat/str_eq, so the
        // contract could compile but every one of those calls reverted
        // at runtime.
        "string.length" => {
            // str_len(s: str) -> u256. Byte length of the UTF-8 string
            // (SynQ's `str` has no separate "character count" notion, and
            // this matches Value::encode()'s length-prefix byte count for
            // the same value). Value::U64 rather than Value::U128 --
            // comparison opcodes (Lt/Gt/Le/Ge/Ne used by the require(...)
            // length checks) call as_u64() on both operands regardless of
            // which numeric variant either side is, so U64 compares fine
            // against the u128-downcast literals (64, 8, 32, 0) those
            // require(...) checks use.
            let s = stack.pop().ok_or(AivmError::StackUnderflow)?;
            stack.push(Value::U64(value_as_str(&s)?.len() as u64));
        }
        "string.concat" => {
            // str_concat(a: str, b: str) -> str. Args are pushed in
            // source-written order (a then b), so the LAST-pushed operand
            // (b) is on top and pops first -- same convention as
            // asset.transfer/asset.create above.
            let b = stack.pop().ok_or(AivmError::StackUnderflow)?;
            let a = stack.pop().ok_or(AivmError::StackUnderflow)?;
            let mut out = value_as_str(&a)?;
            out.push_str(&value_as_str(&b)?);
            stack.push(Value::String(out));
        }
        "string.eq" => {
            // str_eq(a: str, b: str) -> bool. Byte-for-byte content
            // equality -- deliberately NOT `a == b` on the raw `Value`
            // (which would also require identical *variants*): a string
            // read back from state and a fresh string literal are both
            // Value::String in practice, but going through value_as_str
            // on both sides keeps this robust if a caller ever stores a
            // str-typed value as Value::Bytes instead.
            let b = stack.pop().ok_or(AivmError::StackUnderflow)?;
            let a = stack.pop().ok_or(AivmError::StackUnderflow)?;
            stack.push(Value::Bool(value_as_str(&a)? == value_as_str(&b)?));
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
            let value = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u256()?;
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
            stack.push(Value::from_u256_shrink(record.value));
        }
        "asset.balance" => {
            let asset_id = stack.pop().ok_or(AivmError::StackUnderflow)?.as_u64()?;
            let value = assets.records.get(&asset_id).filter(|r| r.active).map(|r| r.value).unwrap_or(U256::ZERO);
            stack.push(Value::from_u256_shrink(value));
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
        // Authority model -- see vm/src/vm.rs's LoadAuthority/AuthRequire/
        // AuthIdentity opcodes (0x51-0x53) for the canonical semantics this
        // mirrors. Envelope layout (when present): bytes[0..32] = UMA
        // identity, bytes[32..64] = scope hash, bytes[72..80] = big-endian
        // expiry height (0 = never expires). ctx.authority_envelope is
        // empty by default today (no request path populates a real signed
        // envelope yet, on this backend or the primary IR/VM one), so in
        // practice these currently degrade to the same harmless
        // zero/false the IR/VM backend already returns for an empty
        // envelope -- NOT a hard error like the previous
        // HostFunctionNotDeclared("auth.identity") bug this fixes (found
        // via V3Types.synq's init(), which calls
        // authority_identity(authority_envelope()) directly).
        "auth.envelope" => {
            stack.push(Value::Bytes(ctx.authority_envelope.clone()));
        }
        "auth.require" => {
            // Pops (in source-written-arg order, last arg on top):
            // scope_hash then envelope -- same push/pop convention as
            // asset.transfer/string.concat above.
            let scope_hash = match stack.pop().ok_or(AivmError::StackUnderflow)? {
                Value::Bytes(b) => b,
                Value::Bytes32(b) => b.to_vec(),
                Value::U64(n) => { let mut b = vec![0u8; 24]; b.extend_from_slice(&n.to_be_bytes()); b }
                Value::U128(n) => n.to_be_bytes().to_vec(),
                other => return Err(AivmError::TypeMismatch { expected: "bytes (scope_hash)", got: other.type_name() }),
            };
            let envelope = match stack.pop().ok_or(AivmError::StackUnderflow)? {
                Value::Bytes(b) => b,
                Value::Bytes32(b) => b.to_vec(),
                other => return Err(AivmError::TypeMismatch { expected: "bytes (envelope)", got: other.type_name() }),
            };
            if envelope.len() < 80 {
                stack.push(Value::Bool(false));
            } else {
                let env_scope = &envelope[32..64];
                let env_expiry = u64::from_be_bytes(envelope[72..80].try_into().unwrap_or([0u8; 8]));
                let scope_matches = env_scope == scope_hash.as_slice()
                    || env_scope.iter().all(|&b| b == 0); // devnet wildcard
                let not_expired = env_expiry == 0 || env_expiry > ctx.block_height;
                let identity_is_set = envelope[0..32].iter().any(|&b| b != 0);
                stack.push(Value::Bool(scope_matches && not_expired && identity_is_set));
            }
        }
        "auth.identity" => {
            let envelope = match stack.pop().ok_or(AivmError::StackUnderflow)? {
                Value::Bytes(b) => b,
                Value::Bytes32(b) => b.to_vec(),
                other => return Err(AivmError::TypeMismatch { expected: "bytes (envelope)", got: other.type_name() }),
            };
            if envelope.len() < 32 {
                stack.push(Value::Bytes32([0u8; 32]));
            } else {
                let mut identity = [0u8; 32];
                identity.copy_from_slice(&envelope[0..32]);
                stack.push(Value::Bytes32(identity));
            }
        }
        // addr.encode / addr.decode (2026-09-09): these two names have been
        // in HostFunctions::default_v01()'s import table since the address
        // builtins were added (indices 17/18 -- aivm_codegen.rs's host_idx
        // table has compiled to_tsynq/to_syna/from_tsynq/from_syn/from_syna
        // calls to HostCall(17)/HostCall(18) all along), but this dispatch
        // match had no arms for either name -- every call fell through to
        // the `other` catch-all below and returned
        // HostFunctionNotDeclared("addr.encode"), exactly the
        // string.length/concat/eq gap documented above. Any contract using
        // to_tsynq(caller)/to_tsynq(owner) for a human-readable getter (the
        // demo V3Types.getCallerSyna()/getOwnerSyna() pattern) could compile
        // but always reverted at runtime in AIVM dry-run, while the same
        // call succeeded in a Live QVM session (native vm crate's
        // OpCode::AddrEncode has always had a real implementation). Wired
        // to the addr module (a self-contained port of vm::bech32's CURRENT
        // synw-wallet encoding -- see addr.rs's module doc for why it's a
        // port rather than a cross-crate dep on synq-vm, and for what's
        // deliberately NOT covered: legacy tsynq/synq decode and the
        // Phase-3-gated contract-address derivation).
        "addr.encode" => {
            // to_tsynq(x)/to_syna(x): x is whatever the argument expression
            // evaluates to -- typically caller()/call_sender() (a real
            // Value::Address) or an owner state var round-tripped through
            // as_address() if it was ever assigned from caller. as_address()
            // already normalizes any of AIVM's numeric Value variants into
            // the same 41-byte layout caller()/call_sender() push, so this
            // one call covers every input shape the language allows here.
            let v = stack.pop().ok_or(AivmError::StackUnderflow)?;
            let addr41 = v.as_address()?;
            // pk_hash occupies bytes[5..37] of the 41-byte layout (see
            // as_address's doc comment + vm::bech32::SynqAddress::to_bytes);
            // its leading 20 bytes are the VM's internal identifier --
            // exact analogue of vm::bech32::SynqAddress::to_20_bytes().
            let mut id20 = [0u8; 20];
            id20.copy_from_slice(&addr41[5..25]);
            let encoded = crate::addr::encode_wallet_address(&id20)
                .map_err(|e| AivmError::HostFunctionFailed(format!("addr.encode: {}", e)))?;
            stack.push(Value::String(encoded));
        }
        "addr.decode" => {
            // from_tsynq(s)/from_syn(s)/from_syna(s): s is a str-typed
            // Bech32m address. Rebuilds the full 41-byte SynqAddress-shaped
            // value so the result is byte-for-byte identical to what
            // context.caller/context.call_sender would push for the same
            // underlying wallet (see decoded_id_to_address_bytes's doc
            // comment) -- round-tripping a value through addr.decode then
            // addr.encode reproduces the original string.
            let v = stack.pop().ok_or(AivmError::StackUnderflow)?;
            let s = value_as_str(&v)?;
            let id20 = crate::addr::decode_network_address(&s)
                .map_err(|e| AivmError::HostFunctionFailed(format!("addr.decode: {}", e)))?;
            stack.push(Value::Address(crate::addr::decoded_id_to_address_bytes(&id20)));
        }
        other => {
            return Err(AivmError::HostFunctionNotDeclared(other.to_string()));
        }
    }

    Ok(())
}
