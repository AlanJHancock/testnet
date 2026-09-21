//! Gas + PQ-Gas metering per synq-pq-gas-spec.md
//!
//! Gas meters ordinary execution; PQ-Gas meters post-quantum verification separately.

/// PQ-Gas costs per spec
pub mod pq_gas_cost {
    pub const PARSE_ML_DSA_65_PUBKEY: u64 = 1_000;
    pub const PARSE_ML_DSA_65_SIGNATURE: u64 = 1_500;
    pub const SHA256_PAYLOAD_HASH: u64 = 500;
    pub const DERIVE_SYNQ_ADDRESS: u64 = 800;
    pub const VERIFY_ML_DSA_65: u64 = 50_000;
    pub const VALIDATE_DEPLOY_MANIFEST: u64 = 5_000;
    pub const AUTHORIZE_DEPLOY: u64 = 60_000;
    pub const AUTHORIZE_CALL: u64 = 55_000;
}

/// PQ-Gas limits per spec
pub mod pq_gas_limit {
    pub const DEPLOY: u64 = 300_000;
    pub const CALL: u64 = 200_000;
}

/// Ordinary execution gas costs (AIVM internal, not in spec but needed)
pub mod gas_cost {
    pub const NOP: u64 = 1;
    pub const PUSH_U64: u64 = 2;
    pub const PUSH_BYTES: u64 = 3;
    pub const LOAD_STATE: u64 = 3;
    pub const STORE_STATE: u64 = 5;
    pub const LOAD_LOCAL: u64 = 2;
    pub const STORE_LOCAL: u64 = 2;
    pub const ARITHMETIC: u64 = 5;
    /// BitAnd/BitOr/BitXor/Shl/Shr (2026-09-14, bitwise/shift support) -- priced the same as ARITHMETIC.
    pub const BITWISE: u64 = 5;
    pub const DIVISION: u64 = 10;
    pub const COMPARISON: u64 = 3;
    pub const JUMP: u64 = 5;
    pub const CALL: u64 = 10;
    pub const RET: u64 = 2;
    pub const EMIT: u64 = 20;
    pub const TRAP: u64 = 1;
    pub const HOST_CALL: u64 = 15;
    /// Real cross-contract call (21 Sept 2026) -- costs more than a
    /// plain HOST_CALL since it actually invokes another contract's
    /// function body, not just a single host-native operation.
    pub const EXTERN_CALL: u64 = 25;
    pub const PACK_BASE: u64 = 3;
    pub const PACK_PER_FIELD: u64 = 2;
    pub const ARRAY_GET: u64 = 3;
    pub const ARRAY_SET: u64 = 4;
    /// Map lookup: BTreeMap::get on a canonicalized key -- O(log n) but
    /// priced a bit above ARRAY_GET since it also runs map_key_bytes().
    pub const MAP_GET: u64 = 6;
    /// Map insert: BTreeMap::insert (may clone the map's backing tree on
    /// write in the worst case) -- priced above MAP_GET/ARRAY_SET.
    pub const MAP_SET: u64 = 8;
}

/// Gas meter
#[derive(Debug, Clone)]
pub struct GasMeter {
    pub used: u64,
    pub limit: u64,
}

impl GasMeter {
    pub fn new(limit: u64) -> Self {
        Self { used: 0, limit }
    }

    pub fn charge(&mut self, cost: u64) -> Result<(), crate::errors::AivmError> {
        self.used = self.used
            .checked_add(cost)
            .ok_or(crate::errors::AivmError::InternalError("gas overflow".into()))?;
        if self.used > self.limit {
            return Err(crate::errors::AivmError::GasExhausted {
                used: self.used,
                limit: self.limit,
            });
        }
        Ok(())
    }
}

/// PQ-Gas meter
#[derive(Debug, Clone)]
pub struct PqGasMeter {
    pub used: u64,
    pub limit: u64,
}

impl PqGasMeter {
    pub fn new(limit: u64) -> Self {
        Self { used: 0, limit }
    }

    pub fn charge(&mut self, cost: u64) -> Result<(), crate::errors::AivmError> {
        self.used = self.used
            .checked_add(cost)
            .ok_or(crate::errors::AivmError::InternalError("pq-gas overflow".into()))?;
        if self.used > self.limit {
            return Err(crate::errors::AivmError::PqGasExhausted {
                used: self.used,
                limit: self.limit,
            });
        }
        Ok(())
    }
}
