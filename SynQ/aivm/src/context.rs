//! ExecutionContext per synq-aivm-execution-spec.md
//! Deterministic context provided to contract execution.

use sha2::{Digest, Sha256};

/// 32-byte hash
pub type Hash32 = [u8; 32];

/// Chain ID — u64, 1266 for testnet
pub type ChainId = u64;

/// Network ID — e.g. "synergy-testnet-v3"
pub type NetworkId = String;

/// SynQ address — 41-byte canonical address bytes per address format spec
pub type SynQAddress = [u8; 41];

/// Security policy from manifest
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    pub required_signature_algorithm: String,
    pub chain_bound: bool,
    pub domain_separation: bool,
    pub required_chain_id: u64,
    pub required_network_id: String,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            required_signature_algorithm: "ML-DSA-65".to_string(),
            chain_bound: true,
            domain_separation: true,
            required_chain_id: 1266,
            required_network_id: "synergy-testnet-v3".to_string(),
        }
    }
}

/// Execution context provided to contract execution.
/// Per spec: "Consensus context values come only from ExecutionContext."
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub block_height: u64,
    pub block_timestamp: u64,
    pub tx_hash: Hash32,
    pub caller: SynQAddress,
    pub contract_address: SynQAddress,
    pub gas_limit: u64,
    pub pq_gas_limit: u64,
    pub security_policy: SecurityPolicy,
}

impl ExecutionContext {
    /// Create a testnet context for testing
    pub fn testnet(caller: SynQAddress, contract_address: SynQAddress) -> Self {
        Self {
            chain_id: 1266,
            network_id: "synergy-testnet-v3".to_string(),
            block_height: 0,
            block_timestamp: 0,
            tx_hash: [0u8; 32],
            caller,
            contract_address,
            gas_limit: 1_000_000,
            pq_gas_limit: 300_000,
            security_policy: SecurityPolicy::default(),
        }
    }

    /// Hash the context for receipt generation
    pub fn context_hash(&self) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update(self.chain_id.to_be_bytes());
        hasher.update(self.network_id.as_bytes());
        hasher.update(self.block_height.to_be_bytes());
        hasher.update(self.block_timestamp.to_be_bytes());
        hasher.update(self.tx_hash);
        hasher.update(self.caller);
        hasher.update(self.contract_address);
        hasher.finalize().into()
    }
}
