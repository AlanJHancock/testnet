//! Manifest per synq-manifest-spec.md
//!
//! Canonical JSON manifest with SHA-256 hash.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::abi::canonicalize_json;

/// Manifest per spec
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub manifest_version: String,
    pub contract_name: String,
    pub compiler_version: String,
    pub bytecode_hash: String,    // hex32
    pub abi_hash: String,         // hex32
    pub security_policy: serde_json::Value,
    pub required_signature_algorithm: String,
    pub required_chain_id: u64,
    pub required_network_id: String,
    pub required_aivm_version: String,
    pub permissions: Vec<String>,
    pub host_functions: Vec<String>,
    pub storage_schema_hash: String, // hex32
}

impl Manifest {
    /// Canonical JSON encoding (sorted keys, no whitespace)
    pub fn canonical_json(&self) -> Vec<u8> {
        let value = serde_json::to_value(self).unwrap();
        canonicalize_json(&value)
    }

    /// Compute manifest hash
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(&self.canonical_json()).into()
    }

    /// Create a default testnet manifest
    pub fn testnet_default(contract_name: &str, compiler_version: &str) -> Self {
        Self {
            manifest_version: "0.1".to_string(),
            contract_name: contract_name.to_string(),
            compiler_version: compiler_version.to_string(),
            bytecode_hash: format!("{:064x}", 0u128),
            abi_hash: format!("{:064x}", 0u128),
            security_policy: serde_json::json!({
                "chain_bound": true,
                "domain_separation": true
            }),
            required_signature_algorithm: "ML-DSA-65".to_string(),
            required_chain_id: 1264,
            required_network_id: "synergy-testnet".to_string(),
            required_aivm_version: "0.1".to_string(),
            permissions: vec![],
            host_functions: vec![
                "state.read".to_string(),
                "state.write".to_string(),
                "event.emit".to_string(),
                "context.chain_id".to_string(),
                "context.network_id".to_string(),
                "context.caller".to_string(),
                "context.contract_address".to_string(),
            ],
            storage_schema_hash: format!("{:064x}", 0u128),
        }
    }
}

/// Manifest validation result
#[derive(Debug, Clone)]
pub enum ManifestValidation {
    Valid,
    Invalid(crate::errors::AivmError),
}

/// Validate manifest against chain-1264 testnet requirements
pub fn validate_manifest(manifest: &Manifest) -> ManifestValidation {
    if manifest.required_chain_id != 1264 {
        return ManifestValidation::Invalid(crate::errors::AivmError::ManifestChainIdMismatch {
            expected: 1264,
            got: manifest.required_chain_id,
        });
    }

    let network_valid = manifest.required_network_id == "synergy-testnet"
        || manifest.required_network_id == "synergy-testnet-v2";
    if !network_valid {
        return ManifestValidation::Invalid(crate::errors::AivmError::ManifestNetworkIdMismatch {
            expected: "synergy-testnet".to_string(),
            got: manifest.required_network_id.clone(),
        });
    }

    let allowed_algorithms = ["ML-DSA-65"];
    if !allowed_algorithms.contains(&manifest.required_signature_algorithm.as_str()) {
        return ManifestValidation::Invalid(crate::errors::AivmError::ManifestAlgorithmNotAllowed(
            manifest.required_signature_algorithm.clone(),
        ));
    }

    let allowed_host_functions = [
        "state.read", "state.write", "event.emit",
        "context.chain_id", "context.network_id",
        "context.caller", "context.contract_address",
    ];
    for hf in &manifest.host_functions {
        if !allowed_host_functions.contains(&hf.as_str()) {
            return ManifestValidation::Invalid(crate::errors::AivmError::ManifestHostFunctionNotSupported(hf.clone()));
        }
    }

    ManifestValidation::Valid
}
