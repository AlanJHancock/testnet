//! SQSP signing payload format per synq-signing-payload-spec.md
//!
//! Magic: SQSP (0x51535054... wait, ASCII SQSP = 0x53 0x51 0x53 0x50)
//! Layout: magic(4B) + version(2B) + domain_id(2B) + chain_id(8B) +
//!         network_id_len(2B) + network_id(N) + protocol_version(2B) +
//!         algorithm_id(2B) + signature_purpose(2B) + nonce(8B) +
//!         not_before(8B) + expiration(8B) + signer_addr_len(2B) + signer_addr(N) +
//!         payload_hash(32B)

use crate::errors::AivmError;
use sha2::{Digest, Sha256};

/// Magic bytes: ASCII "SQSP"
pub const MAGIC: [u8; 4] = *b"SQSP";

/// Payload version
pub const PAYLOAD_VERSION: u16 = 1;

/// Domain IDs per spec
pub mod domain {
    pub const TX: u16 = 0x0001;
    pub const CONTRACT_DEPLOY: u16 = 0x0002;
    pub const CONTRACT_CALL: u16 = 0x0003;
    pub const VALIDATOR_MESSAGE: u16 = 0x0004;
    pub const AIVM_RECEIPT: u16 = 0x0005;
    pub const STATE_COMMITMENT: u16 = 0x0006;
    pub const WALLET_AUTH: u16 = 0x0007;
    pub const CROSS_CHAIN_MESSAGE: u16 = 0x0008;
}

/// Algorithm IDs per security policy spec
pub mod algorithm {
    pub const ML_DSA_44: u16 = 0x0101;
    pub const ML_DSA_65: u16 = 0x0102;
    pub const ML_DSA_87: u16 = 0x0103;
    pub const FN_DSA_512: u16 = 0x0201;
    pub const FN_DSA_1024: u16 = 0x0202;
    pub const SLH_DSA_SHA2_128S: u16 = 0x0301;
    pub const SLH_DSA_SHA2_192S: u16 = 0x0302;
    pub const SLH_DSA_SHA2_256S: u16 = 0x0303;
    pub const HQC_128: u16 = 0x0401;
    pub const HQC_192: u16 = 0x0402;
    pub const HQC_256: u16 = 0x0403;
    pub const CLASSIC_MCELIECE_348864: u16 = 0x0501;
}

/// Signing payload wrapper
#[derive(Debug, Clone)]
pub struct SigningPayload {
    pub domain_id: u16,
    pub chain_id: u64,
    pub network_id: String,
    pub protocol_version: u16,
    pub algorithm_id: u16,
    pub signature_purpose: u16,
    pub nonce: u64,
    pub not_before: u64, // unix seconds, 0 if unused
    pub expiration: u64, // unix seconds
    pub signer_address: Vec<u8>, // canonical address bytes
    pub payload_hash: [u8; 32],  // SHA-256 of artifact-specific payload body
}

impl SigningPayload {
    /// Encode to binary per spec layout
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&PAYLOAD_VERSION.to_be_bytes());
        buf.extend_from_slice(&self.domain_id.to_be_bytes());
        buf.extend_from_slice(&self.chain_id.to_be_bytes());
        buf.extend_from_slice(&(self.network_id.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.network_id.as_bytes());
        buf.extend_from_slice(&self.protocol_version.to_be_bytes());
        buf.extend_from_slice(&self.algorithm_id.to_be_bytes());
        buf.extend_from_slice(&self.signature_purpose.to_be_bytes());
        buf.extend_from_slice(&self.nonce.to_be_bytes());
        buf.extend_from_slice(&self.not_before.to_be_bytes());
        buf.extend_from_slice(&self.expiration.to_be_bytes());
        buf.extend_from_slice(&(self.signer_address.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.signer_address);
        buf.extend_from_slice(&self.payload_hash);
        buf
    }

    /// Decode from binary
    pub fn decode(bytes: &[u8]) -> Result<Self, AivmError> {
        if bytes.len() < 4 + 2 + 2 + 8 + 2 {
            return Err(AivmError::TruncatedBytecode);
        }
        let mut offset = 0;
        let magic: [u8; 4] = bytes[0..4].try_into().unwrap();
        if magic != MAGIC {
            return Err(AivmError::BadMagic);
        }
        offset += 4;

        let version = u16::from_be_bytes([bytes[offset], bytes[offset+1]]);
        if version != PAYLOAD_VERSION {
            return Err(AivmError::UnsupportedBytecodeVersion(version));
        }
        offset += 2;

        let domain_id = u16::from_be_bytes([bytes[offset], bytes[offset+1]]);
        offset += 2;

        let chain_id = u64::from_be_bytes([
            bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3],
            bytes[offset+4], bytes[offset+5], bytes[offset+6], bytes[offset+7],
        ]);
        offset += 8;

        let network_id_len = u16::from_be_bytes([bytes[offset], bytes[offset+1]]) as usize;
        offset += 2;

        if offset + network_id_len > bytes.len() {
            return Err(AivmError::TruncatedBytecode);
        }
        let network_id = String::from_utf8(bytes[offset..offset+network_id_len].to_vec())
            .map_err(|e| AivmError::InternalError(format!("network_id UTF-8: {}", e)))?;
        offset += network_id_len;

        let protocol_version = u16::from_be_bytes([bytes[offset], bytes[offset+1]]);
        offset += 2;
        let algorithm_id = u16::from_be_bytes([bytes[offset], bytes[offset+1]]);
        offset += 2;
        let signature_purpose = u16::from_be_bytes([bytes[offset], bytes[offset+1]]);
        offset += 2;
        let nonce = u64::from_be_bytes([
            bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3],
            bytes[offset+4], bytes[offset+5], bytes[offset+6], bytes[offset+7],
        ]);
        offset += 8;
        let not_before = u64::from_be_bytes([
            bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3],
            bytes[offset+4], bytes[offset+5], bytes[offset+6], bytes[offset+7],
        ]);
        offset += 8;
        let expiration = u64::from_be_bytes([
            bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3],
            bytes[offset+4], bytes[offset+5], bytes[offset+6], bytes[offset+7],
        ]);
        offset += 8;

        let signer_addr_len = u16::from_be_bytes([bytes[offset], bytes[offset+1]]) as usize;
        offset += 2;

        if offset + signer_addr_len + 32 > bytes.len() {
            return Err(AivmError::TruncatedBytecode);
        }
        let signer_address = bytes[offset..offset+signer_addr_len].to_vec();
        offset += signer_addr_len;

        let mut payload_hash = [0u8; 32];
        payload_hash.copy_from_slice(&bytes[offset..offset+32]);

        Ok(Self {
            domain_id,
            chain_id,
            network_id,
            protocol_version,
            algorithm_id,
            signature_purpose,
            nonce,
            not_before,
            expiration,
            signer_address,
            payload_hash,
        })
    }

    /// Compute deploy payload body hash
    pub fn deploy_body_hash(
        bytecode_hash: &[u8; 32],
        manifest_hash: &[u8; 32],
        abi_hash: &[u8; 32],
        deployer_address: &[u8],
        constructor_args_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(bytecode_hash);
        hasher.update(manifest_hash);
        hasher.update(abi_hash);
        hasher.update(deployer_address);
        hasher.update(constructor_args_hash);
        hasher.finalize().into()
    }

    /// Compute call payload body hash
    pub fn call_body_hash(
        contract_address: &[u8],
        method_selector: u32,
        encoded_args_hash: &[u8; 32],
        caller_address: &[u8],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(contract_address);
        hasher.update(method_selector.to_be_bytes());
        hasher.update(encoded_args_hash);
        hasher.update(caller_address);
        hasher.finalize().into()
    }
}
