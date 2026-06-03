use serde::{Deserialize, Serialize};
use std::fmt;

use crate::synergy_types::{
    Transaction, SYNERGY_TESTNET_V2_CHAIN_ID, SYNERGY_TESTNET_V2_NETWORK_ID,
};

pub const SYNQ_ADMISSION_CARRIER_PREFIX: &[u8] = b"synq-admission-v1:";
pub const SYNQ_ADMISSION_VERSION: u16 = 1;
pub const SYNQ_CANONICAL_TESTNET_NETWORK_ID: &str = "synergy-testnet";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedSynQNetwork {
    pub chain_id: u64,
    pub node_network_id: String,
    pub pqsynq_network_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SynQAdmissionKind {
    Deploy,
    Call,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQAdmissionEnvelope {
    pub version: u16,
    pub kind: SynQAdmissionKind,
    pub chain_id: u64,
    pub network_id: String,
    pub signer: String,
    pub payload_hash: [u8; 32],
    pub bytecode_hash: Option<[u8; 32]>,
    pub manifest_hash: Option<[u8; 32]>,
    pub abi_hash: Option<[u8; 32]>,
    pub encoded_pqsynq_envelope: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQVerificationSummary {
    pub chain_id: u64,
    pub normalized_network_id: String,
    pub node_network_id: String,
    pub domain: String,
    pub algorithm: String,
    pub signer: String,
    pub payload_hash: [u8; 32],
    pub bytecode_hash: Option<[u8; 32]>,
    pub manifest_hash: Option<[u8; 32]>,
    pub abi_hash: Option<[u8; 32]>,
    pub verified_at_admission: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SynQAdmissionError {
    Decode {
        code: &'static str,
        message: String,
    },
    UnsupportedVersion {
        found: u16,
    },
    UnsupportedKind {
        expected: SynQAdmissionKind,
        found: SynQAdmissionKind,
    },
    NetworkMismatch {
        chain_id: u64,
        network_id: String,
    },
    PqSynQ {
        code: &'static str,
        message: String,
    },
    MissingRequiredField {
        field: &'static str,
    },
    InvalidCarrier {
        code: &'static str,
        message: String,
    },
}

impl SynQAdmissionError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Decode { code, .. } => code,
            Self::UnsupportedVersion { .. } => "SYNQ-VERSION",
            Self::UnsupportedKind { .. } => "SYNQ-KIND",
            Self::NetworkMismatch { chain_id, .. } if *chain_id != SYNERGY_TESTNET_V2_CHAIN_ID => {
                "AEGIS-CHAIN"
            }
            Self::NetworkMismatch { .. } => "AEGIS-NETWORK",
            Self::PqSynQ { code, .. } => code,
            Self::MissingRequiredField { .. } => "SYNQ-MISSING-FIELD",
            Self::InvalidCarrier { code, .. } => code,
        }
    }
}

impl fmt::Display for SynQAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode { code, message } => write!(f, "{code}: {message}"),
            Self::UnsupportedVersion { found } => {
                write!(f, "SYNQ-VERSION: unsupported SynQ carrier version {found}")
            }
            Self::UnsupportedKind { expected, found } => write!(
                f,
                "SYNQ-KIND: expected SynQ {:?} carrier, found {:?}",
                expected, found
            ),
            Self::NetworkMismatch {
                chain_id,
                network_id,
            } => write!(
                f,
                "{}: SynQ carrier network {network_id} is not allowed for chain {chain_id}",
                self.code()
            ),
            Self::PqSynQ { code, message } => write!(f, "{code}: {message}"),
            Self::MissingRequiredField { field } => {
                write!(f, "SYNQ-MISSING-FIELD: missing required field {field}")
            }
            Self::InvalidCarrier { code, message } => write!(f, "{code}: {message}"),
        }
    }
}

impl std::error::Error for SynQAdmissionError {}

pub fn normalize_synq_network(
    chain_id: u64,
    network_id: &str,
) -> Result<NormalizedSynQNetwork, SynQAdmissionError> {
    if chain_id != SYNERGY_TESTNET_V2_CHAIN_ID {
        return Err(SynQAdmissionError::NetworkMismatch {
            chain_id,
            network_id: network_id.to_string(),
        });
    }

    match network_id {
        SYNQ_CANONICAL_TESTNET_NETWORK_ID | SYNERGY_TESTNET_V2_NETWORK_ID => {
            Ok(NormalizedSynQNetwork {
                chain_id,
                node_network_id: network_id.to_string(),
                pqsynq_network_id: SYNQ_CANONICAL_TESTNET_NETWORK_ID.to_string(),
            })
        }
        _ => Err(SynQAdmissionError::NetworkMismatch {
            chain_id,
            network_id: network_id.to_string(),
        }),
    }
}

pub fn encode_synq_admission_carrier(
    envelope: &SynQAdmissionEnvelope,
) -> Result<Vec<u8>, SynQAdmissionError> {
    let mut out = SYNQ_ADMISSION_CARRIER_PREFIX.to_vec();
    let bytes = serde_json::to_vec(envelope).map_err(|error| SynQAdmissionError::Decode {
        code: "AEGIS-CANON",
        message: format!("serialize SynQ admission carrier: {error}"),
    })?;
    out.extend_from_slice(&bytes);
    Ok(out)
}

pub fn decode_synq_admission_carrier(
    payload: &[u8],
) -> Result<Option<SynQAdmissionEnvelope>, SynQAdmissionError> {
    let Some(bytes) = payload.strip_prefix(SYNQ_ADMISSION_CARRIER_PREFIX) else {
        return Ok(None);
    };
    serde_json::from_slice(bytes)
        .map(Some)
        .map_err(|error| SynQAdmissionError::Decode {
            code: "AEGIS-CANON",
            message: format!("decode SynQ admission carrier: {error}"),
        })
}

pub fn is_synq_admission_carrier(payload: &[u8]) -> bool {
    payload.starts_with(SYNQ_ADMISSION_CARRIER_PREFIX)
}

pub fn verify_transaction_payload_for_chain_admission(
    tx: &Transaction,
    now_unix: u64,
) -> Result<Option<SynQVerificationSummary>, SynQAdmissionError> {
    let Some(envelope) = decode_synq_admission_carrier(&tx.payload)? else {
        return Ok(None);
    };
    if envelope.chain_id != tx.chain_id.0 {
        return Err(SynQAdmissionError::NetworkMismatch {
            chain_id: envelope.chain_id,
            network_id: envelope.network_id,
        });
    }
    if envelope.network_id != tx.network_id.0
        && normalize_synq_network(envelope.chain_id, &envelope.network_id)?.pqsynq_network_id
            != normalize_synq_network(tx.chain_id.0, &tx.network_id.0)?.pqsynq_network_id
    {
        return Err(SynQAdmissionError::NetworkMismatch {
            chain_id: envelope.chain_id,
            network_id: envelope.network_id,
        });
    }
    verify_synq_carrier_for_chain_admission(&envelope, now_unix).map(Some)
}

pub fn verify_synq_carrier_for_chain_admission(
    envelope: &SynQAdmissionEnvelope,
    now_unix: u64,
) -> Result<SynQVerificationSummary, SynQAdmissionError> {
    match envelope.kind {
        SynQAdmissionKind::Deploy => verify_synq_deploy_for_chain_admission(envelope, now_unix),
        SynQAdmissionKind::Call => verify_synq_call_for_chain_admission(envelope, now_unix),
    }
}

pub fn verify_synq_deploy_for_chain_admission(
    envelope: &SynQAdmissionEnvelope,
    _now_unix: u64,
) -> Result<SynQVerificationSummary, SynQAdmissionError> {
    ensure_version(envelope)?;
    ensure_kind(envelope, SynQAdmissionKind::Deploy)?;
    ensure_required_hash(envelope.bytecode_hash, "bytecode_hash")?;
    ensure_required_hash(envelope.manifest_hash, "manifest_hash")?;
    ensure_required_hash(envelope.abi_hash, "abi_hash")?;
    normalize_synq_network(envelope.chain_id, &envelope.network_id)?;
    Err(SynQAdmissionError::PqSynQ {
        code: "SYNQ-DISABLED",
        message: "SynQ admission requires a release-safe aegis-pqsynq verifier; default launch runtime rejects SynQ carriers fail-closed".to_string(),
    })
}

pub fn verify_synq_call_for_chain_admission(
    envelope: &SynQAdmissionEnvelope,
    _now_unix: u64,
) -> Result<SynQVerificationSummary, SynQAdmissionError> {
    ensure_version(envelope)?;
    ensure_kind(envelope, SynQAdmissionKind::Call)?;
    normalize_synq_network(envelope.chain_id, &envelope.network_id)?;
    Err(SynQAdmissionError::PqSynQ {
        code: "SYNQ-DISABLED",
        message: "SynQ admission requires a release-safe aegis-pqsynq verifier; default launch runtime rejects SynQ carriers fail-closed".to_string(),
    })
}

fn ensure_version(envelope: &SynQAdmissionEnvelope) -> Result<(), SynQAdmissionError> {
    if envelope.version == SYNQ_ADMISSION_VERSION {
        Ok(())
    } else {
        Err(SynQAdmissionError::UnsupportedVersion {
            found: envelope.version,
        })
    }
}

fn ensure_kind(
    envelope: &SynQAdmissionEnvelope,
    expected: SynQAdmissionKind,
) -> Result<(), SynQAdmissionError> {
    if envelope.kind == expected {
        Ok(())
    } else {
        Err(SynQAdmissionError::UnsupportedKind {
            expected,
            found: envelope.kind,
        })
    }
}

fn ensure_required_hash(
    value: Option<[u8; 32]>,
    field: &'static str,
) -> Result<(), SynQAdmissionError> {
    if value.is_some() {
        Ok(())
    } else {
        Err(SynQAdmissionError::MissingRequiredField { field })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_NOW: u64 = 1_800_000_000;

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn deploy_carrier(network_id: &str) -> SynQAdmissionEnvelope {
        SynQAdmissionEnvelope {
            version: SYNQ_ADMISSION_VERSION,
            kind: SynQAdmissionKind::Deploy,
            chain_id: SYNERGY_TESTNET_V2_CHAIN_ID,
            network_id: network_id.to_string(),
            signer: "synq-test-signer".to_string(),
            payload_hash: hash(9),
            bytecode_hash: Some(hash(1)),
            manifest_hash: Some(hash(2)),
            abi_hash: Some(hash(3)),
            encoded_pqsynq_envelope: b"{}".to_vec(),
        }
    }

    fn call_carrier(network_id: &str) -> SynQAdmissionEnvelope {
        SynQAdmissionEnvelope {
            version: SYNQ_ADMISSION_VERSION,
            kind: SynQAdmissionKind::Call,
            chain_id: SYNERGY_TESTNET_V2_CHAIN_ID,
            network_id: network_id.to_string(),
            signer: "synq-test-signer".to_string(),
            payload_hash: hash(9),
            bytecode_hash: None,
            manifest_hash: None,
            abi_hash: None,
            encoded_pqsynq_envelope: b"{}".to_vec(),
        }
    }

    #[test]
    fn network_alias_normalization_accepts_testnet_names_for_chain_1264() {
        let canonical = normalize_synq_network(
            SYNERGY_TESTNET_V2_CHAIN_ID,
            SYNQ_CANONICAL_TESTNET_NETWORK_ID,
        )
        .expect("canonical testnet accepted");
        assert_eq!(
            canonical.pqsynq_network_id,
            SYNQ_CANONICAL_TESTNET_NETWORK_ID
        );

        let node_alias =
            normalize_synq_network(SYNERGY_TESTNET_V2_CHAIN_ID, SYNERGY_TESTNET_V2_NETWORK_ID)
                .expect("node testnet alias accepted");
        assert_eq!(
            node_alias.pqsynq_network_id,
            SYNQ_CANONICAL_TESTNET_NETWORK_ID
        );
    }

    #[test]
    fn network_alias_normalization_rejects_wrong_chain_and_unrelated_network() {
        let wrong_chain = normalize_synq_network(999, SYNQ_CANONICAL_TESTNET_NETWORK_ID)
            .expect_err("wrong chain rejected");
        assert_eq!(wrong_chain.code(), "AEGIS-CHAIN");

        let wrong_network = normalize_synq_network(SYNERGY_TESTNET_V2_CHAIN_ID, "mainnet")
            .expect_err("wrong network rejected");
        assert_eq!(wrong_network.code(), "AEGIS-NETWORK");
    }

    #[test]
    fn synq_deploy_carrier_fails_closed_without_release_safe_verifier() {
        let error = verify_synq_deploy_for_chain_admission(
            &deploy_carrier(SYNERGY_TESTNET_V2_NETWORK_ID),
            TEST_NOW,
        )
        .expect_err("SynQ deploy carrier rejected without linked verifier");
        assert_eq!(error.code(), "SYNQ-DISABLED");
    }

    #[test]
    fn synq_call_carrier_fails_closed_without_release_safe_verifier() {
        let error = verify_synq_call_for_chain_admission(
            &call_carrier(SYNERGY_TESTNET_V2_NETWORK_ID),
            TEST_NOW,
        )
        .expect_err("SynQ call carrier rejected without linked verifier");
        assert_eq!(error.code(), "SYNQ-DISABLED");
    }

    #[test]
    fn wrong_chain_preserves_aegis_chain_code() {
        let mut carrier = deploy_carrier(SYNERGY_TESTNET_V2_NETWORK_ID);
        carrier.chain_id = 999;
        let error = verify_synq_deploy_for_chain_admission(&carrier, TEST_NOW)
            .expect_err("wrong chain rejected");
        assert_eq!(error.code(), "AEGIS-CHAIN");
    }

    #[test]
    fn malformed_carrier_preserves_canonicalization_code() {
        let error = decode_synq_admission_carrier(b"synq-admission-v1:{not-json")
            .expect_err("malformed carrier rejected");
        assert_eq!(error.code(), "AEGIS-CANON");
    }
}
