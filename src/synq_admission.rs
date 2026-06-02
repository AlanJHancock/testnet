use pqsynq::{
    AegisSynQError, AegisSynQVerifier, AlgorithmId, ChainId, ContractCallEnvelope,
    ContractDeployEnvelope, DomainTag, NetworkId, SynQSecurityPolicy, VerificationContext,
};
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

impl From<AegisSynQError> for SynQAdmissionError {
    fn from(error: AegisSynQError) -> Self {
        Self::PqSynQ {
            code: error.code(),
            message: error.to_string(),
        }
    }
}

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
    now_unix: u64,
) -> Result<SynQVerificationSummary, SynQAdmissionError> {
    ensure_version(envelope)?;
    ensure_kind(envelope, SynQAdmissionKind::Deploy)?;
    ensure_required_hash(envelope.bytecode_hash, "bytecode_hash")?;
    ensure_required_hash(envelope.manifest_hash, "manifest_hash")?;
    ensure_required_hash(envelope.abi_hash, "abi_hash")?;

    let deploy = decode_pqsynq_deploy(envelope)?;
    let payload = &deploy.signing_payload;
    if payload.payload_hash != envelope.payload_hash {
        return Err(SynQAdmissionError::InvalidCarrier {
            code: "AEGIS-CANON",
            message: "carrier payload_hash does not match pqsynq deploy payload".to_string(),
        });
    }
    if Some(deploy.bytecode_hash) != envelope.bytecode_hash
        || Some(deploy.manifest_hash) != envelope.manifest_hash
        || Some(deploy.abi_hash) != envelope.abi_hash
    {
        return Err(SynQAdmissionError::InvalidCarrier {
            code: "AEGIS-CANON",
            message: "carrier deploy hashes do not match pqsynq deploy envelope".to_string(),
        });
    }

    let normalized = normalize_synq_network(envelope.chain_id, &envelope.network_id)?;
    let context = verification_context(&normalized, now_unix);
    let verified = AegisSynQVerifier::testnet_1264().verify_contract_deploy(&deploy, &context)?;
    Ok(SynQVerificationSummary {
        chain_id: normalized.chain_id,
        normalized_network_id: normalized.pqsynq_network_id,
        node_network_id: normalized.node_network_id,
        domain: payload.domain_tag.as_str().to_string(),
        algorithm: algorithm_name(payload.algorithm_id).to_string(),
        signer: verified.deployer.to_testnet_debug_string(),
        payload_hash: payload.payload_hash,
        bytecode_hash: Some(verified.bytecode_hash),
        manifest_hash: Some(verified.manifest_hash),
        abi_hash: Some(verified.abi_hash),
        verified_at_admission: true,
    })
}

pub fn verify_synq_call_for_chain_admission(
    envelope: &SynQAdmissionEnvelope,
    now_unix: u64,
) -> Result<SynQVerificationSummary, SynQAdmissionError> {
    ensure_version(envelope)?;
    ensure_kind(envelope, SynQAdmissionKind::Call)?;

    let call = decode_pqsynq_call(envelope)?;
    let payload = &call.signing_payload;
    if payload.payload_hash != envelope.payload_hash {
        return Err(SynQAdmissionError::InvalidCarrier {
            code: "AEGIS-CANON",
            message: "carrier payload_hash does not match pqsynq call payload".to_string(),
        });
    }

    let normalized = normalize_synq_network(envelope.chain_id, &envelope.network_id)?;
    let context = verification_context(&normalized, now_unix);
    let verified = AegisSynQVerifier::testnet_1264().verify_contract_call(&call, &context)?;
    Ok(SynQVerificationSummary {
        chain_id: normalized.chain_id,
        normalized_network_id: normalized.pqsynq_network_id,
        node_network_id: normalized.node_network_id,
        domain: payload.domain_tag.as_str().to_string(),
        algorithm: algorithm_name(payload.algorithm_id).to_string(),
        signer: verified.caller.to_testnet_debug_string(),
        payload_hash: payload.payload_hash,
        bytecode_hash: envelope.bytecode_hash,
        manifest_hash: envelope.manifest_hash,
        abi_hash: envelope.abi_hash,
        verified_at_admission: true,
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

fn decode_pqsynq_deploy(
    envelope: &SynQAdmissionEnvelope,
) -> Result<ContractDeployEnvelope, SynQAdmissionError> {
    serde_json::from_slice(&envelope.encoded_pqsynq_envelope).map_err(|error| {
        SynQAdmissionError::Decode {
            code: "AEGIS-CANON",
            message: format!("decode pqsynq deploy envelope: {error}"),
        }
    })
}

fn decode_pqsynq_call(
    envelope: &SynQAdmissionEnvelope,
) -> Result<ContractCallEnvelope, SynQAdmissionError> {
    serde_json::from_slice(&envelope.encoded_pqsynq_envelope).map_err(|error| {
        SynQAdmissionError::Decode {
            code: "AEGIS-CANON",
            message: format!("decode pqsynq call envelope: {error}"),
        }
    })
}

fn verification_context(normalized: &NormalizedSynQNetwork, now_unix: u64) -> VerificationContext {
    VerificationContext {
        chain_id: ChainId(normalized.chain_id),
        network_id: NetworkId(normalized.pqsynq_network_id.clone()),
        now_unix,
        policy: SynQSecurityPolicy::testnet_1264_policy(),
    }
}

fn algorithm_name(algorithm: AlgorithmId) -> &'static str {
    match algorithm {
        AlgorithmId::MlDsa44 => "ML-DSA-44",
        AlgorithmId::MlDsa65 => "ML-DSA-65",
        AlgorithmId::MlDsa87 => "ML-DSA-87",
        AlgorithmId::FnDsa => "FN-DSA",
        AlgorithmId::SlhDsaSha2_128s => "SLH-DSA-SHA2-128S",
        AlgorithmId::SlhDsaSha2_192s => "SLH-DSA-SHA2-192S",
        AlgorithmId::SlhDsaSha2_256s => "SLH-DSA-SHA2-256S",
        AlgorithmId::Hqc128 => "HQC-128",
        AlgorithmId::Hqc192 => "HQC-192",
        AlgorithmId::Hqc256 => "HQC-256",
        AlgorithmId::ClassicMcEliece348864 => "Classic-McEliece-348864",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqsynq::{
        canonicalize_signing_payload, derive_synq_address, hash_contract_call_body,
        hash_contract_deploy_body, DigitalSignature, Sign, SignaturePurpose, SynQAddress,
        SynQPublicKey, SynQSignature, SynQSigningPayload,
    };
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::PathBuf;

    const TEST_NOW: u64 = 1_800_000_000;
    const TEST_EXPIRY: u64 = 4_102_444_800;

    #[derive(Clone)]
    struct SignedFixture {
        deploy: ContractDeployEnvelope,
        call: ContractCallEnvelope,
    }

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn signed_fixture() -> SignedFixture {
        let signer = Sign::mldsa65();
        let (public_key_bytes, private_key_bytes) = signer.keygen().expect("keygen");
        let public_key = SynQPublicKey::new(public_key_bytes);
        let signer_address =
            derive_synq_address(&public_key, AlgorithmId::MlDsa65, &NetworkId::testnet())
                .expect("derive signer address");
        let contract_address = SynQAddress::from_bytes(*signer_address.as_bytes());

        let bytecode_hash = hash(1);
        let manifest_hash = hash(2);
        let abi_hash = hash(3);
        let constructor_args_hash = hash(4);
        let deploy_payload_hash = hash_contract_deploy_body(
            &bytecode_hash,
            &manifest_hash,
            &abi_hash,
            signer_address.as_bytes(),
            &constructor_args_hash,
        );
        let deploy_payload = SynQSigningPayload {
            domain_tag: DomainTag::SynqContractDeployV1,
            chain_id: ChainId::testnet_1264(),
            network_id: NetworkId::testnet(),
            protocol_version: 1,
            algorithm_id: AlgorithmId::MlDsa65,
            signature_purpose: SignaturePurpose::ContractDeploy,
            nonce: 1,
            not_before_unix: 0,
            expiration_unix: TEST_EXPIRY,
            signer_address,
            payload_hash: deploy_payload_hash,
        };
        let deploy_sig = signer
            .detached_sign(
                &canonicalize_signing_payload(&deploy_payload).expect("canonical deploy"),
                &private_key_bytes,
            )
            .expect("sign deploy");
        let deploy = ContractDeployEnvelope {
            signing_payload: deploy_payload,
            public_key: public_key.clone(),
            signature: SynQSignature::new(deploy_sig),
            bytecode_hash,
            manifest_hash,
            abi_hash,
            constructor_args_hash,
        };

        let method_selector = [0x12, 0x34, 0x56, 0x78];
        let encoded_args_hash = hash(5);
        let call_payload_hash = hash_contract_call_body(
            contract_address.as_bytes(),
            &method_selector,
            &encoded_args_hash,
            signer_address.as_bytes(),
        );
        let call_payload = SynQSigningPayload {
            domain_tag: DomainTag::SynqContractCallV1,
            chain_id: ChainId::testnet_1264(),
            network_id: NetworkId::testnet(),
            protocol_version: 1,
            algorithm_id: AlgorithmId::MlDsa65,
            signature_purpose: SignaturePurpose::ContractCall,
            nonce: 2,
            not_before_unix: 0,
            expiration_unix: TEST_EXPIRY,
            signer_address,
            payload_hash: call_payload_hash,
        };
        let call_sig = signer
            .detached_sign(
                &canonicalize_signing_payload(&call_payload).expect("canonical call"),
                &private_key_bytes,
            )
            .expect("sign call");
        let call = ContractCallEnvelope {
            signing_payload: call_payload,
            public_key,
            signature: SynQSignature::new(call_sig),
            contract_address,
            method_selector,
            encoded_args_hash,
        };

        SignedFixture { deploy, call }
    }

    fn deploy_carrier(deploy: &ContractDeployEnvelope, network_id: &str) -> SynQAdmissionEnvelope {
        SynQAdmissionEnvelope {
            version: SYNQ_ADMISSION_VERSION,
            kind: SynQAdmissionKind::Deploy,
            chain_id: SYNERGY_TESTNET_V2_CHAIN_ID,
            network_id: network_id.to_string(),
            signer: deploy
                .signing_payload
                .signer_address
                .to_testnet_debug_string(),
            payload_hash: deploy.signing_payload.payload_hash,
            bytecode_hash: Some(deploy.bytecode_hash),
            manifest_hash: Some(deploy.manifest_hash),
            abi_hash: Some(deploy.abi_hash),
            encoded_pqsynq_envelope: serde_json::to_vec(deploy).expect("encode deploy"),
        }
    }

    fn call_carrier(call: &ContractCallEnvelope, network_id: &str) -> SynQAdmissionEnvelope {
        SynQAdmissionEnvelope {
            version: SYNQ_ADMISSION_VERSION,
            kind: SynQAdmissionKind::Call,
            chain_id: SYNERGY_TESTNET_V2_CHAIN_ID,
            network_id: network_id.to_string(),
            signer: call
                .signing_payload
                .signer_address
                .to_testnet_debug_string(),
            payload_hash: call.signing_payload.payload_hash,
            bytecode_hash: None,
            manifest_hash: None,
            abi_hash: None,
            encoded_pqsynq_envelope: serde_json::to_vec(call).expect("encode call"),
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
    fn valid_deploy_carrier_verifies_with_pqsynq() {
        let fixture = signed_fixture();
        let summary = verify_synq_deploy_for_chain_admission(
            &deploy_carrier(&fixture.deploy, SYNERGY_TESTNET_V2_NETWORK_ID),
            TEST_NOW,
        )
        .expect("deploy verifies");
        assert_eq!(summary.chain_id, SYNERGY_TESTNET_V2_CHAIN_ID);
        assert_eq!(summary.domain, "SYNQ_CONTRACT_DEPLOY_V1");
        assert_eq!(summary.algorithm, "ML-DSA-65");
        assert_eq!(
            summary.payload_hash,
            fixture.deploy.signing_payload.payload_hash
        );
    }

    #[test]
    fn valid_call_carrier_verifies_with_pqsynq() {
        let fixture = signed_fixture();
        let summary = verify_synq_call_for_chain_admission(
            &call_carrier(&fixture.call, SYNERGY_TESTNET_V2_NETWORK_ID),
            TEST_NOW,
        )
        .expect("call verifies");
        assert_eq!(summary.chain_id, SYNERGY_TESTNET_V2_CHAIN_ID);
        assert_eq!(summary.domain, "SYNQ_CONTRACT_CALL_V1");
        assert_eq!(summary.algorithm, "ML-DSA-65");
        assert_eq!(
            summary.payload_hash,
            fixture.call.signing_payload.payload_hash
        );
    }

    #[test]
    fn wrong_chain_preserves_aegis_chain_code() {
        let fixture = signed_fixture();
        let mut carrier = deploy_carrier(&fixture.deploy, SYNERGY_TESTNET_V2_NETWORK_ID);
        carrier.chain_id = 999;
        let error = verify_synq_deploy_for_chain_admission(&carrier, TEST_NOW)
            .expect_err("wrong chain rejected");
        assert_eq!(error.code(), "AEGIS-CHAIN");
    }

    #[test]
    fn wrong_domain_preserves_aegis_domain_code() {
        let fixture = signed_fixture();
        let mut deploy = fixture.deploy;
        deploy.signing_payload.domain_tag = DomainTag::SynqContractCallV1;
        let carrier = deploy_carrier(&deploy, SYNERGY_TESTNET_V2_NETWORK_ID);
        let error = verify_synq_deploy_for_chain_admission(&carrier, TEST_NOW)
            .expect_err("wrong domain rejected");
        assert_eq!(error.code(), "AEGIS-DOMAIN");
    }

    #[test]
    fn invalid_signature_preserves_aegis_sig_code() {
        let fixture = signed_fixture();
        let mut deploy = fixture.deploy;
        deploy.signature.bytes[0] ^= 0x01;
        let carrier = deploy_carrier(&deploy, SYNERGY_TESTNET_V2_NETWORK_ID);
        let error = verify_synq_deploy_for_chain_admission(&carrier, TEST_NOW)
            .expect_err("invalid signature rejected");
        assert_eq!(error.code(), "AEGIS-SIG");
    }

    #[test]
    fn malformed_carrier_preserves_canonicalization_code() {
        let error = decode_synq_admission_carrier(b"synq-admission-v1:{not-json")
            .expect_err("malformed carrier rejected");
        assert_eq!(error.code(), "AEGIS-CANON");
    }

    #[test]
    fn valid_deploy_carrier_passes_pqsynq_then_existing_pqvm_admission() {
        let fixture = signed_fixture();
        let payload = encode_synq_admission_carrier(&deploy_carrier(
            &fixture.deploy,
            SYNERGY_TESTNET_V2_NETWORK_ID,
        ))
        .expect("encode carrier");
        let report = crate::aegis_tx_tool::sign_with_new_aegis_transaction_key(
            crate::aegis_tx_tool::AegisTxBuildOptions {
                payload,
                write_set_hint: vec!["synq-deploy".to_string()],
                ..crate::aegis_tx_tool::AegisTxBuildOptions::default()
            },
        )
        .expect("outer pqvm admission succeeds");
        let summary = report.synq_verification.expect("summary exists");
        assert_eq!(summary.domain, "SYNQ_CONTRACT_DEPLOY_V1");
        assert!(report.admission_result.ready);
    }

    #[test]
    fn valid_call_carrier_passes_pqsynq_then_existing_pqvm_admission() {
        let fixture = signed_fixture();
        let payload = encode_synq_admission_carrier(&call_carrier(
            &fixture.call,
            SYNERGY_TESTNET_V2_NETWORK_ID,
        ))
        .expect("encode carrier");
        let report = crate::aegis_tx_tool::sign_with_new_aegis_transaction_key(
            crate::aegis_tx_tool::AegisTxBuildOptions {
                payload,
                write_set_hint: vec!["synq-call".to_string()],
                ..crate::aegis_tx_tool::AegisTxBuildOptions::default()
            },
        )
        .expect("outer pqvm admission succeeds");
        let summary = report.synq_verification.expect("summary exists");
        assert_eq!(summary.domain, "SYNQ_CONTRACT_CALL_V1");
        assert!(report.admission_result.ready);
    }

    #[test]
    #[ignore = "requires SYNQ_LANGUAGE_ROOT and generated Counter artifacts"]
    fn counter_artifacts_pass_pqsynq_then_existing_pqvm_admission() {
        let root = PathBuf::from(
            std::env::var("SYNQ_LANGUAGE_ROOT")
                .expect("set SYNQ_LANGUAGE_ROOT to the local synq-language workspace"),
        );
        let bytecode = fs::read(root.join("contracts/Counter.compiled.synq"))
            .expect("read generated Counter bytecode");
        let abi =
            fs::read(root.join("contracts/Counter.abi.json")).expect("read generated Counter ABI");
        let manifest = fs::read(root.join("contracts/Counter.manifest.json"))
            .expect("read generated Counter manifest");

        let bytecode_hash = sha256(&bytecode);
        let abi_hash = sha256(&abi);
        let manifest_hash = sha256(&manifest);
        let manifest_json: serde_json::Value =
            serde_json::from_slice(&manifest).expect("parse generated Counter manifest");
        assert_eq!(manifest_json["bytecode_hash"], hex::encode(bytecode_hash));
        assert_eq!(manifest_json["abi_hash"], hex::encode(abi_hash));
        assert_eq!(manifest_json["required_chain_id"], 1264);

        let signer = Sign::mldsa65();
        let (public_key_bytes, private_key_bytes) = signer.keygen().expect("keygen");
        let public_key = SynQPublicKey::new(public_key_bytes);
        let signer_address =
            derive_synq_address(&public_key, AlgorithmId::MlDsa65, &NetworkId::testnet())
                .expect("derive signer address");
        let constructor_args_hash = sha256(&[]);
        let payload_hash = hash_contract_deploy_body(
            &bytecode_hash,
            &manifest_hash,
            &abi_hash,
            signer_address.as_bytes(),
            &constructor_args_hash,
        );
        let signing_payload = SynQSigningPayload {
            domain_tag: DomainTag::SynqContractDeployV1,
            chain_id: ChainId::testnet_1264(),
            network_id: NetworkId::testnet(),
            protocol_version: 1,
            algorithm_id: AlgorithmId::MlDsa65,
            signature_purpose: SignaturePurpose::ContractDeploy,
            nonce: 1,
            not_before_unix: 0,
            expiration_unix: TEST_EXPIRY,
            signer_address,
            payload_hash,
        };
        let signature = signer
            .detached_sign(
                &canonicalize_signing_payload(&signing_payload).expect("canonical deploy"),
                &private_key_bytes,
            )
            .expect("sign deploy");
        let deploy = ContractDeployEnvelope {
            signing_payload,
            public_key,
            signature: SynQSignature::new(signature),
            bytecode_hash,
            manifest_hash,
            abi_hash,
            constructor_args_hash,
        };
        let payload =
            encode_synq_admission_carrier(&deploy_carrier(&deploy, SYNERGY_TESTNET_V2_NETWORK_ID))
                .expect("encode carrier");
        let report = crate::aegis_tx_tool::sign_with_new_aegis_transaction_key(
            crate::aegis_tx_tool::AegisTxBuildOptions {
                payload,
                write_set_hint: vec!["synq-counter-deploy".to_string()],
                ..crate::aegis_tx_tool::AegisTxBuildOptions::default()
            },
        )
        .expect("outer pqvm admission succeeds");
        let summary = report.synq_verification.expect("summary exists");

        assert_eq!(summary.bytecode_hash, Some(bytecode_hash));
        assert_eq!(summary.manifest_hash, Some(manifest_hash));
        assert_eq!(summary.abi_hash, Some(abi_hash));
        assert_eq!(summary.domain, "SYNQ_CONTRACT_DEPLOY_V1");
        assert!(report.admission_result.ready);
        println!("counter_bytecode_hash={}", hex::encode(bytecode_hash));
        println!("counter_abi_hash={}", hex::encode(abi_hash));
        println!("counter_manifest_hash={}", hex::encode(manifest_hash));
        println!("pqsynq_domain={}", summary.domain);
        println!(
            "pqvm_outer_admission_ready={}",
            report.admission_result.ready
        );
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        let digest = Sha256::digest(bytes);
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&digest);
        hash
    }
}
