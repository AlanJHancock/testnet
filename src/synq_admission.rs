use serde::{Deserialize, Serialize};
use std::fmt;

use crate::synergy_types::{
    Transaction, SYNERGY_TESTNET_V2_CHAIN_ID, SYNERGY_TESTNET_V2_NETWORK_ID,
};
use pqsynq::{
    AegisSynQVerifier, AlgorithmId, ChainId, ContractCallEnvelope, ContractDeployEnvelope,
    DomainTag, NetworkId, SynQSecurityPolicy, VerificationContext,
};

pub const SYNQ_ADMISSION_CARRIER_PREFIX: &[u8] = b"synq-admission-v1:";
pub const SYNQ_ADMISSION_VERSION: u16 = 1;
pub const SYNQ_CANONICAL_TESTNET_NETWORK_ID: &str = "synergy-testnet";
pub const MAX_SYNQ_DEPLOY_BYTECODE_BYTES: usize = 256 * 1024;
pub const MAX_SYNQ_DEPLOY_ABI_JSON_BYTES: usize = 64 * 1024;
pub const MAX_SYNQ_DEPLOY_MANIFEST_JSON_BYTES: usize = 64 * 1024;

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
    #[serde(default)]
    pub bytecode: Option<Vec<u8>>,
    #[serde(default)]
    pub abi_json: Option<String>,
    #[serde(default)]
    pub manifest_json: Option<String>,
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

pub fn build_deploy_admission_envelope_from_pqsynq_bytes(
    chain_id: u64,
    network_id: &str,
    encoded_pqsynq_envelope: &[u8],
    now_unix: u64,
) -> Result<SynQAdmissionEnvelope, SynQAdmissionError> {
    let deploy: ContractDeployEnvelope =
        decode_pqsynq_envelope(encoded_pqsynq_envelope, "decode SynQ deploy envelope")?;
    let envelope = SynQAdmissionEnvelope {
        version: SYNQ_ADMISSION_VERSION,
        kind: SynQAdmissionKind::Deploy,
        chain_id,
        network_id: network_id.to_string(),
        signer: deploy
            .signing_payload
            .signer_address
            .to_testnet_debug_string(),
        payload_hash: deploy.signing_payload.payload_hash,
        bytecode_hash: Some(deploy.bytecode_hash),
        manifest_hash: Some(deploy.manifest_hash),
        abi_hash: Some(deploy.abi_hash),
        encoded_pqsynq_envelope: encoded_pqsynq_envelope.to_vec(),
        bytecode: None,
        abi_json: None,
        manifest_json: None,
    };
    verify_synq_deploy_for_chain_admission(&envelope, now_unix)?;
    Ok(envelope)
}

pub fn build_deploy_admission_envelope_from_pqsynq_bytes_with_artifacts(
    chain_id: u64,
    network_id: &str,
    encoded_pqsynq_envelope: &[u8],
    bytecode: Vec<u8>,
    abi_json: String,
    manifest_json: String,
    now_unix: u64,
) -> Result<SynQAdmissionEnvelope, SynQAdmissionError> {
    let mut envelope = build_deploy_admission_envelope_from_pqsynq_bytes(
        chain_id,
        network_id,
        encoded_pqsynq_envelope,
        now_unix,
    )?;
    attach_deploy_artifacts(&mut envelope, bytecode, abi_json, manifest_json)?;
    Ok(envelope)
}

pub fn build_call_admission_envelope_from_pqsynq_bytes(
    chain_id: u64,
    network_id: &str,
    encoded_pqsynq_envelope: &[u8],
    now_unix: u64,
) -> Result<SynQAdmissionEnvelope, SynQAdmissionError> {
    let call: ContractCallEnvelope =
        decode_pqsynq_envelope(encoded_pqsynq_envelope, "decode SynQ call envelope")?;
    let envelope = SynQAdmissionEnvelope {
        version: SYNQ_ADMISSION_VERSION,
        kind: SynQAdmissionKind::Call,
        chain_id,
        network_id: network_id.to_string(),
        signer: call
            .signing_payload
            .signer_address
            .to_testnet_debug_string(),
        payload_hash: call.signing_payload.payload_hash,
        bytecode_hash: None,
        manifest_hash: None,
        abi_hash: None,
        encoded_pqsynq_envelope: encoded_pqsynq_envelope.to_vec(),
        bytecode: None,
        abi_json: None,
        manifest_json: None,
    };
    verify_synq_call_for_chain_admission(&envelope, now_unix)?;
    Ok(envelope)
}

pub fn build_deploy_admission_carrier_from_pqsynq_bytes(
    chain_id: u64,
    network_id: &str,
    encoded_pqsynq_envelope: &[u8],
    now_unix: u64,
) -> Result<Vec<u8>, SynQAdmissionError> {
    let envelope = build_deploy_admission_envelope_from_pqsynq_bytes(
        chain_id,
        network_id,
        encoded_pqsynq_envelope,
        now_unix,
    )?;
    encode_synq_admission_carrier(&envelope)
}

pub fn build_deploy_admission_carrier_from_pqsynq_bytes_with_artifacts(
    chain_id: u64,
    network_id: &str,
    encoded_pqsynq_envelope: &[u8],
    bytecode: Vec<u8>,
    abi_json: String,
    manifest_json: String,
    now_unix: u64,
) -> Result<Vec<u8>, SynQAdmissionError> {
    let envelope = build_deploy_admission_envelope_from_pqsynq_bytes_with_artifacts(
        chain_id,
        network_id,
        encoded_pqsynq_envelope,
        bytecode,
        abi_json,
        manifest_json,
        now_unix,
    )?;
    encode_synq_admission_carrier(&envelope)
}

pub fn build_call_admission_carrier_from_pqsynq_bytes(
    chain_id: u64,
    network_id: &str,
    encoded_pqsynq_envelope: &[u8],
    now_unix: u64,
) -> Result<Vec<u8>, SynQAdmissionError> {
    let envelope = build_call_admission_envelope_from_pqsynq_bytes(
        chain_id,
        network_id,
        encoded_pqsynq_envelope,
        now_unix,
    )?;
    encode_synq_admission_carrier(&envelope)
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
    let normalized = normalize_synq_network(envelope.chain_id, &envelope.network_id)?;
    let deploy: ContractDeployEnvelope = decode_pqsynq_envelope(
        &envelope.encoded_pqsynq_envelope,
        "decode SynQ deploy envelope",
    )?;
    let context = pqsynq_context(envelope.chain_id, &normalized.pqsynq_network_id, now_unix);
    let verified = AegisSynQVerifier::testnet_1264()
        .verify_contract_deploy(&deploy, &context)
        .map_err(pqsynq_error)?;

    let bytecode_hash = envelope
        .bytecode_hash
        .expect("checked required bytecode_hash");
    let manifest_hash = envelope
        .manifest_hash
        .expect("checked required manifest_hash");
    let abi_hash = envelope.abi_hash.expect("checked required abi_hash");
    if deploy.signing_payload.payload_hash != envelope.payload_hash
        || verified.bytecode_hash != bytecode_hash
        || verified.manifest_hash != manifest_hash
        || verified.abi_hash != abi_hash
        || verified.deployer.to_testnet_debug_string() != envelope.signer
    {
        return Err(SynQAdmissionError::InvalidCarrier {
            code: "AEGIS-CANON",
            message: "SynQ deploy carrier fields do not match verified aegis-pqsynq envelope"
                .to_string(),
        });
    }
    validate_attached_deploy_artifacts(envelope)?;

    Ok(summary_from_payload(
        envelope,
        &normalized,
        deploy.signing_payload.domain_tag,
        deploy.signing_payload.algorithm_id,
    ))
}

pub fn verify_synq_call_for_chain_admission(
    envelope: &SynQAdmissionEnvelope,
    now_unix: u64,
) -> Result<SynQVerificationSummary, SynQAdmissionError> {
    ensure_version(envelope)?;
    ensure_kind(envelope, SynQAdmissionKind::Call)?;
    let normalized = normalize_synq_network(envelope.chain_id, &envelope.network_id)?;
    let call: ContractCallEnvelope = decode_pqsynq_envelope(
        &envelope.encoded_pqsynq_envelope,
        "decode SynQ call envelope",
    )?;
    let context = pqsynq_context(envelope.chain_id, &normalized.pqsynq_network_id, now_unix);
    let verified = AegisSynQVerifier::testnet_1264()
        .verify_contract_call(&call, &context)
        .map_err(pqsynq_error)?;

    if call.signing_payload.payload_hash != envelope.payload_hash
        || verified.caller.to_testnet_debug_string() != envelope.signer
    {
        return Err(SynQAdmissionError::InvalidCarrier {
            code: "AEGIS-CANON",
            message: "SynQ call carrier fields do not match verified aegis-pqsynq envelope"
                .to_string(),
        });
    }

    Ok(summary_from_payload(
        envelope,
        &normalized,
        call.signing_payload.domain_tag,
        call.signing_payload.algorithm_id,
    ))
}

fn decode_pqsynq_envelope<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    context: &'static str,
) -> Result<T, SynQAdmissionError> {
    serde_json::from_slice(bytes).map_err(|error| SynQAdmissionError::Decode {
        code: "AEGIS-CANON",
        message: format!("{context}: {error}"),
    })
}

fn attach_deploy_artifacts(
    envelope: &mut SynQAdmissionEnvelope,
    bytecode: Vec<u8>,
    abi_json: String,
    manifest_json: String,
) -> Result<(), SynQAdmissionError> {
    ensure_kind(envelope, SynQAdmissionKind::Deploy)?;
    ensure_artifact_size("bytecode", bytecode.len(), MAX_SYNQ_DEPLOY_BYTECODE_BYTES)?;
    ensure_artifact_size("abi_json", abi_json.len(), MAX_SYNQ_DEPLOY_ABI_JSON_BYTES)?;
    ensure_artifact_size(
        "manifest_json",
        manifest_json.len(),
        MAX_SYNQ_DEPLOY_MANIFEST_JSON_BYTES,
    )?;
    let bytecode_hash = sha256_array(&bytecode);
    let abi_hash = sha256_array(abi_json.as_bytes());
    let manifest_hash = sha256_array(manifest_json.as_bytes());
    if envelope.bytecode_hash != Some(bytecode_hash)
        || envelope.abi_hash != Some(abi_hash)
        || envelope.manifest_hash != Some(manifest_hash)
    {
        return Err(SynQAdmissionError::InvalidCarrier {
            code: "AEGIS-CANON",
            message:
                "SynQ deploy artifact bytes do not match the verified aegis-pqsynq hash envelope"
                    .to_string(),
        });
    }
    envelope.bytecode = Some(bytecode);
    envelope.abi_json = Some(abi_json);
    envelope.manifest_json = Some(manifest_json);
    Ok(())
}

fn ensure_artifact_size(
    field: &'static str,
    actual: usize,
    max: usize,
) -> Result<(), SynQAdmissionError> {
    if actual <= max {
        Ok(())
    } else {
        Err(SynQAdmissionError::InvalidCarrier {
            code: "SYNQ-ARTIFACT-SIZE",
            message: format!(
                "SynQ deploy {field} is {actual} bytes, exceeding testnet limit {max}"
            ),
        })
    }
}

fn validate_attached_deploy_artifacts(
    envelope: &SynQAdmissionEnvelope,
) -> Result<(), SynQAdmissionError> {
    let any_artifact = envelope.bytecode.is_some()
        || envelope.abi_json.is_some()
        || envelope.manifest_json.is_some();
    if !any_artifact {
        return Ok(());
    }

    let bytecode = envelope
        .bytecode
        .as_ref()
        .ok_or_else(artifact_availability_error)?;
    let abi_json = envelope
        .abi_json
        .as_ref()
        .ok_or_else(artifact_availability_error)?;
    let manifest_json = envelope
        .manifest_json
        .as_ref()
        .ok_or_else(artifact_availability_error)?;

    ensure_artifact_size("bytecode", bytecode.len(), MAX_SYNQ_DEPLOY_BYTECODE_BYTES)?;
    ensure_artifact_size("abi_json", abi_json.len(), MAX_SYNQ_DEPLOY_ABI_JSON_BYTES)?;
    ensure_artifact_size(
        "manifest_json",
        manifest_json.len(),
        MAX_SYNQ_DEPLOY_MANIFEST_JSON_BYTES,
    )?;

    if envelope.bytecode_hash != Some(sha256_array(bytecode))
        || envelope.abi_hash != Some(sha256_array(abi_json.as_bytes()))
        || envelope.manifest_hash != Some(sha256_array(manifest_json.as_bytes()))
    {
        return Err(SynQAdmissionError::InvalidCarrier {
            code: "AEGIS-CANON",
            message:
                "SynQ deploy artifact bytes do not match the verified aegis-pqsynq hash envelope"
                    .to_string(),
        });
    }

    Ok(())
}

fn artifact_availability_error() -> SynQAdmissionError {
    SynQAdmissionError::InvalidCarrier {
        code: "SYNQ-ARTIFACT-AVAILABILITY",
        message: "SynQ deploy artifact availability requires bytecode, ABI, and manifest together"
            .to_string(),
    }
}

fn sha256_array(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(bytes);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn pqsynq_context(chain_id: u64, network_id: &str, now_unix: u64) -> VerificationContext {
    VerificationContext {
        chain_id: ChainId(chain_id),
        network_id: NetworkId(network_id.to_string()),
        now_unix,
        policy: SynQSecurityPolicy::testnet_1264_policy(),
    }
}

fn pqsynq_error(error: pqsynq::AegisSynQError) -> SynQAdmissionError {
    SynQAdmissionError::PqSynQ {
        code: error.code(),
        message: error.to_string(),
    }
}

fn summary_from_payload(
    envelope: &SynQAdmissionEnvelope,
    normalized: &NormalizedSynQNetwork,
    domain: DomainTag,
    algorithm: AlgorithmId,
) -> SynQVerificationSummary {
    SynQVerificationSummary {
        chain_id: envelope.chain_id,
        normalized_network_id: normalized.pqsynq_network_id.clone(),
        node_network_id: normalized.node_network_id.clone(),
        domain: domain.as_str().to_string(),
        algorithm: algorithm_name(algorithm).to_string(),
        signer: envelope.signer.clone(),
        payload_hash: envelope.payload_hash,
        bytecode_hash: envelope.bytecode_hash,
        manifest_hash: envelope.manifest_hash,
        abi_hash: envelope.abi_hash,
        verified_at_admission: true,
    }
}

fn algorithm_name(algorithm: AlgorithmId) -> &'static str {
    match algorithm {
        AlgorithmId::MlDsa44 => "ML-DSA-44",
        AlgorithmId::MlDsa65 => "ML-DSA-65",
        AlgorithmId::MlDsa87 => "ML-DSA-87",
        AlgorithmId::SlhDsaSha2_128s => "SLH-DSA-SHA2-128s",
        AlgorithmId::SlhDsaSha2_192s => "SLH-DSA-SHA2-192s",
        AlgorithmId::SlhDsaSha2_256s => "SLH-DSA-SHA2-256s",
        AlgorithmId::FnDsa => "FN-DSA",
        AlgorithmId::Hqc128 => "HQC-128",
        AlgorithmId::Hqc192 => "HQC-192",
        AlgorithmId::Hqc256 => "HQC-256",
        AlgorithmId::ClassicMcEliece348864 => "Classic-McEliece-348864",
    }
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
pub(crate) mod test_support {
    use super::*;
    use pqsynq::{
        canonicalize_signing_payload, derive_synq_address, hash_contract_call_body,
        hash_contract_deploy_body, DigitalSignature, Sign, SignaturePurpose, SynQAddress,
        SynQPublicKey, SynQSignature, SynQSigningPayload,
    };

    pub(crate) const TEST_NOW: u64 = 1_800_000_000;

    pub(crate) fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    pub(crate) fn deploy_carrier(network_id: &str) -> SynQAdmissionEnvelope {
        let (public_key, private_key, signer) = test_identity();
        let bytecode_hash = hash(1);
        let manifest_hash = hash(2);
        let abi_hash = hash(3);
        let constructor_args_hash = hash(4);
        let payload_hash = hash_contract_deploy_body(
            &bytecode_hash,
            &manifest_hash,
            &abi_hash,
            signer.as_bytes(),
            &constructor_args_hash,
        );
        let signing_payload = signing_payload(
            DomainTag::SynqContractDeployV1,
            SignaturePurpose::ContractDeploy,
            signer,
            payload_hash,
            41,
        );
        let signature = sign_payload(&signing_payload, &private_key);
        let deploy = ContractDeployEnvelope {
            signing_payload,
            public_key,
            signature: SynQSignature::new(signature),
            bytecode_hash,
            manifest_hash,
            abi_hash,
            constructor_args_hash,
        };

        SynQAdmissionEnvelope {
            version: SYNQ_ADMISSION_VERSION,
            kind: SynQAdmissionKind::Deploy,
            chain_id: SYNERGY_TESTNET_V2_CHAIN_ID,
            network_id: network_id.to_string(),
            signer: deploy
                .signing_payload
                .signer_address
                .to_testnet_debug_string(),
            payload_hash,
            bytecode_hash: Some(bytecode_hash),
            manifest_hash: Some(manifest_hash),
            abi_hash: Some(abi_hash),
            encoded_pqsynq_envelope: serde_json::to_vec(&deploy).unwrap(),
            bytecode: None,
            abi_json: None,
            manifest_json: None,
        }
    }

    pub(crate) fn call_carrier(network_id: &str) -> SynQAdmissionEnvelope {
        let (public_key, private_key, signer) = test_identity();
        let contract_address = signer;
        let method_selector = [0x58, 0x42, 0xf1, 0xbe];
        let encoded_args_hash = hash(5);
        let payload_hash = hash_contract_call_body(
            contract_address.as_bytes(),
            &method_selector,
            &encoded_args_hash,
            signer.as_bytes(),
        );
        let signing_payload = signing_payload(
            DomainTag::SynqContractCallV1,
            SignaturePurpose::ContractCall,
            signer,
            payload_hash,
            42,
        );
        let signature = sign_payload(&signing_payload, &private_key);
        let call = ContractCallEnvelope {
            signing_payload,
            public_key,
            signature: SynQSignature::new(signature),
            contract_address,
            method_selector,
            encoded_args_hash,
        };

        SynQAdmissionEnvelope {
            version: SYNQ_ADMISSION_VERSION,
            kind: SynQAdmissionKind::Call,
            chain_id: SYNERGY_TESTNET_V2_CHAIN_ID,
            network_id: network_id.to_string(),
            signer: call
                .signing_payload
                .signer_address
                .to_testnet_debug_string(),
            payload_hash,
            bytecode_hash: None,
            manifest_hash: None,
            abi_hash: None,
            encoded_pqsynq_envelope: serde_json::to_vec(&call).unwrap(),
            bytecode: None,
            abi_json: None,
            manifest_json: None,
        }
    }

    fn test_identity() -> (SynQPublicKey, Vec<u8>, SynQAddress) {
        let signer = Sign::mldsa65();
        let (public_key, private_key) = signer.keygen().expect("ML-DSA-65 keygen");
        let public_key = SynQPublicKey::new(public_key);
        let address = derive_synq_address(
            &public_key,
            AlgorithmId::MlDsa65,
            &NetworkId(SYNQ_CANONICAL_TESTNET_NETWORK_ID.to_string()),
        )
        .expect("derive SynQ address");
        (public_key, private_key, address)
    }

    fn signing_payload(
        domain_tag: DomainTag,
        signature_purpose: SignaturePurpose,
        signer_address: SynQAddress,
        payload_hash: [u8; 32],
        nonce: u64,
    ) -> SynQSigningPayload {
        SynQSigningPayload {
            domain_tag,
            chain_id: ChainId(SYNERGY_TESTNET_V2_CHAIN_ID),
            network_id: NetworkId(SYNQ_CANONICAL_TESTNET_NETWORK_ID.to_string()),
            protocol_version: 1,
            algorithm_id: AlgorithmId::MlDsa65,
            signature_purpose,
            nonce,
            not_before_unix: 0,
            expiration_unix: 4_102_444_800,
            signer_address,
            payload_hash,
        }
    }

    fn sign_payload(payload: &SynQSigningPayload, private_key: &[u8]) -> Vec<u8> {
        let canonical = canonicalize_signing_payload(payload).expect("canonical payload");
        Sign::mldsa65()
            .detached_sign(&canonical, private_key)
            .expect("ML-DSA-65 sign")
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

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
    fn synq_deploy_carrier_verifies_through_pqsynq() {
        let summary = verify_synq_deploy_for_chain_admission(
            &deploy_carrier(SYNERGY_TESTNET_V2_NETWORK_ID),
            TEST_NOW,
        )
        .expect("SynQ deploy carrier verified");
        assert_eq!(summary.domain, "SYNQ_CONTRACT_DEPLOY_V1");
        assert_eq!(summary.algorithm, "ML-DSA-65");
        assert!(summary.verified_at_admission);
        assert_eq!(summary.bytecode_hash, Some(hash(1)));
    }

    #[test]
    fn synq_call_carrier_verifies_through_pqsynq() {
        let summary = verify_synq_call_for_chain_admission(
            &call_carrier(SYNERGY_TESTNET_V2_NETWORK_ID),
            TEST_NOW,
        )
        .expect("SynQ call carrier verified");
        assert_eq!(summary.domain, "SYNQ_CONTRACT_CALL_V1");
        assert_eq!(summary.algorithm, "ML-DSA-65");
        assert!(summary.verified_at_admission);
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

    #[test]
    fn invalid_inner_signature_preserves_pqsynq_error_code() {
        let mut carrier = deploy_carrier(SYNERGY_TESTNET_V2_NETWORK_ID);
        let mut deploy: ContractDeployEnvelope =
            serde_json::from_slice(&carrier.encoded_pqsynq_envelope).unwrap();
        deploy.signature.bytes[0] ^= 0x01;
        carrier.encoded_pqsynq_envelope = serde_json::to_vec(&deploy).unwrap();

        let error = verify_synq_deploy_for_chain_admission(&carrier, TEST_NOW)
            .expect_err("invalid signature rejected");
        assert_eq!(error.code(), "AEGIS-SIG");
    }

    #[test]
    fn partial_deploy_artifacts_reject_at_admission() {
        let mut carrier = deploy_carrier(SYNERGY_TESTNET_V2_NETWORK_ID);
        carrier.bytecode = Some(Vec::new());

        let error = verify_synq_deploy_for_chain_admission(&carrier, TEST_NOW)
            .expect_err("partial artifacts must fail");
        assert_eq!(error.code(), "SYNQ-ARTIFACT-AVAILABILITY");
    }

    #[test]
    fn oversized_deploy_artifacts_reject_at_admission() {
        let mut carrier = deploy_carrier(SYNERGY_TESTNET_V2_NETWORK_ID);
        carrier.bytecode = Some(vec![0; MAX_SYNQ_DEPLOY_BYTECODE_BYTES + 1]);
        carrier.abi_json = Some(String::new());
        carrier.manifest_json = Some(String::new());

        let error = verify_synq_deploy_for_chain_admission(&carrier, TEST_NOW)
            .expect_err("oversized artifacts must fail");
        assert_eq!(error.code(), "SYNQ-ARTIFACT-SIZE");
    }

    #[test]
    fn pqsynq_deploy_bytes_wrap_into_versioned_admission_carrier() {
        let source = deploy_carrier(SYNERGY_TESTNET_V2_NETWORK_ID);
        let bytes = build_deploy_admission_carrier_from_pqsynq_bytes(
            SYNERGY_TESTNET_V2_CHAIN_ID,
            SYNERGY_TESTNET_V2_NETWORK_ID,
            &source.encoded_pqsynq_envelope,
            TEST_NOW,
        )
        .expect("wrap deploy envelope");
        let decoded = decode_synq_admission_carrier(&bytes)
            .expect("decode carrier")
            .expect("carrier present");
        assert_eq!(decoded.kind, SynQAdmissionKind::Deploy);
        assert_eq!(decoded.payload_hash, source.payload_hash);
        assert_eq!(decoded.bytecode_hash, source.bytecode_hash);
        assert_eq!(decoded.signer, source.signer);
    }

    #[test]
    fn pqsynq_call_bytes_wrap_into_versioned_admission_carrier() {
        let source = call_carrier(SYNERGY_TESTNET_V2_NETWORK_ID);
        let bytes = build_call_admission_carrier_from_pqsynq_bytes(
            SYNERGY_TESTNET_V2_CHAIN_ID,
            SYNERGY_TESTNET_V2_NETWORK_ID,
            &source.encoded_pqsynq_envelope,
            TEST_NOW,
        )
        .expect("wrap call envelope");
        let decoded = decode_synq_admission_carrier(&bytes)
            .expect("decode carrier")
            .expect("carrier present");
        assert_eq!(decoded.kind, SynQAdmissionKind::Call);
        assert_eq!(decoded.payload_hash, source.payload_hash);
        assert_eq!(decoded.signer, source.signer);
    }
}
