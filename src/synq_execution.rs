use crate::gas::GasSchedule;
use crate::synergy_types::{Hash, Transaction, TxId};
use crate::synq_admission::{
    decode_synq_admission_carrier, SynQAdmissionEnvelope, SynQAdmissionKind,
    SynQVerificationSummary,
};
use aivm_core::execution::{
    AivmSecurityPolicyRef, ContractArtifact, ContractFormat, ExecutionContext, ExecutionRequest,
    ExecutionStatus,
};
use aivm_core::state::ContractState;
use aivm_core::synq_runtime::{
    call_synq_contract, deploy_synq_contract, synq_execution_request, SynQRuntimeOperation,
    SynQRuntimeReceipt,
};
use pqsynq::{ContractCallEnvelope, ContractDeployEnvelope};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SynQArtifactKey {
    pub bytecode_hash: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub abi_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQContractArtifact {
    pub bytecode: Vec<u8>,
    pub abi_json: String,
    pub manifest_json: String,
}

impl SynQContractArtifact {
    pub fn new(bytecode: Vec<u8>, abi_json: String, manifest_json: String) -> Self {
        Self {
            bytecode,
            abi_json,
            manifest_json,
        }
    }

    pub fn key(&self) -> SynQArtifactKey {
        SynQArtifactKey {
            bytecode_hash: sha256_array(&self.bytecode),
            manifest_hash: sha256_array(self.manifest_json.as_bytes()),
            abi_hash: sha256_array(self.abi_json.as_bytes()),
        }
    }

    pub fn to_aivm_artifact(&self) -> ContractArtifact {
        ContractArtifact {
            format: ContractFormat::SynqBytecodeV1,
            bytes: self.bytecode.clone(),
            abi_json: Some(self.abi_json.clone()),
            manifest_json: Some(self.manifest_json.clone()),
            compiler_version: None,
            source_hash: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQDeploymentRecord {
    pub contract_address: String,
    pub deployer: String,
    pub artifact_key: SynQArtifactKey,
    pub deploy_tx_id: TxId,
    pub deploy_receipt_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQAivmReceiptSummary {
    pub operation: String,
    pub contract_address: String,
    pub status: String,
    pub gas_used: u64,
    pub pqc_gas_used: u64,
    pub return_data_hex: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub receipt_hash: String,
    pub logs: Vec<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

pub fn register_synq_artifact(
    artifacts: &mut BTreeMap<SynQArtifactKey, SynQContractArtifact>,
    artifact: SynQContractArtifact,
) -> Result<SynQArtifactKey, String> {
    let key = artifact.key();
    validate_artifact_hashes(&artifact, &key)?;
    artifacts.insert(key.clone(), artifact);
    Ok(key)
}

pub fn execute_synq_transaction(
    tx_id: &TxId,
    tx: &Transaction,
    verification: &SynQVerificationSummary,
    aivm_state: &mut ContractState,
    artifacts: &mut BTreeMap<SynQArtifactKey, SynQContractArtifact>,
    deployments: &mut BTreeMap<String, SynQDeploymentRecord>,
) -> Result<Option<SynQAivmReceiptSummary>, String> {
    let Some(envelope) = decode_synq_admission_carrier(&tx.payload)
        .map_err(|error| format!("SynQ carrier decode failed [{}]: {error}", error.code()))?
    else {
        return Ok(None);
    };

    match envelope.kind {
        SynQAdmissionKind::Deploy => execute_deploy(
            tx_id,
            tx,
            verification,
            &envelope,
            aivm_state,
            artifacts,
            deployments,
        )
        .map(Some),
        SynQAdmissionKind::Call => execute_call(
            tx,
            verification,
            &envelope,
            aivm_state,
            artifacts,
            deployments,
        )
        .map(Some),
    }
}

fn execute_deploy(
    tx_id: &TxId,
    tx: &Transaction,
    verification: &SynQVerificationSummary,
    envelope: &SynQAdmissionEnvelope,
    aivm_state: &mut ContractState,
    artifacts: &mut BTreeMap<SynQArtifactKey, SynQContractArtifact>,
    deployments: &mut BTreeMap<String, SynQDeploymentRecord>,
) -> Result<SynQAivmReceiptSummary, String> {
    let contract_address = verification.signer.clone();
    let artifact = match artifact_from_envelope(envelope) {
        Ok(artifact) => artifact,
        Err(message) => {
            return Ok(pre_aivm_failed_summary(
                SynQRuntimeOperation::Deploy,
                &contract_address,
                "SYNQ-AIVM-ARTIFACT",
                &message,
                aivm_state,
            ));
        }
    };
    let artifact_key = artifact.key();
    if let Err(message) = validate_artifact_hashes(&artifact, &artifact_key) {
        return Ok(pre_aivm_failed_summary(
            SynQRuntimeOperation::Deploy,
            &contract_address,
            "SYNQ-AIVM-ARTIFACT",
            &message,
            aivm_state,
        ));
    }

    let request = synq_execution_request(
        contract_address.clone(),
        artifact.to_aivm_artifact(),
        aivm_context(tx, verification, &contract_address)?,
        Vec::new(),
    );
    let receipt = deploy_synq_contract(&request, aivm_state);
    let summary = summary_from_aivm_receipt(&contract_address, &receipt);
    if receipt.status == ExecutionStatus::Succeeded {
        artifacts.insert(artifact_key.clone(), artifact);
        deployments.insert(
            contract_address.clone(),
            SynQDeploymentRecord {
                contract_address,
                deployer: verification.signer.clone(),
                artifact_key,
                deploy_tx_id: tx_id.clone(),
                deploy_receipt_hash: summary.receipt_hash.clone(),
            },
        );
    }
    Ok(summary)
}

fn execute_call(
    tx: &Transaction,
    verification: &SynQVerificationSummary,
    envelope: &SynQAdmissionEnvelope,
    aivm_state: &mut ContractState,
    artifacts: &BTreeMap<SynQArtifactKey, SynQContractArtifact>,
    deployments: &BTreeMap<String, SynQDeploymentRecord>,
) -> Result<SynQAivmReceiptSummary, String> {
    let call: ContractCallEnvelope = serde_json::from_slice(&envelope.encoded_pqsynq_envelope)
        .map_err(|error| format!("SynQ call envelope decode failed after admission: {error}"))?;
    let contract_address = call.contract_address.to_testnet_debug_string();
    let Some(deployment) = deployments.get(&contract_address) else {
        return Ok(pre_aivm_failed_summary(
            SynQRuntimeOperation::Call,
            &contract_address,
            "SYNQ-AIVM-STATE",
            "SynQ call precondition failed: contract has not been deployed in execution state",
            aivm_state,
        ));
    };
    let Some(artifact) = artifacts.get(&deployment.artifact_key) else {
        return Ok(pre_aivm_failed_summary(
            SynQRuntimeOperation::Call,
            &contract_address,
            "SYNQ-AIVM-ARTIFACT",
            "SynQ call precondition failed: deployed contract artifact is missing from execution state",
            aivm_state,
        ));
    };

    let request = synq_execution_request(
        contract_address.clone(),
        artifact.to_aivm_artifact(),
        aivm_context(tx, verification, &contract_address)?,
        call.method_selector.to_vec(),
    );
    let receipt = call_synq_contract(&request, aivm_state);
    Ok(summary_from_aivm_receipt(&contract_address, &receipt))
}

fn artifact_from_envelope(
    envelope: &SynQAdmissionEnvelope,
) -> Result<SynQContractArtifact, String> {
    let bytecode = envelope
        .bytecode
        .clone()
        .ok_or_else(|| "SynQ deploy carrier is missing bytecode bytes".to_string())?;
    let abi_json = envelope
        .abi_json
        .clone()
        .ok_or_else(|| "SynQ deploy carrier is missing ABI JSON".to_string())?;
    let manifest_json = envelope
        .manifest_json
        .clone()
        .ok_or_else(|| "SynQ deploy carrier is missing manifest JSON".to_string())?;
    let artifact = SynQContractArtifact::new(bytecode, abi_json, manifest_json);
    let actual = artifact.key();
    if envelope.bytecode_hash != Some(actual.bytecode_hash)
        || envelope.manifest_hash != Some(actual.manifest_hash)
        || envelope.abi_hash != Some(actual.abi_hash)
    {
        return Err(
            "SynQ deploy artifact bytes do not match admitted bytecode/manifest/ABI hashes"
                .to_string(),
        );
    }
    Ok(artifact)
}

fn validate_artifact_hashes(
    artifact: &SynQContractArtifact,
    key: &SynQArtifactKey,
) -> Result<(), String> {
    let request = ExecutionRequest {
        contract_id: "Counter".to_string(),
        artifact: artifact.to_aivm_artifact(),
        calldata: Vec::new(),
        context: ExecutionContext::testnet_1264_for_contract("Counter", 150_000),
    };
    aivm_core::execution::validate_synq_artifact(&request)
        .map_err(|error| format!("AIVM artifact validation failed: {error}"))?;
    if artifact.key() != *key {
        return Err("SynQ artifact key does not match artifact bytes".to_string());
    }
    Ok(())
}

fn aivm_context(
    tx: &Transaction,
    verification: &SynQVerificationSummary,
    contract_address: &str,
) -> Result<ExecutionContext, String> {
    Ok(ExecutionContext {
        admission_pq_gas_used: GasSchedule::default().pqc_signature_verify_gas,
        chain_id: tx.chain_id.0,
        network_id: tx.network_id.0.clone(),
        block_height: 0,
        block_timestamp_unix: 0,
        tx_hash: tx.canonical_tx_bytes_hash()?.0,
        caller: verification.signer.as_bytes().to_vec(),
        contract_address: contract_address.as_bytes().to_vec(),
        gas_limit: tx.gas_limit,
        pq_gas_limit: 300_000,
        security_policy: AivmSecurityPolicyRef {
            policy_id: "synq-testnet-1264-v1".to_string(),
            required_signature_policy: "ml-dsa-65".to_string(),
        },
    })
}

fn summary_from_aivm_receipt(
    contract_address: &str,
    receipt: &SynQRuntimeReceipt,
) -> SynQAivmReceiptSummary {
    SynQAivmReceiptSummary {
        operation: operation_name(receipt.operation).to_string(),
        contract_address: contract_address.to_string(),
        status: execution_status_name(&receipt.status).to_string(),
        gas_used: receipt.gas_used,
        pqc_gas_used: receipt.pqc_gas_used,
        return_data_hex: hex::encode(&receipt.return_data),
        pre_state_root: hex::encode(receipt.pre_state_root),
        post_state_root: hex::encode(receipt.post_state_root),
        receipt_hash: hex::encode(receipt.canonical_hash()),
        logs: receipt.logs.clone(),
        error_code: receipt.error_code.map(|code| format!("{code:?}")),
        error_message: receipt.error.clone(),
    }
}

fn pre_aivm_failed_summary(
    operation: SynQRuntimeOperation,
    contract_address: &str,
    code: &str,
    message: &str,
    state: &ContractState,
) -> SynQAivmReceiptSummary {
    let state_root = hex::encode(state.state_root());
    let mut summary = SynQAivmReceiptSummary {
        operation: operation_name(operation).to_string(),
        contract_address: contract_address.to_string(),
        status: "failed".to_string(),
        gas_used: 0,
        pqc_gas_used: GasSchedule::default().pqc_signature_verify_gas,
        return_data_hex: String::new(),
        pre_state_root: state_root.clone(),
        post_state_root: state_root,
        receipt_hash: String::new(),
        logs: Vec::new(),
        error_code: Some(code.to_string()),
        error_message: Some(message.to_string()),
    };
    summary.receipt_hash = Hash::from_domain_bytes(
        "SYNERGY_SYNQ_AIVM_PRE_EXECUTION_RECEIPT_V1",
        &serde_json::to_vec(&summary).unwrap_or_default(),
    )
    .to_hex();
    summary
}

fn operation_name(operation: SynQRuntimeOperation) -> &'static str {
    match operation {
        SynQRuntimeOperation::Deploy => "deploy",
        SynQRuntimeOperation::Call => "call",
    }
}

fn execution_status_name(status: &ExecutionStatus) -> &'static str {
    match status {
        ExecutionStatus::Succeeded => "succeeded",
        ExecutionStatus::Reverted => "reverted",
        ExecutionStatus::Failed => "failed",
    }
}

fn sha256_array(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn deploy_envelope_from_carrier(
    envelope: &SynQAdmissionEnvelope,
) -> Result<ContractDeployEnvelope, String> {
    serde_json::from_slice(&envelope.encoded_pqsynq_envelope)
        .map_err(|error| format!("SynQ deploy envelope decode failed after admission: {error}"))
}
