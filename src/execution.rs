use crate::crypto::aegis_pqvm::{SYNERGY_RECEIPT_ROOT_V1, SYNERGY_STATE_ROOT_V1};
use crate::sts::{StsSignedPayload, StsState};
use crate::synergy_types::{Block, CanonicalSerialize, Hash, Transaction, TxId};
use crate::synq_admission::SynQVerificationSummary;
use crate::synq_execution::{
    execute_synq_transaction_at, SynQAivmReceiptSummary, SynQArtifactKey, SynQContractArtifact,
    SynQDeploymentRecord, SynQExecutionContext,
};
use aivm_core::state::ContractState;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FeeAccumulator {
    pub epoch: u64,
    pub total_collected_nwei: u128,
    pub by_tx_type: BTreeMap<String, u128>,
    pub opened_at_height: u64,
    pub closed_at_height: Option<u64>,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FeeChargedEvent {
    pub tx_hash: String,
    pub block_height: u64,
    pub epoch: u64,
    pub payer: String,
    pub tx_type: String,
    pub asset_id: String,
    pub amount_raw: u128,
    pub amount_snrgequivalent_nwei: u128,
    pub valuation_source: String,
    pub valuation_status: String,
    pub gas_used: u64,
    pub base_fee_per_gas_nwei: u64,
    pub gas_fee_nwei: u128,
    pub amount_fee_bps: u64,
    pub amount_protocol_fee_nwei: u128,
    pub storage_fee_nwei: u128,
    pub priority_fee_nwei: u128,
    pub total_fee_nwei: u128,
    pub fee_collector_address: String,
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BurnLedgerEntry {
    pub asset_id: String,
    pub total_burned_or_locked: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BurnAddressTransferEvent {
    pub tx_hash: String,
    pub sender: String,
    pub asset_id: String,
    pub amount: u128,
    pub burn_address: String,
    pub supply_reduced_bool: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionState {
    pub balances_nwei: BTreeMap<String, u128>,
    pub fee_accumulators: BTreeMap<u64, FeeAccumulator>,
    pub fee_events: Vec<FeeChargedEvent>,
    pub burn_ledger: BTreeMap<String, BurnLedgerEntry>,
    pub burn_events: Vec<BurnAddressTransferEvent>,
    pub sts_state: StsState,
    pub verified_authorizations: BTreeMap<TxId, Hash>,
    pub synq_verifications: BTreeMap<TxId, SynQVerificationSummary>,
    pub synq_errors: BTreeMap<TxId, (String, String)>,
    pub synq_artifacts: BTreeMap<SynQArtifactKey, SynQContractArtifact>,
    pub synq_contracts: BTreeMap<String, SynQDeploymentRecord>,
    pub synq_aivm_state: ContractState,
}

impl ExecutionState {
    pub fn new() -> Self {
        Self {
            balances_nwei: BTreeMap::new(),
            fee_accumulators: BTreeMap::new(),
            fee_events: Vec::new(),
            burn_ledger: BTreeMap::new(),
            burn_events: Vec::new(),
            sts_state: StsState::new(),
            verified_authorizations: BTreeMap::new(),
            synq_verifications: BTreeMap::new(),
            synq_errors: BTreeMap::new(),
            synq_artifacts: BTreeMap::new(),
            synq_contracts: BTreeMap::new(),
            synq_aivm_state: ContractState::default(),
        }
    }

    pub fn with_balance(mut self, account: &str, amount_nwei: u128) -> Self {
        self.balances_nwei.insert(account.to_string(), amount_nwei);
        self
    }

    fn record_fee_charged(
        &mut self,
        tx_hash: String,
        block_height: u64,
        epoch: u64,
        payer: String,
        breakdown: &crate::gas::NetworkFeeBreakdown,
        success: bool,
    ) -> Result<(), String> {
        if breakdown.total_network_fee_nwei == 0 {
            return Ok(());
        }
        let accumulator = self
            .fee_accumulators
            .entry(epoch)
            .or_insert_with(|| FeeAccumulator {
                epoch,
                total_collected_nwei: 0,
                by_tx_type: BTreeMap::new(),
                opened_at_height: block_height,
                closed_at_height: None,
                status: "open".to_string(),
            });
        accumulator.total_collected_nwei = accumulator
            .total_collected_nwei
            .checked_add(breakdown.total_network_fee_nwei)
            .ok_or_else(|| "fee accumulator overflow".to_string())?;
        let by_type = accumulator
            .by_tx_type
            .entry(breakdown.tx_type.as_str().to_string())
            .or_insert(0);
        *by_type = by_type
            .checked_add(breakdown.total_network_fee_nwei)
            .ok_or_else(|| "fee accumulator tx-type overflow".to_string())?;
        self.fee_events.push(FeeChargedEvent {
            tx_hash,
            block_height,
            epoch,
            payer,
            tx_type: breakdown.tx_type.as_str().to_string(),
            asset_id: breakdown.asset_id.clone(),
            amount_raw: breakdown.amount_raw,
            amount_snrgequivalent_nwei: breakdown.amount_snrgequivalent_nwei,
            valuation_source: breakdown.valuation_source.clone(),
            valuation_status: breakdown.valuation_status.as_str().to_string(),
            gas_used: breakdown.gas_used,
            base_fee_per_gas_nwei: breakdown.base_fee_per_gas_nwei,
            gas_fee_nwei: breakdown.gas_fee_nwei,
            amount_fee_bps: breakdown.amount_fee_bps,
            amount_protocol_fee_nwei: breakdown.amount_protocol_fee_nwei,
            storage_fee_nwei: breakdown.storage_fee_nwei,
            priority_fee_nwei: breakdown.priority_fee_nwei,
            total_fee_nwei: breakdown.total_network_fee_nwei,
            fee_collector_address: crate::token::FEE_COLLECTOR_ADDRESS.to_string(),
            success,
        });
        Ok(())
    }

    fn record_burn_address_transfer(
        &mut self,
        tx_hash: String,
        sender: String,
        asset_id: String,
        amount: u128,
    ) -> Result<(), String> {
        if amount == 0 {
            return Ok(());
        }
        let entry = self
            .burn_ledger
            .entry(asset_id.clone())
            .or_insert_with(|| BurnLedgerEntry {
                asset_id: asset_id.clone(),
                total_burned_or_locked: 0,
            });
        entry.total_burned_or_locked = entry
            .total_burned_or_locked
            .checked_add(amount)
            .ok_or_else(|| "burn ledger overflow".to_string())?;
        self.burn_events.push(BurnAddressTransferEvent {
            tx_hash,
            sender,
            asset_id,
            amount,
            burn_address: crate::address::NETWORK_BURN_ADDRESS.to_string(),
            supply_reduced_bool: false,
        });
        Ok(())
    }

    pub fn mark_authorized(&mut self, tx: &Transaction) -> Result<TxId, String> {
        let tx_id = tx_id(tx)?;
        self.verified_authorizations
            .insert(tx_id.clone(), tx.canonical_tx_bytes_hash()?);
        match crate::synq_admission::verify_transaction_payload_for_chain_admission(
            tx,
            current_unix_timestamp(),
        ) {
            Ok(Some(summary)) => {
                self.synq_verifications.insert(tx_id.clone(), summary);
            }
            Ok(None) => {}
            Err(error) => {
                self.synq_errors
                    .insert(tx_id.clone(), (error.code().to_string(), error.to_string()));
                return Err(error.to_string());
            }
        }
        Ok(tx_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionGraph {
    pub batches: Vec<Vec<TxId>>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReceiptStatus {
    Success,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TransactionReceipt {
    pub tx_id: TxId,
    pub status: ReceiptStatus,
    pub gas_used: u64,
    pub fee_breakdown: Option<crate::gas::NetworkFeeBreakdown>,
    pub error: String,
    pub state_root_after: Hash,
    pub synq_verification: Option<SynQVerificationSummary>,
    pub synq_aivm: Option<SynQAivmReceiptSummary>,
    pub synq_error_code: Option<String>,
    pub synq_error_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    pub state: ExecutionState,
    pub receipts: Vec<TransactionReceipt>,
    pub state_root_after: Hash,
    pub receipt_root: Hash,
}

pub fn execute_block(block: &Block, state: &ExecutionState) -> Result<ExecutionResult, String> {
    let graph = build_execution_graph(&block.transactions)?;
    let batches = split_into_parallel_batches(&graph);
    let mut working_state = state.clone();
    let mut receipts = Vec::new();
    let synq_context = SynQExecutionContext {
        runtime_block_height: block.header.height.0,
    };
    for batch in batches {
        let mut batch_receipts = execute_batch_parallel(
            &batch,
            &block.transactions,
            &mut working_state,
            synq_context,
        )?;
        receipts.append(&mut batch_receipts);
    }
    receipts = merge_results_in_canonical_order(receipts);
    let state_root_after = compute_state_root_after(&working_state)?;
    let receipt_root = compute_receipt_root(&receipts)?;
    Ok(ExecutionResult {
        state: working_state,
        receipts,
        state_root_after,
        receipt_root,
    })
}

pub fn build_execution_graph(transactions: &[Transaction]) -> Result<ExecutionGraph, String> {
    let mut resource_owner = BTreeMap::<String, TxId>::new();
    let mut tx_depth = BTreeMap::<TxId, usize>::new();
    let mut batches: Vec<Vec<TxId>> = Vec::new();
    for tx in transactions {
        let id = tx_id(tx)?;
        let mut depth = 0usize;
        for resource in &tx.write_set_hint {
            if let Some(parent) = resource_owner.get(resource) {
                depth = depth.max(tx_depth.get(parent).copied().unwrap_or(0).saturating_add(1));
            }
        }
        tx_depth.insert(id.clone(), depth);
        for resource in &tx.write_set_hint {
            resource_owner.insert(resource.clone(), id.clone());
        }
        if batches.len() <= depth {
            batches.resize(depth + 1, Vec::new());
        }
        batches[depth].push(id);
    }
    for batch in &mut batches {
        batch.sort();
    }
    Ok(ExecutionGraph { batches })
}

pub fn split_into_parallel_batches(graph: &ExecutionGraph) -> Vec<Vec<TxId>> {
    graph.batches.clone()
}

pub fn execute_batch_parallel(
    batch: &[TxId],
    transactions: &[Transaction],
    state: &mut ExecutionState,
    synq_context: SynQExecutionContext,
) -> Result<Vec<TransactionReceipt>, String> {
    let by_id = transactions
        .iter()
        .map(|tx| tx_id(tx).map(|id| (id, tx)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let mut receipts = Vec::new();
    for tx_id in batch {
        let tx = by_id
            .get(tx_id)
            .ok_or_else(|| format!("transaction {} missing from batch input", tx_id.0))?;
        receipts.push(execute_transaction(tx_id.clone(), tx, state, synq_context)?);
    }
    Ok(receipts)
}

pub fn merge_results_in_canonical_order(
    mut receipts: Vec<TransactionReceipt>,
) -> Vec<TransactionReceipt> {
    receipts.sort_by(|a, b| a.tx_id.cmp(&b.tx_id));
    receipts
}

pub fn compute_state_root_after(state: &ExecutionState) -> Result<Hash, String> {
    #[derive(serde::Serialize)]
    struct ArtifactRootEntry<'a> {
        key: &'a SynQArtifactKey,
        artifact: &'a SynQContractArtifact,
    }

    #[derive(serde::Serialize)]
    struct StateRootPayload<'a> {
        balances_nwei: &'a BTreeMap<String, u128>,
        fee_accumulators: &'a BTreeMap<u64, FeeAccumulator>,
        fee_events: &'a [FeeChargedEvent],
        burn_ledger: &'a BTreeMap<String, BurnLedgerEntry>,
        burn_events: &'a [BurnAddressTransferEvent],
        sts_state: &'a StsState,
        synq_artifacts: Vec<ArtifactRootEntry<'a>>,
        synq_contracts: &'a BTreeMap<String, SynQDeploymentRecord>,
        synq_aivm_state_root: [u8; 32],
    }

    let synq_artifacts = state
        .synq_artifacts
        .iter()
        .map(|(key, artifact)| ArtifactRootEntry { key, artifact })
        .collect::<Vec<_>>();
    let payload = StateRootPayload {
        balances_nwei: &state.balances_nwei,
        fee_accumulators: &state.fee_accumulators,
        fee_events: &state.fee_events,
        burn_ledger: &state.burn_ledger,
        burn_events: &state.burn_events,
        sts_state: &state.sts_state,
        synq_artifacts,
        synq_contracts: &state.synq_contracts,
        synq_aivm_state_root: state.synq_aivm_state.state_root(),
    };
    serde_json::to_vec(&payload)
        .map(|bytes| Hash::from_domain_bytes(SYNERGY_STATE_ROOT_V1, &bytes))
        .map_err(|error| format!("state root serialize failed: {error}"))
}

pub fn compute_receipt_root(receipts: &[TransactionReceipt]) -> Result<Hash, String> {
    serde_json::to_vec(receipts)
        .map(|bytes| Hash::from_domain_bytes(SYNERGY_RECEIPT_ROOT_V1, &bytes))
        .map_err(|error| format!("receipt root serialize failed: {error}"))
}

fn execute_transaction(
    id: TxId,
    tx: &Transaction,
    state: &mut ExecutionState,
    synq_context: SynQExecutionContext,
) -> Result<TransactionReceipt, String> {
    let canonical_hash = tx.canonical_tx_bytes_hash()?;
    match state.verified_authorizations.get(&id) {
        Some(recorded) if *recorded == canonical_hash => {}
        Some(_) => {
            return Err(format!(
                "transaction {} bytes changed after PQC authorization verification",
                id.0
            ));
        }
        None => {
            return Err(format!(
                "transaction {} missing verified Aegis PQC authorization context",
                id.0
            ));
        }
    }

    let sender = tx.sender_uma_or_account.clone();
    if let Some(sts_payload) =
        crate::sts::decode_sts_payload(&tx.payload).map_err(|error| error.to_string())?
    {
        return execute_sts_transaction(id, tx, state, sts_payload);
    }

    let receiver = tx.receiver_uma_or_account.clone();
    let total_debit = tx.amount_nwei.saturating_add(tx.max_fee_nwei);
    let sender_balance = state.balances_nwei.get(&sender).copied().unwrap_or(0);
    let synq_verification = state.synq_verifications.get(&id).cloned();
    let synq_error = state.synq_errors.get(&id).cloned();
    let receipt = if sender_balance >= total_debit {
        let synq_aivm = if let Some(summary) = synq_verification.as_ref() {
            execute_synq_transaction_at(
                &id,
                tx,
                summary,
                &mut state.synq_aivm_state,
                &mut state.synq_artifacts,
                &mut state.synq_contracts,
                synq_context,
            )?
        } else {
            None
        };
        if synq_aivm
            .as_ref()
            .is_some_and(|receipt| receipt.status != "succeeded")
        {
            let error = synq_aivm
                .as_ref()
                .and_then(|receipt| receipt.error_message.clone())
                .unwrap_or_else(|| "SYNQ_AIVM_EXECUTION_FAILED".to_string());
            return Ok(TransactionReceipt {
                tx_id: id,
                status: ReceiptStatus::Failed,
                gas_used: synq_aivm
                    .as_ref()
                    .map(|receipt| receipt.gas_used)
                    .unwrap_or_else(|| tx.gas_limit.min(21_000)),
                error,
                state_root_after: compute_state_root_after(state)?,
                synq_verification,
                synq_aivm,
                synq_error_code: synq_error.as_ref().map(|(code, _)| code.clone()),
                synq_error_message: synq_error.map(|(_, message)| message),
            });
        }
        state
            .balances_nwei
            .insert(sender.clone(), sender_balance - total_debit);
        let receiver_balance = state.balances_nwei.get(&receiver).copied().unwrap_or(0);
        state
            .balances_nwei
            .insert(receiver, receiver_balance.saturating_add(tx.amount_nwei));
        TransactionReceipt {
            tx_id: id,
            status: ReceiptStatus::Success,
            gas_used: synq_aivm
                .as_ref()
                .map(|receipt| receipt.gas_used)
                .unwrap_or_else(|| tx.gas_limit.min(21_000)),
            error: String::new(),
            state_root_after: compute_state_root_after(state)?,
            synq_verification,
            synq_aivm,
            synq_error_code: synq_error.as_ref().map(|(code, _)| code.clone()),
            synq_error_message: synq_error.map(|(_, message)| message),
        }
    } else {
        TransactionReceipt {
            tx_id: id,
            status: ReceiptStatus::Failed,
            gas_used: tx.gas_limit.min(21_000),
            error: "INSUFFICIENT_FUNDS".to_string(),
            state_root_after: compute_state_root_after(state)?,
            synq_verification,
            synq_aivm: None,
            synq_error_code: synq_error.as_ref().map(|(code, _)| code.clone()),
            synq_error_message: synq_error.map(|(_, message)| message),
        }
    };
    Ok(receipt)
}

fn execute_sts_transaction(
    id: TxId,
    tx: &Transaction,
    state: &mut ExecutionState,
    sts_payload: StsSignedPayload,
) -> Result<TransactionReceipt, String> {
    let sender = tx.sender_uma_or_account.clone();
    let sender_balance = state.balances_nwei.get(&sender).copied().unwrap_or(0);
    let fee_nwei = tx.max_fee_nwei;
    let gas_used = tx
        .gas_limit
        .min(crate::sts::estimate_sts_gas(&sts_payload.tx));
    let synq_error = state.synq_errors.get(&id).cloned();

    if sender_balance < fee_nwei {
        return Ok(TransactionReceipt {
            tx_id: id,
            status: ReceiptStatus::Failed,
            gas_used,
            error: "INSUFFICIENT_FUNDS".to_string(),
            state_root_after: compute_state_root_after(state)?,
            synq_verification: None,
            synq_aivm: None,
            synq_error_code: synq_error.as_ref().map(|(code, _)| code.clone()),
            synq_error_message: synq_error.map(|(_, message)| message),
        });
    }

    let mut candidate = state.sts_state.clone();
    let apply_result = candidate.apply_signed_payload(&sender, &sts_payload);
    charge_fee_to_collector(state, &sender, fee_nwei)?;

    match apply_result {
        Ok(_) => {
            state.sts_state = candidate;
            Ok(TransactionReceipt {
                tx_id: id,
                status: ReceiptStatus::Success,
                gas_used,
                error: String::new(),
                state_root_after: compute_state_root_after(state)?,
                synq_verification: None,
                synq_aivm: None,
                synq_error_code: synq_error.as_ref().map(|(code, _)| code.clone()),
                synq_error_message: synq_error.map(|(_, message)| message),
            })
        }
        Err(error) => Ok(TransactionReceipt {
            tx_id: id,
            status: ReceiptStatus::Failed,
            gas_used,
            error: error.to_string(),
            state_root_after: compute_state_root_after(state)?,
            synq_verification: None,
            synq_aivm: None,
            synq_error_code: synq_error.as_ref().map(|(code, _)| code.clone()),
            synq_error_message: synq_error.map(|(_, message)| message),
        }),
    }
}

fn charge_fee_to_collector(
    state: &mut ExecutionState,
    sender: &str,
    fee_nwei: u128,
) -> Result<(), String> {
    let sender_balance = state.balances_nwei.get(sender).copied().unwrap_or(0);
    if sender_balance < fee_nwei {
        return Err("insufficient SNRG balance for STS fee".to_string());
    }
    state
        .balances_nwei
        .insert(sender.to_string(), sender_balance - fee_nwei);
    let collector = crate::token::FEE_COLLECTOR_ADDRESS.to_string();
    let collector_balance = state.balances_nwei.get(&collector).copied().unwrap_or(0);
    let next_collector_balance = collector_balance
        .checked_add(fee_nwei)
        .ok_or_else(|| "fee collector balance overflow".to_string())?;
    state
        .balances_nwei
        .insert(collector, next_collector_balance);
    Ok(())
}

fn current_unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn tx_id(tx: &Transaction) -> Result<TxId, String> {
    Ok(TxId::from_hash(Hash::from_domain_bytes(
        "SYNERGY_EXECUTION_TX_ID_V1",
        &tx.canonical_bytes()?,
    )))
}

pub fn verified_context_for_block(
    transactions: &[Transaction],
) -> Result<BTreeMap<TxId, Hash>, String> {
    let mut context = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for tx in transactions {
        let id = tx_id(tx)?;
        if !seen.insert(id.clone()) {
            return Err(format!("duplicate transaction {} in block", id.0));
        }
        context.insert(id, tx.canonical_tx_bytes_hash()?);
    }
    Ok(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synergy_types::{
        AegisPqKeyId, AegisPqSignature, ChainId, Epoch, Height, NetworkId, UmaId,
    };
    use crate::synq_execution::{
        derive_synq_contract_address_from_deploy, synergy_contract_address_from_pqsynq_address,
    };
    use pqsynq::{
        canonicalize_signing_payload, derive_synq_address, hash_contract_call_body,
        hash_contract_deploy_body, AlgorithmId, ChainId as PqSynQChainId, ContractCallEnvelope,
        ContractDeployEnvelope, DigitalSignature, DomainTag, NetworkId as PqSynQNetworkId, Sign,
        SignaturePurpose, SynQAddress, SynQPublicKey, SynQSignature, SynQSigningPayload,
    };
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::PathBuf;

    fn tx(sender: &str, receiver: &str, nonce: u64, amount: u128, write: &str) -> Transaction {
        Transaction {
            version: 1,
            chain_id: ChainId::synergy_testnet_v2(),
            network_id: NetworkId::synergy_testnet_v2(),
            epoch: Epoch(0),
            sender_uma_or_account: sender.to_string(),
            receiver_uma_or_account: receiver.to_string(),
            account_nonce_or_sequence: nonce,
            amount_nwei: amount,
            gas_limit: 21_000,
            max_fee_nwei: 1,
            ttl_height: Height(100),
            explicit_dependencies: Vec::new(),
            read_set_hint: Vec::new(),
            write_set_hint: vec![write.to_string()],
            payload: Vec::new(),
            signer_uma_id: UmaId(sender.to_string()),
            aegis_pq_key_id: AegisPqKeyId("key".to_string()),
            aegis_pq_signature: AegisPqSignature {
                algorithm: "fndsa".to_string(),
                signature_bytes: vec![1, 2, 3],
            },
        }
    }

    fn block(transactions: Vec<Transaction>) -> Block {
        Block {
            header: crate::synergy_types::BlockHeader {
                version: 1,
                chain_id: ChainId::synergy_testnet_v2(),
                network_id: NetworkId::synergy_testnet_v2(),
                height: Height(1),
                round: crate::synergy_types::Round(0),
                epoch: Epoch(0),
                cluster_id: crate::synergy_types::ClusterId(0),
                parent_block_hash: Hash::zero(),
                parent_state_root: Hash::zero(),
                last_finalized_qc_hash: Hash::zero(),
                proposer_validator_id: crate::synergy_types::ValidatorId("v1".to_string()),
                proposer_uma_id: UmaId("uma-v1".to_string()),
                proposer_key_id: AegisPqKeyId("key".to_string()),
                active_validator_set_hash: Hash::zero(),
                eligible_validator_set_hash: Hash::zero(),
                cluster_map_hash: Hash::zero(),
                proposer_schedule_hash: Hash::zero(),
                protocol_config_hash: Hash::zero(),
                dag_frontier_root: Hash::zero(),
                tx_order_root: Hash::zero(),
                tx_count: transactions.len() as u64,
                evidence_root: Hash::zero(),
                state_root_before: Hash::zero(),
                state_root_after: Hash::zero(),
                receipt_root: Hash::zero(),
                app_version: 1,
                execution_version: 1,
                dag_version: 1,
                aegis_pqvm_version: "aegis-pqvm".to_string(),
                timestamp_ms_consensus_bounded: 0,
            },
            transactions,
            proposer_signature: AegisPqSignature {
                algorithm: "fndsa".to_string(),
                signature_bytes: vec![1],
            },
        }
    }

    fn authorized_state(transactions: &[Transaction]) -> ExecutionState {
        let mut state = ExecutionState::new()
            .with_balance("alice", 1_000_000)
            .with_balance("bob", 1_000_000)
            .with_balance("carol", 0)
            .with_balance("dave", 0);
        state.verified_authorizations = verified_context_for_block(transactions).unwrap();
        state
    }

    #[derive(Clone)]
    struct CounterSynQFixture {
        public_key: SynQPublicKey,
        private_key: Vec<u8>,
        address: SynQAddress,
        bytecode: Vec<u8>,
        abi_json: String,
        manifest_json: String,
        bytecode_hash: [u8; 32],
        manifest_hash: [u8; 32],
        abi_hash: [u8; 32],
    }

    impl CounterSynQFixture {
        fn new() -> Self {
            let signer = Sign::mldsa65();
            let (public_key_bytes, private_key) = signer.keygen().expect("ML-DSA-65 keygen");
            let public_key = SynQPublicKey::new(public_key_bytes);
            let address = derive_synq_address(
                &public_key,
                AlgorithmId::MlDsa65,
                &PqSynQNetworkId(
                    crate::synq_admission::SYNQ_CANONICAL_TESTNET_NETWORK_ID.to_string(),
                ),
            )
            .expect("derive SynQ address");

            let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../../../Volumes/xcode/Synergy-Network-Projects/synq-language/contracts");
            let root = if root.exists() {
                root
            } else {
                PathBuf::from("/Volumes/xcode/Synergy-Network-Projects/synq-language/contracts")
            };
            let bytecode = fs::read(root.join("Counter.compiled.synq")).expect("Counter bytecode");
            let abi_json = fs::read_to_string(root.join("Counter.abi.json")).expect("Counter ABI");
            let manifest_json =
                fs::read_to_string(root.join("Counter.manifest.json")).expect("Counter manifest");
            let bytecode_hash = sha256_array(&bytecode);
            let manifest_hash = sha256_array(manifest_json.as_bytes());
            let abi_hash = sha256_array(abi_json.as_bytes());

            Self {
                public_key,
                private_key,
                address,
                bytecode,
                abi_json,
                manifest_json,
                bytecode_hash,
                manifest_hash,
                abi_hash,
            }
        }

        fn deploy_envelope(&self) -> ContractDeployEnvelope {
            let constructor_args_hash = sha256_array(&[]);
            let payload_hash = hash_contract_deploy_body(
                &self.bytecode_hash,
                &self.manifest_hash,
                &self.abi_hash,
                self.address.as_bytes(),
                &constructor_args_hash,
            );
            let signing_payload = self.signing_payload(
                DomainTag::SynqContractDeployV1,
                SignaturePurpose::ContractDeploy,
                payload_hash,
                101,
            );
            let signature = self.sign_payload(&signing_payload);
            ContractDeployEnvelope {
                signing_payload,
                public_key: self.public_key.clone(),
                signature: SynQSignature::new(signature),
                bytecode_hash: self.bytecode_hash,
                manifest_hash: self.manifest_hash,
                abi_hash: self.abi_hash,
                constructor_args_hash,
            }
        }

        fn contract_address(&self) -> SynQAddress {
            derive_synq_contract_address_from_deploy(&self.deploy_envelope())
                .expect("derive SynQ contract address")
        }

        fn deploy_payload(&self, include_artifacts: bool) -> Vec<u8> {
            let deploy = self.deploy_envelope();
            let pqsynq_bytes = serde_json::to_vec(&deploy).expect("deploy JSON");
            if include_artifacts {
                crate::synq_admission::build_deploy_admission_carrier_from_pqsynq_bytes_with_artifacts(
                    crate::synergy_types::SYNERGY_TESTNET_V2_CHAIN_ID,
                    crate::synergy_types::SYNERGY_TESTNET_V2_NETWORK_ID,
                    &pqsynq_bytes,
                    self.bytecode.clone(),
                    self.abi_json.clone(),
                    self.manifest_json.clone(),
                    crate::synq_admission::test_support::TEST_NOW,
                )
                .expect("deploy carrier with artifacts")
            } else {
                crate::synq_admission::build_deploy_admission_carrier_from_pqsynq_bytes(
                    crate::synergy_types::SYNERGY_TESTNET_V2_CHAIN_ID,
                    crate::synergy_types::SYNERGY_TESTNET_V2_NETWORK_ID,
                    &pqsynq_bytes,
                    crate::synq_admission::test_support::TEST_NOW,
                )
                .expect("deploy carrier")
            }
        }

        fn call_payload(
            &self,
            contract_address: SynQAddress,
            method_selector: [u8; 4],
            nonce: u64,
        ) -> Vec<u8> {
            let encoded_args_hash = sha256_array(&[]);
            let payload_hash = hash_contract_call_body(
                contract_address.as_bytes(),
                &method_selector,
                &encoded_args_hash,
                self.address.as_bytes(),
            );
            let signing_payload = self.signing_payload(
                DomainTag::SynqContractCallV1,
                SignaturePurpose::ContractCall,
                payload_hash,
                nonce,
            );
            let signature = self.sign_payload(&signing_payload);
            let call = ContractCallEnvelope {
                signing_payload,
                public_key: self.public_key.clone(),
                signature: SynQSignature::new(signature),
                contract_address,
                method_selector,
                encoded_args_hash,
            };
            crate::synq_admission::build_call_admission_carrier_from_pqsynq_bytes(
                crate::synergy_types::SYNERGY_TESTNET_V2_CHAIN_ID,
                crate::synergy_types::SYNERGY_TESTNET_V2_NETWORK_ID,
                &serde_json::to_vec(&call).expect("call JSON"),
                crate::synq_admission::test_support::TEST_NOW,
            )
            .expect("call carrier")
        }

        fn signing_payload(
            &self,
            domain_tag: DomainTag,
            signature_purpose: SignaturePurpose,
            payload_hash: [u8; 32],
            nonce: u64,
        ) -> SynQSigningPayload {
            SynQSigningPayload {
                domain_tag,
                chain_id: PqSynQChainId(crate::synergy_types::SYNERGY_TESTNET_V2_CHAIN_ID),
                network_id: PqSynQNetworkId(
                    crate::synq_admission::SYNQ_CANONICAL_TESTNET_NETWORK_ID.to_string(),
                ),
                protocol_version: 1,
                algorithm_id: AlgorithmId::MlDsa65,
                signature_purpose,
                nonce,
                not_before_unix: 0,
                expiration_unix: 4_102_444_800,
                signer_address: self.address,
                payload_hash,
            }
        }

        fn sign_payload(&self, payload: &SynQSigningPayload) -> Vec<u8> {
            let canonical = canonicalize_signing_payload(payload).expect("canonical payload");
            Sign::mldsa65()
                .detached_sign(&canonical, &self.private_key)
                .expect("ML-DSA-65 sign")
        }
    }

    fn synq_tx(payload: Vec<u8>, nonce: u64, gas_limit: u64, write: &str) -> Transaction {
        let mut transaction = tx("alice", "carol", nonce, 0, write);
        transaction.payload = payload;
        transaction.gas_limit = gas_limit;
        transaction
    }

    fn run_counter_flow(
        deploy_payload: Vec<u8>,
        increment_payload: Vec<u8>,
        get_payload: Vec<u8>,
        expected_contract_address: &str,
    ) -> (Hash, String, String, String, u64) {
        let mut state = ExecutionState::new()
            .with_balance("alice", 1_000_000)
            .with_balance("carol", 0);

        let deploy = synq_tx(deploy_payload, 0, 150_000, "synq-counter");
        state.mark_authorized(&deploy).expect("deploy authorized");
        let deploy_result = execute_block(&block(vec![deploy]), &state).expect("deploy executes");
        let deploy_receipt = deploy_result.receipts.first().expect("deploy receipt");
        assert_eq!(deploy_receipt.status, ReceiptStatus::Success);
        let deploy_aivm = deploy_receipt
            .synq_aivm
            .as_ref()
            .expect("deploy AIVM receipt");
        assert_eq!(deploy_aivm.contract_address, expected_contract_address);
        let deploy_hash = deploy_aivm.receipt_hash.clone();

        let mut state = deploy_result.state;
        let increment = synq_tx(increment_payload, 1, 30_000, "synq-counter");
        state
            .mark_authorized(&increment)
            .expect("increment authorized");
        let increment_result =
            execute_block(&block(vec![increment]), &state).expect("increment executes");
        let increment_receipt = increment_result
            .receipts
            .first()
            .expect("increment receipt");
        assert_eq!(increment_receipt.status, ReceiptStatus::Success);
        let increment_aivm = increment_receipt
            .synq_aivm
            .as_ref()
            .expect("increment AIVM receipt");
        assert_eq!(decode_u256_hex(&increment_aivm.return_data_hex), 1);
        let increment_hash = increment_aivm.receipt_hash.clone();

        let mut state = increment_result.state;
        let get = synq_tx(get_payload, 2, 30_000, "synq-counter");
        state.mark_authorized(&get).expect("get authorized");
        let get_result = execute_block(&block(vec![get]), &state).expect("get executes");
        let get_receipt = get_result.receipts.first().expect("get receipt");
        assert_eq!(get_receipt.status, ReceiptStatus::Success);
        let get_aivm = get_receipt.synq_aivm.as_ref().expect("get AIVM receipt");
        let get_value = decode_u256_hex(&get_aivm.return_data_hex);

        (
            get_result.state_root_after,
            deploy_hash,
            increment_hash,
            get_aivm.receipt_hash.clone(),
            get_value,
        )
    }

    fn decode_u256_hex(value: &str) -> u64 {
        let bytes = hex::decode(value).expect("return data hex");
        assert_eq!(bytes.len(), 32);
        u64::from_be_bytes(bytes[24..32].try_into().expect("u64 tail"))
    }

    fn sha256_array(bytes: &[u8]) -> [u8; 32] {
        let digest = Sha256::digest(bytes);
        let mut out = [0_u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    #[test]
    fn same_block_executed_repeatedly_produces_same_state_root() {
        let transactions = vec![
            tx("alice", "carol", 0, 10, "alice"),
            tx("bob", "dave", 0, 20, "bob"),
        ];
        let block = block(transactions.clone());
        let state = authorized_state(&transactions);
        let first = execute_block(&block, &state).unwrap().state_root_after;
        for _ in 0..100 {
            assert_eq!(
                execute_block(&block, &state).unwrap().state_root_after,
                first
            );
        }
    }

    #[test]
    fn failed_receipt_is_deterministic_and_conflicts_execute_in_order() {
        let transactions = vec![
            tx("alice", "carol", 0, 10, "alice"),
            tx("alice", "dave", 1, 2_000_000, "alice"),
        ];
        let block = block(transactions.clone());
        let state = authorized_state(&transactions);
        let a = execute_block(&block, &state).unwrap();
        let b = execute_block(&block, &state).unwrap();
        assert_eq!(a.receipts, b.receipts);
        assert!(a
            .receipts
            .iter()
            .any(|receipt| receipt.status == ReceiptStatus::Failed));
    }

    #[test]
    fn receipt_preserves_synq_verification_summary() {
        let transaction = tx("alice", "carol", 0, 10, "synq-contract");
        let id = tx_id(&transaction).unwrap();
        let block = block(vec![transaction.clone()]);
        let mut state = authorized_state(&[transaction]);
        state.synq_verifications.insert(
            id,
            crate::synq_admission::SynQVerificationSummary {
                chain_id: crate::synergy_types::SYNERGY_TESTNET_V2_CHAIN_ID,
                normalized_network_id: "synergy-testnet".to_string(),
                node_network_id: crate::synergy_types::SYNERGY_TESTNET_V2_NETWORK_ID.to_string(),
                domain: "SYNQ_CONTRACT_DEPLOY_V1".to_string(),
                algorithm: "ML-DSA-65".to_string(),
                signer: "tsynq1fixture".to_string(),
                payload_hash: [7; 32],
                bytecode_hash: Some([1; 32]),
                manifest_hash: Some([2; 32]),
                abi_hash: Some([3; 32]),
                verified_at_admission: true,
            },
        );

        let result = execute_block(&block, &state).unwrap();
        let receipt = result.receipts.first().expect("receipt");
        assert_eq!(
            receipt
                .synq_verification
                .as_ref()
                .map(|summary| summary.domain.as_str()),
            Some("SYNQ_CONTRACT_DEPLOY_V1")
        );
    }

    #[test]
    fn synq_deploy_carrier_reaches_receipt_through_node_admission() {
        let carrier = crate::synq_admission::test_support::deploy_carrier(
            crate::synergy_types::SYNERGY_TESTNET_V2_NETWORK_ID,
        );
        let mut transaction = tx("alice", "carol", 0, 10, "synq-contract");
        transaction.payload = crate::synq_admission::encode_synq_admission_carrier(&carrier)
            .expect("encode SynQ admission carrier");
        transaction.gas_limit = 150_000;

        let block = block(vec![transaction.clone()]);
        let mut state = ExecutionState::new()
            .with_balance("alice", 1_000_000)
            .with_balance("carol", 0);
        state
            .mark_authorized(&transaction)
            .expect("SynQ carrier admitted by node authorization path");

        let result = execute_block(&block, &state).expect("authorized block executes");
        let receipt = result.receipts.first().expect("receipt");
        let summary = receipt
            .synq_verification
            .as_ref()
            .expect("receipt includes SynQ verification summary");
        assert_eq!(summary.domain, "SYNQ_CONTRACT_DEPLOY_V1");
        assert_eq!(summary.algorithm, "ML-DSA-65");
        assert_eq!(summary.signer, carrier.signer);
        assert_eq!(summary.payload_hash, carrier.payload_hash);
        assert_eq!(summary.bytecode_hash, carrier.bytecode_hash);
        assert!(summary.verified_at_admission);
    }

    #[test]
    fn synq_counter_deploy_increment_get_execute_through_aivm_and_replay() {
        let fixture = CounterSynQFixture::new();
        let deploy_payload = fixture.deploy_payload(true);
        let contract_address = fixture.contract_address();
        let contract_address_text = synergy_contract_address_from_pqsynq_address(&contract_address);
        assert_ne!(
            contract_address_text,
            fixture.address.to_testnet_debug_string()
        );
        let increment_payload = fixture.call_payload(
            contract_address,
            aivm_core::synq_runtime::COUNTER_INCREMENT_SELECTOR,
            102,
        );
        let get_payload = fixture.call_payload(
            contract_address,
            aivm_core::synq_runtime::COUNTER_GET_SELECTOR,
            103,
        );

        let first = run_counter_flow(
            deploy_payload.clone(),
            increment_payload.clone(),
            get_payload.clone(),
            &contract_address_text,
        );
        let replay = run_counter_flow(
            deploy_payload,
            increment_payload,
            get_payload,
            &contract_address_text,
        );

        assert_eq!(first, replay);
        assert_eq!(first.4, 1);
    }

    #[test]
    fn synq_hash_only_deploy_fails_closed_before_aivm_execution() {
        let fixture = CounterSynQFixture::new();
        let deploy = synq_tx(fixture.deploy_payload(false), 0, 150_000, "synq-counter");
        let mut state = ExecutionState::new()
            .with_balance("alice", 1_000_000)
            .with_balance("carol", 0);
        state.mark_authorized(&deploy).expect("deploy authorized");

        let result = execute_block(&block(vec![deploy]), &state).expect("block executes");
        let receipt = result.receipts.first().expect("receipt");
        assert_eq!(receipt.status, ReceiptStatus::Failed);
        let aivm = receipt
            .synq_aivm
            .as_ref()
            .expect("failure includes AIVM summary");
        assert_eq!(aivm.operation, "deploy");
        assert_eq!(aivm.status, "failed");
        assert_eq!(aivm.error_code.as_deref(), Some("SYNQ-AIVM-ARTIFACT"));
        assert!(result.state.synq_contracts.is_empty());
    }

    #[test]
    fn synq_bad_call_selector_rolls_back_aivm_state() {
        let fixture = CounterSynQFixture::new();
        let deploy = synq_tx(fixture.deploy_payload(true), 0, 150_000, "synq-counter");
        let contract_address = fixture.contract_address();
        let mut state = ExecutionState::new()
            .with_balance("alice", 1_000_000)
            .with_balance("carol", 0);
        state.mark_authorized(&deploy).expect("deploy authorized");
        let deploy_result = execute_block(&block(vec![deploy]), &state).expect("deploy executes");
        assert_eq!(
            deploy_result.receipts.first().expect("receipt").status,
            ReceiptStatus::Success
        );

        let mut state = deploy_result.state;
        let state_root_before = compute_state_root_after(&state).expect("state root");
        let bad_call = synq_tx(
            fixture.call_payload(contract_address, [0, 0, 0, 0], 104),
            1,
            30_000,
            "synq-counter",
        );
        state
            .mark_authorized(&bad_call)
            .expect("bad call authorized");

        let result = execute_block(&block(vec![bad_call]), &state).expect("bad call executes");
        let receipt = result.receipts.first().expect("receipt");
        assert_eq!(receipt.status, ReceiptStatus::Failed);
        let aivm = receipt
            .synq_aivm
            .as_ref()
            .expect("failure includes AIVM summary");
        assert_eq!(aivm.operation, "call");
        assert_eq!(aivm.status, "failed");
        assert_eq!(aivm.error_code.as_deref(), Some("Abi"));
        assert_eq!(result.state_root_after, state_root_before);
    }

    #[test]
    fn missing_or_altered_authorization_context_fails_closed() {
        let mut transaction = tx("alice", "carol", 0, 10, "alice");
        let original_block = block(vec![transaction.clone()]);
        let state = ExecutionState::new().with_balance("alice", 100);
        assert!(execute_block(&original_block, &state).is_err());

        let mut state = authorized_state(&[transaction.clone()]);
        transaction.amount_nwei = 11;
        let altered = block(vec![transaction]);
        assert!(execute_block(&altered, &state).is_err());
        state.verified_authorizations.clear();
        assert!(execute_block(&altered, &state).is_err());
    }
}
