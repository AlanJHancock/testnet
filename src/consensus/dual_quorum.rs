use super::timing_trace;
use crate::block::Block;
use crate::consensus::anti_divergence::current_validator_quarantine_duty_block;
use crate::consensus::legacy_canonical_lock::{
    latest_legacy_canonical_commit_record, legacy_canonical_commit_record,
};
use crate::consensus::validator_keys::{
    sign_with_local_validator_key_for_height, verify_block_proposer_key_matches_validator,
    verify_signer_key_matches_validator_at_height,
};
use crate::crypto::pqc::{PQCCiphertext, PQCManager, PQCPrivateKey, PQCPublicKey, PQCSignature};
use crate::validator::{
    consensus_membership_validators, target_validator_cluster_count, Validator, ValidatorManager,
    ValidatorPerformanceUpdate, TESTNET_VALIDATOR_CLUSTER_SIZE, VALIDATOR_MANAGER,
};
use crate::{debug, warn};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Once};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

lazy_static::lazy_static! {
    static ref NETWORK_VOTE_MAILBOX: Arc<Mutex<HashMap<String, Vec<Vote>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    static ref COMMITTED_QC_STORE: Arc<Mutex<HashMap<String, QuorumCertificate>>> =
        Arc::new(Mutex::new(HashMap::new()));
    static ref OBSERVED_VOTES: Arc<Mutex<HashMap<String, Vote>>> = Arc::new(Mutex::new(HashMap::new()));
    static ref EQUIVOCATION_EVIDENCE_LOG: Arc<Mutex<HashMap<String, VoteEquivocationEvidence>>> =
        Arc::new(Mutex::new(HashMap::new()));
    static ref PROCESSED_EQUIVOCATION_EVIDENCE: Arc<Mutex<BTreeSet<String>>> =
        Arc::new(Mutex::new(BTreeSet::new()));
    static ref LOCAL_VOTE_LOCK_FILE_MUTEX: Mutex<()> = Mutex::new(());
}

static COMMITTED_QC_STORE_INIT: Once = Once::new();

pub const VALIDATOR_QUORUM_PERCENT: usize = 67;
pub const VALIDATOR_QUORUM_RATIO: f64 = VALIDATOR_QUORUM_PERCENT as f64 / 100.0;
pub const MIN_LAUNCH_VOTE_TIMEOUT_SECS: u64 = 1;
const LOCAL_VOTE_LOCK_COMPACTION_MIN_LOCKS: usize = 1024;
const LOCAL_VOTE_LOCK_FINALIZED_RETENTION_DEPTH: u64 = 16;
const COMMITTED_QC_HOT_RETENTION_BLOCKS_ENV: &str = "SYNERGY_COMMITTED_QC_HOT_RETENTION_BLOCKS";
const COMMITTED_QC_RETENTION_PRUNE_INTERVAL: usize = 1024;

#[derive(Debug, Clone)]
struct SameHeightVoteParent {
    height: u64,
    block_hash: String,
    source: &'static str,
    checkpoint_fork_parent: bool,
}

#[cfg(test)]
lazy_static::lazy_static! {
    static ref TEST_LOCAL_VOTE_LOCK_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);
    static ref TEST_VOTE_TRACKING_MUTEX: Mutex<()> = Mutex::new(());
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub validator_address: String,
    pub block_hash: String,
    #[serde(default)]
    pub block_index: u64,
    pub epoch_number: u64,
    #[serde(default)]
    pub round_number: u64,
    pub signature: PQCSignature,
    #[serde(default)]
    pub signer_public_key: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteEquivocationEvidence {
    pub validator_address: String,
    pub epoch_number: u64,
    pub block_index: u64,
    pub round_number: u64,
    pub first_vote: Vote,
    pub conflicting_vote: Vote,
    pub detected_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SupersededLocalVoteLock {
    block_hash: String,
    first_round_number: u64,
    latest_round_number: u64,
    proposer: String,
    superseded_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalVoteLock {
    validator_address: String,
    block_hash: String,
    block_index: u64,
    epoch_number: u64,
    first_round_number: u64,
    latest_round_number: u64,
    proposer: String,
    created_at: u64,
    updated_at: u64,
    #[serde(default)]
    superseded: Vec<SupersededLocalVoteLock>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalLockedVote {
    pub validator_address: String,
    pub block_hash: String,
    pub block_index: u64,
    pub epoch_number: u64,
    pub first_round_number: u64,
    pub latest_round_number: u64,
    pub proposer: String,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredTransientVoteLock {
    pub validator_address: String,
    pub block_hash: String,
    pub block_index: u64,
    pub epoch_number: u64,
    pub first_round_number: u64,
    pub latest_round_number: u64,
    pub proposer: String,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransientVoteLockRecoveryReport {
    pub action: String,
    pub reason: String,
    pub finalized_height: u64,
    pub min_age_secs: u64,
    pub vote_lock_path: String,
    pub evidence_path: String,
    pub before_count: usize,
    pub kept_count: usize,
    pub removed_count: usize,
    pub removed: Vec<RecoveredTransientVoteLock>,
    pub mutated: bool,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub block_hash: String,
    pub epoch_number: u64,
    pub round_number: u64,
    pub aggregate_signature: Vec<u8>,
    pub participant_bitmap: Vec<u8>,
    pub cumulative_weight: f64,
    pub validation_quorum_met: bool,
    pub cooperation_quorum_met: bool,
    pub timestamp: u64,
    #[serde(default)]
    pub votes: Vec<Vote>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CommittedQcLogEntry {
    block_hash: String,
    qc: QuorumCertificate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateSignature {
    pub combined_signature: Vec<u8>,
    pub participation_bitmap: Vec<u8>,
    pub message_hash: Vec<u8>,
    pub participant_count: usize,
}

#[derive(Debug)]
pub struct DualQuorumConsensus {
    pub validator_manager: Arc<ValidatorManager>,
    pub pqc_manager: Arc<Mutex<PQCManager>>,
    pub penalization_enabled: bool,
    pub minimum_validator_count: usize,
    pub validator_vote_threshold: usize,
    pub validation_quorum_threshold: f64,
    pub cooperation_quorum_threshold: f64,
    pub vote_timeout: u64,
    pub block_timeout: u64,
    pub current_epoch: u64,
    pub current_round_by_height: HashMap<u64, u64>,
    pub votes: HashMap<String, Vec<Vote>>, // block_hash -> votes
    pub quorum_certificates: HashMap<String, QuorumCertificate>, // block_hash -> QC
    verified_vote_signatures: Mutex<HashSet<String>>,
}

impl DualQuorumConsensus {
    pub fn new(
        validator_manager: Arc<ValidatorManager>,
        pqc_manager: Arc<Mutex<PQCManager>>,
        penalization_enabled: bool,
        minimum_validator_count: usize,
        validator_vote_threshold: usize,
        vote_timeout_secs: u64,
        block_timeout_secs: u64,
    ) -> Self {
        DualQuorumConsensus {
            validator_manager,
            pqc_manager,
            penalization_enabled,
            minimum_validator_count: minimum_validator_count.max(1),
            validator_vote_threshold,
            validation_quorum_threshold: VALIDATOR_QUORUM_RATIO,
            cooperation_quorum_threshold: VALIDATOR_QUORUM_RATIO,
            vote_timeout: vote_timeout_secs.max(MIN_LAUNCH_VOTE_TIMEOUT_SECS),
            block_timeout: block_timeout_secs.max(1),
            current_epoch: 0,
            current_round_by_height: HashMap::new(),
            votes: HashMap::new(),
            quorum_certificates: HashMap::new(),
            verified_vote_signatures: Mutex::new(HashSet::new()),
        }
    }

    pub fn start_consensus_round(
        &mut self,
        proposed_block: &Block,
        minimum_round_number: u64,
    ) -> Result<QuorumCertificate, String> {
        self.start_consensus_round_with_recovery(proposed_block, minimum_round_number, u64::MAX)
    }

    pub fn start_consensus_round_with_recovery(
        &mut self,
        proposed_block: &Block,
        minimum_round_number: u64,
        transient_vote_recovery_min_age_secs: u64,
    ) -> Result<QuorumCertificate, String> {
        if let Some(record) = current_validator_quarantine_duty_block() {
            return Err(format!(
                "validator is quarantined at divergence height {} by {} and cannot propose, vote, or aggregate QCs: {}",
                record.divergence_height.0, record.source, record.reason
            ));
        }
        let block_hash = proposed_block.hash.clone();
        let epoch_number = self.current_epoch;
        let local_validator_address = self
            .resolve_local_validator_address_for_round()
            .ok_or_else(|| "Local validator address is not configured".to_string())?;
        let round_number = self.allocate_round_number(
            proposed_block.block_index,
            epoch_number,
            &local_validator_address,
            minimum_round_number,
        );

        // Phase 1: Proposal validation
        self.validate_block_proposal(proposed_block)?;

        // Phase 2: Voting
        let votes = self.collect_votes(
            proposed_block,
            &block_hash,
            epoch_number,
            round_number,
            transient_vote_recovery_min_age_secs,
        )?;

        // Phase 3: Commitment
        self.check_quorums_and_commit(&block_hash, epoch_number, round_number, &votes)
    }

    fn validate_block_proposal(&self, block: &Block) -> Result<(), String> {
        Self::validate_block_proposal_static(block)?;
        verify_block_proposer_key_matches_validator(block, &self.validator_manager)
    }

    pub fn validate_block_proposal_static(block: &Block) -> Result<(), String> {
        if !Self::is_block_hash_valid(block) {
            return Err("Invalid block hash payload".to_string());
        }

        block.verify_proposer_signature()?;

        // Verify all transactions in the block
        for tx in &block.transactions {
            Self::verify_transaction_static(tx)?;
        }

        Ok(())
    }

    fn collect_votes(
        &mut self,
        proposed_block: &Block,
        block_hash: &str,
        epoch_number: u64,
        round_number: u64,
        transient_vote_recovery_min_age_secs: u64,
    ) -> Result<Vec<Vote>, String> {
        let active_validators = self.collect_live_validators();
        if active_validators.len() < self.minimum_validator_count {
            return Err(format!(
                "Insufficient live validators: {} active on the network, {} required",
                active_validators.len(),
                self.minimum_validator_count
            ));
        }

        let expected_validators = active_validators
            .iter()
            .map(|validator| validator.address.clone())
            .collect::<BTreeSet<_>>();
        let local_validator_address = self
            .resolve_local_validator_address_for_round()
            .ok_or_else(|| "Local validator address is not configured".to_string())?;
        if !expected_validators.contains(&local_validator_address) {
            return Err(format!(
                "Local validator {} is not eligible for this consensus round",
                local_validator_address
            ));
        }

        Self::recover_stale_conflicting_vote_lock_before_vote(
            &local_validator_address,
            proposed_block,
            epoch_number,
            round_number,
            transient_vote_recovery_min_age_secs,
            "local proposer pre-vote transient lock reconciliation",
        )?;

        Self::register_local_vote_intent(
            &local_validator_address,
            proposed_block,
            epoch_number,
            round_number,
        )?;
        let local_vote = Self::create_vote_for_validator_with_manager(
            &local_validator_address,
            proposed_block,
            epoch_number,
            round_number,
            &self.validator_manager,
        )?;
        self.register_local_vote_or_slash(&local_vote)?;
        let mut votes = vec![local_vote];

        Self::reset_network_vote_mailbox(block_hash, epoch_number, round_number);

        let remote_validators = expected_validators
            .iter()
            .filter(|address| *address != &local_validator_address)
            .count();
        let collection_started = Instant::now();
        timing_trace::emit(
            "vote_collection_start",
            serde_json::json!({
                "height": proposed_block.block_index,
                "block_hash": block_hash.to_string(),
                "previous_hash": proposed_block.previous_hash.clone(),
                "proposer": proposed_block.validator_id.clone(),
                "epoch": epoch_number,
                "round": round_number,
                "local_validator": local_validator_address.clone(),
                "expected_validators": expected_validators.iter().cloned().collect::<Vec<_>>(),
                "remote_validators": remote_validators,
                "initial_vote_count": votes.len(),
                "effective_vote_timeout_secs": self.vote_timeout.max(1)
            }),
        );
        if remote_validators > 0 {
            if let Some(network) = crate::p2p::get_p2p_network() {
                let notified =
                    network.broadcast_vote_request(proposed_block, epoch_number, round_number);
                timing_trace::emit(
                    "proposal_sent",
                    serde_json::json!({
                        "height": proposed_block.block_index,
                        "block_hash": block_hash.to_string(),
                        "previous_hash": proposed_block.previous_hash.clone(),
                        "proposer": proposed_block.validator_id.clone(),
                        "epoch": epoch_number,
                        "round": round_number,
                        "local_validator": local_validator_address.clone(),
                        "notified_peers": notified,
                        "network_peer_count": network.get_peer_count()
                    }),
                );
                timing_trace::emit(
                    "vote_request_sent",
                    serde_json::json!({
                        "height": proposed_block.block_index,
                        "block_hash": block_hash.to_string(),
                        "previous_hash": proposed_block.previous_hash.clone(),
                        "proposer": proposed_block.validator_id.clone(),
                        "epoch": epoch_number,
                        "round": round_number,
                        "local_validator": local_validator_address.clone(),
                        "remote_validators": remote_validators,
                        "notified_peers": notified,
                        "network_peer_count": network.get_peer_count()
                    }),
                );
                debug!(
                    "consensus",
                    "Broadcasted vote request",
                    "block_hash" => block_hash.to_string(),
                    "epoch" => epoch_number,
                    "round" => round_number,
                    "remote_validators" => remote_validators as u64,
                    "notified_peers" => notified as u64
                );
            } else {
                warn!(
                    "consensus",
                    "Consensus round has remote validators but no active P2P network",
                    "block_hash" => block_hash.to_string(),
                    "epoch" => epoch_number,
                    "round" => round_number
                );
                timing_trace::emit(
                    "vote_request_send_skipped",
                    serde_json::json!({
                        "height": proposed_block.block_index,
                        "block_hash": block_hash.to_string(),
                        "previous_hash": proposed_block.previous_hash.clone(),
                        "proposer": proposed_block.validator_id.clone(),
                        "epoch": epoch_number,
                        "round": round_number,
                        "local_validator": local_validator_address.clone(),
                        "remote_validators": remote_validators,
                        "reason": "no_active_p2p_network"
                    }),
                );
            }
        }

        let deadline = Instant::now() + Duration::from_secs(self.vote_timeout.max(1));
        let mut qc_threshold_reported = false;
        while Instant::now() < deadline {
            self.apply_recorded_equivocations();
            votes.retain(|vote| self.vote_is_eligible(vote));

            let pending_votes =
                Self::snapshot_network_votes(block_hash, epoch_number, round_number);
            self.merge_remote_votes(
                &mut votes,
                &expected_validators,
                block_hash,
                epoch_number,
                round_number,
                pending_votes,
            );

            if self.has_commit_quorum(&active_validators, &votes) {
                if !qc_threshold_reported {
                    timing_trace::emit(
                        "qc_threshold_reached",
                        serde_json::json!({
                            "height": proposed_block.block_index,
                            "block_hash": block_hash.to_string(),
                            "previous_hash": proposed_block.previous_hash.clone(),
                            "proposer": proposed_block.validator_id.clone(),
                            "epoch": epoch_number,
                            "round": round_number,
                            "local_validator": local_validator_address.clone(),
                            "vote_count": votes.len(),
                            "elapsed_ms": timing_trace::duration_ms(collection_started.elapsed())
                        }),
                    );
                    qc_threshold_reported = true;
                }
                break;
            }

            thread::sleep(Duration::from_millis(100));
        }

        // Drain the mailbox one final time after the wait window closes so votes
        // that arrive right on the timeout edge still count toward this round.
        let pending_votes = Self::snapshot_network_votes(block_hash, epoch_number, round_number);
        self.merge_remote_votes(
            &mut votes,
            &expected_validators,
            block_hash,
            epoch_number,
            round_number,
            pending_votes,
        );

        self.apply_recorded_equivocations();
        votes.retain(|vote| self.vote_is_eligible(vote));
        let final_quorum_met = self.has_commit_quorum(&active_validators, &votes);
        if final_quorum_met && !qc_threshold_reported {
            timing_trace::emit(
                "qc_threshold_reached",
                serde_json::json!({
                    "height": proposed_block.block_index,
                    "block_hash": block_hash.to_string(),
                    "previous_hash": proposed_block.previous_hash.clone(),
                    "proposer": proposed_block.validator_id.clone(),
                    "epoch": epoch_number,
                    "round": round_number,
                    "local_validator": local_validator_address.clone(),
                    "vote_count": votes.len(),
                    "elapsed_ms": timing_trace::duration_ms(collection_started.elapsed()),
                    "after_deadline_drain": true
                }),
            );
        }
        self.record_vote_participation(&votes);
        if self.penalization_enabled {
            self.record_missed_vote_timeouts(&active_validators, &votes);
        }

        if !final_quorum_met {
            let received_validators = votes
                .iter()
                .map(|vote| vote.validator_address.clone())
                .collect::<BTreeSet<_>>();
            let missing_validators = expected_validators
                .iter()
                .filter(|validator| !received_validators.contains(*validator))
                .cloned()
                .collect::<Vec<_>>();
            warn!(
                "consensus",
                "Vote collection ended without quorum",
                "height" => proposed_block.block_index,
                "block_hash" => block_hash.to_string(),
                "epoch" => epoch_number,
                "round" => round_number,
                "vote_count" => votes.len() as u64,
                "required_validator_votes" => self.required_validator_votes(active_validators.len()) as u64,
                "missing_validators" => serde_json::to_string(&missing_validators).unwrap_or_default(),
                "elapsed_ms" => timing_trace::duration_ms(collection_started.elapsed()),
                "effective_vote_timeout_secs" => self.vote_timeout.max(1)
            );
        }

        Self::reset_network_vote_mailbox(block_hash, epoch_number, round_number);
        self.votes.insert(block_hash.to_string(), votes.clone());
        timing_trace::emit(
            "vote_collection_end",
            serde_json::json!({
                "height": proposed_block.block_index,
                "block_hash": block_hash.to_string(),
                "previous_hash": proposed_block.previous_hash.clone(),
                "proposer": proposed_block.validator_id.clone(),
                "epoch": epoch_number,
                "round": round_number,
                "vote_count": votes.len(),
                "required_validator_votes": self.required_validator_votes(active_validators.len()),
                "missing_validators": expected_validators
                    .iter()
                    .filter(|validator| {
                        !votes
                            .iter()
                            .any(|vote| &vote.validator_address == *validator)
                    })
                    .cloned()
                    .collect::<Vec<_>>(),
                "quorum_met": final_quorum_met,
                "elapsed_ms": timing_trace::duration_ms(collection_started.elapsed()),
                "effective_vote_timeout_secs": self.vote_timeout.max(1)
            }),
        );
        Ok(votes)
    }

    pub fn build_local_vote_for_proposal(
        proposed_block: &Block,
        epoch_number: u64,
        round_number: u64,
    ) -> Result<Vote, String> {
        Self::build_local_vote_for_proposal_with_recovery(
            proposed_block,
            epoch_number,
            round_number,
            u64::MAX,
        )
    }

    pub fn build_local_vote_for_proposal_with_recovery(
        proposed_block: &Block,
        epoch_number: u64,
        round_number: u64,
        transient_vote_recovery_min_age_secs: u64,
    ) -> Result<Vote, String> {
        Self::validate_block_proposal_static(proposed_block)?;
        verify_block_proposer_key_matches_validator(proposed_block, &VALIDATOR_MANAGER)?;

        let local_validator_address = Self::resolve_local_validator_address()
            .ok_or_else(|| "Local validator address is not configured for voting".to_string())?;
        let local_validator_is_active =
            consensus_membership_validators(VALIDATOR_MANAGER.get_active_validators())
                .into_iter()
                .any(|validator| validator.address == local_validator_address);
        if !local_validator_is_active {
            return Err(format!(
                "Local validator {} is not an active consensus validator",
                local_validator_address
            ));
        }

        Self::recover_stale_conflicting_vote_lock_before_vote(
            &local_validator_address,
            proposed_block,
            epoch_number,
            round_number,
            transient_vote_recovery_min_age_secs,
            "remote vote-request transient lock reconciliation",
        )?;

        Self::register_local_vote_intent(
            &local_validator_address,
            proposed_block,
            epoch_number,
            round_number,
        )?;
        let vote = Self::create_vote_for_validator_with_manager(
            &local_validator_address,
            proposed_block,
            epoch_number,
            round_number,
            &VALIDATOR_MANAGER,
        )?;
        if let Some(evidence) = Self::register_local_vote_attempt(&vote) {
            return Err(format!(
                "Refusing to double-sign for validator {} at height {} in epoch {} round {}",
                evidence.validator_address,
                evidence.block_index,
                evidence.epoch_number,
                evidence.round_number
            ));
        }

        Ok(vote)
    }

    pub fn record_network_vote(vote: Vote) {
        if vote.validator_address.trim().is_empty() || vote.block_hash.trim().is_empty() {
            return;
        }

        if Self::register_vote_observation(&vote).is_some() {
            return;
        }
        timing_trace::emit(
            "vote_response_received_by_proposer",
            serde_json::json!({
                "height": vote.block_index,
                "block_hash": vote.block_hash.clone(),
                "validator": vote.validator_address.clone(),
                "epoch": vote.epoch_number,
                "round": vote.round_number,
                "vote_timestamp": vote.timestamp
            }),
        );

        let key = Self::vote_mailbox_key(&vote.block_hash, vote.epoch_number, vote.round_number);
        if let Ok(mut mailbox) = NETWORK_VOTE_MAILBOX.lock() {
            let entry = mailbox.entry(key).or_default();
            if entry
                .iter()
                .all(|existing| existing.validator_address != vote.validator_address)
            {
                entry.push(vote);
            }
        }
    }

    pub fn record_committed_qc(qc: QuorumCertificate) {
        if let Err(error) = Self::record_committed_qc_checked(qc) {
            warn!(
                "consensus",
                "Failed to append committed quorum certificate",
                "error" => error
            );
        }
    }

    pub fn record_committed_qc_checked(qc: QuorumCertificate) -> Result<(), String> {
        Self::ensure_committed_qc_store_loaded();
        let mut store = COMMITTED_QC_STORE
            .lock()
            .map_err(|_| "failed to lock committed QC store".to_string())?;
        if store.contains_key(&qc.block_hash) {
            return Ok(());
        }

        Self::append_committed_qc_to_log(&qc)?;
        store.insert(qc.block_hash.clone(), qc);
        Self::prune_committed_qc_store_for_retention(&mut store);
        Ok(())
    }

    pub fn committed_qc_for_block_hash(block_hash: &str) -> Option<QuorumCertificate> {
        Self::ensure_committed_qc_store_loaded();
        COMMITTED_QC_STORE
            .lock()
            .ok()
            .and_then(|store| store.get(block_hash).cloned())
    }

    pub fn committed_qcs_for_block_hashes<I, S>(block_hashes: I) -> Vec<QuorumCertificate>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut missing = block_hashes
            .into_iter()
            .map(|hash| hash.as_ref().trim().to_string())
            .filter(|hash| !hash.is_empty())
            .collect::<HashSet<_>>();
        if missing.is_empty() {
            return Vec::new();
        }

        Self::ensure_committed_qc_store_loaded();
        let mut found = Vec::new();
        if let Ok(store) = COMMITTED_QC_STORE.lock() {
            let hot_matches = missing
                .iter()
                .filter_map(|hash| store.get(hash).cloned())
                .collect::<Vec<_>>();
            for qc in hot_matches {
                missing.remove(&qc.block_hash);
                found.push(qc);
            }
        }
        if missing.is_empty() {
            return found;
        }

        match Self::committed_qcs_from_log_for_block_hashes(&missing) {
            Ok(mut historical) => {
                found.append(&mut historical);
            }
            Err(error) => {
                warn!(
                    "consensus",
                    "Failed to load historical committed quorum certificates",
                    "error" => error
                );
            }
        }
        found
    }

    fn committed_qcs_from_log_for_block_hashes(
        block_hashes: &HashSet<String>,
    ) -> Result<Vec<QuorumCertificate>, String> {
        if block_hashes.is_empty() {
            return Ok(Vec::new());
        }

        let log_path = Self::committed_qc_log_path();
        let file = fs::File::open(&log_path)
            .map_err(|err| format!("failed to open committed QC log {:?}: {err}", log_path))?;
        let mut remaining = block_hashes.clone();
        let mut found = Vec::new();
        for (line_number, line) in BufReader::new(file).lines().enumerate() {
            let line = line.map_err(|err| {
                format!(
                    "failed to read committed QC log {:?} line {}: {err}",
                    log_path,
                    line_number + 1
                )
            })?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let entry = serde_json::from_str::<CommittedQcLogEntry>(trimmed).map_err(|err| {
                format!(
                    "failed to parse committed QC log {:?} line {}: {err}",
                    log_path,
                    line_number + 1
                )
            })?;
            if remaining.remove(&entry.block_hash) {
                found.push(entry.qc);
                if remaining.is_empty() {
                    break;
                }
            }
        }
        Ok(found)
    }

    fn ensure_committed_qc_store_loaded() {
        COMMITTED_QC_STORE_INIT.call_once(|| match Self::load_committed_qc_store_from_disk() {
            Ok(loaded) => {
                if let Ok(mut store) = COMMITTED_QC_STORE.lock() {
                    for (block_hash, qc) in loaded {
                        store.entry(block_hash).or_insert(qc);
                    }
                }
            }
            Err(error) => {
                warn!(
                    "consensus",
                    "Failed to load committed quorum certificate store",
                    "error" => error
                );
            }
        });
    }

    fn committed_qc_store_path() -> PathBuf {
        if let Ok(path) = std::env::var("SYNERGY_COMMITTED_QC_STORE_FILE") {
            let trimmed = path.trim();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed);
            }
        }

        #[cfg(test)]
        {
            return std::env::temp_dir().join(format!(
                "synergy-test-committed-qcs-{}.json",
                std::process::id()
            ));
        }

        #[cfg(not(test))]
        {
            crate::utils::resolve_data_path("data/committed_qcs.json")
        }
    }

    fn committed_qc_log_path() -> PathBuf {
        let mut path = Self::committed_qc_store_path();
        path.set_extension("jsonl");
        path
    }

    fn load_committed_qc_store_from_disk() -> Result<HashMap<String, QuorumCertificate>, String> {
        let path = Self::committed_qc_store_path();
        let mut loaded = HashMap::new();
        let retention_blocks = Self::configured_committed_qc_hot_retention_blocks();
        let mut latest_height = 0_u64;
        let mut seen_log_entries = 0_usize;

        if path.exists() {
            let data = fs::read(&path)
                .map_err(|err| format!("failed to read committed QC store {:?}: {err}", path))?;
            if !data.is_empty() {
                let legacy = serde_json::from_slice::<BTreeMap<String, QuorumCertificate>>(&data)
                    .map_err(|err| {
                    format!("failed to parse committed QC store {:?}: {err}", path)
                })?;
                for (block_hash, qc) in legacy {
                    Self::insert_committed_qc_with_retention(
                        &mut loaded,
                        block_hash,
                        qc,
                        retention_blocks,
                        &mut latest_height,
                    );
                }
                Self::prune_committed_qc_store_for_retention_with_latest(
                    &mut loaded,
                    retention_blocks,
                    latest_height,
                );
            }
        }

        let log_path = Self::committed_qc_log_path();
        if log_path.exists() {
            let file = fs::File::open(&log_path)
                .map_err(|err| format!("failed to open committed QC log {:?}: {err}", log_path))?;
            for (line_number, line) in BufReader::new(file).lines().enumerate() {
                let line = line.map_err(|err| {
                    format!(
                        "failed to read committed QC log {:?} line {}: {err}",
                        log_path,
                        line_number + 1
                    )
                })?;
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let entry =
                    serde_json::from_str::<CommittedQcLogEntry>(trimmed).map_err(|err| {
                        format!(
                            "failed to parse committed QC log {:?} line {}: {err}",
                            log_path,
                            line_number + 1
                        )
                    })?;
                Self::insert_committed_qc_with_retention(
                    &mut loaded,
                    entry.block_hash,
                    entry.qc,
                    retention_blocks,
                    &mut latest_height,
                );
                seen_log_entries = seen_log_entries.saturating_add(1);
                if retention_blocks.is_some()
                    && seen_log_entries % COMMITTED_QC_RETENTION_PRUNE_INTERVAL == 0
                {
                    Self::prune_committed_qc_store_for_retention_with_latest(
                        &mut loaded,
                        retention_blocks,
                        latest_height,
                    );
                }
            }
        }

        Self::prune_committed_qc_store_for_retention_with_latest(
            &mut loaded,
            retention_blocks,
            latest_height,
        );
        Self::trim_allocator_after_hot_retention();
        Ok(loaded)
    }

    fn insert_committed_qc_with_retention(
        store: &mut HashMap<String, QuorumCertificate>,
        block_hash: String,
        qc: QuorumCertificate,
        retention_blocks: Option<u64>,
        latest_height: &mut u64,
    ) {
        let qc_height = Self::committed_qc_height(&qc);
        if let Some(height) = qc_height {
            *latest_height = (*latest_height).max(height);
        }

        if Self::committed_qc_is_within_retention(qc_height, retention_blocks, *latest_height) {
            store.insert(block_hash, qc);
        }
    }

    fn committed_qc_height(qc: &QuorumCertificate) -> Option<u64> {
        qc.votes
            .iter()
            .map(|vote| vote.block_index)
            .filter(|height| *height > 0)
            .max()
    }

    fn configured_committed_qc_hot_retention_blocks() -> Option<u64> {
        env::var(COMMITTED_QC_HOT_RETENTION_BLOCKS_ENV)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|value| *value > 0)
    }

    fn committed_qc_is_within_retention(
        qc_height: Option<u64>,
        retention_blocks: Option<u64>,
        latest_height: u64,
    ) -> bool {
        let Some(retention_blocks) = retention_blocks else {
            return true;
        };
        let Some(qc_height) = qc_height else {
            return true;
        };
        if latest_height < retention_blocks {
            return true;
        }
        qc_height
            >= latest_height
                .saturating_sub(retention_blocks)
                .saturating_add(1)
    }

    fn prune_committed_qc_store_for_retention(
        store: &mut HashMap<String, QuorumCertificate>,
    ) -> usize {
        let retention_blocks = Self::configured_committed_qc_hot_retention_blocks();
        let latest_height = store
            .values()
            .filter_map(Self::committed_qc_height)
            .max()
            .unwrap_or(0);
        Self::prune_committed_qc_store_for_retention_with_latest(
            store,
            retention_blocks,
            latest_height,
        )
    }

    fn prune_committed_qc_store_for_retention_with_latest(
        store: &mut HashMap<String, QuorumCertificate>,
        retention_blocks: Option<u64>,
        latest_height: u64,
    ) -> usize {
        if retention_blocks.is_none() || latest_height == 0 {
            return 0;
        }
        let before = store.len();
        store.retain(|_, qc| {
            Self::committed_qc_is_within_retention(
                Self::committed_qc_height(qc),
                retention_blocks,
                latest_height,
            )
        });
        let removed = before.saturating_sub(store.len());
        if removed > 0 {
            Self::trim_allocator_after_hot_retention();
        }
        removed
    }

    fn trim_allocator_after_hot_retention() {
        #[cfg(target_os = "linux")]
        unsafe {
            libc::malloc_trim(0);
        }
    }

    fn append_committed_qc_to_log(qc: &QuorumCertificate) -> Result<(), String> {
        let path = Self::committed_qc_log_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("failed to create committed QC log directory: {err}"))?;
        }

        let entry = CommittedQcLogEntry {
            block_hash: qc.block_hash.clone(),
            qc: qc.clone(),
        };
        let serialized = serde_json::to_vec(&entry)
            .map_err(|err| format!("failed to encode committed QC log entry: {err}"))?;

        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&path)
            .map_err(|err| format!("failed to open committed QC log file: {err}"))?;
        file.write_all(&serialized)
            .map_err(|err| format!("failed to write committed QC log entry: {err}"))?;
        file.write_all(b"\n")
            .map_err(|err| format!("failed to write committed QC log newline: {err}"))?;
        file.sync_all()
            .map_err(|err| format!("failed to sync committed QC log file: {err}"))
    }

    pub(crate) fn create_vote_for_validator(
        validator_address: &str,
        proposed_block: &Block,
        epoch_number: u64,
        round_number: u64,
    ) -> Result<Vote, String> {
        Self::create_vote_for_validator_with_manager(
            validator_address,
            proposed_block,
            epoch_number,
            round_number,
            &VALIDATOR_MANAGER,
        )
    }

    pub(crate) fn create_vote_for_validator_with_manager(
        validator_address: &str,
        proposed_block: &Block,
        epoch_number: u64,
        round_number: u64,
        validator_manager: &Arc<ValidatorManager>,
    ) -> Result<Vote, String> {
        let timestamp = Self::current_timestamp();
        let message = Self::vote_signature_payload(
            validator_address,
            &proposed_block.hash,
            proposed_block.block_index,
            epoch_number,
            round_number,
        );

        let sign_started = Instant::now();
        timing_trace::emit(
            "pqc_vote_sign_start",
            serde_json::json!({
                "height": proposed_block.block_index,
                "block_hash": proposed_block.hash.clone(),
                "previous_hash": proposed_block.previous_hash.clone(),
                "proposer": proposed_block.validator_id.clone(),
                "validator": validator_address,
                "epoch": epoch_number,
                "round": round_number
            }),
        );
        let sign_result = sign_with_local_validator_key_for_height(
            proposed_block.block_index,
            validator_address,
            message.as_bytes(),
            validator_manager,
        );
        let sign_duration_ms = timing_trace::duration_ms(sign_started.elapsed());
        let (public_key, signature) = match sign_result {
            Ok(result) => {
                timing_trace::emit(
                    "pqc_vote_sign_end",
                    serde_json::json!({
                        "height": proposed_block.block_index,
                        "block_hash": proposed_block.hash.clone(),
                        "previous_hash": proposed_block.previous_hash.clone(),
                        "proposer": proposed_block.validator_id.clone(),
                        "validator": validator_address,
                        "epoch": epoch_number,
                        "round": round_number,
                        "duration_ms": sign_duration_ms,
                        "status": "ok"
                    }),
                );
                result
            }
            Err(error) => {
                timing_trace::emit(
                    "pqc_vote_sign_end",
                    serde_json::json!({
                        "height": proposed_block.block_index,
                        "block_hash": proposed_block.hash.clone(),
                        "previous_hash": proposed_block.previous_hash.clone(),
                        "proposer": proposed_block.validator_id.clone(),
                        "validator": validator_address,
                        "epoch": epoch_number,
                        "round": round_number,
                        "duration_ms": sign_duration_ms,
                        "status": "error",
                        "error": error
                    }),
                );
                return Err(error);
            }
        };

        Ok(Vote {
            validator_address: validator_address.to_string(),
            block_hash: proposed_block.hash.clone(),
            block_index: proposed_block.block_index,
            epoch_number,
            round_number,
            signature,
            signer_public_key: public_key.key_data,
            timestamp,
        })
    }

    fn merge_remote_votes(
        &self,
        votes: &mut Vec<Vote>,
        expected_validators: &BTreeSet<String>,
        block_hash: &str,
        epoch_number: u64,
        round_number: u64,
        pending_votes: Vec<Vote>,
    ) {
        let mut seen_validators = votes
            .iter()
            .map(|vote| vote.validator_address.clone())
            .collect::<BTreeSet<_>>();
        let mut cached_votes = Vec::new();
        let mut uncached_votes = Vec::new();

        for vote in pending_votes {
            if vote.block_hash != block_hash
                || vote.epoch_number != epoch_number
                || vote.round_number != round_number
            {
                continue;
            }
            if Self::has_equivocation_evidence(
                &vote.validator_address,
                vote.epoch_number,
                vote.block_index,
                vote.round_number,
            ) {
                warn!(
                    "consensus",
                    "Discarding equivocating vote",
                    "validator" => vote.validator_address.clone(),
                    "block_hash" => vote.block_hash.clone(),
                    "height" => vote.block_index,
                    "epoch" => vote.epoch_number,
                    "round" => vote.round_number
                );
                continue;
            }
            if !expected_validators.contains(&vote.validator_address) {
                continue;
            }
            if !self.vote_is_eligible(&vote) {
                continue;
            }
            if !seen_validators.insert(vote.validator_address.clone()) {
                continue;
            }

            let cache_key = Self::vote_signature_cache_key(&vote);
            if self.vote_signature_cache_contains(&cache_key) {
                cached_votes.push(vote);
            } else {
                uncached_votes.push((vote, cache_key));
            }
        }

        votes.extend(cached_votes);

        let mut handles = Vec::new();
        for (vote, cache_key) in uncached_votes {
            handles.push(Self::spawn_vote_signature_verification_with_key(
                vote,
                cache_key,
                Arc::clone(&self.validator_manager),
            ));
        }

        for handle in handles {
            let Ok((vote, cache_key, verification)) = handle.join() else {
                warn!(
                    "consensus",
                    "Remote vote verification worker panicked",
                    "block_hash" => block_hash.to_string(),
                    "epoch" => epoch_number,
                    "round" => round_number
                );
                continue;
            };

            if let Err(error) = verification {
                warn!(
                    "consensus",
                    "Discarding invalid remote vote",
                    "validator" => vote.validator_address.clone(),
                    "block_hash" => vote.block_hash.clone(),
                    "epoch" => vote.epoch_number,
                    "round" => vote.round_number,
                    "error" => error
                );
                continue;
            }

            self.cache_verified_vote_signature(cache_key);
            votes.push(vote);
        }
    }

    fn spawn_vote_signature_verification_with_key(
        vote: Vote,
        cache_key: String,
        validator_manager: Arc<ValidatorManager>,
    ) -> thread::JoinHandle<(Vote, String, Result<(), String>)> {
        thread::spawn(move || {
            let verify_started = Instant::now();
            timing_trace::emit(
                "pqc_vote_verify_start",
                serde_json::json!({
                    "height": vote.block_index,
                    "block_hash": vote.block_hash.clone(),
                    "validator": vote.validator_address.clone(),
                    "epoch": vote.epoch_number,
                    "round": vote.round_number
                }),
            );
            let verification = Self::verify_vote_signature_uncached(&vote, &validator_manager);
            timing_trace::emit(
                "pqc_vote_verify_end",
                serde_json::json!({
                    "height": vote.block_index,
                    "block_hash": vote.block_hash.clone(),
                    "validator": vote.validator_address.clone(),
                    "epoch": vote.epoch_number,
                    "round": vote.round_number,
                    "duration_ms": timing_trace::duration_ms(verify_started.elapsed()),
                    "status": if verification.is_ok() { "ok" } else { "error" },
                    "error": verification.as_ref().err().cloned()
                }),
            );
            (vote, cache_key, verification)
        })
    }

    fn check_quorums_and_commit(
        &mut self,
        block_hash: &str,
        epoch_number: u64,
        round_number: u64,
        votes: &[Vote],
    ) -> Result<QuorumCertificate, String> {
        let cumulative_weight = self.calculate_cumulative_vote_weight(votes);
        let validator_count = votes.len();
        let active_validators = self.collect_live_validators();
        let total_validators = active_validators.len();

        if total_validators < self.minimum_validator_count {
            return Err(format!(
                "Insufficient active validators: {} active, {} required",
                total_validators, self.minimum_validator_count
            ));
        }

        let required_validator_votes = self.required_validator_votes(total_validators);
        if validator_count < required_validator_votes {
            return Err(format!(
                "Insufficient validator votes: {} votes, {} required for quorum",
                validator_count, required_validator_votes
            ));
        }

        // Check validation quorum against the total live validator weight for the round.
        let total_live_weight = self.total_validator_weight(&active_validators);
        let validation_ratio = if total_live_weight > 0.0 {
            cumulative_weight / total_live_weight
        } else {
            0.0
        };
        let required_validation_ratio =
            self.validation_quorum_threshold.max(VALIDATOR_QUORUM_RATIO);
        let validation_quorum_met = validation_ratio > required_validation_ratio;

        // Check cooperation quorum using a BFT-style supermajority count.
        let cooperation_ratio = validator_count as f64 / total_validators as f64;
        let required_cooperation_ratio = self
            .cooperation_quorum_threshold
            .max(VALIDATOR_QUORUM_RATIO);
        let cooperation_quorum_met = cooperation_ratio > required_cooperation_ratio
            && validator_count >= required_validator_votes;

        if validation_quorum_met && cooperation_quorum_met {
            // Create quorum certificate
            let qc =
                self.create_quorum_certificate(block_hash, epoch_number, round_number, votes)?;
            self.quorum_certificates
                .insert(block_hash.to_string(), qc.clone());
            Ok(qc)
        } else {
            Err("Quorum thresholds not met".to_string())
        }
    }

    fn calculate_cumulative_vote_weight(&self, votes: &[Vote]) -> f64 {
        let mut total_weight = 0.0;

        for vote in votes {
            if let Some(validator) = self
                .validator_manager
                .get_validator(&vote.validator_address)
            {
                // Use normalized synergy score as vote weight
                total_weight += validator.synergy_score / 100.0;
            }
        }

        total_weight
    }

    fn total_validator_weight(&self, validators: &[Validator]) -> f64 {
        validators
            .iter()
            .map(|validator| (validator.synergy_score / 100.0).max(0.0))
            .sum()
    }

    fn required_validator_votes(&self, total_validators: usize) -> usize {
        required_validator_quorum(total_validators).max(1)
    }

    fn has_commit_quorum(&self, live_validators: &[Validator], votes: &[Vote]) -> bool {
        if live_validators.is_empty() {
            return false;
        }

        let required_validator_votes = self.required_validator_votes(live_validators.len());
        if votes.len() < required_validator_votes {
            return false;
        }

        let total_live_weight = self.total_validator_weight(live_validators);
        if total_live_weight <= 0.0 {
            return false;
        }

        let cumulative_weight = self.calculate_cumulative_vote_weight(votes);
        let required_validation_ratio =
            self.validation_quorum_threshold.max(VALIDATOR_QUORUM_RATIO);
        cumulative_weight + 0.000_001 >= total_live_weight * required_validation_ratio
    }

    fn record_missed_vote_timeouts(&self, live_validators: &[Validator], votes: &[Vote]) {
        if !self.penalization_enabled {
            return;
        }

        let received_votes = votes
            .iter()
            .map(|vote| vote.validator_address.clone())
            .collect::<BTreeSet<_>>();

        for validator in live_validators {
            if received_votes.contains(&validator.address) {
                continue;
            }

            self.validator_manager
                .update_performance(ValidatorPerformanceUpdate {
                    validator_address: validator.address.clone(),
                    update_type: "block_missed".to_string(),
                    value: None,
                    timestamp: Self::current_timestamp(),
                });

            warn!(
                "consensus",
                "Validator missed vote deadline",
                "validator" => validator.address.clone()
            );
        }
    }

    fn record_vote_participation(&self, votes: &[Vote]) {
        for vote in votes {
            self.validator_manager
                .update_performance(ValidatorPerformanceUpdate {
                    validator_address: vote.validator_address.clone(),
                    update_type: "vote_cast".to_string(),
                    value: None,
                    timestamp: Self::current_timestamp(),
                });
        }
    }

    fn create_quorum_certificate(
        &self,
        block_hash: &str,
        epoch_number: u64,
        round_number: u64,
        votes: &[Vote],
    ) -> Result<QuorumCertificate, String> {
        // Aggregate signatures
        let aggregate_sig = self.aggregate_signatures(votes)?;

        // Create participation bitmap
        let participant_bitmap = self.create_participant_bitmap(votes);

        // Calculate cumulative weight
        let cumulative_weight = self.calculate_cumulative_vote_weight(votes);

        let qc = QuorumCertificate {
            block_hash: block_hash.to_string(),
            epoch_number,
            round_number,
            aggregate_signature: aggregate_sig.combined_signature,
            participant_bitmap,
            cumulative_weight,
            validation_quorum_met: true,
            cooperation_quorum_met: true,
            timestamp: Self::current_timestamp(),
            votes: {
                let mut sorted_votes = votes.to_vec();
                sorted_votes.sort_by(|a, b| a.validator_address.cmp(&b.validator_address));
                sorted_votes
            },
        };
        Ok(qc)
    }

    fn aggregate_signatures(&self, votes: &[Vote]) -> Result<AggregateSignature, String> {
        // Sort votes by validator address for deterministic ordering
        let mut sorted_votes = votes.to_vec();
        sorted_votes.sort_by(|a, b| a.validator_address.cmp(&b.validator_address));

        // Create participation bitmap
        let participant_bitmap = self.create_participant_bitmap(&sorted_votes);

        // Collect all individual signatures and verify each one before aggregation.
        let mut signatures = Vec::new();

        for vote in &sorted_votes {
            self.verify_vote_signature(vote)?;
            signatures.push(vote.signature.signature_data.clone());
        }

        // Deterministically bind all individual signatures into a compact attestation digest.
        let mut hasher = Sha3_512::new();
        for sig in &signatures {
            hasher.update((sig.len() as u64).to_be_bytes());
            hasher.update(sig);
        }
        let combined_signature = hasher.finalize().to_vec();

        // Use first vote's message hash as common message hash
        let message_hash = if let Some(first_vote) = sorted_votes.first() {
            first_vote.signature.message_hash.clone()
        } else {
            Vec::new()
        };

        Ok(AggregateSignature {
            combined_signature,
            participation_bitmap: participant_bitmap.clone(),
            message_hash,
            participant_count: sorted_votes.len(),
        })
    }

    fn create_participant_bitmap(&self, votes: &[Vote]) -> Vec<u8> {
        let active_validators = self.collect_live_validators();
        let mut bitmap = vec![0u8; (active_validators.len() + 7) / 8];

        for (i, validator) in active_validators.iter().enumerate() {
            let byte_index = i / 8;
            let bit_index = i % 8;

            if votes
                .iter()
                .any(|v| v.validator_address == validator.address)
            {
                bitmap[byte_index] |= 1 << bit_index;
            }
        }

        bitmap
    }

    fn collect_live_validators(&self) -> Vec<Validator> {
        let active_validators =
            consensus_membership_validators(self.validator_manager.get_active_validators());
        let active_by_address = active_validators
            .into_iter()
            .map(|validator| (validator.address.clone(), validator))
            .collect::<HashMap<_, _>>();

        let mut live_addresses = BTreeSet::new();

        if let Some(local_validator_address) = self.resolve_local_validator_address_for_round() {
            if active_by_address.contains_key(&local_validator_address) {
                live_addresses.insert(local_validator_address);
            }
        }

        if let Some(network) = crate::p2p::get_p2p_network() {
            for validator_address in network.get_status_ready_validator_addresses() {
                if active_by_address.contains_key(&validator_address) {
                    live_addresses.insert(validator_address);
                }
            }
        }

        live_addresses
            .into_iter()
            .filter_map(|address| active_by_address.get(&address).cloned())
            .collect()
    }

    fn resolve_local_validator_address() -> Option<String> {
        let from_env = crate::config::resolve_runtime_validator_address();

        if from_env.is_some() {
            return from_env;
        }

        let active_validators =
            consensus_membership_validators(VALIDATOR_MANAGER.get_active_validators());
        if active_validators.len() == 1 {
            active_validators
                .first()
                .map(|validator| validator.address.clone())
        } else {
            None
        }
    }

    fn resolve_local_validator_address_for_round(&self) -> Option<String> {
        Self::resolve_local_validator_address().or_else(|| {
            let active_validators =
                consensus_membership_validators(self.validator_manager.get_active_validators());
            if active_validators.len() == 1 {
                active_validators
                    .first()
                    .map(|validator| validator.address.clone())
            } else {
                None
            }
        })
    }

    fn is_block_hash_valid(block: &Block) -> bool {
        let expected = format!(
            "{:?}{}{}{}{}{}",
            block.block_index,
            block.previous_hash,
            block.validator_id,
            block.nonce,
            block.timestamp,
            block.transactions_root
        );
        blake3::hash(expected.as_bytes()).to_hex().to_string() == block.hash
    }

    fn verify_transaction_static(tx: &crate::transaction::Transaction) -> Result<(), String> {
        let validation = tx.validate_for_admission();
        if validation.is_valid {
            Ok(())
        } else {
            Err(validation
                .error_message
                .unwrap_or_else(|| "transaction failed admission validation".to_string()))
        }
    }

    fn verify_vote_signature(&self, vote: &Vote) -> Result<(), String> {
        let cache_key = Self::vote_signature_cache_key(vote);
        if self.vote_signature_cache_contains(&cache_key) {
            return Ok(());
        }

        Self::verify_vote_signature_uncached(vote, &self.validator_manager)?;
        self.cache_verified_vote_signature(cache_key);
        Ok(())
    }

    fn verify_vote_signature_uncached(
        vote: &Vote,
        validator_manager: &Arc<ValidatorManager>,
    ) -> Result<(), String> {
        let message = Self::vote_signature_payload(
            &vote.validator_address,
            &vote.block_hash,
            vote.block_index,
            vote.epoch_number,
            vote.round_number,
        );
        let public_key = verify_signer_key_matches_validator_at_height(
            vote.block_index,
            &vote.validator_address,
            &vote.signer_public_key,
            validator_manager,
        )?;
        if vote.signature.algorithm != public_key.algorithm {
            return Err(format!(
                "vote signature algorithm does not match canonical consensus key for validator {}",
                vote.validator_address
            ));
        }

        let pqc_manager = PQCManager::new();
        let valid = pqc_manager
            .verify(&public_key, &vote.signature, message.as_bytes())
            .map_err(|err| format!("vote signature verify error: {err}"))?;

        if valid {
            Ok(())
        } else {
            Err(format!(
                "invalid vote signature from validator {}",
                vote.validator_address
            ))
        }
    }

    pub fn verify_commit_certificate_for_block_static(
        block: &Block,
        qc: &QuorumCertificate,
        validator_manager: &Arc<ValidatorManager>,
    ) -> Result<(), String> {
        block.verify_proposer_signature()?;
        verify_block_proposer_key_matches_validator(block, validator_manager)?;

        if qc.block_hash != block.hash {
            return Err("QC block hash does not match exact block".to_string());
        }
        if qc.aggregate_signature.is_empty() {
            return Err("QC aggregate signature is missing".to_string());
        }
        if qc.participant_bitmap.is_empty() {
            return Err("QC signer bitmap is missing".to_string());
        }
        if !qc.validation_quorum_met || !qc.cooperation_quorum_met {
            return Err("QC does not prove both validation and cooperation quorum".to_string());
        }
        if qc.votes.is_empty() {
            return Err("QC does not include individually verifiable Aegis PQC votes".to_string());
        }

        let active_validators =
            consensus_membership_validators(validator_manager.get_active_validators());
        if active_validators.is_empty() {
            return Err("QC verification has no active validator set".to_string());
        }
        let active_by_address = active_validators
            .iter()
            .map(|validator| (validator.address.clone(), validator))
            .collect::<HashMap<_, _>>();

        let mut seen = BTreeSet::new();
        let mut signed_weight = 0.0;
        for vote in &qc.votes {
            if vote.block_hash != block.hash {
                return Err("QC vote signs a different block hash".to_string());
            }
            if vote.block_index != block.block_index {
                return Err("QC vote signs a different block height".to_string());
            }
            if vote.epoch_number != qc.epoch_number || vote.round_number != qc.round_number {
                return Err("QC vote context does not match QC epoch/round".to_string());
            }
            if !seen.insert(vote.validator_address.clone()) {
                return Err("QC contains duplicate signer".to_string());
            }
            let Some(validator) = active_by_address.get(&vote.validator_address) else {
                return Err("QC contains signer outside active validator set".to_string());
            };
            Self::verify_vote_signature_uncached(vote, validator_manager)?;
            signed_weight += (validator.synergy_score / 100.0).max(0.0);
        }

        let required_votes = Self::required_qc_validator_votes(active_validators.len());
        if seen.len() < required_votes {
            return Err(format!(
                "QC has {} signer(s), {} required for dynamic validator quorum",
                seen.len(),
                required_votes,
            ));
        }

        let total_weight = active_validators
            .iter()
            .map(|validator| (validator.synergy_score / 100.0).max(0.0))
            .sum::<f64>();
        if total_weight <= 0.0 {
            return Err("active validator set has zero voting weight".to_string());
        }
        if signed_weight + 0.000_001 < total_weight * VALIDATOR_QUORUM_RATIO {
            return Err("QC signed weight is below validator quorum threshold".to_string());
        }

        Ok(())
    }

    fn required_qc_validator_votes(total_validators: usize) -> usize {
        required_validator_quorum(total_validators).max(1)
    }

    fn vote_signature_cache_contains(&self, cache_key: &str) -> bool {
        self.verified_vote_signatures
            .lock()
            .map(|cache| cache.contains(cache_key))
            .unwrap_or(false)
    }

    fn cache_verified_vote_signature(&self, cache_key: String) {
        if let Ok(mut cache) = self.verified_vote_signatures.lock() {
            if cache.len() > 8192 {
                cache.clear();
            }
            cache.insert(cache_key);
        }
    }

    fn vote_signature_cache_key(vote: &Vote) -> String {
        let mut hasher = Sha3_512::new();
        hasher.update(vote.validator_address.as_bytes());
        hasher.update(vote.block_hash.as_bytes());
        hasher.update(vote.block_index.to_be_bytes());
        hasher.update(vote.epoch_number.to_be_bytes());
        hasher.update(vote.round_number.to_be_bytes());
        hasher.update(format!("{:?}", vote.signature.algorithm).as_bytes());
        hasher.update((vote.signer_public_key.len() as u64).to_be_bytes());
        hasher.update(&vote.signer_public_key);
        hasher.update((vote.signature.signature_data.len() as u64).to_be_bytes());
        hasher.update(&vote.signature.signature_data);
        hex::encode(hasher.finalize())
    }

    fn vote_signature_payload(
        validator_address: &str,
        block_hash: &str,
        block_index: u64,
        epoch_number: u64,
        round_number: u64,
    ) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            validator_address, block_index, round_number, block_hash, epoch_number
        )
    }

    fn scoped_local_vote_lock_key(
        validator_address: &str,
        epoch_number: u64,
        block_index: u64,
        round_number: u64,
        block_hash: &str,
    ) -> String {
        format!("{epoch_number}:{block_index}:{round_number}:{block_hash}:{validator_address}")
    }

    fn local_vote_lock_path() -> PathBuf {
        #[cfg(test)]
        {
            if let Ok(path) = TEST_LOCAL_VOTE_LOCK_PATH.lock() {
                if let Some(path) = path.clone() {
                    return path;
                }
            }

            return std::env::temp_dir().join(format!(
                "synergy-test-local-vote-locks-{}.json",
                std::process::id()
            ));
        }

        #[cfg(not(test))]
        {
            crate::utils::resolve_data_path("data/consensus_vote_locks.json")
        }
    }

    fn load_local_vote_locks_unlocked() -> Result<HashMap<String, LocalVoteLock>, String> {
        let path = Self::local_vote_lock_path();
        if !path.exists() {
            return Ok(HashMap::new());
        }

        let data = fs::read(&path)
            .map_err(|err| format!("failed to read local vote lock file {:?}: {err}", path))?;
        if data.is_empty() {
            return Ok(HashMap::new());
        }

        serde_json::from_slice::<HashMap<String, LocalVoteLock>>(&data)
            .map_err(|err| format!("failed to parse local vote lock file {:?}: {err}", path))
    }

    fn persist_local_vote_locks_unlocked(
        locks: &HashMap<String, LocalVoteLock>,
    ) -> Result<(), String> {
        let path = Self::local_vote_lock_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("failed to create local vote lock directory: {err}"))?;
        }

        let tmp_path = path.with_extension("json.tmp");
        let serialized = serde_json::to_vec_pretty(locks)
            .map_err(|err| format!("failed to encode local vote locks: {err}"))?;

        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&tmp_path)
            .map_err(|err| format!("failed to open local vote lock temp file: {err}"))?;
        file.write_all(&serialized)
            .map_err(|err| format!("failed to write local vote lock temp file: {err}"))?;
        file.sync_all()
            .map_err(|err| format!("failed to sync local vote lock temp file: {err}"))?;
        drop(file);

        fs::rename(&tmp_path, &path)
            .map_err(|err| format!("failed to replace local vote lock file: {err}"))
    }

    fn local_vote_lock_to_recovered(lock: &LocalVoteLock) -> RecoveredTransientVoteLock {
        RecoveredTransientVoteLock {
            validator_address: lock.validator_address.clone(),
            block_hash: lock.block_hash.clone(),
            block_index: lock.block_index,
            epoch_number: lock.epoch_number,
            first_round_number: lock.first_round_number,
            latest_round_number: lock.latest_round_number,
            proposer: lock.proposer.clone(),
            created_at: lock.created_at,
            updated_at: lock.updated_at,
        }
    }

    fn preserve_vote_lock_compaction_evidence_unlocked(
        path: &PathBuf,
        locks: &HashMap<String, LocalVoteLock>,
        removed: &[(String, RecoveredTransientVoteLock)],
        finalized_height: u64,
        finalized_hash: &str,
        prune_cutoff_height: u64,
        reason: &str,
        now: u64,
    ) -> Result<PathBuf, String> {
        let evidence_root = crate::utils::resolve_data_path("data/consensus_recovery_evidence");
        fs::create_dir_all(&evidence_root)
            .map_err(|err| format!("failed to create vote-lock evidence directory: {err}"))?;
        let evidence_nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let evidence_path = evidence_root.join(format!(
            "{}-{}-finalized-vote-lock-compaction-through-{}.json",
            now, evidence_nonce, prune_cutoff_height
        ));
        let removed_locks = removed
            .iter()
            .map(|(_, lock)| lock.clone())
            .collect::<Vec<_>>();
        let evidence = serde_json::json!({
            "action": "compact_finalized_vote_locks_for_hot_path",
            "reason": reason,
            "vote_lock_path": path.to_string_lossy(),
            "finalized_height": finalized_height,
            "finalized_hash": finalized_hash,
            "retention_depth": LOCAL_VOTE_LOCK_FINALIZED_RETENTION_DEPTH,
            "prune_cutoff_height": prune_cutoff_height,
            "before_count": locks.len(),
            "removed_count": removed_locks.len(),
            "kept_count": locks.len().saturating_sub(removed_locks.len()),
            "removed": removed_locks,
            "timestamp": now,
        });
        let serialized = serde_json::to_vec_pretty(&evidence).map_err(|err| {
            format!("failed to encode finalized vote-lock compaction evidence: {err}")
        })?;
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&evidence_path)
            .map_err(|err| format!("failed to create finalized vote-lock evidence file: {err}"))?;
        file.write_all(&serialized)
            .map_err(|err| format!("failed to write finalized vote-lock evidence file: {err}"))?;
        file.sync_all()
            .map_err(|err| format!("failed to sync finalized vote-lock evidence file: {err}"))?;
        Ok(evidence_path)
    }

    fn compact_finalized_vote_locks_for_hot_path_unlocked(
        locks: &mut HashMap<String, LocalVoteLock>,
        now: u64,
        reason: &str,
    ) -> Result<Option<(usize, PathBuf)>, String> {
        if locks.len() < LOCAL_VOTE_LOCK_COMPACTION_MIN_LOCKS {
            return Ok(None);
        }

        let Some(canonical) = latest_legacy_canonical_commit_record()? else {
            return Ok(None);
        };
        let prune_cutoff_height = canonical
            .height
            .saturating_sub(LOCAL_VOTE_LOCK_FINALIZED_RETENTION_DEPTH);
        let path = Self::local_vote_lock_path();
        let mut removed = locks
            .iter()
            .filter_map(|(key, lock)| {
                (lock.block_index <= prune_cutoff_height)
                    .then(|| (key.clone(), Self::local_vote_lock_to_recovered(lock)))
            })
            .collect::<Vec<_>>();
        removed.sort_by(|(_, left), (_, right)| {
            (
                left.block_index,
                left.epoch_number,
                left.latest_round_number,
                left.block_hash.as_str(),
            )
                .cmp(&(
                    right.block_index,
                    right.epoch_number,
                    right.latest_round_number,
                    right.block_hash.as_str(),
                ))
        });

        if removed.is_empty() {
            return Ok(None);
        }

        let evidence_path = Self::preserve_vote_lock_compaction_evidence_unlocked(
            &path,
            locks,
            &removed,
            canonical.height,
            &canonical.block_hash,
            prune_cutoff_height,
            reason,
            now,
        )?;

        for (key, _) in &removed {
            locks.remove(key);
        }

        Ok(Some((removed.len(), evidence_path)))
    }

    pub fn local_locked_vote_for_height(
        validator_address: &str,
        epoch_number: u64,
        block_index: u64,
    ) -> Result<Option<LocalLockedVote>, String> {
        let _guard = LOCAL_VOTE_LOCK_FILE_MUTEX
            .lock()
            .map_err(|_| "local vote lock file mutex is poisoned".to_string())?;
        let locks = Self::load_local_vote_locks_unlocked()?;
        let latest_lock = Self::latest_local_vote_lock_for_height_unlocked(
            &locks,
            validator_address,
            epoch_number,
            block_index,
        );

        Ok(latest_lock.map(|lock| LocalLockedVote {
            validator_address: lock.validator_address.clone(),
            block_hash: lock.block_hash.clone(),
            block_index: lock.block_index,
            epoch_number: lock.epoch_number,
            first_round_number: lock.first_round_number,
            latest_round_number: lock.latest_round_number,
            proposer: lock.proposer.clone(),
            created_at: lock.created_at,
            updated_at: lock.updated_at,
        }))
    }

    pub fn recover_transient_vote_locks_above_finalized_height(
        finalized_height: u64,
        min_age_secs: u64,
        reason: &str,
    ) -> Result<TransientVoteLockRecoveryReport, String> {
        let _guard = LOCAL_VOTE_LOCK_FILE_MUTEX
            .lock()
            .map_err(|_| "local vote lock file mutex is poisoned".to_string())?;
        let path = Self::local_vote_lock_path();
        let mut locks = Self::load_local_vote_locks_unlocked()?;
        let now = Self::current_timestamp();
        let before_count = locks.len();

        let mut removed = locks
            .iter()
            .filter_map(|(key, lock)| {
                let stale_enough = now.saturating_sub(lock.updated_at) >= min_age_secs;
                (lock.block_index > finalized_height && stale_enough).then(|| {
                    (
                        key.clone(),
                        RecoveredTransientVoteLock {
                            validator_address: lock.validator_address.clone(),
                            block_hash: lock.block_hash.clone(),
                            block_index: lock.block_index,
                            epoch_number: lock.epoch_number,
                            first_round_number: lock.first_round_number,
                            latest_round_number: lock.latest_round_number,
                            proposer: lock.proposer.clone(),
                            created_at: lock.created_at,
                            updated_at: lock.updated_at,
                        },
                    )
                })
            })
            .collect::<Vec<_>>();
        removed.sort_by(|(_, left), (_, right)| {
            (
                left.block_index,
                left.epoch_number,
                left.latest_round_number,
                left.block_hash.as_str(),
            )
                .cmp(&(
                    right.block_index,
                    right.epoch_number,
                    right.latest_round_number,
                    right.block_hash.as_str(),
                ))
        });

        if removed.is_empty() {
            return Ok(TransientVoteLockRecoveryReport {
                action: "recover_transient_vote_locks_above_finalized_height".to_string(),
                reason: reason.to_string(),
                finalized_height,
                min_age_secs,
                vote_lock_path: path.to_string_lossy().to_string(),
                evidence_path: String::new(),
                before_count,
                kept_count: locks.len(),
                removed_count: 0,
                removed: Vec::new(),
                mutated: false,
                timestamp: now,
            });
        }

        let evidence_root = crate::utils::resolve_data_path("data/consensus_recovery_evidence");
        fs::create_dir_all(&evidence_root)
            .map_err(|err| format!("failed to create vote-lock evidence directory: {err}"))?;
        let evidence_nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let evidence_path = evidence_root.join(format!(
            "{}-{}-transient-vote-locks-above-{}.json",
            now, evidence_nonce, finalized_height
        ));

        let removed_locks = removed
            .iter()
            .map(|(_, lock)| lock.clone())
            .collect::<Vec<_>>();
        let evidence = serde_json::json!({
            "action": "recover_transient_vote_locks_above_finalized_height",
            "reason": reason,
            "finalized_height": finalized_height,
            "min_age_secs": min_age_secs,
            "vote_lock_path": path.to_string_lossy(),
            "before_count": before_count,
            "removed_count": removed_locks.len(),
            "removed": removed_locks,
            "all_locks_before": locks,
            "timestamp": now,
        });
        let serialized = serde_json::to_vec_pretty(&evidence)
            .map_err(|err| format!("failed to encode vote-lock evidence: {err}"))?;
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&evidence_path)
            .map_err(|err| format!("failed to create vote-lock evidence file: {err}"))?;
        file.write_all(&serialized)
            .map_err(|err| format!("failed to write vote-lock evidence file: {err}"))?;
        file.sync_all()
            .map_err(|err| format!("failed to sync vote-lock evidence file: {err}"))?;
        drop(file);

        for (key, _) in &removed {
            locks.remove(key);
        }
        Self::persist_local_vote_locks_unlocked(&locks)?;

        Ok(TransientVoteLockRecoveryReport {
            action: "recover_transient_vote_locks_above_finalized_height".to_string(),
            reason: reason.to_string(),
            finalized_height,
            min_age_secs,
            vote_lock_path: path.to_string_lossy().to_string(),
            evidence_path: evidence_path.to_string_lossy().to_string(),
            before_count,
            kept_count: locks.len(),
            removed_count: removed.len(),
            removed: removed.into_iter().map(|(_, lock)| lock).collect(),
            mutated: before_count != locks.len(),
            timestamp: now,
        })
    }

    fn validate_same_height_vote_supersede(
        proposed_block: &Block,
        round_number: u64,
        latest_conflicting_round: u64,
    ) -> Result<(), String> {
        if round_number <= latest_conflicting_round {
            return Err(format!(
                "same-height vote supersede requires a higher consensus round: requested_round={round_number}, latest_conflicting_round={latest_conflicting_round}"
            ));
        }

        if let Some(existing) = legacy_canonical_commit_record(proposed_block.block_index)? {
            return Err(format!(
                "height {} is already finalized by canonical lock {}; refusing transient vote supersede for {}",
                proposed_block.block_index, existing.block_hash, proposed_block.hash
            ));
        }

        let latest_lock =
            Self::same_height_vote_parent_for_proposal(proposed_block)?.ok_or_else(|| {
                "same-height vote supersede requires a durable finalized canonical parent lock"
                    .to_string()
            })?;
        if proposed_block.block_index != latest_lock.height + 1 {
            return Err(format!(
                "same-height vote supersede target height {} must be the direct child of finalized canonical height {}",
                proposed_block.block_index, latest_lock.height
            ));
        }
        if proposed_block.previous_hash != latest_lock.block_hash {
            return Err(format!(
                "same-height vote supersede proposal does not extend latest canonical lock: expected_parent={}, proposed_parent={}",
                latest_lock.block_hash, proposed_block.previous_hash
            ));
        }

        warn!(
            "consensus",
            "Accepting higher-round same-height vote supersede after deterministic view change",
            "height" => proposed_block.block_index,
            "new_hash" => proposed_block.hash.clone(),
            "new_proposer" => proposed_block.validator_id.clone(),
            "requested_round" => round_number,
            "latest_conflicting_round" => latest_conflicting_round,
            "canonical_parent_height" => latest_lock.height,
            "canonical_parent_hash" => latest_lock.block_hash,
            "canonical_parent_source" => latest_lock.source
        );

        Ok(())
    }

    fn same_height_vote_parent_for_proposal(
        proposed_block: &Block,
    ) -> Result<Option<SameHeightVoteParent>, String> {
        if let Some(migration) =
            crate::consensus::consensus_fork::active_consensus_fork_migration()?
        {
            if proposed_block.block_index == migration.fork_height {
                if proposed_block.previous_hash != migration.parent_hash {
                    return Err(format!(
                        "checkpoint fork proposal at height {} does not extend configured fork parent {}",
                        proposed_block.block_index, migration.parent_hash
                    ));
                }
                return Ok(Some(SameHeightVoteParent {
                    height: migration.parent_height,
                    block_hash: migration.parent_hash,
                    source: "checkpoint_consensus_fork",
                    checkpoint_fork_parent: true,
                }));
            }
        }

        Ok(
            latest_legacy_canonical_commit_record()?.map(|record| SameHeightVoteParent {
                height: record.height,
                block_hash: record.block_hash,
                source: "legacy_canonical_lock",
                checkpoint_fork_parent: false,
            }),
        )
    }

    fn latest_local_vote_lock_for_height_unlocked(
        locks: &HashMap<String, LocalVoteLock>,
        validator_address: &str,
        epoch_number: u64,
        block_index: u64,
    ) -> Option<LocalVoteLock> {
        locks
            .values()
            .filter(|lock| {
                lock.validator_address == validator_address
                    && lock.epoch_number == epoch_number
                    && lock.block_index == block_index
            })
            .max_by_key(|lock| (lock.latest_round_number, lock.updated_at))
            .cloned()
    }

    fn recover_stale_conflicting_vote_lock_before_vote(
        validator_address: &str,
        proposed_block: &Block,
        epoch_number: u64,
        round_number: u64,
        min_age_secs: u64,
        reason: &str,
    ) -> Result<(), String> {
        if min_age_secs == u64::MAX {
            return Ok(());
        }

        let latest_lock = {
            let _guard = LOCAL_VOTE_LOCK_FILE_MUTEX
                .lock()
                .map_err(|_| "local vote lock file mutex is poisoned".to_string())?;
            let locks = Self::load_local_vote_locks_unlocked()?;
            Self::latest_local_vote_lock_for_height_unlocked(
                &locks,
                validator_address,
                epoch_number,
                proposed_block.block_index,
            )
        };

        let Some(latest_lock) = latest_lock else {
            return Ok(());
        };
        if latest_lock.block_hash == proposed_block.hash
            || round_number <= latest_lock.latest_round_number
        {
            return Ok(());
        }

        if legacy_canonical_commit_record(proposed_block.block_index)?.is_some() {
            return Ok(());
        }

        let Some(canonical_parent) = Self::same_height_vote_parent_for_proposal(proposed_block)?
        else {
            return Ok(());
        };
        if proposed_block.block_index != canonical_parent.height.saturating_add(1)
            || proposed_block.previous_hash != canonical_parent.block_hash
        {
            return Ok(());
        }

        let now = Self::current_timestamp();
        let effective_min_age_secs = if canonical_parent.checkpoint_fork_parent {
            0
        } else {
            min_age_secs
        };
        if now.saturating_sub(latest_lock.updated_at) < effective_min_age_secs {
            return Ok(());
        }

        let recovery_reason = format!(
            "{reason}: validator={validator_address} height={} requested_hash={} requested_proposer={} requested_round={} stale_locked_hash={} stale_locked_proposer={} stale_latest_round={} canonical_parent_height={} canonical_parent_hash={} canonical_parent_source={}",
            proposed_block.block_index,
            proposed_block.hash,
            proposed_block.validator_id,
            round_number,
            latest_lock.block_hash,
            latest_lock.proposer,
            latest_lock.latest_round_number,
            canonical_parent.height,
            canonical_parent.block_hash,
            canonical_parent.source
        );
        let report = Self::recover_transient_vote_locks_above_finalized_height(
            canonical_parent.height,
            effective_min_age_secs,
            &recovery_reason,
        )?;

        if report.mutated {
            timing_trace::emit(
                "stale_transient_lock_recovery",
                serde_json::json!({
                    "height": proposed_block.block_index,
                    "block_hash": proposed_block.hash.clone(),
                    "previous_hash": proposed_block.previous_hash.clone(),
                    "proposer": proposed_block.validator_id.clone(),
                    "validator": validator_address,
                    "epoch": epoch_number,
                    "round": round_number,
                    "removed_count": report.removed_count,
                    "evidence_path": report.evidence_path.clone()
                }),
            );
            warn!(
                "consensus",
                "Recovered stale transient vote locks before signing higher-round proposal",
                "validator" => validator_address.to_string(),
                "height" => proposed_block.block_index,
                "requested_hash" => proposed_block.hash.clone(),
                "requested_proposer" => proposed_block.validator_id.clone(),
                "requested_round" => round_number,
                "removed_count" => report.removed_count as u64,
                "evidence_path" => report.evidence_path.clone()
            );
        }

        Ok(())
    }

    fn register_local_vote_intent(
        validator_address: &str,
        proposed_block: &Block,
        epoch_number: u64,
        round_number: u64,
    ) -> Result<(), String> {
        let _guard = LOCAL_VOTE_LOCK_FILE_MUTEX
            .lock()
            .map_err(|_| "local vote lock file mutex is poisoned".to_string())?;
        let mut locks = Self::load_local_vote_locks_unlocked()?;
        let now = Self::current_timestamp();
        if let Some((removed_count, evidence_path)) =
            Self::compact_finalized_vote_locks_for_hot_path_unlocked(
                &mut locks,
                now,
                "automatic finalized vote-lock compaction before local vote persistence",
            )?
        {
            warn!(
                "consensus",
                "Compacted finalized local vote locks before signing vote",
                "validator" => validator_address.to_string(),
                "height" => proposed_block.block_index,
                "epoch" => epoch_number,
                "round" => round_number,
                "removed_count" => removed_count as u64,
                "evidence_path" => evidence_path.to_string_lossy().to_string()
            );
        }

        let matching_keys = locks
            .iter()
            .filter_map(|(key, lock)| {
                if lock.validator_address == validator_address
                    && lock.epoch_number == epoch_number
                    && lock.block_index == proposed_block.block_index
                {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if let Some(existing_key) = matching_keys.iter().find(|key| {
            locks
                .get(*key)
                .map(|lock| lock.block_hash == proposed_block.hash)
                .unwrap_or(false)
        }) {
            if let Some(existing) = locks.get_mut(existing_key) {
                existing.latest_round_number = existing.latest_round_number.max(round_number);
                existing.updated_at = now;
                Self::persist_local_vote_locks_unlocked(&locks)?;
                return Ok(());
            }
        }

        if !matching_keys.is_empty() {
            let latest_conflicting = matching_keys
                .iter()
                .filter_map(|key| locks.get(key))
                .max_by_key(|lock| (lock.latest_round_number, lock.updated_at))
                .cloned()
                .ok_or_else(|| "failed to load matching local vote lock".to_string())?;

            if round_number <= latest_conflicting.latest_round_number {
                return Err(format!(
                    "already locally voted for different block at height {} in this or a later round: locked_hash={}, locked_proposer={}, locked_epoch={}, locked_first_round={}, locked_latest_round={}, requested_hash={}, requested_proposer={}, requested_epoch={}, requested_round={}",
                    proposed_block.block_index,
                    latest_conflicting.block_hash,
                    latest_conflicting.proposer,
                    latest_conflicting.epoch_number,
                    latest_conflicting.first_round_number,
                    latest_conflicting.latest_round_number,
                    proposed_block.hash,
                    proposed_block.validator_id,
                    epoch_number,
                    round_number
                ));
            }

            Self::validate_same_height_vote_supersede(
                proposed_block,
                round_number,
                latest_conflicting.latest_round_number,
            )?;

            warn!(
                "consensus",
                "Advancing local same-height transient vote lock after higher-round view change",
                "validator" => validator_address.to_string(),
                "height" => proposed_block.block_index,
                "epoch" => epoch_number,
                "previous_hash" => latest_conflicting.block_hash.clone(),
                "previous_proposer" => latest_conflicting.proposer.clone(),
                "previous_first_round" => latest_conflicting.first_round_number,
                "previous_latest_round" => latest_conflicting.latest_round_number,
                "new_hash" => proposed_block.hash.clone(),
                "new_proposer" => proposed_block.validator_id.clone(),
                "new_round" => round_number
            );
        }

        let key = Self::scoped_local_vote_lock_key(
            validator_address,
            epoch_number,
            proposed_block.block_index,
            round_number,
            &proposed_block.hash,
        );
        let superseded = matching_keys
            .iter()
            .filter_map(|key| locks.get(key))
            .filter(|lock| lock.block_hash != proposed_block.hash)
            .map(|lock| SupersededLocalVoteLock {
                block_hash: lock.block_hash.clone(),
                first_round_number: lock.first_round_number,
                latest_round_number: lock.latest_round_number,
                proposer: lock.proposer.clone(),
                superseded_at: now,
            })
            .collect();

        locks.insert(
            key,
            LocalVoteLock {
                validator_address: validator_address.to_string(),
                block_hash: proposed_block.hash.clone(),
                block_index: proposed_block.block_index,
                epoch_number,
                first_round_number: round_number,
                latest_round_number: round_number,
                proposer: proposed_block.validator_id.clone(),
                created_at: now,
                updated_at: now,
                superseded,
            },
        );

        Self::persist_local_vote_locks_unlocked(&locks)
    }

    fn vote_observation_key(
        validator_address: &str,
        epoch_number: u64,
        block_index: u64,
        round_number: u64,
    ) -> String {
        format!("{epoch_number}:{block_index}:{round_number}:{validator_address}")
    }

    fn observe_vote(
        vote: &Vote,
        persist_equivocation_evidence: bool,
    ) -> Option<VoteEquivocationEvidence> {
        let key = Self::vote_observation_key(
            &vote.validator_address,
            vote.epoch_number,
            vote.block_index,
            vote.round_number,
        );

        let mut observed_votes = OBSERVED_VOTES.lock().ok()?;
        match observed_votes.get(&key) {
            // Idempotent replays of the exact same vote are allowed.
            Some(existing) if existing.block_hash == vote.block_hash => None,
            Some(existing) => {
                let evidence = VoteEquivocationEvidence {
                    validator_address: vote.validator_address.clone(),
                    block_index: vote.block_index,
                    epoch_number: vote.epoch_number,
                    round_number: vote.round_number,
                    first_vote: existing.clone(),
                    conflicting_vote: vote.clone(),
                    detected_at: Self::current_timestamp(),
                };

                if persist_equivocation_evidence {
                    if let Ok(mut evidence_log) = EQUIVOCATION_EVIDENCE_LOG.lock() {
                        evidence_log.insert(key, evidence.clone());
                    }
                }

                Some(evidence)
            }
            None => {
                observed_votes.insert(key, vote.clone());
                None
            }
        }
    }

    fn register_vote_observation(vote: &Vote) -> Option<VoteEquivocationEvidence> {
        Self::observe_vote(vote, true)
    }

    fn register_local_vote_attempt(vote: &Vote) -> Option<VoteEquivocationEvidence> {
        Self::observe_vote(vote, false)
    }

    fn has_equivocation_evidence(
        validator_address: &str,
        epoch_number: u64,
        block_index: u64,
        round_number: u64,
    ) -> bool {
        let key =
            Self::vote_observation_key(validator_address, epoch_number, block_index, round_number);
        EQUIVOCATION_EVIDENCE_LOG
            .lock()
            .ok()
            .map(|log| log.contains_key(&key))
            .unwrap_or(false)
    }

    fn register_local_vote_or_slash(&self, vote: &Vote) -> Result<(), String> {
        if let Some(evidence) = Self::register_local_vote_attempt(vote) {
            return Err(format!(
                "Validator {} attempted conflicting votes at height {} in epoch {} round {}",
                evidence.validator_address,
                evidence.block_index,
                evidence.epoch_number,
                evidence.round_number
            ));
        }

        Ok(())
    }

    fn pending_equivocation_evidence(&self) -> Vec<VoteEquivocationEvidence> {
        let processed = PROCESSED_EQUIVOCATION_EVIDENCE
            .lock()
            .ok()
            .map(|entries| entries.clone())
            .unwrap_or_default();

        EQUIVOCATION_EVIDENCE_LOG
            .lock()
            .ok()
            .map(|entries| {
                entries
                    .iter()
                    .filter(|(key, _)| !processed.contains(*key))
                    .map(|(_, evidence)| evidence.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn apply_recorded_equivocations(&self) {
        for evidence in self.pending_equivocation_evidence() {
            self.apply_equivocation_evidence(&evidence);
        }
    }

    fn apply_equivocation_evidence(&self, evidence: &VoteEquivocationEvidence) {
        let key = Self::vote_observation_key(
            &evidence.validator_address,
            evidence.epoch_number,
            evidence.block_index,
            evidence.round_number,
        );

        let should_process = if let Ok(mut processed) = PROCESSED_EQUIVOCATION_EVIDENCE.lock() {
            processed.insert(key)
        } else {
            false
        };
        if !should_process {
            return;
        }

        match self
            .validator_manager
            .slash_validator(&evidence.validator_address, "double_sign")
        {
            Ok(_) => {
                warn!(
                    "consensus",
                    "Slashed validator for vote equivocation",
                    "validator" => evidence.validator_address.clone(),
                    "height" => evidence.block_index,
                    "epoch" => evidence.epoch_number,
                    "round" => evidence.round_number
                );
            }
            Err(error) => {
                warn!(
                    "consensus",
                    "Failed to slash equivocating validator",
                    "validator" => evidence.validator_address.clone(),
                    "height" => evidence.block_index,
                    "epoch" => evidence.epoch_number,
                    "round" => evidence.round_number,
                    "error" => error
                );
            }
        }
    }

    fn vote_is_eligible(&self, vote: &Vote) -> bool {
        if Self::has_equivocation_evidence(
            &vote.validator_address,
            vote.epoch_number,
            vote.block_index,
            vote.round_number,
        ) {
            return false;
        }

        consensus_membership_validators(self.validator_manager.get_active_validators())
            .into_iter()
            .any(|validator| validator.address == vote.validator_address)
    }

    fn vote_mailbox_key(block_hash: &str, epoch_number: u64, round_number: u64) -> String {
        format!("{epoch_number}:{round_number}:{block_hash}")
    }

    fn reset_network_vote_mailbox(block_hash: &str, epoch_number: u64, round_number: u64) {
        let key = Self::vote_mailbox_key(block_hash, epoch_number, round_number);
        if let Ok(mut mailbox) = NETWORK_VOTE_MAILBOX.lock() {
            mailbox.remove(&key);
        }
    }

    fn snapshot_network_votes(block_hash: &str, epoch_number: u64, round_number: u64) -> Vec<Vote> {
        let key = Self::vote_mailbox_key(block_hash, epoch_number, round_number);
        NETWORK_VOTE_MAILBOX
            .lock()
            .ok()
            .and_then(|mailbox| mailbox.get(&key).cloned())
            .unwrap_or_default()
    }

    fn allocate_round_number(
        &mut self,
        block_index: u64,
        epoch_number: u64,
        validator_address: &str,
        minimum_round_number: u64,
    ) -> u64 {
        let persisted_lock_floor =
            Self::local_locked_vote_for_height(validator_address, epoch_number, block_index)
                .ok()
                .flatten()
                .map(|lock| lock.latest_round_number.saturating_add(1))
                .unwrap_or(1);
        let round_number = minimum_round_number.max(persisted_lock_floor).max(1);
        self.current_round_by_height
            .insert(block_index, round_number);
        round_number
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[cfg(test)]
    pub(crate) fn test_vote_tracking_guard() -> std::sync::MutexGuard<'static, ()> {
        TEST_VOTE_TRACKING_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[cfg(test)]
    pub(crate) fn reset_test_vote_tracking() {
        if let Ok(mut mailbox) = NETWORK_VOTE_MAILBOX.lock() {
            mailbox.clear();
        }
        if let Ok(mut observed) = OBSERVED_VOTES.lock() {
            observed.clear();
        }
        if let Ok(mut evidence) = EQUIVOCATION_EVIDENCE_LOG.lock() {
            evidence.clear();
        }
        if let Ok(mut processed) = PROCESSED_EQUIVOCATION_EVIDENCE.lock() {
            processed.clear();
        }
        if let Ok(mut qcs) = COMMITTED_QC_STORE.lock() {
            qcs.clear();
        }
        let qc_store_path = Self::committed_qc_store_path();
        let _ = fs::remove_file(qc_store_path.with_extension("json.tmp"));
        let _ = fs::remove_file(qc_store_path);
        let _ = fs::remove_file(Self::committed_qc_log_path());
        if let Ok(_guard) = LOCAL_VOTE_LOCK_FILE_MUTEX.lock() {
            let path = Self::local_vote_lock_path();
            let _ = fs::remove_file(path.with_extension("json.tmp"));
            let _ = fs::remove_file(path);
        }
    }

    #[cfg(test)]
    pub(crate) fn set_test_local_vote_lock_path(path: Option<PathBuf>) {
        if let Ok(mut test_path) = TEST_LOCAL_VOTE_LOCK_PATH.lock() {
            *test_path = path;
        }
    }
}

pub fn required_validator_quorum(total_validators: usize) -> usize {
    if total_validators == 0 {
        0
    } else {
        (total_validators * VALIDATOR_QUORUM_PERCENT).div_ceil(100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::validator_keys::{
        consensus_algorithm_label, register_test_validator_signing_key,
    };
    use crate::crypto::pqc::PQCAlgorithm;
    use crate::validator::{Validator, ValidatorRegistration, ValidatorStatus};
    use base64::{engine::general_purpose, Engine as _};
    use std::fs;
    use std::path::PathBuf;

    fn approved_validator_manager(addresses: &[&str]) -> Arc<ValidatorManager> {
        let manager = Arc::new(ValidatorManager::new());
        for address in addresses {
            let mut pqc_manager = PQCManager::new();
            let (public_key, private_key) = pqc_manager
                .generate_keypair(PQCAlgorithm::FNDSA)
                .expect("test validator consensus key should generate");
            register_test_validator_signing_key(address, public_key.clone(), private_key);
            let encoded_public_key = format!(
                "{}:{}",
                consensus_algorithm_label(&public_key.algorithm),
                general_purpose::STANDARD.encode(&public_key.key_data)
            );
            manager
                .register_validator(ValidatorRegistration {
                    address: (*address).to_string(),
                    public_key: encoded_public_key,
                    name: format!("{address} validator"),
                    stake_amount: 1_000,
                    submitted_at: 0,
                    registration_tx_hash: format!("{address}-registration"),
                })
                .expect("validator registration should succeed");
            manager
                .approve_validator(address)
                .expect("validator approval should succeed");

            if let Ok(mut registry) = VALIDATOR_MANAGER.registry.lock() {
                let mut validator = Validator::new(
                    (*address).to_string(),
                    manager
                        .get_validator(address)
                        .expect("test validator should be registered")
                        .public_key,
                    format!("{address} validator"),
                    1_000,
                );
                validator.status = ValidatorStatus::Active;
                validator.activation_tx_hash = Some(format!("syntxn-test-{address}"));
                registry
                    .validators
                    .insert((*address).to_string(), validator);
                registry.pending_registrations.remove(*address);
            }
        }
        manager
    }

    fn test_qc(block_hash: &str) -> QuorumCertificate {
        QuorumCertificate {
            block_hash: block_hash.to_string(),
            epoch_number: 0,
            round_number: 1,
            aggregate_signature: vec![1, 2, 3],
            participant_bitmap: vec![0x0f],
            cumulative_weight: 4.0,
            validation_quorum_met: true,
            cooperation_quorum_met: true,
            timestamp: 1_700_000_000,
            votes: Vec::new(),
        }
    }

    fn test_qc_at_height(block_hash: &str, height: u64) -> QuorumCertificate {
        let mut qc = test_qc(block_hash);
        qc.votes = vec![Vote {
            validator_address: "validator1".to_string(),
            block_hash: block_hash.to_string(),
            block_index: height,
            epoch_number: 0,
            round_number: 1,
            signature: PQCSignature {
                algorithm: PQCAlgorithm::FNDSA,
                signature_data: Vec::new(),
                message_hash: Vec::new(),
                public_key_id: String::new(),
                created_at: 0,
            },
            signer_public_key: Vec::new(),
            timestamp: height,
        }];
        qc
    }

    #[test]
    fn qc_verification_requires_dynamic_quorum_for_five_validators() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();

        let required = DualQuorumConsensus::required_qc_validator_votes(5);

        assert_eq!(required, required_validator_quorum(5));
    }

    #[test]
    fn qc_verification_requires_dynamic_five_of_six_quorum() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();

        let required = DualQuorumConsensus::required_qc_validator_votes(6);

        assert_eq!(required, required_validator_quorum(6));
    }

    #[test]
    fn qc_verification_requires_dynamic_quorum_for_expanded_set() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();

        let required = DualQuorumConsensus::required_qc_validator_votes(10);

        assert_eq!(required, required_validator_quorum(10));
    }

    #[test]
    fn committed_qc_store_is_persisted_incrementally() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let later = test_qc("block-z");
        let earlier = test_qc("block-a");
        DualQuorumConsensus::record_committed_qc(later.clone());
        DualQuorumConsensus::record_committed_qc(earlier.clone());

        assert_eq!(
            DualQuorumConsensus::committed_qc_for_block_hash("block-a").map(|qc| qc.block_hash),
            Some("block-a".to_string())
        );

        let loaded = DualQuorumConsensus::load_committed_qc_store_from_disk()
            .expect("committed QC store should reload from disk");
        assert_eq!(loaded.get("block-z").map(|qc| qc.round_number), Some(1));

        let raw =
            fs::read_to_string(DualQuorumConsensus::committed_qc_log_path()).unwrap_or_default();
        let lines = raw.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"block-z\""));
        assert!(lines[1].contains("\"block-a\""));
    }

    #[test]
    fn committed_qc_store_does_not_append_duplicate_qc() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let qc = test_qc("block-once");
        DualQuorumConsensus::record_committed_qc(qc.clone());
        DualQuorumConsensus::record_committed_qc(qc);

        let raw =
            fs::read_to_string(DualQuorumConsensus::committed_qc_log_path()).unwrap_or_default();
        assert_eq!(raw.lines().count(), 1);
    }

    #[test]
    fn committed_qc_store_load_honors_hot_retention_env() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        let previous = env::var(COMMITTED_QC_HOT_RETENTION_BLOCKS_ENV).ok();
        env::set_var(COMMITTED_QC_HOT_RETENTION_BLOCKS_ENV, "3");

        for height in 1..=8 {
            DualQuorumConsensus::append_committed_qc_to_log(&test_qc_at_height(
                &format!("block-{height}"),
                height,
            ))
            .unwrap();
        }

        let loaded = DualQuorumConsensus::load_committed_qc_store_from_disk()
            .expect("committed QC log should load");

        assert!(!loaded.contains_key("block-5"));
        assert!(loaded.contains_key("block-6"));
        assert!(loaded.contains_key("block-7"));
        assert!(loaded.contains_key("block-8"));

        match previous {
            Some(value) => env::set_var(COMMITTED_QC_HOT_RETENTION_BLOCKS_ENV, value),
            None => env::remove_var(COMMITTED_QC_HOT_RETENTION_BLOCKS_ENV),
        }
    }

    #[test]
    fn committed_qc_batch_lookup_reads_historical_log_entries_outside_hot_retention() {
        let _guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        let previous = env::var(COMMITTED_QC_HOT_RETENTION_BLOCKS_ENV).ok();
        env::set_var(COMMITTED_QC_HOT_RETENTION_BLOCKS_ENV, "3");

        for height in 1..=8 {
            DualQuorumConsensus::append_committed_qc_to_log(&test_qc_at_height(
                &format!("block-{height}"),
                height,
            ))
            .unwrap();
        }

        let qcs = DualQuorumConsensus::committed_qcs_for_block_hashes([
            "block-2",
            "block-8",
            "missing-block",
        ]);
        let hashes = qcs
            .iter()
            .map(|qc| qc.block_hash.as_str())
            .collect::<HashSet<_>>();

        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains("block-2"));
        assert!(hashes.contains("block-8"));

        match previous {
            Some(value) => env::set_var(COMMITTED_QC_HOT_RETENTION_BLOCKS_ENV, value),
            None => env::remove_var(COMMITTED_QC_HOT_RETENTION_BLOCKS_ENV),
        }
    }

    fn signed_block(block_index: u64, nonce: u64, validator_id: &str) -> Block {
        let mut block = Block::new(
            block_index,
            vec![],
            "parent-hash".to_string(),
            validator_id.to_string(),
            nonce,
        );

        let mut pqc_manager = PQCManager::new();
        let (public_key, private_key) = pqc_manager
            .generate_keypair(PQCAlgorithm::FNDSA)
            .expect("FN-DSA key generation should succeed");
        let signature = pqc_manager
            .sign(&private_key, block.hash.as_bytes())
            .expect("block signing should succeed");
        block.proposer_public_key = public_key.key_data;
        block.block_signature = signature.signature_data;
        block.block_signature_algorithm = "fndsa".to_string();
        block
    }

    fn signed_test_transaction() -> crate::transaction::Transaction {
        let mut tx = crate::transaction::Transaction::new(
            "synw1sender".to_string(),
            "synw1receiver".to_string(),
            1,
            0,
            Vec::new(),
            1,
            21_000,
            None,
            "fndsa".to_string(),
        );
        let mut pqc_manager = PQCManager::new();
        let (public_key, private_key) = pqc_manager
            .generate_keypair(PQCAlgorithm::FNDSA)
            .expect("FN-DSA transaction key generation should succeed");
        tx.sign_with_public_key(&public_key, &private_key, &mut pqc_manager)
            .expect("transaction signing should succeed");
        tx
    }

    #[test]
    fn block_proposal_rejects_transaction_without_valid_pqc_admission() {
        let mut block = signed_block(1, 1, "validator1");
        block.transactions = vec![signed_test_transaction()];
        block.transactions[0].signature.clear();
        block.transactions_root = crate::block::compute_merkle_root(&block.transactions);
        block.hash = block.recompute_hash();
        let mut pqc_manager = PQCManager::new();
        let (public_key, private_key) = pqc_manager
            .generate_keypair(PQCAlgorithm::FNDSA)
            .expect("FN-DSA block key generation should succeed");
        let signature = pqc_manager
            .sign(&private_key, block.hash.as_bytes())
            .expect("block signing should succeed");
        block.proposer_public_key = public_key.key_data;
        block.block_signature = signature.signature_data;

        assert!(DualQuorumConsensus::validate_block_proposal_static(&block).is_err());
    }

    fn temp_vote_lock_path(test_name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        std::env::temp_dir()
            .join(format!("synergy-{test_name}-{unique}"))
            .join("data")
            .join("consensus_vote_locks.json")
    }

    #[test]
    fn configured_vote_timeout_has_launch_liveness_floor() {
        let validator_manager = approved_validator_manager(&["validator1", "validator2"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            true,
            2,
            2,
            0,
            6,
        );

        assert_eq!(consensus.vote_timeout, MIN_LAUNCH_VOTE_TIMEOUT_SECS);
        assert_eq!(consensus.validator_vote_threshold, 2);
        assert_eq!(consensus.minimum_validator_count, 2);
    }

    #[test]
    fn same_height_same_round_double_vote_rejected() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager = approved_validator_manager(&["validator1", "validator2"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            true,
            1,
            1,
            8,
            5,
        );

        let first_block = signed_block(7, 1, "validator1");
        let conflicting_block = signed_block(7, 2, "validator1");

        let first_vote =
            DualQuorumConsensus::create_vote_for_validator("validator2", &first_block, 12, 1)
                .expect("first vote should be created");
        assert!(DualQuorumConsensus::register_vote_observation(&first_vote).is_none());

        let conflicting_vote =
            DualQuorumConsensus::create_vote_for_validator("validator2", &conflicting_block, 12, 1)
                .expect("conflicting vote should be created");
        let evidence = DualQuorumConsensus::register_vote_observation(&conflicting_vote)
            .expect("conflicting vote should emit equivocation evidence");

        consensus.apply_recorded_equivocations();

        let validator = validator_manager
            .get_validator("validator2")
            .expect("validator should still exist");
        assert_eq!(validator.status, ValidatorStatus::Slashed);
        assert_eq!(validator.double_signs, 1);
        assert_eq!(validator.equivocation_evidence_count, 1);
        assert_eq!(evidence.block_index, 7);
        assert_eq!(evidence.epoch_number, 12);
        assert_eq!(evidence.round_number, 1);
    }

    #[test]
    fn validator_can_repeat_same_block_vote_in_new_round() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager = approved_validator_manager(&["validator1", "validator2"]);
        let block = signed_block(9, 1, "validator1");

        let first_vote =
            DualQuorumConsensus::create_vote_for_validator("validator2", &block, 21, 1)
                .expect("round one vote should be created");
        assert!(DualQuorumConsensus::register_vote_observation(&first_vote).is_none());

        let next_round_vote =
            DualQuorumConsensus::create_vote_for_validator("validator2", &block, 21, 2)
                .expect("round two vote should be created");
        assert!(DualQuorumConsensus::register_vote_observation(&next_round_vote).is_none());

        let validator = validator_manager
            .get_validator("validator2")
            .expect("validator should still exist");
        assert_eq!(validator.status, ValidatorStatus::Active);
        assert_eq!(validator.double_signs, 0);
    }

    #[test]
    fn vote_observation_for_conflicting_higher_round_is_round_scoped() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager = approved_validator_manager(&["validator1", "validator2"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            true,
            1,
            1,
            8,
            5,
        );
        let first_block = signed_block(10, 1, "validator1");
        let conflicting_block = signed_block(10, 2, "validator1");

        let first_vote =
            DualQuorumConsensus::create_vote_for_validator("validator2", &first_block, 22, 1)
                .expect("round one vote should be created");
        assert!(DualQuorumConsensus::register_vote_observation(&first_vote).is_none());

        let conflicting_vote =
            DualQuorumConsensus::create_vote_for_validator("validator2", &conflicting_block, 22, 2)
                .expect("round two vote should be created");
        assert!(
            DualQuorumConsensus::register_vote_observation(&conflicting_vote).is_none(),
            "vote observation is round-scoped; local vote intent enforces supersede safety before signing"
        );

        consensus.apply_recorded_equivocations();

        let validator = validator_manager
            .get_validator("validator2")
            .expect("validator should still exist");
        assert_eq!(validator.status, ValidatorStatus::Active);
        assert_eq!(validator.double_signs, 0);
        assert_eq!(validator.equivocation_evidence_count, 0);
    }

    #[test]
    fn local_vote_intent_rejects_same_height_conflict_without_canonical_parent() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();

        let path = temp_vote_lock_path("local-vote-intent");
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let block = signed_block(13, 1, "validator1");
        let conflicting_block = signed_block(13, 2, "validator1");

        DualQuorumConsensus::register_local_vote_intent("validator2", &block, 40, 1)
            .expect("first local vote intent should persist");
        DualQuorumConsensus::register_local_vote_intent("validator2", &block, 40, 2)
            .expect("same block hash may be repeated in a later round");

        let locked = DualQuorumConsensus::local_locked_vote_for_height("validator2", 40, 13)
            .expect("local vote lock lookup should succeed")
            .expect("local vote lock should exist");
        assert_eq!(locked.block_hash, block.hash);
        assert_eq!(locked.first_round_number, 1);
        assert_eq!(locked.latest_round_number, 2);

        let same_round_error = DualQuorumConsensus::register_local_vote_intent(
            "validator2",
            &conflicting_block,
            40,
            2,
        )
        .expect_err("conflicting local vote intent in the same round should be rejected");
        assert!(
            same_round_error.contains("already locally voted for different block"),
            "unexpected local vote lock error: {same_round_error}"
        );

        let higher_round_error = DualQuorumConsensus::register_local_vote_intent(
            "validator2",
            &conflicting_block,
            40,
            3,
        )
        .expect_err("higher-round conflicting local vote intent needs durable view-change proof");
        assert!(
            higher_round_error.contains("durable finalized canonical parent lock"),
            "unexpected higher-round local vote lock error: {higher_round_error}"
        );

        let locked = DualQuorumConsensus::local_locked_vote_for_height("validator2", 40, 13)
            .expect("local vote lock lookup should succeed")
            .expect("vote lock should remain on the original same-height block");
        assert_eq!(locked.block_hash, block.hash);
        assert_eq!(locked.first_round_number, 1);
        assert_eq!(locked.latest_round_number, 2);
        assert_eq!(locked.proposer, "validator1");

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();
        if let Some(root) = path.parent().and_then(|data| data.parent()) {
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn same_height_higher_round_extending_canonical_parent_supersedes_transient_lock() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();

        let path = temp_vote_lock_path("local-vote-intent-view-change");
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let parent = signed_block(12, 1, "validator0");
        crate::consensus::legacy_canonical_lock::write_legacy_canonical_lock(
            &parent,
            &test_qc(&parent.hash),
        )
        .expect("canonical parent lock should be written");

        let mut block = signed_block(13, 1, "validator1");
        block.previous_hash = parent.hash.clone();
        let mut conflicting_block = signed_block(13, 2, "validator3");
        conflicting_block.previous_hash = parent.hash.clone();

        DualQuorumConsensus::register_local_vote_intent("validator2", &block, 40, 1)
            .expect("first local vote intent should persist");
        let same_round_error = DualQuorumConsensus::register_local_vote_intent(
            "validator2",
            &conflicting_block,
            40,
            1,
        )
        .expect_err("same-round conflicting vote remains unsafe");
        assert!(
            same_round_error.contains("already locally voted for different block"),
            "unexpected same-round error: {same_round_error}"
        );

        DualQuorumConsensus::register_local_vote_intent("validator2", &conflicting_block, 40, 2)
            .expect("higher-round canonical-parent vote supersede should be accepted");

        let locked = DualQuorumConsensus::local_locked_vote_for_height("validator2", 40, 13)
            .expect("local vote lock lookup should succeed")
            .expect("latest local vote lock should advance");
        assert_eq!(locked.block_hash, conflicting_block.hash);
        assert_eq!(locked.first_round_number, 2);
        assert_eq!(locked.latest_round_number, 2);
        assert_eq!(locked.proposer, "validator3");

        let locks = DualQuorumConsensus::load_local_vote_locks_unlocked()
            .expect("persisted vote locks should load");
        assert!(
            locks.values().any(|lock| lock.block_hash == block.hash),
            "original unfinalized vote lock should remain as evidence"
        );
        assert!(
            locks
                .values()
                .any(|lock| lock.block_hash == conflicting_block.hash
                    && lock.block_index == 13
                    && lock.latest_round_number == 2
                    && lock.superseded.iter().any(|superseded| {
                        superseded.block_hash == block.hash
                            && superseded.first_round_number == 1
                            && superseded.latest_round_number == 1
                    })),
            "higher-round superseding vote lock should be persisted"
        );

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();
        if let Some(root) = path.parent().and_then(|data| data.parent()) {
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn stale_unfinalized_vote_locks_are_pruned_after_evidence() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let path = temp_vote_lock_path("transient-recovery");
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let finalized = signed_block(12, 1, "validator1");
        let transient = signed_block(13, 1, "validator1");
        DualQuorumConsensus::register_local_vote_intent("validator2", &finalized, 40, 1)
            .expect("finalized-height vote lock should persist");
        DualQuorumConsensus::register_local_vote_intent("validator2", &transient, 40, 1)
            .expect("transient vote lock should persist");

        let report = DualQuorumConsensus::recover_transient_vote_locks_above_finalized_height(
            12,
            0,
            "test stale transient recovery",
        )
        .expect("transient vote lock recovery should succeed");

        assert!(report.mutated);
        assert_eq!(report.removed_count, 1);
        assert_eq!(report.removed[0].block_hash, transient.hash);
        assert!(PathBuf::from(&report.evidence_path).exists());

        let locks = DualQuorumConsensus::load_local_vote_locks_unlocked()
            .expect("remaining vote locks should load");
        assert!(locks
            .values()
            .any(|lock| lock.block_hash == finalized.hash && lock.block_index == 12));
        assert!(locks
            .values()
            .all(|lock| lock.block_index <= 12 && lock.block_hash != transient.hash));

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        if let Some(root) = path.parent().and_then(|data| data.parent()) {
            let _ = fs::remove_dir_all(root);
        }
        let _ = fs::remove_file(report.evidence_path);
    }

    #[test]
    fn finalized_vote_lock_compaction_preserves_evidence_and_keeps_recent_locks() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let path = temp_vote_lock_path("finalized-lock-compaction");
        let root = path
            .parent()
            .and_then(|data| data.parent())
            .expect("vote lock path has test root")
            .to_path_buf();
        let previous_root = std::env::var("SYNERGY_PROJECT_ROOT").ok();
        std::env::set_var("SYNERGY_PROJECT_ROOT", &root);
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();
        fs::create_dir_all(path.parent().expect("vote lock path has parent"))
            .expect("vote lock parent should be created");
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let finalized = signed_block(2_000, 1, "validator1");
        crate::consensus::legacy_canonical_lock::write_legacy_canonical_lock(
            &finalized,
            &test_qc(&finalized.hash),
        )
        .expect("canonical finalized lock should be written");

        let now = DualQuorumConsensus::current_timestamp();
        let mut locks = HashMap::new();
        for height in 1..=LOCAL_VOTE_LOCK_COMPACTION_MIN_LOCKS as u64 {
            let hash = format!("old-hash-{height}");
            let key =
                DualQuorumConsensus::scoped_local_vote_lock_key("validator2", 40, height, 1, &hash);
            locks.insert(
                key,
                LocalVoteLock {
                    validator_address: "validator2".to_string(),
                    block_hash: hash,
                    block_index: height,
                    epoch_number: 40,
                    first_round_number: 1,
                    latest_round_number: 1,
                    proposer: "validator1".to_string(),
                    created_at: now.saturating_sub(60),
                    updated_at: now.saturating_sub(60),
                    superseded: Vec::new(),
                },
            );
        }
        let recent_hash = "recent-finalized-lock".to_string();
        let recent_key = DualQuorumConsensus::scoped_local_vote_lock_key(
            "validator2",
            40,
            1_990,
            1,
            &recent_hash,
        );
        locks.insert(
            recent_key,
            LocalVoteLock {
                validator_address: "validator2".to_string(),
                block_hash: recent_hash.clone(),
                block_index: 1_990,
                epoch_number: 40,
                first_round_number: 1,
                latest_round_number: 1,
                proposer: "validator1".to_string(),
                created_at: now.saturating_sub(60),
                updated_at: now.saturating_sub(60),
                superseded: Vec::new(),
            },
        );
        fs::write(&path, serde_json::to_vec(&locks).unwrap())
            .expect("large vote lock file should be seeded");

        let mut next = signed_block(2_001, 2, "validator1");
        next.previous_hash = finalized.hash.clone();
        DualQuorumConsensus::register_local_vote_intent("validator2", &next, 40, 1)
            .expect("vote intent should compact finalized locks and persist new lock");

        let compacted = DualQuorumConsensus::load_local_vote_locks_unlocked()
            .expect("compacted vote locks should load");
        assert!(
            compacted.values().all(|lock| lock.block_index > 1_984),
            "locks at or below finalized retention cutoff should be pruned"
        );
        assert!(compacted
            .values()
            .any(|lock| lock.block_hash == recent_hash && lock.block_index == 1_990));
        assert!(compacted
            .values()
            .any(|lock| lock.block_hash == next.hash && lock.block_index == 2_001));

        let evidence_root = crate::utils::resolve_data_path("data/consensus_recovery_evidence");
        let evidence_found = fs::read_dir(&evidence_root)
            .ok()
            .into_iter()
            .flat_map(|entries| entries.flatten())
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("finalized-vote-lock-compaction-through-1984")
            });
        assert!(
            evidence_found,
            "compaction must preserve removed lock evidence"
        );

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();
        match previous_root {
            Some(value) => std::env::set_var("SYNERGY_PROJECT_ROOT", value),
            None => std::env::remove_var("SYNERGY_PROJECT_ROOT"),
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn stale_conflicting_vote_lock_is_recovered_before_higher_round_vote() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();

        let path = temp_vote_lock_path("pre-vote-transient-recovery");
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let parent = signed_block(12, 1, "validator0");
        crate::consensus::legacy_canonical_lock::write_legacy_canonical_lock(
            &parent,
            &test_qc(&parent.hash),
        )
        .expect("canonical parent lock should be written");

        let mut first_block = signed_block(13, 1, "validator1");
        first_block.previous_hash = parent.hash.clone();
        let mut recovery_block = signed_block(13, 2, "validator3");
        recovery_block.previous_hash = parent.hash.clone();

        DualQuorumConsensus::register_local_vote_intent("validator2", &first_block, 40, 1)
            .expect("first local vote intent should persist");

        DualQuorumConsensus::recover_stale_conflicting_vote_lock_before_vote(
            "validator2",
            &recovery_block,
            40,
            2,
            0,
            "test higher-round transient recovery",
        )
        .expect("stale conflicting lock should recover before signing");

        DualQuorumConsensus::register_local_vote_intent("validator2", &recovery_block, 40, 2)
            .expect("higher-round vote may proceed only after stale transient evidence recovery");

        let locks = DualQuorumConsensus::load_local_vote_locks_unlocked()
            .expect("persisted vote locks should load");
        assert!(locks
            .values()
            .any(|lock| lock.block_hash == recovery_block.hash
                && lock.block_index == 13
                && lock.latest_round_number == 2));
        assert!(
            locks
                .values()
                .all(|lock| lock.block_hash != first_block.hash),
            "stale lock must be archived as recovery evidence before replacement"
        );

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();
        if let Some(root) = path.parent().and_then(|data| data.parent()) {
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn checkpoint_fork_parent_recovers_transient_vote_lock_without_legacy_lock() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let path = temp_vote_lock_path("checkpoint-fork-transient-recovery");
        let root = path
            .parent()
            .and_then(|data| data.parent())
            .expect("vote lock path has test root")
            .to_path_buf();
        fs::create_dir_all(path.parent().expect("vote lock path has parent"))
            .expect("vote lock parent should be created");
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let parent = signed_block(204_215, 1, "validator0");
        let mut pqc_manager = PQCManager::new();
        let (public_key, _) = pqc_manager
            .generate_keypair(PQCAlgorithm::FNDSA)
            .expect("FN-DSA key generation should succeed");
        let fork = serde_json::json!({
            "fork_height": 204_216,
            "parent_height": 204_215,
            "parent_hash": parent.hash,
            "state_root": "checkpoint-v1:test",
            "old_consensus_algorithm": "FN-DSA",
            "new_consensus_algorithm": "FN-DSA",
            "new_validator_registry": [{
                "validator_address": "validator2",
                "consensus_key_type": "FN-DSA",
                "consensus_public_key": general_purpose::STANDARD.encode(&public_key.key_data),
            }],
            "migration_reason": "test checkpointed FN-DSA fork",
            "parser_mode": "fail_closed"
        });
        let migration: crate::consensus::consensus_fork::ConsensusForkMigration =
            serde_json::from_value(fork.clone()).expect("test fork config should decode");
        let _fork_guard =
            crate::consensus::consensus_fork::set_test_active_consensus_fork_migration(migration);

        let mut first_block = signed_block(204_216, 1, "validator1");
        first_block.previous_hash = fork["parent_hash"]
            .as_str()
            .expect("fork parent hash should be a string")
            .to_string();
        let mut recovery_block = signed_block(204_216, 2, "validator3");
        recovery_block.previous_hash = first_block.previous_hash.clone();

        DualQuorumConsensus::register_local_vote_intent("validator2", &first_block, 204, 1)
            .expect("pre-fork transient vote intent should persist");

        DualQuorumConsensus::recover_stale_conflicting_vote_lock_before_vote(
            "validator2",
            &recovery_block,
            204,
            2,
            u64::MAX - 1,
            "checkpoint fork transient lock recovery",
        )
        .expect("checkpoint fork parent should recover transient vote lock immediately");

        DualQuorumConsensus::register_local_vote_intent("validator2", &recovery_block, 204, 2)
            .expect("post-fork higher-round vote can proceed after evidence recovery");

        let locks = DualQuorumConsensus::load_local_vote_locks_unlocked()
            .expect("persisted vote locks should load");
        assert!(locks
            .values()
            .any(|lock| lock.block_hash == recovery_block.hash
                && lock.block_index == 204_216
                && lock.latest_round_number == 2));
        assert!(locks
            .values()
            .all(|lock| lock.block_hash != first_block.hash));

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn fresh_conflicting_vote_lock_can_supersede_at_higher_round_without_recovery() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();

        let path = temp_vote_lock_path("fresh-pre-vote-transient-recovery");
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let parent = signed_block(12, 1, "validator0");
        crate::consensus::legacy_canonical_lock::write_legacy_canonical_lock(
            &parent,
            &test_qc(&parent.hash),
        )
        .expect("canonical parent lock should be written");

        let mut first_block = signed_block(13, 1, "validator1");
        first_block.previous_hash = parent.hash.clone();
        let mut recovery_block = signed_block(13, 2, "validator3");
        recovery_block.previous_hash = parent.hash.clone();

        DualQuorumConsensus::register_local_vote_intent("validator2", &first_block, 40, 1)
            .expect("first local vote intent should persist");

        DualQuorumConsensus::recover_stale_conflicting_vote_lock_before_vote(
            "validator2",
            &recovery_block,
            40,
            2,
            u64::MAX - 1,
            "test fresh transient lock remains locked",
        )
        .expect("fresh lock check should fail closed without mutation");

        DualQuorumConsensus::register_local_vote_intent("validator2", &recovery_block, 40, 2)
            .expect(
                "higher-round canonical-parent vote supersede should not wait for stale recovery",
            );

        let locked = DualQuorumConsensus::local_locked_vote_for_height("validator2", 40, 13)
            .expect("local vote lock lookup should succeed")
            .expect("higher-round lock should become latest");
        assert_eq!(locked.block_hash, recovery_block.hash);
        assert_eq!(locked.latest_round_number, 2);
        let locks = DualQuorumConsensus::load_local_vote_locks_unlocked()
            .expect("persisted vote locks should load");
        assert!(locks.values().any(|lock| {
            lock.block_hash == recovery_block.hash
                && lock.superseded.iter().any(|superseded| {
                    superseded.block_hash == first_block.hash && superseded.latest_round_number == 1
                })
        }));

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();
        if let Some(root) = path.parent().and_then(|data| data.parent()) {
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn finalized_canonical_lock_same_height_conflict_rejected_for_vote_supersede() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();

        let path = temp_vote_lock_path("local-vote-intent-finalized-conflict");
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let finalized = signed_block(13, 1, "validator1");
        let conflicting_block = signed_block(13, 2, "validator3");
        crate::consensus::legacy_canonical_lock::write_legacy_canonical_lock(
            &finalized,
            &test_qc(&finalized.hash),
        )
        .expect("finalized canonical lock should be written");

        DualQuorumConsensus::register_local_vote_intent("validator2", &finalized, 40, 1)
            .expect("first local vote intent should persist");
        let err = DualQuorumConsensus::register_local_vote_intent(
            "validator2",
            &conflicting_block,
            40,
            2,
        )
        .expect_err("finalized same-height canonical conflict must be rejected");
        assert!(
            err.contains("already finalized by canonical lock"),
            "unexpected finalized conflict error: {err}"
        );

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        crate::consensus::legacy_canonical_lock::clear_legacy_canonical_locks_for_tests();
        if let Some(root) = path.parent().and_then(|data| data.parent()) {
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn local_locked_vote_for_height_returns_persisted_same_height_lock() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let path = temp_vote_lock_path("local-locked-vote-read");
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let block = signed_block(14, 1, "validator1");
        DualQuorumConsensus::register_local_vote_intent("validator2", &block, 41, 3)
            .expect("local vote intent should persist");

        let locked_vote = DualQuorumConsensus::local_locked_vote_for_height("validator2", 41, 14)
            .expect("local vote lock lookup should succeed")
            .expect("local vote lock should exist");

        assert_eq!(locked_vote.validator_address, "validator2");
        assert_eq!(locked_vote.block_hash, block.hash);
        assert_eq!(locked_vote.block_index, 14);
        assert_eq!(locked_vote.epoch_number, 41);
        assert_eq!(locked_vote.first_round_number, 3);
        assert_eq!(locked_vote.latest_round_number, 3);
        assert_eq!(locked_vote.proposer, "validator1");

        let missing = DualQuorumConsensus::local_locked_vote_for_height("validator2", 41, 15)
            .expect("missing local vote lock lookup should succeed");
        assert!(missing.is_none());

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        if let Some(root) = path.parent().and_then(|data| data.parent()) {
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn verified_vote_signature_cache_key_binds_signature_material() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager = approved_validator_manager(&["validator1", "validator2"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            true,
            1,
            1,
            8,
            5,
        );

        let block = signed_block(8, 1, "validator1");
        let vote = DualQuorumConsensus::create_vote_for_validator("validator2", &block, 12, 1)
            .expect("vote should be created");

        consensus
            .verify_vote_signature(&vote)
            .expect("first verification should succeed");
        let cache_key = DualQuorumConsensus::vote_signature_cache_key(&vote);
        assert!(consensus
            .verified_vote_signatures
            .lock()
            .expect("cache lock")
            .contains(&cache_key));

        let mut tampered_vote = vote.clone();
        tampered_vote.signature.signature_data.push(0);
        assert_ne!(
            cache_key,
            DualQuorumConsensus::vote_signature_cache_key(&tampered_vote)
        );
    }

    #[test]
    fn merge_remote_votes_accepts_verified_votes_and_caches_signatures() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager =
            approved_validator_manager(&["validator1", "validator2", "validator3", "validator4"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            true,
            1,
            1,
            8,
            5,
        );

        let block = signed_block(9, 1, "validator1");
        let local_vote =
            DualQuorumConsensus::create_vote_for_validator("validator1", &block, 12, 1)
                .expect("local vote should be created");
        let remote_vote_a =
            DualQuorumConsensus::create_vote_for_validator("validator2", &block, 12, 1)
                .expect("remote vote should be created");
        let remote_vote_b =
            DualQuorumConsensus::create_vote_for_validator("validator3", &block, 12, 1)
                .expect("remote vote should be created");

        let expected_validators = ["validator1", "validator2", "validator3", "validator4"]
            .into_iter()
            .map(String::from)
            .collect::<BTreeSet<_>>();
        let remote_cache_key = DualQuorumConsensus::vote_signature_cache_key(&remote_vote_a);
        let mut votes = vec![local_vote];

        consensus.merge_remote_votes(
            &mut votes,
            &expected_validators,
            &block.hash,
            12,
            1,
            vec![remote_vote_a, remote_vote_b],
        );

        assert_eq!(votes.len(), 3);
        assert!(consensus.vote_signature_cache_contains(&remote_cache_key));
    }

    #[test]
    fn round_allocation_respects_view_floor() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager = approved_validator_manager(&["validator1"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let mut consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            true,
            1,
            1,
            8,
            5,
        );

        assert_eq!(consensus.allocate_round_number(4, 1, "validator1", 3), 3);
        assert_eq!(consensus.allocate_round_number(4, 1, "validator1", 3), 3);
        assert_eq!(consensus.allocate_round_number(4, 1, "validator1", 1), 1);
        assert_eq!(consensus.allocate_round_number(5, 1, "validator1", 1), 1);
    }

    #[test]
    fn round_allocation_resumes_above_persisted_lock_after_restart() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager = approved_validator_manager(&["validator1", "validator2"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let mut consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            true,
            1,
            1,
            8,
            5,
        );

        let path = temp_vote_lock_path("round-allocation-resume");
        DualQuorumConsensus::set_test_local_vote_lock_path(Some(path.clone()));

        let remote_leader_block = signed_block(14, 1, "validator1");
        DualQuorumConsensus::register_local_vote_intent("validator2", &remote_leader_block, 41, 41)
            .expect("prior local vote intent should be persisted");

        assert_eq!(
            consensus.allocate_round_number(14, 41, "validator2", 2),
            42,
            "round allocation must resume above a persisted same-height vote lock after restart"
        );

        DualQuorumConsensus::set_test_local_vote_lock_path(None);
        if let Some(root) = path.parent().and_then(|data| data.parent()) {
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn missed_vote_timeouts_are_ignored_when_penalization_is_disabled() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager = approved_validator_manager(&["validator1", "validator2"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            false,
            1,
            1,
            8,
            5,
        );

        let before = validator_manager
            .get_validator("validator2")
            .expect("validator should exist")
            .clone();

        consensus.record_missed_vote_timeouts(std::slice::from_ref(&before), &[]);

        let after = validator_manager
            .get_validator("validator2")
            .expect("validator should exist");
        assert_eq!(after.uptime_percentage, before.uptime_percentage);
        assert_eq!(after.task_accuracy, before.task_accuracy);
        assert_eq!(after.reputation_score, before.reputation_score);
        assert_eq!(after.missed_vote_window, before.missed_vote_window);
        assert_eq!(
            after.consecutive_missed_votes,
            before.consecutive_missed_votes
        );
        assert_eq!(after.status, ValidatorStatus::Active);
    }

    #[test]
    fn below_dynamic_quorum_equal_weight_votes_do_not_commit() {
        let validator_manager = approved_validator_manager(&[
            "validator1",
            "validator2",
            "validator3",
            "validator4",
            "validator5",
            "validator6",
        ]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            false,
            3,
            4,
            2,
            6,
        );
        let active_validators =
            consensus_membership_validators(validator_manager.get_active_validators());
        let votes = ["validator1", "validator2", "validator3", "validator4"]
            .into_iter()
            .map(|validator_address| Vote {
                validator_address: validator_address.to_string(),
                block_hash: "block-hash".to_string(),
                block_index: 42,
                epoch_number: 1,
                round_number: 1,
                signature: PQCSignature {
                    algorithm: PQCAlgorithm::FNDSA,
                    signature_data: Vec::new(),
                    message_hash: Vec::new(),
                    public_key_id: String::new(),
                    created_at: 0,
                },
                signer_public_key: Vec::new(),
                timestamp: 0,
            })
            .collect::<Vec<_>>();

        assert_eq!(
            consensus.required_validator_votes(active_validators.len()),
            5
        );
        assert!(
            !consensus.has_commit_quorum(&active_validators, &votes),
            "4 collected votes across six active validators must not satisfy 67% quorum"
        );

        let five_votes = [
            "validator1",
            "validator2",
            "validator3",
            "validator4",
            "validator5",
        ]
        .into_iter()
        .map(|validator_address| Vote {
            validator_address: validator_address.to_string(),
            block_hash: "block-hash".to_string(),
            block_index: 42,
            epoch_number: 1,
            round_number: 1,
            signature: PQCSignature {
                algorithm: PQCAlgorithm::FNDSA,
                signature_data: Vec::new(),
                message_hash: Vec::new(),
                public_key_id: String::new(),
                created_at: 0,
            },
            signer_public_key: Vec::new(),
            timestamp: 0,
        })
        .collect::<Vec<_>>();
        assert!(
            consensus.has_commit_quorum(&active_validators, &five_votes),
            "5 of 6 equal-weight votes should satisfy 67% quorum"
        );
    }

    #[test]
    fn validator_quorum_follows_active_validator_count_not_static_config() {
        let validator_manager =
            approved_validator_manager(&["validator1", "validator2", "validator3"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            false,
            1,
            4,
            2,
            6,
        );
        let active_validators =
            consensus_membership_validators(validator_manager.get_active_validators());
        let votes = ["validator1", "validator2", "validator3"]
            .into_iter()
            .map(|validator_address| Vote {
                validator_address: validator_address.to_string(),
                block_hash: "block-hash".to_string(),
                block_index: 42,
                epoch_number: 1,
                round_number: 1,
                signature: PQCSignature {
                    algorithm: PQCAlgorithm::FNDSA,
                    signature_data: Vec::new(),
                    message_hash: Vec::new(),
                    public_key_id: String::new(),
                    created_at: 0,
                },
                signer_public_key: Vec::new(),
                timestamp: 0,
            })
            .collect::<Vec<_>>();

        assert_eq!(
            consensus.required_validator_votes(active_validators.len()),
            required_validator_quorum(active_validators.len())
        );
        assert!(
            consensus.has_commit_quorum(&active_validators, &votes),
            "dynamic quorum must come from the active validator set, not a stale configured value"
        );
    }

    #[test]
    fn configured_quorum_does_not_override_bft_for_five_validators() {
        let validator_manager = approved_validator_manager(&[
            "validator1",
            "validator2",
            "validator3",
            "validator4",
            "validator5",
        ]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            false,
            1,
            3,
            2,
            6,
        );
        let active_validators =
            consensus_membership_validators(validator_manager.get_active_validators());
        let votes = ["validator1", "validator2", "validator3"]
            .into_iter()
            .map(|validator_address| Vote {
                validator_address: validator_address.to_string(),
                block_hash: "block-hash".to_string(),
                block_index: 42,
                epoch_number: 1,
                round_number: 1,
                signature: PQCSignature {
                    algorithm: PQCAlgorithm::FNDSA,
                    signature_data: Vec::new(),
                    message_hash: Vec::new(),
                    public_key_id: String::new(),
                    created_at: 0,
                },
                signer_public_key: Vec::new(),
                timestamp: 0,
            })
            .collect::<Vec<_>>();

        assert_eq!(
            consensus.required_validator_votes(active_validators.len()),
            4
        );
        assert!(
            !consensus.has_commit_quorum(&active_validators, &votes),
            "configured quorum must not allow 3 collected votes across five active validators"
        );
    }

    #[test]
    fn local_conflicting_vote_attempt_is_rejected_without_self_slashing() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager = approved_validator_manager(&["validator1", "validator2"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            true,
            1,
            1,
            8,
            5,
        );

        let first_block = signed_block(11, 1, "validator1");
        let conflicting_block = signed_block(11, 2, "validator1");

        let first_vote =
            DualQuorumConsensus::create_vote_for_validator("validator2", &first_block, 30, 1)
                .expect("first local vote should be created");
        consensus
            .register_local_vote_or_slash(&first_vote)
            .expect("first local vote should be accepted");

        let conflicting_vote =
            DualQuorumConsensus::create_vote_for_validator("validator2", &conflicting_block, 30, 1)
                .expect("conflicting local vote should be created");
        let error = consensus
            .register_local_vote_or_slash(&conflicting_vote)
            .expect_err("conflicting local vote should be rejected");
        assert!(
            error.contains("attempted conflicting votes"),
            "unexpected local conflict error: {error}"
        );

        let validator = validator_manager
            .get_validator("validator2")
            .expect("validator should still exist");
        assert_eq!(validator.status, ValidatorStatus::Active);
        assert_eq!(validator.double_signs, 0);
        assert_eq!(validator.equivocation_evidence_count, 0);

        let evidence = EQUIVOCATION_EVIDENCE_LOG.lock().expect("evidence log lock");
        let local_key = DualQuorumConsensus::vote_observation_key("validator2", 30, 11, 1);
        assert!(
            !evidence.contains_key(&local_key),
            "local conflicting vote should not persist slashable evidence"
        );
    }

    #[test]
    fn identical_vote_replay_is_idempotent() {
        let _vote_tracking_guard = DualQuorumConsensus::test_vote_tracking_guard();
        DualQuorumConsensus::reset_test_vote_tracking();

        let validator_manager = approved_validator_manager(&["validator1", "validator2"]);
        let pqc_manager = Arc::new(Mutex::new(PQCManager::new()));
        let consensus = DualQuorumConsensus::new(
            Arc::clone(&validator_manager),
            Arc::clone(&pqc_manager),
            true,
            1,
            1,
            8,
            5,
        );

        let block = signed_block(12, 1, "validator1");
        let vote = DualQuorumConsensus::create_vote_for_validator("validator2", &block, 31, 1)
            .expect("vote should be created");

        consensus
            .register_local_vote_or_slash(&vote)
            .expect("first local vote should be accepted");
        consensus
            .register_local_vote_or_slash(&vote)
            .expect("replaying the same vote should be idempotent");

        let validator = validator_manager
            .get_validator("validator2")
            .expect("validator should still exist");
        assert_eq!(validator.status, ValidatorStatus::Active);
        assert_eq!(validator.double_signs, 0);
        assert_eq!(validator.equivocation_evidence_count, 0);

        let evidence = EQUIVOCATION_EVIDENCE_LOG.lock().expect("evidence log lock");
        let local_key = DualQuorumConsensus::vote_observation_key("validator2", 31, 12, 1);
        assert!(
            !evidence.contains_key(&local_key),
            "idempotent replay should not persist slashable evidence"
        );
    }

    #[test]
    fn epoch_randomness_is_deterministic_for_shared_qc() {
        let previous_qc = QuorumCertificate {
            block_hash: "shared-block-hash".to_string(),
            epoch_number: 7,
            round_number: 3,
            aggregate_signature: vec![1, 2, 3],
            participant_bitmap: vec![0x1f],
            cumulative_weight: 5.0,
            validation_quorum_met: true,
            cooperation_quorum_met: true,
            timestamp: 1_777_000_000,
            votes: Vec::new(),
        };
        let mut beacon_a = EntropyBeacon::new(Arc::new(Mutex::new(PQCManager::new())));
        let mut beacon_b = EntropyBeacon::new(Arc::new(Mutex::new(PQCManager::new())));

        let randomness_a = beacon_a.generate_epoch_randomness(&previous_qc);
        let randomness_b = beacon_b.generate_epoch_randomness(&previous_qc);

        assert_eq!(randomness_a, randomness_b);
    }

    #[test]
    fn epoch_randomness_ignores_qc_timestamp_differences() {
        let previous_qc_a = QuorumCertificate {
            block_hash: "shared-block-hash".to_string(),
            epoch_number: 7,
            round_number: 3,
            aggregate_signature: vec![1, 2, 3],
            participant_bitmap: vec![0x1f],
            cumulative_weight: 5.0,
            validation_quorum_met: true,
            cooperation_quorum_met: true,
            timestamp: 1_777_000_000,
            votes: Vec::new(),
        };
        let mut previous_qc_b = previous_qc_a.clone();
        previous_qc_b.timestamp += 42;

        let mut beacon_a = EntropyBeacon::new(Arc::new(Mutex::new(PQCManager::new())));
        let mut beacon_b = EntropyBeacon::new(Arc::new(Mutex::new(PQCManager::new())));

        let randomness_a = beacon_a.generate_epoch_randomness(&previous_qc_a);
        let randomness_b = beacon_b.generate_epoch_randomness(&previous_qc_b);

        assert_eq!(randomness_a, randomness_b);
    }

    #[test]
    fn epoch_randomness_ignores_local_beacon_epoch_drift() {
        let previous_qc = QuorumCertificate {
            block_hash: "shared-block-hash".to_string(),
            epoch_number: 7,
            round_number: 3,
            aggregate_signature: vec![1, 2, 3],
            participant_bitmap: vec![0x1f],
            cumulative_weight: 5.0,
            validation_quorum_met: true,
            cooperation_quorum_met: true,
            timestamp: 1_777_000_000,
            votes: Vec::new(),
        };
        let mut beacon_a = EntropyBeacon::new(Arc::new(Mutex::new(PQCManager::new())));
        let mut beacon_b = EntropyBeacon::new(Arc::new(Mutex::new(PQCManager::new())));

        // Simulate nodes that have taken a different number of local transition
        // attempts before observing the same epoch-boundary QC.
        beacon_a.current_epoch = 2;
        beacon_b.current_epoch = 19;

        let randomness_a = beacon_a.generate_epoch_randomness(&previous_qc);
        let randomness_b = beacon_b.generate_epoch_randomness(&previous_qc);

        assert_eq!(randomness_a, randomness_b);
        assert_eq!(beacon_a.current_epoch, 8);
        assert_eq!(beacon_b.current_epoch, 8);
    }
}

#[derive(Debug, Clone)]
pub struct EntropyBeacon {
    pub current_epoch: u64,
    pub epoch_randomness: Vec<u8>,
    pub previous_qc_hash: String,
    pub nonce: u64,
    pub pqc_manager: Arc<Mutex<PQCManager>>,
    pub mlkem_keypairs: HashMap<u64, (PQCPublicKey, PQCPrivateKey)>, // Store keypairs per epoch
}

impl EntropyBeacon {
    pub fn new(pqc_manager: Arc<Mutex<PQCManager>>) -> Self {
        EntropyBeacon {
            current_epoch: 0,
            epoch_randomness: Vec::new(),
            previous_qc_hash: String::new(),
            nonce: 0,
            pqc_manager,
            mlkem_keypairs: HashMap::new(),
        }
    }

    pub fn generate_epoch_randomness(&mut self, previous_qc: &QuorumCertificate) -> Vec<u8> {
        let next_epoch = previous_qc.epoch_number.saturating_add(1);
        self.current_epoch = next_epoch;
        self.previous_qc_hash = self.hash_qc(previous_qc);
        self.nonce += 1;

        // Epoch randomness must be identical across validators at the same chain
        // tip. Only use deterministic inputs derived from the previous QC. Do
        // not generate KEM material in the live consensus epoch-transition path:
        // validator consensus signing is FN-DSA, while ML-KEM is a separate
        // encapsulation primitive and is not required to produce the next block.
        let mut input = Vec::new();
        input.extend(next_epoch.to_be_bytes());
        input.extend(self.previous_qc_hash.as_bytes());

        let mut hasher = Sha3_512::new();
        hasher.update(&input);
        let hash = hasher.finalize();

        // Store the computed randomness
        self.epoch_randomness = hash.to_vec();

        self.epoch_randomness.clone()
    }

    // Method to decapsulate and verify the shared secret (for cross-validation between validators)
    pub fn decapsulate_epoch_randomness(
        &self,
        epoch: u64,
        ciphertext: &PQCCiphertext,
    ) -> Result<Vec<u8>, String> {
        if let Some((_, priv_key)) = self.mlkem_keypairs.get(&epoch) {
            let pqc_manager = self.pqc_manager.lock().unwrap();
            let shared_secret = pqc_manager
                .decapsulate(priv_key, ciphertext)
                .map_err(|e| format!("Failed to decapsulate epoch randomness: {}", e))?;
            Ok(shared_secret.secret)
        } else {
            Err("No keypair found for epoch".to_string())
        }
    }

    fn hash_qc(&self, qc: &QuorumCertificate) -> String {
        let mut hasher = Sha3_512::new();
        hasher.update(qc.block_hash.as_bytes());
        hasher.update(qc.epoch_number.to_be_bytes());
        hasher.update(qc.round_number.to_be_bytes());
        hasher.update(&qc.aggregate_signature);
        hasher.update(&qc.participant_bitmap);
        hasher.update([qc.validation_quorum_met as u8]);
        hasher.update([qc.cooperation_quorum_met as u8]);
        let hash = hasher.finalize();
        hex::encode(hash)
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

#[derive(Debug, Clone)]
pub struct ValidatorRotation {
    pub validator_manager: Arc<ValidatorManager>,
    pub entropy_beacon: Arc<Mutex<EntropyBeacon>>,
    pub target_cluster_size: usize,
}

impl ValidatorRotation {
    pub fn new(
        validator_manager: Arc<ValidatorManager>,
        entropy_beacon: Arc<Mutex<EntropyBeacon>>,
    ) -> Self {
        ValidatorRotation {
            validator_manager,
            entropy_beacon,
            target_cluster_size: TESTNET_VALIDATOR_CLUSTER_SIZE,
        }
    }

    pub fn rotate_validators(&self) {
        let active_validators = self.validator_manager.get_active_validators();
        let epoch_randomness = self.get_current_epoch_randomness();

        // Use the canonical cluster policy so a new cluster is not created
        // until it can contain at least five validators.
        let num_clusters = target_validator_cluster_count(active_validators.len());
        if num_clusters == 0 {
            return;
        }

        // Assign validators to clusters using deterministic randomness
        for validator in &active_validators {
            self.assign_to_cluster(&validator.address, &epoch_randomness, num_clusters);
            // Update validator's cluster assignment
        }
    }

    fn assign_to_cluster(
        &self,
        validator_address: &str,
        epoch_randomness: &[u8],
        num_clusters: usize,
    ) -> usize {
        // Create hash of epoch_randomness + validator_address
        let mut hasher = Sha3_512::new();
        hasher.update(epoch_randomness);
        hasher.update(validator_address.as_bytes());
        let hash = hasher.finalize();

        // Use first 8 bytes as cluster assignment
        let cluster_hash = u64::from_be_bytes(hash[..8].try_into().unwrap());
        (cluster_hash % num_clusters as u64) as usize
    }

    fn get_current_epoch_randomness(&self) -> Vec<u8> {
        let beacon = self.entropy_beacon.lock().unwrap();
        beacon.epoch_randomness.clone()
    }
}
