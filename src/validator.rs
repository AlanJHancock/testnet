use crate::address::generate_cluster_address;
use crate::consensus::consensus_fork;
use crate::genesis::canonical_genesis;
use crate::token::TokenManager;
use crate::transaction::Transaction;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub const EPOCH_VALIDATOR_SETS_ENV: &str = "SYNERGY_EPOCH_VALIDATOR_SETS_FILE";
pub const DEFAULT_EPOCH_VALIDATOR_SETS_PATH: &str = "config/epoch-validator-sets.json";
pub const SUPPORTED_EPOCH_VALIDATOR_SET_FORMAT_VERSION: u64 = 1;

const VERBOSE_VALIDATOR_LOGS: bool = false;
pub const INITIAL_VALIDATOR_SYNERGY_SCORE: f64 = 100.0;
pub const TESTNET_VALIDATOR_CLUSTER_SIZE: usize = 7;
pub const TESTNET_MIN_VALIDATOR_CLUSTER_SIZE: usize = 5;
pub const TESTNET_FIRST_CLUSTER_SPLIT_THRESHOLD: usize = TESTNET_MIN_VALIDATOR_CLUSTER_SIZE * 2;
pub const MISSED_VOTE_JAIL_THRESHOLD: u64 = 3;
pub const MISSED_VOTE_SLASH_THRESHOLD: u64 = 6;
pub const VALIDATOR_SHADOW_PHASE_BLOCKS: u64 = 1_000;
const MISSED_VOTE_WINDOW_DECAY: u64 = 1;
const MISSED_VOTE_UPTIME_PENALTY: f64 = 2.5;
const MISSED_VOTE_ACCURACY_PENALTY: f64 = 2.0;
const MISSED_VOTE_REPUTATION_PENALTY: f64 = 4.0;
const MISSED_VOTE_SLASHING_INCREMENT: f64 = 0.05;
const VOTE_PARTICIPATION_RECOVERY: f64 = 0.5;
pub const TESTNET_MIN_VALIDATOR_STAKE_NWEI: u64 = 50_000_000_000_000;

macro_rules! validator_log {
    ($($arg:tt)*) => {
        if VERBOSE_VALIDATOR_LOGS {
            println!($($arg)*);
        }
    };
}

pub fn target_validator_cluster_count(active_validator_count: usize) -> usize {
    if active_validator_count == 0 {
        0
    } else if active_validator_count < TESTNET_FIRST_CLUSTER_SPLIT_THRESHOLD {
        1
    } else {
        2.max(active_validator_count.div_ceil(TESTNET_VALIDATOR_CLUSTER_SIZE))
    }
}

pub fn balanced_validator_cluster_id(index: usize, active_validator_count: usize) -> Option<u64> {
    let cluster_count = target_validator_cluster_count(active_validator_count);
    if cluster_count == 0 || index >= active_validator_count {
        return None;
    }

    let base_cluster_size = active_validator_count / cluster_count;
    let extra_members = active_validator_count % cluster_count;
    let mut start = 0usize;

    for cluster_index in 0..cluster_count {
        let size = base_cluster_size + usize::from(cluster_index < extra_members);
        let end = start + size;
        if index < end {
            return Some(cluster_index as u64);
        }
        start = end;
    }

    None
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    pub address: String,
    pub public_key: String,
    pub name: String,
    pub website: Option<String>,
    pub description: Option<String>,
    pub email: Option<String>,

    // Registration info
    pub registered_at: u64,
    pub last_active: u64,
    pub total_blocks_produced: u64,
    pub total_transactions_validated: u64,

    // Performance metrics
    pub uptime_percentage: f64,
    pub average_block_time: f64,
    pub missed_blocks: u64,
    pub double_signs: u64,
    #[serde(default)]
    pub consecutive_missed_votes: u64,
    #[serde(default)]
    pub missed_vote_window: u64,
    #[serde(default)]
    pub last_vote_timestamp: u64,
    #[serde(default)]
    pub equivocation_evidence_count: u64,

    // Synergy scores
    pub synergy_score: f64,
    pub task_accuracy: f64,
    pub collaboration_score: f64,
    pub reputation_score: f64,
    pub slashing_penalty: f64,

    // Staking info
    pub stake_amount: u64,
    pub min_stake_required: u64,

    // Network info
    pub cluster_id: Option<u64>,
    #[serde(default)]
    pub cluster_address: Option<String>,
    pub status: ValidatorStatus,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_tx_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shadow_started_at_height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_recorded_height: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_effective_height: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValidatorDisciplineAction {
    JailForInactivity,
    SlashForInactivity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ValidatorStatus {
    Active,
    Inactive,
    Jailed,
    Slashed,
    Pending,
    Shadow,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorCluster {
    pub id: u64,
    pub address: String, // Cluster address using syngrp{1-5} format
    pub validators: Vec<String>,
    pub total_stake: u64,
    pub average_synergy_score: f64,
    pub created_at: u64,
    pub last_rotation: u64,
    pub group: u8, // Cluster group (1-5) for address prefix
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorRegistry {
    pub validators: HashMap<String, Validator>,
    pub clusters: HashMap<u64, ValidatorCluster>,
    pub pending_registrations: HashMap<String, ValidatorRegistration>,
    pub jailed_validators: HashSet<String>,

    // Registry settings
    pub min_stake_amount: u64,
    pub max_validators: usize,
    pub cluster_size: usize,
    pub epoch_length: u64,
    pub current_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorRegistration {
    pub address: String,
    pub public_key: String,
    pub name: String,
    pub stake_amount: u64,
    pub submitted_at: u64,
    pub registration_tx_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochValidatorSetSnapshot {
    #[serde(default = "default_epoch_validator_set_format_version")]
    pub snapshot_format_version: u64,
    #[serde(default)]
    pub chain_id: Option<u64>,
    #[serde(default)]
    pub epoch_id: Option<u64>,
    #[serde(default)]
    pub validator_set_version: Option<u64>,
    pub effective_from_height: u64,
    #[serde(default)]
    pub effective_to_height: Option<u64>,
    #[serde(default)]
    pub active_validators: Vec<EpochValidatorMember>,
    #[serde(default)]
    pub pending_validators: Vec<EpochValidatorMember>,
    #[serde(default)]
    pub jailed_validators: Vec<EpochValidatorMember>,
    #[serde(default)]
    pub removed_validators: Vec<EpochValidatorMember>,
    #[serde(default)]
    pub quorum_threshold: Option<usize>,
    #[serde(default)]
    pub source_registry_hash: Option<String>,
    #[serde(default)]
    pub state_hash: Option<String>,
    #[serde(default)]
    pub previous_set_hash: Option<String>,
    #[serde(default)]
    pub validator_set_hash: Option<String>,
    #[serde(
        default,
        alias = "protocol_version",
        alias = "consensus_protocol_version",
        skip_serializing_if = "Option::is_none"
    )]
    pub required_protocol_version: Option<String>,
    #[serde(
        default,
        alias = "binary_version",
        alias = "runtime_version",
        alias = "required_runtime_version",
        skip_serializing_if = "Option::is_none"
    )]
    pub required_binary_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EpochValidatorMember {
    Address(String),
    Record {
        #[serde(
            default,
            alias = "address",
            alias = "operator_address",
            alias = "validator_id"
        )]
        validator_address: String,
        #[serde(default)]
        voting_weight: Option<u64>,
        #[serde(default)]
        proposer_eligible: Option<bool>,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum EpochValidatorSetDocument {
    List(Vec<EpochValidatorSetSnapshot>),
    Wrapped {
        #[serde(default, alias = "validator_sets")]
        epoch_validator_sets: Vec<EpochValidatorSetSnapshot>,
    },
}

impl EpochValidatorSetSnapshot {
    fn applies_to_height(&self, height: u64) -> bool {
        height >= self.effective_from_height
            && self
                .effective_to_height
                .map(|effective_to| height <= effective_to)
                .unwrap_or(true)
    }

    fn active_validator_addresses(&self) -> Result<Vec<String>, String> {
        let mut addresses = Vec::with_capacity(self.active_validators.len());
        let mut seen = HashSet::new();
        for member in &self.active_validators {
            let address = member.validator_address().ok_or_else(|| {
                "epoch validator set contains an empty active validator".to_string()
            })?;
            if !seen.insert(address.clone()) {
                return Err(format!(
                    "epoch validator set contains duplicate active validator {address}"
                ));
            }
            addresses.push(address);
        }
        if addresses.is_empty() {
            return Err("epoch validator set has no active validators".to_string());
        }
        Ok(addresses)
    }

    fn validate_local_compatibility(&self) -> Result<(), String> {
        if self.snapshot_format_version > SUPPORTED_EPOCH_VALIDATOR_SET_FORMAT_VERSION {
            return Err(format!(
                "epoch validator set format version {} is newer than supported version {}; refusing consensus participation",
                self.snapshot_format_version, SUPPORTED_EPOCH_VALIDATOR_SET_FORMAT_VERSION
            ));
        }

        if let Some(required_protocol_version) =
            normalized_optional_string(self.required_protocol_version.as_deref())
        {
            let local_protocol_version = local_epoch_validator_set_protocol_version();
            if required_protocol_version != local_protocol_version {
                return Err(format!(
                    "epoch validator set requires protocol version {required_protocol_version}, local protocol version is {local_protocol_version}; refusing consensus participation"
                ));
            }
        }

        if let Some(required_binary_version) =
            normalized_optional_string(self.required_binary_version.as_deref())
        {
            let local_binary_version = env!("CARGO_PKG_VERSION");
            if required_binary_version != local_binary_version {
                return Err(format!(
                    "epoch validator set requires binary version {required_binary_version}, local binary version is {local_binary_version}; refusing consensus participation"
                ));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochValidatorSetCompatibility {
    pub snapshot_format_version: u64,
    pub supported_snapshot_format_version: u64,
    pub required_protocol_version: Option<String>,
    pub local_protocol_version: String,
    pub required_binary_version: Option<String>,
    pub local_binary_version: String,
    pub validator_set_hash: Option<String>,
}

fn default_epoch_validator_set_format_version() -> u64 {
    SUPPORTED_EPOCH_VALIDATOR_SET_FORMAT_VERSION
}

fn normalized_optional_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub fn local_epoch_validator_set_protocol_version() -> String {
    canonical_genesis()
        .map(|genesis| genesis.protocol_version().to_string())
        .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string())
}

impl EpochValidatorMember {
    fn validator_address(&self) -> Option<String> {
        match self {
            EpochValidatorMember::Address(address) => {
                let trimmed = address.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            }
            EpochValidatorMember::Record {
                validator_address, ..
            } => {
                let trimmed = validator_address.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            }
        }
    }
}

#[derive(Debug)]
pub struct ValidatorManager {
    pub registry: Arc<Mutex<ValidatorRegistry>>,
}

impl Validator {
    pub fn new(address: String, public_key: String, name: String, stake_amount: u64) -> Self {
        let current_time = Self::current_timestamp();

        Validator {
            address,
            public_key,
            name,
            website: None,
            description: None,
            email: None,
            registered_at: current_time,
            last_active: current_time,
            total_blocks_produced: 0,
            total_transactions_validated: 0,
            uptime_percentage: 100.0,
            average_block_time: 5.0,
            missed_blocks: 0,
            double_signs: 0,
            consecutive_missed_votes: 0,
            missed_vote_window: 0,
            last_vote_timestamp: 0,
            equivocation_evidence_count: 0,
            synergy_score: INITIAL_VALIDATOR_SYNERGY_SCORE,
            task_accuracy: 100.0,
            collaboration_score: 0.0,
            reputation_score: 100.0,
            slashing_penalty: 0.0,
            stake_amount,
            min_stake_required: stake_amount,
            cluster_id: None,
            cluster_address: None,
            status: ValidatorStatus::Pending,
            version: "1.0.0".to_string(),
            activation_tx_hash: None,
            shadow_started_at_height: None,
            activation_recorded_height: None,
            activation_effective_height: None,
        }
    }

    pub fn update_activity(&mut self) {
        self.last_active = Self::current_timestamp();
    }

    pub fn record_block_production(&mut self) {
        self.total_blocks_produced += 1;
        self.record_vote_participation();
    }

    pub fn record_missed_block(&mut self) {
        self.record_missed_vote();
    }

    pub fn record_vote_participation(&mut self) {
        self.total_transactions_validated += 1;
        self.consecutive_missed_votes = 0;
        self.missed_vote_window = self
            .missed_vote_window
            .saturating_sub(MISSED_VOTE_WINDOW_DECAY);
        self.last_vote_timestamp = Self::current_timestamp();
        self.uptime_percentage = (self.uptime_percentage + VOTE_PARTICIPATION_RECOVERY).min(100.0);
        self.task_accuracy = (self.task_accuracy + VOTE_PARTICIPATION_RECOVERY).min(100.0);
        self.update_activity();
        self.calculate_synergy_score();
    }

    pub fn record_missed_vote(&mut self) {
        self.missed_blocks += 1;
        self.consecutive_missed_votes += 1;
        self.missed_vote_window = self.missed_vote_window.saturating_add(1);
        self.uptime_percentage = (self.uptime_percentage - MISSED_VOTE_UPTIME_PENALTY).max(0.0);
        self.task_accuracy = (self.task_accuracy - MISSED_VOTE_ACCURACY_PENALTY).max(0.0);
        self.reputation_score = (self.reputation_score - MISSED_VOTE_REPUTATION_PENALTY).max(0.0);
        self.slashing_penalty = (self.slashing_penalty + MISSED_VOTE_SLASHING_INCREMENT).min(1.0);
        self.calculate_synergy_score();
    }

    pub fn record_double_sign(&mut self) {
        self.double_signs += 1;
        self.equivocation_evidence_count += 1;
        self.slashing_penalty = 1.0;
        self.reputation_score = 0.0;
        self.task_accuracy = 0.0;
        self.status = ValidatorStatus::Slashed;
        self.update_activity();
        self.calculate_synergy_score();
    }

    fn inactivity_discipline_action(&self) -> Option<ValidatorDisciplineAction> {
        if self.missed_vote_window >= MISSED_VOTE_SLASH_THRESHOLD {
            Some(ValidatorDisciplineAction::SlashForInactivity)
        } else if self.missed_vote_window >= MISSED_VOTE_JAIL_THRESHOLD {
            Some(ValidatorDisciplineAction::JailForInactivity)
        } else {
            None
        }
    }

    pub fn calculate_synergy_score(&mut self) {
        // Calculate synergy score based on multiple factors
        let uptime_factor = self.uptime_percentage / 100.0;
        let accuracy_factor = self.task_accuracy / 100.0;
        let reputation_factor = self.reputation_score / 100.0;
        let stake_factor = (self.stake_amount as f64 / self.min_stake_required as f64).min(2.0);
        let slashing_factor = (1.0 - self.slashing_penalty.clamp(0.0, 1.0)).max(0.0);

        // Weighted average of factors
        self.synergy_score = (uptime_factor * 0.3
            + accuracy_factor * 0.3
            + reputation_factor * 0.2
            + stake_factor * 0.2)
            * 100.0
            * slashing_factor;
    }

    pub fn is_eligible(&self, min_stake: u64) -> bool {
        // Consensus membership must only depend on shared state. Local uptime,
        // reputation, and soft-score observations can drift between validators
        // and must not evict peers from the active set.
        self.status == ValidatorStatus::Active && self.stake_amount >= min_stake
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

impl ValidatorRegistry {
    pub fn new() -> Self {
        ValidatorRegistry {
            validators: HashMap::new(),
            clusters: HashMap::new(),
            pending_registrations: HashMap::new(),
            jailed_validators: HashSet::new(),
            min_stake_amount: 0, // Lowered for testnet (production: 1000)
            max_validators: 0,
            cluster_size: TESTNET_VALIDATOR_CLUSTER_SIZE,
            epoch_length: 30000,
            current_epoch: 0,
        }
    }

    pub fn register_validator(
        &mut self,
        registration: ValidatorRegistration,
    ) -> Result<String, String> {
        // Check if already registered
        if self.validators.contains_key(&registration.address) {
            return Err("Validator already registered".to_string());
        }

        // Check if pending
        if self
            .pending_registrations
            .contains_key(&registration.address)
        {
            return Err("Registration already pending".to_string());
        }

        // Validate stake amount
        if registration.stake_amount < self.min_stake_amount {
            return Err(format!(
                "Insufficient stake. Minimum required: {}",
                self.min_stake_amount
            ));
        }

        // Add to pending registrations
        self.pending_registrations
            .insert(registration.address.clone(), registration);

        Ok("Validator registration submitted successfully".to_string())
    }

    pub fn approve_registration(&mut self, address: &str) -> Result<(), String> {
        if let Some(registration) = self.pending_registrations.remove(address) {
            let mut validator = Validator::new(
                registration.address.clone(),
                registration.public_key,
                registration.name,
                registration.stake_amount,
            );

            validator.status = ValidatorStatus::Active;

            // New validators start fully healthy, then consensus updates the score from activity.
            validator.synergy_score = INITIAL_VALIDATOR_SYNERGY_SCORE;
            validator.uptime_percentage = 100.0;

            // Ensure stake amount is properly set (this was the missing piece)
            validator.stake_amount = registration.stake_amount;
            validator.min_stake_required = registration.stake_amount;
            validator.activation_tx_hash = Some(registration.registration_tx_hash);

            self.validators.insert(address.to_string(), validator);

            // Trigger cluster reorganization
            self.reorganize_clusters();

            Ok(())
        } else {
            Err("No pending registration found".to_string())
        }
    }

    pub fn start_shadow_activation(
        &mut self,
        address: &str,
        activation_block_height: u64,
    ) -> Result<(), String> {
        if let Some(registration) = self.pending_registrations.remove(address) {
            let activation_recorded_height =
                activation_block_height.saturating_add(VALIDATOR_SHADOW_PHASE_BLOCKS);
            let mut validator = Validator::new(
                registration.address.clone(),
                registration.public_key,
                registration.name,
                registration.stake_amount,
            );

            validator.status = ValidatorStatus::Shadow;
            validator.stake_amount = registration.stake_amount;
            validator.min_stake_required = registration.stake_amount;
            validator.activation_tx_hash = Some(registration.registration_tx_hash);
            validator.shadow_started_at_height = Some(activation_block_height);
            validator.activation_recorded_height = Some(activation_recorded_height);
            validator.activation_effective_height =
                Some(activation_recorded_height.saturating_add(1));

            self.validators.insert(address.to_string(), validator);
            Ok(())
        } else {
            Err("No pending registration found".to_string())
        }
    }

    pub fn restart_shadow_activation_for_existing(
        &mut self,
        address: &str,
        public_key: String,
        name: String,
        stake_amount: u64,
        activation_tx_hash: String,
        activation_block_height: u64,
    ) -> Result<(), String> {
        let Some(validator) = self.validators.get_mut(address) else {
            return Err("Validator not found".to_string());
        };

        match validator.status.clone() {
            ValidatorStatus::Active => {
                return Ok(());
            }
            ValidatorStatus::Shadow => {
                validator.stake_amount = stake_amount;
                validator.min_stake_required = stake_amount;
                return Ok(());
            }
            ValidatorStatus::Jailed | ValidatorStatus::Slashed => {
                return Err(format!(
                    "Validator {address} is disciplined and cannot be activation-replayed"
                ));
            }
            ValidatorStatus::Inactive | ValidatorStatus::Pending => {}
        }

        let activation_recorded_height =
            activation_block_height.saturating_add(VALIDATOR_SHADOW_PHASE_BLOCKS);
        validator.public_key = public_key;
        validator.name = name;
        validator.status = ValidatorStatus::Shadow;
        validator.stake_amount = stake_amount;
        validator.min_stake_required = stake_amount;
        validator.activation_tx_hash = Some(activation_tx_hash);
        validator.shadow_started_at_height = Some(activation_block_height);
        validator.activation_recorded_height = Some(activation_recorded_height);
        validator.activation_effective_height = Some(activation_recorded_height.saturating_add(1));
        validator.synergy_score = INITIAL_VALIDATOR_SYNERGY_SCORE;
        validator.uptime_percentage = 100.0;
        Ok(())
    }

    pub fn apply_pending_shadow_activations(&mut self, finalized_height: u64) -> Vec<String> {
        let mut activated = Vec::new();
        for validator in self.validators.values_mut() {
            if validator.status != ValidatorStatus::Shadow {
                continue;
            }
            let effective_height = validator
                .activation_effective_height
                .or_else(|| {
                    validator
                        .activation_recorded_height
                        .map(|height| height.saturating_add(1))
                })
                .unwrap_or(u64::MAX);
            if finalized_height < effective_height {
                continue;
            };

            validator.status = ValidatorStatus::Active;
            validator.synergy_score = INITIAL_VALIDATOR_SYNERGY_SCORE;
            validator.uptime_percentage = 100.0;
            activated.push(validator.address.clone());
        }

        if !activated.is_empty() {
            self.reorganize_clusters();
        }

        activated
    }

    pub fn update_validator_performance(
        &mut self,
        address: &str,
        performance_data: ValidatorPerformanceUpdate,
    ) {
        let mut should_reorganize = false;
        let mut should_jail = false;

        if let Some(validator) = self.validators.get_mut(address) {
            match performance_data.update_type.as_str() {
                "block_produced" => {
                    validator.record_block_production();
                }
                "vote_cast" => {
                    validator.record_vote_participation();
                }
                "block_missed" => {
                    validator.record_missed_vote();
                }
                "double_sign" | "equivocation" => {
                    validator.record_double_sign();
                    should_jail = true;
                    should_reorganize = true;
                }
                "uptime_update" => {
                    if let Some(uptime) = performance_data.value {
                        validator.uptime_percentage = uptime;
                        validator.update_activity();
                    }
                }
                "accuracy_update" => {
                    if let Some(accuracy) = performance_data.value {
                        validator.task_accuracy = accuracy;
                        validator.update_activity();
                    }
                }
                _ => {}
            }

            match validator.inactivity_discipline_action() {
                Some(ValidatorDisciplineAction::SlashForInactivity)
                    if validator.status != ValidatorStatus::Slashed =>
                {
                    validator.status = ValidatorStatus::Slashed;
                    validator.slashing_penalty = validator.slashing_penalty.max(0.5);
                    validator.calculate_synergy_score();
                    should_jail = true;
                    should_reorganize = true;
                }
                Some(ValidatorDisciplineAction::JailForInactivity)
                    if validator.status == ValidatorStatus::Active =>
                {
                    validator.status = ValidatorStatus::Jailed;
                    should_jail = true;
                    should_reorganize = true;
                }
                _ => {}
            }

            validator.calculate_synergy_score();
        }

        if should_jail {
            self.jailed_validators.insert(address.to_string());
        }

        if should_reorganize {
            self.reorganize_clusters();
        }
    }

    pub fn get_active_validators(&self) -> Vec<&Validator> {
        self.validators
            .values()
            .filter(|v| v.status == ValidatorStatus::Active && v.is_eligible(self.min_stake_amount))
            .collect()
    }

    pub fn get_validator_by_address(&self, address: &str) -> Option<&Validator> {
        self.validators.get(address)
    }

    pub fn reorganize_clusters(&mut self) {
        self.reorganize_clusters_for_epoch(self.current_epoch);
    }

    pub fn reorganize_clusters_for_epoch(&mut self, epoch: u64) {
        self.current_epoch = epoch;
        let mut active_validators: Vec<Validator> =
            self.get_active_validators().into_iter().cloned().collect();

        for validator in self.validators.values_mut() {
            validator.cluster_id = None;
            validator.cluster_address = None;
        }
        self.clusters.clear();

        if active_validators.is_empty() {
            return;
        }

        active_validators.sort_by(|a, b| {
            epoch_cluster_rank(epoch, &a.address)
                .cmp(&epoch_cluster_rank(epoch, &b.address))
                .then_with(|| a.address.cmp(&b.address))
        });

        let cluster_count = target_validator_cluster_count(active_validators.len());
        let base_cluster_size = active_validators.len() / cluster_count;
        let extra_members = active_validators.len() % cluster_count;
        let target_sizes: Vec<usize> = (0..cluster_count)
            .map(|index| base_cluster_size + usize::from(index < extra_members))
            .collect();
        let mut cluster_members: Vec<Vec<Validator>> =
            (0..cluster_count).map(|_| Vec::new()).collect();
        let mut next_cluster_index = 0usize;

        for validator in active_validators {
            while cluster_members[next_cluster_index].len() >= target_sizes[next_cluster_index] {
                next_cluster_index = (next_cluster_index + 1) % cluster_count;
            }
            cluster_members[next_cluster_index].push(validator);
            next_cluster_index = (next_cluster_index + 1) % cluster_count;
        }

        let now = Validator::current_timestamp();
        for (cluster_index, members) in cluster_members.into_iter().enumerate() {
            let cluster_id = cluster_index as u64;
            let cluster_group = ((cluster_id % 5) + 1) as u8;
            let validator_addresses: Vec<String> = members
                .iter()
                .map(|validator| validator.address.clone())
                .collect();
            let cluster_seed = format!("cluster-{}-{}", cluster_id, validator_addresses.join("-"));
            let cluster_address = generate_cluster_address(&cluster_seed, cluster_group);
            let total_stake = members.iter().map(|validator| validator.stake_amount).sum();
            let average_synergy_score = members
                .iter()
                .map(|validator| validator.synergy_score)
                .sum::<f64>()
                / members.len() as f64;

            self.clusters.insert(
                cluster_id,
                ValidatorCluster {
                    id: cluster_id,
                    address: cluster_address.clone(),
                    validators: validator_addresses.clone(),
                    total_stake,
                    average_synergy_score,
                    created_at: now,
                    last_rotation: now,
                    group: cluster_group,
                },
            );

            for address in validator_addresses {
                if let Some(validator) = self.validators.get_mut(&address) {
                    validator.cluster_id = Some(cluster_id);
                    validator.cluster_address = Some(cluster_address.clone());
                }
            }
        }
    }

    pub fn get_validator_cluster(&self, address: &str) -> Option<&ValidatorCluster> {
        if let Some(validator) = self.validators.get(address) {
            if let Some(cluster_id) = validator.cluster_id {
                return self.clusters.get(&cluster_id);
            }
        }
        None
    }

    pub fn slash_validator(&mut self, address: &str, reason: &str) -> Result<(), String> {
        if let Some(validator) = self.validators.get_mut(address) {
            match reason {
                "double_sign" => {
                    validator.record_double_sign();
                    validator.status = ValidatorStatus::Slashed;
                    self.jailed_validators.insert(address.to_string());
                }
                "inactivity" | "inactivity_jail" => {
                    validator.status = ValidatorStatus::Jailed;
                    validator.missed_vote_window =
                        validator.missed_vote_window.max(MISSED_VOTE_JAIL_THRESHOLD);
                    validator.slashing_penalty = validator.slashing_penalty.max(0.15);
                    validator.calculate_synergy_score();
                    self.jailed_validators.insert(address.to_string());
                }
                "inactivity_slash" => {
                    validator.status = ValidatorStatus::Slashed;
                    validator.missed_vote_window = validator
                        .missed_vote_window
                        .max(MISSED_VOTE_SLASH_THRESHOLD);
                    validator.slashing_penalty = validator.slashing_penalty.max(0.5);
                    validator.calculate_synergy_score();
                    self.jailed_validators.insert(address.to_string());
                }
                _ => {
                    return Err("Unknown slashing reason".to_string());
                }
            }

            // Trigger cluster reorganization
            self.reorganize_clusters();

            Ok(())
        } else {
            Err("Validator not found".to_string())
        }
    }

    pub fn unjail_validator(&mut self, address: &str) -> Result<(), String> {
        if let Some(validator) = self.validators.get_mut(address) {
            if self.jailed_validators.remove(address) {
                validator.status = ValidatorStatus::Active;
                validator.consecutive_missed_votes = 0;
                validator.missed_vote_window = 0;
                validator.update_activity();
                self.reorganize_clusters();
                Ok(())
            } else {
                Err("Validator is not jailed".to_string())
            }
        } else {
            Err("Validator not found".to_string())
        }
    }

    pub fn get_top_validators(&self, count: usize) -> Vec<&Validator> {
        let mut validators: Vec<_> = self.validators.values().collect();
        validators.sort_by(|a, b| b.synergy_score.partial_cmp(&a.synergy_score).unwrap());
        validators.into_iter().take(count).collect()
    }

    pub fn calculate_epoch_rewards(&self, _epoch: u64) -> HashMap<String, u64> {
        let mut rewards = HashMap::new();

        // Ensure we have active validators with stakes
        let active_validators: Vec<_> = self
            .validators
            .values()
            .filter(|v| v.status == ValidatorStatus::Active && v.stake_amount > 0)
            .collect();

        if active_validators.is_empty() {
            // If no active validators with stakes, return empty rewards
            return rewards;
        }

        for validator in active_validators {
            if validator.is_eligible(self.min_stake_amount) {
                // Legacy reward preview only. Consensus settlement now uses
                // rewards.rs two-phase integer accounting.
                let base_reward = 100u64;
                let capped_stake = validator
                    .stake_amount
                    .min(self.min_stake_amount.saturating_mul(3));
                let total_reward = (base_reward as u128)
                    .saturating_mul(capped_stake as u128)
                    .checked_div(self.min_stake_amount.max(1) as u128)
                    .and_then(|value| u64::try_from(value).ok())
                    .unwrap_or(u64::MAX);
                rewards.insert(validator.address.clone(), total_reward);
            }
        }

        rewards
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let registry: ValidatorRegistry = serde_json::from_str(&content)?;
        Ok(registry)
    }
}

fn epoch_cluster_rank(epoch: u64, address: &str) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(epoch.to_be_bytes());
    hasher.update(address.as_bytes());
    hasher.finalize().into()
}

#[derive(Debug, Clone)]
pub struct ValidatorPerformanceUpdate {
    pub validator_address: String,
    pub update_type: String, // "block_produced", "block_missed", "uptime_update", etc.
    pub value: Option<f64>,
    pub timestamp: u64,
}

impl ValidatorManager {
    pub fn new() -> Self {
        ValidatorManager {
            registry: Arc::new(Mutex::new(ValidatorRegistry::new())),
        }
    }

    pub fn register_validator(
        &self,
        registration: ValidatorRegistration,
    ) -> Result<String, String> {
        if let Ok(mut registry) = self.registry.lock() {
            registry.register_validator(registration)
        } else {
            Err("Failed to acquire registry lock".to_string())
        }
    }

    pub fn approve_validator(&self, address: &str) -> Result<(), String> {
        if let Ok(mut registry) = self.registry.lock() {
            // First try to approve from pending registrations
            if registry.approve_registration(address).is_ok() {
                return Ok(());
            }

            // If not in pending, check if already registered but not approved
            if let Some(validator) = registry.validators.get(address) {
                if validator.status != ValidatorStatus::Active {
                    // Create a new active validator with proper defaults
                    let mut active_validator = validator.clone();
                    active_validator.status = ValidatorStatus::Active;
                    active_validator.synergy_score = INITIAL_VALIDATOR_SYNERGY_SCORE;
                    active_validator.uptime_percentage = 100.0;
                    registry
                        .validators
                        .insert(address.to_string(), active_validator);
                    registry.reorganize_clusters();
                    return Ok(());
                }
            }

            Err("Validator not found or already active".to_string())
        } else {
            Err("Failed to acquire registry lock".to_string())
        }
    }

    pub fn start_shadow_activation(
        &self,
        address: &str,
        activation_block_height: u64,
    ) -> Result<(), String> {
        if let Ok(mut registry) = self.registry.lock() {
            registry.start_shadow_activation(address, activation_block_height)
        } else {
            Err("Failed to acquire registry lock".to_string())
        }
    }

    pub fn restart_shadow_activation_for_existing(
        &self,
        address: &str,
        public_key: String,
        name: String,
        stake_amount: u64,
        activation_tx_hash: String,
        activation_block_height: u64,
    ) -> Result<(), String> {
        if let Ok(mut registry) = self.registry.lock() {
            registry.restart_shadow_activation_for_existing(
                address,
                public_key,
                name,
                stake_amount,
                activation_tx_hash,
                activation_block_height,
            )
        } else {
            Err("Failed to acquire registry lock".to_string())
        }
    }

    pub fn apply_pending_shadow_activations(&self, finalized_height: u64) -> Vec<String> {
        if let Ok(mut registry) = self.registry.lock() {
            registry.apply_pending_shadow_activations(finalized_height)
        } else {
            Vec::new()
        }
    }

    pub fn update_performance(&self, update: ValidatorPerformanceUpdate) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.update_validator_performance(&update.validator_address.clone(), update);
        }
    }

    pub fn update_synergy_score(&self, address: &str, score: f64) -> bool {
        if let Ok(mut registry) = self.registry.lock() {
            if let Some(validator) = registry.validators.get_mut(address) {
                validator.synergy_score = score;
                return true;
            }
        }
        false
    }

    pub fn update_validator_stake(&self, address: &str, stake_amount: u64) -> bool {
        if let Ok(mut registry) = self.registry.lock() {
            if let Some(validator) = registry.validators.get_mut(address) {
                validator.stake_amount = stake_amount;
                validator.min_stake_required = stake_amount;
                validator.calculate_synergy_score();
                return true;
            }
        }
        false
    }

    pub fn minimum_stake_amount(&self) -> u64 {
        self.registry
            .lock()
            .map(|registry| registry.min_stake_amount)
            .unwrap_or(0)
    }

    pub fn get_validator(&self, address: &str) -> Option<Validator> {
        if let Ok(registry) = self.registry.lock() {
            registry.get_validator_by_address(address).cloned()
        } else {
            None
        }
    }

    pub fn get_validator_cluster(&self, address: &str) -> Option<ValidatorCluster> {
        if let Ok(registry) = self.registry.lock() {
            registry.get_validator_cluster(address).cloned()
        } else {
            None
        }
    }

    pub fn get_active_validators(&self) -> Vec<Validator> {
        if let Ok(registry) = self.registry.lock() {
            validator_log!(
                "🔍 [get_active_validators] Total validators in registry: {}",
                registry.validators.len()
            );
            validator_log!(
                "🔍 [get_active_validators] Min stake amount: {}",
                registry.min_stake_amount
            );
            let active_validators: Vec<Validator> = registry.validators.values()
                .filter(|v| {
                    let is_active = v.status == ValidatorStatus::Active;
                    let is_eligible = v.is_eligible(registry.min_stake_amount);
                    validator_log!("🔍 [get_active_validators] Validator {}: Active={}, Eligible={}, Stake={}, Score={}, Uptime={}",
                        v.address, is_active, is_eligible, v.stake_amount, v.synergy_score, v.uptime_percentage);
                    is_active && is_eligible
                })
                .cloned()
                .collect();
            validator_log!(
                "🔍 [get_active_validators] Returning {} active validators",
                active_validators.len()
            );
            active_validators
        } else {
            validator_log!("⚠️ [get_active_validators] Failed to acquire registry lock!");
            Vec::new()
        }
    }

    pub fn get_all_validators(&self) -> Vec<Validator> {
        if let Ok(registry) = self.registry.lock() {
            registry.validators.values().cloned().collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_validator_count(&self) -> usize {
        if let Ok(registry) = self.registry.lock() {
            registry.validators.len()
        } else {
            0
        }
    }

    pub fn get_cluster_count(&self) -> usize {
        if let Ok(registry) = self.registry.lock() {
            registry.clusters.len()
        } else {
            0
        }
    }

    pub fn reorganize_clusters_for_epoch(&self, epoch: u64) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.reorganize_clusters_for_epoch(epoch);
        }
    }

    pub fn get_total_stake(&self) -> u64 {
        if let Ok(registry) = self.registry.lock() {
            registry
                .validators
                .values()
                .map(|validator| validator.stake_amount)
                .sum()
        } else {
            0
        }
    }

    pub fn slash_validator(&self, address: &str, reason: &str) -> Result<(), String> {
        if let Ok(mut registry) = self.registry.lock() {
            registry.slash_validator(address, reason)
        } else {
            Err("Failed to acquire registry lock".to_string())
        }
    }

    pub fn get_top_validators(&self, count: usize) -> Vec<Validator> {
        if let Ok(registry) = self.registry.lock() {
            registry
                .get_top_validators(count)
                .into_iter()
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn calculate_epoch_rewards(&self, epoch: u64) -> HashMap<String, u64> {
        if let Ok(registry) = self.registry.lock() {
            registry.calculate_epoch_rewards(epoch)
        } else {
            HashMap::new()
        }
    }

    pub fn save_registry(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        if let Ok(registry) = self.registry.lock() {
            let resolved = crate::utils::resolve_data_path(path);
            registry.save_to_file(resolved)
        } else {
            Err("Failed to acquire registry lock".into())
        }
    }

    pub fn load_registry(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let resolved = crate::utils::resolve_data_path(path);
        let registry = ValidatorRegistry::load_from_file(resolved)?;
        if let Ok(mut current_registry) = self.registry.lock() {
            *current_registry = registry;
        }
        Ok(())
    }

    pub fn is_pending(&self, address: &str) -> bool {
        if let Ok(registry) = self.registry.lock() {
            registry.pending_registrations.contains_key(address)
        } else {
            false
        }
    }
}

// Global validator manager instance
lazy_static::lazy_static! {
    pub static ref VALIDATOR_MANAGER: Arc<ValidatorManager> = Arc::new(ValidatorManager::new());
}

fn configured_max_validators(active_validators: &[Validator]) -> usize {
    let config = crate::config::load_node_config(None).ok();
    config
        .as_ref()
        .map(|config| config.consensus.max_validators.max(active_validators.len()))
        .unwrap_or(usize::MAX)
}

fn epoch_validator_sets_path() -> Result<Option<PathBuf>, String> {
    if let Ok(value) = std::env::var(EPOCH_VALIDATOR_SETS_ENV) {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let path = PathBuf::from(trimmed);
        if !path.is_file() {
            return Err(format!(
                "epoch validator set file {} does not exist",
                path.display()
            ));
        }
        return Ok(Some(path));
    }

    let path = std::env::var("SYNERGY_PROJECT_ROOT")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| PathBuf::from(value).join(DEFAULT_EPOCH_VALIDATOR_SETS_PATH))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_EPOCH_VALIDATOR_SETS_PATH));
    if path.is_file() {
        Ok(Some(path))
    } else {
        Ok(None)
    }
}

fn load_epoch_validator_sets() -> Result<Vec<EpochValidatorSetSnapshot>, String> {
    let Some(path) = epoch_validator_sets_path()? else {
        return Ok(Vec::new());
    };
    let raw = fs::read_to_string(&path)
        .map_err(|error| format!("read epoch validator set file {}: {error}", path.display()))?;
    let document: EpochValidatorSetDocument = serde_json::from_str(&raw)
        .map_err(|error| format!("parse epoch validator set file {}: {error}", path.display()))?;
    let mut sets = match document {
        EpochValidatorSetDocument::List(sets) => sets,
        EpochValidatorSetDocument::Wrapped {
            epoch_validator_sets,
        } => epoch_validator_sets,
    };
    sets.sort_by(|left, right| {
        right
            .effective_from_height
            .cmp(&left.effective_from_height)
            .then_with(|| right.validator_set_version.cmp(&left.validator_set_version))
    });
    Ok(sets)
}

fn epoch_validator_set_for_height(
    height: u64,
) -> Result<Option<EpochValidatorSetSnapshot>, String> {
    for set in load_epoch_validator_sets()? {
        if set.applies_to_height(height) {
            return Ok(Some(set));
        }
    }
    Ok(None)
}

fn epoch_validator_addresses_for_height(height: u64) -> Result<Option<Vec<String>>, String> {
    let Some(set) = epoch_validator_set_for_height(height)? else {
        return Ok(None);
    };
    set.validate_local_compatibility()?;
    set.active_validator_addresses().map(Some)
}

pub fn epoch_validator_set_hash_for_height(height: u64) -> Result<Option<String>, String> {
    Ok(epoch_validator_set_for_height(height)?
        .and_then(|set| normalized_optional_string(set.validator_set_hash.as_deref())))
}

pub fn epoch_validator_set_compatibility_for_height(
    height: u64,
) -> Result<Option<EpochValidatorSetCompatibility>, String> {
    Ok(
        epoch_validator_set_for_height(height)?.map(|set| EpochValidatorSetCompatibility {
            snapshot_format_version: set.snapshot_format_version,
            supported_snapshot_format_version: SUPPORTED_EPOCH_VALIDATOR_SET_FORMAT_VERSION,
            required_protocol_version: normalized_optional_string(
                set.required_protocol_version.as_deref(),
            ),
            local_protocol_version: local_epoch_validator_set_protocol_version(),
            required_binary_version: normalized_optional_string(
                set.required_binary_version.as_deref(),
            ),
            local_binary_version: env!("CARGO_PKG_VERSION").to_string(),
            validator_set_hash: normalized_optional_string(set.validator_set_hash.as_deref()),
        }),
    )
}

pub fn assert_epoch_validator_set_compatible_for_height(height: u64) -> Result<(), String> {
    let Some(set) = epoch_validator_set_for_height(height)? else {
        return Ok(());
    };
    set.validate_local_compatibility()
}

fn current_configured_consensus_order(
    active_validators: &[Validator],
) -> (Option<Vec<String>>, usize) {
    let max_validators = configured_max_validators(active_validators);
    let active_addresses = active_validators
        .iter()
        .map(|validator| validator.address.clone())
        .collect::<HashSet<_>>();

    if let Ok(Some(migration)) = consensus_fork::active_consensus_fork_migration() {
        let mut ordered = migration
            .new_validator_registry
            .iter()
            .map(|entry| entry.validator_address.clone())
            .filter(|address| active_addresses.contains(address))
            .collect::<Vec<_>>();
        ordered.truncate(max_validators);
        if !ordered.is_empty() {
            return (Some(ordered), max_validators);
        }
    }

    if let Ok(genesis) = canonical_genesis() {
        let genesis_addresses = genesis
            .validators()
            .iter()
            .map(|entry| entry.operator_address.clone())
            .collect::<HashSet<_>>();
        let mut ordered = genesis
            .validators()
            .iter()
            .map(|entry| entry.operator_address.clone())
            .filter(|address| active_addresses.contains(address))
            .collect::<Vec<_>>();
        let mut added_validators = active_validators
            .iter()
            .map(|validator| validator.address.clone())
            .filter(|address| !genesis_addresses.contains(address))
            .collect::<Vec<_>>();
        added_validators.sort();
        ordered.extend(added_validators);
        if !ordered.is_empty() {
            ordered.truncate(max_validators);
            return (Some(ordered), max_validators);
        }
    }

    (None, max_validators)
}

fn validators_for_authoritative_order(
    active_validators: Vec<Validator>,
    ordered_addresses: Vec<String>,
    max_validators: usize,
) -> Result<Vec<Validator>, String> {
    let validators_by_address = active_validators
        .into_iter()
        .map(|validator| (validator.address.clone(), validator))
        .collect::<HashMap<_, _>>();
    let mut validators = Vec::with_capacity(ordered_addresses.len());
    for address in ordered_addresses.into_iter().take(max_validators) {
        let Some(validator) = validators_by_address.get(&address) else {
            return Err(format!(
                "authoritative validator set references validator {address} missing from local registry"
            ));
        };
        validators.push(validator.clone());
    }
    Ok(validators)
}

pub fn is_validator_activation_transaction(tx: &Transaction) -> bool {
    tx.data
        .as_deref()
        .map(|data| data.starts_with("validator_activation:"))
        .unwrap_or(false)
}

fn parse_validator_activation(tx: &Transaction) -> Result<(String, String, String, u64), String> {
    let payload = tx
        .data
        .as_deref()
        .and_then(|data| data.strip_prefix("validator_activation:"))
        .ok_or_else(|| "Transaction is not a validator activation transaction.".to_string())?;
    let value = serde_json::from_str::<serde_json::Value>(payload)
        .map_err(|error| format!("Invalid validator activation payload: {error}"))?;
    let validator = value
        .get("validator")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Validator activation is missing validator address.".to_string())?
        .to_string();
    let public_key = value
        .get("public_key")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Validator activation is missing public key.".to_string())?
        .to_string();
    let name = value
        .get("name")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Activated Validator")
        .to_string();
    let stake_amount = value
        .get("stake_amount_nwei")
        .and_then(|value| value.as_u64())
        .or_else(|| value.get("stake_amount").and_then(|value| value.as_u64()))
        .ok_or_else(|| "Validator activation is missing stake amount.".to_string())?;

    if tx.sender != validator || tx.receiver != validator {
        return Err(
            "Validator activation must be self-signed by the validator address.".to_string(),
        );
    }

    Ok((validator, public_key, name, stake_amount))
}

pub fn apply_validator_activation_transaction(
    tx: &Transaction,
    token_manager: &TokenManager,
    validator_manager: &Arc<ValidatorManager>,
    block_height: u64,
) -> Result<String, String> {
    let (validator, public_key, name, _stake_amount) = parse_validator_activation(tx)?;
    let minimum_stake = validator_manager
        .minimum_stake_amount()
        .max(canonical_minimum_validator_stake_nwei());
    let bonded_stake = token_manager.get_staked_balance(&validator, "SNRG");
    if bonded_stake < minimum_stake {
        return Err(format!(
            "Validator {validator} has {bonded_stake} nWei bonded; {minimum_stake} nWei is required for activation."
        ));
    }

    if let Some(existing) = validator_manager.get_validator(&validator) {
        validator_manager.update_validator_stake(&validator, bonded_stake);
        let existing_status = existing.status.clone();
        match existing_status.clone() {
            ValidatorStatus::Active => {
                return Ok(format!(
                    "Validator {validator} already active; stake refreshed."
                ));
            }
            ValidatorStatus::Shadow => {
                return Ok(format!(
                    "Validator {validator} already shadowing; stake refreshed."
                ));
            }
            ValidatorStatus::Inactive | ValidatorStatus::Pending => {
                validator_manager.restart_shadow_activation_for_existing(
                    &validator,
                    public_key,
                    name,
                    bonded_stake,
                    tx.hash(),
                    block_height,
                )?;
                return Ok(format!(
                    "Validator {validator} re-entered shadow activation from existing {:?} registry state.",
                    existing_status
                ));
            }
            ValidatorStatus::Jailed | ValidatorStatus::Slashed => {
                return Err(format!(
                    "Validator {validator} is {:?}; activation replay will not revive disciplined validators.",
                    existing_status
                ));
            }
        }
    }

    let registration = ValidatorRegistration {
        address: validator.clone(),
        public_key,
        name,
        stake_amount: bonded_stake,
        submitted_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        registration_tx_hash: tx.hash(),
    };

    match validator_manager.register_validator(registration) {
        Ok(_) => {
            validator_manager.start_shadow_activation(&validator, block_height)?;
            Ok(format!(
                "Validator {validator} entered 1000-block shadow activation window."
            ))
        }
        Err(error) if error == "Registration already pending" => {
            validator_manager.start_shadow_activation(&validator, block_height)?;
            validator_manager.update_validator_stake(&validator, bonded_stake);
            Ok(format!(
                "Validator {validator} pending activation entered shadow window."
            ))
        }
        Err(error) => Err(error),
    }
}

pub fn replay_validator_activation_transactions(
    chain: &crate::block::BlockChain,
    token_manager: &TokenManager,
    validator_manager: &Arc<ValidatorManager>,
) -> (u64, u64) {
    let mut applied = 0u64;
    let mut failed = 0u64;

    for block in &chain.chain {
        for tx in &block.transactions {
            if !is_validator_activation_transaction(tx) {
                continue;
            }

            match apply_validator_activation_transaction(
                tx,
                token_manager,
                validator_manager,
                block.block_index,
            ) {
                Ok(_) => applied += 1,
                Err(_) => failed += 1,
            }
        }
        let _ = validator_manager.apply_pending_shadow_activations(block.block_index);
    }

    (applied, failed)
}

fn canonical_minimum_validator_stake_nwei() -> u64 {
    canonical_genesis()
        .ok()
        .and_then(|genesis| {
            genesis
                .validators()
                .iter()
                .map(|validator| validator.stake_nwei)
                .min()
        })
        .unwrap_or(TESTNET_MIN_VALIDATOR_STAKE_NWEI)
}

pub fn consensus_membership_validators(active_validators: Vec<Validator>) -> Vec<Validator> {
    let (configured_order, max_validators) = current_configured_consensus_order(&active_validators);
    if let Some(ordered_addresses) = configured_order {
        let validators_by_address = active_validators
            .into_iter()
            .map(|validator| (validator.address.clone(), validator))
            .collect::<HashMap<_, _>>();
        return ordered_addresses
            .into_iter()
            .filter_map(|address| validators_by_address.get(&address).cloned())
            .collect();
    }

    let mut fallback_validators = active_validators;
    fallback_validators.sort_by(|left, right| left.address.cmp(&right.address));
    fallback_validators.truncate(max_validators);
    fallback_validators
}

pub fn consensus_membership_validators_for_height(
    validators: Vec<Validator>,
    height: u64,
) -> Result<Vec<Validator>, String> {
    let max_validators = configured_max_validators(&validators);
    if let Some(ordered_addresses) = epoch_validator_addresses_for_height(height)? {
        return validators_for_authoritative_order(validators, ordered_addresses, max_validators);
    }

    if let Some(migration) = consensus_fork::active_consensus_fork_migration()? {
        if migration.applies_to_height(height) {
            let ordered_addresses = migration
                .new_validator_registry
                .iter()
                .map(|entry| entry.validator_address.clone())
                .collect::<Vec<_>>();
            return validators_for_authoritative_order(
                validators,
                ordered_addresses,
                max_validators,
            );
        }
    }

    if let Ok(genesis) = canonical_genesis() {
        let ordered_addresses = genesis
            .validators()
            .iter()
            .map(|entry| entry.operator_address.clone())
            .collect::<Vec<_>>();
        if !ordered_addresses.is_empty() {
            if let Ok(genesis_validators) = validators_for_authoritative_order(
                validators.clone(),
                ordered_addresses,
                max_validators,
            ) {
                return Ok(genesis_validators);
            }
        }
    }

    Ok(consensus_membership_validators(validators))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{Block, BlockChain};
    use crate::consensus::consensus_fork::{
        self, ConsensusForkMigration, ForkValidatorConsensusKey,
    };
    use base64::{engine::general_purpose, Engine as _};
    use std::sync::{Mutex, MutexGuard};

    static VALIDATOR_TEST_ENV_LOCK: Mutex<()> = Mutex::new(());

    fn validator_test_env_lock() -> MutexGuard<'static, ()> {
        VALIDATOR_TEST_ENV_LOCK
            .lock()
            .expect("validator test env mutex should lock")
    }

    fn pending_registration(index: usize) -> ValidatorRegistration {
        ValidatorRegistration {
            address: format!("validator-{}", index),
            public_key: format!("validator-key-{}", index),
            name: format!("Validator {}", index),
            stake_amount: 1_000,
            submitted_at: 0,
            registration_tx_hash: format!("registration-{}", index),
        }
    }

    fn active_registry(count: usize) -> ValidatorRegistry {
        let mut registry = ValidatorRegistry::new();
        for index in 0..count {
            let mut validator = Validator::new(
                format!("validator-{}", index),
                format!("validator-key-{}", index),
                format!("Validator {}", index),
                1_000,
            );
            validator.status = ValidatorStatus::Active;
            validator.synergy_score = INITIAL_VALIDATOR_SYNERGY_SCORE - index as f64;
            registry
                .validators
                .insert(validator.address.clone(), validator);
        }
        registry.reorganize_clusters();
        registry
    }

    fn active_validator(address: &str) -> Validator {
        let mut validator = Validator::new(
            address.to_string(),
            format!("public-key-{address}"),
            format!("Validator {address}"),
            TESTNET_MIN_VALIDATOR_STAKE_NWEI,
        );
        validator.status = ValidatorStatus::Active;
        validator
    }

    fn fork_migration_for(addresses: &[&str]) -> ConsensusForkMigration {
        ConsensusForkMigration {
            fork_height: 204_216,
            parent_height: 204_215,
            parent_hash: "parent".to_string(),
            state_root: "state".to_string(),
            old_consensus_algorithm: "FN-DSA".to_string(),
            new_consensus_algorithm: "FN-DSA".to_string(),
            new_validator_registry: addresses
                .iter()
                .enumerate()
                .map(|(index, address)| ForkValidatorConsensusKey {
                    validator_address: (*address).to_string(),
                    consensus_key_type: "FN-DSA".to_string(),
                    consensus_public_key: format!(
                        "fn-dsa:{}",
                        general_purpose::STANDARD.encode([index as u8 + 1, 2, 3, 4])
                    ),
                })
                .collect(),
            migration_reason: "test fork membership authority".to_string(),
            parser_mode: "fail_closed".to_string(),
            migration_signature: None,
        }
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.previous.as_ref() {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn unique_test_dir(slug: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("synergy-{slug}-{unique}"))
    }

    fn write_epoch_validator_sets(path: &Path, sets: serde_json::Value) {
        std::fs::write(
            path,
            serde_json::json!({
                "epoch_validator_sets": sets
            })
            .to_string(),
        )
        .expect("epoch validator set snapshot should be written");
    }

    fn validator_addresses(start: usize, end_inclusive: usize) -> Vec<String> {
        (start..=end_inclusive)
            .map(|index| format!("validator-{index}"))
            .collect()
    }

    fn active_validators_from_addresses(addresses: &[String]) -> Vec<Validator> {
        addresses
            .iter()
            .map(|address| active_validator(address))
            .collect()
    }

    fn membership_addresses(validators: &[Validator]) -> Vec<String> {
        validators
            .iter()
            .map(|validator| validator.address.clone())
            .collect()
    }

    fn funded_test_address(required_nwei: u64) -> String {
        crate::genesis::canonical_genesis()
            .ok()
            .and_then(|genesis| {
                genesis
                    .balances()
                    .iter()
                    .find(|balance| balance.balance_nwei >= required_nwei)
                    .map(|balance| balance.address.clone())
            })
            .unwrap_or_else(|| "synu1nd0fvzfhhj4s0te3ks06csfsnpg2hed8vsmh".to_string())
    }

    fn funded_activation_fixture(
        public_key: &str,
        tx_bytes: Vec<u8>,
    ) -> (crate::token::TokenManager, String, Transaction) {
        let validator_address = crate::address::generate_validator_address(public_key, 1);
        let bonded_stake = TESTNET_MIN_VALIDATOR_STAKE_NWEI;
        let funding_source = funded_test_address(bonded_stake);
        let token_manager = crate::token::TokenManager::new();
        token_manager
            .transfer_tokens(&funding_source, &validator_address, "SNRG", bonded_stake, 0)
            .expect("test stake balance should fund from genesis allocation");
        token_manager
            .stake_tokens(&validator_address, &validator_address, "SNRG", bonded_stake)
            .expect("test validator should bond stake");

        let tx = Transaction::new(
            validator_address.clone(),
            validator_address.clone(),
            0,
            0,
            tx_bytes,
            1,
            21_000,
            Some(format!(
                "validator_activation:{{\"validator\":\"{}\",\"public_key\":\"{}\",\"name\":\"Outside Validator\",\"stake_amount_nwei\":{}}}",
                validator_address, public_key, bonded_stake
            )),
            "fndsa".to_string(),
        );

        (token_manager, validator_address, tx)
    }

    #[test]
    fn validator_manager_resolves_legacy_registry_path_to_runtime_data_root() {
        let _env_lock = validator_test_env_lock();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("synergy-validator-registry-{unique}"));
        let state_dir = temp_dir.join("state-store");
        let legacy_dir = temp_dir.join("data");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::create_dir_all(&legacy_dir).unwrap();

        let stale_registry = active_registry(5);
        std::fs::write(
            legacy_dir.join("validator_registry.json"),
            serde_json::to_string_pretty(&stale_registry).unwrap(),
        )
        .unwrap();

        let restored_registry = active_registry(6);
        std::fs::write(
            state_dir.join("validator_registry.json"),
            serde_json::to_string_pretty(&restored_registry).unwrap(),
        )
        .unwrap();

        let _data_path = EnvVarGuard::set("SYNERGY_DATA_PATH", &state_dir.to_string_lossy());
        let manager = ValidatorManager::new();
        manager
            .load_registry("data/validator_registry.json")
            .expect("legacy registry path should resolve to SYNERGY_DATA_PATH");

        assert_eq!(
            manager.get_active_validators().len(),
            6,
            "runtime validator registry must load the restored snapshot registry, not stale workspace/data"
        );

        manager
            .save_registry("data/validator_registry.json")
            .expect("legacy registry save should resolve to SYNERGY_DATA_PATH");
        let saved = ValidatorRegistry::load_from_file(state_dir.join("validator_registry.json"))
            .expect("saved runtime registry should be readable");
        assert_eq!(saved.get_active_validators().len(), 6);

        std::fs::remove_dir_all(temp_dir).ok();
    }

    #[test]
    fn approved_validators_start_at_full_synergy_score() {
        let mut registry = ValidatorRegistry::new();
        let registration = pending_registration(1);
        let address = registration.address.clone();

        registry
            .register_validator(registration)
            .expect("validator registration should be accepted");
        registry
            .approve_registration(&address)
            .expect("pending validator should be approved");

        let validator = registry
            .get_validator_by_address(&address)
            .expect("approved validator should exist");
        assert_eq!(validator.status, ValidatorStatus::Active);
        assert_eq!(validator.synergy_score, INITIAL_VALIDATOR_SYNERGY_SCORE);
        assert_eq!(validator.uptime_percentage, 100.0);
    }

    #[test]
    fn consensus_eligibility_ignores_local_soft_scores() {
        let mut validator = Validator::new(
            "validator-soft-scores".to_string(),
            "validator-soft-scores-key".to_string(),
            "Validator Soft Scores".to_string(),
            1_000,
        );
        validator.status = ValidatorStatus::Active;
        validator.synergy_score = 0.0;
        validator.uptime_percentage = 0.0;
        validator.task_accuracy = 0.0;
        validator.reputation_score = 0.0;

        assert!(
            validator.is_eligible(1_000),
            "local health metrics must not remove a validator from the shared active set"
        );

        validator.status = ValidatorStatus::Jailed;
        assert!(!validator.is_eligible(1_000));
        validator.status = ValidatorStatus::Active;
        assert!(!validator.is_eligible(1_001));
    }

    #[test]
    fn activated_validator_expands_consensus_membership_when_allowlist_disabled() {
        let _env_lock = validator_test_env_lock();
        let previous_strict = std::env::var("SYNERGY_STRICT_VALIDATOR_ALLOWLIST").ok();
        std::env::set_var("SYNERGY_STRICT_VALIDATOR_ALLOWLIST", "0");

        let genesis = crate::genesis::canonical_genesis().expect("canonical genesis should load");
        let mut active_validators = genesis
            .validators()
            .iter()
            .map(|entry| {
                let mut validator = Validator::new(
                    entry.operator_address.clone(),
                    entry.consensus_public_key.clone(),
                    entry.moniker.clone(),
                    entry.stake_nwei,
                );
                validator.status = ValidatorStatus::Active;
                validator.activation_tx_hash = Some("genesis".to_string());
                validator
            })
            .collect::<Vec<_>>();
        let mut activated = Validator::new(
            "synv11wsfus6ghzgjvm4glpatuy8tnyacrwealyjv".to_string(),
            "fndsa:test-public-key".to_string(),
            "Local Validator v14 onboarding test".to_string(),
            TESTNET_MIN_VALIDATOR_STAKE_NWEI,
        );
        activated.status = ValidatorStatus::Active;
        activated.activation_tx_hash = Some("syntxn-onboarding-test".to_string());
        active_validators.push(activated);

        let membership = consensus_membership_validators(active_validators);
        let membership_addresses = membership
            .iter()
            .map(|validator| validator.address.as_str())
            .collect::<Vec<_>>();

        match previous_strict {
            Some(value) => std::env::set_var("SYNERGY_STRICT_VALIDATOR_ALLOWLIST", value),
            None => std::env::remove_var("SYNERGY_STRICT_VALIDATOR_ALLOWLIST"),
        }

        assert_eq!(membership.len(), genesis.validators().len() + 1);
        assert_eq!(
            membership_addresses.last().copied(),
            Some("synv11wsfus6ghzgjvm4glpatuy8tnyacrwealyjv")
        );
    }

    #[test]
    fn consensus_membership_does_not_truncate_active_validators_with_stale_max_config() {
        let _env_lock = validator_test_env_lock();
        let active = active_registry(6)
            .validators
            .into_values()
            .collect::<Vec<_>>();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("synergy-validator-max-test-{unique}"));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let config_path = temp_dir.join("node.toml");
        let mut config = crate::config::NodeConfig::default();
        config.consensus.max_validators = 3;
        std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        let _config_path = EnvVarGuard::set("SYNERGY_CONFIG_PATH", &config_path.to_string_lossy());

        let membership = consensus_membership_validators(active);

        assert_eq!(membership.len(), 6);
    }

    #[test]
    fn consensus_membership_ignores_stale_strict_allowlist_config() {
        let _env_lock = validator_test_env_lock();
        let active = active_registry(6)
            .validators
            .into_values()
            .collect::<Vec<_>>();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir =
            std::env::temp_dir().join(format!("synergy-validator-allowlist-test-{unique}"));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let config_path = temp_dir.join("node.toml");
        let mut config = crate::config::NodeConfig::default();
        config.node.strict_validator_allowlist = true;
        config.node.allowed_validator_addresses = vec![
            "validator-0".to_string(),
            "validator-1".to_string(),
            "validator-2".to_string(),
        ];
        std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        let _config_path = EnvVarGuard::set("SYNERGY_CONFIG_PATH", &config_path.to_string_lossy());

        let membership = consensus_membership_validators(active);

        std::fs::remove_dir_all(temp_dir).ok();
        assert_eq!(membership.len(), 6);
    }

    #[test]
    fn epoch_validator_set_for_height_overrides_current_registry_membership() {
        let _env_lock = validator_test_env_lock();
        let active = (1..=7)
            .map(|index| active_validator(&format!("validator-{index}")))
            .collect::<Vec<_>>();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("synergy-epoch-validator-set-{unique}"));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let snapshot_path = temp_dir.join("epoch-validator-sets.json");
        std::fs::write(
            &snapshot_path,
            serde_json::json!({
                "epoch_validator_sets": [{
                    "chain_id": 1264,
                    "epoch_id": 7,
                    "validator_set_version": 3,
                    "effective_from_height": 100,
                    "effective_to_height": 199,
                    "active_validators": [
                        "validator-1",
                        "validator-2",
                        "validator-3",
                        "validator-4",
                        "validator-5",
                        "validator-6"
                    ],
                    "pending_validators": ["validator-7"],
                    "quorum_threshold": 4,
                    "validator_set_hash": "test-epoch-set-hash"
                }]
            })
            .to_string(),
        )
        .unwrap();
        let _snapshot_path =
            EnvVarGuard::set(EPOCH_VALIDATOR_SETS_ENV, &snapshot_path.to_string_lossy());

        let historical = consensus_membership_validators_for_height(active.clone(), 150)
            .expect("historical epoch validator set should resolve");
        let historical_addresses = historical
            .iter()
            .map(|validator| validator.address.as_str())
            .collect::<Vec<_>>();

        std::fs::remove_dir_all(temp_dir).ok();
        assert_eq!(
            historical_addresses,
            vec![
                "validator-1",
                "validator-2",
                "validator-3",
                "validator-4",
                "validator-5",
                "validator-6"
            ]
        );
        assert!(!historical_addresses.contains(&"validator-7"));
    }

    #[test]
    fn unsupported_epoch_validator_set_format_blocks_consensus_membership() {
        let _env_lock = validator_test_env_lock();
        let active = active_validators_from_addresses(&validator_addresses(1, 6));
        let temp_dir = unique_test_dir("epoch-unsupported-format");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let snapshot_path = temp_dir.join("epoch-validator-sets.json");
        write_epoch_validator_sets(
            &snapshot_path,
            serde_json::json!([{
                "snapshot_format_version": SUPPORTED_EPOCH_VALIDATOR_SET_FORMAT_VERSION + 1,
                "chain_id": 1264,
                "epoch_id": 7,
                "validator_set_version": 3,
                "effective_from_height": 100,
                "active_validators": validator_addresses(1, 6),
                "quorum_threshold": 4,
                "validator_set_hash": "future-format-set"
            }]),
        );
        let _snapshot_path =
            EnvVarGuard::set(EPOCH_VALIDATOR_SETS_ENV, &snapshot_path.to_string_lossy());

        let error = consensus_membership_validators_for_height(active, 150)
            .expect_err("future snapshot format must fail closed");

        std::fs::remove_dir_all(temp_dir).ok();
        assert!(
            error.contains("newer than supported version"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn incompatible_epoch_validator_set_binary_version_blocks_consensus_membership() {
        let _env_lock = validator_test_env_lock();
        let active = active_validators_from_addresses(&validator_addresses(1, 6));
        let temp_dir = unique_test_dir("epoch-wrong-binary");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let snapshot_path = temp_dir.join("epoch-validator-sets.json");
        write_epoch_validator_sets(
            &snapshot_path,
            serde_json::json!([{
                "snapshot_format_version": SUPPORTED_EPOCH_VALIDATOR_SET_FORMAT_VERSION,
                "chain_id": 1264,
                "epoch_id": 7,
                "validator_set_version": 3,
                "effective_from_height": 100,
                "active_validators": validator_addresses(1, 6),
                "quorum_threshold": 4,
                "validator_set_hash": "wrong-binary-set",
                "required_binary_version": "0.0.0-incompatible"
            }]),
        );
        let _snapshot_path =
            EnvVarGuard::set(EPOCH_VALIDATOR_SETS_ENV, &snapshot_path.to_string_lossy());

        let error = consensus_membership_validators_for_height(active, 150)
            .expect_err("wrong binary version must fail closed");
        let compatibility = epoch_validator_set_compatibility_for_height(150)
            .expect("compatibility diagnostics should load")
            .expect("height should have an epoch validator set");

        std::fs::remove_dir_all(temp_dir).ok();
        assert!(
            error.contains("requires binary version 0.0.0-incompatible"),
            "unexpected error: {error}"
        );
        assert_eq!(
            compatibility.validator_set_hash.as_deref(),
            Some("wrong-binary-set")
        );
        assert_eq!(
            compatibility.local_binary_version,
            env!("CARGO_PKG_VERSION")
        );
    }

    #[test]
    fn epoch_validator_set_ignores_config_peers_vpn_and_registry_drift() {
        let _env_lock = validator_test_env_lock();
        let all_addresses = validator_addresses(1, 7);
        let active = active_validators_from_addresses(&all_addresses);
        let temp_dir = unique_test_dir("epoch-drift-sources");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let config_path = temp_dir.join("node.toml");
        let peers_path = temp_dir.join("peers.toml");
        let snapshot_path = temp_dir.join("epoch-validator-sets.json");

        let mut config = crate::config::NodeConfig::default();
        config.node.strict_validator_allowlist = true;
        config.node.allowed_validator_addresses = all_addresses.clone();
        config.network.persistent_peers = vec!["validator-7".to_string()];
        config.network.validator_vpn_transports =
            vec![crate::config::ValidatorVpnTransportConfig {
                validator_address: "validator-7".to_string(),
                dial_address: "10.69.10.7:5622".to_string(),
            }];
        std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        std::fs::write(
            &peers_path,
            r#"
[global]
persistent_peers = ["validator-7", "10.69.10.7:5622"]
additional_dial_targets = ["validator-7", "10.69.10.7:5622"]
"#,
        )
        .unwrap();
        write_epoch_validator_sets(
            &snapshot_path,
            serde_json::json!([{
                "chain_id": 1264,
                "epoch_id": 7,
                "validator_set_version": 3,
                "effective_from_height": 100,
                "effective_to_height": 199,
                "active_validators": validator_addresses(1, 6),
                "pending_validators": ["validator-7"],
                "quorum_threshold": 4,
                "validator_set_hash": "six-validator-set"
            }]),
        );

        let _config_path = EnvVarGuard::set("SYNERGY_CONFIG_PATH", &config_path.to_string_lossy());
        let _snapshot_path =
            EnvVarGuard::set(EPOCH_VALIDATOR_SETS_ENV, &snapshot_path.to_string_lossy());

        let loaded_config =
            crate::config::load_node_config(None).expect("test config should load with peers.toml");
        assert!(loaded_config
            .node
            .allowed_validator_addresses
            .contains(&"validator-7".to_string()));
        assert!(loaded_config
            .network
            .persistent_peers
            .contains(&"10.69.10.7:5622".to_string()));
        assert!(loaded_config
            .network
            .validator_vpn_transports
            .iter()
            .any(|transport| transport.validator_address == "validator-7"));

        let membership = consensus_membership_validators_for_height(active, 150)
            .expect("epoch validator set should resolve despite drift sources");
        let addresses = membership_addresses(&membership);

        std::fs::remove_dir_all(temp_dir).ok();
        assert_eq!(addresses, validator_addresses(1, 6));
        assert!(!addresses.contains(&"validator-7".to_string()));
        assert_eq!(
            crate::consensus::dual_quorum::required_validator_quorum(membership.len()),
            4,
            "peer/config/VPN drift must not inflate quorum beyond the EpochValidatorSet"
        );
    }

    #[test]
    fn epoch_validator_set_keeps_added_validator_pending_until_boundary() {
        let _env_lock = validator_test_env_lock();
        let all_addresses = validator_addresses(1, 7);
        let active = active_validators_from_addresses(&all_addresses);
        let temp_dir = unique_test_dir("epoch-pending-boundary");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let snapshot_path = temp_dir.join("epoch-validator-sets.json");
        write_epoch_validator_sets(
            &snapshot_path,
            serde_json::json!([
                {
                    "chain_id": 1264,
                    "epoch_id": 7,
                    "validator_set_version": 3,
                    "effective_from_height": 100,
                    "effective_to_height": 199,
                    "active_validators": validator_addresses(1, 6),
                    "pending_validators": ["validator-7"],
                    "quorum_threshold": 4,
                    "validator_set_hash": "six-validator-set"
                },
                {
                    "chain_id": 1264,
                    "epoch_id": 8,
                    "validator_set_version": 4,
                    "effective_from_height": 200,
                    "active_validators": all_addresses,
                    "pending_validators": [],
                    "quorum_threshold": 5,
                    "previous_set_hash": "six-validator-set",
                    "validator_set_hash": "seven-validator-set"
                }
            ]),
        );
        let _snapshot_path =
            EnvVarGuard::set(EPOCH_VALIDATOR_SETS_ENV, &snapshot_path.to_string_lossy());

        let before_boundary = consensus_membership_validators_for_height(active.clone(), 199)
            .expect("pre-boundary epoch set should resolve");
        let at_boundary = consensus_membership_validators_for_height(active, 200)
            .expect("boundary epoch set should resolve");

        std::fs::remove_dir_all(temp_dir).ok();
        let before_addresses = membership_addresses(&before_boundary);
        let boundary_addresses = membership_addresses(&at_boundary);
        assert_eq!(before_addresses, validator_addresses(1, 6));
        assert!(!before_addresses.contains(&"validator-7".to_string()));
        assert_eq!(boundary_addresses, validator_addresses(1, 7));
        assert_eq!(
            crate::consensus::dual_quorum::required_validator_quorum(before_boundary.len()),
            4
        );
        assert_eq!(
            crate::consensus::dual_quorum::required_validator_quorum(at_boundary.len()),
            5
        );
    }

    #[test]
    fn jailed_validator_changes_membership_only_through_next_epoch_set() {
        let _env_lock = validator_test_env_lock();
        let all_addresses = validator_addresses(1, 6);
        let active = active_validators_from_addresses(&all_addresses);
        let temp_dir = unique_test_dir("epoch-jail-boundary");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let snapshot_path = temp_dir.join("epoch-validator-sets.json");
        write_epoch_validator_sets(
            &snapshot_path,
            serde_json::json!([
                {
                    "chain_id": 1264,
                    "epoch_id": 7,
                    "validator_set_version": 3,
                    "effective_from_height": 100,
                    "effective_to_height": 199,
                    "active_validators": all_addresses,
                    "jailed_validators": [],
                    "quorum_threshold": 4,
                    "validator_set_hash": "six-validator-set"
                },
                {
                    "chain_id": 1264,
                    "epoch_id": 8,
                    "validator_set_version": 4,
                    "effective_from_height": 200,
                    "active_validators": validator_addresses(1, 5),
                    "jailed_validators": ["validator-6"],
                    "quorum_threshold": 4,
                    "previous_set_hash": "six-validator-set",
                    "validator_set_hash": "jailed-validator-set"
                }
            ]),
        );
        let _snapshot_path =
            EnvVarGuard::set(EPOCH_VALIDATOR_SETS_ENV, &snapshot_path.to_string_lossy());

        let before_boundary = consensus_membership_validators_for_height(active.clone(), 199)
            .expect("pre-jail epoch set should resolve");
        let at_boundary = consensus_membership_validators_for_height(active, 200)
            .expect("post-jail epoch set should resolve");

        std::fs::remove_dir_all(temp_dir).ok();
        let before_addresses = membership_addresses(&before_boundary);
        let boundary_addresses = membership_addresses(&at_boundary);
        assert_eq!(before_addresses, validator_addresses(1, 6));
        assert!(before_addresses.contains(&"validator-6".to_string()));
        assert_eq!(boundary_addresses, validator_addresses(1, 5));
        assert!(!boundary_addresses.contains(&"validator-6".to_string()));
    }

    #[test]
    fn consensus_membership_prefers_active_fork_and_defers_non_fork_validator() {
        let _env_lock = validator_test_env_lock();
        let canonical = [
            "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs",
            "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt",
            "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re",
            "synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5",
            "synv11kguave5fpdpm9hru4acfvw0hcp4fcc7zv9f",
            "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx",
        ];
        let _fork_guard = consensus_fork::set_test_active_consensus_fork_migration(
            fork_migration_for(&canonical),
        );
        let mut active = canonical
            .iter()
            .map(|address| active_validator(address))
            .collect::<Vec<_>>();
        active.push(active_validator(
            "synv11wsfus6ghzgjvm4glpatuy8tnyacrwealyjv",
        ));

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("synergy-validator-fork-test-{unique}"));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let config_path = temp_dir.join("node.toml");
        let mut config = crate::config::NodeConfig::default();
        config.node.strict_validator_allowlist = true;
        config.node.allowed_validator_addresses = canonical[..4]
            .iter()
            .map(|address| (*address).to_string())
            .collect();
        std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        let _config_path = EnvVarGuard::set("SYNERGY_CONFIG_PATH", &config_path.to_string_lossy());

        let membership = consensus_membership_validators(active);
        let membership_addresses = membership
            .iter()
            .map(|validator| validator.address.as_str())
            .collect::<Vec<_>>();

        std::fs::remove_dir_all(temp_dir).ok();
        assert_eq!(membership_addresses, canonical);
        assert!(!membership_addresses.contains(&"synv11wsfus6ghzgjvm4glpatuy8tnyacrwealyjv"));
    }

    #[test]
    fn reorganize_clusters_keeps_six_validators_in_one_cluster() {
        let registry = active_registry(6);
        let mut cluster_sizes: Vec<usize> = registry
            .clusters
            .values()
            .map(|cluster| cluster.validators.len())
            .collect();
        cluster_sizes.sort_unstable();

        assert_eq!(registry.clusters.len(), 1);
        assert_eq!(cluster_sizes, vec![6]);
    }

    #[test]
    fn reorganize_clusters_stores_syngrp_address_on_validators() {
        let registry = active_registry(5);
        let validator = registry
            .get_validator_by_address("validator-0")
            .expect("validator should exist");

        assert_eq!(validator.cluster_id, Some(0));
        assert!(validator
            .cluster_address
            .as_deref()
            .is_some_and(|address| address.starts_with("syngrp1")));
    }

    #[test]
    fn chain_activation_registers_bonded_validator_with_activation_hash() {
        let public_key = "activation-public-key";
        let validator_address = crate::address::generate_validator_address(public_key, 1);
        let bonded_stake = TESTNET_MIN_VALIDATOR_STAKE_NWEI;
        let funding_source = funded_test_address(bonded_stake);
        let token_manager = crate::token::TokenManager::new();
        token_manager
            .transfer_tokens(&funding_source, &validator_address, "SNRG", bonded_stake, 0)
            .expect("test stake balance should fund from genesis allocation");
        token_manager
            .stake_tokens(&validator_address, &validator_address, "SNRG", bonded_stake)
            .expect("test validator should bond stake");

        let validator_manager = Arc::new(ValidatorManager::new());
        let tx = Transaction::new(
            validator_address.clone(),
            validator_address.clone(),
            0,
            0,
            vec![1, 2, 3],
            1,
            21_000,
            Some(format!(
                "validator_activation:{{\"validator\":\"{}\",\"public_key\":\"{}\",\"name\":\"Outside Validator\",\"stake_amount_nwei\":{}}}",
                validator_address, public_key, bonded_stake
            )),
            "fndsa".to_string(),
        );

        let tx_hash = tx.hash();
        apply_validator_activation_transaction(&tx, &token_manager, &validator_manager, 10)
            .expect("bonded validator activation should apply");

        let activated = validator_manager
            .get_validator(&validator_address)
            .expect("validator should be registered after activation transaction");
        assert_eq!(activated.status, ValidatorStatus::Shadow);
        assert_eq!(activated.stake_amount, bonded_stake);
        assert_eq!(
            activated.activation_tx_hash.as_deref(),
            Some(tx_hash.as_str())
        );
        assert_eq!(activated.shadow_started_at_height, Some(10));
        assert_eq!(
            activated.activation_recorded_height,
            Some(10 + VALIDATOR_SHADOW_PHASE_BLOCKS)
        );
        assert_eq!(
            activated.activation_effective_height,
            Some(10 + VALIDATOR_SHADOW_PHASE_BLOCKS + 1)
        );

        assert!(validator_manager
            .apply_pending_shadow_activations(10 + VALIDATOR_SHADOW_PHASE_BLOCKS - 1)
            .is_empty());
        assert!(validator_manager
            .apply_pending_shadow_activations(10 + VALIDATOR_SHADOW_PHASE_BLOCKS)
            .is_empty());
        let recorded = validator_manager
            .get_validator(&validator_address)
            .expect("validator should remain registered at activation record boundary");
        assert_eq!(recorded.status, ValidatorStatus::Shadow);

        let promoted = validator_manager
            .apply_pending_shadow_activations(10 + VALIDATOR_SHADOW_PHASE_BLOCKS + 1);
        assert_eq!(promoted, vec![validator_address.clone()]);
        let active = validator_manager
            .get_validator(&validator_address)
            .expect("validator should be active after activation boundary");
        assert_eq!(active.status, ValidatorStatus::Active);
    }

    #[test]
    fn replay_validator_activations_restores_registry_from_chain() {
        let public_key = "replay-public-key";
        let validator_address = crate::address::generate_validator_address(public_key, 1);
        let bonded_stake = TESTNET_MIN_VALIDATOR_STAKE_NWEI;
        let funding_source = funded_test_address(bonded_stake);
        let token_manager = crate::token::TokenManager::new();
        token_manager
            .transfer_tokens(&funding_source, &validator_address, "SNRG", bonded_stake, 0)
            .expect("test stake balance should fund from genesis allocation");
        token_manager
            .stake_tokens(&validator_address, &validator_address, "SNRG", bonded_stake)
            .expect("test validator should bond stake");

        let activation_tx = Transaction::new(
            validator_address.clone(),
            validator_address.clone(),
            0,
            0,
            vec![4, 5, 6],
            1,
            21_000,
            Some(format!(
                "validator_activation:{{\"validator\":\"{}\",\"public_key\":\"{}\",\"name\":\"Replayed Validator\",\"stake_amount_nwei\":{}}}",
                validator_address, public_key, bonded_stake
            )),
            "fndsa".to_string(),
        );
        let activation_hash = activation_tx.hash();
        let mut chain = BlockChain::new();
        chain.add_block(Block::new_with_timestamp(
            1,
            vec![activation_tx],
            "genesis".to_string(),
            "genesis-validator".to_string(),
            0,
            1,
        ));
        chain.add_block(Block::new_with_timestamp(
            1 + VALIDATOR_SHADOW_PHASE_BLOCKS,
            Vec::new(),
            "activation-record-block".to_string(),
            "genesis-validator".to_string(),
            0,
            2,
        ));
        chain.add_block(Block::new_with_timestamp(
            1 + VALIDATOR_SHADOW_PHASE_BLOCKS + 1,
            Vec::new(),
            "activation-effective-block".to_string(),
            "genesis-validator".to_string(),
            0,
            3,
        ));

        let validator_manager = Arc::new(ValidatorManager::new());
        let (applied, failed) =
            replay_validator_activation_transactions(&chain, &token_manager, &validator_manager);

        assert_eq!(applied, 1);
        assert_eq!(failed, 0);
        let activated = validator_manager
            .get_validator(&validator_address)
            .expect("validator should be restored from replayed activation");
        assert_eq!(activated.status, ValidatorStatus::Active);
        assert_eq!(activated.stake_amount, bonded_stake);
        assert_eq!(
            activated.activation_tx_hash.as_deref(),
            Some(activation_hash.as_str())
        );
        assert_eq!(activated.shadow_started_at_height, Some(1));
    }

    #[test]
    fn replay_validator_activation_restores_existing_inactive_validator() {
        let public_key = "inactive-replay-public-key";
        let (token_manager, validator_address, activation_tx) =
            funded_activation_fixture(public_key, vec![13, 14, 15]);
        let activation_hash = activation_tx.hash();
        let activation_height = 42;
        let recorded_height = activation_height + VALIDATOR_SHADOW_PHASE_BLOCKS;
        let effective_height = recorded_height + 1;
        let validator_manager = Arc::new(ValidatorManager::new());

        {
            let mut registry = validator_manager
                .registry
                .lock()
                .expect("test registry lock should be available");
            let mut inactive = Validator::new(
                validator_address.clone(),
                "stale-public-key".to_string(),
                "Stale Validator".to_string(),
                TESTNET_MIN_VALIDATOR_STAKE_NWEI,
            );
            inactive.status = ValidatorStatus::Inactive;
            inactive.activation_tx_hash = Some("stale-activation".to_string());
            registry
                .validators
                .insert(validator_address.clone(), inactive);
        }

        let mut chain = BlockChain::new();
        chain.add_block(Block::new_with_timestamp(
            activation_height,
            vec![activation_tx],
            "genesis".to_string(),
            "genesis-validator".to_string(),
            0,
            1,
        ));
        chain.add_block(Block::new_with_timestamp(
            recorded_height,
            Vec::new(),
            "activation-record-block".to_string(),
            "genesis-validator".to_string(),
            0,
            2,
        ));
        chain.add_block(Block::new_with_timestamp(
            effective_height,
            Vec::new(),
            "activation-effective-block".to_string(),
            "genesis-validator".to_string(),
            0,
            3,
        ));

        let (applied, failed) =
            replay_validator_activation_transactions(&chain, &token_manager, &validator_manager);

        assert_eq!((applied, failed), (1, 0));
        let restored = validator_manager
            .get_validator(&validator_address)
            .expect("inactive validator should be restored by replayed activation");
        assert_eq!(restored.status, ValidatorStatus::Active);
        assert_eq!(restored.public_key, public_key);
        assert_eq!(restored.name, "Outside Validator");
        assert_eq!(
            restored.activation_tx_hash.as_deref(),
            Some(activation_hash.as_str())
        );
        assert_eq!(restored.shadow_started_at_height, Some(activation_height));
        assert_eq!(restored.activation_recorded_height, Some(recorded_height));
        assert_eq!(restored.activation_effective_height, Some(effective_height));
    }

    #[test]
    fn replay_validator_activation_keeps_shadow_through_recorded_boundary() {
        let public_key = "replay-shadow-public-key";
        let validator_address = crate::address::generate_validator_address(public_key, 1);
        let bonded_stake = TESTNET_MIN_VALIDATOR_STAKE_NWEI;
        let funding_source = funded_test_address(bonded_stake);
        let token_manager = crate::token::TokenManager::new();
        token_manager
            .transfer_tokens(&funding_source, &validator_address, "SNRG", bonded_stake, 0)
            .expect("test stake balance should fund from genesis allocation");
        token_manager
            .stake_tokens(&validator_address, &validator_address, "SNRG", bonded_stake)
            .expect("test validator should bond stake");

        let activation_tx = Transaction::new(
            validator_address.clone(),
            validator_address.clone(),
            0,
            0,
            vec![7, 8, 9],
            1,
            21_000,
            Some(format!(
                "validator_activation:{{\"validator\":\"{}\",\"public_key\":\"{}\",\"name\":\"Recorded Boundary Validator\",\"stake_amount_nwei\":{}}}",
                validator_address, public_key, bonded_stake
            )),
            "fndsa".to_string(),
        );
        let mut chain = BlockChain::new();
        chain.add_block(Block::new_with_timestamp(
            1,
            vec![activation_tx],
            "genesis".to_string(),
            "genesis-validator".to_string(),
            0,
            1,
        ));
        chain.add_block(Block::new_with_timestamp(
            1 + VALIDATOR_SHADOW_PHASE_BLOCKS,
            Vec::new(),
            "activation-record-block".to_string(),
            "genesis-validator".to_string(),
            0,
            2,
        ));

        let validator_manager = Arc::new(ValidatorManager::new());
        let (applied, failed) =
            replay_validator_activation_transactions(&chain, &token_manager, &validator_manager);

        assert_eq!(applied, 1);
        assert_eq!(failed, 0);
        let shadow = validator_manager
            .get_validator(&validator_address)
            .expect("validator should be restored from replayed activation");
        assert_eq!(shadow.status, ValidatorStatus::Shadow);
        assert_eq!(
            shadow.activation_recorded_height,
            Some(1 + VALIDATOR_SHADOW_PHASE_BLOCKS)
        );
        assert_eq!(
            shadow.activation_effective_height,
            Some(1 + VALIDATOR_SHADOW_PHASE_BLOCKS + 1)
        );
    }

    #[test]
    fn repeated_activation_application_is_idempotent_and_restart_safe() {
        let (token_manager, validator_address, activation_tx) =
            funded_activation_fixture("idempotent-activation-public-key", vec![10, 11, 12]);
        let activation_hash = activation_tx.hash();
        let activation_height = 25;
        let recorded_height = activation_height + VALIDATOR_SHADOW_PHASE_BLOCKS;
        let effective_height = recorded_height + 1;
        let validator_manager = Arc::new(ValidatorManager::new());

        apply_validator_activation_transaction(
            &activation_tx,
            &token_manager,
            &validator_manager,
            activation_height,
        )
        .expect("first activation should enter shadow");
        apply_validator_activation_transaction(
            &activation_tx,
            &token_manager,
            &validator_manager,
            activation_height,
        )
        .expect("duplicate activation should be idempotent while shadowing");

        let shadow = validator_manager
            .get_validator(&validator_address)
            .expect("validator should remain registered after duplicate activation");
        assert_eq!(shadow.status, ValidatorStatus::Shadow);
        assert_eq!(
            shadow.activation_tx_hash.as_deref(),
            Some(activation_hash.as_str())
        );
        assert_eq!(shadow.shadow_started_at_height, Some(activation_height));
        assert_eq!(shadow.activation_recorded_height, Some(recorded_height));
        assert_eq!(shadow.activation_effective_height, Some(effective_height));

        assert!(validator_manager
            .apply_pending_shadow_activations(recorded_height)
            .is_empty());
        assert_eq!(
            validator_manager.apply_pending_shadow_activations(effective_height),
            vec![validator_address.clone()]
        );
        assert!(
            validator_manager
                .apply_pending_shadow_activations(effective_height)
                .is_empty(),
            "activation promotion must be idempotent across repeated boundary processing"
        );

        let mut replay_chain = BlockChain::new();
        replay_chain.add_block(Block::new_with_timestamp(
            activation_height,
            vec![activation_tx],
            "genesis".to_string(),
            "genesis-validator".to_string(),
            0,
            1,
        ));
        replay_chain.add_block(Block::new_with_timestamp(
            recorded_height,
            Vec::new(),
            "activation-record-block".to_string(),
            "genesis-validator".to_string(),
            0,
            2,
        ));
        replay_chain.add_block(Block::new_with_timestamp(
            effective_height,
            Vec::new(),
            "activation-effective-block".to_string(),
            "genesis-validator".to_string(),
            0,
            3,
        ));

        let restarted_manager = Arc::new(ValidatorManager::new());
        let (applied, failed) = replay_validator_activation_transactions(
            &replay_chain,
            &token_manager,
            &restarted_manager,
        );
        assert_eq!((applied, failed), (1, 0));
        let restarted = restarted_manager
            .get_validator(&validator_address)
            .expect("restart replay should restore activated validator");
        assert_eq!(restarted.status, ValidatorStatus::Active);
        assert_eq!(
            restarted.activation_tx_hash.as_deref(),
            Some(activation_hash.as_str())
        );

        let (applied_again, failed_again) = replay_validator_activation_transactions(
            &replay_chain,
            &token_manager,
            &restarted_manager,
        );
        assert_eq!(failed_again, 0);
        assert_eq!(applied_again, 1);
        assert_eq!(
            restarted_manager.get_active_validators().len(),
            1,
            "replaying the same activation chain must not duplicate validators"
        );
    }

    #[test]
    fn multi_validator_shadow_membership_changes_only_at_effective_boundaries() {
        let mut registry = active_registry(5);
        let first = pending_registration(100);
        let first_address = first.address.clone();
        let second = pending_registration(101);
        let second_address = second.address.clone();
        registry
            .register_validator(first)
            .expect("first pending registration should be accepted");
        registry
            .register_validator(second)
            .expect("second pending registration should be accepted");

        registry
            .start_shadow_activation(&first_address, 40)
            .expect("first validator should enter shadow");
        registry
            .start_shadow_activation(&second_address, 41)
            .expect("second validator should enter shadow");

        registry.reorganize_clusters_for_epoch(1);
        let active_before = registry
            .get_active_validators()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(active_before.len(), 5);
        assert!(
            consensus_membership_validators(active_before)
                .iter()
                .all(|validator| validator.address != first_address
                    && validator.address != second_address),
            "shadow validators must not count toward epoch consensus membership"
        );

        let first_recorded = 40 + VALIDATOR_SHADOW_PHASE_BLOCKS;
        let first_effective = first_recorded + 1;
        let second_recorded = 41 + VALIDATOR_SHADOW_PHASE_BLOCKS;
        let second_effective = second_recorded + 1;

        assert!(registry
            .apply_pending_shadow_activations(first_recorded)
            .is_empty());
        assert_eq!(
            registry
                .get_validator_by_address(&first_address)
                .expect("first shadow validator should still exist")
                .status,
            ValidatorStatus::Shadow
        );

        assert_eq!(
            registry.apply_pending_shadow_activations(first_effective),
            vec![first_address.clone()]
        );
        let active_after_first = registry.get_active_validators();
        assert_eq!(active_after_first.len(), 6);
        assert_eq!(
            registry
                .get_validator_by_address(&second_address)
                .expect("second shadow validator should still exist")
                .status,
            ValidatorStatus::Shadow
        );

        assert!(registry
            .apply_pending_shadow_activations(second_recorded)
            .is_empty());
        assert_eq!(
            registry.apply_pending_shadow_activations(second_effective),
            vec![second_address.clone()]
        );
        registry.reorganize_clusters_for_epoch(2);
        let active_after_second = registry
            .get_active_validators()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let membership_addresses = consensus_membership_validators(active_after_second)
            .into_iter()
            .map(|validator| validator.address)
            .collect::<HashSet<_>>();
        assert!(membership_addresses.contains(&first_address));
        assert!(membership_addresses.contains(&second_address));
    }

    #[test]
    fn reorganize_clusters_splits_ten_validators_into_two_clusters() {
        let registry = active_registry(10);
        let mut cluster_sizes: Vec<usize> = registry
            .clusters
            .values()
            .map(|cluster| cluster.validators.len())
            .collect();
        cluster_sizes.sort_unstable();

        assert_eq!(registry.clusters.len(), 2);
        assert_eq!(cluster_sizes, vec![5, 5]);
    }

    #[test]
    fn reorganize_clusters_keeps_fourteen_validators_in_two_balanced_clusters() {
        let registry = active_registry(14);
        let mut cluster_sizes: Vec<usize> = registry
            .clusters
            .values()
            .map(|cluster| cluster.validators.len())
            .collect();
        cluster_sizes.sort_unstable();

        assert_eq!(registry.clusters.len(), 2);
        assert_eq!(cluster_sizes, vec![7, 7]);
    }

    #[test]
    fn reorganize_clusters_adds_third_cluster_at_fifteen_validators() {
        let registry = active_registry(15);
        let mut cluster_sizes: Vec<usize> = registry
            .clusters
            .values()
            .map(|cluster| cluster.validators.len())
            .collect();
        cluster_sizes.sort_unstable();

        assert_eq!(registry.clusters.len(), 3);
        assert_eq!(cluster_sizes, vec![5, 5, 5]);
    }

    #[test]
    fn reorganize_clusters_shuffles_assignments_by_epoch() {
        let mut registry = active_registry(12);
        let epoch_zero_assignments: HashMap<String, Option<u64>> = registry
            .validators
            .iter()
            .map(|(address, validator)| (address.clone(), validator.cluster_id))
            .collect();

        registry.reorganize_clusters_for_epoch(1);

        let moved = registry.validators.iter().any(|(address, validator)| {
            epoch_zero_assignments.get(address).copied().flatten() != validator.cluster_id
        });

        assert!(
            moved,
            "at least one validator should move clusters after an epoch shuffle"
        );
    }

    #[test]
    fn repeated_missed_votes_jail_then_slash_validator() {
        let mut registry = active_registry(1);
        let address = "validator-0".to_string();

        for _ in 0..MISSED_VOTE_JAIL_THRESHOLD {
            registry.update_validator_performance(
                &address,
                ValidatorPerformanceUpdate {
                    validator_address: address.clone(),
                    update_type: "block_missed".to_string(),
                    value: None,
                    timestamp: 0,
                },
            );
        }

        let validator = registry
            .get_validator_by_address(&address)
            .expect("validator should exist after missed-vote updates");
        assert_eq!(validator.status, ValidatorStatus::Jailed);
        assert_eq!(validator.missed_vote_window, MISSED_VOTE_JAIL_THRESHOLD);

        for _ in MISSED_VOTE_JAIL_THRESHOLD..MISSED_VOTE_SLASH_THRESHOLD {
            registry.update_validator_performance(
                &address,
                ValidatorPerformanceUpdate {
                    validator_address: address.clone(),
                    update_type: "block_missed".to_string(),
                    value: None,
                    timestamp: 0,
                },
            );
        }

        let validator = registry
            .get_validator_by_address(&address)
            .expect("validator should exist after inactivity slashing");
        assert_eq!(validator.status, ValidatorStatus::Slashed);
        assert_eq!(validator.missed_vote_window, MISSED_VOTE_SLASH_THRESHOLD);
        assert!(validator.slashing_penalty >= 0.5);
    }

    #[test]
    fn vote_participation_resets_streak_and_decays_missed_vote_window() {
        let mut registry = active_registry(1);
        let address = "validator-0".to_string();

        for _ in 0..2 {
            registry.update_validator_performance(
                &address,
                ValidatorPerformanceUpdate {
                    validator_address: address.clone(),
                    update_type: "block_missed".to_string(),
                    value: None,
                    timestamp: 0,
                },
            );
        }

        registry.update_validator_performance(
            &address,
            ValidatorPerformanceUpdate {
                validator_address: address.clone(),
                update_type: "vote_cast".to_string(),
                value: None,
                timestamp: 0,
            },
        );

        let validator = registry
            .get_validator_by_address(&address)
            .expect("validator should exist after vote participation");
        assert_eq!(validator.consecutive_missed_votes, 0);
        assert_eq!(validator.missed_vote_window, 1);
        assert!(validator.total_transactions_validated >= 1);
    }
}
