use crate::block::{Block, BlockChain};
use crate::consensus::chain_durability::{
    committed_block_log_path, validate_chain_body_covers_canonical_lock, CommittedBlockLogEntry,
};
use crate::consensus::consensus_algorithm::ProofOfSynergy;
use crate::consensus::consensus_fork;
use crate::consensus::dual_quorum::DualQuorumConsensus;
use crate::consensus::self_realign::{
    apply_chain_state_wipe_plan, build_chain_state_wipe_plan, build_snapshot_restore_plan,
    default_allowed_restore_roles_for_class, fail_closed_mutation_response,
    launch_snapshot_allowed_files, sign_snapshot_manifest, verify_signed_snapshot_manifest,
    QuarantineMarker, RealignmentState, ShadowDecisionRecord, ShadowObservation,
    SignedSnapshotManifest, SnapshotBuildInput, SnapshotQcEvidence, SnapshotSchedule,
    SnapshotVerificationPolicy, ValidatorDutyGate, WipeApplyPreconditions,
    DEFAULT_SHADOW_OBSERVATION_BLOCKS, SNAPSHOT_CLASS_VALIDATOR_PRUNED,
};
use crate::crypto::aegis_pqvm::AegisPqvmSigner;
use crate::synergy_types::{AegisPqKeyRole, Epoch};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const EXPECTED_CHAIN_ID: u64 = 1264;
const EXPECTED_NETWORK_ID: &str = "synergy-testnet-v2";
const EXPECTED_GENESIS_HASH: &str =
    "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789";
const DIAGNOSTIC_STALE_TRANSIENT_VOTE_LOCK_SECS: u64 = 30;
const SHADOW_REJOIN_EPOCH_SIZE: u64 = 1_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VoteLockEntry {
    #[serde(default)]
    validator_address: String,
    #[serde(default)]
    block_hash: String,
    #[serde(default)]
    block_index: u64,
    #[serde(default)]
    epoch_number: u64,
    #[serde(default)]
    first_round_number: u64,
    #[serde(default)]
    latest_round_number: u64,
    #[serde(default)]
    proposer: String,
    #[serde(default)]
    created_at: u64,
    #[serde(default)]
    updated_at: u64,
}

#[derive(Debug, Clone, Default)]
pub struct CreateSnapshotOptions {
    pub source_node_majority_branch_proven: bool,
    pub source_role: Option<String>,
    pub conflict_height_hash: Option<String>,
    pub snapshot_class: Option<String>,
    pub allowed_restore_roles: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct VerifySnapshotOptions {
    pub snapshot_class: Option<String>,
    pub target_role: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct OperatorQuarantineOptions {
    pub reason: Option<String>,
    pub target_stopped: bool,
    pub operator_approved_containment: bool,
    pub quorum_majority_height: Option<u64>,
    pub quorum_majority_hash: Option<String>,
    pub local_conflicting_height: Option<u64>,
    pub local_conflicting_hash: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SyncFromCanonicalPeerOptions {
    pub canonical_height: Option<u64>,
    pub canonical_hash: Option<String>,
    pub source_peer: Option<String>,
    pub source_qc_aegis_pqc_verified: bool,
    pub parent_continuity_verified: bool,
    pub state_root_matches: bool,
    pub source_peer_quarantined: bool,
}

#[derive(Debug, Clone, Default)]
pub struct StartShadowObserveOptions {
    pub required_blocks: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct RejoinRequestOptions {
    pub common_height: Option<u64>,
    pub common_hash: Option<String>,
    pub exact_common_height_match: bool,
    pub latest_finalized_qc_aegis_pqc_verified: bool,
    pub state_root_matches: bool,
    pub rejoin_at_finalized_safe_boundary: bool,
    pub cluster_marks_pending_reactivation: bool,
    pub operator_approved_reactivation: bool,
}

#[derive(Debug, Clone)]
struct BlockSummary {
    height: u64,
    hash: String,
    parent_hash: String,
    validator_id: String,
    transactions_root: String,
}

impl From<&Block> for BlockSummary {
    fn from(block: &Block) -> Self {
        Self {
            height: block.block_index,
            hash: block.hash.clone(),
            parent_hash: block.previous_hash.clone(),
            validator_id: block.validator_id.clone(),
            transactions_root: block.transactions_root.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct ShadowEpochBounds {
    epoch_size: u64,
    shadow_start_height: u64,
    shadow_start_epoch: u64,
    current_epoch_start: u64,
    current_epoch_end: u64,
    partial_epoch_start: Option<u64>,
    partial_epoch_end: Option<u64>,
    required_full_shadow_epoch_start: u64,
    required_full_shadow_epoch_end: u64,
    earliest_activation_height: u64,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn shadow_epoch_bounds(start_height: u64, latest_height: u64) -> Result<ShadowEpochBounds, String> {
    let epoch_size = SHADOW_REJOIN_EPOCH_SIZE;
    if epoch_size == 0 {
        return Err("shadow rejoin epoch size is zero".to_string());
    }
    let shadow_start_epoch = start_height / epoch_size;
    let current_epoch_start = (latest_height / epoch_size) * epoch_size;
    let current_epoch_end = current_epoch_start.saturating_add(epoch_size - 1);
    let start_epoch_start = shadow_start_epoch * epoch_size;
    let start_epoch_end = start_epoch_start.saturating_add(epoch_size - 1);
    let starts_at_epoch_boundary = start_height == start_epoch_start;
    let required_full_shadow_epoch_start = if starts_at_epoch_boundary {
        start_height
    } else {
        start_epoch_start.saturating_add(epoch_size)
    };
    let required_full_shadow_epoch_end =
        required_full_shadow_epoch_start.saturating_add(epoch_size - 1);
    let earliest_activation_height = required_full_shadow_epoch_end.saturating_add(1);
    if earliest_activation_height % epoch_size != 0 {
        return Err(format!(
            "computed earliest activation height {earliest_activation_height} is not an epoch boundary for epoch size {epoch_size}"
        ));
    }
    Ok(ShadowEpochBounds {
        epoch_size,
        shadow_start_height: start_height,
        shadow_start_epoch,
        current_epoch_start,
        current_epoch_end,
        partial_epoch_start: (!starts_at_epoch_boundary).then_some(start_epoch_start),
        partial_epoch_end: (!starts_at_epoch_boundary).then_some(start_epoch_end),
        required_full_shadow_epoch_start,
        required_full_shadow_epoch_end,
        earliest_activation_height,
    })
}

fn epoch_bounds_json(bounds: &ShadowEpochBounds) -> Value {
    json!({
        "epoch_size": bounds.epoch_size,
        "shadow_start_height": bounds.shadow_start_height,
        "shadow_start_epoch": bounds.shadow_start_epoch,
        "current_epoch_start": bounds.current_epoch_start,
        "current_epoch_end": bounds.current_epoch_end,
        "partial_epoch_start": bounds.partial_epoch_start,
        "partial_epoch_end": bounds.partial_epoch_end,
        "required_full_shadow_epoch_start": bounds.required_full_shadow_epoch_start,
        "required_full_shadow_epoch_end": bounds.required_full_shadow_epoch_end,
        "earliest_activation_height": bounds.earliest_activation_height,
    })
}

fn fail_closed_rejoin_response(
    validator_id: &str,
    previous_state: impl Into<String>,
    blocked_reasons: Vec<String>,
    shadow: Value,
) -> Value {
    json!({
        "success": false,
        "typed_status": "FAILED_CLOSED",
        "chain": chain_identity(),
        "validator_id": validator_id,
        "previous_state": previous_state.into(),
        "new_state": "QUARANTINED",
        "blocked_reasons": blocked_reasons,
        "shadow": shadow,
        "keys_or_configs_copied": false,
        "genesis_mutated": false,
        "quorum_mutated": false,
    })
}

fn append_epoch_bounds(mut value: Value, bounds: &ShadowEpochBounds) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.insert("epoch_size".to_string(), json!(bounds.epoch_size));
        object.insert(
            "shadow_start_height".to_string(),
            json!(bounds.shadow_start_height),
        );
        object.insert(
            "shadow_start_epoch".to_string(),
            json!(bounds.shadow_start_epoch),
        );
        object.insert(
            "current_epoch_start".to_string(),
            json!(bounds.current_epoch_start),
        );
        object.insert(
            "current_epoch_end".to_string(),
            json!(bounds.current_epoch_end),
        );
        object.insert(
            "partial_epoch_start".to_string(),
            json!(bounds.partial_epoch_start),
        );
        object.insert(
            "partial_epoch_end".to_string(),
            json!(bounds.partial_epoch_end),
        );
        object.insert(
            "required_full_shadow_epoch_start".to_string(),
            json!(bounds.required_full_shadow_epoch_start),
        );
        object.insert(
            "required_full_shadow_epoch_end".to_string(),
            json!(bounds.required_full_shadow_epoch_end),
        );
        object.insert(
            "earliest_activation_height".to_string(),
            json!(bounds.earliest_activation_height),
        );
    }
    value
}

fn shadow_boundary_assessment(
    bounds: &ShadowEpochBounds,
    latest_height: u64,
    full_epoch_shadow_completed: bool,
    has_failures: bool,
) -> Value {
    let next_eligible_boundary = if latest_height <= bounds.earliest_activation_height {
        bounds.earliest_activation_height
    } else if latest_height % bounds.epoch_size == 0 {
        latest_height
    } else {
        latest_height
            .saturating_div(bounds.epoch_size)
            .saturating_add(1)
            .saturating_mul(bounds.epoch_size)
    };
    let last_eligible_boundary = if latest_height >= bounds.earliest_activation_height {
        Some((latest_height / bounds.epoch_size) * bounds.epoch_size)
    } else {
        None
    };
    let epoch_rejoin_window_open = full_epoch_shadow_completed
        && !has_failures
        && latest_height >= bounds.earliest_activation_height
        && latest_height % bounds.epoch_size == 0;
    let missed_boundary = full_epoch_shadow_completed
        && !has_failures
        && latest_height > bounds.earliest_activation_height
        && latest_height % bounds.epoch_size != 0;
    let mut reasons = Vec::new();
    if has_failures {
        reasons.push("shadow or safety verification has failures".to_string());
    }
    if !full_epoch_shadow_completed {
        reasons.push("continuous full shadow epoch is incomplete".to_string());
    }
    if latest_height < bounds.earliest_activation_height {
        reasons.push(format!(
            "current height {latest_height} is before earliest activation height {}",
            bounds.earliest_activation_height
        ));
    }
    if full_epoch_shadow_completed
        && latest_height >= bounds.earliest_activation_height
        && latest_height % bounds.epoch_size != 0
    {
        reasons.push(format!(
            "current height {latest_height} is not an epoch boundary for epoch_size {}",
            bounds.epoch_size
        ));
    }
    if epoch_rejoin_window_open {
        reasons.push("epoch rejoin window is open".to_string());
    }

    json!({
        "epoch_size": bounds.epoch_size,
        "current_height": latest_height,
        "earliest_activation_height": bounds.earliest_activation_height,
        "last_eligible_boundary": last_eligible_boundary,
        "next_eligible_boundary": next_eligible_boundary,
        "epoch_rejoin_window_open": epoch_rejoin_window_open,
        "missed_boundary": missed_boundary,
        "last_missed_boundary": missed_boundary.then_some((latest_height / bounds.epoch_size) * bounds.epoch_size),
        "missed_boundary_reason": missed_boundary.then_some(format!(
            "full shadow proof existed but no rejoin transition was executed at epoch boundary {}",
            (latest_height / bounds.epoch_size) * bounds.epoch_size
        )),
        "blocked_reasons": reasons,
    })
}

fn configured_chain_id() -> u64 {
    crate::config::load_node_config(None)
        .ok()
        .map(|config| config.blockchain.chain_id)
        .unwrap_or(EXPECTED_CHAIN_ID)
}

fn configured_network_id() -> String {
    crate::config::load_node_config(None)
        .ok()
        .map(|config| config.network.network_id)
        .filter(|network_id| !network_id.is_empty())
        .unwrap_or_else(|| EXPECTED_NETWORK_ID.to_string())
}

fn configured_genesis_hash() -> String {
    crate::genesis::load_canonical_genesis_for_runtime()
        .map(|genesis| genesis.hash().to_string())
        .unwrap_or_else(|_| EXPECTED_GENESIS_HASH.to_string())
}

fn chain_identity() -> Value {
    let chain_id = configured_chain_id();
    json!({
        "chain_id": chain_id,
        "chain_id_hex": format!("0x{chain_id:x}"),
        "network_id": configured_network_id(),
        "genesis_hash": configured_genesis_hash(),
    })
}

fn require_local_testnet_v2() -> Result<(), String> {
    let config = crate::config::load_node_config(None)
        .map_err(|error| format!("node config invalid; refusing mutation: {error}"))?;
    let chain_id = config.blockchain.chain_id;
    let network_id = config.network.network_id;
    let genesis_hash = crate::genesis::load_canonical_genesis_for_runtime()
        .map(|genesis| genesis.hash().to_string())
        .map_err(|error| format!("genesis unavailable; refusing mutation: {error}"))?;
    if chain_id != EXPECTED_CHAIN_ID {
        return Err(format!(
            "wrong chain_id {chain_id}; expected {EXPECTED_CHAIN_ID}"
        ));
    }
    if network_id != EXPECTED_NETWORK_ID {
        return Err(format!(
            "wrong network_id {network_id}; expected {EXPECTED_NETWORK_ID}"
        ));
    }
    if !genesis_hash.eq_ignore_ascii_case(EXPECTED_GENESIS_HASH) {
        return Err(format!(
            "wrong genesis_hash {genesis_hash}; expected {EXPECTED_GENESIS_HASH}"
        ));
    }
    Ok(())
}

fn read_json_file(path: &str) -> Option<Value> {
    let path = crate::utils::resolve_data_path(path);
    fs::read_to_string(path)
        .ok()
        .and_then(|content| serde_json::from_str::<Value>(&content).ok())
}

fn read_json_file_raw(path: &Path) -> Option<Value> {
    fs::read_to_string(path)
        .ok()
        .and_then(|content| serde_json::from_str::<Value>(&content).ok())
}

fn marker_recovery_state(marker_paths: &[String]) -> RealignmentState {
    for marker_path in marker_paths {
        let path = PathBuf::from(marker_path);
        let Some(value) = read_json_file_raw(&path) else {
            continue;
        };
        if let Some(state) = value
            .get("recovery_state")
            .or_else(|| value.get("status"))
            .and_then(Value::as_str)
        {
            match state {
                "ACTIVE" | "Active" | "active" => return RealignmentState::Active,
                "SUSPECT" | "Suspect" | "suspect" => return RealignmentState::Suspect,
                "EVIDENCE_PRESERVED" => return RealignmentState::EvidencePreserved,
                "CHAIN_DATA_WIPE_READY" => return RealignmentState::ChainDataWipeReady,
                "CHAIN_DATA_WIPED" => return RealignmentState::ChainDataWiped,
                "SNAPSHOT_DISCOVERY" => return RealignmentState::SnapshotDiscovery,
                "SNAPSHOT_DOWNLOADING" => return RealignmentState::SnapshotDownloading,
                "SNAPSHOT_VERIFIED" => return RealignmentState::SnapshotVerified,
                "SNAPSHOT_RESTORED" => return RealignmentState::SnapshotRestored,
                "SPEED_SYNCING" => return RealignmentState::SpeedSyncing,
                "CAUGHT_UP" => return RealignmentState::CaughtUp,
                "SHADOW_OBSERVING" | "Shadow" => return RealignmentState::ShadowObserving,
                "SHADOW_PASSED" => return RealignmentState::ShadowPassed,
                "READY_TO_REJOIN" => return RealignmentState::ReadyToRejoin,
                "PENDING_REACTIVATION" => return RealignmentState::PendingReactivation,
                "FAILED_CLOSED" => return RealignmentState::FailedClosed,
                _ => return RealignmentState::Quarantined,
            }
        }
    }
    if marker_paths.is_empty() {
        RealignmentState::Active
    } else {
        RealignmentState::Quarantined
    }
}

fn latest_canonical_lock_height() -> Option<u64> {
    let map = read_json_file("data/canonical_locks.json")?;
    map.as_object()?
        .keys()
        .filter_map(|key| key.parse::<u64>().ok())
        .max()
}

fn latest_canonical_lock() -> Option<(u64, String)> {
    let map = read_json_file("data/canonical_locks.json")?;
    let object = map.as_object()?;
    let height = object
        .keys()
        .filter_map(|key| key.parse::<u64>().ok())
        .max()?;
    let entry = object.get(&height.to_string())?;
    let hash = string_field(entry, &["hash", "block_hash"])?;
    Some((height, hash))
}

fn canonical_lock_at_height(height: u64) -> Option<String> {
    let map = read_json_file("data/canonical_locks.json")?;
    let entry = map.as_object()?.get(&height.to_string())?;
    string_field(entry, &["hash", "block_hash"])
}

fn latest_committed_qc() -> Option<Value> {
    let path = crate::utils::resolve_data_path("data/committed_qcs.jsonl");
    let content = fs::read_to_string(path).ok()?;
    content
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .and_then(|line| serde_json::from_str::<Value>(line).ok())
}

fn string_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|key| value.get(*key))
        .find_map(Value::as_str)
        .map(str::to_string)
}

fn u64_field(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .filter_map(|key| value.get(*key))
        .find_map(|item| {
            item.as_u64()
                .or_else(|| item.as_str().and_then(|text| text.parse::<u64>().ok()))
        })
}

fn find_block_at_height(value: &Value, height: u64) -> Option<BlockSummary> {
    if let Some(object) = value.as_object() {
        let candidate_height =
            u64_field(value, &["height", "number", "block_number", "block_index"]);
        if candidate_height == Some(height) {
            let hash = string_field(value, &["hash", "block_hash"])?;
            let parent_hash = string_field(value, &["parent_hash", "previous_hash", "parentHash"])
                .unwrap_or_default();
            let validator_id =
                string_field(value, &["validator_id", "validator"]).unwrap_or_default();
            let transactions_root =
                string_field(value, &["transactions_root", "tx_root"]).unwrap_or_default();
            return Some(BlockSummary {
                height,
                hash,
                parent_hash,
                validator_id,
                transactions_root,
            });
        }
        for child in object.values() {
            if let Some(found) = find_block_at_height(child, height) {
                return Some(found);
            }
        }
    } else if let Some(array) = value.as_array() {
        for child in array {
            if let Some(found) = find_block_at_height(child, height) {
                return Some(found);
            }
        }
    }
    None
}

fn read_block_at_height(height: u64) -> Result<BlockSummary, String> {
    let mut committed_log_blocks = BTreeMap::<u64, BlockSummary>::new();
    fill_blocks_from_committed_log(height, height, &mut committed_log_blocks)?;
    if let Some(block) = committed_log_blocks.remove(&height) {
        return Ok(block);
    }

    let path = crate::utils::resolve_data_path("data/chain.json");
    let mut found = None;
    stream_chain_blocks(&path, |value| {
        if let Some(block) = find_block_at_height(value, height) {
            found = Some(block);
            Ok(true)
        } else {
            Ok(false)
        }
    })?;
    found.ok_or_else(|| format!("chain state does not contain finalized block height {height}"))
}

fn read_blocks_in_height_range(
    start_height: u64,
    end_height: u64,
) -> Result<Vec<BlockSummary>, String> {
    if end_height < start_height {
        return Ok(Vec::new());
    }
    let path = crate::utils::resolve_data_path("data/chain.json");
    let expected = end_height.saturating_sub(start_height).saturating_add(1) as usize;
    let mut blocks = BTreeMap::<u64, BlockSummary>::new();
    fill_blocks_from_committed_log(start_height, end_height, &mut blocks)?;
    if blocks.len() == expected {
        return Ok(blocks.into_values().collect());
    }

    stream_chain_blocks(&path, |value| {
        let Some(height) = u64_field(value, &["height", "number", "block_number", "block_index"])
        else {
            return Ok(false);
        };
        if height < start_height || height > end_height {
            return Ok(false);
        }
        let Some(hash) = string_field(value, &["hash", "block_hash"]) else {
            return Ok(false);
        };
        let parent_hash = string_field(value, &["parent_hash", "previous_hash", "parentHash"])
            .unwrap_or_default();
        let validator_id = string_field(value, &["validator_id", "validator"]).unwrap_or_default();
        let transactions_root =
            string_field(value, &["transactions_root", "tx_root"]).unwrap_or_default();
        blocks.insert(
            height,
            BlockSummary {
                height,
                hash,
                parent_hash,
                validator_id,
                transactions_root,
            },
        );
        Ok(blocks.len() >= expected)
    })?;
    if blocks.len() != expected {
        let missing = (start_height..=end_height)
            .find(|height| !blocks.contains_key(height))
            .map(|height| height.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        return Err(format!(
            "chain state missing shadow observation block height {missing} in range {start_height}-{end_height}"
        ));
    }
    Ok(blocks.into_values().collect())
}

fn fill_blocks_from_committed_log(
    start_height: u64,
    end_height: u64,
    blocks: &mut BTreeMap<u64, BlockSummary>,
) -> Result<(), String> {
    let path = committed_block_log_path();
    if !path.exists() {
        return Ok(());
    }
    let file = fs::File::open(&path)
        .map_err(|error| format!("open committed block log {}: {error}", path.display()))?;
    let expected = end_height.saturating_sub(start_height).saturating_add(1) as usize;
    for (line_number, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|error| {
            format!(
                "read committed block log {} line {}: {error}",
                path.display(),
                line_number + 1
            )
        })?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry = serde_json::from_str::<CommittedBlockLogEntry>(trimmed).map_err(|error| {
            format!(
                "parse committed block log {} line {}: {error}",
                path.display(),
                line_number + 1
            )
        })?;
        if entry.height < start_height || entry.height > end_height {
            continue;
        }
        if entry.height != entry.block.block_index || entry.hash != entry.block.hash {
            return Err(format!(
                "committed block log entry at line {} has inconsistent height/hash",
                line_number + 1
            ));
        }
        blocks
            .entry(entry.height)
            .or_insert_with(|| BlockSummary::from(&entry.block));
        if blocks.len() >= expected {
            break;
        }
    }
    Ok(())
}

fn evaluate_shadow_block_range(
    validator_id: String,
    start_height: u64,
    end_height: u64,
    required_blocks: u64,
) -> Result<ShadowObservation, String> {
    let blocks = read_blocks_in_height_range(start_height, end_height)?;
    let mut shadow_observation = ShadowObservation::new(validator_id, required_blocks);
    for block in blocks {
        shadow_observation.record(ShadowDecisionRecord {
            height: block.height,
            canonical_hash: block.hash.clone(),
            would_have_voted_hash: Some(block.hash),
            would_have_proposed_hash: None,
            state_root_matches: true,
            rejected_valid_majority_block: false,
            accepted_conflicting_block: false,
        });
    }
    Ok(shadow_observation.evaluate())
}

fn read_latest_block_summary() -> Result<BlockSummary, String> {
    let path = crate::utils::resolve_data_path("data/chain.json");
    let mut latest = None;
    stream_chain_blocks(&path, |value| {
        let candidate_height =
            u64_field(value, &["height", "number", "block_number", "block_index"]);
        let Some(height) = candidate_height else {
            return Ok(false);
        };
        let Some(hash) = string_field(value, &["hash", "block_hash"]) else {
            return Ok(false);
        };
        let parent_hash = string_field(value, &["parent_hash", "previous_hash", "parentHash"])
            .unwrap_or_default();
        let validator_id = string_field(value, &["validator_id", "validator"]).unwrap_or_default();
        let transactions_root =
            string_field(value, &["transactions_root", "tx_root"]).unwrap_or_default();
        if latest
            .as_ref()
            .map(|block: &BlockSummary| height > block.height)
            .unwrap_or(true)
        {
            latest = Some(BlockSummary {
                height,
                hash,
                parent_hash,
                validator_id,
                transactions_root,
            });
        }
        Ok(false)
    })?;
    latest.ok_or_else(|| "chain state does not contain any persisted blocks".to_string())
}

fn stream_chain_blocks<F>(path: &Path, mut on_block: F) -> Result<(), String>
where
    F: FnMut(&Value) -> Result<bool, String>,
{
    let file = fs::File::open(path)
        .map_err(|error| format!("open chain state {}: {error}", path.display()))?;
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut buffer = [0u8; 64 * 1024];
    let mut offset = 0u64;
    let mut saw_array = false;
    let mut capturing = false;
    let mut in_string = false;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut need_value = true;
    let mut parsed_any = false;
    let mut block_bytes = Vec::with_capacity(32 * 1024);

    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| format!("read chain state {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        for byte in buffer[..read].iter().copied() {
            offset += 1;
            if !saw_array {
                if byte.is_ascii_whitespace() {
                    continue;
                }
                if byte == b'[' {
                    saw_array = true;
                    continue;
                }
                return Err(format!(
                    "stream parse chain state {}: expected array at byte {}",
                    path.display(),
                    offset
                ));
            }

            if !capturing {
                if byte.is_ascii_whitespace() {
                    continue;
                }
                if byte == b']' {
                    if need_value && parsed_any {
                        return Err(format!(
                            "stream parse chain state {}: trailing comma before array close at byte {}",
                            path.display(),
                            offset
                        ));
                    }
                    return Ok(());
                }
                if byte == b',' {
                    if need_value {
                        return Err(format!(
                            "stream parse chain state {}: unexpected comma at byte {}",
                            path.display(),
                            offset
                        ));
                    }
                    need_value = true;
                    continue;
                }
                if !need_value {
                    return Err(format!(
                        "stream parse chain state {}: missing comma before byte {}",
                        path.display(),
                        offset
                    ));
                }
                if byte != b'{' {
                    return Err(format!(
                        "stream parse chain state {}: expected block object at byte {}",
                        path.display(),
                        offset
                    ));
                }
                capturing = true;
                in_string = false;
                escaped = false;
                depth = 0;
                block_bytes.clear();
            }

            block_bytes.push(byte);
            if in_string {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    in_string = false;
                }
                continue;
            }

            match byte {
                b'"' => in_string = true,
                b'{' | b'[' => depth = depth.saturating_add(1),
                b'}' | b']' => {
                    if depth == 0 {
                        return Err(format!(
                            "stream parse chain state {}: unexpected closing delimiter at byte {}",
                            path.display(),
                            offset
                        ));
                    }
                    depth -= 1;
                    if depth == 0 {
                        let value =
                            serde_json::from_slice::<Value>(&block_bytes).map_err(|error| {
                                format!(
                                    "stream parse chain state {} block ending at byte {}: {error}",
                                    path.display(),
                                    offset
                                )
                            })?;
                        capturing = false;
                        parsed_any = true;
                        need_value = false;
                        block_bytes.clear();
                        if on_block(&value)? {
                            return Ok(());
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if !saw_array {
        return Err(format!(
            "stream parse chain state {}: missing chain array",
            path.display()
        ));
    }
    if capturing {
        return Err(format!(
            "stream parse chain state {}: unterminated block object",
            path.display()
        ));
    }
    Err(format!(
        "stream parse chain state {}: missing closing array delimiter",
        path.display()
    ))
}

fn active_genesis_validator_addresses() -> Result<Vec<String>, String> {
    let genesis = crate::genesis::load_canonical_genesis_for_runtime()?;
    let validators = genesis
        .validators()
        .iter()
        .map(|validator| {
            if validator.operator_address.trim().is_empty() {
                validator.validator_id.clone()
            } else {
                validator.operator_address.clone()
            }
        })
        .collect::<Vec<_>>();
    if validators.len() != 5 {
        return Err(format!(
            "active genesis validator set has {} validator(s); expected 5",
            validators.len()
        ));
    }
    Ok(validators)
}

fn active_validator_addresses_for_snapshot_height(
    snapshot_height: u64,
) -> Result<Vec<String>, String> {
    if let Some(migration) = consensus_fork::active_consensus_fork_migration()? {
        if migration.applies_to_height(snapshot_height) {
            migration.validate()?;
            let validators = migration
                .new_validator_registry
                .iter()
                .map(|validator| {
                    validator.validate()?;
                    Ok(validator.validator_address.clone())
                })
                .collect::<Result<Vec<_>, String>>()?;
            if validators.len() != 5 {
                return Err(format!(
                    "post-fork active validator set has {} validator(s); expected 5",
                    validators.len()
                ));
            }
            return Ok(validators);
        }
    }
    active_genesis_validator_addresses()
}

fn env_truthy(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "y" | "on"
            )
        })
        .unwrap_or(false)
}

fn snapshot_source_node_id() -> String {
    std::env::var("SYNERGY_SNAPSHOT_SOURCE_NODE_ID")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(crate::config::resolve_runtime_validator_address)
        .unwrap_or_else(|| "unknown-validator".to_string())
}

#[derive(Debug)]
struct SnapshotCanonicalLockMaterialization {
    block: BlockSummary,
    qc_vote_count: u64,
}

fn copy_snapshot_state_files(
    data_dir: &Path,
    snapshot_dir: &Path,
    snapshot_height: u64,
    materialized_lock: Option<&SnapshotCanonicalLockMaterialization>,
) -> Result<usize, String> {
    fs::create_dir_all(snapshot_dir).map_err(|error| {
        format!(
            "create snapshot state directory {}: {error}",
            snapshot_dir.display()
        )
    })?;
    let mut copied = 0usize;
    for file_name in launch_snapshot_allowed_files() {
        let source = data_dir.join(file_name);
        if !source.is_file() {
            continue;
        }
        let target = snapshot_dir.join(file_name);
        fs::copy(&source, &target).map_err(|error| {
            format!(
                "copy launch-approved snapshot state {} -> {}: {error}",
                source.display(),
                target.display()
            )
        })?;
        copied += 1;
    }
    if copied == 0 {
        return Err("snapshot source contains no launch-approved chain/state files".to_string());
    }
    constrain_snapshot_metadata_to_height(snapshot_dir, snapshot_height, materialized_lock)?;
    Ok(copied)
}

fn qc_height_from_json(value: &Value) -> Option<u64> {
    for key in ["height", "block_height", "block_index"] {
        if let Some(height) = value.get(key).and_then(Value::as_u64) {
            return Some(height);
        }
    }
    let qc = value.get("qc").unwrap_or(value);
    for key in ["height", "block_height", "block_index"] {
        if let Some(height) = qc.get(key).and_then(Value::as_u64) {
            return Some(height);
        }
    }
    qc.get("votes").and_then(Value::as_array).and_then(|votes| {
        votes
            .iter()
            .filter_map(|vote| {
                vote.get("block_index")
                    .or_else(|| vote.get("height"))
                    .and_then(Value::as_u64)
            })
            .max()
    })
}

fn constrain_snapshot_metadata_to_height(
    snapshot_dir: &Path,
    snapshot_height: u64,
    materialized_lock: Option<&SnapshotCanonicalLockMaterialization>,
) -> Result<(), String> {
    let canonical_path = snapshot_dir.join("canonical_locks.json");
    if canonical_path.is_file() {
        let canonical_value: Value =
            serde_json::from_slice(&fs::read(&canonical_path).map_err(|error| {
                format!(
                    "read {} for snapshot height constraint: {error}",
                    canonical_path.display()
                )
            })?)
            .map_err(|error| format!("parse {}: {error}", canonical_path.display()))?;
        let mut canonical_map = canonical_value
            .as_object()
            .cloned()
            .ok_or_else(|| format!("{} must be a JSON object", canonical_path.display()))?;
        canonical_map.retain(|height, _| {
            height
                .parse::<u64>()
                .map(|height| height <= snapshot_height)
                .unwrap_or(false)
        });
        if !canonical_map.contains_key(&snapshot_height.to_string()) {
            let Some(lock) = materialized_lock else {
                return Err(format!(
                    "snapshot canonical_locks.json has no canonical lock at snapshot height {snapshot_height}"
                ));
            };
            if lock.block.height != snapshot_height {
                return Err(format!(
                    "snapshot canonical lock materialization height {} does not match snapshot height {snapshot_height}",
                    lock.block.height
                ));
            }
            canonical_map.insert(
                snapshot_height.to_string(),
                json!({
                    "height": snapshot_height,
                    "hash": lock.block.hash,
                    "block_hash": lock.block.hash,
                    "parent_hash": lock.block.parent_hash,
                    "validator_id": lock.block.validator_id,
                    "transactions_root": lock.block.transactions_root,
                    "qc_block_hash": lock.block.hash,
                    "qc_hash": lock.block.hash,
                    "written_at_unix_secs": now_secs(),
                    "qc_vote_count": lock.qc_vote_count,
                    "finality_source": "verified_committed_qc",
                    "snapshot_only_materialized": true,
                }),
            );
        }
        fs::write(
            &canonical_path,
            serde_json::to_vec_pretty(&Value::Object(canonical_map))
                .map_err(|error| format!("serialize {}: {error}", canonical_path.display()))?,
        )
        .map_err(|error| format!("write constrained {}: {error}", canonical_path.display()))?;
    }

    let committed_qcs_path = snapshot_dir.join("committed_qcs.jsonl");
    if committed_qcs_path.is_file() {
        let source = fs::File::open(&committed_qcs_path)
            .map_err(|error| format!("open {}: {error}", committed_qcs_path.display()))?;
        let tmp_path = committed_qcs_path.with_extension("jsonl.tmp");
        let mut tmp = fs::File::create(&tmp_path)
            .map_err(|error| format!("create {}: {error}", tmp_path.display()))?;
        let mut found_snapshot_qc = false;
        let mut kept = 0usize;
        for line in BufReader::new(source).lines() {
            let line =
                line.map_err(|error| format!("read {}: {error}", committed_qcs_path.display()))?;
            if line.trim().is_empty() {
                continue;
            }
            let value = serde_json::from_str::<Value>(&line).map_err(|error| {
                format!(
                    "parse committed QC in {}: {error}",
                    committed_qcs_path.display()
                )
            })?;
            let Some(height) = qc_height_from_json(&value) else {
                return Err(format!(
                    "committed QC entry in {} has no height",
                    committed_qcs_path.display()
                ));
            };
            if height > snapshot_height {
                continue;
            }
            if height == snapshot_height {
                found_snapshot_qc = true;
            }
            writeln!(tmp, "{line}")
                .map_err(|error| format!("write {}: {error}", tmp_path.display()))?;
            kept += 1;
        }
        tmp.flush()
            .map_err(|error| format!("flush {}: {error}", tmp_path.display()))?;
        if kept == 0 || !found_snapshot_qc {
            return Err(format!(
                "committed_qcs.jsonl has no committed QC at snapshot height {snapshot_height}"
            ));
        }
        fs::rename(&tmp_path, &committed_qcs_path).map_err(|error| {
            format!(
                "replace constrained {} with {}: {error}",
                committed_qcs_path.display(),
                tmp_path.display()
            )
        })?;
    }
    Ok(())
}

fn snapshot_metadata_consistency_report(
    signed: &SignedSnapshotManifest,
    snapshot_root: &Path,
) -> Result<Value, String> {
    let snapshot_height = signed.manifest.snapshot_height;
    let canonical_path = snapshot_root.join("canonical_locks.json");
    let canonical_max_height = if canonical_path.is_file() {
        let value: Value = serde_json::from_slice(&fs::read(&canonical_path).map_err(|error| {
            format!(
                "read {} for consistency check: {error}",
                canonical_path.display()
            )
        })?)
        .map_err(|error| format!("parse {}: {error}", canonical_path.display()))?;
        let object = value
            .as_object()
            .ok_or_else(|| format!("{} must be a JSON object", canonical_path.display()))?;
        let max_height = object
            .keys()
            .filter_map(|height| height.parse::<u64>().ok())
            .max()
            .ok_or_else(|| format!("{} has no canonical lock entries", canonical_path.display()))?;
        if max_height > snapshot_height {
            return Err(format!(
                "snapshot canonical lock height {max_height} is above manifest snapshot height {snapshot_height}"
            ));
        }
        if !object.contains_key(&snapshot_height.to_string()) {
            return Err(format!(
                "snapshot canonical_locks.json has no canonical lock at manifest height {snapshot_height}"
            ));
        }
        Some(max_height)
    } else {
        None
    };

    let committed_qcs_path = snapshot_root.join("committed_qcs.jsonl");
    let mut committed_qc_max_height: Option<u64> = None;
    let mut committed_qc_has_snapshot_height = false;
    if committed_qcs_path.is_file() {
        let file = fs::File::open(&committed_qcs_path)
            .map_err(|error| format!("open {}: {error}", committed_qcs_path.display()))?;
        for line in BufReader::new(file).lines() {
            let line =
                line.map_err(|error| format!("read {}: {error}", committed_qcs_path.display()))?;
            if line.trim().is_empty() {
                continue;
            }
            let value = serde_json::from_str::<Value>(&line).map_err(|error| {
                format!(
                    "parse committed QC in {}: {error}",
                    committed_qcs_path.display()
                )
            })?;
            let Some(height) = qc_height_from_json(&value) else {
                return Err(format!(
                    "committed QC entry in {} has no height",
                    committed_qcs_path.display()
                ));
            };
            if height > snapshot_height {
                return Err(format!(
                    "snapshot committed QC height {height} is above manifest snapshot height {snapshot_height}"
                ));
            }
            if height == snapshot_height {
                committed_qc_has_snapshot_height = true;
            }
            committed_qc_max_height =
                Some(committed_qc_max_height.map_or(height, |max| max.max(height)));
        }
        if !committed_qc_has_snapshot_height {
            return Err(format!(
                "snapshot committed_qcs.jsonl has no committed QC at manifest height {snapshot_height}"
            ));
        }
    }

    Ok(json!({
        "snapshot_metadata_consistent": true,
        "snapshot_height": snapshot_height,
        "canonical_lock_max_height": canonical_max_height,
        "committed_qc_max_height": committed_qc_max_height,
    }))
}

fn enforce_snapshot_retention(snapshot_root: &Path, retain_last: usize) -> Result<(), String> {
    if retain_last == 0 || !snapshot_root.is_dir() {
        return Ok(());
    }
    let mut snapshots = fs::read_dir(snapshot_root)
        .map_err(|error| format!("read snapshot root {}: {error}", snapshot_root.display()))?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_type()
                .map(|file_type| file_type.is_dir())
                .unwrap_or(false)
                && entry
                    .file_name()
                    .to_str()
                    .map(|name| name.starts_with("snapshot-"))
                    .unwrap_or(false)
        })
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    snapshots.sort_by(|left, right| {
        snapshot_retention_key(left)
            .cmp(&snapshot_retention_key(right))
            .then_with(|| left.cmp(right))
    });
    let stale_count = snapshots.len().saturating_sub(retain_last);
    for path in snapshots.into_iter().take(stale_count) {
        fs::remove_dir_all(&path)
            .map_err(|error| format!("remove stale snapshot {}: {error}", path.display()))?;
    }
    Ok(())
}

fn snapshot_retention_key(path: &Path) -> (u64, u64) {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return (0, 0);
    };
    let Some(rest) = name.strip_prefix("snapshot-") else {
        return (0, 0);
    };
    let mut parts = rest.splitn(3, '-');
    let height = parts
        .next()
        .and_then(|part| part.parse::<u64>().ok())
        .unwrap_or(0);
    let created_at = parts
        .next()
        .and_then(|part| part.parse::<u64>().ok())
        .unwrap_or(0);
    (height, created_at)
}

fn current_runtime_checksum() -> Result<String, String> {
    let exe =
        std::env::current_exe().map_err(|error| format!("resolve current runtime: {error}"))?;
    let bytes = fs::read(&exe)
        .map_err(|error| format!("read current runtime {}: {error}", exe.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn read_signed_snapshot_manifest(manifest_path: &Path) -> Result<SignedSnapshotManifest, String> {
    let content = fs::read_to_string(manifest_path).map_err(|error| {
        format!(
            "read snapshot manifest {}: {error}",
            manifest_path.display()
        )
    })?;
    serde_json::from_str(&content).map_err(|error| {
        format!(
            "parse snapshot manifest {}: {error}",
            manifest_path.display()
        )
    })
}

fn self_heal_status_path() -> PathBuf {
    crate::utils::resolve_data_path("data/self_heal_status.json")
}

fn shadow_observation_path() -> PathBuf {
    crate::utils::resolve_data_path("data/shadow_observation.json")
}

fn preserve_and_remove_stale_shadow_observation(
    evidence_path: &Path,
) -> Result<Option<String>, String> {
    let path = shadow_observation_path();
    if !path.exists() {
        return Ok(None);
    }
    fs::create_dir_all(evidence_path).map_err(|error| {
        format!(
            "create stale shadow observation evidence directory {}: {error}",
            evidence_path.display()
        )
    })?;
    let preserved_path = evidence_path.join("stale-shadow-observation-before-restore.json");
    fs::copy(&path, &preserved_path).map_err(|error| {
        format!(
            "preserve stale shadow observation {} -> {}: {error}",
            path.display(),
            preserved_path.display()
        )
    })?;
    fs::remove_file(&path).map_err(|error| {
        format!(
            "remove stale shadow observation after preservation {}: {error}",
            path.display()
        )
    })?;
    Ok(Some(preserved_path.to_string_lossy().to_string()))
}

fn read_self_heal_status_file() -> Option<Value> {
    read_json_file_raw(&self_heal_status_path())
}

fn write_json_pretty(path: &Path, value: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let bytes =
        serde_json::to_vec_pretty(value).map_err(|error| format!("serialize json: {error}"))?;
    fs::write(path, bytes).map_err(|error| format!("write {}: {error}", path.display()))
}

fn file_evidence_summary(path: &Path) -> Value {
    let exists = path.exists();
    let size_bytes = fs::metadata(path).ok().map(|metadata| metadata.len());
    let sha256 = size_bytes
        .filter(|size| *size <= 64 * 1024 * 1024)
        .and_then(|_| fs::read(path).ok())
        .map(|bytes| format!("{:x}", Sha256::digest(&bytes)));
    json!({
        "path": path.to_string_lossy(),
        "exists": exists,
        "size_bytes": size_bytes,
        "sha256": sha256,
        "sha256_skipped_large_file": size_bytes.map(|size| size > 64 * 1024 * 1024).unwrap_or(false),
    })
}

fn preserve_operator_quarantine_evidence(evidence_path: &Path) -> Result<Value, String> {
    fs::create_dir_all(evidence_path)
        .map_err(|error| format!("create evidence dir {}: {error}", evidence_path.display()))?;
    let data_dir = crate::utils::resolve_data_path("data");
    let files = [
        "chain.json",
        "canonical_locks.json",
        "committed_qcs.jsonl",
        "consensus_vote_locks.json",
        "validator_quarantine.json",
        "validator_quarantine_peer_evidence.json",
        "self_heal_status.json",
    ];
    let summaries = files
        .iter()
        .map(|name| file_evidence_summary(&data_dir.join(name)))
        .collect::<Vec<_>>();
    let evidence = json!({
        "chain": chain_identity(),
        "evidence_path": evidence_path.to_string_lossy(),
        "captured_at": now_secs(),
        "file_summaries": summaries,
        "process_mutation": false,
        "chain_state_mutated": false,
        "canonical_locks_mutated": false,
        "committed_qcs_mutated": false,
        "keys_or_configs_copied": false,
        "genesis_mutated": false,
        "quorum_mutated": false,
    });
    write_json_pretty(
        &evidence_path.join("operator-quarantine-evidence.json"),
        &evidence,
    )?;
    Ok(evidence)
}

fn read_standard_quarantine_marker() -> Result<QuarantineMarker, String> {
    let marker_path = crate::utils::resolve_data_path("data/validator_quarantine.json");
    let content = fs::read_to_string(&marker_path).map_err(|error| {
        format!(
            "standard local quarantine marker {} is required before self-heal: {error}",
            marker_path.display()
        )
    })?;
    let marker = serde_json::from_str::<QuarantineMarker>(&content).map_err(|error| {
        format!(
            "local quarantine marker {} is malformed or not the standard schema: {error}",
            marker_path.display()
        )
    })?;
    if marker.recovery_state != RealignmentState::Quarantined {
        return Err(format!(
            "local quarantine marker recovery_state {:?} is not QUARANTINED",
            marker.recovery_state
        ));
    }
    if !marker.voting_disabled
        || !marker.proposing_disabled
        || !marker.qc_aggregation_disabled
        || !marker.canonical_source_disabled
    {
        return Err("local quarantine marker does not disable all consensus duties".to_string());
    }
    if marker.rejoin_eligibility {
        return Err("local quarantine marker cannot be rejoin eligible before restore".to_string());
    }
    if marker.evidence_path.trim().is_empty() || !Path::new(&marker.evidence_path).exists() {
        return Err("local quarantine marker evidence_path is missing or unavailable".to_string());
    }
    Ok(marker)
}

fn status_state(status: Option<&Value>) -> Option<String> {
    status
        .and_then(|value| {
            value
                .get("new_state")
                .or_else(|| value.get("typed_status"))
                .or_else(|| value.get("status"))
        })
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn current_validator_id() -> String {
    crate::config::resolve_runtime_validator_address()
        .unwrap_or_else(|| "unknown-validator".to_string())
}

fn latest_verified_qc_summary() -> Result<crate::recovery::QcProofSummary, String> {
    let data_dir = crate::utils::resolve_data_path("data");
    let summary = crate::recovery::verify_latest_committed_qc_in_state_dir(&data_dir, None)?;
    if !summary.verified || summary.vote_count < 4 {
        return Err("latest committed QC is not verified through Aegis/PQC quorum".to_string());
    }
    Ok(summary)
}

fn vote_locks_clean(finalized_height: u64) -> Result<Value, String> {
    let report = diagnose_vote_locks(Some(finalized_height));
    let locks_above = report
        .get("locks_above_finalized")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if locks_above != 0 {
        return Err(format!(
            "vote locks remain above finalized height {finalized_height}: {locks_above}"
        ));
    }
    Ok(report)
}

fn preserve_and_remove_quarantine_markers(evidence_path: &Path) -> Result<Vec<String>, String> {
    fs::create_dir_all(evidence_path).map_err(|error| {
        format!(
            "create rejoin evidence directory {}: {error}",
            evidence_path.display()
        )
    })?;
    let marker_paths = [
        crate::utils::resolve_data_path("data/validator_quarantine.json"),
        crate::utils::resolve_data_path("data/validator_quarantine_peer_evidence.json"),
    ];
    let mut preserved = Vec::new();
    for marker_path in marker_paths {
        if !marker_path.exists() {
            continue;
        }
        let target = evidence_path.join(
            marker_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("quarantine-marker.json"),
        );
        fs::copy(&marker_path, &target).map_err(|error| {
            format!(
                "preserve quarantine marker {} -> {}: {error}",
                marker_path.display(),
                target.display()
            )
        })?;
        fs::remove_file(&marker_path).map_err(|error| {
            format!(
                "remove quarantine marker {}: {error}",
                marker_path.display()
            )
        })?;
        preserved.push(target.to_string_lossy().to_string());
    }
    Ok(preserved)
}

fn resolved_snapshot_root(
    manifest_path: &Path,
    snapshot_root: Option<&str>,
) -> Result<PathBuf, String> {
    if let Some(root) = snapshot_root {
        let root = PathBuf::from(root);
        if root.is_dir() {
            return Ok(root);
        }
        return Err(format!(
            "snapshot_root {} is not a directory",
            root.display()
        ));
    }
    manifest_path
        .parent()
        .map(PathBuf::from)
        .filter(|parent| parent.is_dir())
        .ok_or_else(|| {
            format!(
                "snapshot_root is required because manifest parent is unavailable for {}",
                manifest_path.display()
            )
        })
}

fn restore_snapshot_files(
    signed: &SignedSnapshotManifest,
    snapshot_root: &Path,
    target_data_dir: &Path,
) -> Result<Vec<String>, String> {
    fs::create_dir_all(target_data_dir).map_err(|error| {
        format!(
            "create target data directory {}: {error}",
            target_data_dir.display()
        )
    })?;
    let mut restored = Vec::new();
    for entry in &signed.manifest.files {
        if !launch_snapshot_allowed_files()
            .iter()
            .any(|allowed| *allowed == entry.relative_path)
        {
            return Err(format!(
                "snapshot restore refused non-launch-approved state file {}",
                entry.relative_path
            ));
        }
        let source = snapshot_root.join(&entry.relative_path);
        let target = target_data_dir.join(&entry.relative_path);
        fs::copy(&source, &target).map_err(|error| {
            format!(
                "restore snapshot state {} -> {}: {error}",
                source.display(),
                target.display()
            )
        })?;
        restored.push(target.to_string_lossy().to_string());
    }
    Ok(restored)
}

fn vote_lock_entries() -> (String, Vec<VoteLockEntry>, Option<String>) {
    let path = crate::utils::resolve_data_path("data/consensus_vote_locks.json");
    let path_string = path.to_string_lossy().to_string();
    let Ok(content) = fs::read_to_string(&path) else {
        return (path_string, Vec::new(), None);
    };
    let parsed = match serde_json::from_str::<BTreeMap<String, VoteLockEntry>>(&content) {
        Ok(parsed) => parsed,
        Err(error) => return (path_string, Vec::new(), Some(error.to_string())),
    };
    (path_string, parsed.into_values().collect(), None)
}

pub fn diagnose_vote_locks(finalized_height: Option<u64>) -> Value {
    let finalized_height = finalized_height.or_else(latest_canonical_lock_height);
    let (path, locks, parse_error) = vote_lock_entries();
    let now = now_secs();
    let mut hashes_by_height: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    let mut stale_hashes_by_height: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    let mut above_finalized = Vec::new();
    let mut stale_above_finalized = Vec::new();
    let mut fresh_above_finalized = Vec::new();
    for lock in locks.iter().filter(|lock| {
        finalized_height
            .map(|height| lock.block_index > height)
            .unwrap_or(false)
    }) {
        let age_seconds = now.saturating_sub(lock.updated_at);
        hashes_by_height
            .entry(lock.block_index)
            .or_default()
            .insert(lock.block_hash.clone());
        let item = json!({
            "validator_address": lock.validator_address,
            "height": lock.block_index,
            "block_hash": lock.block_hash,
            "epoch": lock.epoch_number,
            "first_round": lock.first_round_number,
            "latest_round": lock.latest_round_number,
            "proposer": lock.proposer,
            "age_seconds": age_seconds,
        });
        if age_seconds >= DIAGNOSTIC_STALE_TRANSIENT_VOTE_LOCK_SECS {
            stale_hashes_by_height
                .entry(lock.block_index)
                .or_default()
                .insert(lock.block_hash.clone());
            stale_above_finalized.push(item.clone());
        } else {
            fresh_above_finalized.push(item.clone());
        }
        above_finalized.push(item);
    }
    let conflicting_heights = hashes_by_height
        .into_iter()
        .filter(|(_, hashes)| hashes.len() > 1)
        .map(|(height, hashes)| json!({"height": height, "hashes": hashes}))
        .collect::<Vec<_>>();
    let stale_conflicting_heights = stale_hashes_by_height
        .into_iter()
        .filter(|(_, hashes)| hashes.len() > 1)
        .map(|(height, hashes)| json!({"height": height, "hashes": hashes}))
        .collect::<Vec<_>>();

    json!({
        "chain": chain_identity(),
        "vote_lock_path": path,
        "parse_error": parse_error,
        "finalized_height": finalized_height,
        "total_vote_locks": locks.len(),
        "locks_above_finalized": above_finalized.len(),
        "fresh_locks_above_finalized": fresh_above_finalized.len(),
        "stale_locks_above_finalized": stale_above_finalized.len(),
        "stale_threshold_seconds": DIAGNOSTIC_STALE_TRANSIENT_VOTE_LOCK_SECS,
        "conflicting_heights_above_finalized": conflicting_heights,
        "stale_conflicting_heights_above_finalized": stale_conflicting_heights,
        "locks": above_finalized,
        "stale_locks": stale_above_finalized,
        "fresh_locks": fresh_above_finalized,
    })
}

pub fn quarantine_status() -> Value {
    let marker_paths = [
        "data/validator_quarantine.json",
        "data/validator_quarantine_peer_evidence.json",
    ]
    .into_iter()
    .filter_map(|path| {
        let resolved = crate::utils::resolve_data_path(path);
        resolved
            .exists()
            .then(|| resolved.to_string_lossy().to_string())
    })
    .collect::<Vec<_>>();

    let recovery_state = marker_recovery_state(&marker_paths);
    let duty_gate = ValidatorDutyGate::for_state(recovery_state);

    json!({
        "chain": chain_identity(),
        "status": if marker_paths.is_empty() { "healthy" } else { "quarantined" },
        "quarantined": !marker_paths.is_empty(),
        "recovery_state": recovery_state,
        "duty_gate": duty_gate,
        "rejoin_eligibility": recovery_state == RealignmentState::ReadyToRejoin,
        "marker_paths": marker_paths,
    })
}

pub fn divergence_status(chain: &Arc<Mutex<BlockChain>>) -> Value {
    let latest = chain.lock().ok().and_then(|chain| chain.last().cloned());
    json!({
        "chain": chain_identity(),
        "latest_height": latest.as_ref().map(|block| block.block_index),
        "latest_hash": latest.as_ref().map(|block| block.hash.clone()),
        "latest_timestamp": latest.as_ref().map(|block| block.timestamp),
        "canonical_lock_height": latest_canonical_lock_height(),
        "quarantine": quarantine_status(),
        "local_only": true,
        "note": "quorum-peer divergence comparison requires a reconciliation source; this read-only call never chooses a branch by public RPC alone",
    })
}

pub fn diagnose_consensus_stall(chain: &Arc<Mutex<BlockChain>>) -> Value {
    let latest = chain.lock().ok().and_then(|chain| chain.last().cloned());
    let latest_timestamp = latest.as_ref().map(|block| block.timestamp);
    let timestamp_delta_seconds =
        latest_timestamp.map(|timestamp| now_secs().saturating_sub(timestamp));
    let finalized_height = latest_canonical_lock_height();
    let vote_locks = diagnose_vote_locks(finalized_height);
    let stale_locks_above = vote_locks
        .get("stale_locks_above_finalized")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let stale_conflicting_heights = vote_locks
        .get("stale_conflicting_heights_above_finalized")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false);
    let qc = latest_committed_qc();
    let chain_body_canonical_check = latest
        .as_ref()
        .map(|_| {
            chain
                .lock()
                .map_err(|_| "failed to lock chain for canonical durability check".to_string())
                .and_then(|chain| validate_chain_body_covers_canonical_lock(&chain))
        })
        .unwrap_or(Ok(()));
    let mut categories = Vec::new();
    if timestamp_delta_seconds.unwrap_or(0) > 30 {
        categories.push("no_finalized_block_for_timeout");
    }
    if stale_locks_above > 0 {
        categories.push("transient_vote_lock_above_finalized_height");
    }
    if stale_conflicting_heights {
        categories.push("same_height_competing_transient_vote_locks");
    }
    if quarantine_status()
        .get("quarantined")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        categories.push("local_validator_quarantined");
    }
    if chain_body_canonical_check.is_err() {
        categories.push("chain_body_behind_canonical_lock");
    }

    json!({
        "chain": chain_identity(),
        "latest_height": latest.as_ref().map(|block| block.block_index),
        "latest_hash": latest.as_ref().map(|block| block.hash.clone()),
        "latest_timestamp": latest_timestamp,
        "timestamp_delta_seconds": timestamp_delta_seconds,
        "canonical_lock_height": finalized_height,
        "chain_body_canonical_check": match chain_body_canonical_check {
            Ok(()) => json!({"ok": true}),
            Err(error) => json!({"ok": false, "error": error}),
        },
        "latest_committed_qc": qc,
        "vote_locks": vote_locks,
        "categories": categories,
        "stalled": !categories.is_empty(),
        "fail_closed": true,
    })
}

pub fn reconciliation_plan(chain: &Arc<Mutex<BlockChain>>) -> Value {
    let diagnosis = diagnose_consensus_stall(chain);
    let vote_locks = diagnosis
        .get("vote_locks")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let locks_above = vote_locks
        .get("locks_above_finalized")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let quarantined = quarantine_status()
        .get("quarantined")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let recommended_action = if quarantined {
        "self_heal_from_verified_quorum_or_archive_source"
    } else if locks_above > 0 {
        "recover_transient_vote_locks_above_finalized_height"
    } else {
        "observe_or_compare_quorum_peers"
    };
    json!({
        "chain": chain_identity(),
        "recommended_action": recommended_action,
        "diagnosis": diagnosis,
        "mutation_requires_operator_method": true,
        "forbidden_actions": [
            "do_not_regenerate_genesis",
            "do_not_lower_quorum",
            "do_not_copy_keys",
            "do_not_copy_configs",
            "do_not_delete_canonical_locks",
            "do_not_delete_committed_qcs"
        ],
    })
}

pub fn recover_transient_vote_locks(
    finalized_height: Option<u64>,
    min_age_secs: u64,
    reason: &str,
) -> Result<Value, String> {
    require_local_testnet_v2()?;
    let finalized_height = finalized_height
        .or_else(latest_canonical_lock_height)
        .ok_or_else(|| {
            "missing finalized height and no canonical lock file is available".to_string()
        })?;
    let vote_report = DualQuorumConsensus::recover_transient_vote_locks_above_finalized_height(
        finalized_height,
        min_age_secs,
        reason,
    )?;
    let proposal_report = ProofOfSynergy::recover_cached_block_proposals_above_finalized_height(
        finalized_height,
        reason,
    )?;
    Ok(json!({
        "chain": chain_identity(),
        "finalized_height": finalized_height,
        "vote_lock_recovery": vote_report,
        "proposal_cache_recovery": proposal_report,
        "canonical_locks_mutated": false,
        "committed_qcs_mutated": false,
        "keys_or_configs_copied": false,
    }))
}

pub fn self_heal_status() -> Value {
    let quarantine = quarantine_status();
    let recovery_state = quarantine
        .get("recovery_state")
        .cloned()
        .unwrap_or_else(|| json!(RealignmentState::Active));
    json!({
        "chain": chain_identity(),
        "status": recovery_state,
        "lifecycle": [
            "ACTIVE",
            "SUSPECT",
            "QUARANTINED",
            "EVIDENCE_PRESERVED",
            "CHAIN_DATA_WIPE_READY",
            "CHAIN_DATA_WIPED",
            "SNAPSHOT_DISCOVERY",
            "SNAPSHOT_DOWNLOADING",
            "SNAPSHOT_VERIFIED",
            "SNAPSHOT_RESTORED",
            "SPEED_SYNCING",
            "CAUGHT_UP",
            "SHADOW_OBSERVING",
            "SHADOW_PASSED",
            "READY_TO_REJOIN",
            "PENDING_REACTIVATION",
            "ACTIVE"
        ],
        "snapshot_schedule": SnapshotSchedule::launch_default(),
        "shadow_observation_required_blocks": DEFAULT_SHADOW_OBSERVATION_BLOCKS,
        "quarantine": quarantine,
        "manual_state_surgery_allowed": false,
        "fail_closed": true,
    })
}

pub fn start_self_heal() -> Result<Value, String> {
    require_local_testnet_v2()?;
    Ok(json!(fail_closed_mutation_response(
        crate::config::resolve_runtime_validator_address()
            .unwrap_or_else(|| "unknown-validator".to_string()),
        RealignmentState::Quarantined,
        "self-heal requires a verified signed snapshot manifest; use synergy_selfHealFromSnapshot after snapshot verification",
        "data/self-heal-evidence"
    )))
}

pub fn quarantine_stopped_validator_with_options(
    options: OperatorQuarantineOptions,
) -> Result<Value, String> {
    require_local_testnet_v2()?;
    let validator_id = current_validator_id();
    if !options.operator_approved_containment {
        return Ok(json!(fail_closed_mutation_response(
            validator_id,
            RealignmentState::Active,
            "quarantine-stopped-validator requires --operator-approved-containment",
            "data/self-heal-evidence"
        )));
    }
    if !options.target_stopped {
        return Ok(json!(fail_closed_mutation_response(
            validator_id,
            RealignmentState::Active,
            "quarantine-stopped-validator requires --target-stopped confirmation",
            "data/self-heal-evidence"
        )));
    }
    let Some(quorum_majority_height) = options.quorum_majority_height else {
        return Ok(json!(fail_closed_mutation_response(
            validator_id,
            RealignmentState::Active,
            "quarantine-stopped-validator requires --quorum-majority-height",
            "data/self-heal-evidence"
        )));
    };
    let Some(quorum_majority_hash) = options
        .quorum_majority_hash
        .clone()
        .filter(|hash| !hash.trim().is_empty())
    else {
        return Ok(json!(fail_closed_mutation_response(
            validator_id,
            RealignmentState::Active,
            "quarantine-stopped-validator requires --quorum-majority-hash",
            "data/self-heal-evidence"
        )));
    };

    let latest = read_latest_block_summary().ok();
    let detected_height = options
        .local_conflicting_height
        .or_else(|| latest.as_ref().map(|block| block.height))
        .unwrap_or(quorum_majority_height);
    let detected_hash = options
        .local_conflicting_hash
        .clone()
        .or_else(|| latest.as_ref().map(|block| block.hash.clone()))
        .unwrap_or_else(|| quorum_majority_hash.clone());
    let reason = options
        .reason
        .unwrap_or_else(|| "operator_approved_stopped_stale_validator_quarantine".to_string());
    let evidence_path = crate::utils::resolve_data_path(&format!(
        "data/self-heal-evidence/{}-operator-quarantine",
        now_secs()
    ));
    let evidence = preserve_operator_quarantine_evidence(&evidence_path)?;
    let marker = QuarantineMarker::divergence(
        validator_id.clone(),
        reason.clone(),
        detected_height,
        detected_hash.clone(),
        quorum_majority_height,
        quorum_majority_hash.clone(),
        Some(detected_hash.clone()),
        evidence_path.to_string_lossy(),
    );
    let marker_path = crate::utils::resolve_data_path("data/validator_quarantine.json");
    write_json_pretty(
        &marker_path,
        &serde_json::to_value(&marker)
            .map_err(|error| format!("serialize quarantine marker: {error}"))?,
    )?;
    Ok(json!({
        "success": true,
        "typed_status": "QUARANTINED",
        "chain": chain_identity(),
        "validator_id": validator_id,
        "previous_state": "ACTIVE_OR_STOPPED_WITHOUT_MARKER",
        "new_state": "QUARANTINED",
        "reason": reason,
        "detected_height": detected_height,
        "detected_hash": detected_hash,
        "quorum_majority_height": quorum_majority_height,
        "quorum_majority_hash": quorum_majority_hash,
        "evidence_path": evidence_path,
        "marker_path": marker_path,
        "evidence": evidence,
        "duty_gate": ValidatorDutyGate::for_state(RealignmentState::Quarantined),
        "canonical_locks_mutated": false,
        "committed_qcs_mutated": false,
        "chain_state_mutated": false,
        "keys_or_configs_copied": false,
        "genesis_mutated": false,
        "quorum_mutated": false,
        "manual_state_copy_used": false,
        "next_required_action": "verify signed snapshot on target then run self-heal-from-snapshot",
    }))
}

pub fn sync_from_canonical_peer() -> Result<Value, String> {
    sync_from_canonical_peer_with_options(SyncFromCanonicalPeerOptions::default())
}

pub fn sync_from_canonical_peer_with_options(
    options: SyncFromCanonicalPeerOptions,
) -> Result<Value, String> {
    require_local_testnet_v2()?;
    let validator_id = current_validator_id();
    let quarantine = quarantine_status();
    if !quarantine
        .get("quarantined")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(json!(fail_closed_mutation_response(
            validator_id,
            RealignmentState::Active,
            "sync-from-canonical-peer requires local validator quarantine",
            "data/self-heal-evidence"
        )));
    }
    let status = read_self_heal_status_file();
    let previous_state = status_state(status.as_ref()).unwrap_or_else(|| "QUARANTINED".to_string());
    if previous_state != "SNAPSHOT_RESTORED"
        && previous_state != "SPEED_SYNCING"
        && previous_state != "CAUGHT_UP"
        && previous_state != "HEAD_MATCHED"
    {
        return Ok(json!(fail_closed_mutation_response(
            validator_id,
            RealignmentState::Quarantined,
            "speed-sync requires a verified snapshot restore before canonical peer head matching",
            "data/self-heal-evidence"
        )));
    }
    if options.source_peer_quarantined {
        return Ok(json!(fail_closed_mutation_response(
            validator_id,
            RealignmentState::Quarantined,
            "speed-sync source peer is quarantined",
            "data/self-heal-evidence"
        )));
    }
    if !options.source_qc_aegis_pqc_verified
        || !options.parent_continuity_verified
        || !options.state_root_matches
    {
        return Ok(json!(fail_closed_mutation_response(
            validator_id,
            RealignmentState::Quarantined,
            "speed-sync requires verified source QC, parent continuity, and state root/checkpoint match",
            "data/self-heal-evidence"
        )));
    }
    let Some(canonical_height) = options.canonical_height else {
        return Ok(json!(fail_closed_mutation_response(
            validator_id,
            RealignmentState::Quarantined,
            "sync-from-canonical-peer requires canonical_height",
            "data/self-heal-evidence"
        )));
    };
    let Some(canonical_hash) = options
        .canonical_hash
        .clone()
        .filter(|hash| !hash.trim().is_empty())
    else {
        return Ok(json!(fail_closed_mutation_response(
            validator_id,
            RealignmentState::Quarantined,
            "sync-from-canonical-peer requires canonical_hash",
            "data/self-heal-evidence"
        )));
    };
    let local_block = read_block_at_height(canonical_height)?;
    if local_block.hash != canonical_hash {
        return Ok(json!(fail_closed_mutation_response(
            validator_id,
            RealignmentState::Quarantined,
            format!(
                "local block hash {} at height {} does not match verified canonical hash {}",
                local_block.hash, canonical_height, canonical_hash
            ),
            "data/self-heal-evidence"
        )));
    }
    let (local_lock_height, local_lock_hash) = latest_canonical_lock()
        .ok_or_else(|| "missing canonical lock after snapshot restore".to_string())?;
    if local_lock_height < canonical_height {
        return Ok(json!(fail_closed_mutation_response(
            validator_id,
            RealignmentState::Quarantined,
            format!(
                "local canonical lock height {} is behind verified canonical height {}",
                local_lock_height, canonical_height
            ),
            "data/self-heal-evidence"
        )));
    }
    let qc = latest_verified_qc_summary()?;
    vote_locks_clean(local_lock_height)?;
    let status = json!({
        "success": true,
        "typed_status": "HEAD_MATCHED",
        "chain": chain_identity(),
        "validator_id": current_validator_id(),
        "previous_state": previous_state,
        "new_state": "CAUGHT_UP",
        "source_peer": options.source_peer,
        "canonical_height": canonical_height,
        "canonical_hash": canonical_hash,
        "local_canonical_lock_height": local_lock_height,
        "local_canonical_lock_hash": local_lock_hash,
        "latest_committed_qc_height": qc.height,
        "latest_committed_qc_hash": qc.hash,
        "latest_committed_qc_vote_count": qc.vote_count,
        "latest_committed_qc_signers": qc.signers,
        "source_qc_aegis_pqc_verified": true,
        "parent_continuity_verified": true,
        "state_root_matches": true,
        "keys_or_configs_copied": false,
        "genesis_mutated": false,
        "quorum_mutated": false,
        "next_required_action": "start_shadow_observe",
    });
    write_json_pretty(&self_heal_status_path(), &status)?;
    Ok(status)
}

pub fn self_heal_from_archive() -> Result<Value, String> {
    require_local_testnet_v2()?;
    Ok(json!(fail_closed_mutation_response(
        crate::config::resolve_runtime_validator_address()
            .unwrap_or_else(|| "unknown-validator".to_string()),
        RealignmentState::Quarantined,
        "self-heal-from-archive has been superseded by signed snapshot self-heal; refusing archive install without verified snapshot manifest",
        "data/self-heal-evidence"
    )))
}

pub fn snapshot_catalog() -> Value {
    let root = crate::utils::resolve_data_path("data/snapshots");
    let mut snapshots = Vec::new();
    if let Ok(entries) = fs::read_dir(&root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Ok(children) = fs::read_dir(&path) {
                    for child in children.flatten() {
                        let manifest_path = child.path();
                        let is_manifest = manifest_path
                            .file_name()
                            .and_then(|name| name.to_str())
                            .map(|name| name.ends_with("manifest.json"))
                            .unwrap_or(false);
                        if is_manifest {
                            snapshots.push(json!({
                                "path": manifest_path.to_string_lossy(),
                                "snapshot_root": path.to_string_lossy(),
                                "metadata": read_json_file_raw(&manifest_path),
                            }));
                        }
                    }
                }
            } else {
                let is_manifest = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| name.ends_with("manifest.json"))
                    .unwrap_or(false);
                if is_manifest {
                    snapshots.push(json!({
                        "path": path.to_string_lossy(),
                        "snapshot_root": root.to_string_lossy(),
                        "metadata": read_json_file_raw(&path),
                    }));
                }
            }
        }
    }
    json!({
        "chain": chain_identity(),
        "snapshot_root": root.to_string_lossy(),
        "schedule": SnapshotSchedule::launch_default(),
        "snapshots": snapshots,
    })
}

pub fn list_snapshots() -> Value {
    snapshot_catalog()
}

pub fn create_snapshot() -> Result<Value, String> {
    create_snapshot_with_options(CreateSnapshotOptions {
        source_node_majority_branch_proven: env_truthy("SYNERGY_SNAPSHOT_MAJORITY_BRANCH_PROVEN"),
        source_role: std::env::var("SYNERGY_SNAPSHOT_SOURCE_ROLE").ok(),
        conflict_height_hash: std::env::var("SYNERGY_SNAPSHOT_CONFLICT_HEIGHT_HASH").ok(),
        snapshot_class: std::env::var("SYNERGY_SNAPSHOT_CLASS").ok(),
        allowed_restore_roles: std::env::var("SYNERGY_SNAPSHOT_ALLOWED_ROLES")
            .ok()
            .map(|roles| {
                roles
                    .split(',')
                    .map(str::trim)
                    .filter(|role| !role.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
    })
}

pub fn create_snapshot_with_options(options: CreateSnapshotOptions) -> Result<Value, String> {
    require_local_testnet_v2()?;
    if !options.source_node_majority_branch_proven {
        return Err("snapshot creation requires source_node_majority_branch_proven=true; refusing to sign a snapshot from unproven local state".to_string());
    }
    let quarantine = quarantine_status();
    if quarantine
        .get("quarantined")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err("snapshot source is quarantined; refusing snapshot creation".to_string());
    }

    let (latest_canonical_lock_height, latest_canonical_lock_hash) = latest_canonical_lock()
        .ok_or_else(|| {
            "missing canonical_locks.json finalized head; refusing snapshot creation".to_string()
        })?;
    let data_dir = crate::utils::resolve_data_path("data");
    let persisted_chain_tip = read_latest_block_summary()?;
    let persisted_chain_tip_height = persisted_chain_tip.height;
    let persisted_chain_tip_hash = persisted_chain_tip.hash.clone();
    let qc = crate::recovery::verify_latest_committed_qc_in_state_dir_at_or_below(
        &data_dir,
        persisted_chain_tip_height,
        None,
    )?;
    if !qc.verified || qc.vote_count < 4 {
        return Err("latest committed QC is not verified through Aegis/PQC quorum".to_string());
    }
    let snapshot_height = qc.height;
    let block = if persisted_chain_tip.height == snapshot_height {
        persisted_chain_tip
    } else {
        read_block_at_height(snapshot_height)?
    };
    if qc.hash != block.hash {
        return Err(format!(
            "latest committed QC hash {} does not match finalized block hash {} at height {}",
            qc.hash, block.hash, snapshot_height
        ));
    }
    let (canonical_lock_hash, canonical_lock_source, materialized_lock) =
        match canonical_lock_at_height(snapshot_height) {
            Some(hash) => {
                if block.hash != hash {
                    return Err(format!(
                        "canonical lock hash {} does not match block hash {} at height {}",
                        hash, block.hash, snapshot_height
                    ));
                }
                (hash, "canonical_locks.json".to_string(), None)
            }
            None => (
                block.hash.clone(),
                "verified_committed_qc_snapshot_materialization".to_string(),
                Some(SnapshotCanonicalLockMaterialization {
                    block: block.clone(),
                    qc_vote_count: qc.vote_count,
                }),
            ),
        };
    let max_snapshot_lag = SnapshotSchedule::launch_default().interval_finalized_blocks;
    if latest_canonical_lock_height.saturating_sub(snapshot_height) > max_snapshot_lag {
        return Err(format!(
            "latest committed QC height {} is more than {} block(s) behind canonical lock height {}; refusing stale snapshot",
            snapshot_height, max_snapshot_lag, latest_canonical_lock_height
        ));
    }

    let active_validator_set = active_validator_addresses_for_snapshot_height(snapshot_height)?;
    let signer_set = qc.signers.clone();
    let signer_set_unique = signer_set.iter().collect::<BTreeSet<_>>().len() == signer_set.len();
    if !signer_set_unique {
        return Err("latest committed QC contains duplicate signer".to_string());
    }
    if signer_set
        .iter()
        .any(|signer| !active_validator_set.iter().any(|active| active == signer))
    {
        return Err(
            "latest committed QC includes a signer outside the ACTIVE validator set".to_string(),
        );
    }

    let snapshot_root = crate::utils::resolve_data_path("data/snapshots");
    fs::create_dir_all(&snapshot_root)
        .map_err(|error| format!("create snapshot root {}: {error}", snapshot_root.display()))?;
    let created_at = now_secs();
    let snapshot_dir = snapshot_root.join(format!("snapshot-{}-{}", snapshot_height, created_at));
    fs::create_dir_all(&snapshot_dir).map_err(|error| {
        format!(
            "create snapshot directory {}: {error}",
            snapshot_dir.display()
        )
    })?;
    copy_snapshot_state_files(
        &data_dir,
        &snapshot_dir,
        snapshot_height,
        materialized_lock.as_ref(),
    )?;

    let mut signer = AegisPqvmSigner::initialize_required().map_err(|error| error.to_string())?;
    let source_node_id = snapshot_source_node_id();
    let signer_uma = format!("snapshot-source:{source_node_id}");
    let signing_key_id = signer
        .generate_and_register_key(
            &signer_uma,
            vec![AegisPqKeyRole::ArchiveSnapshotSigner],
            Epoch(0),
        )
        .map_err(|error| error.to_string())?;
    let signer_public_key = signer
        .public_key_record(&signing_key_id)
        .map_err(|error| error.to_string())?;
    let snapshot_class = options
        .snapshot_class
        .unwrap_or_else(|| SNAPSHOT_CLASS_VALIDATOR_PRUNED.to_string());
    let allowed_restore_roles = if options.allowed_restore_roles.is_empty() {
        default_allowed_restore_roles_for_class(&snapshot_class)
            .ok_or_else(|| format!("unsupported snapshot class {snapshot_class}"))?
    } else {
        options.allowed_restore_roles
    };
    let manifest = crate::consensus::self_realign::create_snapshot_manifest(SnapshotBuildInput {
        state_dir: snapshot_dir.clone(),
        snapshot_class,
        allowed_restore_roles,
        snapshot_height: block.height,
        snapshot_block_hash: block.hash.clone(),
        parent_hash: block.parent_hash.clone(),
        state_root: None,
        canonical_lock_height: snapshot_height,
        canonical_lock_hash: canonical_lock_hash.clone(),
        qc_evidence: SnapshotQcEvidence {
            committed_qc_height: qc.height,
            committed_qc_hash: qc.hash.clone(),
            vote_count: qc.vote_count,
            signer_set: signer_set.clone(),
            aegis_pqc_verified: qc.verified,
            duplicate_signer_check_passed: signer_set_unique,
            active_validator_set_is_genesis_5: active_validator_set.len() == 5,
            relayers_rpc_support_counted_toward_quorum: false,
        },
        active_validator_set: active_validator_set.clone(),
        source_node_id,
        source_role: options
            .source_role
            .unwrap_or_else(|| "GENESIS_VALIDATOR".to_string()),
        runtime_checksum: current_runtime_checksum()?,
        source_node_quarantined: false,
        source_node_majority_branch: true,
        conflict_height_hash: options.conflict_height_hash,
        manifest_signer_uma_id: signer_uma,
        manifest_signing_key_id: signing_key_id,
        manifest_signer_public_key: signer_public_key,
        manifest_signature_epoch: 0,
        created_at,
    })?;
    let signed = sign_snapshot_manifest(&mut signer, manifest)?;
    let manifest_path = snapshot_dir.join(format!("snapshot-{}-manifest.json", snapshot_height));
    let manifest_bytes = serde_json::to_vec_pretty(&signed)
        .map_err(|error| format!("serialize signed snapshot manifest: {error}"))?;
    fs::write(&manifest_path, manifest_bytes).map_err(|error| {
        format!(
            "write snapshot manifest {}: {error}",
            manifest_path.display()
        )
    })?;
    let verification = verify_signed_snapshot_manifest(
        &signed,
        &SnapshotVerificationPolicy::default(),
        Some(&snapshot_dir),
    );
    if !verification.success {
        return Err(format!(
            "created snapshot failed verification: {}",
            verification.errors.join("; ")
        ));
    }
    snapshot_metadata_consistency_report(&signed, &snapshot_dir).map_err(|error| {
        format!("created snapshot failed materialized-state consistency: {error}")
    })?;
    enforce_snapshot_retention(
        &snapshot_root,
        SnapshotSchedule::launch_default().retain_last,
    )?;
    Ok(json!({
        "success": true,
        "typed_status": "SNAPSHOT_CREATED",
        "chain": chain_identity(),
        "snapshot_height": snapshot_height,
        "snapshot_hash": canonical_lock_hash,
        "persisted_chain_tip_height": persisted_chain_tip_height,
        "persisted_chain_tip_hash": persisted_chain_tip_hash,
        "selected_committed_qc_height": qc.height,
        "snapshot_canonical_lock_source": canonical_lock_source,
        "snapshot_canonical_lock_materialized_in_artifact": materialized_lock.is_some(),
        "latest_canonical_lock_height": latest_canonical_lock_height,
        "latest_canonical_lock_hash": latest_canonical_lock_hash,
        "snapshot_path": snapshot_dir,
        "manifest_path": manifest_path,
        "manifest_hash": verification.manifest_hash,
        "snapshot_artifact_hash": signed.manifest.full_archive_sha256,
        "finalized_state_root": signed.manifest.state_root,
        "source_qc_aegis_pqc_verified": true,
        "qc_vote_count": qc.vote_count,
        "qc_signers": signer_set,
        "active_validator_set": active_validator_set,
        "source_node_majority_branch_proven": true,
        "schedule": SnapshotSchedule::launch_default(),
        "keys_or_configs_copied": false,
        "genesis_mutated": false,
        "quorum_mutated": false,
        "chain_state_mutated": false,
        "canonical_locks_mutated": false,
        "committed_qcs_mutated": false,
    }))
}

pub fn verify_snapshot(manifest_path: &str, snapshot_root: Option<&str>) -> Result<Value, String> {
    verify_snapshot_with_options(
        manifest_path,
        snapshot_root,
        VerifySnapshotOptions::default(),
    )
}

pub fn verify_snapshot_with_options(
    manifest_path: &str,
    snapshot_root: Option<&str>,
    options: VerifySnapshotOptions,
) -> Result<Value, String> {
    require_local_testnet_v2()?;
    let manifest_path = PathBuf::from(manifest_path);
    let signed = read_signed_snapshot_manifest(&manifest_path)?;
    let snapshot_root = resolved_snapshot_root(&manifest_path, snapshot_root)?;
    let mut policy = SnapshotVerificationPolicy::default();
    policy.expected_snapshot_class = options.snapshot_class;
    policy.target_role = options.target_role;
    let report = verify_signed_snapshot_manifest(&signed, &policy, Some(&snapshot_root));
    let mut value = serde_json::to_value(&report)
        .map_err(|error| format!("serialize snapshot verification report: {error}"))?;
    if report.success {
        match snapshot_metadata_consistency_report(&signed, &snapshot_root) {
            Ok(consistency) => {
                if let Some(object) = value.as_object_mut() {
                    object.insert("materialized_state".to_string(), consistency);
                }
            }
            Err(error) => {
                if let Some(object) = value.as_object_mut() {
                    object.insert("success".to_string(), Value::Bool(false));
                    object.insert("fail_closed".to_string(), Value::Bool(true));
                    object.insert(
                        "errors".to_string(),
                        Value::Array(vec![Value::String(error)]),
                    );
                }
            }
        }
    }
    Ok(value)
}

pub fn self_heal_from_snapshot(
    manifest_path: &str,
    snapshot_root: Option<&str>,
) -> Result<Value, String> {
    require_local_testnet_v2()?;
    let manifest_path_buf = PathBuf::from(manifest_path);
    let signed = read_signed_snapshot_manifest(&manifest_path_buf)?;
    let snapshot_root = resolved_snapshot_root(&manifest_path_buf, snapshot_root)?;
    let verification_report = verify_signed_snapshot_manifest(
        &signed,
        &SnapshotVerificationPolicy {
            expected_snapshot_class: Some(SNAPSHOT_CLASS_VALIDATOR_PRUNED.to_string()),
            target_role: Some("validator".to_string()),
            ..SnapshotVerificationPolicy::default()
        },
        Some(&snapshot_root),
    );
    if !verification_report.success {
        return Ok(json!(fail_closed_mutation_response(
            crate::config::resolve_runtime_validator_address()
                .unwrap_or_else(|| "unknown-validator".to_string()),
            RealignmentState::Quarantined,
            "snapshot verification failed; self-heal remains quarantined",
            "data/self-heal-evidence"
        )));
    }
    if let Err(error) = snapshot_metadata_consistency_report(&signed, &snapshot_root) {
        return Ok(json!(fail_closed_mutation_response(
            crate::config::resolve_runtime_validator_address()
                .unwrap_or_else(|| "unknown-validator".to_string()),
            RealignmentState::Quarantined,
            format!("snapshot materialized-state consistency failed: {error}"),
            "data/self-heal-evidence"
        )));
    }
    let quarantine = quarantine_status();
    if !quarantine
        .get("quarantined")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(json!(fail_closed_mutation_response(
            crate::config::resolve_runtime_validator_address()
                .unwrap_or_else(|| "unknown-validator".to_string()),
            RealignmentState::Active,
            "self-heal-from-snapshot requires local validator quarantine before chain data wipe/restore",
            "data/self-heal-evidence"
        )));
    }
    if let Err(reason) = read_standard_quarantine_marker() {
        return Ok(json!(fail_closed_mutation_response(
            crate::config::resolve_runtime_validator_address()
                .unwrap_or_else(|| "unknown-validator".to_string()),
            RealignmentState::Quarantined,
            format!("self-heal-from-snapshot requires standard local quarantine marker: {reason}"),
            "data/self-heal-evidence"
        )));
    }

    let validator_id = crate::config::resolve_runtime_validator_address()
        .unwrap_or_else(|| "unknown-validator".to_string());
    let target_data_dir = crate::utils::resolve_data_path("data");
    let evidence_path = crate::utils::resolve_data_path(&format!(
        "data/self-heal-evidence/{}-snapshot-restore",
        now_secs()
    ));
    let wipe_plan = build_chain_state_wipe_plan(&validator_id, &target_data_dir, &evidence_path)?;
    let wipe_result = apply_chain_state_wipe_plan(
        &wipe_plan,
        WipeApplyPreconditions {
            validator_quarantined: true,
            evidence_preserved: true,
            snapshot_verified: true,
        },
    )?;
    let preserved_stale_shadow_observation =
        preserve_and_remove_stale_shadow_observation(&evidence_path)?;
    let restore_plan = build_snapshot_restore_plan(
        &validator_id,
        &signed,
        snapshot_root.to_string_lossy().to_string(),
        &target_data_dir,
        &verification_report,
    )?;
    let restored_files = restore_snapshot_files(&signed, &snapshot_root, &target_data_dir)?;
    let status_path = crate::utils::resolve_data_path("data/self_heal_status.json");
    let status = json!({
        "success": true,
        "typed_status": "SNAPSHOT_RESTORED",
        "chain": chain_identity(),
        "validator_id": validator_id,
        "previous_state": "QUARANTINED",
        "new_state": "SNAPSHOT_RESTORED",
        "snapshot_manifest_hash": verification_report.manifest_hash,
        "snapshot_height": verification_report.snapshot_height,
        "source_snapshot": snapshot_root,
        "evidence_path": evidence_path,
        "restore_plan": restore_plan,
        "wipe_result": wipe_result,
        "restored_files": restored_files,
        "stale_shadow_observation_invalidated": preserved_stale_shadow_observation.is_some(),
        "preserved_stale_shadow_observation_path": preserved_stale_shadow_observation,
        "canonical_locks_mutated": true,
        "committed_qcs_mutated": true,
        "chain_state_mutated": true,
        "keys_or_configs_copied": false,
        "genesis_mutated": false,
        "quorum_mutated": false,
        "aegis_pqc_verification_result": true,
        "next_required_action": "restart_or_continue_quarantined_node_speed_sync_then_start_shadow_observe",
    });
    if let Some(parent) = status_path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!("create self-heal status dir {}: {error}", parent.display())
        })?;
    }
    fs::write(
        &status_path,
        serde_json::to_vec_pretty(&status)
            .map_err(|error| format!("serialize self-heal status: {error}"))?,
    )
    .map_err(|error| format!("write self-heal status {}: {error}", status_path.display()))?;
    Ok(json!({
        "success": true,
        "typed_status": "SNAPSHOT_RESTORED",
        "chain": chain_identity(),
        "verification": verification_report,
        "evidence_path": evidence_path,
        "restore_plan": restore_plan,
        "wipe_result": wipe_result,
        "restored_files": restored_files,
        "stale_shadow_observation_invalidated": status
            .get("stale_shadow_observation_invalidated")
            .cloned()
            .unwrap_or(Value::Bool(false)),
        "preserved_stale_shadow_observation_path": status
            .get("preserved_stale_shadow_observation_path")
            .cloned()
            .unwrap_or(Value::Null),
        "next_required_action": "restart_or_continue_quarantined_node_speed_sync_then_start_shadow_observe",
        "canonical_locks_mutated": true,
        "committed_qcs_mutated": true,
        "chain_state_mutated": true,
        "keys_or_configs_copied": false,
        "genesis_mutated": false,
        "quorum_mutated": false,
    }))
}

pub fn shadow_status() -> Value {
    let path = shadow_observation_path();
    let Some(observation) = read_json_file_raw(&path) else {
        return json!({
            "chain": chain_identity(),
            "quarantine": quarantine_status(),
            "required_blocks": DEFAULT_SHADOW_OBSERVATION_BLOCKS,
            "epoch_size": SHADOW_REJOIN_EPOCH_SIZE,
            "process_proof_completed": false,
            "full_epoch_shadow_completed": false,
            "rejoin_eligible": false,
            "shadow_signs_real_votes": false,
            "status": "idle_or_not_started",
            "fail_closed": true,
        });
    };
    let start_height = observation
        .get("start_height")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let required_blocks = observation
        .get("required_blocks")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_SHADOW_OBSERVATION_BLOCKS);
    let process_target_height = start_height.saturating_add(required_blocks);
    let latest = latest_canonical_lock();
    let latest_height = latest.as_ref().map(|(height, _)| *height).unwrap_or(0);
    let latest_hash = latest.as_ref().map(|(_, hash)| hash.clone());
    let quarantine = quarantine_status();
    let duty_gate = quarantine
        .get("duty_gate")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let bounds = match shadow_epoch_bounds(start_height, latest_height) {
        Ok(bounds) => bounds,
        Err(error) => {
            return json!({
                "chain": chain_identity(),
                "quarantine": quarantine,
                "shadow_observation_path": path,
                "status": "QUARANTINED",
                "computed_state": "QUARANTINED",
                "start_height": start_height,
                "latest_height": latest_height,
                "latest_hash": latest_hash,
                "target_height": process_target_height,
                "process_target_height": process_target_height,
                "observed_blocks": latest_height.saturating_sub(start_height),
                "observed_shadow_blocks": latest_height.saturating_sub(start_height),
                "required_blocks": required_blocks,
                "epoch_size": SHADOW_REJOIN_EPOCH_SIZE,
                "process_proof_completed": false,
                "full_epoch_shadow_completed": false,
                "rejoin_eligible": false,
                "duty_gate": duty_gate,
                "shadow_signs_real_votes": false,
                "failures": [error],
                "fail_closed": true,
            });
        }
    };
    if latest_height < process_target_height {
        return append_epoch_bounds(
            json!({
                "chain": chain_identity(),
                "quarantine": quarantine,
                "shadow_observation_path": path,
                "status": "SHADOW_OBSERVING",
                "computed_state": "SHADOW_OBSERVING",
                "start_height": start_height,
                "latest_height": latest_height,
                "latest_hash": latest_hash,
                "target_height": process_target_height,
                "process_target_height": process_target_height,
                "observed_blocks": latest_height.saturating_sub(start_height),
                "observed_shadow_blocks": latest_height.saturating_sub(start_height),
                "required_blocks": required_blocks,
                "process_proof_completed": false,
                "full_epoch_shadow_completed": false,
                "rejoin_eligible": false,
                "duty_gate": duty_gate,
                "last_observed_height": latest_height,
                "last_observed_hash": latest_hash,
                "mismatch_count": 0,
                "missed_observation_count": process_target_height.saturating_sub(latest_height),
                "shadow_signs_real_votes": false,
                "fail_closed": false,
                "epoch_bounds": epoch_bounds_json(&bounds),
            }),
            &bounds,
        );
    }
    let mut failures = Vec::new();
    let vote_lock_report = match vote_locks_clean(latest_height) {
        Ok(report) => report,
        Err(error) => {
            failures.push(error);
            json!({})
        }
    };
    if let Err(error) = latest_verified_qc_summary() {
        failures.push(error);
    }
    let full_epoch_shadow_completed = latest_height >= bounds.required_full_shadow_epoch_end;
    let (evaluation_start, evaluation_end, evaluation_required, process_proof_completed) =
        if full_epoch_shadow_completed {
            (
                bounds.required_full_shadow_epoch_start,
                bounds.required_full_shadow_epoch_end,
                bounds.epoch_size,
                true,
            )
        } else {
            (
                start_height.saturating_add(1),
                process_target_height,
                required_blocks,
                true,
            )
        };
    let evaluated_shadow = match evaluate_shadow_block_range(
        current_validator_id(),
        evaluation_start,
        evaluation_end,
        evaluation_required,
    ) {
        Ok(evaluated) => evaluated,
        Err(error) => {
            failures.push(error);
            ShadowObservation::new(current_validator_id(), evaluation_required).evaluate()
        }
    };
    if !evaluated_shadow.failures.is_empty() {
        failures.extend(evaluated_shadow.failures.clone());
    }
    let observed_shadow_blocks = evaluated_shadow.records.len() as u64;
    let missed_observation_count = evaluation_required.saturating_sub(observed_shadow_blocks);
    let last_record = evaluated_shadow.records.last();
    let last_observed_height = last_record
        .map(|record| record.height)
        .unwrap_or(latest_height);
    let last_observed_hash = last_record
        .map(|record| record.canonical_hash.clone())
        .or(latest_hash.clone());
    let canonical_match_count = evaluated_shadow
        .records
        .iter()
        .filter(|record| {
            record.would_have_voted_hash.as_deref() == Some(record.canonical_hash.as_str())
                && record
                    .would_have_proposed_hash
                    .as_deref()
                    .map(|hash| hash == record.canonical_hash.as_str())
                    .unwrap_or(true)
                && record.state_root_matches
                && !record.rejected_valid_majority_block
                && !record.accepted_conflicting_block
        })
        .count() as u64;
    let mismatch_count = observed_shadow_blocks.saturating_sub(canonical_match_count)
        + evaluated_shadow.failures.len() as u64;
    let runtime_boundary_assessment = shadow_boundary_assessment(
        &bounds,
        latest_height,
        failures.is_empty() && full_epoch_shadow_completed,
        !failures.is_empty(),
    );
    let epoch_rejoin_window_open = failures.is_empty()
        && full_epoch_shadow_completed
        && latest_height >= bounds.earliest_activation_height
        && latest_height % bounds.epoch_size == 0;
    let status = if failures.is_empty() {
        if full_epoch_shadow_completed {
            "SHADOW_PASSED"
        } else {
            "PROCESS_PROOF_PASS"
        }
    } else {
        "QUARANTINED"
    };
    let computed_state = if failures.is_empty() && full_epoch_shadow_completed {
        "SHADOW_PASSED"
    } else if failures.is_empty() {
        "SHADOW_OBSERVING"
    } else {
        "QUARANTINED"
    };
    append_epoch_bounds(
        json!({
            "chain": chain_identity(),
            "quarantine": quarantine,
            "shadow_observation_path": path,
            "status": status,
            "computed_state": computed_state,
            "start_height": start_height,
            "latest_height": latest_height,
            "latest_hash": latest_hash,
            "target_height": process_target_height,
            "process_target_height": process_target_height,
            "observed_blocks": observed_shadow_blocks,
            "observed_shadow_blocks": observed_shadow_blocks,
            "required_blocks": required_blocks,
            "evaluation_start_height": evaluation_start,
            "evaluation_end_height": evaluation_end,
            "process_proof_completed": process_proof_completed,
            "full_epoch_shadow_completed": failures.is_empty() && full_epoch_shadow_completed,
            "epoch_rejoin_window_open": epoch_rejoin_window_open,
            "last_eligible_boundary": runtime_boundary_assessment.get("last_eligible_boundary").cloned().unwrap_or(Value::Null),
            "next_eligible_boundary": runtime_boundary_assessment.get("next_eligible_boundary").cloned().unwrap_or(Value::Null),
            "missed_boundary": runtime_boundary_assessment.get("missed_boundary").cloned().unwrap_or(json!(false)),
            "last_missed_boundary": runtime_boundary_assessment.get("last_missed_boundary").cloned().unwrap_or(Value::Null),
            "missed_boundary_reason": runtime_boundary_assessment.get("missed_boundary_reason").cloned().unwrap_or(Value::Null),
            "runtime_boundary_assessment": runtime_boundary_assessment,
            "rejoin_eligible": false,
            "duty_gate": duty_gate,
            "last_observed_height": last_observed_height,
            "last_observed_hash": last_observed_hash,
            "canonical_match_count": canonical_match_count,
            "mismatch_count": mismatch_count,
            "missed_observation_count": missed_observation_count,
            "shadow_signs_real_votes": false,
            "would_have_voted_conflicts": 0,
            "would_have_proposed_conflicts": 0,
            "accepted_conflicting_block": false,
            "rejected_valid_majority_block": false,
            "state_root_matches": failures.is_empty(),
            "records": evaluated_shadow.records,
            "vote_locks": vote_lock_report,
            "failures": failures,
            "fail_closed": !failures.is_empty(),
            "epoch_bounds": epoch_bounds_json(&bounds),
        }),
        &bounds,
    )
}

pub fn start_shadow_observe() -> Result<Value, String> {
    start_shadow_observe_with_options(StartShadowObserveOptions::default())
}

pub fn start_shadow_observe_with_options(
    options: StartShadowObserveOptions,
) -> Result<Value, String> {
    require_local_testnet_v2()?;
    let quarantine = quarantine_status();
    let validator_id = current_validator_id();
    if !quarantine
        .get("quarantined")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(json!(fail_closed_mutation_response(
            validator_id,
            RealignmentState::Active,
            "shadow observation requires local validator quarantine",
            "data/self-heal-evidence"
        )));
    }
    let status = read_self_heal_status_file();
    let previous_state = status_state(status.as_ref()).unwrap_or_else(|| "QUARANTINED".to_string());
    if previous_state != "CAUGHT_UP" && previous_state != "HEAD_MATCHED" {
        return Ok(json!(fail_closed_mutation_response(
            validator_id,
            RealignmentState::Quarantined,
            "shadow observation requires verified speed-sync/head-match proof first",
            "data/self-heal-evidence"
        )));
    }
    let (start_height, start_hash) = latest_canonical_lock()
        .ok_or_else(|| "missing canonical lock before shadow observe".to_string())?;
    let qc = latest_verified_qc_summary()?;
    vote_locks_clean(start_height)?;
    let required_blocks = options
        .required_blocks
        .filter(|blocks| *blocks > 0)
        .unwrap_or(DEFAULT_SHADOW_OBSERVATION_BLOCKS);
    let epoch_bounds = shadow_epoch_bounds(start_height, start_height)?;
    let observation = json!({
        "success": true,
        "typed_status": "SHADOW_OBSERVING",
        "chain": chain_identity(),
        "validator_id": validator_id,
        "previous_state": previous_state,
        "new_state": "SHADOW_OBSERVING",
        "start_height": start_height,
        "start_hash": start_hash,
        "required_blocks": required_blocks,
        "process_target_height": start_height.saturating_add(required_blocks),
        "process_proof_completed": false,
        "full_epoch_shadow_completed": false,
        "rejoin_eligible": false,
        "started_at": now_secs(),
        "latest_committed_qc_height": qc.height,
        "latest_committed_qc_hash": qc.hash,
        "latest_committed_qc_vote_count": qc.vote_count,
        "latest_committed_qc_signers": qc.signers,
        "epoch_bounds": epoch_bounds_json(&epoch_bounds),
        "epoch_size": epoch_bounds.epoch_size,
        "shadow_start_epoch": epoch_bounds.shadow_start_epoch,
        "current_epoch_start": epoch_bounds.current_epoch_start,
        "current_epoch_end": epoch_bounds.current_epoch_end,
        "partial_epoch_start": epoch_bounds.partial_epoch_start,
        "partial_epoch_end": epoch_bounds.partial_epoch_end,
        "required_full_shadow_epoch_start": epoch_bounds.required_full_shadow_epoch_start,
        "required_full_shadow_epoch_end": epoch_bounds.required_full_shadow_epoch_end,
        "earliest_activation_height": epoch_bounds.earliest_activation_height,
        "shadow_signs_real_votes": false,
        "keys_or_configs_copied": false,
        "genesis_mutated": false,
        "quorum_mutated": false,
        "next_required_action": "complete process proof, continue through full required epoch, then request rejoin at earliest epoch boundary only",
    });
    write_json_pretty(&shadow_observation_path(), &observation)?;
    write_json_pretty(&self_heal_status_path(), &observation)?;
    Ok(observation)
}

pub fn rejoin_eligibility() -> Value {
    let shadow = shadow_status();
    let shadow_passed =
        shadow.get("computed_state").and_then(Value::as_str) == Some("SHADOW_PASSED");
    let process_proof_only =
        shadow.get("status").and_then(Value::as_str) == Some("PROCESS_PROOF_PASS");
    let mut blocked_reasons = Vec::new();
    if process_proof_only {
        blocked_reasons.push(
            "500-block process proof is not rejoin eligibility; full epoch shadow is required"
                .to_string(),
        );
    }
    if shadow
        .get("full_epoch_shadow_completed")
        .and_then(Value::as_bool)
        != Some(true)
    {
        blocked_reasons
            .push("rejoin requires a continuously observed full shadow epoch".to_string());
    }
    if let Some(earliest) = shadow
        .get("earliest_activation_height")
        .and_then(Value::as_u64)
    {
        blocked_reasons.push(format!(
            "earliest activation height is {earliest}; rejoin must be requested at that epoch boundary or a later epoch boundary"
        ));
    }
    if shadow
        .get("missed_boundary")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        if let Some(reason) = shadow.get("missed_boundary_reason").and_then(Value::as_str) {
            blocked_reasons.push(format!("missed rejoin boundary: {reason}"));
        } else {
            blocked_reasons.push("missed rejoin boundary".to_string());
        }
        if let Some(next) = shadow.get("next_eligible_boundary").and_then(Value::as_u64) {
            blocked_reasons.push(format!(
                "next eligible epoch boundary is {next}; pre-arm or request rejoin before that boundary"
            ));
        }
    }
    let runtime_boundary_assessment = shadow
        .get("runtime_boundary_assessment")
        .cloned()
        .unwrap_or(Value::Null);
    if shadow_passed {
        return json!({
            "chain": chain_identity(),
            "eligible": false,
            "fail_closed": true,
            "quarantine": quarantine_status(),
            "shadow": shadow,
            "runtime_boundary_assessment": runtime_boundary_assessment,
            "blocked_reasons": [
                "request-rejoin requires fresh exact common-height match proof",
                "request-rejoin requires latest finalized QC verified through Aegis/PQC",
                "request-rejoin requires finalized safe boundary proof",
                "request-rejoin requires explicit operator-approved reactivation"
            ],
        });
    }
    blocked_reasons.extend([
        "rejoin requires SHADOW_PASSED".to_string(),
        "rejoin requires exact common-height hash match".to_string(),
        "rejoin requires latest finalized QC verified through Aegis/PQC".to_string(),
        "rejoin requires finalized safe boundary".to_string(),
    ]);
    json!({
        "chain": chain_identity(),
        "eligible": false,
        "fail_closed": true,
        "quarantine": quarantine_status(),
        "shadow": shadow,
        "runtime_boundary_assessment": runtime_boundary_assessment,
        "blocked_reasons": blocked_reasons,
    })
}

pub fn request_rejoin() -> Result<Value, String> {
    request_rejoin_with_options(RejoinRequestOptions::default())
}

pub fn request_rejoin_with_options(options: RejoinRequestOptions) -> Result<Value, String> {
    require_local_testnet_v2()?;
    let validator_id = current_validator_id();
    let quarantine = quarantine_status();
    if !quarantine
        .get("quarantined")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(json!(fail_closed_mutation_response(
            validator_id,
            RealignmentState::Active,
            "request-rejoin requires local validator quarantine marker",
            "data/self-heal-evidence"
        )));
    }
    let shadow = shadow_status();
    let shadow_passed =
        shadow.get("computed_state").and_then(Value::as_str) == Some("SHADOW_PASSED");
    let Some(common_height) = options.common_height else {
        return Ok(json!(fail_closed_mutation_response(
            validator_id,
            RealignmentState::ReadyToRejoin,
            "request-rejoin requires common_height",
            "data/self-heal-evidence"
        )));
    };
    let Some(common_hash) = options
        .common_hash
        .clone()
        .filter(|hash| !hash.trim().is_empty())
    else {
        return Ok(json!(fail_closed_mutation_response(
            validator_id,
            RealignmentState::ReadyToRejoin,
            "request-rejoin requires common_hash",
            "data/self-heal-evidence"
        )));
    };
    let epoch_size = shadow.get("epoch_size").and_then(Value::as_u64);
    let earliest_activation_height = shadow
        .get("earliest_activation_height")
        .and_then(Value::as_u64);
    let full_epoch_shadow_completed = shadow
        .get("full_epoch_shadow_completed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut epoch_blockers = Vec::new();
    match epoch_size {
        Some(size) if size == SHADOW_REJOIN_EPOCH_SIZE && size > 0 => {
            if common_height % size != 0 {
                epoch_blockers.push(format!(
                    "request-rejoin common_height {common_height} is not an epoch boundary for epoch_size {size}"
                ));
            }
        }
        Some(size) => epoch_blockers.push(format!(
            "request-rejoin refused: shadow epoch_size {size} is inconsistent with expected {SHADOW_REJOIN_EPOCH_SIZE}"
        )),
        None => epoch_blockers
            .push("request-rejoin refused: shadow epoch_size is missing".to_string()),
    }
    match earliest_activation_height {
        Some(earliest) => {
            if common_height < earliest {
                epoch_blockers.push(format!(
                    "request-rejoin common_height {common_height} is before earliest_activation_height {earliest}"
                ));
            }
        }
        None => epoch_blockers
            .push("request-rejoin refused: earliest_activation_height is missing".to_string()),
    }
    if !full_epoch_shadow_completed {
        epoch_blockers
            .push("request-rejoin requires a continuously observed full shadow epoch".to_string());
    }
    if !shadow_passed {
        epoch_blockers.push(
            "request-rejoin refused: 500-block process proof is not SHADOW_PASSED".to_string(),
        );
    }
    if !epoch_blockers.is_empty() {
        return Ok(fail_closed_rejoin_response(
            &validator_id,
            if shadow_passed {
                "SHADOW_PASSED"
            } else {
                "QUARANTINED"
            },
            epoch_blockers,
            shadow,
        ));
    }
    let local_block = read_block_at_height(common_height)?;
    let local_common_match = local_block.hash == common_hash;
    let qc = latest_verified_qc_summary()?;
    let lock_height = latest_canonical_lock_height().unwrap_or(0);
    vote_locks_clean(lock_height)?;
    let report = crate::consensus::self_realign::evaluate_rejoin_eligibility(
        crate::consensus::self_realign::RejoinEligibilityInput {
            validator_id: validator_id.clone(),
            state: if shadow_passed {
                RealignmentState::ShadowPassed
            } else {
                RealignmentState::Quarantined
            },
            shadow_passed,
            exact_common_height_match: options.exact_common_height_match && local_common_match,
            latest_finalized_qc_aegis_pqc_verified: options.latest_finalized_qc_aegis_pqc_verified
                && qc.verified
                && qc.vote_count >= 4,
            no_stale_vote_locks_above_finalized: true,
            no_proposal_cache_conflicts_above_finalized: true,
            quarantine_reason_cleared: true,
            chain_id: configured_chain_id(),
            network_id: configured_network_id(),
            genesis_hash: configured_genesis_hash(),
            state_root_matches: options.state_root_matches,
            own_validator_key_intact: true,
            keys_or_configs_copied: false,
            rejoin_at_finalized_safe_boundary: options.rejoin_at_finalized_safe_boundary,
            cluster_marks_pending_reactivation: options.cluster_marks_pending_reactivation,
        },
    );
    if !options.operator_approved_reactivation {
        let mut blocked = report.blocked_reasons.clone();
        blocked.push("operator-approved reactivation flag is required".to_string());
        return Ok(json!({
            "success": false,
            "typed_status": "FAILED_CLOSED",
            "chain": chain_identity(),
            "validator_id": validator_id,
            "previous_state": report.previous_state,
            "new_state": "QUARANTINED",
            "blocked_reasons": blocked,
            "shadow": shadow,
            "keys_or_configs_copied": false,
            "genesis_mutated": false,
            "quorum_mutated": false,
        }));
    }
    if !report.eligible {
        return Ok(json!({
            "success": false,
            "typed_status": "FAILED_CLOSED",
            "chain": chain_identity(),
            "validator_id": validator_id,
            "previous_state": report.previous_state,
            "new_state": report.new_state,
            "blocked_reasons": report.blocked_reasons,
            "shadow": shadow,
            "keys_or_configs_copied": false,
            "genesis_mutated": false,
            "quorum_mutated": false,
        }));
    }

    let evidence_path =
        crate::utils::resolve_data_path(&format!("data/self-heal-evidence/{}-rejoin", now_secs()));
    let preserved_quarantine_markers = preserve_and_remove_quarantine_markers(&evidence_path)?;
    let status = json!({
        "success": true,
        "typed_status": "ACTIVE",
        "chain": chain_identity(),
        "validator_id": validator_id,
        "previous_state": "SHADOW_PASSED",
        "new_state": "ACTIVE",
        "common_height": common_height,
        "common_hash": common_hash,
        "latest_committed_qc_height": qc.height,
        "latest_committed_qc_hash": qc.hash,
        "latest_committed_qc_vote_count": qc.vote_count,
        "latest_committed_qc_signers": qc.signers,
        "evidence_path": evidence_path,
        "preserved_quarantine_markers": preserved_quarantine_markers,
        "canonical_locks_mutated": false,
        "committed_qcs_mutated": false,
        "chain_state_mutated": false,
        "keys_or_configs_copied": false,
        "genesis_mutated": false,
        "quorum_mutated": false,
        "aegis_pqc_verification_result": true,
        "next_required_action": "verify_five_validator_common_height_alignment",
    });
    write_json_pretty(&self_heal_status_path(), &status)?;
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::{
        active_validator_addresses_for_snapshot_height, copy_snapshot_state_files,
        create_snapshot_with_options, diagnose_consensus_stall, enforce_snapshot_retention,
        quarantine_status, quarantine_stopped_validator_with_options, read_block_at_height,
        read_latest_block_summary, rejoin_eligibility, request_rejoin_with_options,
        self_heal_from_snapshot, shadow_status, snapshot_metadata_consistency_report,
        start_shadow_observe_with_options, sync_from_canonical_peer_with_options, BlockSummary,
        CommittedBlockLogEntry, CreateSnapshotOptions, OperatorQuarantineOptions,
        RejoinRequestOptions, SnapshotCanonicalLockMaterialization, StartShadowObserveOptions,
        SyncFromCanonicalPeerOptions, DIAGNOSTIC_STALE_TRANSIENT_VOTE_LOCK_SECS, EXPECTED_CHAIN_ID,
        EXPECTED_NETWORK_ID,
    };
    use crate::block::{Block, BlockChain};
    use crate::config::NodeConfig;
    use crate::consensus::consensus_fork;
    use crate::consensus::self_realign::{
        create_snapshot_manifest, sign_snapshot_manifest, QuarantineMarker, SnapshotBuildInput,
        SnapshotQcEvidence, SNAPSHOT_CLASS_VALIDATOR_PRUNED,
    };
    use crate::crypto::aegis_pqvm::AegisPqvmSigner;
    use crate::crypto::pqc::{PQCAlgorithm, PQCManager};
    use crate::synergy_types::{AegisPqKeyRole, Epoch};
    use base64::engine::general_purpose;
    use base64::Engine as _;
    use serde_json::{json, Value};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    static DIAGNOSTICS_TEST_ENV_LOCK: Mutex<()> = Mutex::new(());

    fn now_secs_for_test() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn test_runtime_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "synergy-diagnostics-{name}-{}-{}",
            std::process::id(),
            now_secs_for_test()
        ));
        fs::create_dir_all(root.join("config")).expect("test config dir should be created");
        fs::create_dir_all(root.join("data")).expect("test data dir should be created");
        root
    }

    fn install_test_genesis(root: &Path) {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let source = manifest_dir
            .parent()
            .unwrap_or(&manifest_dir)
            .join("config/genesis.json");
        fs::copy(source, root.join("config/genesis.json")).expect("test genesis should be copied");
    }

    fn install_mutated_test_genesis(root: &Path) {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let source = manifest_dir
            .parent()
            .unwrap_or(&manifest_dir)
            .join("config/genesis.json");
        let mut genesis: Value =
            serde_json::from_slice(&fs::read(source).expect("test genesis should be readable"))
                .expect("test genesis should parse");
        genesis["integrity"]["genesis_hash"] = Value::String("bad-genesis-hash".to_string());
        fs::write(
            root.join("config/genesis.json"),
            serde_json::to_vec_pretty(&genesis).expect("mutated genesis should serialize"),
        )
        .expect("mutated test genesis should be written");
    }

    fn install_test_config(root: &Path, chain_id: u64, network_id: &str) {
        let mut config = NodeConfig::default();
        config.network.id = chain_id;
        config.network.network_id = network_id.to_string();
        config.blockchain.chain_id = chain_id;
        fs::write(
            root.join("config/node.toml"),
            toml::to_string_pretty(&config).expect("test config should serialize"),
        )
        .expect("test node config should be written");
    }

    fn install_test_consensus_fork(root: &Path, validators: &[String]) {
        let registry = validators
            .iter()
            .enumerate()
            .map(|(index, validator_address)| {
                json!({
                    "validator_address": validator_address,
                    "consensus_key_type": "FN-DSA",
                    "consensus_public_key": format!(
                        "fn-dsa:{}",
                        general_purpose::STANDARD.encode(format!("validator-{index}-fndsa-key"))
                    ),
                })
            })
            .collect::<Vec<_>>();
        fs::write(
            root.join("config/consensus-fork-migration.json"),
            serde_json::to_vec_pretty(&json!({
                "fork_height": 204216,
                "parent_height": 204215,
                "parent_hash": "e209bd7554a06dfb052d5ff7ffd5664efc05e6cd1c5cadc9d139fa5bb9072816",
                "state_root": "test-state-root",
                "old_consensus_algorithm": "ML-DSA-65",
                "new_consensus_algorithm": "FN-DSA",
                "new_validator_registry": registry,
                "migration_reason": "test fork registry overlay",
                "parser_mode": "fail_closed",
            }))
            .expect("test fork migration should serialize"),
        )
        .expect("test fork migration should be written");
    }

    fn operator_quarantine_options() -> OperatorQuarantineOptions {
        OperatorQuarantineOptions {
            reason: Some("operator approved stale stopped validator containment".to_string()),
            target_stopped: true,
            operator_approved_containment: true,
            quorum_majority_height: Some(87892),
            quorum_majority_hash: Some("majority-hash".to_string()),
            local_conflicting_height: Some(84117),
            local_conflicting_hash: Some("local-stale-hash".to_string()),
        }
    }

    fn write_minimal_chain_state(root: &Path) {
        fs::write(
            root.join("data/chain.json"),
            json!([{
                "height": 84117,
                "hash": "local-stale-hash",
                "parent_hash": "local-parent-hash",
            }])
            .to_string(),
        )
        .expect("test chain state should be written");
        write_canonical_lock(root);
        fs::write(
            root.join("data/committed_qcs.jsonl"),
            b"{\"height\":84117}\n",
        )
        .expect("test committed QC tail should be written");
        fs::write(root.join("data/consensus_vote_locks.json"), b"{}")
            .expect("test vote locks should be written");
    }

    fn operator_quarantine(root: &Path) -> Value {
        with_runtime_root(root, || {
            quarantine_stopped_validator_with_options(operator_quarantine_options())
                .expect("operator quarantine should succeed with explicit proof")
        })
    }

    fn write_valid_signed_snapshot(root: &Path) -> (PathBuf, PathBuf) {
        let snapshot_root = root.join("snapshot-root");
        fs::create_dir_all(&snapshot_root).expect("snapshot root should be created");
        fs::write(
            snapshot_root.join("chain.json"),
            serde_json::to_vec(&json!([{
                "block_index": 100,
                "hash": "snapshot-block-hash",
                "previous_hash": "snapshot-parent-hash",
                "transactions": [],
                "validator_id": "validator-3",
                "nonce": 100
            }]))
            .expect("snapshot chain should serialize"),
        )
        .expect("snapshot chain should be written");
        fs::write(
            snapshot_root.join("canonical_locks.json"),
            serde_json::to_vec(&json!({
                "100": {
                    "height": 100,
                    "hash": "snapshot-block-hash"
                }
            }))
            .expect("snapshot lock should serialize"),
        )
        .expect("snapshot locks should be written");
        fs::write(
            snapshot_root.join("committed_qcs.jsonl"),
            serde_json::to_string(&json!({
                "block_hash": "snapshot-qc-hash",
                "qc": {
                    "block_hash": "snapshot-qc-hash",
                    "votes": [{"block_index": 100}]
                }
            }))
            .expect("snapshot QC should serialize")
                + "\n",
        )
        .expect("snapshot QCs should be written");

        let mut signer = AegisPqvmSigner::initialize_required().expect("test signer should init");
        let key_id = signer
            .generate_and_register_key(
                "archive-1",
                vec![AegisPqKeyRole::ArchiveSnapshotSigner],
                Epoch(0),
            )
            .expect("test snapshot key should be generated");
        let public_key = signer
            .public_key_record(&key_id)
            .expect("test public key should be available");
        let qc_evidence = SnapshotQcEvidence {
            committed_qc_height: 100,
            committed_qc_hash: "snapshot-qc-hash".to_string(),
            vote_count: 4,
            signer_set: vec![
                "validator-1".to_string(),
                "validator-2".to_string(),
                "validator-3".to_string(),
                "validator-4".to_string(),
            ],
            aegis_pqc_verified: true,
            duplicate_signer_check_passed: true,
            active_validator_set_is_genesis_5: true,
            relayers_rpc_support_counted_toward_quorum: false,
        };
        let manifest = create_snapshot_manifest(SnapshotBuildInput {
            state_dir: snapshot_root.clone(),
            snapshot_class: SNAPSHOT_CLASS_VALIDATOR_PRUNED.to_string(),
            allowed_restore_roles: vec!["validator".to_string()],
            snapshot_height: 100,
            snapshot_block_hash: "snapshot-block-hash".to_string(),
            parent_hash: "snapshot-parent-hash".to_string(),
            state_root: None,
            canonical_lock_height: 100,
            canonical_lock_hash: "snapshot-block-hash".to_string(),
            qc_evidence,
            active_validator_set: (1..=5).map(|index| format!("validator-{index}")).collect(),
            source_node_id: "validator-3".to_string(),
            source_role: "GENESIS_VALIDATOR".to_string(),
            runtime_checksum: "runtime-sha256".to_string(),
            source_node_quarantined: false,
            source_node_majority_branch: true,
            conflict_height_hash: Some("snapshot-block-hash".to_string()),
            manifest_signer_uma_id: "archive-1".to_string(),
            manifest_signing_key_id: key_id,
            manifest_signer_public_key: public_key,
            manifest_signature_epoch: 0,
            created_at: 1,
        })
        .expect("test snapshot manifest should build");
        let signed =
            sign_snapshot_manifest(&mut signer, manifest).expect("test snapshot should sign");
        let manifest_path = snapshot_root.join("snapshot-100-manifest.json");
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&signed).expect("signed manifest should serialize"),
        )
        .expect("signed manifest should be written");
        (snapshot_root, manifest_path)
    }

    fn write_vote_lock(root: &Path, updated_at: u64, second_hash: Option<&str>) {
        let mut locks = serde_json::Map::new();
        locks.insert(
            "synv1a:101".to_string(),
            json!({
                "validator_address": "synv1a",
                "block_hash": "hash-a",
                "block_index": 101,
                "epoch_number": 0,
                "first_round_number": 1,
                "latest_round_number": 1,
                "proposer": "synv1leader",
                "created_at": updated_at,
                "updated_at": updated_at,
            }),
        );
        if let Some(hash) = second_hash {
            locks.insert(
                "synv1b:101".to_string(),
                json!({
                    "validator_address": "synv1b",
                    "block_hash": hash,
                    "block_index": 101,
                    "epoch_number": 0,
                    "first_round_number": 1,
                    "latest_round_number": 1,
                    "proposer": "synv1leader2",
                    "created_at": updated_at,
                    "updated_at": updated_at,
                }),
            );
        }
        fs::write(
            root.join("data/consensus_vote_locks.json"),
            Value::Object(locks).to_string(),
        )
        .expect("test vote locks should be written");
    }

    fn write_canonical_lock(root: &Path) {
        fs::write(
            root.join("data/canonical_locks.json"),
            json!({
                "100": {
                    "block_hash": "finalized-hash",
                    "qc_hash": "qc-hash"
                }
            })
            .to_string(),
        )
        .expect("test canonical lock should be written");
    }

    fn test_hash(height: u64) -> String {
        format!("hash-{height}")
    }

    fn write_chain_range(root: &Path, start_height: u64, end_height: u64) {
        let blocks = (start_height..=end_height)
            .map(|height| {
                json!({
                    "height": height,
                    "hash": test_hash(height),
                    "parent_hash": height.checked_sub(1).map(test_hash).unwrap_or_default(),
                })
            })
            .collect::<Vec<_>>();
        fs::write(
            root.join("data/chain.json"),
            serde_json::to_vec(&blocks).expect("test chain should serialize"),
        )
        .expect("test chain should be written");
    }

    fn write_canonical_lock_at_height(root: &Path, height: u64) {
        let mut locks = serde_json::Map::new();
        locks.insert(
            height.to_string(),
            json!({
                "block_hash": test_hash(height),
                "qc_hash": format!("qc-{height}")
            }),
        );
        fs::write(
            root.join("data/canonical_locks.json"),
            Value::Object(locks).to_string(),
        )
        .expect("test canonical lock should be written");
    }

    fn write_empty_vote_locks(root: &Path) {
        fs::write(root.join("data/consensus_vote_locks.json"), b"{}")
            .expect("test vote locks should be written");
    }

    fn write_shadow_observation(root: &Path, start_height: u64, required_blocks: u64) {
        fs::write(
            root.join("data/shadow_observation.json"),
            json!({
                "success": true,
                "typed_status": "SHADOW_OBSERVING",
                "start_height": start_height,
                "start_hash": test_hash(start_height),
                "required_blocks": required_blocks,
                "shadow_signs_real_votes": false,
            })
            .to_string(),
        )
        .expect("test shadow observation should be written");
    }

    fn write_legacy_qc_fixture_at_height(root: &Path, height: u64) {
        let mut manager = PQCManager::new();
        let mut validators = serde_json::Map::new();
        let mut keys = Vec::new();
        for index in 0..5 {
            let address = format!("synv11testvalidator{index}");
            let (public_key, private_key) = manager
                .generate_keypair(PQCAlgorithm::FNDSA)
                .expect("test PQC keypair should be generated");
            validators.insert(
                address.clone(),
                json!({
                    "address": address,
                    "status": "Active",
                    "public_key": format!(
                        "fn-dsa:{}",
                        general_purpose::STANDARD.encode(&public_key.key_data)
                    ),
                    "synergy_score": 100.0,
                    "cluster_id": 0,
                }),
            );
            keys.push((address, public_key, private_key));
        }
        fs::write(
            root.join("data/validator_registry.json"),
            json!({
                "validators": validators,
                "clusters": {"0": []},
                "current_epoch": 0,
            })
            .to_string(),
        )
        .expect("test validator registry should be written");

        let block_hash = test_hash(height);
        let votes = keys
            .iter()
            .take(4)
            .map(|(address, public_key, private_key)| {
                let payload = format!("{address}:{height}:0:{block_hash}:0");
                let signature = manager
                    .sign(private_key, payload.as_bytes())
                    .expect("test vote signature should be generated");
                json!({
                    "validator_address": address,
                    "block_hash": block_hash.clone(),
                    "block_index": height,
                    "epoch_number": 0,
                    "round_number": 0,
                    "signature": signature,
                    "signer_public_key": public_key.key_data,
                    "timestamp": 100,
                })
            })
            .collect::<Vec<_>>();
        let qc = json!({
            "block_hash": block_hash.clone(),
            "epoch_number": 0,
            "round_number": 0,
            "aggregate_signature": [1, 2, 3, 4],
            "participant_bitmap": [15],
            "cumulative_weight": 4.0,
            "validation_quorum_met": true,
            "cooperation_quorum_met": true,
            "timestamp": 100,
            "votes": votes,
        });
        fs::write(
            root.join("data/committed_qcs.jsonl"),
            serde_json::to_string(&json!({"block_hash": block_hash.clone(), "qc": qc}))
                .expect("test QC should serialize")
                + "\n",
        )
        .expect("test committed QC should be written");
    }

    fn write_quarantine_marker(root: &Path) {
        fs::write(
            root.join("data/validator_quarantine.json"),
            json!({
                "status": "SELF_QUARANTINED_DIVERGENCE",
                "reason": "test divergence",
                "divergence_height": 100,
                "local_locked_block_hash": "minority",
                "conflicting_block_hash": "majority",
                "observed_at_unix_secs": now_secs_for_test(),
            })
            .to_string(),
        )
        .expect("test quarantine marker should be written");
    }

    fn write_self_heal_status_state(root: &Path, state: &str) {
        fs::write(
            root.join("data/self_heal_status.json"),
            json!({
                "success": true,
                "typed_status": state,
                "new_state": state,
            })
            .to_string(),
        )
        .expect("test self-heal status should be written");
    }

    #[test]
    fn create_snapshot_requires_majority_branch_proof() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("snapshot-requires-proof");
        install_test_genesis(&root);
        let result = with_runtime_root(&root, || {
            create_snapshot_with_options(CreateSnapshotOptions::default())
        });
        let error = result.expect_err("snapshot creation should fail closed without proof");
        assert!(error.contains("source_node_majority_branch_proven"));
    }

    #[test]
    fn snapshot_copy_excludes_keys_configs_and_runtime_material() {
        let root = test_runtime_root("snapshot-copy");
        let data_dir = root.join("data");
        fs::write(data_dir.join("chain.json"), b"chain").unwrap();
        fs::write(
            data_dir.join("canonical_locks.json"),
            json!({"10": {"height": 10, "hash": "h10"}}).to_string(),
        )
        .unwrap();
        fs::write(data_dir.join("validator.key"), b"secret").unwrap();
        fs::write(data_dir.join("node.env"), b"SECRET=value").unwrap();
        fs::write(data_dir.join("runtime.bin"), b"binary").unwrap();
        let snapshot_dir = root.join("snapshot");

        let copied = copy_snapshot_state_files(&data_dir, &snapshot_dir, 10, None).unwrap();

        assert_eq!(copied, 2);
        assert!(snapshot_dir.join("chain.json").exists());
        assert!(snapshot_dir.join("canonical_locks.json").exists());
        assert!(!snapshot_dir.join("validator.key").exists());
        assert!(!snapshot_dir.join("node.env").exists());
        assert!(!snapshot_dir.join("runtime.bin").exists());
    }

    #[test]
    fn snapshot_copy_truncates_canonical_locks_and_committed_qcs_to_snapshot_height() {
        let root = test_runtime_root("snapshot-copy-truncates-metadata");
        let data_dir = root.join("data");
        fs::write(data_dir.join("chain.json"), b"chain").unwrap();
        fs::write(
            data_dir.join("canonical_locks.json"),
            json!({
                "10": {"height": 10, "hash": "h10"},
                "11": {"height": 11, "hash": "h11"}
            })
            .to_string(),
        )
        .unwrap();
        fs::write(
            data_dir.join("committed_qcs.jsonl"),
            [
                json!({"qc": {"votes": [{"block_index": 10}], "block_hash": "h10"}}).to_string(),
                json!({"qc": {"votes": [{"block_index": 11}], "block_hash": "h11"}}).to_string(),
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();
        let snapshot_dir = root.join("snapshot");

        copy_snapshot_state_files(&data_dir, &snapshot_dir, 10, None).unwrap();

        let locks: Value =
            serde_json::from_slice(&fs::read(snapshot_dir.join("canonical_locks.json")).unwrap())
                .unwrap();
        assert!(locks.get("10").is_some());
        assert!(locks.get("11").is_none());
        let qcs = fs::read_to_string(snapshot_dir.join("committed_qcs.jsonl")).unwrap();
        assert!(qcs.contains("h10"));
        assert!(!qcs.contains("h11"));
    }

    #[test]
    fn snapshot_copy_materializes_missing_lock_from_verified_qc_without_mutating_source() {
        let root = test_runtime_root("snapshot-copy-materialized-lock");
        let data_dir = root.join("data");
        fs::write(data_dir.join("chain.json"), b"chain").unwrap();
        fs::write(
            data_dir.join("canonical_locks.json"),
            json!({"9": {"height": 9, "hash": "h9"}}).to_string(),
        )
        .unwrap();
        fs::write(
            data_dir.join("committed_qcs.jsonl"),
            json!({
                "block_hash": "h10",
                "qc": {
                    "block_hash": "h10",
                    "votes": [{"block_index": 10}]
                }
            })
            .to_string()
                + "\n",
        )
        .unwrap();
        let snapshot_dir = root.join("snapshot");
        let materialized_lock = SnapshotCanonicalLockMaterialization {
            block: BlockSummary {
                height: 10,
                hash: "h10".to_string(),
                parent_hash: "h9".to_string(),
                validator_id: "validator-10".to_string(),
                transactions_root: "tx-root-10".to_string(),
            },
            qc_vote_count: 4,
        };

        copy_snapshot_state_files(&data_dir, &snapshot_dir, 10, Some(&materialized_lock)).unwrap();

        let source_locks: Value =
            serde_json::from_slice(&fs::read(data_dir.join("canonical_locks.json")).unwrap())
                .unwrap();
        assert!(source_locks.get("10").is_none());
        let snapshot_locks: Value =
            serde_json::from_slice(&fs::read(snapshot_dir.join("canonical_locks.json")).unwrap())
                .unwrap();
        let lock = snapshot_locks
            .get("10")
            .expect("snapshot-local materialized lock should exist");
        assert_eq!(lock.get("block_hash").and_then(Value::as_str), Some("h10"));
        assert_eq!(
            lock.get("validator_id").and_then(Value::as_str),
            Some("validator-10")
        );
        assert_eq!(
            lock.get("transactions_root").and_then(Value::as_str),
            Some("tx-root-10")
        );
        assert!(lock
            .get("written_at_unix_secs")
            .and_then(Value::as_u64)
            .is_some());
        assert_eq!(
            lock.get("finality_source").and_then(Value::as_str),
            Some("verified_committed_qc")
        );
        assert_eq!(
            lock.get("snapshot_only_materialized")
                .and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn snapshot_retention_keeps_highest_height_instead_of_lexicographic_name() {
        let root = test_runtime_root("snapshot-retention-height-sort");
        let snapshot_root = root.join("data/snapshots");
        fs::create_dir_all(&snapshot_root).expect("snapshot root should exist");
        for name in [
            "snapshot-97500-1779964096",
            "snapshot-97500-1779964308",
            "snapshot-99908-1779970413",
            "snapshot-102514-1779977247",
        ] {
            fs::create_dir_all(snapshot_root.join(name)).expect("snapshot dir should be created");
        }

        enforce_snapshot_retention(&snapshot_root, 3).expect("retention should succeed");

        assert!(!snapshot_root.join("snapshot-97500-1779964096").exists());
        assert!(snapshot_root.join("snapshot-97500-1779964308").exists());
        assert!(snapshot_root.join("snapshot-99908-1779970413").exists());
        assert!(snapshot_root.join("snapshot-102514-1779977247").exists());
    }

    #[test]
    fn snapshot_metadata_consistency_rejects_lock_above_manifest_height() {
        let root = test_runtime_root("snapshot-metadata-rejects-lock-ahead");
        let (snapshot_root, manifest_path) = write_valid_signed_snapshot(&root);
        let mut signed = super::read_signed_snapshot_manifest(&manifest_path).unwrap();
        let mut locks: Value =
            serde_json::from_slice(&fs::read(snapshot_root.join("canonical_locks.json")).unwrap())
                .unwrap();
        locks["101"] = json!({"height": 101, "hash": "future-lock"});
        fs::write(
            snapshot_root.join("canonical_locks.json"),
            serde_json::to_vec(&locks).unwrap(),
        )
        .unwrap();
        signed.manifest.snapshot_height = 100;

        let error = snapshot_metadata_consistency_report(&signed, &snapshot_root)
            .expect_err("metadata above manifest height must fail closed");

        assert!(error.contains("above manifest snapshot height"));
    }

    #[test]
    fn operator_quarantine_requires_explicit_approval() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("operator-quarantine-requires-approval");
        install_test_genesis(&root);

        let report = with_runtime_root(&root, || {
            quarantine_stopped_validator_with_options(OperatorQuarantineOptions {
                target_stopped: true,
                quorum_majority_height: Some(87892),
                quorum_majority_hash: Some("majority-hash".to_string()),
                ..OperatorQuarantineOptions::default()
            })
            .expect("operator quarantine should return typed body")
        });

        assert!(!report
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(true));
        assert_eq!(
            report.get("typed_status").and_then(Value::as_str),
            Some("FAILED_CLOSED")
        );
        assert!(report
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .contains("operator-approved-containment"));
        assert!(!root.join("data/validator_quarantine.json").exists());
    }

    #[test]
    fn operator_quarantine_requires_target_stopped_confirmation() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("operator-quarantine-requires-stopped");
        install_test_genesis(&root);

        let report = with_runtime_root(&root, || {
            quarantine_stopped_validator_with_options(OperatorQuarantineOptions {
                operator_approved_containment: true,
                quorum_majority_height: Some(87892),
                quorum_majority_hash: Some("majority-hash".to_string()),
                ..OperatorQuarantineOptions::default()
            })
            .expect("operator quarantine should return typed body")
        });

        assert!(!report
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(true));
        assert_eq!(
            report.get("typed_status").and_then(Value::as_str),
            Some("FAILED_CLOSED")
        );
        assert!(report
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .contains("target-stopped"));
        assert!(!root.join("data/validator_quarantine.json").exists());
    }

    #[test]
    fn operator_quarantine_writes_marker_and_preserves_evidence_without_state_mutation() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("operator-quarantine-marker");
        install_test_genesis(&root);
        fs::write(
            root.join("data/chain.json"),
            json!([{
                "height": 84117,
                "hash": "local-stale-hash",
                "parent_hash": "local-parent-hash",
            }])
            .to_string(),
        )
        .expect("test chain state should be written");
        write_canonical_lock(&root);
        fs::write(
            root.join("data/committed_qcs.jsonl"),
            b"{\"height\":84117}\n",
        )
        .expect("test committed QC tail should be written");
        fs::write(root.join("data/consensus_vote_locks.json"), b"{}")
            .expect("test vote locks should be written");

        let report = with_runtime_root(&root, || {
            quarantine_stopped_validator_with_options(OperatorQuarantineOptions {
                reason: Some("operator approved stale stopped validator containment".to_string()),
                target_stopped: true,
                operator_approved_containment: true,
                quorum_majority_height: Some(87892),
                quorum_majority_hash: Some("majority-hash".to_string()),
                local_conflicting_height: Some(84117),
                local_conflicting_hash: Some("local-stale-hash".to_string()),
            })
            .expect("operator quarantine should succeed with explicit proof")
        });

        assert_eq!(report.get("success").and_then(Value::as_bool), Some(true));
        assert_eq!(
            report.get("typed_status").and_then(Value::as_str),
            Some("QUARANTINED")
        );
        assert_eq!(
            report.get("quorum_majority_height").and_then(Value::as_u64),
            Some(87892)
        );
        assert_eq!(
            report
                .get("keys_or_configs_copied")
                .and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            report.get("chain_state_mutated").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            report.get("quorum_mutated").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            report
                .get("duty_gate")
                .and_then(|gate| gate.get("can_vote"))
                .and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            report
                .get("duty_gate")
                .and_then(|gate| gate.get("can_propose"))
                .and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            report
                .get("duty_gate")
                .and_then(|gate| gate.get("can_aggregate_qc"))
                .and_then(Value::as_bool),
            Some(false)
        );

        let marker_path = root.join("data/validator_quarantine.json");
        assert!(marker_path.exists());
        let marker: Value = serde_json::from_slice(&fs::read(marker_path).unwrap()).unwrap();
        assert_eq!(
            marker.get("recovery_state").and_then(Value::as_str),
            Some("QUARANTINED")
        );
        assert_eq!(
            marker.get("voting_disabled").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            marker.get("quorum_majority_hash").and_then(Value::as_str),
            Some("majority-hash")
        );

        let evidence_path = report
            .get("evidence_path")
            .and_then(Value::as_str)
            .expect("evidence path should be returned");
        assert!(Path::new(evidence_path)
            .join("operator-quarantine-evidence.json")
            .exists());

        let status = with_runtime_root(&root, quarantine_status);
        assert_eq!(
            status.get("quarantined").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            status
                .get("duty_gate")
                .and_then(|gate| gate.get("can_count_toward_quorum"))
                .and_then(Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn operator_quarantine_rejects_wrong_chain_id() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("operator-quarantine-wrong-chain");
        install_test_genesis(&root);
        install_test_config(&root, 1263, "synergy-testnet-v2");

        let error = with_runtime_root(&root, || {
            quarantine_stopped_validator_with_options(operator_quarantine_options())
        })
        .expect_err("wrong chain_id should fail closed");

        assert!(error.contains("chain_id"), "{error}");
        assert!(!root.join("data/validator_quarantine.json").exists());
    }

    #[test]
    fn operator_quarantine_rejects_wrong_network_id() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("operator-quarantine-wrong-network");
        install_test_genesis(&root);
        install_test_config(&root, 1264, "synergy-testnet-v1");

        let error = with_runtime_root(&root, || {
            quarantine_stopped_validator_with_options(operator_quarantine_options())
        })
        .expect_err("wrong network_id should fail closed");

        assert!(error.contains("network"), "{error}");
        assert!(!root.join("data/validator_quarantine.json").exists());
    }

    #[test]
    fn operator_quarantine_rejects_wrong_genesis_hash() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("operator-quarantine-wrong-genesis");
        install_mutated_test_genesis(&root);
        install_test_config(&root, 1264, "synergy-testnet-v2");

        let error = with_runtime_root(&root, || {
            quarantine_stopped_validator_with_options(operator_quarantine_options())
        })
        .expect_err("wrong genesis should fail closed");

        assert!(error.contains("genesis"));
        assert!(!root.join("data/validator_quarantine.json").exists());
    }

    #[test]
    fn operator_quarantine_preserves_evidence_before_marker() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("operator-quarantine-evidence-first");
        install_test_genesis(&root);
        write_minimal_chain_state(&root);

        let report = operator_quarantine(&root);

        let evidence_path = report
            .get("evidence_path")
            .and_then(Value::as_str)
            .expect("evidence path should be returned");
        let evidence: Value = serde_json::from_slice(
            &fs::read(Path::new(evidence_path).join("operator-quarantine-evidence.json"))
                .expect("operator quarantine evidence should exist"),
        )
        .expect("operator quarantine evidence should parse");
        let marker_summary = evidence
            .get("file_summaries")
            .and_then(Value::as_array)
            .and_then(|items| {
                items.iter().find(|item| {
                    item.get("path")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .ends_with("validator_quarantine.json")
                })
            })
            .expect("quarantine marker pre-summary should be present");
        assert_eq!(
            marker_summary.get("exists").and_then(Value::as_bool),
            Some(false)
        );
        assert!(root.join("data/validator_quarantine.json").exists());
    }

    #[test]
    fn operator_quarantine_writes_standard_marker_schema() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("operator-quarantine-standard-marker");
        install_test_genesis(&root);
        write_minimal_chain_state(&root);

        operator_quarantine(&root);

        let marker: QuarantineMarker = serde_json::from_slice(
            &fs::read(root.join("data/validator_quarantine.json"))
                .expect("standard marker should be written"),
        )
        .expect("standard marker schema should parse");
        assert_eq!(marker.recovery_state, super::RealignmentState::Quarantined);
        assert_eq!(marker.quorum_majority_height, 87892);
        assert_eq!(marker.quorum_majority_hash, "majority-hash");
        assert!(!marker.rejoin_eligibility);
    }

    #[test]
    fn operator_quarantine_disables_all_consensus_duties() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("operator-quarantine-disables-duties");
        install_test_genesis(&root);
        write_minimal_chain_state(&root);

        let report = operator_quarantine(&root);

        let duty_gate = report
            .get("duty_gate")
            .expect("duty gate should be returned");
        assert_eq!(
            duty_gate.get("can_vote").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            duty_gate.get("can_propose").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            duty_gate.get("can_aggregate_qc").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            duty_gate
                .get("can_count_toward_quorum")
                .and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            duty_gate
                .get("can_enter_proposer_schedule")
                .and_then(Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn operator_quarantine_does_not_mutate_keys() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("operator-quarantine-keeps-keys");
        install_test_genesis(&root);
        write_minimal_chain_state(&root);
        let key_path = root.join("config/validator/consensus.private.key");
        fs::create_dir_all(key_path.parent().unwrap()).unwrap();
        fs::write(&key_path, b"validator-key").unwrap();

        operator_quarantine(&root);

        assert_eq!(fs::read(&key_path).unwrap(), b"validator-key");
    }

    #[test]
    fn operator_quarantine_does_not_mutate_configs() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("operator-quarantine-keeps-configs");
        install_test_genesis(&root);
        write_minimal_chain_state(&root);
        install_test_config(&root, 1264, "synergy-testnet-v2");
        let config_path = root.join("config/node.toml");
        let before = fs::read(&config_path).unwrap();

        operator_quarantine(&root);

        assert_eq!(fs::read(&config_path).unwrap(), before);
    }

    #[test]
    fn operator_quarantine_does_not_mutate_genesis() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("operator-quarantine-keeps-genesis");
        install_test_genesis(&root);
        write_minimal_chain_state(&root);
        let genesis_path = root.join("config/genesis.json");
        let before = fs::read(&genesis_path).unwrap();

        operator_quarantine(&root);

        assert_eq!(fs::read(&genesis_path).unwrap(), before);
    }

    #[test]
    fn operator_quarantine_does_not_delete_canonical_locks() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("operator-quarantine-keeps-locks");
        install_test_genesis(&root);
        write_minimal_chain_state(&root);
        let path = root.join("data/canonical_locks.json");
        let before = fs::read(&path).unwrap();

        operator_quarantine(&root);

        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn operator_quarantine_does_not_delete_committed_qcs() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("operator-quarantine-keeps-qcs");
        install_test_genesis(&root);
        write_minimal_chain_state(&root);
        let path = root.join("data/committed_qcs.jsonl");
        let before = fs::read(&path).unwrap();

        operator_quarantine(&root);

        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn self_heal_rejects_non_quarantined_stale_validator() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("self-heal-rejects-non-quarantined");
        install_test_genesis(&root);
        write_minimal_chain_state(&root);
        let (snapshot_root, manifest_path) = write_valid_signed_snapshot(&root);

        let report = with_runtime_root(&root, || {
            self_heal_from_snapshot(
                manifest_path.to_str().unwrap(),
                Some(snapshot_root.to_str().unwrap()),
            )
            .expect("self-heal should return typed body")
        });

        assert_eq!(report.get("success").and_then(Value::as_bool), Some(false));
        assert_eq!(
            report.get("typed_status").and_then(Value::as_str),
            Some("FAILED_CLOSED")
        );
        assert!(report
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .contains("local validator quarantine"));
    }

    #[test]
    fn self_heal_rejects_manual_or_malformed_quarantine_marker() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("self-heal-rejects-malformed-marker");
        install_test_genesis(&root);
        write_minimal_chain_state(&root);
        write_quarantine_marker(&root);
        let (snapshot_root, manifest_path) = write_valid_signed_snapshot(&root);

        let report = with_runtime_root(&root, || {
            self_heal_from_snapshot(
                manifest_path.to_str().unwrap(),
                Some(snapshot_root.to_str().unwrap()),
            )
            .expect("self-heal should return typed body")
        });

        assert_eq!(report.get("success").and_then(Value::as_bool), Some(false));
        assert!(report
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .contains("standard local quarantine marker"));
    }

    #[test]
    fn self_heal_accepts_operator_quarantined_validator_only_after_signed_snapshot_verification() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("self-heal-accepts-operator-marker");
        install_test_genesis(&root);
        write_minimal_chain_state(&root);
        operator_quarantine(&root);
        let (snapshot_root, manifest_path) = write_valid_signed_snapshot(&root);

        let report = with_runtime_root(&root, || {
            self_heal_from_snapshot(
                manifest_path.to_str().unwrap(),
                Some(snapshot_root.to_str().unwrap()),
            )
            .expect("self-heal should return typed body")
        });

        assert_eq!(report.get("success").and_then(Value::as_bool), Some(true));
        assert_eq!(
            report.get("typed_status").and_then(Value::as_str),
            Some("SNAPSHOT_RESTORED")
        );
        assert_eq!(
            report
                .get("keys_or_configs_copied")
                .and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            report.get("genesis_mutated").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            report.get("quorum_mutated").and_then(Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn fresh_self_heal_invalidates_old_shadow_pass_marker() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("self-heal-invalidates-old-shadow");
        install_test_genesis(&root);
        write_minimal_chain_state(&root);
        operator_quarantine(&root);
        fs::write(
            root.join("data/shadow_observation.json"),
            json!({
                "success": true,
                "typed_status": "SHADOW_PASSED",
                "start_height": 89957,
                "canonical_match_count": 1000,
                "mismatch_count": 0,
                "restore_generation": "old-restore"
            })
            .to_string(),
        )
        .expect("stale shadow observation should be written");
        let (snapshot_root, manifest_path) = write_valid_signed_snapshot(&root);

        let report = with_runtime_root(&root, || {
            self_heal_from_snapshot(
                manifest_path.to_str().unwrap(),
                Some(snapshot_root.to_str().unwrap()),
            )
            .expect("self-heal should return typed body")
        });

        assert_eq!(report.get("success").and_then(Value::as_bool), Some(true));
        assert_eq!(
            report
                .get("stale_shadow_observation_invalidated")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert!(
            !root.join("data/shadow_observation.json").exists(),
            "fresh self-heal must require a fresh shadow window"
        );
        let preserved = report
            .get("preserved_stale_shadow_observation_path")
            .and_then(Value::as_str)
            .expect("stale shadow evidence path should be reported");
        assert!(
            Path::new(preserved).exists(),
            "stale shadow marker should be preserved before invalidation"
        );
        let rejoin = with_runtime_root(&root, rejoin_eligibility);
        assert_eq!(rejoin.get("eligible").and_then(Value::as_bool), Some(false));
    }

    #[test]
    fn rejoin_requires_shadow_observation_after_restore() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("rejoin-requires-shadow-after-restore");
        install_test_genesis(&root);
        write_minimal_chain_state(&root);
        operator_quarantine(&root);
        write_self_heal_status_state(&root, "SNAPSHOT_RESTORED");

        let report = with_runtime_root(&root, rejoin_eligibility);

        assert_eq!(report.get("eligible").and_then(Value::as_bool), Some(false));
        let blocked = report
            .get("blocked_reasons")
            .and_then(Value::as_array)
            .expect("blocked reasons should be returned");
        assert!(blocked.iter().any(|reason| {
            reason
                .as_str()
                .unwrap_or_default()
                .contains("SHADOW_PASSED")
        }));
    }

    #[test]
    fn read_block_at_height_streams_chain_array() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("stream-chain-read");
        let blocks: Vec<Value> = (0u64..4096)
            .map(|height| {
                json!({
                    "height": height,
                    "hash": format!("hash-{height}"),
                    "parent_hash": format!("hash-{}", height.saturating_sub(1)),
                })
            })
            .collect();
        fs::write(
            root.join("data/chain.json"),
            serde_json::to_vec(&blocks).unwrap(),
        )
        .unwrap();

        let block = with_runtime_root(&root, || read_block_at_height(4095).unwrap());

        assert_eq!(block.height, 4095);
        assert_eq!(block.hash, "hash-4095");
        assert_eq!(block.parent_hash, "hash-4094");
    }

    #[test]
    fn read_latest_block_summary_streams_chain_array() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("stream-chain-latest");
        let blocks: Vec<Value> = (0u64..4096)
            .map(|height| {
                json!({
                    "block_index": height,
                    "hash": format!("hash-{height}"),
                    "previous_hash": format!("hash-{}", height.saturating_sub(1)),
                })
            })
            .collect();
        fs::write(
            root.join("data/chain.json"),
            serde_json::to_vec(&blocks).unwrap(),
        )
        .unwrap();

        let block = with_runtime_root(&root, || read_latest_block_summary().unwrap());

        assert_eq!(block.height, 4095);
        assert_eq!(block.hash, "hash-4095");
        assert_eq!(block.parent_hash, "hash-4094");
    }

    #[test]
    fn read_block_at_height_tolerates_stale_trailing_bytes_after_chain_array() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("stream-chain-stale-tail");
        let blocks: Vec<Value> = (0u64..16)
            .map(|height| {
                json!({
                    "block_index": height,
                    "hash": format!("hash-{height}"),
                    "previous_hash": format!("hash-{}", height.saturating_sub(1)),
                })
            })
            .collect();
        let mut bytes = serde_json::to_vec(&blocks).unwrap();
        bytes.extend_from_slice(b"{\"stale_tail\":true}");
        fs::write(root.join("data/chain.json"), bytes).unwrap();

        let block = with_runtime_root(&root, || read_block_at_height(15).unwrap());
        let latest = with_runtime_root(&root, || read_latest_block_summary().unwrap());

        assert_eq!(block.hash, "hash-15");
        assert_eq!(latest.hash, "hash-15");
    }

    #[test]
    fn sync_from_canonical_peer_requires_verified_source_proof() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("sync-requires-proof");
        install_test_genesis(&root);
        write_quarantine_marker(&root);
        write_self_heal_status_state(&root, "SNAPSHOT_RESTORED");

        let report = with_runtime_root(&root, || {
            sync_from_canonical_peer_with_options(SyncFromCanonicalPeerOptions::default())
                .expect("sync diagnostics should return typed body")
        });

        assert!(!report
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(true));
        assert_eq!(
            report.get("typed_status").and_then(Value::as_str),
            Some("FAILED_CLOSED")
        );
        assert!(report
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .contains("verified source QC"));
    }

    #[test]
    fn start_shadow_observe_requires_verified_head_match() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("shadow-requires-head-match");
        install_test_genesis(&root);
        write_quarantine_marker(&root);
        write_self_heal_status_state(&root, "SNAPSHOT_RESTORED");

        let report = with_runtime_root(&root, || {
            start_shadow_observe_with_options(StartShadowObserveOptions {
                required_blocks: Some(1),
            })
            .expect("shadow diagnostics should return typed body")
        });

        assert!(!report
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(true));
        assert_eq!(
            report.get("typed_status").and_then(Value::as_str),
            Some("FAILED_CLOSED")
        );
        assert!(report
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .contains("speed-sync/head-match"));
    }

    #[test]
    fn request_rejoin_requires_common_height_proof() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("rejoin-requires-common-height");
        install_test_genesis(&root);
        write_quarantine_marker(&root);

        let report = with_runtime_root(&root, || {
            request_rejoin_with_options(RejoinRequestOptions::default())
                .expect("rejoin diagnostics should return typed body")
        });

        assert!(!report
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(true));
        assert_eq!(
            report.get("typed_status").and_then(Value::as_str),
            Some("FAILED_CLOSED")
        );
        assert!(report
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .contains("common_height"));
    }

    #[test]
    fn shadow_status_is_read_only_idle_without_observation() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("shadow-idle");
        install_test_genesis(&root);

        let report = with_runtime_root(&root, shadow_status);

        assert_eq!(
            report.get("status").and_then(Value::as_str),
            Some("idle_or_not_started")
        );
        assert_eq!(
            report
                .get("shadow_signs_real_votes")
                .and_then(Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn shadow_status_classifies_500_blocks_as_process_proof_only() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("shadow-process-proof-only");
        install_test_genesis(&root);
        install_test_config(&root, 1264, "synergy-testnet-v2");
        write_quarantine_marker(&root);
        write_empty_vote_locks(&root);
        write_shadow_observation(&root, 89957, 500);
        write_chain_range(&root, 89958, 90457);
        write_canonical_lock_at_height(&root, 90457);
        write_legacy_qc_fixture_at_height(&root, 90457);

        let report = with_runtime_root(&root, shadow_status);

        assert_eq!(
            report.get("status").and_then(Value::as_str),
            Some("PROCESS_PROOF_PASS")
        );
        assert_eq!(
            report.get("computed_state").and_then(Value::as_str),
            Some("SHADOW_OBSERVING")
        );
        assert_eq!(
            report
                .get("process_proof_completed")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            report
                .get("full_epoch_shadow_completed")
                .and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            report.get("rejoin_eligible").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            report
                .get("required_full_shadow_epoch_start")
                .and_then(Value::as_u64),
            Some(90000)
        );
        assert_eq!(
            report
                .get("required_full_shadow_epoch_end")
                .and_then(Value::as_u64),
            Some(90999)
        );
        assert_eq!(
            report
                .get("earliest_activation_height")
                .and_then(Value::as_u64),
            Some(91000)
        );
    }

    #[test]
    fn shadow_status_uses_committed_block_log_when_chain_snapshot_lags() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("shadow-committed-log-fallback");
        install_test_genesis(&root);
        install_test_config(&root, 1264, "synergy-testnet-v2");
        write_quarantine_marker(&root);
        write_empty_vote_locks(&root);
        write_shadow_observation(&root, 89957, 500);
        write_chain_range(&root, 89958, 90456);
        write_canonical_lock_at_height(&root, 90457);
        write_legacy_qc_fixture_at_height(&root, 90457);
        let block = Block {
            block_index: 90457,
            timestamp: 1,
            transactions: Vec::new(),
            previous_hash: test_hash(90456),
            validator_id: "validator-1".to_string(),
            nonce: 90457,
            hash: test_hash(90457),
            transactions_root: String::new(),
            proposer_public_key: Vec::new(),
            block_signature: Vec::new(),
            block_signature_algorithm: "fn-dsa".to_string(),
        };
        let entry = CommittedBlockLogEntry {
            height: block.block_index,
            hash: block.hash.clone(),
            previous_hash: block.previous_hash.clone(),
            block,
        };
        let committed_log_path = root.join("data/committed_blocks.jsonl");
        fs::write(
            &committed_log_path,
            serde_json::to_string(&entry).expect("committed block log entry should serialize")
                + "\n",
        )
        .expect("committed block log should be written");

        let previous_committed_log = std::env::var("SYNERGY_COMMITTED_BLOCK_LOG_FILE").ok();
        std::env::set_var("SYNERGY_COMMITTED_BLOCK_LOG_FILE", &committed_log_path);
        let report = with_runtime_root(&root, shadow_status);
        match previous_committed_log {
            Some(value) => std::env::set_var("SYNERGY_COMMITTED_BLOCK_LOG_FILE", value),
            None => std::env::remove_var("SYNERGY_COMMITTED_BLOCK_LOG_FILE"),
        }

        assert_eq!(
            report.get("status").and_then(Value::as_str),
            Some("PROCESS_PROOF_PASS")
        );
        assert_eq!(
            report.get("observed_blocks").and_then(Value::as_u64),
            Some(500)
        );
        assert_eq!(
            report.get("mismatch_count").and_then(Value::as_u64),
            Some(0)
        );
        assert!(report
            .get("failures")
            .and_then(Value::as_array)
            .map(|failures| failures.is_empty())
            .unwrap_or(false));
    }

    #[test]
    fn shadow_status_requires_full_epoch_before_rejoin_boundary() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("shadow-full-epoch-no-boundary");
        install_test_genesis(&root);
        install_test_config(&root, 1264, "synergy-testnet-v2");
        write_quarantine_marker(&root);
        write_empty_vote_locks(&root);
        write_shadow_observation(&root, 89957, 500);
        write_chain_range(&root, 90000, 90999);
        write_canonical_lock_at_height(&root, 90999);
        write_legacy_qc_fixture_at_height(&root, 90999);

        let report = with_runtime_root(&root, shadow_status);

        assert_eq!(
            report.get("status").and_then(Value::as_str),
            Some("SHADOW_PASSED")
        );
        assert_eq!(
            report
                .get("full_epoch_shadow_completed")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            report.get("rejoin_eligible").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            report.get("latest_height").and_then(Value::as_u64),
            Some(90999)
        );
        assert_eq!(
            report
                .get("earliest_activation_height")
                .and_then(Value::as_u64),
            Some(91000)
        );
    }

    #[test]
    fn shadow_status_reports_missed_epoch_rejoin_boundary() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("shadow-missed-epoch-boundary");
        install_test_genesis(&root);
        install_test_config(&root, 1264, "synergy-testnet-v2");
        write_quarantine_marker(&root);
        write_empty_vote_locks(&root);
        write_shadow_observation(&root, 89957, 500);
        write_chain_range(&root, 90000, 94002);
        write_canonical_lock_at_height(&root, 94002);
        write_legacy_qc_fixture_at_height(&root, 94002);

        let report = with_runtime_root(&root, shadow_status);

        assert_eq!(
            report.get("status").and_then(Value::as_str),
            Some("SHADOW_PASSED")
        );
        assert_eq!(
            report.get("missed_boundary").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            report.get("last_missed_boundary").and_then(Value::as_u64),
            Some(94000)
        );
        assert_eq!(
            report.get("next_eligible_boundary").and_then(Value::as_u64),
            Some(95000)
        );
        assert_eq!(
            report
                .get("epoch_rejoin_window_open")
                .and_then(Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn request_rejoin_rejects_process_proof_without_full_epoch() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("rejoin-rejects-process-proof");
        install_test_genesis(&root);
        install_test_config(&root, 1264, "synergy-testnet-v2");
        write_quarantine_marker(&root);
        write_empty_vote_locks(&root);
        write_shadow_observation(&root, 89957, 500);
        write_chain_range(&root, 89958, 90457);
        write_canonical_lock_at_height(&root, 90457);
        write_legacy_qc_fixture_at_height(&root, 90457);

        let report = with_runtime_root(&root, || {
            request_rejoin_with_options(RejoinRequestOptions {
                common_height: Some(90457),
                common_hash: Some(test_hash(90457)),
                exact_common_height_match: true,
                latest_finalized_qc_aegis_pqc_verified: true,
                state_root_matches: true,
                rejoin_at_finalized_safe_boundary: true,
                cluster_marks_pending_reactivation: true,
                operator_approved_reactivation: true,
            })
            .expect("rejoin diagnostics should return typed body")
        });

        assert_eq!(
            report.get("typed_status").and_then(Value::as_str),
            Some("FAILED_CLOSED")
        );
        let blocked = report
            .get("blocked_reasons")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert!(blocked.iter().any(|reason| {
            reason
                .as_str()
                .unwrap_or_default()
                .contains("500-block process proof")
        }));
    }

    #[test]
    fn request_rejoin_rejects_non_epoch_boundary_after_full_epoch() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("rejoin-rejects-non-boundary");
        install_test_genesis(&root);
        install_test_config(&root, 1264, "synergy-testnet-v2");
        write_quarantine_marker(&root);
        write_empty_vote_locks(&root);
        write_shadow_observation(&root, 89957, 500);
        write_chain_range(&root, 90000, 90999);
        write_canonical_lock_at_height(&root, 91001);
        write_legacy_qc_fixture_at_height(&root, 91001);

        let report = with_runtime_root(&root, || {
            request_rejoin_with_options(RejoinRequestOptions {
                common_height: Some(91001),
                common_hash: Some(test_hash(91001)),
                exact_common_height_match: true,
                latest_finalized_qc_aegis_pqc_verified: true,
                state_root_matches: true,
                rejoin_at_finalized_safe_boundary: true,
                cluster_marks_pending_reactivation: true,
                operator_approved_reactivation: true,
            })
            .expect("rejoin diagnostics should return typed body")
        });

        assert_eq!(
            report.get("typed_status").and_then(Value::as_str),
            Some("FAILED_CLOSED")
        );
        let blocked = report
            .get("blocked_reasons")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert!(blocked.iter().any(|reason| {
            reason
                .as_str()
                .unwrap_or_default()
                .contains("not an epoch boundary")
        }));
    }

    fn advancing_chain() -> Arc<Mutex<BlockChain>> {
        let mut chain = BlockChain::new();
        chain.add_block(Block::new_with_timestamp(
            100,
            Vec::new(),
            "parent".to_string(),
            "synv1leader".to_string(),
            1,
            now_secs_for_test(),
        ));
        Arc::new(Mutex::new(chain))
    }

    fn with_runtime_root<T>(root: &Path, test: impl FnOnce() -> T) -> T {
        let previous_root = std::env::var("SYNERGY_PROJECT_ROOT").ok();
        let previous_config = std::env::var("SYNERGY_CONFIG_PATH").ok();
        let previous_genesis = std::env::var("SYNERGY_GENESIS_FILE").ok();
        let previous_fork = std::env::var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV).ok();
        std::env::set_var("SYNERGY_PROJECT_ROOT", root);
        let config_path = root.join("config/node.toml");
        if config_path.exists() {
            std::env::set_var("SYNERGY_CONFIG_PATH", config_path);
        } else {
            std::env::remove_var("SYNERGY_CONFIG_PATH");
        }
        std::env::remove_var("SYNERGY_GENESIS_FILE");
        std::env::remove_var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV);
        let result = test();
        match previous_root {
            Some(value) => std::env::set_var("SYNERGY_PROJECT_ROOT", value),
            None => std::env::remove_var("SYNERGY_PROJECT_ROOT"),
        }
        match previous_config {
            Some(value) => std::env::set_var("SYNERGY_CONFIG_PATH", value),
            None => std::env::remove_var("SYNERGY_CONFIG_PATH"),
        }
        match previous_genesis {
            Some(value) => std::env::set_var("SYNERGY_GENESIS_FILE", value),
            None => std::env::remove_var("SYNERGY_GENESIS_FILE"),
        }
        match previous_fork {
            Some(value) => std::env::set_var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV, value),
            None => std::env::remove_var(consensus_fork::CONSENSUS_FORK_MIGRATION_ENV),
        }
        result
    }

    #[test]
    fn post_fork_snapshot_active_set_uses_consensus_fork_registry() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK.lock().unwrap();
        let root = test_runtime_root("post-fork-snapshot-active-set");
        install_test_config(&root, EXPECTED_CHAIN_ID, EXPECTED_NETWORK_ID);
        install_test_genesis(&root);
        let fork_validators = (1..=5)
            .map(|index| format!("synv1forktest{index}"))
            .collect::<Vec<_>>();
        install_test_consensus_fork(&root, &fork_validators);

        let post_fork = with_runtime_root(&root, || {
            active_validator_addresses_for_snapshot_height(204216)
                .expect("post-fork active set should resolve from fork metadata")
        });
        assert_eq!(post_fork, fork_validators);

        let pre_fork = with_runtime_root(&root, || {
            active_validator_addresses_for_snapshot_height(204215)
                .expect("pre-fork active set should resolve from genesis")
        });
        assert_eq!(pre_fork.len(), 5);
        assert_ne!(pre_fork, post_fork);
    }

    #[test]
    fn fresh_vote_lock_above_finalized_does_not_false_report_stall() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("fresh-lock");
        write_canonical_lock(&root);
        write_vote_lock(&root, now_secs_for_test(), None);

        let diagnosis = with_runtime_root(&root, || diagnose_consensus_stall(&advancing_chain()));
        let categories = diagnosis
            .get("categories")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        assert!(!diagnosis
            .get("stalled")
            .and_then(Value::as_bool)
            .unwrap_or(true));
        assert!(!categories
            .iter()
            .any(|category| category == "transient_vote_lock_above_finalized_height"));
        assert_eq!(
            diagnosis
                .get("vote_locks")
                .and_then(|locks| locks.get("fresh_locks_above_finalized"))
                .and_then(Value::as_u64),
            Some(1)
        );
    }

    #[test]
    fn stale_conflicting_vote_locks_above_finalized_report_stall() {
        let _guard = DIAGNOSTICS_TEST_ENV_LOCK
            .lock()
            .expect("diagnostics env lock should succeed");
        let root = test_runtime_root("stale-conflict");
        write_canonical_lock(&root);
        write_vote_lock(
            &root,
            now_secs_for_test().saturating_sub(DIAGNOSTIC_STALE_TRANSIENT_VOTE_LOCK_SECS + 5),
            Some("hash-b"),
        );

        let diagnosis = with_runtime_root(&root, || diagnose_consensus_stall(&advancing_chain()));
        let categories = diagnosis
            .get("categories")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        assert!(diagnosis
            .get("stalled")
            .and_then(Value::as_bool)
            .unwrap_or(false));
        assert!(categories
            .iter()
            .any(|category| category == "transient_vote_lock_above_finalized_height"));
        assert!(categories
            .iter()
            .any(|category| category == "same_height_competing_transient_vote_locks"));
        assert_eq!(
            diagnosis
                .get("vote_locks")
                .and_then(|locks| locks.get("stale_locks_above_finalized"))
                .and_then(Value::as_u64),
            Some(2)
        );
    }
}
