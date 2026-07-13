use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::block::{Block, BlockChain};
use crate::genesis::canonical_genesis;
use crate::p2p::networking::{P2PNetwork, PeerSnapshot};
use crate::sync::fast_sync;
use crate::sync::validation;

const SYNC_RECONCILIATION_LOOKBACK: u64 = 8;
const SYNC_PROGRESS_OVERLAP: u64 = 2;
const MAX_SYNC_BATCH_BLOCKS: u64 = 48;

fn resolve_local_genesis_hash(blockchain: &Arc<Mutex<BlockChain>>) -> String {
    let canonical = canonical_genesis()
        .map(|genesis| genesis.hash().to_string())
        .unwrap_or_default();
    if !canonical.trim().is_empty() {
        return canonical;
    }

    blockchain
        .lock()
        .ok()
        .and_then(|chain| chain.get_genesis_hash())
        .unwrap_or_default()
}

/// Represents where the sync engine currently is in the lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    Idle,
    Discovering,
    Downloading,
    Validating,
    Applying,
    Synced,
}

/// Snapshot of sync progress for reporting and RPC.
#[derive(Debug, Clone)]
pub struct SyncProgress {
    pub starting_block: u64,
    pub current_block: u64,
    pub highest_block: u64,
}

impl SyncProgress {
    fn new(starting_block: u64, highest_block: u64) -> Self {
        SyncProgress {
            starting_block,
            current_block: starting_block,
            highest_block,
        }
    }

    fn percentage(&self) -> f64 {
        if self.highest_block == self.starting_block {
            return 100.0;
        }
        let range = self.highest_block.saturating_sub(self.starting_block) as f64;
        let completed = self.current_block.saturating_sub(self.starting_block) as f64;
        if range == 0.0 {
            100.0
        } else {
            (completed / range * 100.0).min(100.0)
        }
    }
}

/// Sync manager errors represent recoverable conditions that should be surfaced via logs.
#[derive(Debug)]
pub enum SyncError {
    NetworkUnavailable,
    NoPeers,
    Timeout(String),
    MissingBlock(u64),
    InvalidParentHash {
        height: u64,
        expected: String,
        got: String,
    },
    InvalidTransactionsRoot,
    BlockValidationFailed(String),
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncError::NetworkUnavailable => write!(f, "P2P network unavailable"),
            SyncError::NoPeers => write!(f, "No peers available for sync"),
            SyncError::Timeout(reason) => write!(f, "Timeout waiting for {}", reason),
            SyncError::MissingBlock(height) => write!(f, "Missing block at height {}", height),
            SyncError::InvalidParentHash {
                height,
                expected,
                got,
            } => write!(
                f,
                "Header at {} points to {}, expected {}",
                height, got, expected
            ),
            SyncError::InvalidTransactionsRoot => write!(f, "Computed transaction root mismatched"),
            SyncError::BlockValidationFailed(reason) => {
                write!(f, "Block validation failed: {}", reason)
            }
        }
    }
}

/// Lightweight peer information derived from snapshots exposed by the network layer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub address: String,
    pub node_id: Option<String>,
    pub validator_address: Option<String>,
    pub block_height: u64,
    pub best_block_hash: String,
    pub genesis_hash: String,
    pub quarantined: bool,
    pub consensus_duties_disabled: bool,
    pub recovery_state: Option<String>,
}

/// Represents a requested range that should be downloaded/applied.
#[derive(Debug, Clone)]
pub struct BlockRange {
    pub start: u64,
    pub end: u64,
}

/// Sync manager responsible for bootstrapping from genesis and keeping the node current.
pub struct SyncManager {
    pub state: SyncState,
    pub local_height: u64,
    pub network_height: u64,
    pub sync_start_height: u64,
    pub pending_blocks: BTreeMap<u64, Block>,
    pub download_queue: VecDeque<BlockRange>,
    pub peers: Vec<PeerInfo>,
    blockchain: Arc<Mutex<BlockChain>>,
    p2p_network: Option<Arc<P2PNetwork>>,
    max_sync_batch_blocks: u64,
    progress: SyncProgress,
}

impl SyncManager {
    pub fn new(blockchain: Arc<Mutex<BlockChain>>) -> Self {
        let tip_height = blockchain
            .lock()
            .ok()
            .and_then(|chain| chain.last().map(|block| block.block_index))
            .unwrap_or(0);
        SyncManager {
            state: SyncState::Idle,
            local_height: tip_height,
            network_height: tip_height,
            sync_start_height: tip_height,
            pending_blocks: BTreeMap::new(),
            download_queue: VecDeque::new(),
            peers: Vec::new(),
            blockchain,
            p2p_network: None,
            max_sync_batch_blocks: MAX_SYNC_BATCH_BLOCKS,
            progress: SyncProgress::new(tip_height, tip_height),
        }
    }

    pub fn attach_network(&mut self, network: Arc<P2PNetwork>) {
        self.max_sync_batch_blocks = network.sync_batch_limit().max(1);
        self.p2p_network = Some(network);
    }

    fn refresh_local_height(&mut self) {
        if let Ok(chain) = self.blockchain.lock() {
            self.local_height = chain.last().map(|b| b.block_index).unwrap_or(0);
            self.progress.current_block = self.local_height;
        }
    }

    fn collect_peer_snapshots(&self) -> Vec<PeerSnapshot> {
        if let Some(network) = &self.p2p_network {
            network.collect_peer_snapshots()
        } else {
            Vec::new()
        }
    }

    fn refresh_peers_from_snapshots(&mut self, snapshots: Vec<PeerSnapshot>) {
        self.peers = snapshots
            .into_iter()
            .map(|snap| PeerInfo {
                address: snap.address,
                node_id: snap.node_id,
                validator_address: snap.validator_address,
                block_height: snap.block_height,
                best_block_hash: snap.best_block_hash,
                genesis_hash: snap.genesis_hash,
                quarantined: snap.quarantined,
                consensus_duties_disabled: snap.consensus_duties_disabled,
                recovery_state: snap.recovery_state,
            })
            .collect();
    }

    fn peer_is_support_sync_source(&self, peer: &PeerInfo) -> bool {
        let node_id = peer
            .node_id
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let recovery_state = peer
            .recovery_state
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let address = peer.address.trim();

        node_id.starts_with("sentry")
            || node_id.starts_with("relayer")
            || node_id.starts_with("relay")
            || node_id.contains("rpc")
            || node_id.contains("gateway")
            || node_id.contains("archive")
            || address == "167.86.83.83:5623"
            || address == "73.79.66.255:5622"
            || recovery_state.contains("support")
            || recovery_state.contains("sentry")
            || recovery_state.contains("relay")
    }

    fn peer_is_eligible_sync_source(&self, peer: &PeerInfo, local_genesis: &str) -> bool {
        !peer.quarantined
            && (!peer.consensus_duties_disabled
                || peer
                    .validator_address
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .is_none()
                || self.peer_is_support_sync_source(peer))
            && (local_genesis.is_empty() || peer.genesis_hash == local_genesis)
    }

    fn eligible_network_height(&self, local_genesis: &str) -> u64 {
        self.peers
            .iter()
            .filter(|peer| self.peer_is_eligible_sync_source(peer, local_genesis))
            .map(|peer| peer.block_height)
            .max()
            .unwrap_or(0)
    }

    fn await_peer_snapshots(&self, timeout: Duration) -> Vec<PeerSnapshot> {
        let start = Instant::now();
        let mut last = Vec::new();

        if let Some(network) = &self.p2p_network {
            network.request_peer_statuses();
        }

        loop {
            let snapshots = self.collect_peer_snapshots();
            if !snapshots.is_empty() {
                last = snapshots;
                let has_height = last.iter().any(|peer| peer.block_height > 0);
                if has_height {
                    return last;
                }
            }

            if start.elapsed() >= timeout {
                return last;
            }

            thread::sleep(Duration::from_millis(500));
            if let Some(network) = &self.p2p_network {
                network.request_peer_statuses();
            }
        }
    }

    fn select_sync_peer(&self) -> Option<String> {
        let local_genesis = resolve_local_genesis_hash(&self.blockchain);
        let remaining = self.network_height.saturating_sub(self.local_height);
        let mut candidates: Vec<&PeerInfo> = self
            .peers
            .iter()
            .filter(|peer| self.peer_is_eligible_sync_source(peer, &local_genesis))
            .collect();
        candidates.sort_by(|a, b| {
            let a_score = sync_peer_history_score(a, remaining);
            let b_score = sync_peer_history_score(b, remaining);
            let a_key = (
                sync_peer_effective_height(a, remaining, self.network_height),
                a_score,
            );
            let b_key = (
                sync_peer_effective_height(b, remaining, self.network_height),
                b_score,
            );
            b_key.cmp(&a_key)
        });
        candidates.first().map(|peer| peer.address.clone())
    }

    pub fn discover_network_height(&mut self) -> Result<u64, SyncError> {
        let snapshots = self.await_peer_snapshots(Duration::from_secs(10));
        self.refresh_peers_from_snapshots(snapshots);

        if self.peers.is_empty() {
            return Err(SyncError::NoPeers);
        }

        let local_genesis = resolve_local_genesis_hash(&self.blockchain);

        Ok(self.eligible_network_height(&local_genesis))
    }

    pub fn start_sync(&mut self) -> Result<(), SyncError> {
        self.refresh_local_height();
        self.state = SyncState::Discovering;
        let network_height = self.discover_network_height()?;
        self.network_height = network_height;

        if self.local_height >= network_height {
            self.state = SyncState::Synced;
            return Ok(());
        }

        self.sync_start_height = self.local_height;
        self.progress.starting_block = self.local_height;
        self.progress.highest_block = network_height;
        self.state = SyncState::Downloading;

        while self.local_height < self.network_height {
            self.refresh_peers_from_snapshots(self.collect_peer_snapshots());
            if let Ok(updated_height) = self.discover_network_height() {
                if updated_height > self.network_height {
                    self.network_height = updated_height;
                }
            }
            let sync_tip = self.local_height;
            let remaining = self.network_height - self.local_height;
            let batch_size = remaining.min(self.max_sync_batch_blocks.max(1));
            let target_height = std::cmp::min(self.network_height, sync_tip + batch_size);
            let request_overlap = self.sync_request_overlap(batch_size, sync_tip);
            let request_start = sync_tip.saturating_sub(request_overlap);
            let request_count = target_height
                .saturating_sub(request_start)
                .saturating_add(1)
                .min(u32::MAX as u64) as u32;

            if let Some(network) = &self.p2p_network {
                let preferred_peer = self.select_sync_peer();
                let sent = preferred_peer
                    .as_ref()
                    .map(|peer| {
                        network.request_blocks_from_peer(peer, request_start, request_count)
                    })
                    .unwrap_or(false);
                if !sent {
                    network.request_blocks(request_start, request_count);
                }
            } else {
                return Err(SyncError::NetworkUnavailable);
            }

            // Scale timeout with request size because overlap/reconciliation can request
            // a wider range than the net-new block count.
            let batch_timeout_secs =
                std::cmp::max(15, std::cmp::min(180, request_count as u64 / 50 + 10));
            let batch_timeout = Duration::from_secs(batch_timeout_secs);
            let mut satisfied = self.wait_for_height(target_height, batch_timeout);
            self.refresh_local_height();
            if !satisfied && self.local_height > sync_tip {
                satisfied = true;
            }
            if !satisfied {
                if let Some(network) = &self.p2p_network {
                    let preferred_peer = self.select_sync_peer();
                    let sent = preferred_peer
                        .as_ref()
                        .map(|peer| {
                            network.request_blocks_from_peer(peer, request_start, request_count)
                        })
                        .unwrap_or(false);
                    if !sent {
                        network.request_blocks(request_start, request_count);
                    }
                }
                satisfied = self.wait_for_height(target_height, batch_timeout);
                self.refresh_local_height();
                if !satisfied && self.local_height > sync_tip {
                    satisfied = true;
                }
            }
            if !satisfied {
                return Err(SyncError::Timeout(format!(
                    "blocks up to height {}",
                    target_height
                )));
            }

            self.state = SyncState::Validating;

            let validation_start = sync_tip.saturating_add(1);
            let headers =
                fast_sync::download_headers(&self.blockchain, validation_start, self.local_height);
            let prev_hash = if validation_start > 0 {
                Some(self.get_block_hash(validation_start - 1)?)
            } else {
                None
            };
            validation::validate_header_chain(&headers, prev_hash)?;

            let bodies = fast_sync::download_block_bodies(&self.blockchain, &headers);
            for block in bodies {
                validation::validate_block(&block)?;
            }

            self.progress.current_block = self.local_height;
            self.progress.highest_block = self.network_height;

            self.state = SyncState::Applying;
            self.download_queue.push_back(BlockRange {
                start: validation_start,
                end: target_height,
            });
        }

        self.state = SyncState::Synced;
        Ok(())
    }

    fn wait_for_height(&self, target: u64, timeout: Duration) -> bool {
        let start = Instant::now();
        while Instant::now().duration_since(start) < timeout {
            if let Ok(chain) = self.blockchain.lock() {
                if let Some(last) = chain.last() {
                    if last.block_index >= target {
                        return true;
                    }
                }
            }
            thread::sleep(Duration::from_millis(250));
        }
        false
    }

    fn sync_request_overlap(&self, batch_size: u64, local_height: u64) -> u64 {
        let overlap = sync_progress_overlap(batch_size);
        if overlap == 0 {
            return 0;
        }

        let Ok(chain) = self.blockchain.lock() else {
            return 0;
        };
        if !chain_has_reconciliation_window(&chain, local_height, overlap) {
            return 0;
        }

        overlap
    }

    fn get_block_hash(&self, height: u64) -> Result<String, SyncError> {
        let chain = self
            .blockchain
            .lock()
            .map_err(|_| SyncError::NetworkUnavailable)?;
        chain
            .chain
            .iter()
            .find(|block| block.block_index == height)
            .map(|block| block.hash.clone())
            .ok_or(SyncError::MissingBlock(height))
    }

    pub fn get_state(&self) -> SyncState {
        self.state
    }

    pub fn get_network_height(&self) -> u64 {
        self.network_height
    }

    pub fn get_sync_start_height(&self) -> u64 {
        self.sync_start_height
    }

    pub fn get_progress_percentage(&self) -> f64 {
        self.progress.percentage()
    }
}

fn sync_progress_overlap(batch_size: u64) -> u64 {
    if batch_size <= 1 {
        return 0;
    }

    SYNC_RECONCILIATION_LOOKBACK
        .min(SYNC_PROGRESS_OVERLAP)
        .min(batch_size - 1)
}

fn chain_has_reconciliation_window(chain: &BlockChain, local_height: u64, overlap: u64) -> bool {
    if overlap == 0 {
        return true;
    }

    let start = local_height.saturating_sub(overlap);
    (start..=local_height).all(|height| chain.block_at_height(height).is_some())
}

fn sync_peer_history_score(peer: &PeerInfo, remaining: u64) -> u8 {
    if remaining <= 5_000 {
        return 0;
    }

    let node_id = peer
        .node_id
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let address = peer.address.trim();

    if node_id.contains("rpc")
        || node_id.contains("gateway")
        || node_id.contains("archive")
        || address == "167.86.83.83:5623"
        || address == "73.79.66.255:5622"
    {
        2
    } else if node_id.starts_with("sentry")
        || node_id.starts_with("relayer")
        || node_id.starts_with("relay")
    {
        1
    } else {
        0
    }
}

fn sync_peer_effective_height(peer: &PeerInfo, remaining: u64, network_height: u64) -> u64 {
    if peer.block_height == 0 && sync_peer_history_score(peer, remaining) >= 2 {
        network_height
    } else {
        peer.block_height
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(
        address: &str,
        node_id: Option<&str>,
        validator_address: Option<&str>,
        height: u64,
        quarantined: bool,
        duty_disabled: bool,
    ) -> PeerInfo {
        PeerInfo {
            address: address.to_string(),
            node_id: node_id.map(str::to_string),
            validator_address: validator_address.map(str::to_string),
            block_height: height,
            best_block_hash: format!("hash-{height}"),
            genesis_hash: String::new(),
            quarantined,
            consensus_duties_disabled: duty_disabled,
            recovery_state: None,
        }
    }

    fn assign_peer_genesis(peers: &mut [PeerInfo], local_genesis: &str) {
        for peer in peers {
            peer.genesis_hash = local_genesis.to_string();
        }
    }

    #[test]
    fn sync_overlap_is_smaller_than_support_response_budget() {
        assert_eq!(sync_progress_overlap(0), 0);
        assert_eq!(sync_progress_overlap(1), 0);
        assert_eq!(sync_progress_overlap(2), 1);
        assert_eq!(sync_progress_overlap(64), SYNC_PROGRESS_OVERLAP);
    }

    #[test]
    fn compact_snapshot_chain_disables_sync_overlap() {
        let mut chain = BlockChain::new();
        let mut retained = Block::new_with_timestamp(
            743_026,
            Vec::new(),
            "parent".to_string(),
            "validator".to_string(),
            0,
            2,
        );
        retained.hash = "retained-tip".to_string();
        chain.add_block(retained);

        let blockchain = Arc::new(Mutex::new(chain));
        let manager = SyncManager::new(blockchain);

        assert_eq!(manager.sync_request_overlap(96, 743_026), 0);
    }

    #[test]
    fn contiguous_hot_chain_keeps_sync_overlap() {
        let mut chain = BlockChain::new();
        for height in 100..=102 {
            let mut block = Block::new_with_timestamp(
                height,
                Vec::new(),
                format!("parent-{height}"),
                "validator".to_string(),
                height,
                height,
            );
            block.hash = format!("hash-{height}");
            chain.add_block(block);
        }
        let blockchain = Arc::new(Mutex::new(chain));
        let manager = SyncManager::new(blockchain);

        assert_eq!(manager.sync_request_overlap(96, 102), SYNC_PROGRESS_OVERLAP);
    }

    #[test]
    fn sync_peer_selection_rejects_quarantined_and_duty_disabled_validators() {
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let mut manager = SyncManager::new(blockchain);
        manager.peers = vec![
            peer(
                "quarantined",
                None,
                Some("synv1quarantined"),
                200,
                true,
                true,
            ),
            peer("duty-disabled", None, Some("synv1shadow"), 180, false, true),
            peer("active", None, Some("synv1active"), 100, false, false),
        ];
        let local_genesis = resolve_local_genesis_hash(&manager.blockchain);
        assign_peer_genesis(&mut manager.peers, &local_genesis);

        assert_eq!(manager.select_sync_peer(), Some("active".to_string()));
        assert_eq!(manager.eligible_network_height(""), 100);
    }

    #[test]
    fn sync_peer_selection_accepts_duty_disabled_support_peers() {
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let mut manager = SyncManager::new(blockchain);
        manager.peers = vec![
            peer(
                "active-validator",
                None,
                Some("synv1active"),
                100,
                false,
                false,
            ),
            peer(
                "relayer",
                Some("sentry1"),
                Some("synv21ga3nsdjagzt9pmks4mzjq4vdjyngdwq6jst632"),
                195_000,
                false,
                true,
            ),
        ];
        let local_genesis = resolve_local_genesis_hash(&manager.blockchain);
        assign_peer_genesis(&mut manager.peers, &local_genesis);

        assert_eq!(manager.select_sync_peer(), Some("relayer".to_string()));
        assert_eq!(manager.eligible_network_height(""), 195_000);
    }

    #[test]
    fn deep_sync_peer_selection_prefers_history_gateway_over_relayers() {
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let mut manager = SyncManager::new(blockchain);
        manager.local_height = 748_937;
        manager.network_height = 760_908;
        manager.peers = vec![
            peer(
                "195.26.241.95:5622",
                Some("sentry1"),
                Some("synv21ga3nsdjagzt9pmks4mzjq4vdjyngdwq6jst632"),
                760_908,
                false,
                true,
            ),
            peer(
                "167.86.83.83:5623",
                Some("genesisrpc"),
                Some("synv5d2b6a255a574438fd8bdcb194a782acbdcf2"),
                0,
                false,
                true,
            ),
            peer(
                "94.72.117.108:5622",
                Some("sentry2"),
                Some("synv21xaqlq808sunuchd0jwr4m324h85fza2ps3s4k7"),
                760_908,
                false,
                true,
            ),
        ];
        let local_genesis = resolve_local_genesis_hash(&manager.blockchain);
        assign_peer_genesis(&mut manager.peers, &local_genesis);

        assert_eq!(
            manager.select_sync_peer(),
            Some("167.86.83.83:5623".to_string())
        );
    }

    #[test]
    fn sync_peer_selection_uses_canonical_genesis_for_compact_chain() {
        std::env::set_var(
            "SYNERGY_GENESIS_FILE",
            concat!(env!("CARGO_MANIFEST_DIR"), "/../config/genesis.json"),
        );
        let canonical_hash = canonical_genesis()
            .expect("canonical genesis should load")
            .hash()
            .to_string();
        assert!(!canonical_hash.is_empty());

        let mut chain = BlockChain::new();
        let mut retained = Block::new_with_timestamp(
            261_825,
            Vec::new(),
            "retained-parent".to_string(),
            "validator".to_string(),
            0,
            1,
        );
        retained.hash = "retained-block-hash".to_string();
        chain.chain.push(retained);

        let blockchain = Arc::new(Mutex::new(chain));
        let mut manager = SyncManager::new(blockchain);
        let mut canonical_peer = peer("canonical", None, Some("synv1active"), 100, false, false);
        canonical_peer.genesis_hash = canonical_hash.clone();
        let mut retained_hash_peer = peer("retained", None, Some("synv1stale"), 200, false, false);
        retained_hash_peer.genesis_hash = "retained-block-hash".to_string();
        manager.peers = vec![retained_hash_peer, canonical_peer];

        assert_eq!(
            resolve_local_genesis_hash(&manager.blockchain),
            canonical_hash
        );
        assert_eq!(manager.select_sync_peer(), Some("canonical".to_string()));
    }
}
