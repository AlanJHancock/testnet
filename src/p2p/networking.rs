use crate::block::{Block, BlockChain, HOT_CHAIN_RETENTION_BLOCKS_ENV};
use crate::config::NodeConfig;
use crate::consensus::anti_divergence::current_validator_quarantine_duty_block;
use crate::consensus::chain_durability::append_committed_block_body;
use crate::consensus::consensus_algorithm::ProofOfSynergy;
use crate::consensus::dual_quorum::{DualQuorumConsensus, QuorumCertificate};
use crate::consensus::legacy_canonical_lock::{
    legacy_canonical_commit_record, verify_legacy_canonical_lock, write_legacy_canonical_lock,
};
use crate::consensus::timing_trace;
use crate::crypto::aegis_pqvm::{
    AegisPqvmKeyRegistry, AegisPqvmSigner, AegisPqvmVerifier, SYNERGY_P2P_HANDSHAKE_V1,
};
use crate::crypto::pqc::{PQCAlgorithm, PQCPublicKey};
use crate::genesis::canonical_genesis;
use crate::p2p::messages::NetworkMessage;
use crate::rpc::rpc_server::{
    prune_transaction_hashes_from_pool, transaction_hashes, SYNC_MANAGER, TX_POOL,
};
use crate::sync::SyncState;
use crate::synergy_types::{AegisPqKeyId, AegisPqKeyRole, Epoch};
use crate::transaction::Transaction;
use crate::validator::{
    apply_validator_activation_transaction, consensus_membership_validators,
    is_validator_activation_transaction, ValidatorManager, ValidatorRegistration,
    VALIDATOR_MANAGER,
};
use crate::{debug, error, info, warn};
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::{Resolver, TokioResolver};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json;
use socket2::{SockRef, TcpKeepalive};
#[cfg(test)]
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::runtime::{Builder as TokioRuntimeBuilder, Runtime as TokioRuntime};

#[cfg(test)]
thread_local! {
    static TEST_COMMIT_VERIFIER_VALIDATOR_MANAGER: RefCell<Option<Arc<ValidatorManager>>> =
        RefCell::new(None);
}

// Type aliases to avoid nested generics parsing issues
type PeerMap = HashMap<String, PeerConnection>;
type BlockchainArc = Arc<Mutex<BlockChain>>;
type PeersArc = Arc<Mutex<PeerMap>>;
type DialTargetsArc = Arc<Mutex<Vec<String>>>;
type PeerStateCacheArc = Arc<Mutex<HashMap<String, CachedPeerState>>>;
type DialRegistryArc = Arc<Mutex<HashMap<String, DialReservation>>>;

#[cfg(test)]
const DEFAULT_BOOTSTRAP_REFRESH_SECS: u64 = 10;
const NORMAL_BOOTSTRAP_REFRESH_SECS: u64 = 120;
const TCP_KEEPALIVE_IDLE_SECS: u64 = 300;
const TCP_KEEPALIVE_INTERVAL_SECS: u64 = 60;
const IMMEDIATE_STATUS_SYNC_BATCH: u32 = 32;
const MAX_STATUS_SYNC_BATCH: u32 = 48;
const PUBLIC_HISTORY_GATEWAY_DIAL_ADDRESSES: &[&str] = &[
    "167.86.83.83:5623",
    "73.79.66.255:5622",
    "archive.synergynode.xyz:5615",
    "73.79.66.255:5615",
];
const MAX_BLOCK_SYNC_RESPONSE_BLOCKS: u32 = 64;
const MAX_VALIDATOR_SUPPORT_SYNC_RESPONSE_BLOCKS: u32 = 64;
const MAX_SUPPORT_NODE_BLOCK_SYNC_RESPONSE_BLOCKS: u32 = 128;
const MAX_SUPPORT_PEER_DEEP_SYNC_LAG: u64 = 64_000;
const MAX_P2P_FRAME_BYTES: usize = 64 * 1024 * 1024;
const BLOCK_SYNC_RESPONSE_WRITE_TIMEOUT_SECS: u64 = 1;
const SUPPORT_NODE_BLOCK_SYNC_RESPONSE_WRITE_TIMEOUT_SECS: u64 = 2;
const VALIDATOR_SUPPORT_SYNC_RESPONSE_WRITE_TIMEOUT_MILLIS: u64 = 500;
const BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS: u64 = 1;
const VALIDATOR_SUPPORT_BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS: u64 = 2;
const SUPPORT_NODE_BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS: u64 = 1;
const CONSENSUS_MESSAGE_WRITE_TIMEOUT_MILLIS: u64 = 500;
const CONSENSUS_DIRECT_VOTE_DIAL_TIMEOUT_MILLIS: u64 = 1_200;
const VOTE_REQUEST_PARENT_SYNC_WAIT_MILLIS: u64 = 900;
const VOTE_REQUEST_PARENT_SYNC_POLL_MILLIS: u64 = 25;
const MAX_PENDING_BLOCK_HEIGHTS: usize = 256;
const MAX_PENDING_BLOCKS_PER_HEIGHT: usize = 4;
const OUTBOUND_DIAL_COOLDOWN_SECS: u64 = 3;
const MAX_PENDING_INCOMING_CONNECTIONS_PER_HOST: usize = 8;
const VALIDATOR_P2P_PORT: u16 = 5622;
const VALIDATOR_STATUS_GENESIS_GRACE_SECS: u64 = 30;
const STALE_UNIDENTIFIED_PEER_SECS: u64 = 15;
const STALE_VALIDATOR_STATUS_SECS: u64 = VALIDATOR_STATUS_GENESIS_GRACE_SECS + 15;
const BACKGROUND_SYNC_POLL_MILLIS: u64 = 1000;
const BLOCK_SYNC_RECONCILIATION_LOOKBACK: u64 = 8;
const BLOCK_SYNC_PROGRESS_OVERLAP: u64 = 2;
const TESTNET_NATIVE_CAIP2: &str = "synergy:testnet";
const TESTNET_RESERVED_EIP155: &str = "eip155:1264";
const TESTNET_NETWORK_ID_TEXT: &str = "synergy-testnet-v2";
const TESTNET_AEGIS_PQVM_VERSION: &str = "aegis-pqvm";
const DEFAULT_MAX_CHAIN_SNAPSHOT_CLONE_HEIGHT: u64 = 50_000;

fn compact_hot_chain_state_from_env(chain: &mut BlockChain, context: &str) {
    if let Some((retain_recent_blocks, removed_blocks)) = chain.compact_from_env() {
        if removed_blocks > 0 {
            debug!(
                "p2p",
                "Compacted hot chain state from retention setting",
                "context" => context.to_string(),
                "retention_env" => HOT_CHAIN_RETENTION_BLOCKS_ENV,
                "retain_recent_blocks" => retain_recent_blocks,
                "removed_blocks" => removed_blocks as u64,
                "first_retained_height" => chain.chain.first().map(|block| block.block_index).unwrap_or(0),
                "tip_height" => chain.last().map(|block| block.block_index).unwrap_or(0),
                "hot_block_count" => chain.chain.len() as u64
            );
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionDirection {
    Incoming,
    Outgoing,
}

#[derive(Debug, Clone, Copy)]
struct DialReservation {
    in_flight: bool,
    last_attempt_at: Instant,
}

#[derive(Debug, Clone)]
struct PendingCommittedBlock {
    block: Block,
    quorum_certificate: QuorumCertificate,
}

lazy_static! {
    static ref LAST_CHAIN_PERSIST: Mutex<Option<(u64, Instant)>> = Mutex::new(None);
    static ref PENDING_BLOCKS: Mutex<BTreeMap<u64, Vec<PendingCommittedBlock>>> =
        Mutex::new(BTreeMap::new());
    static ref CHAIN_PERSIST_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
    static ref BLOCK_SYNC_LAST_SERVED: Mutex<HashMap<String, u64>> = Mutex::new(HashMap::new());
}

pub struct P2PNetwork {
    blockchain: BlockchainArc,
    config: NodeConfig,
    connected_peers: PeersArc,
    peer_state_cache: PeerStateCacheArc,
    discovered_dial_targets: DialTargetsArc,
    outbound_dial_registry: DialRegistryArc,
    is_running: Arc<Mutex<bool>>,
    message_sender: mpsc::Sender<(String, NetworkMessage)>,
    message_receiver: Arc<Mutex<mpsc::Receiver<(String, NetworkMessage)>>>,
}

struct PeerConnection {
    address: String,
    direction: ConnectionDirection,
    public_address: Option<String>,
    validator_address: Option<String>,
    connected_at: u64,
    last_seen: u64,
    blocks_sent: u64,
    blocks_received: u64,
    txs_sent: u64,
    txs_received: u64,
    stream: Option<TcpStream>,
    node_id: Option<String>,
    version: Option<String>,
    capabilities: Vec<String>,
    last_known_height: u64,
    best_block_hash: String,
    genesis_hash: String,
    status_received_at: Option<u64>,
    quarantined: bool,
    consensus_duties_disabled: bool,
    recovery_state: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlockSyncResponsePolicy {
    max_blocks: u32,
    write_timeout: Duration,
}

fn select_block_sync_response_blocks(
    chain: &BlockChain,
    from_height: u64,
    response_count: u32,
) -> Vec<Block> {
    let start = chain
        .chain
        .partition_point(|block| block.block_index < from_height);
    chain.chain[start..]
        .iter()
        .take(response_count as usize)
        .cloned()
        .collect()
}

#[derive(Debug, Clone, Default)]
struct CachedPeerState {
    public_address: Option<String>,
    validator_address: Option<String>,
    node_id: Option<String>,
    version: Option<String>,
    capabilities: Vec<String>,
    last_known_height: u64,
    best_block_hash: String,
    genesis_hash: String,
    status_received_at: Option<u64>,
    quarantined: bool,
    consensus_duties_disabled: bool,
    recovery_state: Option<String>,
    last_seen: u64,
    connected_at: u64,
}

struct PeerEntryGuard {
    peer_address: String,
    connected_peers: PeersArc,
    peer_state_cache: PeerStateCacheArc,
}

struct BootstrapDnsResolver {
    resolver: TokioResolver,
    runtime: TokioRuntime,
}

impl PeerEntryGuard {
    fn new(
        peer_address: String,
        connected_peers: PeersArc,
        peer_state_cache: PeerStateCacheArc,
    ) -> Self {
        Self {
            peer_address,
            connected_peers,
            peer_state_cache,
        }
    }
}

impl Drop for PeerEntryGuard {
    fn drop(&mut self) {
        if let Ok(mut peers) = self.connected_peers.lock() {
            if peers.contains_key(&self.peer_address) {
                disconnect_peer_entry(&self.peer_state_cache, &mut peers, &self.peer_address);
                info!("p2p", "Peer disconnected", "peer" => self.peer_address.clone());
            }
        }
    }
}

fn should_disconnect_for_status_genesis_mismatch(
    local_genesis_hash: &str,
    remote_genesis_hash: &str,
    peer_validator_address: Option<&str>,
) -> bool {
    if local_genesis_hash.trim().is_empty() {
        return false;
    }

    let peer_is_validator = peer_validator_address
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);

    if remote_genesis_hash.is_empty() {
        return peer_is_validator;
    }

    remote_genesis_hash != local_genesis_hash
}

fn canonical_genesis_hash() -> String {
    canonical_genesis()
        .map(|genesis| genesis.hash().to_string())
        .unwrap_or_default()
}

fn canonical_network_magic_bytes() -> String {
    canonical_genesis()
        .map(|genesis| genesis.network_magic_bytes().to_string())
        .unwrap_or_default()
}

fn local_chain_id(config: &NodeConfig) -> u64 {
    canonical_genesis()
        .map(|genesis| genesis.chain_id())
        .unwrap_or(config.blockchain.chain_id)
}

fn local_network_id(config: &NodeConfig) -> u64 {
    canonical_genesis()
        .map(|genesis| genesis.network_id())
        .unwrap_or(config.network.id)
}

fn local_protocol_version(config: &NodeConfig) -> String {
    canonical_genesis()
        .map(|genesis| genesis.protocol_version().to_string())
        .unwrap_or_else(|_| config.network.name.clone())
}

fn local_consensus_version(config: &NodeConfig) -> String {
    canonical_genesis()
        .map(|genesis| genesis.consensus_version().to_string())
        .unwrap_or_else(|_| config.consensus.algorithm.clone())
}

fn local_p2p_role(config: &NodeConfig) -> String {
    config
        .identity
        .role
        .trim()
        .split_whitespace()
        .next()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            config
                .node
                .validator_address
                .trim()
                .is_empty()
                .then_some("observer")
        })
        .unwrap_or("validator")
        .to_string()
}

fn canonical_validator_set_hash() -> String {
    canonical_genesis()
        .ok()
        .and_then(|genesis| {
            genesis
                .value()
                .get("integrity")
                .and_then(|value| value.get("validator_set_hash"))
                .and_then(|value| value.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default()
}

fn canonical_json_subtree_hash(path: &[&str]) -> String {
    let Some(mut value) = canonical_genesis().ok().map(|genesis| genesis.value()) else {
        return String::new();
    };
    for segment in path {
        let Some(next) = value.get(*segment) else {
            return String::new();
        };
        value = next;
    }
    serde_json::to_vec(value)
        .map(|bytes| blake3::hash(&bytes).to_hex().to_string())
        .unwrap_or_default()
}

fn canonical_cluster_map_hash() -> String {
    canonical_json_subtree_hash(&["validators"])
}

fn canonical_protocol_config_hash() -> String {
    canonical_json_subtree_hash(&["network"])
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct HandshakePqSigningPayload {
    node_id: String,
    version: String,
    capabilities: Vec<String>,
    chain_id: Option<u64>,
    network_id: Option<u64>,
    network_id_text: Option<String>,
    genesis_hash: String,
    network_magic_bytes: String,
    protocol_version: Option<String>,
    consensus_version: Option<String>,
    native_caip2: Option<String>,
    reserved_eip155: Option<String>,
    public_address: Option<String>,
    validator_address: Option<String>,
    role: Option<String>,
    active_validator_set_hash: Option<String>,
    cluster_map_hash: Option<String>,
    protocol_config_hash: Option<String>,
    aegis_pqvm_version: Option<String>,
    aegis_pq_public_key_id: Option<String>,
    aegis_pq_public_key_algorithm: Option<String>,
    aegis_pq_public_key: Vec<u8>,
}

fn handshake_pq_signing_payload(message: &NetworkMessage) -> Result<Vec<u8>, String> {
    let NetworkMessage::Handshake {
        node_id,
        version,
        capabilities,
        chain_id,
        network_id,
        network_id_text,
        genesis_hash,
        network_magic_bytes,
        protocol_version,
        consensus_version,
        native_caip2,
        reserved_eip155,
        public_address,
        validator_address,
        role,
        active_validator_set_hash,
        cluster_map_hash,
        protocol_config_hash,
        aegis_pqvm_version,
        aegis_pq_public_key_id,
        aegis_pq_public_key_algorithm,
        aegis_pq_public_key,
        ..
    } = message
    else {
        return Err("P2P handshake signature payload requested for non-handshake".to_string());
    };

    serde_json::to_vec(&HandshakePqSigningPayload {
        node_id: node_id.clone(),
        version: version.clone(),
        capabilities: capabilities.clone(),
        chain_id: *chain_id,
        network_id: *network_id,
        network_id_text: network_id_text.clone(),
        genesis_hash: genesis_hash.clone(),
        network_magic_bytes: network_magic_bytes.clone(),
        protocol_version: protocol_version.clone(),
        consensus_version: consensus_version.clone(),
        native_caip2: native_caip2.clone(),
        reserved_eip155: reserved_eip155.clone(),
        public_address: public_address.clone(),
        validator_address: validator_address.clone(),
        role: role.clone(),
        active_validator_set_hash: active_validator_set_hash.clone(),
        cluster_map_hash: cluster_map_hash.clone(),
        protocol_config_hash: protocol_config_hash.clone(),
        aegis_pqvm_version: aegis_pqvm_version.clone(),
        aegis_pq_public_key_id: aegis_pq_public_key_id.clone(),
        aegis_pq_public_key_algorithm: aegis_pq_public_key_algorithm.clone(),
        aegis_pq_public_key: aegis_pq_public_key.clone(),
    })
    .map_err(|error| format!("serialize canonical P2P handshake payload: {error}"))
}

fn parse_handshake_pqc_algorithm(value: &str) -> Result<PQCAlgorithm, String> {
    match value.trim() {
        "fndsa" | "FN-DSA-1024" => Ok(PQCAlgorithm::FNDSA),
        "slhdsa" | "SLH-DSA" => Err(format!(
            "unsupported Aegis PQC peer key algorithm: {value}; use fndsa"
        )),
        other => Err(format!("unsupported Aegis PQC peer key algorithm: {other}")),
    }
}

fn build_local_handshake(config: &NodeConfig) -> Result<NetworkMessage, String> {
    let mut signer = AegisPqvmSigner::initialize_required()
        .map_err(|error| format!("aegis-pqvm P2P signer initialization failed: {error}"))?;
    let peer_uma = config
        .p2p
        .node_name
        .trim()
        .is_empty()
        .then_some("synergy-node")
        .unwrap_or_else(|| config.p2p.node_name.trim());
    let key_id = signer
        .generate_and_register_key(peer_uma, vec![AegisPqKeyRole::PeerIdentity], Epoch(0))
        .map_err(|error| format!("aegis-pqvm P2P key loading failed: {error}"))?;
    let public_key = signer
        .public_key_record(&key_id)
        .map_err(|error| format!("aegis-pqvm P2P public key loading failed: {error}"))?;
    let mut handshake = NetworkMessage::Handshake {
        node_id: config.p2p.node_name.clone(),
        version: "1.0.0".to_string(),
        capabilities: vec!["blocks".to_string(), "transactions".to_string()],
        chain_id: Some(local_chain_id(config)),
        network_id: Some(local_network_id(config)),
        network_id_text: Some(TESTNET_NETWORK_ID_TEXT.to_string()),
        genesis_hash: canonical_genesis_hash(),
        network_magic_bytes: canonical_network_magic_bytes(),
        protocol_version: Some(local_protocol_version(config)),
        consensus_version: Some(local_consensus_version(config)),
        native_caip2: Some(TESTNET_NATIVE_CAIP2.to_string()),
        reserved_eip155: Some(TESTNET_RESERVED_EIP155.to_string()),
        public_address: Some(config.p2p.public_address.clone()),
        validator_address: announced_validator_address(config),
        role: Some(local_p2p_role(config)),
        active_validator_set_hash: Some(canonical_validator_set_hash()),
        cluster_map_hash: Some(canonical_cluster_map_hash()),
        protocol_config_hash: Some(canonical_protocol_config_hash()),
        aegis_pqvm_version: Some(TESTNET_AEGIS_PQVM_VERSION.to_string()),
        aegis_pq_public_key_id: Some(public_key.key_id.0.clone()),
        aegis_pq_public_key_algorithm: Some(public_key.algorithm.clone()),
        aegis_pq_public_key: public_key.key_bytes.clone(),
        aegis_pq_handshake_signature: None,
    };
    let payload = handshake_pq_signing_payload(&handshake)?;
    let signature = signer
        .sign_peer_hello(&payload, &key_id)
        .map_err(|error| format!("aegis-pqvm P2P handshake signing failed: {error}"))?;
    if let NetworkMessage::Handshake {
        aegis_pq_handshake_signature,
        ..
    } = &mut handshake
    {
        *aegis_pq_handshake_signature = Some(signature);
    }
    Ok(handshake)
}

fn verify_handshake_pq_signature(message: &NetworkMessage) -> Result<(), String> {
    let NetworkMessage::Handshake {
        node_id,
        chain_id,
        network_id_text,
        aegis_pq_public_key_id,
        aegis_pq_public_key_algorithm,
        aegis_pq_public_key,
        aegis_pq_handshake_signature,
        ..
    } = message
    else {
        return Err("P2P handshake verification requested for non-handshake".to_string());
    };

    if *chain_id != Some(1264) {
        return Err("Aegis PQC handshake must bind chain_id 1264".to_string());
    }
    if network_id_text.as_deref() != Some(TESTNET_NETWORK_ID_TEXT) {
        return Err(format!(
            "Aegis PQC handshake must bind network_id {TESTNET_NETWORK_ID_TEXT}"
        ));
    }
    let key_id = aegis_pq_public_key_id
        .as_ref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "missing Aegis PQC peer key id".to_string())?;
    let algorithm = aegis_pq_public_key_algorithm
        .as_ref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "missing Aegis PQC peer key algorithm".to_string())
        .and_then(|value| parse_handshake_pqc_algorithm(value))?;
    if aegis_pq_public_key.is_empty() {
        return Err("missing Aegis PQC peer public key".to_string());
    }
    let signature = aegis_pq_handshake_signature
        .as_ref()
        .filter(|signature| signature.is_present())
        .ok_or_else(|| "missing Aegis PQC peer handshake signature".to_string())?;

    let payload = handshake_pq_signing_payload(message)?;
    let key_id = AegisPqKeyId(key_id.clone());
    let mut registry = AegisPqvmKeyRegistry::default();
    registry.register_public_key(
        node_id,
        PQCPublicKey {
            algorithm,
            key_data: aegis_pq_public_key.clone(),
            key_id: key_id.0.clone(),
            created_at: 0,
        },
        vec![AegisPqKeyRole::PeerIdentity],
        Epoch(0),
    );
    let verifier = AegisPqvmVerifier::initialize_required(registry)
        .map_err(|error| format!("aegis-pqvm P2P verifier initialization failed: {error}"))?;
    verifier
        .verify_domain_signature(
            SYNERGY_P2P_HANDSHAKE_V1,
            &payload,
            node_id,
            &key_id,
            Epoch(0),
            AegisPqKeyRole::PeerIdentity,
            signature,
        )
        .map_err(|error| format!("Aegis PQC peer handshake verification failed: {error}"))
}

fn handshake_mismatch_reason(
    config: &NodeConfig,
    chain_id: Option<u64>,
    network_id: Option<u64>,
    network_id_text: Option<&str>,
    genesis_hash: &str,
    network_magic_bytes: &str,
    native_caip2: Option<&str>,
) -> Option<String> {
    let expected_chain_id = local_chain_id(config);
    let expected_network_id = local_network_id(config);
    let expected_genesis_hash = canonical_genesis_hash();
    let expected_network_magic_bytes = canonical_network_magic_bytes();

    match chain_id {
        Some(value) if value == expected_chain_id => {}
        Some(value) => {
            return Some(format!(
                "chain_id differs: expected {expected_chain_id}, remote {value}"
            ));
        }
        None => return Some(format!("chain_id missing: expected {expected_chain_id}")),
    }

    match network_id {
        Some(value) if value == expected_network_id => {}
        Some(value) => {
            return Some(format!(
                "network_id differs: expected {expected_network_id}, remote {value}"
            ));
        }
        None => {
            return Some(format!(
                "network_id missing: expected {expected_network_id}"
            ))
        }
    }

    match network_id_text {
        Some(value) if value == TESTNET_NETWORK_ID_TEXT => {}
        Some(value) => {
            return Some(format!(
                "network_id text differs: expected {TESTNET_NETWORK_ID_TEXT}, remote {value}"
            ));
        }
        None => {
            return Some(format!(
                "network_id text missing: expected {TESTNET_NETWORK_ID_TEXT}"
            ));
        }
    }

    if genesis_hash.trim().is_empty() {
        return Some("genesis_hash missing from handshake".to_string());
    }
    if !expected_genesis_hash.is_empty() && genesis_hash != expected_genesis_hash {
        return Some(format!(
            "genesis_hash differs: expected {expected_genesis_hash}, remote {genesis_hash}"
        ));
    }

    if network_magic_bytes.trim().is_empty() {
        return Some("network_magic_bytes missing from handshake".to_string());
    }
    if !expected_network_magic_bytes.is_empty()
        && network_magic_bytes != expected_network_magic_bytes
    {
        return Some(format!(
            "network_magic_bytes differs: expected {expected_network_magic_bytes}, remote {network_magic_bytes}"
        ));
    }

    if let Some(caip2) = native_caip2 {
        if caip2 != TESTNET_NATIVE_CAIP2 {
            return Some(format!(
                "native CAIP-2 differs: expected {TESTNET_NATIVE_CAIP2}, remote {caip2}"
            ));
        }
    }

    None
}

fn resolve_local_genesis_hash(blockchain: &BlockchainArc) -> String {
    let canonical = canonical_genesis_hash();
    if !canonical.trim().is_empty() {
        return canonical;
    }

    blockchain
        .lock()
        .ok()
        .and_then(|chain| chain.get_genesis_hash())
        .filter(|hash| !hash.trim().is_empty())
        .unwrap_or_default()
}

fn validator_status_genesis_grace_remaining_secs(connected_at: u64, now: u64) -> u64 {
    VALIDATOR_STATUS_GENESIS_GRACE_SECS.saturating_sub(now.saturating_sub(connected_at))
}

fn validator_status_genesis_within_grace_window(connected_at: u64, now: u64) -> bool {
    now.saturating_sub(connected_at) < VALIDATOR_STATUS_GENESIS_GRACE_SECS
}

fn ensure_peer_status_allows_chain_data(
    blockchain: &BlockchainArc,
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    peer_address: &str,
    message_kind: &str,
) -> bool {
    let local_genesis_hash = resolve_local_genesis_hash(blockchain);
    let mut peers = connected_peers.lock().unwrap();
    let Some((
        remote_genesis_hash,
        peer_validator_address,
        status_received_at,
        authenticated_public_history_gateway,
    )) = peers.get(peer_address).map(|peer| {
        (
            peer.genesis_hash.clone(),
            peer.validator_address.clone(),
            peer.status_received_at,
            peer_has_authenticated_public_history_gateway_status(peer, &local_genesis_hash),
        )
    })
    else {
        return false;
    };

    if should_disconnect_for_status_genesis_mismatch(
        &local_genesis_hash,
        &remote_genesis_hash,
        peer_validator_address.as_deref(),
    ) {
        warn!(
            "p2p",
            "Disconnecting peer attempting chain data exchange with mismatched genesis hash",
            "peer" => peer_address.to_string(),
            "message_kind" => message_kind.to_string(),
            "local_genesis_hash" => local_genesis_hash,
            "remote_genesis_hash" => remote_genesis_hash
        );
        disconnect_peer_entry(peer_state_cache, &mut peers, peer_address);
        return false;
    }

    if (status_received_at.is_none() || remote_genesis_hash.trim().is_empty())
        && !authenticated_public_history_gateway
    {
        debug!(
            "p2p",
            "Ignoring chain data until peer status confirms canonical genesis",
            "peer" => peer_address.to_string(),
            "message_kind" => message_kind.to_string()
        );
        request_status_from_connected_peer(&mut peers, peer_address);
        return false;
    }

    true
}

#[derive(Debug, Deserialize)]
struct SeedPeerListResponse {
    #[serde(default)]
    bootnodes: Vec<SeedBootnodeRecord>,
    #[serde(default)]
    dnsaddr_bootstrap: Vec<String>,
    #[serde(default)]
    peers: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SeedBootnodeRecord {
    hostname: String,
    port: u16,
    #[serde(default)]
    reachable: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DuplicateResolution {
    KeepExisting,
    ReplaceExisting,
}

fn resolve_local_validator_address(config: &NodeConfig) -> String {
    let configured = config.node.validator_address.trim();
    if !configured.is_empty() {
        return configured.to_string();
    }

    std::env::var("SYNERGY_VALIDATOR_ADDRESS")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::env::var("NODE_ADDRESS")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| config.p2p.node_name.clone())
}

fn announced_validator_address(config: &NodeConfig) -> Option<String> {
    if config.node.bootstrap_only {
        return None;
    }

    let resolved = resolve_local_validator_address(config);
    let trimmed = resolved.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn local_peer_identity(config: &NodeConfig) -> String {
    let validator_address = announced_validator_address(config);
    peer_identity_key(&config.p2p.node_name, validator_address.as_deref())
}

fn peer_identity_key(node_id: &str, validator_address: Option<&str>) -> String {
    validator_address
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| format!("validator:{value}"))
        .unwrap_or_else(|| format!("node:{}", node_id.trim()))
}

fn peer_identity_from_connection(peer: &PeerConnection) -> Option<String> {
    peer.node_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|node_id| peer_identity_key(node_id, peer.validator_address.as_deref()))
}

fn peer_has_remote_status(peer: &PeerConnection) -> bool {
    peer.status_received_at.is_some() && !peer.genesis_hash.trim().is_empty()
}

fn peer_has_identifying_metadata(peer: &PeerConnection) -> bool {
    peer.node_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some()
        || peer
            .validator_address
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some()
        || peer
            .public_address
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some()
}

fn peer_has_validator_identity(peer: &PeerConnection) -> bool {
    peer.validator_address
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some()
}

fn peer_matches_address(peer: &PeerConnection, requested_address: &str) -> bool {
    let requested_address = requested_address.trim();
    peer.address.trim() == requested_address
        || peer
            .public_address
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            == Some(requested_address)
}

fn peer_is_public_history_gateway(peer: &PeerConnection) -> bool {
    let node_id = peer
        .node_id
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    (node_id.contains("rpc") || node_id.contains("gateway") || node_id.contains("archive"))
        && PUBLIC_HISTORY_GATEWAY_DIAL_ADDRESSES
            .iter()
            .any(|address| peer_matches_address(peer, address))
}

fn peer_has_authenticated_public_history_gateway_status(
    peer: &PeerConnection,
    local_genesis_hash: &str,
) -> bool {
    !local_genesis_hash.trim().is_empty()
        && peer.genesis_hash.trim() == local_genesis_hash
        && peer_is_public_history_gateway(peer)
}

fn connected_peer_key_for_address(peers: &PeerMap, requested_address: &str) -> Option<String> {
    if peers.contains_key(requested_address) {
        return Some(requested_address.to_string());
    }

    peers.iter().find_map(|(address, peer)| {
        peer_matches_address(peer, requested_address).then(|| address.clone())
    })
}

fn peer_socket_port(address: &str) -> Option<u16> {
    let normalized = parse_bootnode_dial_address(address)?;
    normalized
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
}

fn genesis_validator_slot_from_text(value: &str) -> Option<usize> {
    let lower = value.trim().to_ascii_lowercase();
    let marker = "genesisval";
    let start = lower.find(marker)? + marker.len();
    let digits = lower[start..]
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<usize>().ok().filter(|slot| *slot > 0)
}

fn canonical_validator_address_for_slot(slot: usize) -> Option<String> {
    canonical_genesis()
        .ok()
        .and_then(|genesis| {
            genesis
                .validators()
                .get(slot.saturating_sub(1))
                .map(|validator| validator.operator_address.clone())
        })
        .filter(|address| !address.trim().is_empty())
}

fn configured_vote_target_validator_addresses(
    config: &NodeConfig,
    active_validator_addresses: &HashSet<String>,
) -> Vec<String> {
    let mut configured = config
        .node
        .allowed_validator_addresses
        .iter()
        .map(|address| address.trim().to_string())
        .filter(|address| !address.is_empty())
        .collect::<Vec<_>>();

    if configured.is_empty() {
        if let Ok(genesis) = canonical_genesis() {
            configured = genesis
                .validators()
                .iter()
                .map(|validator| validator.operator_address.trim().to_string())
                .filter(|address| !address.is_empty())
                .collect();
        }
    }

    configured.retain(|address| {
        active_validator_addresses.is_empty() || active_validator_addresses.contains(address)
    });
    configured.dedup();
    configured
}

fn configured_validator_p2p_dials(config: &NodeConfig) -> Vec<String> {
    let mut dials = Vec::new();
    let mut seen = HashSet::new();

    for dial in config
        .network
        .persistent_peers
        .iter()
        .chain(config.network.additional_dial_targets.iter())
    {
        let Some(parsed) = parse_bootnode_dial_address(dial) else {
            continue;
        };
        if peer_socket_port(&parsed) != Some(VALIDATOR_P2P_PORT) {
            continue;
        }
        if !is_assigned_synergy_dial_address(&parsed) {
            continue;
        }
        let host = peer_socket_host(&parsed).to_ascii_lowercase();
        if host.contains("relay")
            || host.contains("rpc")
            || host.contains("archive")
            || host.contains("bootnode")
            || host.contains("seed")
            || host.contains("observer")
        {
            continue;
        }
        if seen.insert(parsed.clone()) {
            dials.push(parsed);
        }
    }

    dials
}

fn configured_validator_public_address_map(
    config: &NodeConfig,
    active_validator_addresses: &HashSet<String>,
) -> HashMap<String, String> {
    let validators =
        configured_vote_target_validator_addresses(config, active_validator_addresses);
    if validators.is_empty() {
        return HashMap::new();
    }

    let dials = configured_validator_p2p_dials(config);
    let mapped_pairs = if dials.len() == validators.len() {
        dials.into_iter().zip(validators).collect::<Vec<_>>()
    } else if dials.len() + 1 == validators.len() {
        let local_validator = announced_validator_address(config)
            .map(|address| address.trim().to_string())
            .filter(|address| !address.is_empty())
            .filter(|address| validators.iter().any(|validator| validator == address));
        if let Some(local_validator) = local_validator {
            let peer_validators = validators
                .into_iter()
                .filter(|validator| validator != &local_validator)
                .collect::<Vec<_>>();
            if peer_validators.len() == dials.len() {
                dials.into_iter().zip(peer_validators).collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    } else if dials.len() > validators.len() {
        dials[dials.len() - validators.len()..]
            .iter()
            .cloned()
            .zip(validators)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    mapped_pairs
        .into_iter()
        .flat_map(|(dial, validator)| {
            let mut entries = Vec::new();
            entries.push((dial.clone(), validator.clone()));
            let host = peer_socket_host(&dial);
            if !host.trim().is_empty() {
                entries.push((format!("{host}:{VALIDATOR_P2P_PORT}"), validator));
            }
            entries
        })
        .collect()
}

fn recover_peer_validator_address_for_vote_target(
    config: &NodeConfig,
    peer: &PeerConnection,
    active_validator_addresses: &HashSet<String>,
) -> Option<String> {
    let enforce_active_validator_filter = !config.node.allowed_validator_addresses.is_empty();
    if let Some(validator_address) = peer
        .validator_address
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if !enforce_active_validator_filter
            || active_validator_addresses.is_empty()
            || active_validator_addresses.contains(validator_address)
        {
            return Some(validator_address.to_string());
        }
    }

    for identity_text in [
        peer.node_id.as_deref(),
        peer.public_address.as_deref(),
        Some(peer.address.as_str()),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(slot) = genesis_validator_slot_from_text(identity_text) {
            if let Some(validator_address) = canonical_validator_address_for_slot(slot) {
                if active_validator_addresses.is_empty()
                    || active_validator_addresses.contains(&validator_address)
                {
                    return Some(validator_address);
                }
            }
        }
    }

    let address_map = configured_validator_public_address_map(config, active_validator_addresses);
    for candidate in [peer.public_address.as_deref(), Some(peer.address.as_str())]
        .into_iter()
        .flatten()
    {
        let Some(parsed) = parse_bootnode_dial_address(candidate) else {
            continue;
        };
        if let Some(validator_address) = address_map.get(&parsed) {
            return Some(validator_address.clone());
        }
        let canonical = canonical_validator_public_address(&parsed, Some(&parsed));
        if let Some(canonical) = canonical {
            if let Some(validator_address) = address_map.get(&canonical) {
                return Some(validator_address.clone());
            }
        }
    }

    None
}

fn should_prune_stale_peer(
    config: &NodeConfig,
    peer: &PeerConnection,
    now: u64,
    active_validator_addresses: &HashSet<String>,
) -> bool {
    let connected_age = now.saturating_sub(peer.connected_at);
    let recovered_validator =
        recover_peer_validator_address_for_vote_target(config, peer, active_validator_addresses);
    let has_identifying_metadata =
        peer_has_identifying_metadata(peer) || recovered_validator.is_some();

    if !has_identifying_metadata {
        return connected_age >= STALE_UNIDENTIFIED_PEER_SECS;
    }

    (peer_has_validator_identity(peer) || recovered_validator.is_some())
        && !peer_has_remote_status(peer)
        && connected_age >= STALE_VALIDATOR_STATUS_SECS
}

fn prune_stale_peers(
    config: &NodeConfig,
    peer_state_cache: &PeerStateCacheArc,
    connected_peers: &PeersArc,
) {
    let now = current_timestamp();
    let active_validator_addresses =
        configured_vote_target_validator_addresses(config, &HashSet::new())
            .into_iter()
            .collect::<HashSet<_>>();
    let mut peers = connected_peers.lock().unwrap();
    let stale_peer_keys = peers
        .iter()
        .filter_map(|(peer_key, peer)| {
            should_prune_stale_peer(config, peer, now, &active_validator_addresses)
                .then_some(peer_key.clone())
        })
        .collect::<Vec<_>>();

    for peer_key in stale_peer_keys {
        if let Some(peer) = peers.get(&peer_key) {
            warn!(
                "p2p",
                "Disconnecting stale peer to force mesh recovery",
                "peer" => peer_key.clone(),
                "direction" => format!("{:?}", peer.direction),
                "connected_age_secs" => now.saturating_sub(peer.connected_at),
                "last_seen_age_secs" => now.saturating_sub(peer.last_seen),
                "validator_address" => peer.validator_address.clone().unwrap_or_default(),
                "has_identifying_metadata" => peer_has_identifying_metadata(peer)
                    || recover_peer_validator_address_for_vote_target(
                        config,
                        peer,
                        &active_validator_addresses,
                    )
                    .is_some(),
                "has_remote_status" => peer_has_remote_status(peer)
            );
        }
        disconnect_peer_entry(peer_state_cache, &mut peers, &peer_key);
    }
}

fn pending_incoming_connections_from_host(peers: &PeerMap, host: &str) -> usize {
    peers
        .values()
        .filter(|peer| {
            peer.direction == ConnectionDirection::Incoming
                && peer_socket_host(&peer.address) == host
                && !peer_has_identifying_metadata(peer)
        })
        .count()
}

fn build_cached_peer_state(peer: &PeerConnection) -> Option<(String, CachedPeerState)> {
    let identity = peer_identity_from_connection(peer)?;
    Some((
        identity,
        CachedPeerState {
            public_address: peer.public_address.clone(),
            validator_address: peer.validator_address.clone(),
            node_id: peer.node_id.clone(),
            version: peer.version.clone(),
            capabilities: peer.capabilities.clone(),
            last_known_height: peer.last_known_height,
            best_block_hash: peer.best_block_hash.clone(),
            genesis_hash: peer.genesis_hash.clone(),
            status_received_at: peer.status_received_at,
            quarantined: peer.quarantined,
            consensus_duties_disabled: peer.consensus_duties_disabled,
            recovery_state: peer.recovery_state.clone(),
            last_seen: peer.last_seen,
            connected_at: peer.connected_at,
        },
    ))
}

fn cache_peer_state(peer_state_cache: &PeerStateCacheArc, peer: &PeerConnection) {
    if let Some((identity, state)) = build_cached_peer_state(peer) {
        if let Ok(mut cache) = peer_state_cache.lock() {
            cache.insert(identity, state);
        }
    }
}

fn merge_cached_state_into_peer(peer: &mut PeerConnection, state: &CachedPeerState) {
    if peer
        .public_address
        .as_deref()
        .map(str::trim)
        .unwrap_or_default()
        .is_empty()
    {
        peer.public_address = state.public_address.clone();
    }
    if peer
        .validator_address
        .as_deref()
        .map(str::trim)
        .unwrap_or_default()
        .is_empty()
    {
        peer.validator_address = state.validator_address.clone();
    }
    if peer.node_id.is_none() {
        peer.node_id = state.node_id.clone();
    }
    if peer.version.is_none() {
        peer.version = state.version.clone();
    }
    if peer.capabilities.is_empty() {
        peer.capabilities = state.capabilities.clone();
    }
    if peer.status_received_at.is_none() && state.status_received_at.is_some() {
        peer.last_known_height = state.last_known_height;
        peer.best_block_hash = state.best_block_hash.clone();
        peer.genesis_hash = state.genesis_hash.clone();
        peer.status_received_at = state.status_received_at;
    }
    peer.quarantined = peer.quarantined || state.quarantined;
    peer.consensus_duties_disabled =
        peer.consensus_duties_disabled || state.consensus_duties_disabled;
    if peer.recovery_state.is_none() {
        peer.recovery_state = state.recovery_state.clone();
    }
    peer.last_seen = peer.last_seen.max(state.last_seen);
    peer.connected_at = if peer.connected_at == 0 {
        state.connected_at
    } else if state.connected_at == 0 {
        peer.connected_at
    } else {
        peer.connected_at.min(state.connected_at)
    };
}

fn hydrate_peer_from_cache(
    peer_state_cache: &PeerStateCacheArc,
    peer_identity: &str,
    peer: &mut PeerConnection,
) {
    if let Ok(cache) = peer_state_cache.lock() {
        if let Some(state) = cache.get(peer_identity) {
            merge_cached_state_into_peer(peer, state);
        }
    }
}

fn merge_peer_state_from_existing(existing: &PeerConnection, replacement: &mut PeerConnection) {
    merge_cached_state_into_peer(
        replacement,
        &CachedPeerState {
            public_address: existing.public_address.clone(),
            validator_address: existing.validator_address.clone(),
            node_id: existing.node_id.clone(),
            version: existing.version.clone(),
            capabilities: existing.capabilities.clone(),
            last_known_height: existing.last_known_height,
            best_block_hash: existing.best_block_hash.clone(),
            genesis_hash: existing.genesis_hash.clone(),
            status_received_at: existing.status_received_at,
            quarantined: existing.quarantined,
            consensus_duties_disabled: existing.consensus_duties_disabled,
            recovery_state: existing.recovery_state.clone(),
            last_seen: existing.last_seen,
            connected_at: existing.connected_at,
        },
    );
}

fn propagate_identity_to_matching_peers(
    peers: &mut PeerMap,
    peer_state_cache: &PeerStateCacheArc,
    peer_address: &str,
    node_id: &str,
    version: &str,
    capabilities: &[String],
    public_address: Option<&str>,
    validator_address: Option<&str>,
    genesis_hash: &str,
) {
    let validator_address = validator_address
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let public_address = public_address
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let node_id = node_id.trim();
    if node_id.is_empty() && validator_address.is_none() && public_address.is_none() {
        return;
    }

    let mut source_hosts = HashSet::<String>::new();
    source_hosts.insert(peer_socket_host(peer_address));
    if let Some(public_address) = public_address {
        source_hosts.insert(peer_socket_host(public_address));
    }
    if let Some(peer) = peers.get(peer_address) {
        source_hosts.insert(peer_socket_host(&peer.address));
        if let Some(public_address) = peer.public_address.as_deref() {
            source_hosts.insert(peer_socket_host(public_address));
        }
    }
    source_hosts.retain(|host| !host.trim().is_empty());

    let mut target_keys = peers
        .iter()
        .filter_map(|(address, peer)| {
            if address == peer_address {
                return Some(address.clone());
            }

            let existing_validator = peer
                .validator_address
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let same_validator = validator_address
                .zip(existing_validator)
                .map(|(announced, existing)| announced == existing)
                .unwrap_or(false);
            if existing_validator.is_some() && !same_validator {
                return None;
            }

            let existing_node = peer
                .node_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            if existing_node.is_some() && existing_node != Some(node_id) && !same_validator {
                return None;
            }

            let peer_hosts = [
                Some(address.as_str()),
                Some(peer.address.as_str()),
                peer.public_address.as_deref(),
            ];
            let shares_source_host = peer_hosts
                .into_iter()
                .flatten()
                .map(peer_socket_host)
                .any(|host| source_hosts.contains(&host));
            let public_address_matches = public_address
                .map(|public_address| {
                    address.trim() == public_address || peer_matches_address(peer, public_address)
                })
                .unwrap_or(false);

            (peer_matches_address(peer, peer_address)
                || public_address_matches
                || shares_source_host)
                .then(|| address.clone())
        })
        .collect::<Vec<_>>();
    target_keys.sort();
    target_keys.dedup();

    for target_key in target_keys {
        if let Some(peer) = peers.get_mut(&target_key) {
            if !node_id.is_empty() {
                peer.node_id = Some(node_id.to_string());
            }
            if !version.trim().is_empty() {
                peer.version = Some(version.to_string());
            }
            if peer.capabilities.is_empty() {
                peer.capabilities = capabilities.to_vec();
            }
            if let Some(public_address) = public_address {
                peer.public_address = Some(public_address.to_string());
            }
            if let Some(validator_address) = validator_address {
                peer.validator_address = Some(validator_address.to_string());
            }
            if !genesis_hash.trim().is_empty() {
                peer.genesis_hash = genesis_hash.to_string();
            }
            cache_peer_state(peer_state_cache, peer);
        }
    }
}

fn apply_status_to_peer(
    peer: &mut PeerConnection,
    block_height: u64,
    best_block_hash: &str,
    genesis_hash: &str,
    quarantined: bool,
    consensus_duties_disabled: bool,
    recovery_state: Option<&str>,
    status_received_at: u64,
) {
    if block_height >= peer.last_known_height {
        peer.last_known_height = block_height;
        if !best_block_hash.trim().is_empty() {
            peer.best_block_hash = best_block_hash.to_string();
        }
    }

    if !genesis_hash.trim().is_empty() {
        peer.genesis_hash = genesis_hash.to_string();
    }

    peer.status_received_at = Some(status_received_at);
    peer.quarantined = quarantined;
    peer.consensus_duties_disabled = consensus_duties_disabled || quarantined;
    peer.recovery_state = recovery_state
        .map(str::trim)
        .filter(|state| !state.is_empty())
        .map(ToOwned::to_owned);
}

fn propagate_status_to_matching_peers(
    peers: &mut PeerMap,
    peer_state_cache: &PeerStateCacheArc,
    peer_address: &str,
    block_height: u64,
    best_block_hash: &str,
    genesis_hash: &str,
    quarantined: bool,
    consensus_duties_disabled: bool,
    recovery_state: Option<&str>,
) {
    let identity = peers
        .get(peer_address)
        .and_then(peer_identity_from_connection);
    let source_hosts = peers
        .get(peer_address)
        .map(|peer| {
            let mut hosts = HashSet::<String>::new();
            hosts.insert(peer_socket_host(peer_address));
            hosts.insert(peer_socket_host(&peer.address));
            if let Some(public_address) = peer.public_address.as_deref() {
                hosts.insert(peer_socket_host(public_address));
            }
            hosts.retain(|host| !host.trim().is_empty());
            hosts
        })
        .unwrap_or_else(|| {
            let mut hosts = HashSet::<String>::new();
            hosts.insert(peer_socket_host(peer_address));
            hosts.retain(|host| !host.trim().is_empty());
            hosts
        });
    let mut target_keys = identity
        .as_deref()
        .map(|peer_identity| {
            peers
                .iter()
                .filter_map(|(address, peer)| {
                    (peer_identity_from_connection(peer).as_deref() == Some(peer_identity))
                        .then(|| address.clone())
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    for (address, peer) in peers.iter() {
        let peer_hosts = [
            Some(address.as_str()),
            Some(peer.address.as_str()),
            peer.public_address.as_deref(),
        ];
        let shares_source_host = peer_hosts
            .into_iter()
            .flatten()
            .map(peer_socket_host)
            .any(|host| source_hosts.contains(&host));
        if address == peer_address
            || peer_matches_address(peer, peer_address)
            || (peer_has_validator_identity(peer) && shares_source_host)
        {
            target_keys.push(address.clone());
        }
    }

    if target_keys.is_empty() {
        target_keys.push(peer_address.to_string());
    }
    target_keys.sort();
    target_keys.dedup();

    let status_received_at = current_timestamp();
    for target_key in target_keys {
        if let Some(peer) = peers.get_mut(&target_key) {
            apply_status_to_peer(
                peer,
                block_height,
                best_block_hash,
                genesis_hash,
                quarantined,
                consensus_duties_disabled,
                recovery_state,
                status_received_at,
            );
            cache_peer_state(peer_state_cache, peer);
        }
    }
}

fn status_sync_batch(block_height: u64, local_height: u64) -> Option<u32> {
    if block_height <= local_height {
        return None;
    }

    let behind = block_height.saturating_sub(local_height);
    Some(if behind > 5000 {
        MAX_STATUS_SYNC_BATCH
    } else if behind > 1000 {
        MAX_STATUS_SYNC_BATCH
    } else {
        IMMEDIATE_STATUS_SYNC_BATCH
    })
}

fn block_sync_request_range(
    local_height: u64,
    remote_height: u64,
    desired_new_blocks: u32,
) -> Option<(u64, u32)> {
    block_sync_request_range_with_overlap(local_height, remote_height, desired_new_blocks, true)
}

fn block_sync_request_range_with_overlap(
    local_height: u64,
    remote_height: u64,
    desired_new_blocks: u32,
    include_reconciliation_overlap: bool,
) -> Option<(u64, u32)> {
    if remote_height <= local_height || desired_new_blocks == 0 {
        return None;
    }

    let overlap = if include_reconciliation_overlap {
        block_sync_progress_overlap(desired_new_blocks)
    } else {
        0
    };
    let request_start = local_height.saturating_sub(overlap);
    let target_height = remote_height.min(local_height.saturating_add(desired_new_blocks as u64));
    let request_count = target_height
        .saturating_sub(request_start)
        .saturating_add(1)
        .min(u32::MAX as u64) as u32;

    Some((request_start, request_count.max(1)))
}

fn block_sync_progress_overlap(desired_new_blocks: u32) -> u64 {
    if desired_new_blocks <= 1 {
        return 0;
    }

    BLOCK_SYNC_RECONCILIATION_LOOKBACK
        .min(BLOCK_SYNC_PROGRESS_OVERLAP)
        .min(desired_new_blocks as u64 - 1)
}

fn chain_has_block_sync_overlap(
    chain: &BlockChain,
    local_height: u64,
    desired_new_blocks: u32,
) -> bool {
    let overlap = block_sync_progress_overlap(desired_new_blocks);
    if overlap == 0 {
        return true;
    }

    let start = local_height.saturating_sub(overlap);
    (start..=local_height).all(|height| chain.block_at_height(height).is_some())
}

fn handle_status_message(
    blockchain: &BlockchainArc,
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    config: &NodeConfig,
    peer_address: &str,
    block_height: u64,
    best_block_hash: &str,
    genesis_hash: &str,
    quarantined: bool,
    consensus_duties_disabled: bool,
    recovery_state: Option<&str>,
) {
    if config.node.bootstrap_only {
        debug!(
            "p2p",
            "Bootstrap-only node ignoring remote chain status",
            "peer" => peer_address.to_string(),
            "height" => block_height
        );
        return;
    }

    let local_genesis_hash = resolve_local_genesis_hash(blockchain);
    let (peer_validator_address, peer_node_id, peer_connected_at) = {
        let peers = connected_peers.lock().unwrap();
        peers
            .get(peer_address)
            .map(|peer| {
                (
                    peer.validator_address.clone(),
                    peer.node_id.clone(),
                    peer.connected_at,
                )
            })
            .unwrap_or((None, None, current_timestamp()))
    };
    let now = current_timestamp();
    let validator_genesis_pending = genesis_hash.is_empty()
        && peer_validator_address
            .as_deref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
        && validator_status_genesis_within_grace_window(peer_connected_at, now);
    if validator_genesis_pending {
        let mut peers = connected_peers.lock().unwrap();
        propagate_status_to_matching_peers(
            &mut peers,
            peer_state_cache,
            peer_address,
            block_height,
            best_block_hash,
            genesis_hash,
            quarantined,
            consensus_duties_disabled,
            recovery_state,
        );
        request_status_from_connected_peer(&mut peers, peer_address);
        info!(
            "p2p",
            "Validator status pending canonical genesis sync",
            "peer" => peer_address.to_string(),
            "validator_address" => peer_validator_address.clone().unwrap_or_default(),
            "connected_secs" => now.saturating_sub(peer_connected_at),
            "grace_remaining_secs" => validator_status_genesis_grace_remaining_secs(peer_connected_at, now),
            "reported_height" => block_height
        );
        return;
    }

    if should_disconnect_for_status_genesis_mismatch(
        &local_genesis_hash,
        genesis_hash,
        peer_validator_address.as_deref(),
    ) {
        warn!(
            "p2p",
            "Disconnecting peer with mismatched genesis hash",
            "peer" => peer_address.to_string(),
            "local_genesis_hash" => local_genesis_hash,
            "remote_genesis_hash" => genesis_hash.to_string()
        );
        let mut peers = connected_peers.lock().unwrap();
        disconnect_peer_entry(peer_state_cache, &mut peers, peer_address);
        return;
    }

    if genesis_hash.is_empty() {
        debug!(
            "p2p",
            "Keeping discovery peer without genesis hash",
            "peer" => peer_address.to_string()
        );
    }

    {
        let mut peers = connected_peers.lock().unwrap();
        propagate_status_to_matching_peers(
            &mut peers,
            peer_state_cache,
            peer_address,
            block_height,
            best_block_hash,
            genesis_hash,
            quarantined,
            consensus_duties_disabled,
            recovery_state,
        );
    }
    info!(
        "p2p",
        "Received status",
        "peer" => peer_address.to_string(),
        "height" => block_height
    );

    let local_height = {
        let chain = blockchain.lock().unwrap();
        chain.last().map(|block| block.block_index).unwrap_or(0)
    };
    if !status_peer_is_eligible_block_sync_source(
        peer_validator_address.as_deref(),
        peer_node_id.as_deref(),
        recovery_state,
        quarantined,
        consensus_duties_disabled,
    ) {
        debug!(
            "p2p",
            "Skipping block sync request to duty-disabled peer",
            "peer" => peer_address.to_string(),
            "reported_height" => block_height,
            "quarantined" => quarantined,
            "consensus_duties_disabled" => consensus_duties_disabled,
            "recovery_state" => recovery_state.clone().unwrap_or_default()
        );
        return;
    }
    if let Some(batch) = status_sync_batch(block_height, local_height) {
        let Some((request_start, request_count)) =
            block_sync_request_range(local_height, block_height, batch)
        else {
            return;
        };
        let mut peers = connected_peers.lock().unwrap();
        request_blocks_from_connected_peer(&mut peers, peer_address, request_start, request_count);
    }
}

fn preferred_connection_direction(
    local_identity: &str,
    remote_identity: &str,
) -> Option<ConnectionDirection> {
    let local_identity = local_identity.trim();
    let remote_identity = remote_identity.trim();

    if local_identity.is_empty() || remote_identity.is_empty() || local_identity == remote_identity
    {
        return None;
    }

    if local_identity < remote_identity {
        Some(ConnectionDirection::Outgoing)
    } else {
        Some(ConnectionDirection::Incoming)
    }
}

fn resolve_duplicate_connection(
    local_identity: &str,
    remote_identity: &str,
    existing_direction: ConnectionDirection,
    existing_connected_at: u64,
    new_direction: ConnectionDirection,
    new_connected_at: u64,
) -> DuplicateResolution {
    match preferred_connection_direction(local_identity, remote_identity) {
        Some(preferred) if existing_direction == preferred && new_direction != preferred => {
            DuplicateResolution::KeepExisting
        }
        Some(preferred) if new_direction == preferred && existing_direction != preferred => {
            DuplicateResolution::ReplaceExisting
        }
        _ => {
            if new_connected_at < existing_connected_at {
                DuplicateResolution::ReplaceExisting
            } else {
                DuplicateResolution::KeepExisting
            }
        }
    }
}

fn disconnect_peer_entry(
    peer_state_cache: &PeerStateCacheArc,
    peers: &mut PeerMap,
    peer_key: &str,
) {
    if let Some(mut peer) = peers.remove(peer_key) {
        cache_peer_state(peer_state_cache, &peer);
        if let Some(stream) = peer.stream.take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

fn disconnect_peer_after_poisoned_write(
    peer_state_cache: &PeerStateCacheArc,
    peers: &mut PeerMap,
    peer_key: &str,
    reason: &str,
) {
    warn!(
        "p2p",
        "Disconnecting peer after partial/failed framed write",
        "peer" => peer_key.to_string(),
        "reason" => reason.to_string()
    );
    disconnect_peer_entry(peer_state_cache, peers, peer_key);
}

fn spawn_named_thread<F>(name: &str, task: F) -> bool
where
    F: FnOnce() + Send + 'static,
{
    match thread::Builder::new().name(name.to_string()).spawn(task) {
        Ok(_) => true,
        Err(error) => {
            error!(
                "p2p",
                "Failed to spawn thread",
                "thread" => name.to_string(),
                "error" => error.to_string()
            );
            false
        }
    }
}

fn reserve_outbound_dial(
    dial_registry: &DialRegistryArc,
    connected_peers: &PeersArc,
    target: &str,
    max_peers: usize,
) -> bool {
    let target = target.trim();
    if target.is_empty() {
        return false;
    }

    {
        let peers = connected_peers.lock().unwrap();
        if peers.len() >= max_peers {
            return false;
        }
        if peers.contains_key(target)
            || peers.values().any(|peer| {
                peer.address == target || peer.public_address.as_deref() == Some(target)
            })
        {
            return false;
        }
    }

    let now = Instant::now();
    let mut registry = dial_registry.lock().unwrap();
    match registry.get_mut(target) {
        Some(state) => {
            if state.in_flight {
                return false;
            }
            if now.duration_since(state.last_attempt_at)
                < Duration::from_secs(OUTBOUND_DIAL_COOLDOWN_SECS)
            {
                return false;
            }
            state.in_flight = true;
            state.last_attempt_at = now;
        }
        None => {
            registry.insert(
                target.to_string(),
                DialReservation {
                    in_flight: true,
                    last_attempt_at: now,
                },
            );
        }
    }

    true
}

fn release_outbound_dial(dial_registry: &DialRegistryArc, target: &str) {
    let now = Instant::now();
    let mut registry = dial_registry.lock().unwrap();
    match registry.get_mut(target) {
        Some(state) => {
            state.in_flight = false;
            state.last_attempt_at = now;
        }
        None => {
            registry.insert(
                target.to_string(),
                DialReservation {
                    in_flight: false,
                    last_attempt_at: now,
                },
            );
        }
    }
    registry.retain(|_, state| {
        state.in_flight || now.duration_since(state.last_attempt_at) < Duration::from_secs(300)
    });
}

fn peer_socket_host(address: &str) -> String {
    let raw = address.trim();
    if let Some(stripped) = raw.strip_prefix('[') {
        if let Some((host, _)) = stripped.rsplit_once("]:") {
            return host.to_string();
        }
    }
    raw.rsplit_once(':')
        .map(|(host, _)| host.trim().to_string())
        .unwrap_or_else(|| raw.to_string())
}

fn dial_target_host(dial: &str) -> Option<String> {
    let normalized = parse_bootnode_dial_address(dial)?;
    if let Some(stripped) = normalized.strip_prefix('[') {
        return stripped.rsplit_once("]:").map(|(host, _)| host.to_string());
    }
    normalized
        .rsplit_once(':')
        .map(|(host, _)| host.trim().to_string())
}

fn canonical_validator_public_address(
    peer_address: &str,
    announced_public_address: Option<&str>,
) -> Option<String> {
    if let Some(peer_dial) = parse_bootnode_dial_address(peer_address) {
        if is_public_history_gateway_dial_address(&peer_dial) {
            return Some(peer_dial);
        }
    }

    if let Some(announced_dial) = announced_public_address.and_then(parse_bootnode_dial_address) {
        if is_public_history_gateway_dial_address(&announced_dial) {
            return Some(announced_dial);
        }
    }

    let announced_host = announced_public_address
        .and_then(dial_target_host)
        .filter(|host| is_public_synergy_advertise_host(host));
    if let Some(host) = announced_host {
        return Some(format!("{host}:{VALIDATOR_P2P_PORT}"));
    }

    let peer_host = dial_target_host(peer_address)?;
    if is_public_synergy_advertise_host(&peer_host) {
        Some(format!("{peer_host}:{VALIDATOR_P2P_PORT}"))
    } else {
        None
    }
}

fn should_canonicalize_validator_public_address(validator_address: Option<&str>) -> bool {
    validator_address
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|value| value.starts_with("synv1"))
}

fn is_public_history_gateway_dial_address(address: &str) -> bool {
    let normalized =
        parse_bootnode_dial_address(address).unwrap_or_else(|| address.trim().to_string());
    PUBLIC_HISTORY_GATEWAY_DIAL_ADDRESSES
        .iter()
        .any(|dial| *dial == normalized)
}

fn is_validator_allowed(config: &NodeConfig, validator_address: &str) -> bool {
    if !config.node.strict_validator_allowlist {
        return true;
    }

    config
        .node
        .allowed_validator_addresses
        .iter()
        .any(|allowed| allowed == validator_address)
}

fn resolve_bootstrap_dial_targets(config: &NodeConfig) -> Vec<String> {
    let mut targets = HashSet::<String>::new();

    for bootnode in &config.network.bootnodes {
        if let Some(dial) = parse_bootnode_dial_address(bootnode) {
            if is_assigned_synergy_dial_address(&dial) {
                targets.insert(dial);
            }
        }
    }

    for dial in resolve_dns_bootstrap_targets(&config.network.bootstrap_dns_records) {
        if is_assigned_synergy_dial_address(&dial) {
            targets.insert(dial);
        }
    }

    for dial in resolve_seed_server_targets(&config.network.seed_servers) {
        if is_assigned_synergy_dial_address(&dial) {
            targets.insert(dial);
        }
    }

    for dial in config
        .network
        .persistent_peers
        .iter()
        .chain(config.network.additional_dial_targets.iter())
    {
        if let Some(parsed) = parse_bootnode_dial_address(dial) {
            if is_assigned_synergy_dial_address(&parsed) {
                targets.insert(parsed);
            }
        }
    }

    let self_aliases = self_dial_aliases(config);
    if !self_aliases.is_empty() {
        targets.retain(|target| !self_aliases.contains(target));
    }

    let mut ordered = targets.into_iter().collect::<Vec<_>>();
    ordered.sort();
    ordered
}

fn self_dial_aliases(config: &NodeConfig) -> HashSet<String> {
    let mut aliases = HashSet::new();

    if let Some(address) = parse_bootnode_dial_address(&config.p2p.public_address) {
        aliases.insert(address);
    }
    if let Some(address) = parse_bootnode_dial_address(&config.p2p.listen_address) {
        aliases.insert(address);
    }

    if let Some(slot) = local_validator_slot(config) {
        aliases.insert(format!(
            "genesisval{slot}.synergy-network.io:{}",
            config.network.p2p_port
        ));
    }

    aliases
}

fn is_self_dial_target(config: &NodeConfig, dial: &str) -> bool {
    let Some(normalized) = parse_bootnode_dial_address(dial) else {
        return false;
    };
    self_dial_aliases(config).contains(&normalized)
}

fn local_validator_slot(config: &NodeConfig) -> Option<u64> {
    let validator_address = announced_validator_address(config)?;
    let workspace_root = Path::new(&config.storage.path).parent()?;
    let manifest_path = workspace_root
        .join("config")
        .join("operational-manifest.json");
    let contents = fs::read_to_string(manifest_path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&contents).ok()?;

    value
        .get("validators")
        .and_then(serde_json::Value::as_array)?
        .iter()
        .find(|entry| {
            entry
                .get("address")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .is_some_and(|address| address.eq_ignore_ascii_case(validator_address.as_str()))
        })
        .and_then(|entry| entry.get("slot"))
        .and_then(serde_json::Value::as_u64)
}

#[cfg(test)]
fn connected_validator_participants(config: &NodeConfig, connected_peers: &PeersArc) -> usize {
    let mut validators = HashSet::<String>::new();

    if let Some(local_validator) = announced_validator_address(config) {
        validators.insert(local_validator);
    }

    if let Ok(peers) = connected_peers.lock() {
        for peer in peers.values() {
            if let Some(address) = peer.validator_address.as_deref() {
                let trimmed = address.trim();
                if !trimmed.is_empty() {
                    validators.insert(trimmed.to_string());
                }
            }
        }
    }

    validators.len()
}

fn status_ready_validator_addresses(
    config: &NodeConfig,
    connected_peers: &PeersArc,
) -> Vec<String> {
    let mut validators = HashSet::<String>::new();
    let active_validator_addresses =
        configured_vote_target_validator_addresses(config, &HashSet::new())
            .into_iter()
            .collect::<HashSet<_>>();
    let now = current_timestamp();

    if current_validator_quarantine_duty_block().is_none() {
        if let Some(local_validator) = announced_validator_address(config) {
            validators.insert(local_validator);
        }
    }

    if let Ok(peers) = connected_peers.lock() {
        for peer in peers.values() {
            if peer.quarantined || peer.consensus_duties_disabled {
                continue;
            }
            let recovered_validator =
                recover_peer_validator_address_for_vote_target(config, peer, &active_validator_addresses);
            let recently_seen_configured_validator = recovered_validator.is_some()
                && now.saturating_sub(peer.last_seen) <= STALE_VALIDATOR_STATUS_SECS;
            if !peer_has_remote_status(peer) && !recently_seen_configured_validator {
                continue;
            }
            if let Some(address) = recovered_validator {
                validators.insert(address);
            }
        }
    }

    let mut validators = validators.into_iter().collect::<Vec<_>>();
    validators.sort();
    validators
}

#[cfg(test)]
fn status_ready_validator_addresses_with_local_duty_gate(
    config: &NodeConfig,
    connected_peers: &PeersArc,
    local_duties_disabled: bool,
) -> Vec<String> {
    let mut validators = HashSet::<String>::new();

    if !local_duties_disabled {
        if let Some(local_validator) = announced_validator_address(config) {
            validators.insert(local_validator);
        }
    }

    if let Ok(peers) = connected_peers.lock() {
        for peer in peers.values() {
            if !peer_has_remote_status(peer) || peer.quarantined || peer.consensus_duties_disabled {
                continue;
            }
            if let Some(address) = peer.validator_address.as_deref() {
                let trimmed = address.trim();
                if !trimmed.is_empty() {
                    validators.insert(trimmed.to_string());
                }
            }
        }
    }

    let mut validators = validators.into_iter().collect::<Vec<_>>();
    validators.sort();
    validators
}

fn status_ready_validator_participants(config: &NodeConfig, connected_peers: &PeersArc) -> usize {
    status_ready_validator_addresses(config, connected_peers).len()
}

fn best_connected_validator_height(connected_peers: &PeersArc) -> u64 {
    connected_peers
        .lock()
        .map(|peers| {
            peers
                .values()
                .filter(|peer| peer_is_active_validator_sync_source(peer))
                .map(|peer| peer.last_known_height)
                .max()
                .unwrap_or(0)
        })
        .unwrap_or(0)
}

fn peer_is_active_validator_sync_source(peer: &PeerConnection) -> bool {
    peer.validator_address
        .as_deref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
        && peer_has_remote_status(peer)
        && !peer.quarantined
        && !peer.consensus_duties_disabled
}

fn peer_is_eligible_block_sync_source(peer: &PeerConnection) -> bool {
    if peer.quarantined {
        return false;
    }

    !peer.consensus_duties_disabled
        || !peer_has_validator_identity(peer)
        || peer_identity_is_support_sync_source(
            peer.node_id.as_deref(),
            peer.recovery_state.as_deref(),
        )
}

fn status_peer_is_eligible_block_sync_source(
    peer_validator_address: Option<&str>,
    peer_node_id: Option<&str>,
    recovery_state: Option<&str>,
    quarantined: bool,
    consensus_duties_disabled: bool,
) -> bool {
    if quarantined {
        return false;
    }

    !consensus_duties_disabled
        || peer_validator_address
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        || peer_identity_is_support_sync_source(peer_node_id, recovery_state)
}

fn peer_identity_is_support_sync_source(
    peer_node_id: Option<&str>,
    recovery_state: Option<&str>,
) -> bool {
    let node_id = peer_node_id.unwrap_or_default().trim().to_ascii_lowercase();
    let recovery_state = recovery_state
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    node_id.starts_with("sentry")
        || node_id.starts_with("relayer")
        || node_id.starts_with("relay")
        || node_id.contains("rpc")
        || node_id.contains("gateway")
        || node_id.contains("archive")
        || recovery_state.contains("support")
        || recovery_state.contains("sentry")
        || recovery_state.contains("relay")
}

fn select_block_sync_targets(peers: &PeerMap, max_targets: usize) -> Vec<String> {
    let mut candidates = peers
        .iter()
        .filter(|(_, peer)| peer.stream.is_some() && peer_is_eligible_block_sync_source(peer))
        .map(|(address, peer)| {
            let has_validator_identity = peer
                .validator_address
                .as_deref()
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false);
            (
                address.clone(),
                peer.last_known_height,
                has_validator_identity,
                peer.status_received_at.unwrap_or(0),
            )
        })
        .collect::<Vec<_>>();

    candidates.sort_by(|left, right| {
        right
            .1
            .cmp(&left.1)
            .then_with(|| right.2.cmp(&left.2))
            .then_with(|| right.3.cmp(&left.3))
            .then_with(|| left.0.cmp(&right.0))
    });

    candidates
        .into_iter()
        .take(max_targets.max(1))
        .map(|(address, _, _, _)| address)
        .collect()
}

fn best_connected_validator_height_with_support(
    connected_peers: &PeersArc,
    min_support: usize,
) -> u64 {
    let min_support = min_support.max(1);
    connected_peers
        .lock()
        .map(|peers| {
            let mut active_heights = peers
                .values()
                .filter(|peer| peer_is_active_validator_sync_source(peer))
                .map(|peer| peer.last_known_height)
                .collect::<Vec<_>>();
            active_heights.sort_unstable_by(|left, right| right.cmp(left));
            active_heights
                .get(min_support.saturating_sub(1))
                .copied()
                .unwrap_or(0)
        })
        .unwrap_or(0)
}

fn current_bootstrap_refresh_interval(config: &NodeConfig, connected_peers: &PeersArc) -> Duration {
    let required_validators = config.consensus.min_validators.max(1);
    let discovered_validators = status_ready_validator_participants(config, connected_peers);
    let bootstrap_refresh_secs = config.p2p.bootstrap_refresh_secs.max(1);

    if discovered_validators < required_validators {
        Duration::from_secs(bootstrap_refresh_secs)
    } else {
        Duration::from_secs(NORMAL_BOOTSTRAP_REFRESH_SECS)
    }
}

fn resolve_dns_bootstrap_targets(record_names: &[String]) -> Vec<String> {
    if record_names.is_empty() {
        return Vec::new();
    }

    let resolver = match build_dns_resolver() {
        Ok(resolver) => resolver,
        Err(error) => {
            warn!("p2p", "Failed to initialize DNS resolver for bootstrap discovery", "error" => error);
            return Vec::new();
        }
    };

    let mut visited = HashSet::<String>::new();
    let mut out = HashSet::<String>::new();

    for record_name in record_names {
        collect_dnsaddr_record_targets(&resolver, record_name, 0, &mut visited, &mut out);
    }

    let mut ordered = out.into_iter().collect::<Vec<_>>();
    ordered.sort();
    ordered
}

fn build_dns_resolver() -> Result<BootstrapDnsResolver, String> {
    let runtime = TokioRuntimeBuilder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;

    let resolver = TokioResolver::builder_tokio()
        .and_then(|builder| builder.build())
        .or_else(|_| {
            Resolver::builder_with_config(
                ResolverConfig::default(),
                TokioRuntimeProvider::default(),
            )
            .build()
        })
        .map_err(|error| error.to_string())?;

    Ok(BootstrapDnsResolver { resolver, runtime })
}

fn collect_dnsaddr_record_targets(
    resolver: &BootstrapDnsResolver,
    record_name: &str,
    depth: usize,
    visited: &mut HashSet<String>,
    out: &mut HashSet<String>,
) {
    let record_name = record_name.trim();
    if record_name.is_empty() || depth > 4 {
        return;
    }

    let canonical = record_name.trim_end_matches('.').to_string();
    if !visited.insert(canonical.clone()) {
        return;
    }

    match resolver
        .runtime
        .block_on(resolver.resolver.txt_lookup(canonical.clone()))
    {
        Ok(records) => {
            for record in records.answers() {
                let RData::TXT(txt_record) = &record.data else {
                    continue;
                };

                for txt in txt_record.txt_data.iter() {
                    let Ok(value) = std::str::from_utf8(txt) else {
                        continue;
                    };
                    collect_dnsaddr_txt_target(resolver, value, depth, visited, out);
                }
            }
        }
        Err(error) => {
            debug!(
                "p2p",
                "Bootstrap DNS TXT lookup failed",
                "record" => canonical,
                "error" => error.to_string()
            );
        }
    }
}

fn collect_dnsaddr_txt_target(
    resolver: &BootstrapDnsResolver,
    value: &str,
    depth: usize,
    visited: &mut HashSet<String>,
    out: &mut HashSet<String>,
) {
    let value = value
        .trim()
        .trim_matches('"')
        .strip_prefix("dnsaddr=")
        .unwrap_or(value.trim())
        .trim();
    if value.is_empty() {
        return;
    }

    if let Some(next_record) = parse_dnsaddr_reference_record(value) {
        collect_dnsaddr_record_targets(resolver, &next_record, depth + 1, visited, out);
        return;
    }

    if let Some(dial) = parse_dnsaddr_multiaddr_to_dial_address(value) {
        out.insert(dial);
    }
}

fn parse_dnsaddr_reference_record(value: &str) -> Option<String> {
    let referenced = value.strip_prefix("/dnsaddr/")?;
    let referenced = referenced.split('/').next()?.trim().trim_end_matches('.');
    if referenced.is_empty() {
        None
    } else {
        Some(format!("_dnsaddr.{}", referenced))
    }
}

fn parse_dnsaddr_multiaddr_to_dial_address(value: &str) -> Option<String> {
    let segments = value
        .split('/')
        .filter(|segment| !segment.trim().is_empty())
        .collect::<Vec<_>>();

    let mut host: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut transport: Option<&str> = None;
    let mut index = 0usize;

    while index + 1 < segments.len() {
        let key = segments[index];
        let val = segments[index + 1];
        match key {
            "dns" | "dns4" | "dns6" | "ip4" | "ip6" if host.is_none() => {
                host = Some(val.to_string());
            }
            "tcp" => {
                if let Ok(parsed) = val.parse::<u16>() {
                    port = Some(parsed);
                    transport = Some("tcp");
                }
            }
            "udp" => {
                transport = Some("udp");
            }
            _ => {}
        }
        index += 2;
    }

    match (host, port, transport) {
        (Some(host), Some(port), Some("tcp")) => Some(format!("{host}:{port}")),
        _ => None,
    }
}

fn resolve_seed_server_targets(seed_servers: &[String]) -> Vec<String> {
    if seed_servers.is_empty() {
        return Vec::new();
    }

    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            warn!(
                "p2p",
                "Failed to build HTTP client for seed discovery",
                "error" => error.to_string()
            );
            return Vec::new();
        }
    };

    let mut out = HashSet::<String>::new();
    for seed_server in seed_servers {
        fetch_seed_server_targets(&client, seed_server, &mut out);
    }

    let mut ordered = out.into_iter().collect::<Vec<_>>();
    ordered.sort();
    ordered
}

fn fetch_seed_server_targets(
    client: &reqwest::blocking::Client,
    seed_server: &str,
    out: &mut HashSet<String>,
) {
    let json_url = normalize_seed_server_url(seed_server, "/peer-list.json");
    if !json_url.is_empty() {
        match client.get(&json_url).send() {
            Ok(response) if response.status().is_success() => {
                match response.json::<SeedPeerListResponse>() {
                    Ok(payload) => {
                        for bootnode in payload.bootnodes {
                            if bootnode.reachable.unwrap_or(true) {
                                let dial = format!("{}:{}", bootnode.hostname, bootnode.port);
                                if is_assigned_synergy_dial_address(&dial) {
                                    out.insert(dial);
                                }
                            }
                        }
                        for value in payload.dnsaddr_bootstrap {
                            if let Some(dial) = parse_dnsaddr_multiaddr_to_dial_address(&value) {
                                if is_assigned_synergy_dial_address(&dial) {
                                    out.insert(dial);
                                }
                            }
                        }
                        for peer in payload.peers {
                            if let Some(dial) = parse_bootnode_dial_address(&peer) {
                                if is_assigned_synergy_dial_address(&dial) {
                                    out.insert(dial);
                                }
                            }
                        }
                        return;
                    }
                    Err(error) => {
                        debug!(
                            "p2p",
                            "Failed to parse seed peer list JSON",
                            "seed_server" => seed_server.to_string(),
                            "error" => error.to_string()
                        );
                    }
                }
            }
            Ok(response) => {
                debug!(
                    "p2p",
                    "Seed peer list request returned non-success status",
                    "seed_server" => seed_server.to_string(),
                    "status" => response.status().as_u16()
                );
            }
            Err(error) => {
                debug!(
                    "p2p",
                    "Seed peer list request failed",
                    "seed_server" => seed_server.to_string(),
                    "error" => error.to_string()
                );
            }
        }
    }

    let text_url = normalize_seed_server_url(seed_server, "/dns/bootstrap.txt");
    if text_url.is_empty() {
        return;
    }

    match client.get(&text_url).send() {
        Ok(response) if response.status().is_success() => {
            if let Ok(body) = response.text() {
                for line in body.lines() {
                    let value = line.trim();
                    if value.is_empty() {
                        continue;
                    }
                    if let Some(dial) = parse_dnsaddr_multiaddr_to_dial_address(
                        value.strip_prefix("dnsaddr=").unwrap_or(value),
                    ) {
                        out.insert(dial);
                    }
                }
            }
        }
        Ok(_) | Err(_) => {}
    }
}

fn register_self_with_seed_servers(config: &NodeConfig) {
    if config.node.bootstrap_only || config.network.seed_servers.is_empty() {
        return;
    }
    let role_id = config.identity.role.trim().to_string();
    if !role_id.eq_ignore_ascii_case("validator") {
        return;
    }
    let public_address = config.p2p.public_address.trim().to_string();
    if public_address.is_empty()
        || public_address.starts_with("127.")
        || public_address.starts_with("0.0.0.0")
        || !is_assigned_synergy_dial_address(&public_address)
    {
        return;
    }
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    let validator_address = config.node.validator_address.trim().to_string();
    if validator_address.is_empty() {
        return;
    }
    let mut payload = serde_json::json!({
        "node_id": config.p2p.node_name,
        "role_id": role_id,
        "dial": public_address,
    });
    payload["wallet_address"] = serde_json::Value::String(validator_address);
    for seed_server in &config.network.seed_servers {
        let register_url = normalize_seed_server_url(seed_server, "/peers/register");
        if register_url.is_empty() {
            continue;
        }
        match client.post(&register_url).json(&payload).send() {
            Ok(resp) if resp.status().is_success() => {
                debug!(
                    "p2p",
                    "Registered self with seed server",
                    "seed_server" => seed_server.clone(),
                    "dial" => public_address.clone()
                );
            }
            Ok(resp) => {
                debug!(
                    "p2p",
                    "Seed server self-registration returned non-success",
                    "seed_server" => seed_server.clone(),
                    "status" => resp.status().as_u16()
                );
            }
            Err(e) => {
                debug!(
                    "p2p",
                    "Failed to register self with seed server",
                    "seed_server" => seed_server.clone(),
                    "error" => e.to_string()
                );
            }
        }
    }
}

fn normalize_seed_server_url(seed_server: &str, default_path: &str) -> String {
    let trimmed = seed_server.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }

    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        let remainder = trimmed
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(trimmed);
        if remainder.contains('/') {
            trimmed.to_string()
        } else {
            format!("{trimmed}{default_path}")
        }
    } else {
        format!("http://{trimmed}{default_path}")
    }
}

fn configure_peer_stream(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    // Keep long-lived validator sockets active so NAT devices do not reap them
    // between proposal/vote rounds.
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(TCP_KEEPALIVE_IDLE_SECS))
        .with_interval(Duration::from_secs(TCP_KEEPALIVE_INTERVAL_SECS));
    let socket = SockRef::from(stream);
    let _ = socket.set_tcp_keepalive(&keepalive);
    let _ = stream.set_read_timeout(None);
    let _ = stream.set_write_timeout(None);
}

#[derive(Debug, Clone)]
pub struct PeerSnapshot {
    pub address: String,
    pub direction: String,
    pub node_id: Option<String>,
    pub validator_address: Option<String>,
    pub block_height: u64,
    pub best_block_hash: String,
    pub genesis_hash: String,
    pub status_received_at: Option<u64>,
    pub quarantined: bool,
    pub consensus_duties_disabled: bool,
    pub recovery_state: Option<String>,
    pub connected_at: u64,
    pub last_seen: u64,
    pub blocks_sent: u64,
    pub blocks_received: u64,
    pub txs_sent: u64,
    pub txs_received: u64,
}

impl P2PNetwork {
    pub fn new(blockchain: BlockchainArc, config: &NodeConfig) -> Self {
        let (sender, receiver) = mpsc::channel();

        P2PNetwork {
            blockchain,
            config: config.clone(),
            connected_peers: Arc::new(Mutex::new(HashMap::new())),
            peer_state_cache: Arc::new(Mutex::new(HashMap::new())),
            discovered_dial_targets: Arc::new(Mutex::new(Vec::new())),
            outbound_dial_registry: Arc::new(Mutex::new(HashMap::new())),
            is_running: Arc::new(Mutex::new(false)),
            message_sender: sender,
            message_receiver: Arc::new(Mutex::new(receiver)),
        }
    }

    pub fn start(&mut self, listen_address: &str) {
        let is_running = Arc::clone(&self.is_running);
        let blockchain = Arc::clone(&self.blockchain);
        let connected_peers = Arc::clone(&self.connected_peers);
        let peer_state_cache = Arc::clone(&self.peer_state_cache);
        let config = self.config.clone();
        let addr_string = listen_address.to_string();
        let message_sender = self.message_sender.clone();

        // Set running flag
        *is_running.lock().unwrap() = true;

        // Start listener thread
        let _ = spawn_named_thread("p2p-listener", move || {
            if let Err(e) = start_listener(
                &addr_string,
                blockchain,
                connected_peers,
                peer_state_cache,
                config,
                message_sender,
            ) {
                error!("p2p", "P2P listener error", "error" => e.to_string());
            }
        });

        // Start message handler thread
        let blockchain_handler = Arc::clone(&self.blockchain);
        let peers_handler = Arc::clone(&self.connected_peers);
        let peer_state_cache_handler = Arc::clone(&self.peer_state_cache);
        let discovered_targets_handler = Arc::clone(&self.discovered_dial_targets);
        let dial_registry_handler = Arc::clone(&self.outbound_dial_registry);
        let receiver = Arc::clone(&self.message_receiver);
        let handler_config = self.config.clone();
        let handler_sender = self.message_sender.clone();

        let _ = spawn_named_thread("p2p-message-handler", move || {
            handle_messages(
                blockchain_handler,
                peers_handler,
                peer_state_cache_handler,
                discovered_targets_handler,
                dial_registry_handler,
                receiver,
                handler_sender,
                handler_config,
            );
        });

        info!(
            "p2p",
            "P2P network started",
            "listen_address" => listen_address.to_string(),
            "public_address" => self.config.p2p.public_address.clone(),
            "bootnodes" => self.config.network.bootnodes.len() as u64
        );
    }

    pub fn connect_to_peer(&self, address: &str) -> Result<(), Box<dyn std::error::Error>> {
        let peer_address = address.to_string();
        if !reserve_outbound_dial(
            &self.outbound_dial_registry,
            &self.connected_peers,
            &peer_address,
            self.config.network.max_peers as usize,
        ) {
            return Ok(());
        }

        let blockchain = Arc::clone(&self.blockchain);
        let connected_peers = Arc::clone(&self.connected_peers);
        let peer_state_cache = Arc::clone(&self.peer_state_cache);
        let dial_registry = Arc::clone(&self.outbound_dial_registry);
        let message_sender = self.message_sender.clone();
        let config = self.config.clone();
        let cleanup_address = peer_address.clone();

        let spawned = spawn_named_thread("p2p-connect-peer", move || {
            match dial_with_timeout(&peer_address, std::time::Duration::from_secs(5)) {
                Ok(stream) => {
                    if let Err(e) = handle_outgoing_connection(
                        stream,
                        peer_address,
                        blockchain,
                        connected_peers,
                        peer_state_cache,
                        message_sender,
                        config,
                    ) {
                        error!("p2p", "Outgoing connection error", "error" => e.to_string());
                    }
                }
                Err(e) => {
                    warn!("p2p", "Failed to dial peer", "peer" => peer_address, "error" => e.to_string());
                }
            }
            release_outbound_dial(&dial_registry, &cleanup_address);
        });
        if !spawned {
            release_outbound_dial(&self.outbound_dial_registry, address);
        }

        Ok(())
    }

    pub fn broadcast_block(&self, block: &Block) {
        let Some(qc) = DualQuorumConsensus::committed_qc_for_block_hash(&block.hash) else {
            warn!(
                "p2p",
                "Refusing to broadcast committed block without locally stored QC",
                "height" => block.block_index,
                "hash" => block.hash.clone()
            );
            return;
        };
        self.broadcast_committed_block(block, &qc);
    }

    pub fn broadcast_committed_block(&self, block: &Block, qc: &QuorumCertificate) {
        let message = NetworkMessage::Block {
            block_data: block.clone(),
            quorum_certificate: Some(qc.clone()),
        };

        let mut peers = self.connected_peers.lock().unwrap();
        let mut sent = 0usize;
        let mut failed_peers = Vec::new();
        for (address, peer) in peers.iter_mut() {
            if let Some(ref mut stream) = peer.stream {
                if let Err(e) = send_consensus_message(stream, &message) {
                    warn!("p2p", "Failed to send block", "peer" => address.clone(), "error" => e.to_string());
                    failed_peers.push(address.clone());
                } else {
                    peer.blocks_sent += 1;
                    sent += 1;
                }
            }
        }
        for address in &failed_peers {
            peers.remove(address);
        }

        info!(
            "p2p",
            "Block broadcast",
            "peers" => sent as u64,
            "dropped_peers" => failed_peers.len() as u64,
            "height" => block.block_index
        );
    }

    pub fn broadcast_vote_request(
        &self,
        block: &Block,
        epoch_number: u64,
        round_number: u64,
    ) -> usize {
        let message = NetworkMessage::VoteRequest {
            block_data: block.clone(),
            epoch_number,
            round_number,
        };

        let mut recipients = 0usize;
        let mut failed_peers = Vec::new();
        let active_validator_addresses =
            consensus_membership_validators(VALIDATOR_MANAGER.get_active_validators())
                .into_iter()
                .map(|validator| validator.address)
                .collect::<HashSet<_>>();
        let mut sent_validator_addresses = HashSet::new();
        let mut peers = self.connected_peers.lock().unwrap();
        for (address, peer) in peers.iter_mut() {
            if peer.quarantined || peer.consensus_duties_disabled {
                debug!(
                    "p2p",
                    "Skipping vote request to duty-disabled validator peer",
                    "peer" => address.clone(),
                    "validator_address" => peer.validator_address.clone().unwrap_or_default(),
                    "height" => block.block_index
                );
                continue;
            }
            let Some(validator_address) = recover_peer_validator_address_for_vote_target(
                &self.config,
                peer,
                &active_validator_addresses,
            ) else {
                debug!(
                    "p2p",
                    "Skipping vote request to peer without recoverable validator identity",
                    "peer" => address.clone(),
                    "node_id" => peer.node_id.clone().unwrap_or_default(),
                    "public_address" => peer.public_address.clone().unwrap_or_default(),
                    "height" => block.block_index
                );
                continue;
            };
            let recovered_validator_identity = peer
                .validator_address
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none();
            if !active_validator_addresses.contains(&validator_address)
                || sent_validator_addresses.contains(&validator_address)
            {
                continue;
            }
            if recovered_validator_identity {
                info!(
                    "p2p",
                    "Recovered vote request target validator identity",
                    "peer" => address.clone(),
                    "node_id" => peer.node_id.clone().unwrap_or_default(),
                    "public_address" => peer.public_address.clone().unwrap_or_default(),
                    "validator_address" => validator_address.clone(),
                    "height" => block.block_index
                );
                peer.validator_address = Some(validator_address.clone());
            }
            if let Some(ref mut stream) = peer.stream {
                if let Err(error) = send_consensus_message(stream, &message) {
                    warn!(
                        "p2p",
                        "Failed to send vote request",
                        "peer" => address.clone(),
                        "error" => error.to_string()
                    );
                    failed_peers.push(address.clone());
                } else {
                    sent_validator_addresses.insert(validator_address);
                    recipients += 1;
                }
            }
        }
        for address in &failed_peers {
            peers.remove(address);
        }

        let mut sent_validators = sent_validator_addresses.into_iter().collect::<Vec<_>>();
        sent_validators.sort();
        info!(
            "p2p",
            "Vote request broadcast",
            "peers" => recipients as u64,
            "dropped_peers" => failed_peers.len() as u64,
            "height" => block.block_index,
            "epoch" => epoch_number,
            "round" => round_number,
            "sent_validator_addresses" => sent_validators.join(",")
        );
        recipients
    }

    pub fn broadcast_transaction(&self, transaction: &Transaction) {
        let message = NetworkMessage::Transaction {
            transaction_data: transaction.clone(),
        };

        let mut peers = self.connected_peers.lock().unwrap();
        for (address, peer) in peers.iter_mut() {
            if let Some(ref mut stream) = peer.stream {
                if let Err(e) = send_message(stream, &message) {
                    warn!("p2p", "Failed to send transaction", "peer" => address.clone(), "error" => e.to_string());
                } else {
                    peer.txs_sent += 1;
                }
            }
        }

        info!("p2p", "Transaction broadcast", "peers" => peers.len() as u64, "tx_hash" => transaction.hash());
    }

    pub fn get_peer_count(&self) -> usize {
        // Return only peers that have completed handshake and identified as
        // validators, matching the count shown by get_connected_validator_addresses().
        // Previously this returned ALL entries (including bootnodes and
        // pre-handshake connections), inflating the dashboard peer count.
        let peers = self.connected_peers.lock().unwrap();
        peers
            .values()
            .filter(|peer| {
                peer.validator_address
                    .as_ref()
                    .map(|a| !a.trim().is_empty())
                    .unwrap_or(false)
            })
            .count()
    }

    pub fn get_peer_info(&self) -> Vec<serde_json::Value> {
        let peers = self.connected_peers.lock().unwrap();
        peers
            .values()
            .map(|peer| {
                serde_json::json!({
                    "address": peer.address,
                    "connected_at": peer.connected_at,
                    "last_seen": peer.last_seen,
                    "blocks_sent": peer.blocks_sent,
                    "blocks_received": peer.blocks_received,
                    "txs_sent": peer.txs_sent,
                    "txs_received": peer.txs_received,
                    "node_id": peer.node_id,
                    "public_address": peer.public_address,
                    "validator_address": peer.validator_address,
                    "version": peer.version,
                    "capabilities": peer.capabilities,
                    "genesis_hash": peer.genesis_hash
                })
            })
            .collect()
    }

    pub fn get_connected_validator_addresses(&self) -> Vec<String> {
        let peers = self.connected_peers.lock().unwrap();
        let mut validator_addresses = peers
            .values()
            .filter_map(|peer| peer.validator_address.clone())
            .filter(|address| !address.trim().is_empty())
            .collect::<Vec<_>>();
        validator_addresses.sort();
        validator_addresses.dedup();
        validator_addresses
    }

    pub fn get_status_ready_validator_count(&self) -> usize {
        status_ready_validator_participants(&self.config, &self.connected_peers)
    }

    pub fn get_status_ready_validator_addresses(&self) -> Vec<String> {
        status_ready_validator_addresses(&self.config, &self.connected_peers)
    }

    pub fn get_best_validator_peer_height(&self) -> u64 {
        best_connected_validator_height(&self.connected_peers)
    }

    pub fn get_best_validator_peer_height_with_support(&self, min_support: usize) -> u64 {
        best_connected_validator_height_with_support(&self.connected_peers, min_support)
    }

    pub fn collect_peer_snapshots(&self) -> Vec<PeerSnapshot> {
        let peers = self.connected_peers.lock().unwrap();
        peers
            .values()
            .map(|peer| PeerSnapshot {
                address: peer
                    .public_address
                    .clone()
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| peer.address.clone()),
                direction: match peer.direction {
                    ConnectionDirection::Incoming => "incoming".to_string(),
                    ConnectionDirection::Outgoing => "outgoing".to_string(),
                },
                node_id: peer.node_id.clone(),
                validator_address: peer.validator_address.clone(),
                block_height: peer.last_known_height,
                best_block_hash: peer.best_block_hash.clone(),
                genesis_hash: peer.genesis_hash.clone(),
                status_received_at: peer.status_received_at,
                quarantined: peer.quarantined,
                consensus_duties_disabled: peer.consensus_duties_disabled,
                recovery_state: peer.recovery_state.clone(),
                connected_at: peer.connected_at,
                last_seen: peer.last_seen,
                blocks_sent: peer.blocks_sent,
                blocks_received: peer.blocks_received,
                txs_sent: peer.txs_sent,
                txs_received: peer.txs_received,
            })
            .collect()
    }

    pub fn request_blocks(&self, from_height: u64, count: u32) {
        let message = NetworkMessage::GetBlocks { from_height, count };

        let mut peers = self.connected_peers.lock().unwrap();
        let target_addresses = select_block_sync_targets(&peers, 1);
        for address in target_addresses {
            let Some(peer) = peers.get_mut(&address) else {
                continue;
            };
            if let Some(ref mut stream) = peer.stream {
                if let Err(e) = send_message(stream, &message) {
                    eprintln!("❌ Failed to request blocks from {}: {}", address, e);
                }
            }
        }
    }

    pub fn request_blocks_from_peer(
        &self,
        peer_address: &str,
        from_height: u64,
        count: u32,
    ) -> bool {
        let message = NetworkMessage::GetBlocks { from_height, count };
        let mut peers = self.connected_peers.lock().unwrap();
        let resolved_peer_address = connected_peer_key_for_address(&peers, peer_address)
            .unwrap_or_else(|| peer_address.to_string());
        if let Some(peer) = peers.get_mut(&resolved_peer_address) {
            if let Some(ref mut stream) = peer.stream {
                if let Err(e) = send_message(stream, &message) {
                    warn!(
                        "p2p",
                        "Failed to request blocks from peer",
                        "peer" => resolved_peer_address.to_string(),
                        "requested_peer" => peer_address.to_string(),
                        "error" => e.to_string()
                    );
                    return false;
                }
                return true;
            }
        }
        false
    }

    pub fn request_peers(&self) {
        let message = NetworkMessage::GetPeers;
        let mut peers = self.connected_peers.lock().unwrap();
        for (address, peer) in peers.iter_mut() {
            if let Some(ref mut stream) = peer.stream {
                if let Err(e) = send_message(stream, &message) {
                    warn!("p2p", "Failed to request peers", "peer" => address.clone(), "error" => e.to_string());
                }
            }
        }
    }

    pub fn ping_peers(&self) {
        let message = NetworkMessage::Ping;

        let mut peers = self.connected_peers.lock().unwrap();
        for (address, peer) in peers.iter_mut() {
            if let Some(ref mut stream) = peer.stream {
                if let Err(e) = send_message(stream, &message) {
                    eprintln!("❌ Failed to ping {}: {}", address, e);
                }
            }
        }
    }

    pub fn request_peer_statuses(&self) {
        let message = NetworkMessage::GetStatus;
        let mut peers = self.connected_peers.lock().unwrap();
        for (address, peer) in peers.iter_mut() {
            if let Some(ref mut stream) = peer.stream {
                if let Err(e) = send_message(stream, &message) {
                    warn!("p2p", "Failed to request status", "peer" => address.clone(), "error" => e.to_string());
                }
            }
        }
    }

    /// Starts a background bootstrap loop:
    /// - dials configured bootnodes
    /// - requests peers
    /// - requests missing blocks
    /// - pings peers
    pub fn start_bootstrap(self: &Arc<Self>) {
        let network = Arc::clone(self);
        let _ = spawn_named_thread("p2p-bootstrap", move || {
            let heartbeat =
                std::time::Duration::from_secs(network.config.p2p.heartbeat_interval.max(1));
            let mut bootnode_dials = Vec::<String>::new();
            let mut last_refresh = Instant::now()
                - current_bootstrap_refresh_interval(&network.config, &network.connected_peers);

            loop {
                let bootstrap_refresh_interval =
                    current_bootstrap_refresh_interval(&network.config, &network.connected_peers);
                if last_refresh.elapsed() >= bootstrap_refresh_interval || bootnode_dials.is_empty()
                {
                    bootnode_dials = resolve_bootstrap_dial_targets(&network.config);
                    last_refresh = Instant::now();
                    register_self_with_seed_servers(&network.config);

                    if bootnode_dials.is_empty() {
                        warn!(
                            "p2p",
                            "Bootstrap resolution returned no dialable peers",
                            "bootnodes" => format!("{:?}", network.config.network.bootnodes),
                            "seed_servers" => format!("{:?}", network.config.network.seed_servers),
                            "dns_records" => format!(
                                "{:?}",
                                network.config.network.bootstrap_dns_records
                            )
                        );
                    } else {
                        if let Ok(mut discovered) = network.discovered_dial_targets.lock() {
                            *discovered = bootnode_dials.clone();
                        }
                        info!(
                            "p2p",
                            "Resolved bootstrap dial targets",
                            "targets" => format!("{:?}", bootnode_dials)
                        );
                    }
                }

                prune_stale_peers(
                    &network.config,
                    &network.peer_state_cache,
                    &network.connected_peers,
                );

                // Keep trying bootnodes until at least one peer is connected.
                for addr in &bootnode_dials {
                    // Avoid self-dial if the config accidentally includes itself.
                    if is_self_dial_target(&network.config, addr) {
                        continue;
                    }
                    let already_connected = {
                        let peers = network.connected_peers.lock().unwrap();
                        peers.contains_key(addr)
                            || peers
                                .values()
                                .any(|p| p.public_address.as_deref() == Some(addr.as_str()))
                    };
                    if !already_connected {
                        let _ = network.connect_to_peer(addr);
                    }
                }

                // Ask connected peers for their peer lists and status.
                if network.config.p2p.enable_discovery {
                    network.request_peers();
                }
                if !network.config.node.bootstrap_only {
                    network.request_peer_statuses();
                }

                let sync_active = sync_manager_is_active();

                // Try to sync missing blocks, but only when the dedicated sync manager
                // is not already driving catch-up. Running both paths at once creates a
                // request storm and starves block-batch processing on lagging nodes.
                if should_request_missing_blocks(&network.config, sync_active) {
                    let required_validator_support =
                        if network.config.consensus.status_ready_min_validators == 0 {
                            network.config.consensus.min_validators.max(1)
                        } else {
                            network.config.consensus.status_ready_min_validators.max(1)
                        }
                        .saturating_sub(1)
                        .max(1);
                    let (local_height, best_peer_height) = {
                        let chain = network.blockchain.lock().unwrap();
                        let local = chain.last().map(|b| b.block_index).unwrap_or(0);
                        let supported_best = network.get_best_validator_peer_height_with_support(
                            required_validator_support,
                        );
                        let best = if supported_best > 0 {
                            supported_best
                        } else {
                            let peers = network.connected_peers.lock().unwrap();
                            peers
                                .values()
                                .map(|p| p.last_known_height)
                                .max()
                                .unwrap_or(0)
                        };
                        (local, best)
                    };
                    let behind = best_peer_height.saturating_sub(local_height);
                    // Keep background catch-up batches small so a syncing node cannot
                    // monopolize validator peer locks while consensus is active.
                    let batch = if behind > 5000 {
                        MAX_STATUS_SYNC_BATCH
                    } else if behind > 1000 {
                        MAX_STATUS_SYNC_BATCH
                    } else {
                        IMMEDIATE_STATUS_SYNC_BATCH
                    };
                    let include_reconciliation_overlap = {
                        let chain = network.blockchain.lock().unwrap();
                        chain_has_block_sync_overlap(&chain, local_height, batch)
                    };
                    if let Some((request_start, request_count)) =
                        block_sync_request_range_with_overlap(
                            local_height,
                            best_peer_height,
                            batch,
                            include_reconciliation_overlap,
                        )
                    {
                        network.request_blocks(request_start, request_count);
                    }
                }

                // Keep connections alive.
                network.ping_peers();

                // When catching up, loop immediately without sleeping.
                // When synced, use normal heartbeat interval.
                let (local_height, best_peer_height) = {
                    let chain = network.blockchain.lock().unwrap();
                    let local = chain.last().map(|b| b.block_index).unwrap_or(0);
                    let peers = network.connected_peers.lock().unwrap();
                    let best = peers
                        .values()
                        .map(|p| p.last_known_height)
                        .max()
                        .unwrap_or(0);
                    (local, best)
                };
                let behind = best_peer_height.saturating_sub(local_height);
                thread::sleep(background_poll_interval(behind, heartbeat, sync_active));
            }
        });
    }
}

fn start_listener(
    listen_address: &str,
    blockchain: BlockchainArc,
    connected_peers: PeersArc,
    peer_state_cache: PeerStateCacheArc,
    config: NodeConfig,
    message_sender: mpsc::Sender<(String, NetworkMessage)>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(listen_address)?;
    info!("p2p", "P2P listener bound", "listen_address" => listen_address.to_string());

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let peer_address = stream.peer_addr()?.to_string();
                let peer_host = peer_socket_host(&peer_address);
                let pending_incoming_from_host = {
                    let peers = connected_peers.lock().unwrap();
                    pending_incoming_connections_from_host(&peers, &peer_host)
                };
                if pending_incoming_from_host >= MAX_PENDING_INCOMING_CONNECTIONS_PER_HOST {
                    warn!(
                        "p2p",
                        "Rejecting excess pending incoming connections from host",
                        "peer" => peer_address.clone(),
                        "host" => peer_host,
                        "active_pending_incoming_connections" => pending_incoming_from_host as u64
                    );
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
                info!("p2p", "Incoming peer connection", "peer" => peer_address.clone());

                let blockchain_clone = Arc::clone(&blockchain);
                let peers_clone = Arc::clone(&connected_peers);
                let peer_state_cache_clone = Arc::clone(&peer_state_cache);
                let sender_clone = message_sender.clone();
                let config_clone = config.clone();

                let _ = spawn_named_thread("p2p-accept-peer", move || {
                    if let Err(e) = handle_incoming_connection(
                        stream,
                        peer_address,
                        blockchain_clone,
                        peers_clone,
                        peer_state_cache_clone,
                        sender_clone,
                        config_clone,
                    ) {
                        error!("p2p", "Incoming connection error", "error" => e.to_string());
                    }
                });
            }
            Err(e) => {
                warn!("p2p", "Incoming connection accept error", "error" => e.to_string());
            }
        }
    }

    Ok(())
}

fn request_status_from_connected_peer(peers: &mut PeerMap, peer_address: &str) {
    let message = NetworkMessage::GetStatus;
    let resolved_peer_address = connected_peer_key_for_address(peers, peer_address)
        .unwrap_or_else(|| peer_address.to_string());
    if let Some(peer) = peers.get_mut(&resolved_peer_address) {
        if let Some(ref mut stream) = peer.stream {
            if let Err(error) = send_message(stream, &message) {
                warn!(
                    "p2p",
                    "Failed to request status from peer",
                    "peer" => resolved_peer_address.to_string(),
                    "requested_peer" => peer_address.to_string(),
                    "error" => error.to_string()
                );
            }
        }
    }
}

fn request_blocks_from_connected_peer(
    peers: &mut PeerMap,
    peer_address: &str,
    from_height: u64,
    count: u32,
) {
    let message = NetworkMessage::GetBlocks { from_height, count };
    let resolved_peer_address = connected_peer_key_for_address(peers, peer_address)
        .unwrap_or_else(|| peer_address.to_string());
    if let Some(peer) = peers.get_mut(&resolved_peer_address) {
        if let Some(ref mut stream) = peer.stream {
            if let Err(error) = send_message(stream, &message) {
                warn!(
                    "p2p",
                    "Failed to request blocks from peer",
                    "peer" => resolved_peer_address.to_string(),
                    "requested_peer" => peer_address.to_string(),
                    "error" => error.to_string()
                );
            }
        }
    }
}

fn send_vote_to_requester(
    peers: &mut PeerMap,
    config: &NodeConfig,
    request_peer_address: &str,
    proposer_validator_address: &str,
    response: &NetworkMessage,
) -> Result<String, String> {
    let mut failed_peers = Vec::new();

    if let Some(proposer_public_address) =
        configured_public_address_for_validator(config, proposer_validator_address)
    {
        match send_direct_vote_to_configured_proposer(config, &proposer_public_address, response) {
            Ok(()) => {
                info!(
                    "p2p",
                    "Vote sent over direct proposer path",
                    "request_peer" => request_peer_address.to_string(),
                    "response_peer" => proposer_public_address.clone(),
                    "proposer" => proposer_validator_address.to_string()
                );
                return Ok(proposer_public_address);
            }
            Err(error) => failed_peers.push((proposer_public_address, error)),
        }
    }

    if let Some(peer) = peers.get_mut(request_peer_address) {
        if let Some(ref mut stream) = peer.stream {
            match send_consensus_message(stream, response) {
                Ok(()) => return Ok(request_peer_address.to_string()),
                Err(error) => {
                    failed_peers.push((request_peer_address.to_string(), error.to_string()))
                }
            }
        }
    }
    for (failed_peer, _) in &failed_peers {
        peers.remove(failed_peer);
    }

    let fallback_peer_key = peers
        .iter()
        .find(|(address, peer)| {
            address.as_str() != request_peer_address
                && peer.stream.is_some()
                && peer.validator_address.as_deref().map(str::trim)
                    == Some(proposer_validator_address)
        })
        .map(|(address, _)| address.clone());

    if let Some(fallback_peer_key) = fallback_peer_key {
        if let Some(peer) = peers.get_mut(&fallback_peer_key) {
            if let Some(ref mut stream) = peer.stream {
                match send_consensus_message(stream, response) {
                    Ok(()) => return Ok(fallback_peer_key),
                    Err(error) => {
                        let error = error.to_string();
                        peers.remove(&fallback_peer_key);
                        return Err(error);
                    }
                }
            }
        }
    }

    if let Some((failed_peer, error)) = failed_peers.into_iter().next() {
        return Err(format!("failed to write vote to {failed_peer}: {error}"));
    }

    Err(format!(
        "no writable connection for proposer {} (request peer {})",
        proposer_validator_address, request_peer_address
    ))
}

fn send_direct_vote_to_configured_proposer(
    config: &NodeConfig,
    proposer_public_address: &str,
    response: &NetworkMessage,
) -> Result<(), String> {
    let mut stream = dial_with_timeout(
        proposer_public_address,
        Duration::from_millis(CONSENSUS_DIRECT_VOTE_DIAL_TIMEOUT_MILLIS),
    )
    .map_err(|error| error.to_string())?;

    let handshake =
        build_local_handshake(config).map_err(|error| format!("build direct vote handshake: {error}"))?;
    send_consensus_message(&mut stream, &handshake)
        .map_err(|error| format!("send direct vote handshake: {error}"))?;
    send_consensus_message(&mut stream, response)
        .map_err(|error| format!("send direct vote payload: {error}"))?;
    let _ = stream.shutdown(Shutdown::Write);

    Ok(())
}

fn configured_public_address_for_validator(
    config: &NodeConfig,
    validator_address: &str,
) -> Option<String> {
    let validator_address = validator_address.trim();
    if validator_address.is_empty() {
        return None;
    }

    let active_validator_addresses = if config.node.allowed_validator_addresses.is_empty() {
        consensus_membership_validators(VALIDATOR_MANAGER.get_active_validators())
            .into_iter()
            .map(|validator| validator.address)
            .collect::<HashSet<_>>()
    } else {
        config
            .node
            .allowed_validator_addresses
            .iter()
            .map(|address| address.trim().to_string())
            .filter(|address| !address.is_empty())
            .collect::<HashSet<_>>()
    };

    configured_validator_public_address_map(config, &active_validator_addresses)
        .remove(validator_address)
}

fn handle_vote_request_message(
    blockchain: &BlockchainArc,
    connected_peers: &PeersArc,
    config: &NodeConfig,
    peer_address: &str,
    block_data: Block,
    epoch_number: u64,
    round_number: u64,
) {
    let vote_request_received_at = Instant::now();
    let local_validator = crate::config::resolve_runtime_validator_address();
    let network_peer_count = connected_peers
        .lock()
        .ok()
        .map(|peers| {
            peers
                .values()
                .filter(|peer| {
                    peer.validator_address
                        .as_ref()
                        .map(|address| !address.trim().is_empty())
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0);
    timing_trace::emit(
        "vote_request_received",
        serde_json::json!({
            "height": block_data.block_index,
            "block_hash": block_data.hash.clone(),
            "previous_hash": block_data.previous_hash.clone(),
            "proposer": block_data.validator_id.clone(),
            "validator": local_validator,
            "peer": peer_address,
            "epoch": epoch_number,
            "round": round_number,
            "network_peer_count": network_peer_count
        }),
    );
    if config.node.bootstrap_only {
        debug!(
            "p2p",
            "Bootstrap-only node ignoring vote request",
            "peer" => peer_address.to_string(),
            "height" => block_data.block_index,
            "epoch" => epoch_number,
            "round" => round_number
        );
        return;
    }
    if let Some(record) = current_validator_quarantine_duty_block() {
        warn!(
            "p2p",
            "Quarantined validator refusing vote request",
            "peer" => peer_address.to_string(),
            "height" => block_data.block_index,
            "epoch" => epoch_number,
            "round" => round_number,
            "quarantine_height" => record.divergence_height.0,
            "quarantine_source" => record.source,
            "reason" => record.reason
        );
        return;
    }

    let mut local_tip = vote_request_local_tip(blockchain);
    if validate_vote_request_extends_local_tip(local_tip.as_ref(), &block_data).is_err() {
        request_vote_request_parent_sync(local_tip.clone(), block_data.block_index);
        let parent_wait_started = Instant::now();
        if vote_request_can_wait_for_parent(local_tip.as_ref(), &block_data)
            && wait_for_vote_request_parent(blockchain, &block_data)
        {
            local_tip = vote_request_local_tip(blockchain);
            timing_trace::emit(
                "vote_request_parent_sync_wait",
                serde_json::json!({
                    "height": block_data.block_index,
                    "block_hash": block_data.hash.clone(),
                    "previous_hash": block_data.previous_hash.clone(),
                    "proposer": block_data.validator_id.clone(),
                    "validator": crate::config::resolve_runtime_validator_address(),
                    "peer": peer_address,
                    "epoch": epoch_number,
                    "round": round_number,
                    "duration_ms": timing_trace::duration_ms(parent_wait_started.elapsed()),
                    "status": "ok"
                }),
            );
        } else {
            timing_trace::emit(
                "vote_request_parent_sync_wait",
                serde_json::json!({
                    "height": block_data.block_index,
                    "block_hash": block_data.hash.clone(),
                    "previous_hash": block_data.previous_hash.clone(),
                    "proposer": block_data.validator_id.clone(),
                    "validator": crate::config::resolve_runtime_validator_address(),
                    "peer": peer_address,
                    "epoch": epoch_number,
                    "round": round_number,
                    "duration_ms": timing_trace::duration_ms(parent_wait_started.elapsed()),
                    "status": "not_ready"
                }),
            );
        }
    }

    if let Err(error) = validate_vote_request_extends_local_tip(local_tip.as_ref(), &block_data) {
        timing_trace::emit(
            "vote_request_rejected",
            serde_json::json!({
                "height": block_data.block_index,
                "block_hash": block_data.hash.clone(),
                "previous_hash": block_data.previous_hash.clone(),
                "proposer": block_data.validator_id.clone(),
                "validator": crate::config::resolve_runtime_validator_address(),
                "peer": peer_address,
                "epoch": epoch_number,
                "round": round_number,
                "reason": error.clone()
            }),
        );
        warn!(
            "p2p",
            "Refusing vote request",
            "peer" => peer_address.to_string(),
            "height" => block_data.block_index,
            "epoch" => epoch_number,
            "round" => round_number,
            "error" => error
        );
        request_vote_request_parent_sync(local_tip, block_data.block_index);
        return;
    }

    info!(
        "p2p",
        "Received vote request",
        "peer" => peer_address.to_string(),
        "proposer" => block_data.validator_id.clone(),
        "height" => block_data.block_index,
        "epoch" => epoch_number,
        "round" => round_number
    );

    let transient_recovery_min_age_secs = vote_request_transient_recovery_min_age_secs(config);
    let validation_started = Instant::now();
    timing_trace::emit(
        "vote_validation_start",
        serde_json::json!({
            "height": block_data.block_index,
            "block_hash": block_data.hash.clone(),
            "previous_hash": block_data.previous_hash.clone(),
            "proposer": block_data.validator_id.clone(),
            "validator": crate::config::resolve_runtime_validator_address(),
            "peer": peer_address,
            "epoch": epoch_number,
            "round": round_number
        }),
    );
    match DualQuorumConsensus::build_local_vote_for_proposal_with_recovery(
        &block_data,
        epoch_number,
        round_number,
        transient_recovery_min_age_secs,
    ) {
        Ok(vote) => {
            timing_trace::emit(
                "vote_validation_end",
                serde_json::json!({
                    "height": block_data.block_index,
                    "block_hash": block_data.hash.clone(),
                    "previous_hash": block_data.previous_hash.clone(),
                    "proposer": block_data.validator_id.clone(),
                    "validator": vote.validator_address.clone(),
                    "peer": peer_address,
                    "epoch": epoch_number,
                    "round": round_number,
                    "duration_ms": timing_trace::duration_ms(validation_started.elapsed()),
                    "status": "ok"
                }),
            );
            let response = NetworkMessage::Vote { vote };
            let mut peers = connected_peers.lock().unwrap();
            match send_vote_to_requester(
                &mut peers,
                config,
                peer_address,
                block_data.validator_id.as_str(),
                &response,
            ) {
                Ok(response_peer) => {
                    timing_trace::emit(
                        "vote_response_sent",
                        serde_json::json!({
                            "height": block_data.block_index,
                            "block_hash": block_data.hash.clone(),
                            "previous_hash": block_data.previous_hash.clone(),
                            "proposer": block_data.validator_id.clone(),
                            "validator": crate::config::resolve_runtime_validator_address(),
                            "request_peer": peer_address,
                            "response_peer": response_peer.clone(),
                            "epoch": epoch_number,
                            "round": round_number,
                            "elapsed_since_request_ms": timing_trace::duration_ms(vote_request_received_at.elapsed())
                        }),
                    );
                    info!(
                        "p2p",
                        "Vote sent",
                        "request_peer" => peer_address.to_string(),
                        "response_peer" => response_peer,
                        "proposer" => block_data.validator_id.clone(),
                        "height" => block_data.block_index,
                        "epoch" => epoch_number,
                        "round" => round_number
                    );
                }
                Err(error) => {
                    timing_trace::emit(
                        "vote_response_send_failed",
                        serde_json::json!({
                            "height": block_data.block_index,
                            "block_hash": block_data.hash.clone(),
                            "previous_hash": block_data.previous_hash.clone(),
                            "proposer": block_data.validator_id.clone(),
                            "validator": crate::config::resolve_runtime_validator_address(),
                            "peer": peer_address,
                            "epoch": epoch_number,
                            "round": round_number,
                            "elapsed_since_request_ms": timing_trace::duration_ms(vote_request_received_at.elapsed()),
                            "error": error.clone()
                        }),
                    );
                    warn!(
                        "p2p",
                        "Failed to send vote",
                        "peer" => peer_address.to_string(),
                        "proposer" => block_data.validator_id.clone(),
                        "height" => block_data.block_index,
                        "epoch" => epoch_number,
                        "round" => round_number,
                        "error" => error
                    );
                }
            }
        }
        Err(error) => {
            timing_trace::emit(
                "vote_validation_end",
                serde_json::json!({
                    "height": block_data.block_index,
                    "block_hash": block_data.hash.clone(),
                    "previous_hash": block_data.previous_hash.clone(),
                    "proposer": block_data.validator_id.clone(),
                    "validator": crate::config::resolve_runtime_validator_address(),
                    "peer": peer_address,
                    "epoch": epoch_number,
                    "round": round_number,
                    "duration_ms": timing_trace::duration_ms(validation_started.elapsed()),
                    "status": "error",
                    "error": error.clone()
                }),
            );
            timing_trace::emit(
                "vote_request_rejected",
                serde_json::json!({
                    "height": block_data.block_index,
                    "block_hash": block_data.hash.clone(),
                    "previous_hash": block_data.previous_hash.clone(),
                    "proposer": block_data.validator_id.clone(),
                    "validator": crate::config::resolve_runtime_validator_address(),
                    "peer": peer_address,
                    "epoch": epoch_number,
                    "round": round_number,
                    "reason": error.clone()
                }),
            );
            warn!(
                "p2p",
                "Refusing vote request",
                "peer" => peer_address.to_string(),
                "height" => block_data.block_index,
                "epoch" => epoch_number,
                "round" => round_number,
                "error" => error
            );
        }
    }
}

fn vote_request_transient_recovery_min_age_secs(config: &NodeConfig) -> u64 {
    let block_time_secs = config.consensus.block_time_secs.max(1);
    let leader_timeout_secs = if config.consensus.leader_timeout_secs == 0 {
        block_time_secs.saturating_mul(2).max(3)
    } else {
        config.consensus.leader_timeout_secs.max(block_time_secs)
    };

    leader_timeout_secs
        .saturating_mul(2)
        .max(block_time_secs.saturating_mul(3))
        .max(6)
}

fn vote_request_local_tip(blockchain: &BlockchainArc) -> Option<(u64, String)> {
    blockchain
        .lock()
        .ok()
        .and_then(|chain| chain.last().map(|tip| (tip.block_index, tip.hash.clone())))
}

fn validate_vote_request_extends_local_tip(
    local_tip: Option<&(u64, String)>,
    block_data: &Block,
) -> Result<(), String> {
    let Some((tip_height, tip_hash)) = local_tip else {
        return Err("local chain has no tip to extend".to_string());
    };

    let expected_height = tip_height.saturating_add(1);
    if block_data.block_index != expected_height {
        return Err(format!(
            "proposal height {} does not extend local tip {}",
            block_data.block_index, tip_height
        ));
    }

    if block_data.previous_hash != *tip_hash {
        return Err(format!(
            "proposal parent hash does not match local tip at height {}",
            tip_height
        ));
    }

    Ok(())
}

fn vote_request_can_wait_for_parent(local_tip: Option<&(u64, String)>, block_data: &Block) -> bool {
    let Some((tip_height, _)) = local_tip else {
        return false;
    };

    block_data.block_index > tip_height.saturating_add(1)
}

fn wait_for_vote_request_parent(blockchain: &BlockchainArc, block_data: &Block) -> bool {
    let deadline = Instant::now() + Duration::from_millis(VOTE_REQUEST_PARENT_SYNC_WAIT_MILLIS);
    while Instant::now() < deadline {
        if validate_vote_request_extends_local_tip(
            vote_request_local_tip(blockchain).as_ref(),
            block_data,
        )
        .is_ok()
        {
            return true;
        }
        thread::sleep(Duration::from_millis(VOTE_REQUEST_PARENT_SYNC_POLL_MILLIS));
    }

    false
}

fn request_vote_request_parent_sync(local_tip: Option<(u64, String)>, proposal_height: u64) {
    let Some((tip_height, _)) = local_tip else {
        return;
    };
    let Some((request_start, request_count)) =
        vote_request_parent_sync_range(tip_height, proposal_height)
    else {
        return;
    };

    if let Some(network) = crate::p2p::get_p2p_network() {
        network.request_blocks(request_start, request_count);
    }
}

fn vote_request_parent_sync_range(tip_height: u64, proposal_height: u64) -> Option<(u64, u32)> {
    if proposal_height <= tip_height.saturating_add(1) {
        return None;
    }

    let request_start = tip_height.saturating_add(1);
    let request_count = proposal_height.saturating_sub(request_start);
    if request_count == 0 {
        return None;
    }

    Some((request_start, request_count.min(u32::MAX as u64) as u32))
}

fn handle_vote_message(
    connected_peers: &PeersArc,
    config: &NodeConfig,
    peer_address: &str,
    vote: crate::consensus::dual_quorum::Vote,
) {
    if config.node.bootstrap_only {
        debug!(
            "p2p",
            "Bootstrap-only node ignoring vote payload",
            "peer" => peer_address.to_string(),
            "validator" => vote.validator_address.clone(),
            "epoch" => vote.epoch_number,
            "round" => vote.round_number
        );
        return;
    }

    let announced_validator = {
        let peers = connected_peers.lock().unwrap();
        resolve_announced_validator_for_vote(&peers, peer_address, &vote.validator_address)
            .or_else(|| recover_active_vote_validator_from_payload(config, &vote.validator_address))
    };
    let Some((announced_validator, recovered_peer_key)) = announced_validator else {
        warn!(
            "p2p",
            "Ignoring vote from peer without validator identity",
            "peer" => peer_address.to_string(),
            "validator" => vote.validator_address.clone()
        );
        return;
    };
    if let Some(recovered_peer_key) = recovered_peer_key {
        info!(
            "p2p",
            "Recovered vote peer identity from active validator mapping",
            "peer" => peer_address.to_string(),
            "recovered_peer" => recovered_peer_key,
            "validator" => announced_validator.clone()
        );
    }
    if announced_validator != vote.validator_address {
        warn!(
            "p2p",
            "Ignoring vote with mismatched validator identity",
            "peer" => peer_address.to_string(),
            "announced_validator" => announced_validator,
            "vote_validator" => vote.validator_address.clone()
        );
        return;
    }

    timing_trace::emit(
        "vote_response_received_by_peer",
        serde_json::json!({
            "height": vote.block_index,
            "block_hash": vote.block_hash.clone(),
            "validator": vote.validator_address.clone(),
            "peer": peer_address,
            "announced_validator": announced_validator,
            "epoch": vote.epoch_number,
            "round": vote.round_number,
            "vote_timestamp": vote.timestamp
        }),
    );
    DualQuorumConsensus::record_network_vote(vote.clone());
    debug!(
        "p2p",
        "Recorded network vote",
        "peer" => peer_address.to_string(),
        "validator" => vote.validator_address.clone(),
        "block_hash" => vote.block_hash.clone(),
        "epoch" => vote.epoch_number,
        "round" => vote.round_number
    );
}

fn recover_active_vote_validator_from_payload(
    config: &NodeConfig,
    vote_validator_address: &str,
) -> Option<(String, Option<String>)> {
    let vote_validator_address = vote_validator_address.trim();
    if vote_validator_address.is_empty() {
        return None;
    }

    let active_validator_addresses =
        configured_vote_target_validator_addresses(config, &HashSet::new())
            .into_iter()
            .collect::<HashSet<_>>();
    if active_validator_addresses.contains(vote_validator_address) {
        return Some((vote_validator_address.to_string(), None));
    }

    None
}

fn handle_block_message(
    blockchain: &BlockchainArc,
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    config: &NodeConfig,
    peer_address: &str,
    block_data: Block,
    quorum_certificate: Option<QuorumCertificate>,
) {
    if config.node.bootstrap_only {
        debug!(
            "p2p",
            "Bootstrap-only node ignoring block propagation",
            "peer" => peer_address.to_string(),
            "height" => block_data.block_index
        );
        return;
    }

    info!("p2p", "Received block", "peer" => peer_address.to_string());

    if !ensure_peer_status_allows_chain_data(
        blockchain,
        connected_peers,
        peer_state_cache,
        peer_address,
        "block",
    ) {
        return;
    }

    {
        let mut peers = connected_peers.lock().unwrap();
        if let Some(peer) = peers.get_mut(peer_address) {
            peer.blocks_received += 1;
            peer.last_known_height = block_data.block_index;
            peer.best_block_hash = block_data.hash.clone();
        }
    }

    if apply_block_if_new(blockchain, block_data.clone(), quorum_certificate) {
        info!(
            "p2p",
            "Block applied",
            "height" => block_data.block_index,
            "hash" => block_data.hash.clone(),
            "txs" => block_data.transactions.len() as u64
        );
    } else {
        debug!(
            "p2p",
            "Block ignored (duplicate/out-of-order)",
            "height" => block_data.block_index,
            "hash" => block_data.hash.clone()
        );
    }
}

fn handle_get_blocks_message(
    blockchain: &BlockchainArc,
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    config: &NodeConfig,
    peer_address: &str,
    from_height: u64,
    count: u32,
) {
    if config.node.bootstrap_only {
        debug!(
            "p2p",
            "Bootstrap-only node returning empty block response",
            "peer" => peer_address.to_string(),
            "from_height" => from_height,
            "count" => count as u64
        );
        let response = NetworkMessage::Blocks {
            blocks: Vec::new(),
            quorum_certificates: Vec::new(),
        };
        let mut peers = connected_peers.lock().unwrap();
        if let Some(peer) = peers.get_mut(peer_address) {
            if let Some(ref mut stream) = peer.stream {
                let _ = send_message(stream, &response);
            }
        }
        return;
    }

    let (policy, min_serve_interval_secs, refuse_deep_support_sync) = {
        let local_height = {
            let chain = blockchain.lock().unwrap();
            chain.last().map(|block| block.block_index).unwrap_or(0)
        };
        let peers = connected_peers.lock().unwrap();
        let peer = peers.get(peer_address);
        (
            block_sync_response_policy(config, peer),
            block_sync_min_serve_interval_secs(config, peer),
            support_peer_sync_request_is_too_deep(peer, local_height, from_height),
        )
    };
    let now = current_timestamp();
    let rate_limit_key = peer_socket_host(peer_address);
    let should_serve = BLOCK_SYNC_LAST_SERVED
        .lock()
        .map(|mut served| {
            let last_served = served.get(&rate_limit_key).copied().unwrap_or(0);
            if now.saturating_sub(last_served) < min_serve_interval_secs {
                return false;
            }
            served.insert(rate_limit_key.clone(), now);
            true
        })
        .unwrap_or(false);
    if !should_serve {
        debug!(
            "p2p",
            "Throttling block sync response",
            "peer" => peer_address.to_string(),
            "host" => rate_limit_key,
            "from_height" => from_height,
            "count" => count as u64,
            "min_serve_interval_secs" => min_serve_interval_secs
        );
        return;
    }

    debug!(
        "p2p",
        "Serving block sync response",
        "peer" => peer_address.to_string(),
        "host" => rate_limit_key,
        "from_height" => from_height,
        "count" => count as u64,
        "max_blocks" => policy.max_blocks as u64
    );

    if refuse_deep_support_sync {
        warn!(
            "p2p",
            "Refusing deep support-peer block sync request",
            "peer" => peer_address.to_string(),
            "from_height" => from_height,
            "max_support_peer_deep_sync_lag" => MAX_SUPPORT_PEER_DEEP_SYNC_LAG
        );
        let mut peers = connected_peers.lock().unwrap();
        disconnect_peer_entry(peer_state_cache, &mut peers, peer_address);
        return;
    }
    let response_count = count.min(policy.max_blocks);
    let (blocks, quorum_certificates) = {
        let chain = blockchain.lock().unwrap();
        let blocks = select_block_sync_response_blocks(&chain, from_height, response_count);
        let quorum_certificates = DualQuorumConsensus::committed_qcs_for_block_hashes(
            blocks.iter().map(|block| block.hash.as_str()),
        );
        (blocks, quorum_certificates)
    };
    let response = NetworkMessage::Blocks {
        blocks,
        quorum_certificates,
    };

    let mut peers = connected_peers.lock().unwrap();
    let mut poison_reason = None;
    if let Some(peer) = peers.get_mut(peer_address) {
        if let Some(ref mut stream) = peer.stream {
            if let Err(e) = send_message_with_write_timeout(stream, &response, policy.write_timeout)
            {
                let error = e.to_string();
                warn!(
                    "p2p",
                    "Failed to send blocks",
                    "peer" => peer_address.to_string(),
                    "requested" => count as u64,
                    "served" => response_count as u64,
                    "max_blocks" => policy.max_blocks as u64,
                    "error" => error.clone()
                );
                poison_reason = Some(format!("block-sync-send-failed: {error}"));
            } else {
                peer.blocks_sent += 1;
            }
        }
    }
    if let Some(reason) = poison_reason {
        disconnect_peer_after_poisoned_write(peer_state_cache, &mut peers, peer_address, &reason);
    }
}

fn handle_blocks_message(
    blockchain: &BlockchainArc,
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    config: &NodeConfig,
    peer_address: &str,
    blocks: Vec<Block>,
    quorum_certificates: Vec<QuorumCertificate>,
) {
    if config.node.bootstrap_only {
        debug!(
            "p2p",
            "Bootstrap-only node ignoring bulk blocks",
            "peer" => peer_address.to_string(),
            "count" => blocks.len()
        );
        return;
    }

    if !ensure_peer_status_allows_chain_data(
        blockchain,
        connected_peers,
        peer_state_cache,
        peer_address,
        "blocks",
    ) {
        return;
    }

    let applied = apply_block_batch(blockchain, blocks, quorum_certificates);
    if applied > 0 {
        info!(
            "p2p",
            "Blocks applied",
            "count" => applied,
            "peer" => peer_address.to_string()
        );
    }
}

fn sync_manager_is_active() -> bool {
    SYNC_MANAGER
        .lock()
        .ok()
        .map(|manager| {
            matches!(
                manager.get_state(),
                SyncState::Discovering
                    | SyncState::Downloading
                    | SyncState::Validating
                    | SyncState::Applying
            )
        })
        .unwrap_or(false)
}

fn should_request_missing_blocks(config: &NodeConfig, sync_active: bool) -> bool {
    !config.node.bootstrap_only && !sync_active
}

fn local_node_runs_validator_consensus(config: &NodeConfig) -> bool {
    let identity_role = config.identity.role.trim().to_ascii_lowercase();
    let compiled_profile = config.role.compiled_profile.trim().to_ascii_lowercase();
    let exposes_consensus_service = config
        .role
        .services
        .iter()
        .any(|service| service.trim().eq_ignore_ascii_case("consensus"));
    identity_role == "validator"
        || compiled_profile.contains("validator")
        || exposes_consensus_service
}

fn peer_is_active_consensus_validator(peer: &PeerConnection) -> bool {
    let Some(peer_validator_address) = peer
        .validator_address
        .as_deref()
        .map(str::trim)
        .filter(|address| !address.is_empty())
    else {
        return false;
    };

    consensus_membership_validators(VALIDATOR_MANAGER.get_active_validators())
        .into_iter()
        .any(|validator| validator.address == peer_validator_address)
}

fn block_sync_response_policy(
    config: &NodeConfig,
    peer: Option<&PeerConnection>,
) -> BlockSyncResponsePolicy {
    if !local_node_runs_validator_consensus(config) {
        return BlockSyncResponsePolicy {
            max_blocks: MAX_SUPPORT_NODE_BLOCK_SYNC_RESPONSE_BLOCKS,
            write_timeout: Duration::from_secs(SUPPORT_NODE_BLOCK_SYNC_RESPONSE_WRITE_TIMEOUT_SECS),
        };
    }

    let serving_support_peer = !peer
        .map(peer_is_active_consensus_validator)
        .unwrap_or(false);

    if serving_support_peer {
        BlockSyncResponsePolicy {
            max_blocks: MAX_VALIDATOR_SUPPORT_SYNC_RESPONSE_BLOCKS,
            write_timeout: Duration::from_millis(
                VALIDATOR_SUPPORT_SYNC_RESPONSE_WRITE_TIMEOUT_MILLIS,
            ),
        }
    } else {
        BlockSyncResponsePolicy {
            max_blocks: MAX_BLOCK_SYNC_RESPONSE_BLOCKS,
            write_timeout: Duration::from_secs(BLOCK_SYNC_RESPONSE_WRITE_TIMEOUT_SECS),
        }
    }
}

fn block_sync_min_serve_interval_secs(config: &NodeConfig, peer: Option<&PeerConnection>) -> u64 {
    if !local_node_runs_validator_consensus(config) {
        SUPPORT_NODE_BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS
    } else if peer
        .map(peer_is_active_consensus_validator)
        .unwrap_or(false)
    {
        BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS
    } else {
        VALIDATOR_SUPPORT_BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS
    }
}

fn support_peer_sync_request_is_too_deep(
    peer: Option<&PeerConnection>,
    local_height: u64,
    from_height: u64,
) -> bool {
    let serving_support_peer = !peer
        .map(peer_is_active_consensus_validator)
        .unwrap_or(false);
    serving_support_peer
        && local_height.saturating_sub(from_height) > MAX_SUPPORT_PEER_DEEP_SYNC_LAG
}

fn background_poll_interval(behind: u64, heartbeat: Duration, sync_active: bool) -> Duration {
    if sync_active {
        heartbeat
    } else if behind > 0 {
        Duration::from_millis(BACKGROUND_SYNC_POLL_MILLIS)
    } else {
        heartbeat
    }
}

fn bypasses_shared_message_queue(message: &NetworkMessage) -> bool {
    matches!(
        message,
        NetworkMessage::VoteRequest { .. }
            | NetworkMessage::Vote { .. }
            | NetworkMessage::Block { .. }
    )
}

fn dispatch_peer_message(
    blockchain: &BlockchainArc,
    connected_peers: &PeersArc,
    peer_state_cache: &PeerStateCacheArc,
    message_sender: &mpsc::Sender<(String, NetworkMessage)>,
    config: &NodeConfig,
    peer_address: &str,
    message: NetworkMessage,
) -> Result<(), mpsc::SendError<(String, NetworkMessage)>> {
    if !bypasses_shared_message_queue(&message) {
        return message_sender.send((peer_address.to_string(), message));
    }

    match message {
        NetworkMessage::VoteRequest {
            block_data,
            epoch_number,
            round_number,
        } => {
            // Vote requests and vote payloads sit directly on the block production
            // critical path. Handle them immediately instead of routing them through
            // the shared background queue with status, ping, and sync traffic.
            handle_vote_request_message(
                blockchain,
                connected_peers,
                config,
                peer_address,
                block_data,
                epoch_number,
                round_number,
            );
            Ok(())
        }
        NetworkMessage::Vote { vote } => {
            handle_vote_message(connected_peers, config, peer_address, vote);
            Ok(())
        }
        NetworkMessage::Block {
            block_data,
            quorum_certificate,
        } => {
            handle_block_message(
                blockchain,
                connected_peers,
                peer_state_cache,
                config,
                peer_address,
                block_data,
                quorum_certificate,
            );
            Ok(())
        }
        NetworkMessage::GetBlocks { from_height, count } => {
            handle_get_blocks_message(
                blockchain,
                connected_peers,
                peer_state_cache,
                config,
                peer_address,
                from_height,
                count,
            );
            Ok(())
        }
        NetworkMessage::Blocks {
            blocks,
            quorum_certificates,
        } => {
            handle_blocks_message(
                blockchain,
                connected_peers,
                peer_state_cache,
                config,
                peer_address,
                blocks,
                quorum_certificates,
            );
            Ok(())
        }
        other => {
            unreachable!("non-priority message {other:?} should not reach direct dispatch path")
        }
    }
}

fn resolve_announced_validator_for_vote(
    peers: &PeerMap,
    peer_address: &str,
    vote_validator_address: &str,
) -> Option<(String, Option<String>)> {
    if let Some(validator_address) = peers
        .get(peer_address)
        .and_then(|peer| peer.validator_address.clone())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return Some((validator_address, None));
    }

    let mut matching_peer_keys = peers
        .iter()
        .filter_map(|(address, peer)| {
            (peer.validator_address.as_deref().map(str::trim) == Some(vote_validator_address))
                .then_some(address.clone())
        })
        .collect::<Vec<_>>();
    matching_peer_keys.sort();
    matching_peer_keys.dedup();

    if matching_peer_keys.len() == 1 {
        Some((
            vote_validator_address.to_string(),
            matching_peer_keys.into_iter().next(),
        ))
    } else {
        None
    }
}

fn build_local_status_message(blockchain: &BlockchainArc, config: &NodeConfig) -> NetworkMessage {
    let genesis_hash = resolve_local_genesis_hash(blockchain);
    let (block_height, best_block_hash) = {
        let chain = blockchain.lock().unwrap();
        (
            if config.node.bootstrap_only {
                0
            } else {
                chain.last().map(|b| b.block_index).unwrap_or(0)
            },
            if config.node.bootstrap_only {
                String::new()
            } else {
                chain.last().map(|b| b.hash.clone()).unwrap_or_default()
            },
        )
    };
    let quarantine_block = current_validator_quarantine_duty_block();
    let vote_only_rejoin = local_vote_only_rejoin_active();
    let quarantined = quarantine_block.is_some() && !vote_only_rejoin;
    let recovery_state = if vote_only_rejoin {
        Some("VOTE_ONLY".to_string())
    } else {
        quarantine_block.map(|block| block.source)
    };

    NetworkMessage::Status {
        block_height,
        best_block_hash,
        genesis_hash,
        quarantined,
        consensus_duties_disabled: quarantined,
        recovery_state,
    }
}

fn local_vote_only_rejoin_active() -> bool {
    let path = crate::utils::resolve_data_path("data/self_heal_status.json");
    let Ok(bytes) = fs::read(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    ["typed_status", "new_state", "recovery_state", "status"]
        .iter()
        .filter_map(|key| value.get(*key).and_then(|item| item.as_str()))
        .any(|state| {
            matches!(
                state.trim().to_ascii_uppercase().as_str(),
                "VOTE_ONLY" | "VOTEONLY"
            )
        })
        || value
            .get("vote_only_rejoin")
            .and_then(|item| item.as_bool())
            .unwrap_or(false)
}

fn handle_incoming_connection(
    stream: TcpStream,
    peer_address: String,
    blockchain: BlockchainArc,
    connected_peers: PeersArc,
    peer_state_cache: PeerStateCacheArc,
    message_sender: mpsc::Sender<(String, NetworkMessage)>,
    config: NodeConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    configure_peer_stream(&stream);
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = BufWriter::new(stream);

    // Add peer to connected peers
    {
        let mut peers = connected_peers.lock().unwrap();
        peers.insert(
            peer_address.clone(),
            PeerConnection {
                address: peer_address.clone(),
                direction: ConnectionDirection::Incoming,
                public_address: None,
                validator_address: None,
                connected_at: current_timestamp(),
                last_seen: current_timestamp(),
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: Some(writer.get_ref().try_clone()?),
                node_id: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
    }
    let _peer_entry_guard = PeerEntryGuard::new(
        peer_address.clone(),
        Arc::clone(&connected_peers),
        Arc::clone(&peer_state_cache),
    );

    // Send handshake
    let handshake = build_local_handshake(&config)
        .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;

    send_message(&mut writer, &handshake)?;
    writer.flush()?;

    let status = build_local_status_message(&blockchain, &config);
    if let Err(error) = send_message(&mut writer, &status) {
        warn!(
            "p2p",
            "Failed to proactively send status after handshake",
            "peer" => peer_address.clone(),
            "error" => error.to_string()
        );
    } else {
        writer.flush()?;
    }

    // Listen for messages
    loop {
        match receive_message(&mut reader) {
            Ok(message) => {
                // Update last seen
                {
                    let mut peers = connected_peers.lock().unwrap();
                    if let Some(peer) = peers.get_mut(&peer_address) {
                        peer.last_seen = current_timestamp();
                    }
                }

                if let Err(_) = dispatch_peer_message(
                    &blockchain,
                    &connected_peers,
                    &peer_state_cache,
                    &message_sender,
                    &config,
                    &peer_address,
                    message,
                ) {
                    break;
                }
            }
            Err(e) => {
                if e.kind() != io::ErrorKind::UnexpectedEof {
                    eprintln!("❌ Error receiving message from {}: {}", peer_address, e);
                }
                break;
            }
        }
    }
    Ok(())
}

fn handle_outgoing_connection(
    stream: TcpStream,
    peer_address: String,
    blockchain: BlockchainArc,
    connected_peers: PeersArc,
    peer_state_cache: PeerStateCacheArc,
    message_sender: mpsc::Sender<(String, NetworkMessage)>,
    config: NodeConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    configure_peer_stream(&stream);
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = BufWriter::new(stream);

    // Add peer to connected peers
    {
        let mut peers = connected_peers.lock().unwrap();
        peers.insert(
            peer_address.clone(),
            PeerConnection {
                address: peer_address.clone(),
                direction: ConnectionDirection::Outgoing,
                public_address: None,
                validator_address: None,
                connected_at: current_timestamp(),
                last_seen: current_timestamp(),
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: Some(writer.get_ref().try_clone()?),
                node_id: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
    }
    let _peer_entry_guard = PeerEntryGuard::new(
        peer_address.clone(),
        Arc::clone(&connected_peers),
        Arc::clone(&peer_state_cache),
    );

    // Send handshake
    let handshake = build_local_handshake(&config)
        .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;

    send_message(&mut writer, &handshake)?;
    writer.flush()?;

    let status = build_local_status_message(&blockchain, &config);
    if let Err(error) = send_message(&mut writer, &status) {
        warn!(
            "p2p",
            "Failed to proactively send status after handshake",
            "peer" => peer_address.clone(),
            "error" => error.to_string()
        );
    } else {
        writer.flush()?;
    }

    // Listen for messages
    loop {
        match receive_message(&mut reader) {
            Ok(message) => {
                // Update last seen
                {
                    let mut peers = connected_peers.lock().unwrap();
                    if let Some(peer) = peers.get_mut(&peer_address) {
                        peer.last_seen = current_timestamp();
                    }
                }

                if let Err(_) = dispatch_peer_message(
                    &blockchain,
                    &connected_peers,
                    &peer_state_cache,
                    &message_sender,
                    &config,
                    &peer_address,
                    message,
                ) {
                    break;
                }
            }
            Err(e) => {
                if e.kind() != io::ErrorKind::UnexpectedEof {
                    eprintln!("❌ Error receiving message from {}: {}", peer_address, e);
                }
                break;
            }
        }
    }
    Ok(())
}

fn handle_messages(
    blockchain: BlockchainArc,
    connected_peers: PeersArc,
    peer_state_cache: PeerStateCacheArc,
    discovered_dial_targets: DialTargetsArc,
    dial_registry: DialRegistryArc,
    receiver: Arc<Mutex<mpsc::Receiver<(String, NetworkMessage)>>>,
    message_sender: mpsc::Sender<(String, NetworkMessage)>,
    config: NodeConfig,
) {
    loop {
        let receiver = receiver.lock().unwrap();
        match receiver.recv() {
            Ok((peer_address, message)) => {
                drop(receiver); // Release lock before processing

                match message {
                    NetworkMessage::Handshake {
                        node_id,
                        version,
                        capabilities,
                        chain_id,
                        network_id,
                        network_id_text,
                        genesis_hash,
                        network_magic_bytes,
                        protocol_version,
                        consensus_version,
                        native_caip2,
                        reserved_eip155,
                        public_address,
                        validator_address,
                        role,
                        active_validator_set_hash,
                        cluster_map_hash,
                        protocol_config_hash,
                        aegis_pqvm_version,
                        aegis_pq_public_key_id,
                        aegis_pq_public_key_algorithm,
                        aegis_pq_public_key,
                        aegis_pq_handshake_signature,
                    } => {
                        let node_id = node_id.trim().to_string();
                        let handshake_for_verification = NetworkMessage::Handshake {
                            node_id: node_id.clone(),
                            version: version.clone(),
                            capabilities: capabilities.clone(),
                            chain_id,
                            network_id,
                            network_id_text: network_id_text.clone(),
                            genesis_hash: genesis_hash.clone(),
                            network_magic_bytes: network_magic_bytes.clone(),
                            protocol_version: protocol_version.clone(),
                            consensus_version: consensus_version.clone(),
                            native_caip2: native_caip2.clone(),
                            reserved_eip155: reserved_eip155.clone(),
                            public_address: public_address.clone(),
                            validator_address: validator_address.clone(),
                            role: role.clone(),
                            active_validator_set_hash: active_validator_set_hash.clone(),
                            cluster_map_hash: cluster_map_hash.clone(),
                            protocol_config_hash: protocol_config_hash.clone(),
                            aegis_pqvm_version: aegis_pqvm_version.clone(),
                            aegis_pq_public_key_id: aegis_pq_public_key_id.clone(),
                            aegis_pq_public_key_algorithm: aegis_pq_public_key_algorithm.clone(),
                            aegis_pq_public_key: aegis_pq_public_key.clone(),
                            aegis_pq_handshake_signature: aegis_pq_handshake_signature.clone(),
                        };
                        if node_id.is_empty() {
                            warn!(
                                "p2p",
                                "Rejecting handshake with empty node_id",
                                "peer" => peer_address.clone()
                            );
                            let mut peers = connected_peers.lock().unwrap();
                            disconnect_peer_entry(&peer_state_cache, &mut peers, &peer_address);
                            continue;
                        }

                        if node_id == config.p2p.node_name {
                            warn!(
                                "p2p",
                                "Rejecting self-connection handshake",
                                "peer" => peer_address.clone(),
                                "node_id" => node_id.clone()
                            );
                            let mut peers = connected_peers.lock().unwrap();
                            disconnect_peer_entry(&peer_state_cache, &mut peers, &peer_address);
                            continue;
                        }

                        if let Some(reason) = handshake_mismatch_reason(
                            &config,
                            chain_id,
                            network_id,
                            network_id_text.as_deref(),
                            &genesis_hash,
                            &network_magic_bytes,
                            native_caip2.as_deref(),
                        ) {
                            warn!(
                                "p2p",
                                "Rejecting peer handshake for canonical testnet identity mismatch",
                                "peer" => peer_address.clone(),
                                "node_id" => node_id.clone(),
                                "reason" => reason,
                                "local_chain_id" => local_chain_id(&config),
                                "local_network_id" => local_network_id(&config),
                                "local_genesis_hash" => canonical_genesis_hash(),
                                "local_network_magic_bytes" => canonical_network_magic_bytes()
                            );
                            let mut peers = connected_peers.lock().unwrap();
                            disconnect_peer_entry(&peer_state_cache, &mut peers, &peer_address);
                            continue;
                        }

                        if let Err(reason) =
                            verify_handshake_pq_signature(&handshake_for_verification)
                        {
                            warn!(
                                "p2p",
                                "Rejecting peer handshake because Aegis PQC authentication failed",
                                "peer" => peer_address.clone(),
                                "node_id" => node_id.clone(),
                                "reason" => reason
                            );
                            let mut peers = connected_peers.lock().unwrap();
                            disconnect_peer_entry(&peer_state_cache, &mut peers, &peer_address);
                            continue;
                        }

                        if reserved_eip155
                            .as_deref()
                            .filter(|value| !value.is_empty())
                            .is_some()
                            && native_caip2.as_deref() != Some(TESTNET_NATIVE_CAIP2)
                        {
                            warn!(
                                "p2p",
                                "Rejecting peer handshake because reserved EIP-155 identity cannot override native Synergy identity",
                                "peer" => peer_address.clone(),
                                "node_id" => node_id.clone(),
                                "reserved_eip155" => reserved_eip155.unwrap_or_default()
                            );
                            let mut peers = connected_peers.lock().unwrap();
                            disconnect_peer_entry(&peer_state_cache, &mut peers, &peer_address);
                            continue;
                        }

                        let announced_validator_address = validator_address
                            .as_ref()
                            .map(|value| value.trim().to_string())
                            .filter(|value| !value.is_empty());
                        let canonicalize_validator_public_address =
                            should_canonicalize_validator_public_address(
                                announced_validator_address.as_deref(),
                            );
                        let normalized_public_address = if canonicalize_validator_public_address {
                            canonical_validator_public_address(
                                &peer_address,
                                public_address.as_deref(),
                            )
                        } else {
                            public_address
                                .as_deref()
                                .and_then(parse_bootnode_dial_address)
                                .or_else(|| public_address.clone())
                        };
                        if canonicalize_validator_public_address
                            && normalized_public_address != public_address
                        {
                            warn!(
                                "p2p",
                                "Normalized validator public address to canonical port",
                                "peer" => peer_address.clone(),
                                "advertised_public_address" => public_address.clone().unwrap_or_default(),
                                "normalized_public_address" => normalized_public_address.clone().unwrap_or_default()
                            );
                        }
                        let peer_identity =
                            peer_identity_key(&node_id, announced_validator_address.as_deref());
                        let local_identity = local_peer_identity(&config);

                        info!(
                            "p2p",
                            "Handshake received",
                            "peer" => peer_address.clone(),
                            "node_id" => node_id.clone(),
                            "validator_address" => announced_validator_address.clone().unwrap_or_default(),
                            "version" => version.clone(),
                            "protocol_version" => protocol_version.unwrap_or_default(),
                            "consensus_version" => consensus_version.unwrap_or_default(),
                            "genesis_hash" => genesis_hash.clone(),
                            "network_magic_bytes" => network_magic_bytes,
                            "public_address" => normalized_public_address.clone().unwrap_or_default()
                        );

                        // Update peer info and deduplicate by stable peer identity.
                        {
                            let mut peers = connected_peers.lock().unwrap();

                            // Prefer validator identity when present; fall back to node_id for
                            // non-validator/discovery peers.
                            let existing_peer_key = peers
                                .iter()
                                .find(|(_, peer)| {
                                    peer_identity_from_connection(peer).as_deref()
                                        == Some(peer_identity.as_str())
                                })
                                .map(|(key, _)| key.clone());

                            if let Some(existing_key) = existing_peer_key.clone() {
                                if existing_key != peer_address {
                                    let existing_metadata = peers.get(&existing_key).map(|peer| {
                                        (
                                            peer.direction,
                                            peer.connected_at,
                                            peer.public_address.clone(),
                                        )
                                    });
                                    let new_metadata = peers
                                        .get(&peer_address)
                                        .map(|peer| (peer.direction, peer.connected_at));

                                    let existing_cached_state =
                                        peers.get(&existing_key).and_then(|peer| {
                                            build_cached_peer_state(peer).map(|(_, state)| state)
                                        });

                                    if let (
                                        Some((
                                            existing_direction,
                                            existing_connected_at,
                                            existing_public_address,
                                        )),
                                        Some((new_direction, new_connected_at)),
                                    ) = (existing_metadata, new_metadata)
                                    {
                                        let existing_needs_status_recovery = peers
                                            .get(&existing_key)
                                            .map(|peer| {
                                                peer_has_validator_identity(peer)
                                                    && !peer_has_remote_status(peer)
                                            })
                                            .unwrap_or(false);
                                        let duplicate_resolution = if existing_needs_status_recovery
                                        {
                                            DuplicateResolution::ReplaceExisting
                                        } else {
                                            resolve_duplicate_connection(
                                                &local_identity,
                                                &peer_identity,
                                                existing_direction,
                                                existing_connected_at,
                                                new_direction,
                                                new_connected_at,
                                            )
                                        };

                                        match duplicate_resolution {
                                            DuplicateResolution::KeepExisting => {
                                                if let Some(peer) = peers.get_mut(&existing_key) {
                                                    peer.node_id = Some(node_id.clone());
                                                    peer.version = Some(version.clone());
                                                    peer.capabilities = capabilities.clone();
                                                    if normalized_public_address
                                                        .as_deref()
                                                        .map(str::trim)
                                                        .filter(|value| !value.is_empty())
                                                        .is_some()
                                                    {
                                                        peer.public_address =
                                                            normalized_public_address.clone();
                                                    }
                                                    if announced_validator_address.is_some() {
                                                        peer.validator_address =
                                                            announced_validator_address.clone();
                                                    }
                                                    if !genesis_hash.trim().is_empty() {
                                                        peer.genesis_hash = genesis_hash.clone();
                                                    }
                                                    hydrate_peer_from_cache(
                                                        &peer_state_cache,
                                                        &peer_identity,
                                                        peer,
                                                    );
                                                    cache_peer_state(&peer_state_cache, peer);
                                                }
                                                propagate_identity_to_matching_peers(
                                                    &mut peers,
                                                    &peer_state_cache,
                                                    &existing_key,
                                                    &node_id,
                                                    &version,
                                                    &capabilities,
                                                    normalized_public_address.as_deref(),
                                                    announced_validator_address.as_deref(),
                                                    &genesis_hash,
                                                );
                                                request_status_from_connected_peer(
                                                    &mut peers,
                                                    &existing_key,
                                                );
                                                warn!(
                                                    "p2p",
                                                    "Duplicate peer session detected; keeping stable connection",
                                                    "node_id" => node_id.clone(),
                                                    "kept_address" => existing_key.clone(),
                                                    "kept_direction" => format!("{:?}", existing_direction),
                                                    "dropped_address" => peer_address.clone(),
                                                    "dropped_direction" => format!("{:?}", new_direction),
                                                    "preferred_direction" => format!(
                                                        "{:?}",
                                                        preferred_connection_direction(
                                                            &local_identity,
                                                            &peer_identity
                                                        )
                                                    ),
                                                    "kept_public_address" => existing_public_address.unwrap_or_default()
                                                );
                                                disconnect_peer_entry(
                                                    &peer_state_cache,
                                                    &mut peers,
                                                    &peer_address,
                                                );
                                                continue;
                                            }
                                            DuplicateResolution::ReplaceExisting => {
                                                if let (Some(existing_state), Some(peer)) = (
                                                    existing_cached_state.as_ref(),
                                                    peers.get_mut(&peer_address),
                                                ) {
                                                    let existing_peer = PeerConnection {
                                                        address: String::new(),
                                                        direction: ConnectionDirection::Outgoing,
                                                        public_address: existing_state
                                                            .public_address
                                                            .clone(),
                                                        validator_address: existing_state
                                                            .validator_address
                                                            .clone(),
                                                        connected_at: existing_state.connected_at,
                                                        last_seen: existing_state.last_seen,
                                                        blocks_sent: 0,
                                                        blocks_received: 0,
                                                        txs_sent: 0,
                                                        txs_received: 0,
                                                        stream: None,
                                                        node_id: existing_state.node_id.clone(),
                                                        version: existing_state.version.clone(),
                                                        capabilities: existing_state
                                                            .capabilities
                                                            .clone(),
                                                        last_known_height: existing_state
                                                            .last_known_height,
                                                        best_block_hash: existing_state
                                                            .best_block_hash
                                                            .clone(),
                                                        genesis_hash: existing_state
                                                            .genesis_hash
                                                            .clone(),
                                                        status_received_at: existing_state
                                                            .status_received_at,
                                                        quarantined: existing_state.quarantined,
                                                        consensus_duties_disabled: existing_state
                                                            .consensus_duties_disabled,
                                                        recovery_state: existing_state
                                                            .recovery_state
                                                            .clone(),
                                                    };
                                                    merge_peer_state_from_existing(
                                                        &existing_peer,
                                                        peer,
                                                    );
                                                }
                                                if let Some(peer) = peers.get(&existing_key) {
                                                    cache_peer_state(&peer_state_cache, peer);
                                                }
                                                warn!(
                                                    "p2p",
                                                    "Duplicate peer session detected; replacing non-preferred connection",
                                                    "node_id" => node_id.clone(),
                                                    "old_address" => existing_key.clone(),
                                                    "old_direction" => format!("{:?}", existing_direction),
                                                    "new_address" => peer_address.clone(),
                                                    "new_direction" => format!("{:?}", new_direction),
                                                    "preferred_direction" => format!(
                                                        "{:?}",
                                                        preferred_connection_direction(
                                                            &local_identity,
                                                            &peer_identity
                                                        )
                                                    ),
                                                    "status_recovery_replacement" => existing_needs_status_recovery
                                                );
                                                disconnect_peer_entry(
                                                    &peer_state_cache,
                                                    &mut peers,
                                                    &existing_key,
                                                );
                                            }
                                        }
                                    }
                                }
                            }

                            // Update peer info
                            if let Some(peer) = peers.get_mut(&peer_address) {
                                peer.node_id = Some(node_id.clone());
                                peer.version = Some(version.clone());
                                peer.capabilities = capabilities.clone();
                                peer.public_address = normalized_public_address.clone();
                                peer.validator_address = announced_validator_address.clone();
                                if !genesis_hash.trim().is_empty() {
                                    peer.genesis_hash = genesis_hash.clone();
                                }
                                hydrate_peer_from_cache(&peer_state_cache, &peer_identity, peer);
                                cache_peer_state(&peer_state_cache, peer);
                            }
                            propagate_identity_to_matching_peers(
                                &mut peers,
                                &peer_state_cache,
                                &peer_address,
                                &node_id,
                                &version,
                                &capabilities,
                                normalized_public_address.as_deref(),
                                announced_validator_address.as_deref(),
                                &genesis_hash,
                            );
                            request_status_from_connected_peer(&mut peers, &peer_address);
                        }

                        // Candidate validators are discovered here, but funding and consensus
                        // activation must run through the explicit source-level workflow.
                        {
                            // Only auto-register if auto-registration is enabled in config
                            if config.node.bootstrap_only {
                                debug!(
                                    "p2p",
                                    "Bootstrap-only mode enabled; skipping validator auto-registration for peer",
                                    "peer" => peer_address.clone(),
                                    "peer_identity" => peer_identity.clone()
                                );
                                continue;
                            }

                            if config.node.auto_register_validator
                                && !config.node.strict_validator_allowlist
                            {
                                debug!(
                                    "p2p",
                                    "Skipping unsafe validator auto-registration because strict validator allowlist is disabled",
                                    "peer" => peer_address.clone(),
                                    "peer_identity" => peer_identity.clone()
                                );
                                continue;
                            }

                            if config.node.auto_register_validator {
                                let Some(validator_address) = announced_validator_address.clone()
                                else {
                                    debug!(
                                        "p2p",
                                        "Peer did not advertise a validator address; skipping validator auto-registration",
                                        "peer" => peer_address.clone(),
                                        "peer_identity" => peer_identity.clone()
                                    );
                                    continue;
                                };

                                if !is_validator_allowed(&config, &validator_address) {
                                    warn!(
                                        "p2p",
                                        "Skipping validator auto-registration: address not in allowlist",
                                        "address" => validator_address.clone()
                                    );
                                    continue;
                                }
                                let validator_manager = VALIDATOR_MANAGER.clone();
                                let is_registered = validator_manager
                                    .get_validator(&validator_address)
                                    .is_some();
                                let is_pending = validator_manager.is_pending(&validator_address);

                                if !is_registered && !is_pending {
                                    info!(
                                        "p2p",
                                        "Observed candidate validator; explicit 5,000 SNRG funding and activation are required before consensus membership",
                                        "address" => validator_address.clone()
                                    );
                                }
                            }
                        }
                    }
                    NetworkMessage::Block {
                        block_data,
                        quorum_certificate,
                    } => {
                        handle_block_message(
                            &blockchain,
                            &connected_peers,
                            &peer_state_cache,
                            &config,
                            &peer_address,
                            block_data,
                            quorum_certificate,
                        );
                    }
                    NetworkMessage::VoteRequest {
                        block_data,
                        epoch_number,
                        round_number,
                    } => handle_vote_request_message(
                        &blockchain,
                        &connected_peers,
                        &config,
                        &peer_address,
                        block_data,
                        epoch_number,
                        round_number,
                    ),
                    NetworkMessage::Vote { vote } => {
                        handle_vote_message(&connected_peers, &config, &peer_address, vote)
                    }
                    NetworkMessage::Transaction { transaction_data } => {
                        if config.node.bootstrap_only {
                            debug!(
                                "p2p",
                                "Bootstrap-only node ignoring transaction propagation",
                                "peer" => peer_address.clone(),
                                "tx_hash" => transaction_data.hash()
                            );
                            continue;
                        }

                        info!("p2p", "Received transaction", "peer" => peer_address.clone());

                        // Update peer stats
                        {
                            let mut peers = connected_peers.lock().unwrap();
                            if let Some(peer) = peers.get_mut(&peer_address) {
                                peer.txs_received += 1;
                            }
                        }

                        let validation = transaction_data.validate_for_admission();
                        if !validation.is_valid {
                            warn!(
                                "p2p",
                                "Rejecting transaction before DAG/mempool admission",
                                "peer" => peer_address.clone(),
                                "tx_hash" => transaction_data.hash(),
                                "error" => validation
                                    .error_message
                                    .unwrap_or_else(|| "invalid transaction".to_string())
                            );
                            continue;
                        }

                        if let Err(error) =
                            ProofOfSynergy::validate_transaction_for_mempool(&transaction_data)
                        {
                            let tx_hash = transaction_data.hash();
                            let pruned = prune_transaction_hashes_from_pool(&transaction_hashes(
                                std::slice::from_ref(&transaction_data),
                            ));
                            warn!(
                                "p2p",
                                "Rejecting transaction after runtime validation",
                                "peer" => peer_address.clone(),
                                "tx_hash" => tx_hash,
                                "error" => error,
                                "pruned_count" => pruned as u64
                            );
                            continue;
                        }

                        let tx_hash = transaction_data.hash();
                        let should_forward = {
                            let mut pool = TX_POOL.lock().unwrap();
                            if !pool.iter().any(|t| t.hash() == tx_hash) {
                                pool.push(transaction_data.clone());
                                info!("p2p", "Transaction added to pool", "tx_hash" => tx_hash.clone());
                                true
                            } else {
                                debug!("p2p", "Duplicate transaction ignored", "tx_hash" => tx_hash.clone());
                                false
                            }
                        };

                        if should_forward {
                            let message = NetworkMessage::Transaction { transaction_data };
                            let mut peers = connected_peers.lock().unwrap();
                            let mut forwarded_peers = 0u64;

                            for (address, peer) in peers.iter_mut() {
                                if address == &peer_address {
                                    continue;
                                }

                                if let Some(ref mut stream) = peer.stream {
                                    if let Err(error) = send_message(stream, &message) {
                                        warn!(
                                            "p2p",
                                            "Failed to forward transaction",
                                            "peer" => address.clone(),
                                            "tx_hash" => tx_hash.clone(),
                                            "error" => error.to_string()
                                        );
                                    } else {
                                        peer.txs_sent += 1;
                                        forwarded_peers += 1;
                                    }
                                }
                            }

                            info!(
                                "p2p",
                                "Transaction forwarded",
                                "tx_hash" => tx_hash,
                                "from_peer" => peer_address.clone(),
                                "peers" => forwarded_peers
                            );
                        }
                    }
                    NetworkMessage::GetBlocks { from_height, count } => {
                        handle_get_blocks_message(
                            &blockchain,
                            &connected_peers,
                            &peer_state_cache,
                            &config,
                            &peer_address,
                            from_height,
                            count,
                        );
                    }
                    NetworkMessage::GetStatus => {
                        let status = build_local_status_message(&blockchain, &config);

                        let mut peers = connected_peers.lock().unwrap();
                        if let Some(peer) = peers.get_mut(&peer_address) {
                            if let Some(ref mut stream) = peer.stream {
                                if let Err(e) = send_message(stream, &status) {
                                    warn!("p2p", "Failed to send status", "peer" => peer_address.clone(), "error" => e.to_string());
                                }
                            }
                        }
                    }
                    NetworkMessage::Status {
                        block_height,
                        best_block_hash,
                        genesis_hash,
                        quarantined,
                        consensus_duties_disabled,
                        recovery_state,
                    } => {
                        handle_status_message(
                            &blockchain,
                            &connected_peers,
                            &peer_state_cache,
                            &config,
                            &peer_address,
                            block_height,
                            &best_block_hash,
                            &genesis_hash,
                            quarantined,
                            consensus_duties_disabled,
                            recovery_state.as_deref(),
                        );
                    }
                    NetworkMessage::GetBlockHeaders {
                        start_height,
                        count,
                    } => {
                        if config.node.bootstrap_only {
                            let response = NetworkMessage::BlockHeaders {
                                headers: Vec::new(),
                            };
                            let mut peers = connected_peers.lock().unwrap();
                            if let Some(peer) = peers.get_mut(&peer_address) {
                                if let Some(ref mut stream) = peer.stream {
                                    let _ = send_message(stream, &response);
                                }
                            }
                            continue;
                        }

                        let headers = {
                            let chain = blockchain.lock().unwrap();
                            chain
                                .chain
                                .iter()
                                .filter(|block| block.block_index >= start_height)
                                .take(count.min(MAX_BLOCK_SYNC_RESPONSE_BLOCKS as u64) as usize)
                                .map(|block| block.header())
                                .collect::<Vec<_>>()
                        };
                        let response = NetworkMessage::BlockHeaders { headers };
                        let mut peers = connected_peers.lock().unwrap();
                        if let Some(peer) = peers.get_mut(&peer_address) {
                            if let Some(ref mut stream) = peer.stream {
                                let _ = send_message(stream, &response);
                            }
                        }
                    }
                    NetworkMessage::BlockHeaders { headers } => {
                        if config.node.bootstrap_only {
                            debug!(
                                "p2p",
                                "Bootstrap-only node ignoring block headers",
                                "peer" => peer_address.clone(),
                                "count" => headers.len()
                            );
                            continue;
                        }

                        debug!("p2p", "Received block headers", "peer" => peer_address.clone(), "count" => headers.len());
                    }
                    NetworkMessage::GetBlockBodies { hashes } => {
                        if config.node.bootstrap_only {
                            let response = NetworkMessage::BlockBodies {
                                blocks: Vec::new(),
                                quorum_certificates: Vec::new(),
                            };
                            let mut peers = connected_peers.lock().unwrap();
                            if let Some(peer) = peers.get_mut(&peer_address) {
                                if let Some(ref mut stream) = peer.stream {
                                    let _ = send_message(stream, &response);
                                }
                            }
                            continue;
                        }

                        let (blocks, quorum_certificates) = {
                            let chain = blockchain.lock().unwrap();
                            let blocks = hashes
                                .iter()
                                .filter_map(|hash| {
                                    chain
                                        .chain
                                        .iter()
                                        .find(|block| &block.hash == hash)
                                        .cloned()
                                })
                                .collect::<Vec<_>>();
                            let quorum_certificates =
                                DualQuorumConsensus::committed_qcs_for_block_hashes(
                                    blocks.iter().map(|block| block.hash.as_str()),
                                );
                            (blocks, quorum_certificates)
                        };
                        let response = NetworkMessage::BlockBodies {
                            blocks,
                            quorum_certificates,
                        };
                        let mut peers = connected_peers.lock().unwrap();
                        if let Some(peer) = peers.get_mut(&peer_address) {
                            if let Some(ref mut stream) = peer.stream {
                                let _ = send_message(stream, &response);
                            }
                        }
                    }
                    NetworkMessage::BlockBodies {
                        blocks,
                        quorum_certificates,
                    } => {
                        if config.node.bootstrap_only {
                            debug!(
                                "p2p",
                                "Bootstrap-only node ignoring block bodies",
                                "peer" => peer_address.clone(),
                                "count" => blocks.len()
                            );
                            continue;
                        }

                        debug!("p2p", "Received block bodies", "peer" => peer_address.clone(), "count" => blocks.len());
                        let applied = apply_block_batch(&blockchain, blocks, quorum_certificates);
                        if applied > 0 {
                            info!("p2p", "Body blocks applied", "count" => applied);
                        }
                    }
                    NetworkMessage::Blocks {
                        blocks,
                        quorum_certificates,
                    } => {
                        handle_blocks_message(
                            &blockchain,
                            &connected_peers,
                            &peer_state_cache,
                            &config,
                            &peer_address,
                            blocks,
                            quorum_certificates,
                        );
                    }
                    NetworkMessage::GetPeers => {
                        // Respond with known peer dial addresses.
                        let peer_addresses = if config.p2p.enable_discovery {
                            collect_known_peer_addresses(
                                &connected_peers,
                                &discovered_dial_targets,
                                &config,
                            )
                        } else {
                            Vec::new()
                        };
                        let response = NetworkMessage::Peers { peer_addresses };

                        {
                            let mut peers = connected_peers.lock().unwrap();
                            if let Some(peer) = peers.get_mut(&peer_address) {
                                if let Some(ref mut stream) = peer.stream {
                                    if let Err(e) = send_message(stream, &response) {
                                        warn!("p2p", "Failed to send peers list", "peer" => peer_address.clone(), "error" => e.to_string());
                                    }
                                }
                            }
                        }
                    }
                    NetworkMessage::Peers { peer_addresses } => {
                        if !config.p2p.enable_discovery {
                            debug!(
                                "p2p",
                                "Ignoring peer discovery response because discovery is disabled",
                                "peer" => peer_address.clone()
                            );
                            continue;
                        }

                        // Attempt to dial new peers (best-effort).
                        let max_peers = config.network.max_peers as usize;
                        for addr in peer_addresses {
                            let Some(addr) = parse_bootnode_dial_address(&addr) else {
                                debug!(
                                    "p2p",
                                    "Ignoring non-dialable peer discovery address",
                                    "peer" => peer_address.clone(),
                                    "address" => addr
                                );
                                continue;
                            };
                            if !is_assigned_synergy_dial_address(&addr) {
                                continue;
                            }
                            if is_self_dial_target(&config, &addr) {
                                continue;
                            }
                            let should_dial = {
                                let peers = connected_peers.lock().unwrap();
                                if peers.len() >= max_peers {
                                    false
                                } else if peers.contains_key(&addr) {
                                    false
                                } else {
                                    // Also avoid redialing if the addr is already known as a public address.
                                    !peers
                                        .values()
                                        .any(|p| p.public_address.as_deref() == Some(addr.as_str()))
                                }
                            };
                            if should_dial {
                                info!(
                                    "p2p",
                                    "Dialing discovered peer",
                                    "source_peer" => peer_address.clone(),
                                    "target" => addr.clone()
                                );
                                let _ = dial_peer_async(
                                    addr.clone(),
                                    Arc::clone(&blockchain),
                                    Arc::clone(&connected_peers),
                                    Arc::clone(&peer_state_cache),
                                    Arc::clone(&dial_registry),
                                    message_sender.clone(),
                                    config.clone(),
                                );
                            }
                        }
                    }
                    NetworkMessage::Ping => {
                        debug!("p2p", "Ping received", "peer" => peer_address.clone());

                        // Send pong
                        {
                            let mut peers = connected_peers.lock().unwrap();
                            if let Some(peer) = peers.get_mut(&peer_address) {
                                if let Some(ref mut stream) = peer.stream {
                                    let pong = NetworkMessage::Pong;
                                    if let Err(e) = send_message(stream, &pong) {
                                        warn!("p2p", "Failed to send pong", "peer" => peer_address.clone(), "error" => e.to_string());
                                    }
                                }
                            }
                        }
                    }
                    NetworkMessage::Pong => {
                        debug!("p2p", "Pong received", "peer" => peer_address.clone());
                    }
                    _ => {
                        debug!("p2p", "Unhandled P2P message", "peer" => peer_address.clone(), "message" => format!("{:?}", message));
                    }
                }
            }
            Err(_) => {
                break;
            }
        }
    }
}

fn send_message(
    stream: &mut impl Write,
    message: &NetworkMessage,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string(message)?;
    let data = json.as_bytes();
    let len = data.len() as u32;

    // Send length prefix
    stream.write_all(&len.to_le_bytes())?;
    // Send message data
    stream.write_all(data)?;
    stream.flush()?;

    Ok(())
}

fn send_consensus_message(
    stream: &mut TcpStream,
    message: &NetworkMessage,
) -> Result<(), Box<dyn std::error::Error>> {
    send_message_with_write_timeout(
        stream,
        message,
        Duration::from_millis(CONSENSUS_MESSAGE_WRITE_TIMEOUT_MILLIS),
    )
}

fn send_message_with_write_timeout(
    stream: &mut TcpStream,
    message: &NetworkMessage,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let previous_timeout = stream.write_timeout()?;
    stream.set_write_timeout(Some(timeout))?;
    let send_result = send_message(stream, message);
    let restore_result = stream.set_write_timeout(previous_timeout);

    match (send_result, restore_result) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(Box::new(error)),
        (Ok(_), Ok(_)) => Ok(()),
    }
}

fn receive_message(stream: &mut impl Read) -> Result<NetworkMessage, io::Error> {
    // Read length prefix
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes)?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > MAX_P2P_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("p2p frame length {len} exceeds limit {MAX_P2P_FRAME_BYTES}"),
        ));
    }

    // Read message data
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data)?;

    // Parse JSON message
    let json =
        String::from_utf8(data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let message: NetworkMessage =
        serde_json::from_str(&json).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(message)
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn parse_bootnode_dial_address(bootnode: &str) -> Option<String> {
    let raw = bootnode.trim();
    if raw.is_empty() {
        return None;
    }

    // Strip common schemes
    let raw = raw
        .strip_prefix("snr://")
        .or_else(|| raw.strip_prefix("enode://"))
        .unwrap_or(raw);

    // Use part after '@' if present.
    let raw = raw.rsplit_once('@').map(|(_, right)| right).unwrap_or(raw);

    // Strip path / query / fragment.
    let raw = raw.split('/').next().unwrap_or(raw);
    let raw = raw.split('?').next().unwrap_or(raw);
    let raw = raw.split('#').next().unwrap_or(raw);

    normalize_dial_target(raw.trim())
}

fn normalize_dial_target(dial: &str) -> Option<String> {
    let dial = dial.trim();
    if dial.is_empty() {
        return None;
    }

    if let Some(stripped) = dial.strip_prefix('[') {
        let (host, port) = stripped.rsplit_once("]:")?;
        return normalize_host_port(host, port);
    }

    let (host, port) = dial.rsplit_once(':')?;
    normalize_host_port(host, port)
}

fn normalize_host_port(host: &str, port: &str) -> Option<String> {
    let host = host
        .trim()
        .trim_matches('[')
        .trim_matches(']')
        .trim_end_matches('.');
    let port = port.trim().parse::<u16>().ok()?;
    if port == 0 || host.is_empty() || !is_plausible_dial_host(host) {
        return None;
    }

    match host.parse::<std::net::IpAddr>() {
        // Preserve IPv6 literals in normalized form even though the dialer later
        // constrains outbound connections to IPv4 endpoints.
        Ok(std::net::IpAddr::V6(_)) => Some(format!("[{host}]:{port}")),
        Ok(std::net::IpAddr::V4(_)) => Some(format!("{host}:{port}")),
        Err(_) if host.contains(':') => None,
        Err(_) => Some(format!("{host}:{port}")), // DNS hostnames
    }
}

fn is_plausible_dial_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }

    host.contains('.')
        && host.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '-' || character == '.'
        })
}

fn dial_with_timeout(peer: &str, timeout: std::time::Duration) -> io::Result<TcpStream> {
    let mut last_err: Option<io::Error> = None;
    let addrs = peer.to_socket_addrs()?;
    // Only dial IPv4 addresses — IPv6 peers behind NAT/firewalls cause
    // spurious timeouts that flood the logs and waste connection budget.
    let ipv4_addrs: Vec<_> = addrs.filter(|a| a.is_ipv4()).collect();
    if ipv4_addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("No IPv4 addresses resolved for {peer}"),
        ));
    }
    for addr in ipv4_addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => {
                configure_peer_stream(&stream);
                return Ok(stream);
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "No resolved addresses")))
}

fn collect_known_peer_addresses(
    connected_peers: &PeersArc,
    discovered_dial_targets: &DialTargetsArc,
    config: &NodeConfig,
) -> Vec<String> {
    let mut out = HashSet::<String>::new();

    if is_assigned_synergy_dial_address(&config.p2p.public_address) {
        if let Some(address) = parse_bootnode_dial_address(&config.p2p.public_address) {
            out.insert(address);
        }
    }

    for dial in config
        .network
        .persistent_peers
        .iter()
        .chain(config.network.additional_dial_targets.iter())
    {
        if is_assigned_synergy_dial_address(dial) {
            if let Some(address) = parse_bootnode_dial_address(dial) {
                out.insert(address);
            }
        }
    }

    if let Ok(discovered) = discovered_dial_targets.lock() {
        for dial in discovered.iter() {
            if !is_assigned_synergy_dial_address(dial) {
                continue;
            }
            if let Some(address) = parse_bootnode_dial_address(dial) {
                out.insert(address);
            }
        }
    }

    if let Ok(peers) = connected_peers.lock() {
        for peer in peers.values() {
            let has_validator_identity = peer
                .validator_address
                .as_deref()
                .map(str::trim)
                .is_some_and(|value| !value.is_empty());
            if !has_validator_identity {
                continue;
            }
            if let Some(pub_addr) = peer.public_address.as_ref() {
                if is_assigned_synergy_dial_address(pub_addr) {
                    if let Some(address) = parse_bootnode_dial_address(pub_addr) {
                        out.insert(address);
                        continue;
                    }
                }
            }
            if peer.direction == ConnectionDirection::Outgoing
                && is_assigned_synergy_dial_address(&peer.address)
            {
                if let Some(address) = parse_bootnode_dial_address(&peer.address) {
                    out.insert(address);
                }
            }
        }
    }

    let mut ordered = out.into_iter().collect::<Vec<_>>();
    ordered.sort();
    ordered
}

fn is_assigned_synergy_dial_address(value: &str) -> bool {
    let Some(normalized) = parse_bootnode_dial_address(value) else {
        return false;
    };
    let Some((host, _port)) = normalized.rsplit_once(':') else {
        return false;
    };
    let host = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    is_public_synergy_advertise_host(&host)
}

fn is_public_synergy_advertise_host(host: &str) -> bool {
    let host = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if host.is_empty() || host == "localhost" {
        return false;
    }

    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            !(ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified())
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local())
        }
        Err(_) => host.ends_with(".synergynode.xyz") || host.ends_with(".synergy-network.io"),
    }
}

fn verify_network_block(block: &Block) -> Result<(), String> {
    if block.block_index == 0 {
        return Ok(());
    }
    block.verify_proposer_signature()
}

fn verify_network_commit_certificate(
    block: &Block,
    qc: Option<&QuorumCertificate>,
) -> Result<QuorumCertificate, String> {
    let validator_manager = commit_verifier_validator_manager();

    if let Err(error) = verify_network_block(block) {
        return Err(format!("invalid Aegis PQC proposer signature: {error}"));
    }

    if block.block_index == 0 {
        return Ok(QuorumCertificate {
            block_hash: block.hash.clone(),
            epoch_number: 0,
            round_number: 0,
            aggregate_signature: vec![0],
            participant_bitmap: vec![0],
            cumulative_weight: 0.0,
            validation_quorum_met: true,
            cooperation_quorum_met: true,
            timestamp: block.timestamp,
            votes: Vec::new(),
        });
    }

    let qc = qc
        .cloned()
        .ok_or_else(|| "missing QC for committed network block".to_string())?;
    DualQuorumConsensus::verify_commit_certificate_for_block_static(
        block,
        &qc,
        &validator_manager,
    )?;
    Ok(qc)
}

fn commit_verifier_validator_manager() -> Arc<ValidatorManager> {
    #[cfg(test)]
    if let Some(validator_manager) =
        TEST_COMMIT_VERIFIER_VALIDATOR_MANAGER.with(|slot| slot.borrow().clone())
    {
        return validator_manager;
    }

    let validator_manager = Arc::new(ValidatorManager::new());
    copy_active_validators_into_commit_verifier(&validator_manager, &VALIDATOR_MANAGER);
    if validator_manager.get_active_validators().is_empty() {
        hydrate_commit_verifier_validator_manager(&validator_manager);
    }
    validator_manager
}

fn copy_active_validators_into_commit_verifier(
    target: &Arc<ValidatorManager>,
    source: &Arc<ValidatorManager>,
) {
    let active_validators = source.get_active_validators();
    if active_validators.is_empty() {
        return;
    }

    if let Ok(mut registry) = target.registry.lock() {
        for validator in active_validators {
            registry
                .validators
                .entry(validator.address.clone())
                .or_insert(validator);
        }
    }
}

fn hydrate_commit_verifier_validator_manager(validator_manager: &Arc<ValidatorManager>) {
    let canonical_validator_addresses = canonical_genesis()
        .ok()
        .map(|genesis| {
            genesis
                .validators()
                .iter()
                .map(|validator| validator.operator_address.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let required_validator_count = canonical_validator_addresses.len();

    if validator_manager
        .load_registry("data/validator_registry.json")
        .is_ok()
        && commit_verifier_has_active_validators(
            &validator_manager,
            &canonical_validator_addresses,
            required_validator_count,
        )
    {
        return;
    }

    let Ok(genesis) = canonical_genesis() else {
        return;
    };

    for validator in genesis.validators() {
        let address = validator.operator_address.as_str();
        if validator_manager.get_validator(address).is_none() {
            let _ = validator_manager.register_validator(ValidatorRegistration {
                address: validator.operator_address.clone(),
                public_key: validator.consensus_public_key.clone(),
                name: validator.moniker.clone(),
                stake_amount: validator.stake_nwei,
                submitted_at: genesis.timestamp(),
                registration_tx_hash: "genesis".to_string(),
            });
        }
        let _ = validator_manager.approve_validator(address);
        validator_manager.update_validator_stake(address, validator.stake_nwei);
        validator_manager.update_synergy_score(address, 100.0);
    }

    #[cfg(not(test))]
    let _ = validator_manager.save_registry("data/validator_registry.json");
}

fn commit_verifier_has_active_validators(
    validator_manager: &Arc<ValidatorManager>,
    required_addresses: &[String],
    required_validator_count: usize,
) -> bool {
    let active_validators = validator_manager.get_active_validators();
    if active_validators.len() < required_validator_count {
        return false;
    }

    if required_addresses.is_empty() {
        return true;
    }

    required_addresses.iter().all(|address| {
        active_validators
            .iter()
            .any(|validator| validator.address == *address)
    })
}

fn record_peer_canonical_lock_conflict(block: &Block, error: &str) {
    let local_locked_hash = legacy_canonical_commit_record(block.block_index)
        .ok()
        .flatten()
        .map(|record| record.block_hash);
    warn!(
        "p2p",
        "Rejected peer block that conflicts with local canonical lock",
        "height" => block.block_index,
        "local_locked_hash" => local_locked_hash.unwrap_or_else(|| "unknown".to_string()),
        "conflicting_hash" => block.hash.clone(),
        "error" => error.to_string()
    );
}

fn record_canonical_lock_conflict_from_peer(
    _blockchain: &BlockchainArc,
    block: &Block,
    error: &str,
) {
    record_peer_canonical_lock_conflict(block, error);
}

fn apply_block_if_new(
    blockchain: &BlockchainArc,
    block: Block,
    quorum_certificate: Option<QuorumCertificate>,
) -> bool {
    let qc = match verify_network_commit_certificate(&block, quorum_certificate.as_ref()) {
        Ok(qc) => qc,
        Err(error) => {
            warn!(
                "p2p",
                "Rejecting block without valid Aegis PQC quorum certificate",
                "height" => block.block_index,
                "hash" => block.hash.clone(),
                "error" => error
            );
            return false;
        }
    };
    if block.block_index > 0 {
        if let Err(error) = verify_legacy_canonical_lock(&block) {
            record_canonical_lock_conflict_from_peer(blockchain, &block, &error);
            warn!(
                "p2p",
                "Rejecting block that conflicts with canonical block lock",
                "height" => block.block_index,
                "hash" => block.hash.clone(),
                "error" => error
            );
            return false;
        }
    }

    let mut applied_blocks = Vec::new();
    let mut confirmed_hashes = HashSet::new();
    let (tip_height, snapshot) = {
        let mut chain = blockchain.lock().unwrap();
        let mut candidate = Some(PendingCommittedBlock {
            block,
            quorum_certificate: qc,
        });
        let mut final_tip_height = chain.last().map(|entry| entry.block_index).unwrap_or(0);

        while let Some(next) = candidate {
            let next_block = next.block;
            let next_qc = next.quorum_certificate;
            let Some(tip) = chain.last() else {
                if next_block.block_index != 0 {
                    break;
                }
                confirmed_hashes.extend(transaction_hashes(&next_block.transactions));
                chain.add_block(next_block.clone());
                final_tip_height = next_block.block_index;
                applied_blocks.push(next_block);
                break;
            };

            if next_block.block_index <= tip.block_index {
                break;
            }

            if next_block.block_index > tip.block_index.saturating_add(1) {
                cache_pending_block(next_block, next_qc);
                break;
            }

            if next_block.previous_hash != tip.hash {
                break;
            }

            if next_block.block_index > 0 {
                if let Err(error) = verify_legacy_canonical_lock(&next_block) {
                    record_canonical_lock_conflict_from_peer(blockchain, &next_block, &error);
                    warn!(
                        "p2p",
                        "Rejecting pending block because it conflicts with canonical block lock",
                        "height" => next_block.block_index,
                        "hash" => next_block.hash.clone(),
                        "error" => error
                    );
                    break;
                }
                if let Err(error) = append_committed_block_body(&next_block) {
                    warn!(
                        "p2p",
                        "Rejecting block because durable committed block body could not be written",
                        "height" => next_block.block_index,
                        "hash" => next_block.hash.clone(),
                        "error" => error
                    );
                    break;
                }
            }

            confirmed_hashes.extend(transaction_hashes(&next_block.transactions));
            if chain.add_block_extending_tip(next_block.clone()).is_err() {
                warn!(
                    "p2p",
                    "Rejecting block because it could not be materialized on the local chain tip after durable body write",
                    "height" => next_block.block_index,
                    "hash" => next_block.hash.clone()
                );
                break;
            }

            if next_block.block_index > 0 {
                if let Err(error) =
                    DualQuorumConsensus::record_committed_qc_checked(next_qc.clone())
                {
                    warn!(
                        "p2p",
                        "Rejecting block because durable committed QC could not be written",
                        "height" => next_block.block_index,
                        "hash" => next_block.hash.clone(),
                        "error" => error
                    );
                    break;
                }
                if let Err(error) = write_legacy_canonical_lock(&next_block, &next_qc) {
                    record_canonical_lock_conflict_from_peer(blockchain, &next_block, &error);
                    warn!(
                        "p2p",
                        "Rejecting block because canonical lock could not be written",
                        "height" => next_block.block_index,
                        "hash" => next_block.hash.clone(),
                        "error" => error
                    );
                    break;
                }
            }

            final_tip_height = next_block.block_index;
            applied_blocks.push(next_block.clone());

            let next_tip = chain.last().cloned();
            candidate = next_tip.as_ref().and_then(take_pending_block_extending_tip);
        }

        compact_hot_chain_state_from_env(&mut chain, "p2p_apply_block_if_new");
        let snapshot = if !applied_blocks.is_empty() && should_persist_chain_tip(final_tip_height) {
            note_chain_persist(final_tip_height);
            if can_clone_chain_for_snapshot(final_tip_height) {
                Some(chain.clone())
            } else {
                None
            }
        } else {
            None
        };
        (final_tip_height, snapshot)
    };

    if applied_blocks.is_empty() {
        return false;
    }

    if let Some(snapshot) = snapshot {
        let chain_path = crate::utils::resolve_data_path("data/chain.json");
        persist_chain_snapshot_async(snapshot, chain_path, tip_height);
    }

    prune_transaction_hashes_from_pool(&confirmed_hashes);
    crate::dag::commit_blocks(&applied_blocks);
    apply_token_state_for_blocks(&applied_blocks);

    true
}

fn cache_pending_block(block: Block, quorum_certificate: QuorumCertificate) {
    if let Err(error) = verify_network_commit_certificate(&block, Some(&quorum_certificate)) {
        warn!(
            "p2p",
            "Rejecting pending block without valid Aegis PQC quorum certificate",
            "height" => block.block_index,
            "hash" => block.hash.clone(),
            "error" => error
        );
        return;
    }

    let Ok(mut pending) = PENDING_BLOCKS.lock() else {
        return;
    };

    if pending.len() >= MAX_PENDING_BLOCK_HEIGHTS && !pending.contains_key(&block.block_index) {
        if let Some(oldest_height) = pending.keys().next().copied() {
            pending.remove(&oldest_height);
        }
    }

    let entry = pending.entry(block.block_index).or_default();
    if entry
        .iter()
        .any(|candidate| candidate.block.hash == block.hash)
    {
        return;
    }
    if entry.len() >= MAX_PENDING_BLOCKS_PER_HEIGHT {
        entry.remove(0);
    }
    entry.push(PendingCommittedBlock {
        block,
        quorum_certificate,
    });
}

fn take_pending_block_extending_tip(tip: &Block) -> Option<PendingCommittedBlock> {
    let Ok(mut pending) = PENDING_BLOCKS.lock() else {
        return None;
    };
    let next_height = tip.block_index.saturating_add(1);
    let entry = pending.get_mut(&next_height)?;
    let position = entry
        .iter()
        .position(|candidate| candidate.block.previous_hash == tip.hash)?;
    let pending_block = entry.remove(position);
    if entry.is_empty() {
        pending.remove(&next_height);
    }
    Some(pending_block)
}

fn apply_block_batch(
    blockchain: &BlockchainArc,
    mut blocks: Vec<Block>,
    quorum_certificates: Vec<QuorumCertificate>,
) -> u64 {
    if blocks.is_empty() {
        return 0;
    }

    blocks.sort_by_key(|block| block.block_index);
    blocks.dedup_by(|left, right| left.block_index == right.block_index && left.hash == right.hash);

    let qc_by_hash = quorum_certificates
        .into_iter()
        .map(|qc| (qc.block_hash.clone(), qc))
        .collect::<HashMap<_, _>>();

    let locally_matching_prefix = {
        let chain = blockchain.lock().unwrap();
        let local_tip_height = chain.last().map(|entry| entry.block_index).unwrap_or(0);
        blocks
            .iter()
            .filter(|block| {
                chain
                    .block_at_height(block.block_index)
                    .map(|local| local.hash == block.hash)
                    .unwrap_or_else(|| {
                        block.block_index <= local_tip_height
                            && block_matches_legacy_canonical_lock(block)
                    })
            })
            .map(|block| block.hash.clone())
            .collect::<HashSet<_>>()
    };

    for block in blocks
        .iter()
        .filter(|block| !locally_matching_prefix.contains(&block.hash))
    {
        if let Err(error) = verify_network_commit_certificate(block, qc_by_hash.get(&block.hash)) {
            warn!(
                "p2p",
                "Rejecting block batch without valid Aegis PQC quorum certificate",
                "height" => block.block_index,
                "hash" => block.hash.clone(),
                "error" => error
            );
            return 0;
        }
        if block.block_index > 0 {
            if let Err(error) = verify_legacy_canonical_lock(block) {
                record_canonical_lock_conflict_from_peer(blockchain, block, &error);
                warn!(
                    "p2p",
                    "Rejecting block batch that conflicts with canonical block lock",
                    "height" => block.block_index,
                    "hash" => block.hash.clone(),
                    "error" => error
                );
                return 0;
            }
        }
    }

    let mut confirmed_hashes = HashSet::new();
    for block in &blocks {
        confirmed_hashes.extend(transaction_hashes(&block.transactions));
    }

    let (applied, applied_blocks, rollback_height, tip_height, snapshot) = {
        let mut chain = blockchain.lock().unwrap();
        let local_tip_height = chain.last().map(|entry| entry.block_index).unwrap_or(0);
        let mut rollback_height = None;
        let mut applied_blocks = Vec::new();

        // Late duplicate sync responses should never rewind a chain that has already
        // advanced beyond the batch tip. Only consider rollback when the incoming batch
        // actually diverges from the local chain at its highest advertised height.
        if let Some(remote_tip) = blocks.last() {
            if remote_tip.block_index <= local_tip_height
                && chain
                    .block_at_height(remote_tip.block_index)
                    .map(|local| local.hash == remote_tip.hash)
                    .unwrap_or(false)
            {
                return 0;
            }
        }

        let highest_common_ancestor = blocks.iter().rev().find_map(|block| {
            if block.block_index > local_tip_height {
                return None;
            }
            chain
                .block_at_height(block.block_index)
                .filter(|local| local.hash == block.hash)
                .map(|_| block.block_index)
        });

        if let Some(common_height) = highest_common_ancestor {
            if common_height < local_tip_height {
                chain.truncate_to_height(common_height);
                rollback_height = Some(common_height);
            }
        }

        let mut applied = 0u64;
        for block in blocks.into_iter() {
            let Some(tip) = chain.last() else {
                break;
            };

            if block.block_index <= tip.block_index {
                continue;
            }

            if block.block_index != tip.block_index + 1 || block.previous_hash != tip.hash {
                break;
            }

            if block.block_index > 0 {
                if qc_by_hash.contains_key(&block.hash) {
                    if let Err(error) = append_committed_block_body(&block) {
                        warn!(
                            "p2p",
                            "Rejecting block batch because durable committed block body could not be written",
                            "height" => block.block_index,
                            "hash" => block.hash.clone(),
                            "error" => error
                        );
                        break;
                    }
                }
            }

            if chain.add_block_extending_tip(block.clone()).is_err() {
                warn!(
                    "p2p",
                    "Rejecting block batch entry because it could not be materialized on the local chain tip after durable body write",
                    "height" => block.block_index,
                    "hash" => block.hash.clone()
                );
                break;
            }
            if block.block_index > 0 {
                if let Some(qc) = qc_by_hash.get(&block.hash) {
                    if let Err(error) = DualQuorumConsensus::record_committed_qc_checked(qc.clone())
                    {
                        warn!(
                            "p2p",
                            "Rejecting block batch because durable committed QC could not be written",
                            "height" => block.block_index,
                            "hash" => block.hash.clone(),
                            "error" => error
                        );
                        break;
                    }
                    if let Err(error) = write_legacy_canonical_lock(&block, qc) {
                        record_canonical_lock_conflict_from_peer(blockchain, &block, &error);
                        warn!(
                            "p2p",
                            "Rejecting block batch because canonical lock could not be written",
                            "height" => block.block_index,
                            "hash" => block.hash.clone(),
                            "error" => error
                        );
                        break;
                    }
                }
            }
            applied_blocks.push(block.clone());
            applied += 1;
        }

        compact_hot_chain_state_from_env(&mut chain, "p2p_apply_block_batch");
        let tip_height = chain.last().map(|entry| entry.block_index).unwrap_or(0);
        let should_snapshot = rollback_height.is_some() || should_persist_chain_tip(tip_height);
        let snapshot = if should_snapshot {
            if rollback_height.is_some() {
                Some(chain.clone())
            } else {
                note_chain_persist(tip_height);
                if can_clone_chain_for_snapshot(tip_height) {
                    Some(chain.clone())
                } else {
                    None
                }
            }
        } else {
            None
        };

        (
            applied,
            applied_blocks,
            rollback_height,
            tip_height,
            snapshot,
        )
    };

    if let Some(common_height) = rollback_height {
        warn!(
            "p2p",
            "Rolled back divergent local tip to common ancestor",
            "common_height" => common_height,
            "new_tip_height" => tip_height
        );
    }

    if rollback_height.is_some() {
        if let Some(snapshot) = snapshot.as_ref() {
            crate::dag::rebuild_global_from_chain(snapshot);
        }
    } else {
        crate::dag::commit_blocks(&applied_blocks);
    }

    if let Some(snapshot) = snapshot {
        let chain_path = crate::utils::resolve_data_path("data/chain.json");
        persist_chain_snapshot_async(snapshot, chain_path, tip_height);
    }

    prune_transaction_hashes_from_pool(&confirmed_hashes);
    apply_token_state_for_blocks(&applied_blocks);

    applied
}

fn block_matches_legacy_canonical_lock(block: &Block) -> bool {
    legacy_canonical_commit_record(block.block_index)
        .ok()
        .flatten()
        .map(|record| record.block_hash == block.hash)
        .unwrap_or(false)
}

fn apply_token_state_for_blocks(blocks: &[Block]) {
    if blocks.is_empty() {
        return;
    }

    let token_manager = crate::token::TOKEN_MANAGER.clone();
    let validator_manager = VALIDATOR_MANAGER.clone();
    let mut applied_txs = 0u64;
    let mut failed_txs = 0u64;
    let mut applied_validator_activations = 0u64;

    for block in blocks {
        for tx in &block.transactions {
            match token_manager.process_transaction_in_block(tx, block.block_index) {
                Ok(_) => applied_txs += 1,
                Err(error) => {
                    failed_txs += 1;
                    warn!(
                        "p2p",
                        "Failed to apply synced block transaction state",
                        "block_height" => block.block_index,
                        "tx_hash" => tx.hash(),
                        "error" => error
                    );
                }
            }
            if is_validator_activation_transaction(tx) {
                match apply_validator_activation_transaction(
                    tx,
                    &token_manager,
                    &validator_manager,
                    block.block_index,
                ) {
                    Ok(message) => {
                        applied_validator_activations += 1;
                        info!(
                            "p2p",
                            "Applied synced validator activation",
                            "block_height" => block.block_index,
                            "tx_hash" => tx.hash(),
                            "message" => message
                        );
                    }
                    Err(error) => warn!(
                        "p2p",
                        "Failed to apply synced validator activation",
                        "block_height" => block.block_index,
                        "tx_hash" => tx.hash(),
                        "error" => error
                    ),
                }
            }
        }
        let activated_validators =
            validator_manager.apply_pending_shadow_activations(block.block_index);
        if !activated_validators.is_empty() {
            applied_validator_activations += activated_validators.len() as u64;
            info!(
                "p2p",
                "Activated shadow validators after synced finalized boundary",
                "block_height" => block.block_index,
                "activated_validators" => activated_validators.join(",")
            );
        }
    }

    if applied_txs > 0 || failed_txs > 0 {
        info!(
            "p2p",
            "Processed token state for synced blocks",
            "blocks" => blocks.len(),
            "applied_transactions" => applied_txs,
            "failed_transactions" => failed_txs
        );
    }

    if applied_txs > 0 {
        if let Err(error) = token_manager.save_state("data/token_state.json") {
            warn!(
                "p2p",
                "Failed to persist synced token state",
                "error" => error.to_string()
            );
        }
    }
    if applied_validator_activations > 0 {
        if let Err(error) = validator_manager.save_registry("data/validator_registry.json") {
            warn!(
                "p2p",
                "Failed to persist validator registry after synced activation",
                "error" => error.to_string()
            );
        }
    }
}

fn should_persist_chain_tip(tip_height: u64) -> bool {
    if tip_height <= 32 {
        return true;
    }

    let gap_blocks = chain_persist_gap_blocks();
    let elapsed_secs = chain_persist_elapsed_secs();
    let state = LAST_CHAIN_PERSIST.lock().unwrap();
    match *state {
        Some((last_height, last_at)) => {
            // Chain bodies are appended to the committed block log before locks/QCs.
            // Full chain snapshots are restart accelerators, not the hot durability path.
            let gap = tip_height.saturating_sub(last_height);
            let elapsed = last_at.elapsed();
            gap >= gap_blocks || elapsed >= Duration::from_secs(elapsed_secs)
        }
        None => tip_height % gap_blocks == 0,
    }
}

fn chain_persist_gap_blocks() -> u64 {
    std::env::var("SYNERGY_CHAIN_PERSIST_GAP_BLOCKS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(250)
}

fn chain_persist_elapsed_secs() -> u64 {
    std::env::var("SYNERGY_CHAIN_PERSIST_MIN_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(600)
}

fn chain_snapshot_max_clone_height() -> u64 {
    std::env::var("SYNERGY_CHAIN_SNAPSHOT_MAX_CLONE_HEIGHT")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_MAX_CHAIN_SNAPSHOT_CLONE_HEIGHT)
}

fn chain_snapshot_clone_allowed(tip_height: u64, max_clone_height: u64) -> bool {
    tip_height <= max_clone_height
}

fn can_clone_chain_for_snapshot(tip_height: u64) -> bool {
    let max_clone_height = chain_snapshot_max_clone_height();
    if chain_snapshot_clone_allowed(tip_height, max_clone_height) {
        return true;
    }

    warn!(
        "p2p",
        "Skipping full-chain snapshot persistence because chain height exceeds clone safety limit",
        "height" => tip_height,
        "max_clone_height" => max_clone_height,
        "override_env" => "SYNERGY_CHAIN_SNAPSHOT_MAX_CLONE_HEIGHT"
    );
    false
}

fn note_chain_persist(tip_height: u64) {
    let mut state = LAST_CHAIN_PERSIST.lock().unwrap();
    *state = Some((tip_height, Instant::now()));
}

fn persist_chain_snapshot_async(
    snapshot: BlockChain,
    chain_path: std::path::PathBuf,
    tip_height: u64,
) {
    if CHAIN_PERSIST_IN_FLIGHT
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        debug!(
            "p2p",
            "Skipping chain persistence because a previous save is still running",
            "height" => tip_height
        );
        return;
    }

    thread::spawn(move || {
        snapshot.save_to_file(chain_path.to_str().unwrap_or("data/chain.json"));
        CHAIN_PERSIST_IN_FLIGHT.store(false, Ordering::SeqCst);
    });
}

/// Best-effort dial for a discovered peer.
fn dial_peer_async(
    peer_address: String,
    blockchain: BlockchainArc,
    connected_peers: PeersArc,
    peer_state_cache: PeerStateCacheArc,
    dial_registry: DialRegistryArc,
    message_sender: mpsc::Sender<(String, NetworkMessage)>,
    config: NodeConfig,
) -> Result<(), ()> {
    if !reserve_outbound_dial(
        &dial_registry,
        &connected_peers,
        &peer_address,
        config.network.max_peers as usize,
    ) {
        return Ok(());
    }

    let cleanup_address = peer_address.clone();
    let cleanup_address_for_thread = cleanup_address.clone();
    let dial_registry_for_thread = Arc::clone(&dial_registry);
    let spawned = spawn_named_thread("p2p-discovery-dial", move || {
        match dial_with_timeout(&peer_address, std::time::Duration::from_secs(5)) {
            Ok(stream) => {
                if let Err(e) = handle_outgoing_connection(
                    stream,
                    peer_address,
                    blockchain,
                    connected_peers,
                    peer_state_cache,
                    message_sender,
                    config,
                ) {
                    warn!("p2p", "Discovered peer dial failed", "error" => e.to_string());
                }
            }
            Err(e) => {
                debug!("p2p", "Discovered peer dial error", "error" => e.to_string());
            }
        }
        release_outbound_dial(&dial_registry_for_thread, &cleanup_address_for_thread);
    });
    if !spawned {
        release_outbound_dial(&dial_registry, &cleanup_address);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        apply_block_batch, apply_block_if_new, background_poll_interval,
        best_connected_validator_height, block_sync_min_serve_interval_secs,
        block_sync_request_range, block_sync_request_range_with_overlap,
        block_sync_response_policy, build_local_handshake, build_local_status_message,
        bypasses_shared_message_queue, cache_peer_state, cache_pending_block,
        canonical_genesis_hash, canonical_validator_public_address, chain_has_block_sync_overlap,
        chain_snapshot_clone_allowed, collect_known_peer_addresses,
        configured_validator_public_address_map, connected_validator_participants,
        current_bootstrap_refresh_interval, current_timestamp, dial_with_timeout,
        disconnect_peer_after_poisoned_write, dispatch_peer_message,
        ensure_peer_status_allows_chain_data, handle_status_message, hydrate_peer_from_cache,
        local_node_runs_validator_consensus, local_peer_identity, merge_peer_state_from_existing,
        parse_bootnode_dial_address, peer_has_identifying_metadata, peer_identity_key,
        peer_is_eligible_block_sync_source, pending_incoming_connections_from_host,
        preferred_connection_direction, receive_message,
        recover_peer_validator_address_for_vote_target, resolve_bootstrap_dial_targets,
        resolve_duplicate_connection, select_block_sync_response_blocks,
        should_canonicalize_validator_public_address,
        should_disconnect_for_status_genesis_mismatch, should_prune_stale_peer,
        should_request_missing_blocks, status_ready_validator_addresses,
        status_ready_validator_addresses_with_local_duty_gate, status_ready_validator_participants,
        status_sync_batch,
        support_peer_sync_request_is_too_deep, validate_vote_request_extends_local_tip,
        validator_status_genesis_grace_remaining_secs,
        validator_status_genesis_within_grace_window, verify_handshake_pq_signature,
        vote_request_parent_sync_range, ConnectionDirection, DialTargetsArc, DuplicateResolution,
        PeerConnection, PeerEntryGuard, BACKGROUND_SYNC_POLL_MILLIS,
        BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS, DEFAULT_BOOTSTRAP_REFRESH_SECS,
        IMMEDIATE_STATUS_SYNC_BATCH, MAX_P2P_FRAME_BYTES, MAX_STATUS_SYNC_BATCH,
        MAX_SUPPORT_NODE_BLOCK_SYNC_RESPONSE_BLOCKS, MAX_VALIDATOR_SUPPORT_SYNC_RESPONSE_BLOCKS,
        NORMAL_BOOTSTRAP_REFRESH_SECS, PENDING_BLOCKS, STALE_UNIDENTIFIED_PEER_SECS,
        STALE_VALIDATOR_STATUS_SECS, SUPPORT_NODE_BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS,
        TEST_COMMIT_VERIFIER_VALIDATOR_MANAGER,
        VALIDATOR_SUPPORT_BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS,
    };
    use crate::block::{Block, BlockChain};
    use crate::config::NodeConfig;
    use crate::consensus::dual_quorum::{DualQuorumConsensus, QuorumCertificate, Vote};
    use crate::consensus::validator_keys::{
        consensus_algorithm_label, load_local_validator_keypair,
        register_test_validator_signing_key,
    };
    use crate::consensus::{
        anti_divergence::current_self_quarantine_record,
        legacy_canonical_lock::{
            clear_legacy_canonical_locks_for_tests, write_legacy_canonical_lock,
        },
    };
    use crate::crypto::pqc::{PQCAlgorithm, PQCManager, PQCSignature};
    use crate::p2p::messages::NetworkMessage;
    use crate::validator::{
        Validator, ValidatorManager, ValidatorRegistration, ValidatorStatus, VALIDATOR_MANAGER,
    };
    use base64::{engine::general_purpose, Engine as _};
    use lazy_static::lazy_static;
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::io;
    use std::net::TcpListener;
    use std::sync::{mpsc, Arc, Mutex, MutexGuard};
    use std::thread;
    use std::time::Duration;

    fn configure_canonical_genesis_path_for_tests() {
        std::env::set_var(
            "SYNERGY_GENESIS_FILE",
            concat!(env!("CARGO_MANIFEST_DIR"), "/../config/genesis.json"),
        );
    }

    #[test]
    fn p2p_snapshot_clone_guard_blocks_large_live_chains() {
        assert!(chain_snapshot_clone_allowed(50_000, 50_000));
        assert!(!chain_snapshot_clone_allowed(50_001, 50_000));
    }

    fn test_peer_with_validator_address(validator_address: Option<&str>) -> PeerConnection {
        PeerConnection {
            address: "peer-a".to_string(),
            direction: ConnectionDirection::Incoming,
            public_address: Some("peer-a.synergy-network.io:5622".to_string()),
            validator_address: validator_address.map(str::to_string),
            connected_at: 0,
            last_seen: 0,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            node_id: Some("peer-a".to_string()),
            version: Some("1.0.0".to_string()),
            capabilities: vec!["blocks".to_string()],
            last_known_height: 0,
            best_block_hash: String::new(),
            genesis_hash: canonical_genesis_hash(),
            status_received_at: Some(0),
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        }
    }

    #[test]
    fn status_ready_excludes_quarantined_and_duty_disabled_validators() {
        let mut config = NodeConfig::default();
        config.node.validator_address = "synv1local".to_string();
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));

        let mut healthy_peer = test_peer_with_validator_address(Some("synv1healthy"));
        healthy_peer.status_received_at = Some(current_timestamp());

        let mut quarantined_peer = test_peer_with_validator_address(Some("synv1quarantined"));
        quarantined_peer.address = "peer-quarantined".to_string();
        quarantined_peer.status_received_at = Some(current_timestamp());
        quarantined_peer.quarantined = true;
        quarantined_peer.consensus_duties_disabled = true;
        quarantined_peer.recovery_state = Some("OPERATOR_QUARANTINE".to_string());

        let mut shadow_peer = test_peer_with_validator_address(Some("synv1shadow"));
        shadow_peer.address = "peer-shadow".to_string();
        shadow_peer.status_received_at = Some(current_timestamp());
        shadow_peer.consensus_duties_disabled = true;
        shadow_peer.recovery_state = Some("SHADOW_OBSERVING".to_string());

        {
            let mut peers = connected_peers.lock().unwrap();
            peers.insert("peer-healthy".to_string(), healthy_peer);
            peers.insert("peer-quarantined".to_string(), quarantined_peer);
            peers.insert("peer-shadow".to_string(), shadow_peer);
        }

        let addresses =
            status_ready_validator_addresses_with_local_duty_gate(&config, &connected_peers, false);
        assert!(addresses.contains(&"synv1local".to_string()));
        assert!(addresses.contains(&"synv1healthy".to_string()));
        assert!(!addresses.contains(&"synv1quarantined".to_string()));
        assert!(!addresses.contains(&"synv1shadow".to_string()));

        let local_disabled =
            status_ready_validator_addresses_with_local_duty_gate(&config, &connected_peers, true);
        assert!(!local_disabled.contains(&"synv1local".to_string()));
        assert!(local_disabled.contains(&"synv1healthy".to_string()));
    }

    #[test]
    fn block_sync_source_accepts_duty_disabled_support_peer_but_not_shadow_validator() {
        let mut relayer_peer =
            test_peer_with_validator_address(Some("synv21ga3nsdjagzt9pmks4mzjq4vdjyngdwq6jst632"));
        relayer_peer.node_id = Some("sentry1".to_string());
        relayer_peer.consensus_duties_disabled = true;
        relayer_peer.last_known_height = 195_000;
        assert!(peer_is_eligible_block_sync_source(&relayer_peer));

        let mut shadow_validator = test_peer_with_validator_address(Some("synv1shadow"));
        shadow_validator.consensus_duties_disabled = true;
        shadow_validator.last_known_height = 195_000;
        assert!(!peer_is_eligible_block_sync_source(&shadow_validator));
    }

    lazy_static! {
        static ref TEST_VALIDATOR_KEY_LOCK: Mutex<()> = Mutex::new(());
        static ref TEST_BLOCK_APPLICATION_LOCK: Mutex<()> = Mutex::new(());
    }

    struct TestCommitVerifierGuard {
        previous: Option<Arc<ValidatorManager>>,
    }

    impl Drop for TestCommitVerifierGuard {
        fn drop(&mut self) {
            let previous = self.previous.take();
            TEST_COMMIT_VERIFIER_VALIDATOR_MANAGER.with(|slot| {
                *slot.borrow_mut() = previous;
            });
        }
    }

    struct BlockApplicationTestGuard {
        _block_guard: MutexGuard<'static, ()>,
        _vote_guard: MutexGuard<'static, ()>,
        _commit_verifier_guard: TestCommitVerifierGuard,
    }

    fn block_application_test_guard() -> BlockApplicationTestGuard {
        let block_guard = TEST_BLOCK_APPLICATION_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let vote_guard = DualQuorumConsensus::test_vote_tracking_guard();
        let commit_verifier = Arc::new(ValidatorManager::new());
        let previous =
            TEST_COMMIT_VERIFIER_VALIDATOR_MANAGER.with(|slot| slot.replace(Some(commit_verifier)));
        DualQuorumConsensus::reset_test_vote_tracking();
        PENDING_BLOCKS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        clear_legacy_canonical_locks_for_tests();
        BlockApplicationTestGuard {
            _block_guard: block_guard,
            _vote_guard: vote_guard,
            _commit_verifier_guard: TestCommitVerifierGuard { previous },
        }
    }

    fn current_test_commit_verifier_manager() -> Option<Arc<ValidatorManager>> {
        TEST_COMMIT_VERIFIER_VALIDATOR_MANAGER.with(|slot| slot.borrow().clone())
    }

    fn register_test_validator_in_manager(
        validator_manager: &Arc<ValidatorManager>,
        address: &str,
        public_key: &crate::crypto::pqc::PQCPublicKey,
    ) {
        let encoded_public_key = format!(
            "{}:{}",
            consensus_algorithm_label(&public_key.algorithm),
            general_purpose::STANDARD.encode(&public_key.key_data)
        );
        if let Ok(mut registry) = validator_manager.registry.lock() {
            let mut validator = Validator::new(
                address.to_string(),
                encoded_public_key,
                format!("Test validator {address}"),
                50_000_000_000_000,
            );
            validator.status = ValidatorStatus::Active;
            validator.synergy_score = 100.0;
            validator.activation_tx_hash = Some(format!("syntxn-test-{address}"));
            registry.validators.insert(address.to_string(), validator);
            registry.pending_registrations.remove(address);
        }
    }

    fn register_current_test_commit_verifier_validator(
        address: &str,
        public_key: &crate::crypto::pqc::PQCPublicKey,
    ) {
        if let Some(validator_manager) = current_test_commit_verifier_manager() {
            register_test_validator_in_manager(&validator_manager, address, public_key);
        }
    }

    fn sign_test_block(block: &mut Block) {
        let _guard = TEST_VALIDATOR_KEY_LOCK
            .lock()
            .expect("test validator key lock should succeed");
        ensure_test_validator_key_locked(&block.validator_id);
        let (public_key, private_key) =
            load_local_validator_keypair(&block.validator_id, &VALIDATOR_MANAGER)
                .expect("test validator signing key should load");
        let mut manager = PQCManager::new();
        let signature = manager
            .sign(&private_key, block.hash.as_bytes())
            .expect("test Aegis PQC block signature should sign");
        block.proposer_public_key = public_key.key_data;
        block.block_signature = signature.signature_data;
        block.block_signature_algorithm =
            consensus_algorithm_label(&public_key.algorithm).to_string();
    }

    fn signed_block(
        height: u64,
        transactions: Vec<crate::transaction::Transaction>,
        previous_hash: String,
        validator: String,
        nonce: u64,
        timestamp: u64,
    ) -> Block {
        let mut block = Block::new_with_timestamp(
            height,
            transactions,
            previous_hash,
            validator,
            nonce,
            timestamp,
        );
        sign_test_block(&mut block);
        block
    }

    fn ensure_test_validator_key(address: &str) {
        let _guard = TEST_VALIDATOR_KEY_LOCK
            .lock()
            .expect("test validator key lock should succeed");
        ensure_test_validator_key_locked(address);
    }

    fn ensure_test_validator_key_locked(address: &str) {
        if let Ok((public_key, _)) = load_local_validator_keypair(address, &VALIDATOR_MANAGER) {
            VALIDATOR_MANAGER.update_synergy_score(address, 100.0);
            register_current_test_commit_verifier_validator(address, &public_key);
            return;
        }

        let mut manager = PQCManager::new();
        let (public_key, private_key) = manager
            .generate_keypair(PQCAlgorithm::FNDSA)
            .expect("test Aegis PQC validator key should generate");
        register_test_validator_signing_key(address, public_key.clone(), private_key);
        let encoded_public_key = format!(
            "{}:{}",
            consensus_algorithm_label(&public_key.algorithm),
            general_purpose::STANDARD.encode(&public_key.key_data)
        );

        if let Ok(mut registry) = VALIDATOR_MANAGER.registry.lock() {
            let mut validator = Validator::new(
                address.to_string(),
                encoded_public_key.clone(),
                format!("Test validator {address}"),
                50_000_000_000_000,
            );
            validator.status = ValidatorStatus::Active;
            validator.synergy_score = 100.0;
            validator.activation_tx_hash = Some(format!("syntxn-test-{address}"));
            registry.validators.insert(address.to_string(), validator);
            registry.pending_registrations.remove(address);
        } else if VALIDATOR_MANAGER.get_validator(address).is_none() {
            let _ = VALIDATOR_MANAGER.register_validator(ValidatorRegistration {
                address: address.to_string(),
                public_key: encoded_public_key,
                name: format!("Test validator {address}"),
                stake_amount: 50_000_000_000_000,
                submitted_at: 0,
                registration_tx_hash: format!("test-registration-{address}"),
            });
            let _ = VALIDATOR_MANAGER.approve_validator(address);
        }
        VALIDATOR_MANAGER.update_synergy_score(address, 100.0);
        register_current_test_commit_verifier_validator(address, &public_key);
    }

    fn ensure_test_qc_validators(addresses: &[&str]) {
        for address in addresses {
            ensure_test_validator_key_locked(address);
        }
    }

    fn test_quorum_certificate(block: &Block) -> QuorumCertificate {
        let _guard = TEST_VALIDATOR_KEY_LOCK
            .lock()
            .expect("test validator key lock should succeed");
        let signers = ["synv1qc01", "synv1qc02", "synv1qc03", "synv1qc04"];
        ensure_test_validator_key_locked(&block.validator_id);
        ensure_test_qc_validators(&signers);
        let validator_manager =
            current_test_commit_verifier_manager().unwrap_or_else(|| VALIDATOR_MANAGER.clone());
        let active_before_signing = validator_manager
            .get_active_validators()
            .into_iter()
            .map(|validator| validator.address)
            .collect::<Vec<_>>();
        for address in active_before_signing {
            ensure_test_validator_key_locked(&address);
        }
        let mut signer_addresses = validator_manager
            .get_active_validators()
            .into_iter()
            .map(|validator| validator.address)
            .collect::<Vec<_>>();
        signer_addresses.sort();
        let votes = signer_addresses
            .iter()
            .map(|validator| {
                DualQuorumConsensus::create_vote_for_validator_with_manager(
                    validator,
                    block,
                    0,
                    1,
                    &validator_manager,
                )
                .expect("test vote should sign")
            })
            .collect::<Vec<_>>();
        QuorumCertificate {
            block_hash: block.hash.clone(),
            epoch_number: 0,
            round_number: 1,
            aggregate_signature: vec![42],
            participant_bitmap: vec![0x0f],
            cumulative_weight: votes.len() as f64,
            validation_quorum_met: true,
            cooperation_quorum_met: true,
            timestamp: block.timestamp,
            votes,
        }
    }

    #[test]
    fn dial_with_timeout_keeps_established_peer_streams_blocking() {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to bind test listener: {error}"),
        };
        let addr = listener.local_addr().unwrap();

        let accept_handle = thread::spawn(move || {
            let _ = listener.accept().unwrap();
        });

        let stream = match dial_with_timeout(&addr.to_string(), Duration::from_millis(250)) {
            Ok(stream) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                // The local desktop sandbox can deny loopback dials in tests even
                // though the runtime code path is valid on normal hosts.
                accept_handle.join().unwrap();
                return;
            }
            Err(error) => panic!("dial_with_timeout failed: {error}"),
        };

        assert_eq!(stream.read_timeout().unwrap(), None);
        assert_eq!(stream.write_timeout().unwrap(), None);

        accept_handle.join().unwrap();
    }

    #[test]
    fn lower_node_id_prefers_outgoing_connection() {
        assert_eq!(
            preferred_connection_direction("node-01", "node-02"),
            Some(ConnectionDirection::Outgoing)
        );
    }

    #[test]
    fn higher_node_id_prefers_incoming_connection() {
        assert_eq!(
            preferred_connection_direction("node-02", "node-01"),
            Some(ConnectionDirection::Incoming)
        );
    }

    #[test]
    fn peer_identity_key_prefers_validator_address_over_node_id() {
        assert_eq!(
            peer_identity_key("testnet-random-node-id", Some("synv1validator")),
            "validator:synv1validator".to_string()
        );
        assert_eq!(
            peer_identity_key("testnet-random-node-id", None),
            "node:testnet-random-node-id".to_string()
        );
    }

    #[test]
    fn local_peer_identity_uses_same_validator_namespace_as_remote_peers() {
        let mut config = NodeConfig::default();
        config.node.bootstrap_only = false;
        config.node.validator_address = "synv1local".to_string();
        config.p2p.node_name = "testnet-local".to_string();

        assert_eq!(
            local_peer_identity(&config),
            "validator:synv1local".to_string()
        );
    }

    #[test]
    fn signed_aegis_pqc_handshake_verifies() {
        configure_canonical_genesis_path_for_tests();
        let mut config = NodeConfig::default();
        config.p2p.node_name = "genesisval1".to_string();
        config.node.validator_address = "synv1local".to_string();

        let handshake = build_local_handshake(&config).expect("handshake should sign");

        verify_handshake_pq_signature(&handshake).expect("handshake signature should verify");
    }

    #[test]
    fn missing_aegis_pqc_handshake_signature_is_rejected() {
        configure_canonical_genesis_path_for_tests();
        let mut config = NodeConfig::default();
        config.p2p.node_name = "genesisval1".to_string();
        let mut handshake = build_local_handshake(&config).expect("handshake should sign");
        if let NetworkMessage::Handshake {
            aegis_pq_handshake_signature,
            ..
        } = &mut handshake
        {
            *aegis_pq_handshake_signature = None;
        }

        let err = verify_handshake_pq_signature(&handshake)
            .expect_err("missing signature must fail closed");

        assert!(err.contains("missing Aegis PQC peer handshake signature"));
    }

    #[test]
    fn altered_aegis_pqc_handshake_signature_is_rejected() {
        configure_canonical_genesis_path_for_tests();
        let mut config = NodeConfig::default();
        config.p2p.node_name = "genesisval1".to_string();
        let mut handshake = build_local_handshake(&config).expect("handshake should sign");
        if let NetworkMessage::Handshake {
            aegis_pq_handshake_signature: Some(signature),
            ..
        } = &mut handshake
        {
            signature.signature_bytes[0] ^= 0x01;
        }

        let err = verify_handshake_pq_signature(&handshake)
            .expect_err("altered signature must fail closed");

        assert!(err.contains("Aegis PQC peer handshake verification failed"));
    }

    #[test]
    fn handshake_without_testnet_network_name_is_rejected() {
        configure_canonical_genesis_path_for_tests();
        let mut config = NodeConfig::default();
        config.p2p.node_name = "genesisval1".to_string();
        let mut handshake = build_local_handshake(&config).expect("handshake should sign");
        if let NetworkMessage::Handshake {
            network_id_text, ..
        } = &mut handshake
        {
            *network_id_text = None;
        }

        let err = verify_handshake_pq_signature(&handshake)
            .expect_err("missing network name must fail closed");

        assert!(err.contains("network_id synergy-testnet-v2"));
    }

    #[test]
    fn duplicate_resolution_keeps_preferred_existing_connection() {
        assert_eq!(
            resolve_duplicate_connection(
                "node-01",
                "node-02",
                ConnectionDirection::Outgoing,
                10,
                ConnectionDirection::Incoming,
                20,
            ),
            DuplicateResolution::KeepExisting
        );
    }

    #[test]
    fn duplicate_resolution_replaces_non_preferred_existing_connection() {
        assert_eq!(
            resolve_duplicate_connection(
                "node-01",
                "node-02",
                ConnectionDirection::Incoming,
                10,
                ConnectionDirection::Outgoing,
                20,
            ),
            DuplicateResolution::ReplaceExisting
        );
    }

    #[test]
    fn validator_duplicate_resolution_prefers_opposite_directions_on_each_side() {
        let local_a = "validator:synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs";
        let local_b = "validator:synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt";

        let decision_a = resolve_duplicate_connection(
            local_a,
            local_b,
            ConnectionDirection::Outgoing,
            10,
            ConnectionDirection::Incoming,
            20,
        );
        let decision_b = resolve_duplicate_connection(
            local_b,
            local_a,
            ConnectionDirection::Outgoing,
            10,
            ConnectionDirection::Incoming,
            20,
        );

        assert_eq!(decision_a, DuplicateResolution::KeepExisting);
        assert_eq!(decision_b, DuplicateResolution::ReplaceExisting);
    }

    #[test]
    fn reconnect_hydration_preserves_remote_status_for_same_validator_identity() {
        let cache = Arc::new(Mutex::new(HashMap::new()));
        let existing = PeerConnection {
            address: "62.146.182.208:5622".to_string(),
            direction: ConnectionDirection::Outgoing,
            public_address: Some("62.146.182.208:5622".to_string()),
            validator_address: Some("synv1peer-b".to_string()),
            connected_at: 10,
            last_seen: 20,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            node_id: Some("testnet-peer-b".to_string()),
            version: Some("1.0.0".to_string()),
            capabilities: vec!["blocks".to_string()],
            last_known_height: 42,
            best_block_hash: "block-hash".to_string(),
            genesis_hash: "genesis-hash".to_string(),
            status_received_at: Some(21),
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        };
        cache_peer_state(&cache, &existing);

        let mut replacement = PeerConnection {
            address: "62.146.182.208:64347".to_string(),
            direction: ConnectionDirection::Incoming,
            public_address: Some("62.146.182.208:5622".to_string()),
            validator_address: Some("synv1peer-b".to_string()),
            connected_at: 30,
            last_seen: 30,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            node_id: Some("testnet-peer-b".to_string()),
            version: Some("1.0.0".to_string()),
            capabilities: vec!["blocks".to_string()],
            last_known_height: 0,
            best_block_hash: String::new(),
            genesis_hash: String::new(),
            status_received_at: None,
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        };

        let peer_identity = peer_identity_key("testnet-peer-b", Some("synv1peer-b"));
        hydrate_peer_from_cache(&cache, &peer_identity, &mut replacement);

        assert_eq!(replacement.last_known_height, 42);
        assert_eq!(replacement.best_block_hash, "block-hash".to_string());
        assert_eq!(replacement.genesis_hash, "genesis-hash".to_string());
        assert_eq!(replacement.status_received_at, Some(21));
    }

    #[test]
    fn replacement_session_inherits_existing_remote_status() {
        let existing = PeerConnection {
            address: "62.146.182.208:5622".to_string(),
            direction: ConnectionDirection::Outgoing,
            public_address: Some("62.146.182.208:5622".to_string()),
            validator_address: Some("synv1peer-a".to_string()),
            connected_at: 10,
            last_seen: 15,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            node_id: Some("testnet-peer-a".to_string()),
            version: Some("1.0.0".to_string()),
            capabilities: vec!["blocks".to_string()],
            last_known_height: 9,
            best_block_hash: "hash-9".to_string(),
            genesis_hash: "genesis-hash".to_string(),
            status_received_at: Some(16),
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        };
        let mut replacement = PeerConnection {
            address: "62.146.182.208:56733".to_string(),
            direction: ConnectionDirection::Incoming,
            public_address: None,
            validator_address: Some("synv1peer-a".to_string()),
            connected_at: 20,
            last_seen: 20,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            node_id: Some("testnet-peer-a".to_string()),
            version: None,
            capabilities: Vec::new(),
            last_known_height: 0,
            best_block_hash: String::new(),
            genesis_hash: String::new(),
            status_received_at: None,
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        };

        merge_peer_state_from_existing(&existing, &mut replacement);

        assert_eq!(replacement.last_known_height, 9);
        assert_eq!(replacement.genesis_hash, "genesis-hash".to_string());
        assert_eq!(replacement.status_received_at, Some(16));
        assert_eq!(
            replacement.public_address,
            Some("62.146.182.208:5622".to_string())
        );
    }

    #[test]
    fn parse_bootnode_dial_address_normalizes_identity_and_ipv6() {
        assert_eq!(
            parse_bootnode_dial_address("snr://peer@74.208.227.23:5620"),
            Some("74.208.227.23:5620".to_string())
        );
        assert_eq!(
            parse_bootnode_dial_address(
                "snr://synv1156xl3ct9cxc4cl9pdn5ww9myxudavl0hxrq7zv@2a02:1812:172a:e900:1497:71dc:d720:e28e:5620",
            ),
            Some("[2a02:1812:172a:e900:1497:71dc:d720:e28e]:5620".to_string())
        );
    }

    #[test]
    fn parse_bootnode_dial_address_rejects_invalid_bare_host_targets() {
        assert_eq!(parse_bootnode_dial_address("snr://peer@test:5620"), None);
        assert_eq!(parse_bootnode_dial_address(""), None);
    }

    #[test]
    fn canonical_validator_public_address_preserves_public_history_gateway_port() {
        assert_eq!(
            canonical_validator_public_address("167.86.83.83:5623", Some("167.86.83.83:5622")),
            Some("167.86.83.83:5623".to_string())
        );
        assert_eq!(
            canonical_validator_public_address(
                "archive.synergynode.xyz:5615",
                Some("archive.synergynode.xyz:5615")
            ),
            Some("archive.synergynode.xyz:5615".to_string())
        );
        assert_eq!(
            canonical_validator_public_address("73.79.66.255:5615", Some("73.79.66.255:5615")),
            Some("73.79.66.255:5615".to_string())
        );
        assert_eq!(
            canonical_validator_public_address("94.72.117.108:62422", Some("94.72.117.108:5622")),
            Some("94.72.117.108:5622".to_string())
        );
    }

    #[test]
    fn validator_public_address_canonicalization_requires_synv_identity() {
        assert!(should_canonicalize_validator_public_address(Some(
            "synv11validatorxxxxxxxxxxxxxxxxxxxx"
        )));
        assert!(!should_canonicalize_validator_public_address(Some(
            "archive-validator-01"
        )));
        assert!(!should_canonicalize_validator_public_address(Some(
            "rpc-gateway-01"
        )));
        assert!(!should_canonicalize_validator_public_address(None));
    }

    #[test]
    fn collect_known_peer_addresses_includes_assigned_synergy_targets() {
        let mut config = NodeConfig::default();
        config.p2p.public_address = "genesisval1.synergy-network.io:5622".to_string();
        config.network.additional_dial_targets =
            vec!["genesisval2.synergy-network.io:5622".to_string()];
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let discovered_targets: DialTargetsArc = Arc::new(Mutex::new(vec![
            "genesisval3.synergy-network.io:5622".to_string(),
        ]));

        let addresses =
            collect_known_peer_addresses(&connected_peers, &discovered_targets, &config);

        assert!(addresses.contains(&"genesisval1.synergy-network.io:5622".to_string()));
        assert!(addresses.contains(&"genesisval2.synergy-network.io:5622".to_string()));
        assert!(addresses.contains(&"genesisval3.synergy-network.io:5622".to_string()));
    }

    #[test]
    fn vote_target_identity_recovers_from_configured_validator_public_address() {
        let validators = vec![
            "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs".to_string(),
            "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt".to_string(),
            "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re".to_string(),
            "synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5".to_string(),
            "synv11kguave5fpdpm9hru4acfvw0hcp4fcc7zv9f".to_string(),
            "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx".to_string(),
        ];
        let active_validator_addresses = validators.iter().cloned().collect::<HashSet<_>>();
        let mut config = NodeConfig::default();
        config.node.allowed_validator_addresses = validators.clone();
        config.network.persistent_peers = vec![
            "relay1.synergynode.xyz:5622".to_string(),
            "relay2.synergynode.xyz:5622".to_string(),
            "rpc.synergynode.xyz:5623".to_string(),
            "archive.synergynode.xyz:5615".to_string(),
            "62.146.182.207:5622".to_string(),
            "62.146.182.208:5622".to_string(),
            "62.146.182.209:5622".to_string(),
            "73.79.66.255:5622".to_string(),
            "194.163.183.166:5622".to_string(),
            "157.173.192.45:5622".to_string(),
        ];

        let address_map =
            configured_validator_public_address_map(&config, &active_validator_addresses);

        assert_eq!(
            address_map.get("62.146.182.209:5622"),
            Some(&"synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re".to_string())
        );

        let peer = PeerConnection {
            address: "62.146.182.209:5622".to_string(),
            direction: ConnectionDirection::Outgoing,
            public_address: None,
            validator_address: None,
            connected_at: 0,
            last_seen: 0,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            node_id: None,
            version: None,
            capabilities: Vec::new(),
            last_known_height: 0,
            best_block_hash: String::new(),
            genesis_hash: String::new(),
            status_received_at: None,
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        };

        assert_eq!(
            recover_peer_validator_address_for_vote_target(
                &config,
                &peer,
                &active_validator_addresses,
            ),
            Some("synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re".to_string())
        );
    }

    #[test]
    fn vote_target_identity_maps_validator_dials_excluding_local_validator() {
        let validators = vec![
            "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs".to_string(),
            "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt".to_string(),
            "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re".to_string(),
            "synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5".to_string(),
            "synv11kguave5fpdpm9hru4acfvw0hcp4fcc7zv9f".to_string(),
            "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx".to_string(),
        ];
        let active_validator_addresses = validators.iter().cloned().collect::<HashSet<_>>();
        let mut config = NodeConfig::default();
        config.node.allowed_validator_addresses = validators;
        config.node.validator_address =
            "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re".to_string();
        config.p2p.public_address = "62.146.182.209:5622".to_string();
        config.network.persistent_peers = vec![
            "62.146.182.207:5622".to_string(),
            "62.146.182.208:5622".to_string(),
            "73.79.66.255:5622".to_string(),
            "194.163.183.166:5622".to_string(),
            "157.173.192.45:5622".to_string(),
            "relay1.synergynode.xyz:5622".to_string(),
            "relay2.synergynode.xyz:5622".to_string(),
        ];

        let address_map =
            configured_validator_public_address_map(&config, &active_validator_addresses);

        assert_eq!(
            address_map.get("62.146.182.207:5622"),
            Some(&"synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs".to_string())
        );
        assert_eq!(
            address_map.get("62.146.182.208:5622"),
            Some(&"synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt".to_string())
        );
        assert_eq!(
            address_map.get("73.79.66.255:5622"),
            Some(&"synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5".to_string())
        );
        assert_eq!(
            address_map.get("194.163.183.166:5622"),
            Some(&"synv11kguave5fpdpm9hru4acfvw0hcp4fcc7zv9f".to_string())
        );
        assert_eq!(
            address_map.get("157.173.192.45:5622"),
            Some(&"synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx".to_string())
        );
        assert!(!address_map.contains_key("62.146.182.209:5622"));

        let peer = PeerConnection {
            address: "73.79.66.255:5622".to_string(),
            direction: ConnectionDirection::Outgoing,
            public_address: None,
            validator_address: None,
            connected_at: 0,
            last_seen: 0,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            node_id: None,
            version: None,
            capabilities: Vec::new(),
            last_known_height: 0,
            best_block_hash: String::new(),
            genesis_hash: String::new(),
            status_received_at: None,
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        };

        assert_eq!(
            recover_peer_validator_address_for_vote_target(
                &config,
                &peer,
                &active_validator_addresses,
            ),
            Some("synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5".to_string())
        );
    }

    #[test]
    fn vote_target_identity_recovers_from_genesis_validator_node_id() {
        configure_canonical_genesis_path_for_tests();
        let validator =
            "synv11kguave5fpdpm9hru4acfvw0hcp4fcc7zv9f".to_string();
        let active_validator_addresses = [validator.clone()].into_iter().collect::<HashSet<_>>();
        let config = NodeConfig::default();
        let peer = PeerConnection {
            address: "194.163.183.166:53988".to_string(),
            direction: ConnectionDirection::Incoming,
            public_address: None,
            validator_address: None,
            connected_at: 0,
            last_seen: 0,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            node_id: Some("genesisval5".to_string()),
            version: None,
            capabilities: Vec::new(),
            last_known_height: 0,
            best_block_hash: String::new(),
            genesis_hash: String::new(),
            status_received_at: None,
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        };

        assert_eq!(
            recover_peer_validator_address_for_vote_target(
                &config,
                &peer,
                &active_validator_addresses,
            ),
            Some(validator)
        );
    }

    #[test]
    fn resolve_bootstrap_dial_targets_includes_persistent_peers() {
        let mut config = NodeConfig::default();
        config.node.validator_address = "synv1validator1".to_string();
        config.p2p.public_address = "genesisval1.synergy-network.io:5622".to_string();
        config.p2p.listen_address = "0.0.0.0:5622".to_string();
        config.network.persistent_peers = vec![
            "genesisval2.synergy-network.io:5622".to_string(),
            "62.146.182.208:5622".to_string(),
        ];

        let targets = resolve_bootstrap_dial_targets(&config);

        assert!(targets.contains(&"genesisval2.synergy-network.io:5622".to_string()));
        assert!(targets.contains(&"62.146.182.208:5622".to_string()));
    }

    #[test]
    fn resolve_bootstrap_dial_targets_excludes_self_genesis_alias_but_keeps_other_validators() {
        let temp = std::env::temp_dir().join(format!(
            "synergy-networking-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be monotonic")
                .as_nanos()
        ));
        fs::create_dir_all(&temp).expect("temp dir");
        let workspace = temp.join("validator-workspace");
        let config_dir = workspace.join("config");
        let data_dir = workspace.join("data");
        fs::create_dir_all(&config_dir).expect("config dir");
        fs::create_dir_all(&data_dir).expect("data dir");

        fs::write(
            config_dir.join("operational-manifest.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "validators": [
                    {"address": "synv1validator1", "slot": 1},
                    {"address": "synv1validator5", "slot": 5}
                ]
            }))
            .expect("manifest should serialize"),
        )
        .expect("manifest should write");

        let mut config = NodeConfig::default();
        config.storage.path = data_dir.to_string_lossy().to_string();
        config.network.p2p_port = 5622;
        config.p2p.public_address = "62.146.182.207:5622".to_string();
        config.p2p.listen_address = "0.0.0.0:5622".to_string();
        config.node.validator_address = "synv1validator1".to_string();
        config.network.additional_dial_targets = vec![
            "genesisval1.synergy-network.io:5622".to_string(),
            "genesisval5.synergy-network.io:5622".to_string(),
        ];

        let targets = resolve_bootstrap_dial_targets(&config);

        assert!(!targets.contains(&"genesisval1.synergy-network.io:5622".to_string()));
        assert!(targets.contains(&"genesisval5.synergy-network.io:5622".to_string()));

        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn collect_known_peer_addresses_excludes_unassigned_outgoing_ip_targets() {
        let config = NodeConfig::default();
        let mut peers = HashMap::new();
        peers.insert(
            "incoming".to_string(),
            PeerConnection {
                address: "62.146.182.209:54792".to_string(),
                direction: ConnectionDirection::Incoming,
                public_address: None,
                validator_address: Some("synv1incoming".to_string()),
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                node_id: Some("testnet-incoming".to_string()),
                version: None,
                capabilities: Vec::new(),
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        peers.insert(
            "outgoing".to_string(),
            PeerConnection {
                address: "62.146.182.209:5622".to_string(),
                direction: ConnectionDirection::Outgoing,
                public_address: Some("genesisval3.synergy-network.io:5622".to_string()),
                validator_address: Some("synv1outgoing".to_string()),
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                node_id: Some("testnet-outgoing".to_string()),
                version: None,
                capabilities: Vec::new(),
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        let connected_peers = Arc::new(Mutex::new(peers));
        let discovered_targets: DialTargetsArc = Arc::new(Mutex::new(Vec::new()));

        let addresses =
            collect_known_peer_addresses(&connected_peers, &discovered_targets, &config);

        assert!(!addresses.contains(&"62.146.182.209:54792".to_string()));
        assert!(!addresses.contains(&"62.146.182.209:5622".to_string()));
        assert!(addresses.contains(&"genesisval3.synergy-network.io:5622".to_string()));
    }

    #[test]
    fn peer_has_identifying_metadata_requires_announced_identity_fields() {
        let unidentified = PeerConnection {
            address: "62.146.182.208:54001".to_string(),
            direction: ConnectionDirection::Incoming,
            public_address: None,
            validator_address: None,
            connected_at: 0,
            last_seen: 0,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            node_id: None,
            version: None,
            capabilities: Vec::new(),
            last_known_height: 0,
            best_block_hash: String::new(),
            genesis_hash: String::new(),
            status_received_at: None,
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        };
        let identified = PeerConnection {
            address: "62.146.182.208:5622".to_string(),
            direction: ConnectionDirection::Incoming,
            public_address: Some("genesisval2.synergy-network.io:5622".to_string()),
            validator_address: Some("synv1peer-a".to_string()),
            connected_at: 0,
            last_seen: 0,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            node_id: Some("testnet-peer-a".to_string()),
            version: None,
            capabilities: Vec::new(),
            last_known_height: 0,
            best_block_hash: String::new(),
            genesis_hash: String::new(),
            status_received_at: None,
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        };

        assert!(!peer_has_identifying_metadata(&unidentified));
        assert!(peer_has_identifying_metadata(&identified));
    }

    #[test]
    fn pending_incoming_connection_limit_ignores_identified_peers_from_same_host() {
        let mut peers = HashMap::new();
        peers.insert(
            "bootnode2".to_string(),
            PeerConnection {
                address: "62.146.182.208:5620".to_string(),
                direction: ConnectionDirection::Incoming,
                public_address: Some("bootnode2.synergy-network.io:5620".to_string()),
                validator_address: None,
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                node_id: Some("bootnode2".to_string()),
                version: Some("1.0.0".to_string()),
                capabilities: Vec::new(),
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        peers.insert(
            "validator2-stable".to_string(),
            PeerConnection {
                address: "62.146.182.208:5622".to_string(),
                direction: ConnectionDirection::Incoming,
                public_address: Some("genesisval2.synergy-network.io:5622".to_string()),
                validator_address: Some("synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt".to_string()),
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                node_id: Some("genesisval2".to_string()),
                version: Some("1.0.0".to_string()),
                capabilities: Vec::new(),
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        peers.insert(
            "validator2-reconnect".to_string(),
            PeerConnection {
                address: "62.146.182.208:54001".to_string(),
                direction: ConnectionDirection::Incoming,
                public_address: None,
                validator_address: None,
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                node_id: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );

        assert_eq!(
            pending_incoming_connections_from_host(&peers, "62.146.182.208"),
            1
        );
    }

    #[test]
    fn peer_entry_guard_removes_pending_peer_on_drop() {
        let peer_address = "62.146.182.208:54001".to_string();
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        connected_peers.lock().unwrap().insert(
            peer_address.clone(),
            PeerConnection {
                address: peer_address.clone(),
                direction: ConnectionDirection::Incoming,
                public_address: None,
                validator_address: None,
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                node_id: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));

        {
            let _guard = PeerEntryGuard::new(
                peer_address.clone(),
                Arc::clone(&connected_peers),
                Arc::clone(&peer_state_cache),
            );
        }

        assert!(!connected_peers.lock().unwrap().contains_key(&peer_address));
    }

    #[test]
    fn empty_remote_genesis_hash_is_allowed_for_discovery_peer() {
        assert!(!should_disconnect_for_status_genesis_mismatch(
            "local-hash",
            "",
            None,
        ));
    }

    #[test]
    fn empty_remote_genesis_hash_disconnects_validator_peer() {
        assert!(should_disconnect_for_status_genesis_mismatch(
            "local-hash",
            "",
            Some("synv1validator"),
        ));
    }

    #[test]
    fn mismatched_nonempty_remote_genesis_hash_disconnects_peer() {
        assert!(should_disconnect_for_status_genesis_mismatch(
            "local-hash",
            "remote-hash",
            None,
        ));
    }

    #[test]
    fn matching_remote_genesis_hash_is_allowed_for_validator_peer() {
        assert!(!should_disconnect_for_status_genesis_mismatch(
            "local-hash",
            "local-hash",
            Some("synv1validator"),
        ));
    }

    #[test]
    fn local_status_uses_canonical_genesis_for_compact_chain() {
        configure_canonical_genesis_path_for_tests();
        let canonical_hash = canonical_genesis_hash();
        assert!(!canonical_hash.is_empty());

        let mut chain = BlockChain::new();
        let mut retained = Block::new_with_timestamp(
            123,
            Vec::new(),
            "retained-parent".to_string(),
            "validator".to_string(),
            0,
            1,
        );
        retained.hash = "retained-block-hash".to_string();
        chain.chain.push(retained);

        let blockchain = Arc::new(Mutex::new(chain));
        let config = NodeConfig::default();
        let status = build_local_status_message(&blockchain, &config);

        let NetworkMessage::Status {
            block_height,
            best_block_hash,
            genesis_hash,
            ..
        } = status
        else {
            panic!("local status should build a status message");
        };

        assert_eq!(block_height, 123);
        assert_eq!(best_block_hash, "retained-block-hash");
        assert_eq!(genesis_hash, canonical_hash);
    }

    #[test]
    fn chain_data_is_rejected_until_peer_status_confirms_genesis() {
        configure_canonical_genesis_path_for_tests();
        let mut chain = BlockChain::new();
        chain.genesis().expect("genesis block should load");
        let blockchain = Arc::new(Mutex::new(chain));
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));

        connected_peers.lock().unwrap().insert(
            "peer-pending".to_string(),
            PeerConnection {
                address: "peer-pending".to_string(),
                direction: ConnectionDirection::Incoming,
                public_address: None,
                validator_address: None,
                connected_at: current_timestamp(),
                last_seen: current_timestamp(),
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                node_id: Some("validator-pending".to_string()),
                version: Some("1.0.0".to_string()),
                capabilities: Vec::new(),
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );

        assert!(!ensure_peer_status_allows_chain_data(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            "peer-pending",
            "blocks",
        ));
        assert!(connected_peers.lock().unwrap().contains_key("peer-pending"));
    }

    #[test]
    fn chain_data_disconnects_peer_with_mismatched_genesis() {
        configure_canonical_genesis_path_for_tests();
        let mut chain = BlockChain::new();
        chain.genesis().expect("genesis block should load");
        let blockchain = Arc::new(Mutex::new(chain));
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));

        connected_peers.lock().unwrap().insert(
            "peer-mismatch".to_string(),
            PeerConnection {
                address: "peer-mismatch".to_string(),
                direction: ConnectionDirection::Incoming,
                public_address: None,
                validator_address: Some("synv1validator".to_string()),
                connected_at: current_timestamp(),
                last_seen: current_timestamp(),
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                node_id: Some("validator-mismatch".to_string()),
                version: Some("1.0.0".to_string()),
                capabilities: Vec::new(),
                last_known_height: 10,
                best_block_hash: "remote-tip".to_string(),
                genesis_hash: "remote-hash".to_string(),
                status_received_at: Some(current_timestamp()),
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );

        assert!(!ensure_peer_status_allows_chain_data(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            "peer-mismatch",
            "block",
        ));
        assert!(!connected_peers
            .lock()
            .unwrap()
            .contains_key("peer-mismatch"));
    }

    #[test]
    fn empty_local_genesis_hash_does_not_force_disconnect() {
        assert!(!should_disconnect_for_status_genesis_mismatch(
            "",
            "remote-hash",
            Some("synv1validator"),
        ));
    }

    #[test]
    fn status_sync_batch_only_requests_blocks_for_ahead_peer() {
        assert_eq!(status_sync_batch(10, 10), None);
        assert_eq!(status_sync_batch(11, 10), Some(IMMEDIATE_STATUS_SYNC_BATCH));
        assert_eq!(status_sync_batch(2_500, 1_000), Some(MAX_STATUS_SYNC_BATCH));
        assert_eq!(status_sync_batch(7_000, 1_000), Some(MAX_STATUS_SYNC_BATCH));
    }

    #[test]
    fn block_sync_request_range_includes_reconciliation_overlap() {
        assert_eq!(block_sync_request_range(10, 10, 500), None);
        assert_eq!(block_sync_request_range(0, 12, 500), Some((0, 13)));
        assert_eq!(
            block_sync_request_range(20_657, 20_735, 500),
            Some((20_655, 81))
        );
        assert_eq!(
            block_sync_request_range(10_000, 20_000, 2_000),
            Some((9_998, 2_003))
        );
    }

    #[test]
    fn block_sync_request_range_progresses_with_support_response_cap() {
        let local_height = 3;
        let (from_height, count) =
            block_sync_request_range(local_height, 1_080, MAX_STATUS_SYNC_BATCH).unwrap();

        assert!(from_height <= local_height);
        assert!(
            from_height + count as u64 - 1 > local_height,
            "first throttled validator response must include at least one block above local height"
        );
        assert!(count <= MAX_VALIDATOR_SUPPORT_SYNC_RESPONSE_BLOCKS);
    }

    #[test]
    fn block_sync_request_range_can_disable_overlap_for_compact_snapshot_chain() {
        assert_eq!(
            block_sync_request_range_with_overlap(743_026, 743_122, 96, false),
            Some((743_026, 97))
        );
    }

    #[test]
    fn block_sync_overlap_requires_contiguous_local_window() {
        let mut compact_chain = BlockChain::new();
        let mut retained_tip = Block::new_with_timestamp(
            743_026,
            Vec::new(),
            "snapshot-parent".to_string(),
            "validator".to_string(),
            0,
            743_026,
        );
        retained_tip.hash = "snapshot-tip".to_string();
        compact_chain.chain.push(retained_tip);

        assert!(!chain_has_block_sync_overlap(&compact_chain, 743_026, 96));

        let mut contiguous_chain = BlockChain::new();
        for height in 743_024..=743_026 {
            let mut block = Block::new_with_timestamp(
                height,
                Vec::new(),
                format!("parent-{height}"),
                "validator".to_string(),
                0,
                height,
            );
            block.hash = format!("hash-{height}");
            contiguous_chain.chain.push(block);
        }

        assert!(chain_has_block_sync_overlap(&contiguous_chain, 743_026, 96));
    }

    #[test]
    fn block_sync_response_selection_seeks_into_compact_chain_window() {
        let mut chain = BlockChain::new();
        for height in 261_825..261_835 {
            let mut block = Block::new_with_timestamp(
                height,
                Vec::new(),
                format!("parent-{height}"),
                "validator".to_string(),
                0,
                height,
            );
            block.hash = format!("hash-{height}");
            chain.chain.push(block);
        }

        let selected = select_block_sync_response_blocks(&chain, 261_829, 4);
        assert_eq!(
            selected
                .iter()
                .map(|block| block.block_index)
                .collect::<Vec<_>>(),
            vec![261_829, 261_830, 261_831, 261_832]
        );

        let before_window = select_block_sync_response_blocks(&chain, 0, 2);
        assert_eq!(
            before_window
                .iter()
                .map(|block| block.block_index)
                .collect::<Vec<_>>(),
            vec![261_825, 261_826]
        );

        assert!(select_block_sync_response_blocks(&chain, 999_999, 4).is_empty());
    }

    #[test]
    fn vote_messages_bypass_the_shared_message_queue() {
        let vote = Vote {
            validator_address: "synv1peer-a".to_string(),
            block_hash: "block-hash".to_string(),
            block_index: 7,
            epoch_number: 2,
            round_number: 1,
            signature: PQCSignature {
                algorithm: PQCAlgorithm::FNDSA,
                signature_data: vec![1, 2, 3],
                message_hash: vec![7, 8, 9],
                public_key_id: "peer-a".to_string(),
                created_at: 123,
            },
            signer_public_key: vec![4, 5, 6],
            timestamp: 123,
        };
        assert!(bypasses_shared_message_queue(&NetworkMessage::Vote {
            vote: vote.clone(),
        }));
        assert!(bypasses_shared_message_queue(
            &NetworkMessage::VoteRequest {
                block_data: Block::new(
                    0,
                    Vec::new(),
                    "genesis".to_string(),
                    "synv1leader".to_string(),
                    0
                ),
                epoch_number: 0,
                round_number: 1,
            }
        ));
        assert!(!bypasses_shared_message_queue(&NetworkMessage::GetBlocks {
            from_height: 10,
            count: 25,
        }));
        assert!(!bypasses_shared_message_queue(&NetworkMessage::Blocks {
            blocks: vec![Block::new(
                1,
                Vec::new(),
                "genesis".to_string(),
                "synv1leader".to_string(),
                1,
            )],
            quorum_certificates: Vec::new(),
        }));
        assert!(bypasses_shared_message_queue(&NetworkMessage::Block {
            block_data: Block::new(
                1,
                Vec::new(),
                "genesis".to_string(),
                "synv1leader".to_string(),
                1,
            ),
            quorum_certificate: None,
        }));
        assert!(!bypasses_shared_message_queue(&NetworkMessage::Status {
            block_height: 1,
            best_block_hash: "tip".to_string(),
            genesis_hash: "genesis".to_string(),
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        }));
    }

    #[test]
    fn vote_request_parent_validation_requires_next_canonical_tip() {
        let local_tip = (7, "tip-hash".to_string());
        let valid_proposal = Block::new(
            8,
            Vec::new(),
            "tip-hash".to_string(),
            "synv1leader".to_string(),
            1,
        );
        assert!(validate_vote_request_extends_local_tip(Some(&local_tip), &valid_proposal).is_ok());

        let future_proposal = Block::new(
            9,
            Vec::new(),
            "tip-hash".to_string(),
            "synv1leader".to_string(),
            2,
        );
        assert!(
            validate_vote_request_extends_local_tip(Some(&local_tip), &future_proposal)
                .expect_err("future proposals should be rejected")
                .contains("does not extend local tip")
        );

        let bad_parent = Block::new(
            8,
            Vec::new(),
            "other-parent".to_string(),
            "synv1leader".to_string(),
            3,
        );
        assert!(
            validate_vote_request_extends_local_tip(Some(&local_tip), &bad_parent)
                .expect_err("wrong parents should be rejected")
                .contains("parent hash")
        );
    }

    #[test]
    fn vote_request_parent_sync_range_ignores_stale_vote_requests() {
        assert_eq!(vote_request_parent_sync_range(21102, 21102), None);
        assert_eq!(vote_request_parent_sync_range(21102, 21101), None);
        assert_eq!(vote_request_parent_sync_range(21102, 21103), None);
        assert_eq!(
            vote_request_parent_sync_range(21102, 21110),
            Some((21103, 7))
        );
    }

    #[test]
    fn future_blocks_are_cached_and_applied_when_parent_arrives() {
        let _guard = block_application_test_guard();

        let genesis = Block::new_with_timestamp(
            0,
            Vec::new(),
            "genesis".to_string(),
            "synv1leader".to_string(),
            0,
            100,
        );
        let block_one = signed_block(
            1,
            Vec::new(),
            genesis.hash.clone(),
            "synv1leader".to_string(),
            1,
            102,
        );
        let block_two = signed_block(
            2,
            Vec::new(),
            block_one.hash.clone(),
            "synv1leader".to_string(),
            2,
            104,
        );
        let mut chain = BlockChain::new();
        chain.add_block(genesis);
        let blockchain = Arc::new(Mutex::new(chain));

        let block_two_qc = test_quorum_certificate(&block_two);
        assert!(!apply_block_if_new(
            &blockchain,
            block_two.clone(),
            Some(block_two_qc)
        ));
        assert_eq!(blockchain.lock().unwrap().last().unwrap().block_index, 0);

        let block_one_qc = test_quorum_certificate(&block_one);
        assert!(apply_block_if_new(
            &blockchain,
            block_one,
            Some(block_one_qc)
        ));
        let chain = blockchain.lock().unwrap();
        assert_eq!(chain.last().unwrap().block_index, 2);
        assert_eq!(chain.last().unwrap().hash, block_two.hash);
        drop(chain);

        PENDING_BLOCKS.lock().unwrap().clear();
        clear_legacy_canonical_locks_for_tests();
    }

    #[test]
    fn unsigned_network_block_is_rejected() {
        let _guard = block_application_test_guard();

        let genesis = Block::new_with_timestamp(
            0,
            Vec::new(),
            "genesis".to_string(),
            "synv1leader".to_string(),
            0,
            100,
        );
        let unsigned_block = Block::new_with_timestamp(
            1,
            Vec::new(),
            genesis.hash.clone(),
            "synv1leader".to_string(),
            1,
            102,
        );
        let mut chain = BlockChain::new();
        chain.add_block(genesis);
        let blockchain = Arc::new(Mutex::new(chain));

        assert!(!apply_block_if_new(&blockchain, unsigned_block, None));
        assert_eq!(blockchain.lock().unwrap().last().unwrap().block_index, 0);
    }

    #[test]
    fn peer_canonical_lock_conflict_does_not_self_quarantine_local_node() {
        let _guard = block_application_test_guard();

        let genesis = Block::new_with_timestamp(
            0,
            Vec::new(),
            "genesis".to_string(),
            "synv1leader".to_string(),
            0,
            100,
        );
        let canonical_block = signed_block(
            1,
            Vec::new(),
            genesis.hash.clone(),
            "synv1leader".to_string(),
            1,
            102,
        );
        let conflicting_peer_block = signed_block(
            1,
            Vec::new(),
            genesis.hash.clone(),
            "synv1leader".to_string(),
            2,
            104,
        );
        let next_canonical_block = signed_block(
            2,
            Vec::new(),
            canonical_block.hash.clone(),
            "synv1leader".to_string(),
            3,
            106,
        );
        let canonical_qc = test_quorum_certificate(&canonical_block);
        write_legacy_canonical_lock(&canonical_block, &canonical_qc)
            .expect("test canonical lock should be written");

        let mut chain = BlockChain::new();
        chain.add_block(genesis);
        chain.add_block(canonical_block);
        chain.add_block(next_canonical_block);
        let blockchain = Arc::new(Mutex::new(chain));

        assert!(!apply_block_if_new(
            &blockchain,
            conflicting_peer_block.clone(),
            Some(test_quorum_certificate(&conflicting_peer_block))
        ));
        assert_eq!(blockchain.lock().unwrap().last().unwrap().block_index, 2);
        assert!(
            current_self_quarantine_record().is_none(),
            "rejecting a historical peer block that conflicts with a local canonical lock must not self-quarantine a node that is already past that height"
        );

        clear_legacy_canonical_locks_for_tests();
    }

    #[test]
    fn peer_canonical_lock_conflict_at_local_tip_does_not_self_quarantine_local_node() {
        let _guard = block_application_test_guard();

        let genesis = Block::new_with_timestamp(
            0,
            Vec::new(),
            "genesis".to_string(),
            "synv1leader".to_string(),
            0,
            100,
        );
        let local_locked_block = signed_block(
            1,
            Vec::new(),
            genesis.hash.clone(),
            "synv1leader".to_string(),
            1,
            102,
        );
        let conflicting_peer_block = signed_block(
            1,
            Vec::new(),
            genesis.hash.clone(),
            "synv1leader".to_string(),
            2,
            104,
        );
        let local_qc = test_quorum_certificate(&local_locked_block);
        write_legacy_canonical_lock(&local_locked_block, &local_qc)
            .expect("test canonical lock should be written");

        let mut chain = BlockChain::new();
        chain.add_block(genesis);
        chain.add_block(local_locked_block);
        let blockchain = Arc::new(Mutex::new(chain));

        assert!(!apply_block_if_new(
            &blockchain,
            conflicting_peer_block.clone(),
            Some(test_quorum_certificate(&conflicting_peer_block))
        ));
        assert_eq!(blockchain.lock().unwrap().last().unwrap().block_index, 1);
        assert_eq!(
            current_self_quarantine_record(),
            None,
            "peer-supplied canonical lock conflicts must be rejected and recorded as peer evidence, not local self-quarantine"
        );

        clear_legacy_canonical_locks_for_tests();
    }

    #[test]
    fn pending_peer_canonical_lock_conflict_after_tip_apply_does_not_self_quarantine() {
        let _guard = block_application_test_guard();

        let genesis = Block::new_with_timestamp(
            0,
            Vec::new(),
            "genesis".to_string(),
            "synv1leader".to_string(),
            0,
            100,
        );
        let block_one = signed_block(
            1,
            Vec::new(),
            genesis.hash.clone(),
            "synv1leader".to_string(),
            1,
            102,
        );
        let local_locked_block_two = signed_block(
            2,
            Vec::new(),
            block_one.hash.clone(),
            "synv1leader".to_string(),
            2,
            104,
        );
        let conflicting_peer_block_two = signed_block(
            2,
            Vec::new(),
            block_one.hash.clone(),
            "synv1leader".to_string(),
            3,
            106,
        );
        write_legacy_canonical_lock(
            &local_locked_block_two,
            &test_quorum_certificate(&local_locked_block_two),
        )
        .expect("test canonical lock should be written");
        cache_pending_block(
            conflicting_peer_block_two.clone(),
            test_quorum_certificate(&conflicting_peer_block_two),
        );

        let mut chain = BlockChain::new();
        chain.add_block(genesis);
        let blockchain = Arc::new(Mutex::new(chain));

        let block_one_qc = test_quorum_certificate(&block_one);
        assert!(apply_block_if_new(
            &blockchain,
            block_one,
            Some(block_one_qc)
        ));
        let chain = blockchain.lock().unwrap();
        assert_eq!(chain.last().unwrap().block_index, 1);
        assert_eq!(
            current_self_quarantine_record(),
            None,
            "pending peer block conflicts discovered after applying the parent must be rejected as peer evidence without local self-quarantine"
        );
        drop(chain);

        PENDING_BLOCKS.lock().unwrap().clear();
        clear_legacy_canonical_locks_for_tests();
    }

    #[test]
    fn signed_network_block_without_qc_is_rejected() {
        let genesis = Block::new_with_timestamp(
            0,
            Vec::new(),
            "genesis".to_string(),
            "synv1leader".to_string(),
            0,
            100,
        );
        let signed_block = signed_block(
            1,
            Vec::new(),
            genesis.hash.clone(),
            "synv1leader".to_string(),
            1,
            102,
        );
        let mut chain = BlockChain::new();
        chain.add_block(genesis);
        let blockchain = Arc::new(Mutex::new(chain));

        assert!(!apply_block_if_new(&blockchain, signed_block, None));
        assert_eq!(blockchain.lock().unwrap().last().unwrap().block_index, 0);
    }

    #[test]
    fn background_sync_requests_pause_while_sync_manager_is_active() {
        let config = NodeConfig::default();
        assert!(should_request_missing_blocks(&config, false));
        assert!(!should_request_missing_blocks(&config, true));
    }

    #[test]
    fn validator_role_is_detected_from_identity_profile_or_address() {
        let mut config = NodeConfig::default();
        assert!(!local_node_runs_validator_consensus(&config));

        config.identity.role = "validator".to_string();
        assert!(local_node_runs_validator_consensus(&config));

        config.identity.role.clear();
        config.role.compiled_profile = "validator_node".to_string();
        assert!(local_node_runs_validator_consensus(&config));

        config.role.compiled_profile.clear();
        config.node.validator_address = "synv1local".to_string();
        assert!(!local_node_runs_validator_consensus(&config));

        config.role.services = vec!["consensus".to_string()];
        assert!(local_node_runs_validator_consensus(&config));
    }

    #[test]
    fn validator_nodes_throttle_support_peer_block_sync_responses() {
        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();
        let support_peer = test_peer_with_validator_address(Some("synv1support"));

        let policy = block_sync_response_policy(&config, Some(&support_peer));

        assert_eq!(
            policy.max_blocks,
            MAX_VALIDATOR_SUPPORT_SYNC_RESPONSE_BLOCKS
        );
        assert_eq!(policy.write_timeout, Duration::from_millis(500));
        assert_eq!(
            block_sync_min_serve_interval_secs(&config, Some(&support_peer)),
            VALIDATOR_SUPPORT_BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS
        );
    }

    #[test]
    fn validator_nodes_serve_active_validator_sync_without_slow_recovery_throttle() {
        configure_canonical_genesis_path_for_tests();
        let active_validator = "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs";
        ensure_test_validator_key(active_validator);

        let mut config = NodeConfig::default();
        config.identity.role = "validator".to_string();
        let active_peer = test_peer_with_validator_address(Some(active_validator));

        assert_eq!(
            block_sync_min_serve_interval_secs(&config, Some(&active_peer)),
            BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS
        );
    }

    #[test]
    fn non_validator_nodes_serve_large_public_onboarding_block_sync_batches() {
        let mut config = NodeConfig::default();
        config.identity.role = "relayer".to_string();
        let support_peer = test_peer_with_validator_address(Some("synv1support"));

        let policy = block_sync_response_policy(&config, Some(&support_peer));

        assert_eq!(
            policy.max_blocks,
            MAX_SUPPORT_NODE_BLOCK_SYNC_RESPONSE_BLOCKS
        );
        assert_eq!(policy.write_timeout, Duration::from_secs(2));
        assert_eq!(
            block_sync_min_serve_interval_secs(&config, Some(&support_peer)),
            SUPPORT_NODE_BLOCK_SYNC_MIN_SERVE_INTERVAL_SECS
        );
    }

    #[test]
    fn deep_support_peer_sync_request_is_refused() {
        configure_canonical_genesis_path_for_tests();
        let active_validator = "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs";
        ensure_test_validator_key(active_validator);

        let support_peer = test_peer_with_validator_address(Some("synv1support"));
        let active_peer = test_peer_with_validator_address(Some(active_validator));

        assert!(support_peer_sync_request_is_too_deep(
            Some(&support_peer),
            250_000,
            11_666
        ));
        assert!(!support_peer_sync_request_is_too_deep(
            Some(&support_peer),
            50_000,
            11_666
        ));
        assert!(!support_peer_sync_request_is_too_deep(
            Some(&support_peer),
            50_000,
            49_500
        ));
        assert!(!support_peer_sync_request_is_too_deep(
            Some(&active_peer),
            50_000,
            11_666
        ));
    }

    #[test]
    fn oversized_p2p_frame_is_rejected_before_body_read() {
        let len = (MAX_P2P_FRAME_BYTES as u32).saturating_add(1);
        let mut input = std::io::Cursor::new(len.to_le_bytes().to_vec());
        let error = receive_message(&mut input).expect_err("oversized frame must fail closed");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn failed_block_sync_write_disconnects_peer_to_preserve_framing() {
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        let mut peers = HashMap::new();
        peers.insert(
            "peer-a".to_string(),
            test_peer_with_validator_address(Some("synv1support")),
        );

        disconnect_peer_after_poisoned_write(
            &peer_state_cache,
            &mut peers,
            "peer-a",
            "block-sync-send-failed: timed out",
        );

        assert!(!peers.contains_key("peer-a"));
        assert!(peer_state_cache
            .lock()
            .unwrap()
            .contains_key("validator:synv1support"));
    }

    #[test]
    fn background_poll_interval_uses_heartbeat_during_active_sync() {
        let heartbeat = Duration::from_secs(7);
        assert_eq!(background_poll_interval(100, heartbeat, true), heartbeat);
        assert_eq!(
            background_poll_interval(100, heartbeat, false),
            Duration::from_millis(BACKGROUND_SYNC_POLL_MILLIS)
        );
        assert_eq!(
            background_poll_interval(5, heartbeat, false),
            Duration::from_millis(BACKGROUND_SYNC_POLL_MILLIS)
        );
        assert_eq!(background_poll_interval(0, heartbeat, false), heartbeat);
    }

    #[test]
    fn dispatch_peer_message_keeps_votes_off_the_background_queue() {
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        connected_peers.lock().unwrap().insert(
            "peer-a".to_string(),
            PeerConnection {
                address: "peer-a".to_string(),
                direction: ConnectionDirection::Incoming,
                public_address: Some("genesisval2.synergy-network.io:5622".to_string()),
                validator_address: Some("synv1peer-a".to_string()),
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                node_id: Some("testnet-peer-a".to_string()),
                version: Some("1.0.0".to_string()),
                capabilities: vec!["blocks".to_string()],
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );

        let (sender, receiver) = mpsc::channel();
        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let config = NodeConfig::default();
        let vote = Vote {
            validator_address: "synv1peer-a".to_string(),
            block_hash: "block-hash".to_string(),
            block_index: 7,
            epoch_number: 2,
            round_number: 1,
            signature: PQCSignature {
                algorithm: PQCAlgorithm::FNDSA,
                signature_data: vec![1, 2, 3],
                message_hash: vec![7, 8, 9],
                public_key_id: "peer-a".to_string(),
                created_at: 123,
            },
            signer_public_key: vec![4, 5, 6],
            timestamp: 123,
        };

        dispatch_peer_message(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            &sender,
            &config,
            "peer-a",
            NetworkMessage::Vote { vote },
        )
        .expect("vote dispatch should succeed");

        assert!(
            receiver.recv_timeout(Duration::from_millis(50)).is_err(),
            "vote dispatch should bypass the shared background queue"
        );
    }

    #[test]
    fn status_handler_records_genesis_hash_and_requests_blocks_without_deadlocking() {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to bind test listener: {error}"),
        };
        let addr = listener.local_addr().expect("listener address");
        let client = match std::net::TcpStream::connect(addr) {
            Ok(stream) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to connect test stream: {error}"),
        };
        let (mut server, _) = listener.accept().expect("accept peer stream");
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("set read timeout");

        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        let mut config = NodeConfig::default();
        config.node.validator_address = "synv1local".to_string();

        connected_peers.lock().unwrap().insert(
            "peer-a".to_string(),
            PeerConnection {
                address: "peer-a".to_string(),
                direction: ConnectionDirection::Outgoing,
                public_address: Some("genesisval2.synergy-network.io:5622".to_string()),
                validator_address: Some("synv1peer-a".to_string()),
                connected_at: 100,
                last_seen: 100,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: Some(client),
                node_id: Some("testnet-peer-a".to_string()),
                version: Some("1.0.0".to_string()),
                capabilities: vec!["blocks".to_string()],
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );

        let genesis_hash = canonical_genesis_hash();
        let (done_tx, done_rx) = mpsc::channel();
        let blockchain_for_thread = Arc::clone(&blockchain);
        let connected_peers_for_thread = Arc::clone(&connected_peers);
        let peer_state_cache_for_thread = Arc::clone(&peer_state_cache);
        let config_for_thread = config.clone();
        let genesis_hash_for_thread = genesis_hash.clone();

        thread::spawn(move || {
            handle_status_message(
                &blockchain_for_thread,
                &connected_peers_for_thread,
                &peer_state_cache_for_thread,
                &config_for_thread,
                "peer-a",
                12,
                "best-hash",
                &genesis_hash_for_thread,
                false,
                false,
                None,
            );
            let _ = done_tx.send(());
        });

        done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("status handler should complete without deadlocking");

        {
            let peers = connected_peers.lock().unwrap();
            let peer = peers.get("peer-a").expect("peer should remain connected");
            assert_eq!(peer.last_known_height, 12);
            assert_eq!(peer.best_block_hash, "best-hash".to_string());
            assert_eq!(peer.genesis_hash, genesis_hash);
            assert!(peer.status_received_at.is_some());
        }

        match receive_message(&mut server).expect("status handling should request blocks") {
            NetworkMessage::GetBlocks { from_height, count } => {
                assert_eq!(from_height, 0);
                assert_eq!(count, 13);
            }
            other => panic!("expected GetBlocks request, got {other:?}"),
        }
    }

    #[test]
    fn status_handler_requests_blocks_from_duty_disabled_support_peer() {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to bind test listener: {error}"),
        };
        let addr = listener.local_addr().expect("listener address");
        let client = match std::net::TcpStream::connect(addr) {
            Ok(stream) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to connect test stream: {error}"),
        };
        let (mut server, _) = listener.accept().expect("accept peer stream");
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("set read timeout");

        let blockchain = Arc::new(Mutex::new(BlockChain::new()));
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let peer_state_cache = Arc::new(Mutex::new(HashMap::new()));
        let config = NodeConfig::default();

        let mut support_peer =
            test_peer_with_validator_address(Some("synv21ga3nsdjagzt9pmks4mzjq4vdjyngdwq6jst632"));
        support_peer.node_id = Some("sentry1".to_string());
        support_peer.stream = Some(client);
        support_peer.status_received_at = None;
        support_peer.consensus_duties_disabled = true;
        connected_peers
            .lock()
            .unwrap()
            .insert("relayer-a".to_string(), support_peer);

        let genesis_hash = canonical_genesis_hash();
        handle_status_message(
            &blockchain,
            &connected_peers,
            &peer_state_cache,
            &config,
            "relayer-a",
            195_000,
            "best-hash",
            &genesis_hash,
            false,
            true,
            Some("SUPPORT_RELAY"),
        );

        let local_height = blockchain
            .lock()
            .unwrap()
            .last()
            .map(|block| block.block_index)
            .unwrap_or(0);
        let (expected_from_height, expected_count) =
            block_sync_request_range(local_height, 195_000, MAX_STATUS_SYNC_BATCH)
                .expect("support peer should advertise blocks above the local tip");

        match receive_message(&mut server).expect("status handling should request blocks") {
            NetworkMessage::GetBlocks { from_height, count } => {
                assert_eq!(from_height, expected_from_height);
                assert_eq!(count, expected_count);
            }
            other => panic!("expected GetBlocks request from support peer, got {other:?}"),
        }
    }

    #[test]
    fn validator_status_genesis_grace_window_expires_after_threshold() {
        assert!(validator_status_genesis_within_grace_window(100, 120));
        assert_eq!(validator_status_genesis_grace_remaining_secs(100, 120), 10);
        assert!(!validator_status_genesis_within_grace_window(100, 130));
        assert_eq!(validator_status_genesis_grace_remaining_secs(100, 130), 0);
    }

    #[test]
    fn bootstrap_refresh_uses_configured_fast_interval_until_validator_mesh_is_complete() {
        let mut config = NodeConfig::default();
        config.consensus.min_validators = 4;
        config.node.validator_address = "synv1local".to_string();
        config.p2p.bootstrap_refresh_secs = 61;
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));

        let interval = current_bootstrap_refresh_interval(&config, &connected_peers);
        assert_eq!(interval, Duration::from_secs(61));
        assert_eq!(
            connected_validator_participants(&config, &connected_peers),
            1
        );
    }

    #[test]
    fn bootstrap_refresh_defaults_to_legacy_fast_interval() {
        let mut config = NodeConfig::default();
        config.consensus.min_validators = 4;
        config.node.validator_address = "synv1local".to_string();
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));

        let interval = current_bootstrap_refresh_interval(&config, &connected_peers);
        assert_eq!(
            interval,
            Duration::from_secs(DEFAULT_BOOTSTRAP_REFRESH_SECS)
        );
    }

    #[test]
    fn bootstrap_refresh_relaxes_after_validator_mesh_is_complete() {
        let mut config = NodeConfig::default();
        config.consensus.min_validators = 4;
        config.node.validator_address = "synv1local".to_string();

        let mut peers = HashMap::new();
        for (index, validator_address) in ["synv1peer-a", "synv1peer-b", "synv1peer-c"]
            .iter()
            .enumerate()
        {
            peers.insert(
                format!("peer-{index}"),
                PeerConnection {
                    address: format!("127.0.0.1:56{:02}", index + 20),
                    direction: ConnectionDirection::Outgoing,
                    public_address: None,
                    validator_address: Some((*validator_address).to_string()),
                    connected_at: 0,
                    last_seen: 0,
                    blocks_sent: 0,
                    blocks_received: 0,
                    txs_sent: 0,
                    txs_received: 0,
                    stream: None,
                    node_id: None,
                    version: None,
                    capabilities: Vec::new(),
                    last_known_height: 0,
                    best_block_hash: String::new(),
                    genesis_hash: "genesis-hash".to_string(),
                    status_received_at: Some(1),
                    quarantined: false,
                    consensus_duties_disabled: false,
                    recovery_state: None,
                },
            );
        }

        let connected_peers = Arc::new(Mutex::new(peers));
        let interval = current_bootstrap_refresh_interval(&config, &connected_peers);

        assert_eq!(
            connected_validator_participants(&config, &connected_peers),
            4
        );
        assert_eq!(interval, Duration::from_secs(NORMAL_BOOTSTRAP_REFRESH_SECS));
    }

    #[test]
    fn status_ready_validator_participants_requires_peer_status_exchange() {
        let mut config = NodeConfig::default();
        config.consensus.min_validators = 4;
        config.node.validator_address = "synv1local".to_string();

        let mut peers = HashMap::new();
        peers.insert(
            "peer-a".to_string(),
            PeerConnection {
                address: "127.0.0.1:5622".to_string(),
                direction: ConnectionDirection::Outgoing,
                public_address: None,
                validator_address: Some("synv1peer-a".to_string()),
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                node_id: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        peers.insert(
            "peer-b".to_string(),
            PeerConnection {
                address: "127.0.0.2:5622".to_string(),
                direction: ConnectionDirection::Outgoing,
                public_address: None,
                validator_address: Some("synv1peer-b".to_string()),
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                node_id: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 0,
                best_block_hash: String::new(),
                genesis_hash: "genesis-hash".to_string(),
                status_received_at: Some(1),
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );

        let connected_peers = Arc::new(Mutex::new(peers));
        assert_eq!(
            connected_validator_participants(&config, &connected_peers),
            3
        );
        assert_eq!(
            status_ready_validator_participants(&config, &connected_peers),
            2
        );
    }

    #[test]
    fn status_ready_validator_addresses_exclude_non_allowlisted_peer_validator_identity() {
        let local_validator = "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs";
        let support_identity = "synv21ga3nsdjagzt9pmks4mzjq4vdjyngdwq6jst632";
        let mut config = NodeConfig::default();
        config.node.validator_address = local_validator.to_string();
        config.node.allowed_validator_addresses = vec![local_validator.to_string()];

        let mut support_peer = test_peer_with_validator_address(Some(support_identity));
        support_peer.status_received_at = Some(current_timestamp());
        support_peer.genesis_hash = "test-genesis".to_string();

        let mut peers = HashMap::new();
        peers.insert("support-peer".to_string(), support_peer);
        let connected_peers = Arc::new(Mutex::new(peers));

        let addresses = status_ready_validator_addresses(&config, &connected_peers);
        assert!(addresses.contains(&local_validator.to_string()));
        assert!(!addresses.contains(&support_identity.to_string()));
        assert_eq!(addresses.len(), 1);
    }

    #[test]
    fn best_connected_validator_height_ignores_unknown_validator_status() {
        let mut peers = HashMap::new();
        peers.insert(
            "peer-a".to_string(),
            PeerConnection {
                address: "127.0.0.1:5622".to_string(),
                direction: ConnectionDirection::Outgoing,
                public_address: None,
                validator_address: Some("synv1peer-a".to_string()),
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                node_id: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 99,
                best_block_hash: String::new(),
                genesis_hash: String::new(),
                status_received_at: None,
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        peers.insert(
            "peer-b".to_string(),
            PeerConnection {
                address: "127.0.0.2:5622".to_string(),
                direction: ConnectionDirection::Outgoing,
                public_address: None,
                validator_address: Some("synv1peer-b".to_string()),
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                node_id: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 7,
                best_block_hash: String::new(),
                genesis_hash: "genesis-hash".to_string(),
                status_received_at: Some(1),
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );

        let connected_peers = Arc::new(Mutex::new(peers));
        assert_eq!(best_connected_validator_height(&connected_peers), 7);
    }

    #[test]
    fn best_connected_validator_height_with_support_ignores_single_higher_fork() {
        let mut peers = HashMap::new();
        peers.insert(
            "peer-a".to_string(),
            PeerConnection {
                address: "127.0.0.1:5622".to_string(),
                direction: ConnectionDirection::Outgoing,
                public_address: None,
                validator_address: Some("synv1peer-a".to_string()),
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                node_id: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 12,
                best_block_hash: "hash-12".to_string(),
                genesis_hash: "genesis-hash".to_string(),
                status_received_at: Some(1),
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        peers.insert(
            "peer-b".to_string(),
            PeerConnection {
                address: "127.0.0.2:5622".to_string(),
                direction: ConnectionDirection::Outgoing,
                public_address: None,
                validator_address: Some("synv1peer-b".to_string()),
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                node_id: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 12,
                best_block_hash: "hash-12".to_string(),
                genesis_hash: "genesis-hash".to_string(),
                status_received_at: Some(1),
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );
        peers.insert(
            "peer-c".to_string(),
            PeerConnection {
                address: "127.0.0.3:5622".to_string(),
                direction: ConnectionDirection::Outgoing,
                public_address: None,
                validator_address: Some("synv1peer-c".to_string()),
                connected_at: 0,
                last_seen: 0,
                blocks_sent: 0,
                blocks_received: 0,
                txs_sent: 0,
                txs_received: 0,
                stream: None,
                node_id: None,
                version: None,
                capabilities: Vec::new(),
                last_known_height: 20,
                best_block_hash: "fork-20".to_string(),
                genesis_hash: "genesis-hash".to_string(),
                status_received_at: Some(1),
                quarantined: false,
                consensus_duties_disabled: false,
                recovery_state: None,
            },
        );

        let connected_peers = Arc::new(Mutex::new(peers));
        assert_eq!(
            super::best_connected_validator_height_with_support(&connected_peers, 2),
            12
        );
    }

    #[test]
    fn best_connected_validator_height_with_support_uses_supported_moving_head_floor() {
        let mut peers = HashMap::new();
        for (peer_id, validator, height) in [
            ("peer-a", "synv1peer-a", 105),
            ("peer-b", "synv1peer-b", 104),
            ("peer-c", "synv1peer-c", 103),
            ("peer-d", "synv1peer-d", 101),
        ] {
            let mut peer = test_peer_with_validator_address(Some(validator));
            peer.address = peer_id.to_string();
            peer.last_known_height = height;
            peer.best_block_hash = format!("hash-{height}");
            peer.status_received_at = Some(1);
            peers.insert(peer_id.to_string(), peer);
        }

        let connected_peers = Arc::new(Mutex::new(peers));
        assert_eq!(
            super::best_connected_validator_height_with_support(&connected_peers, 3),
            103
        );
    }

    #[test]
    fn best_connected_validator_height_with_support_excludes_quarantined_sources() {
        let mut peers = HashMap::new();
        for (peer_id, validator, height, quarantined, duty_disabled) in [
            ("peer-a", "synv1peer-a", 200, true, true),
            ("peer-b", "synv1peer-b", 180, false, true),
            ("peer-c", "synv1peer-c", 100, false, false),
            ("peer-d", "synv1peer-d", 99, false, false),
            ("peer-e", "synv1peer-e", 98, false, false),
        ] {
            let mut peer = test_peer_with_validator_address(Some(validator));
            peer.address = peer_id.to_string();
            peer.last_known_height = height;
            peer.best_block_hash = format!("hash-{height}");
            peer.status_received_at = Some(1);
            peer.quarantined = quarantined;
            peer.consensus_duties_disabled = duty_disabled;
            peers.insert(peer_id.to_string(), peer);
        }

        let connected_peers = Arc::new(Mutex::new(peers));
        assert_eq!(
            super::best_connected_validator_height_with_support(&connected_peers, 3),
            98
        );
    }

    fn test_block(previous: &Block, height: u64, validator: &str, nonce: u64) -> Block {
        signed_block(
            height,
            Vec::new(),
            previous.hash.clone(),
            validator.to_string(),
            nonce,
            1_700_000_000 + height,
        )
    }

    #[test]
    fn apply_block_batch_rolls_back_to_common_ancestor_before_replaying() {
        let _guard = block_application_test_guard();
        let mut chain = BlockChain::new();
        let genesis = Block::new_with_timestamp(
            0,
            Vec::new(),
            "genesis-parent".to_string(),
            "genesis".to_string(),
            0,
            1_700_000_000,
        );
        chain.add_block(genesis.clone());
        let block1 = test_block(&genesis, 1, "validator-a", 1);
        let block2 = test_block(&block1, 2, "validator-b", 2);
        let local_block3 = test_block(&block2, 3, "validator-c", 3);
        chain.add_block(block1.clone());
        chain.add_block(block2.clone());
        chain.add_block(local_block3.clone());

        let blockchain = Arc::new(Mutex::new(chain));

        let remote_block3 = signed_block(
            3,
            Vec::new(),
            block2.hash.clone(),
            "validator-d".to_string(),
            99,
            1_700_000_099,
        );
        let remote_block4 = test_block(&remote_block3, 4, "validator-e", 4);
        let block2_qc = test_quorum_certificate(&block2);
        let remote_block3_qc = test_quorum_certificate(&remote_block3);
        let remote_block4_qc = test_quorum_certificate(&remote_block4);

        let applied = apply_block_batch(
            &blockchain,
            vec![block2.clone(), remote_block3.clone(), remote_block4.clone()],
            vec![block2_qc, remote_block3_qc, remote_block4_qc],
        );
        assert_eq!(applied, 2);

        let chain = blockchain.lock().unwrap();
        assert_eq!(chain.last().map(|block| block.block_index), Some(4));
        assert_eq!(
            chain.block_at_height(3).map(|block| block.hash.clone()),
            Some(remote_block3.hash.clone())
        );
        assert_eq!(
            chain.block_at_height(4).map(|block| block.hash.clone()),
            Some(remote_block4.hash.clone())
        );
        drop(chain);
        clear_legacy_canonical_locks_for_tests();
    }

    #[test]
    fn apply_block_batch_ignores_stale_matching_prefix_batches() {
        let _guard = block_application_test_guard();
        let mut chain = BlockChain::new();
        let genesis = Block::new_with_timestamp(
            0,
            Vec::new(),
            "genesis-parent".to_string(),
            "genesis".to_string(),
            0,
            1_700_000_000,
        );
        chain.add_block(genesis.clone());
        let block1 = test_block(&genesis, 1, "validator-a", 1);
        let block2 = test_block(&block1, 2, "validator-b", 2);
        let block3 = test_block(&block2, 3, "validator-c", 3);
        let block4 = test_block(&block3, 4, "validator-d", 4);
        let block5 = test_block(&block4, 5, "validator-e", 5);
        chain.add_block(block1.clone());
        chain.add_block(block2.clone());
        chain.add_block(block3.clone());
        chain.add_block(block4.clone());
        chain.add_block(block5.clone());

        let blockchain = Arc::new(Mutex::new(chain));
        let applied = apply_block_batch(
            &blockchain,
            vec![block2.clone(), block3.clone(), block4.clone()],
            vec![
                test_quorum_certificate(&block2),
                test_quorum_certificate(&block3),
                test_quorum_certificate(&block4),
            ],
        );
        assert_eq!(applied, 0);

        let chain = blockchain.lock().unwrap();
        assert_eq!(chain.last().map(|block| block.block_index), Some(5));
        assert_eq!(
            chain.block_at_height(5).map(|block| block.hash.clone()),
            Some(block5.hash.clone())
        );
    }

    #[test]
    fn apply_block_batch_accepts_qc_less_matching_overlap_before_new_blocks() {
        let _guard = block_application_test_guard();
        let mut chain = BlockChain::new();
        let genesis = Block::new_with_timestamp(
            0,
            Vec::new(),
            "genesis-parent".to_string(),
            "genesis".to_string(),
            0,
            1_700_000_000,
        );
        chain.add_block(genesis.clone());
        let block1 = test_block(&genesis, 1, "validator-a", 1);
        let block2 = test_block(&block1, 2, "validator-b", 2);
        let block3 = test_block(&block2, 3, "validator-c", 3);
        let block4 = test_block(&block3, 4, "validator-d", 4);
        chain.add_block(block1.clone());
        chain.add_block(block2.clone());
        chain.add_block(block3.clone());

        let blockchain = Arc::new(Mutex::new(chain));
        let applied = apply_block_batch(
            &blockchain,
            vec![block2.clone(), block3.clone(), block4.clone()],
            vec![test_quorum_certificate(&block4)],
        );
        assert_eq!(applied, 1);

        let chain = blockchain.lock().unwrap();
        assert_eq!(chain.last().map(|block| block.block_index), Some(4));
        assert_eq!(
            chain.block_at_height(4).map(|block| block.hash.clone()),
            Some(block4.hash.clone())
        );
        drop(chain);
        clear_legacy_canonical_locks_for_tests();
    }

    #[test]
    fn stale_unidentified_peers_are_pruned_after_grace_window() {
        let peer = PeerConnection {
            address: "10.69.0.5:55354".to_string(),
            direction: ConnectionDirection::Incoming,
            public_address: None,
            validator_address: None,
            connected_at: 100,
            last_seen: 100,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            node_id: None,
            version: None,
            capabilities: Vec::new(),
            last_known_height: 0,
            best_block_hash: String::new(),
            genesis_hash: String::new(),
            status_received_at: None,
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        };
        let config = NodeConfig::default();
        let active_validator_addresses = HashSet::new();

        assert!(!should_prune_stale_peer(
            &config,
            &peer,
            100 + STALE_UNIDENTIFIED_PEER_SECS - 1,
            &active_validator_addresses,
        ));
        assert!(should_prune_stale_peer(
            &config,
            &peer,
            100 + STALE_UNIDENTIFIED_PEER_SECS,
            &active_validator_addresses,
        ));
    }

    #[test]
    fn configured_validator_dial_is_status_ready_during_identity_recovery_grace() {
        let validators = vec![
            "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs".to_string(),
            "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt".to_string(),
            "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re".to_string(),
            "synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5".to_string(),
            "synv11kguave5fpdpm9hru4acfvw0hcp4fcc7zv9f".to_string(),
            "synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx".to_string(),
        ];
        let active_validator_addresses = validators.iter().cloned().collect::<HashSet<_>>();
        let mut config = NodeConfig::default();
        config.node.allowed_validator_addresses = validators;
        config.node.validator_address =
            "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re".to_string();
        config.network.persistent_peers = vec![
            "62.146.182.207:5622".to_string(),
            "62.146.182.208:5622".to_string(),
            "73.79.66.255:5622".to_string(),
            "194.163.183.166:5622".to_string(),
            "157.173.192.45:5622".to_string(),
        ];
        let now = current_timestamp();
        let peer = PeerConnection {
            address: "73.79.66.255:5622".to_string(),
            direction: ConnectionDirection::Outgoing,
            public_address: None,
            validator_address: None,
            connected_at: now,
            last_seen: now,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            node_id: None,
            version: None,
            capabilities: Vec::new(),
            last_known_height: 0,
            best_block_hash: String::new(),
            genesis_hash: String::new(),
            status_received_at: None,
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        };
        let connected_peers = Arc::new(Mutex::new(HashMap::from([(
            "73.79.66.255:5622".to_string(),
            peer,
        )])));

        let status_ready = status_ready_validator_addresses(&config, &connected_peers);

        assert!(status_ready.contains(
            &"synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re".to_string()
        ));
        assert!(status_ready.contains(
            &"synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5".to_string()
        ));
        let peers = connected_peers.lock().expect("peer map should lock");
        let peer = peers
            .get("73.79.66.255:5622")
            .expect("configured validator peer should exist");
        assert!(!should_prune_stale_peer(
            &config,
            peer,
            now + STALE_UNIDENTIFIED_PEER_SECS,
            &active_validator_addresses,
        ));
        assert!(should_prune_stale_peer(
            &config,
            peer,
            now + STALE_VALIDATOR_STATUS_SECS,
            &active_validator_addresses,
        ));
    }

    #[test]
    fn validator_peers_missing_status_are_pruned_after_status_timeout() {
        let peer = PeerConnection {
            address: "10.69.0.2:5622".to_string(),
            direction: ConnectionDirection::Outgoing,
            public_address: Some("10.69.0.2:5622".to_string()),
            validator_address: Some("synv1peer-b".to_string()),
            connected_at: 200,
            last_seen: 200,
            blocks_sent: 0,
            blocks_received: 0,
            txs_sent: 0,
            txs_received: 0,
            stream: None,
            node_id: Some("synv1peer-b".to_string()),
            version: Some("1.0.0".to_string()),
            capabilities: vec!["blocks".to_string()],
            last_known_height: 0,
            best_block_hash: String::new(),
            genesis_hash: String::new(),
            status_received_at: None,
            quarantined: false,
            consensus_duties_disabled: false,
            recovery_state: None,
        };
        let config = NodeConfig::default();
        let active_validator_addresses = HashSet::new();

        assert!(!should_prune_stale_peer(
            &config,
            &peer,
            200 + STALE_VALIDATOR_STATUS_SECS - 1,
            &active_validator_addresses,
        ));
        assert!(should_prune_stale_peer(
            &config,
            &peer,
            200 + STALE_VALIDATOR_STATUS_SECS,
            &active_validator_addresses,
        ));
    }
}
