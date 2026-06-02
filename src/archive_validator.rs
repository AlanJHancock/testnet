use crate::crypto::aegis_pqvm::{
    AegisPqvmSigner, AegisPqvmVerifier, SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1,
    SYNERGY_ARCHIVE_SNAPSHOT_MANIFEST_V1,
};
use crate::synergy_types::{
    AegisPqKeyId, AegisPqKeyRole, AegisPqSignature, CanonicalSerialize, ChainId, ClusterId, Hash,
    Height, NetworkId, QuorumCertificate,
};
use serde::{Deserialize, Serialize};

pub const ARCHIVE_SNAPSHOT_INTERVAL_BLOCKS: u64 = 5_000;
pub const ARCHIVE_SNAPSHOT_CHUNK_SIZE_BYTES: u64 = 512 * 1024 * 1024;
pub const ARCHIVE_SNAPSHOT_RETENTION_PER_CLASS: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArchiveNodeStatus {
    Uninitialized,
    AegisPqvmInitializing,
    AegisPqvmReady,
    ConnectingToTestnet,
    SyncingFromGenesis,
    SyncingFromSnapshot,
    VerifyingChain,
    ArchiveReady,
    CreatingSnapshot,
    ServingSnapshots,
    Degraded,
    FailedClosed,
}

impl ArchiveNodeStatus {
    pub fn can_serve_snapshots(&self) -> bool {
        matches!(self, Self::ArchiveReady | Self::ServingSnapshots)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveValidatorConfig {
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub role: String,
    pub snapshot_interval_blocks: u64,
    pub snapshot_chunk_size_bytes: u64,
    pub retain_verified_snapshots_per_class: usize,
    pub fail_closed_on_verification_error: bool,
    pub archive_peer_key_role: AegisPqKeyRole,
    pub snapshot_signing_key_role: AegisPqKeyRole,
}

impl ArchiveValidatorConfig {
    pub fn testnet_default() -> Self {
        Self {
            chain_id: ChainId::synergy_testnet_v2(),
            network_id: NetworkId::synergy_testnet_v2(),
            role: "ARCHIVE_OBSERVER".to_string(),
            snapshot_interval_blocks: ARCHIVE_SNAPSHOT_INTERVAL_BLOCKS,
            snapshot_chunk_size_bytes: ARCHIVE_SNAPSHOT_CHUNK_SIZE_BYTES,
            retain_verified_snapshots_per_class: ARCHIVE_SNAPSHOT_RETENTION_PER_CLASS,
            fail_closed_on_verification_error: true,
            archive_peer_key_role: AegisPqKeyRole::ArchivePeer,
            snapshot_signing_key_role: AegisPqKeyRole::ArchiveSnapshotSigner,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        self.chain_id.require_testnet_v2()?;
        self.network_id.require_testnet_v2()?;
        if self.role != "ARCHIVE_OBSERVER" && self.role != "ARCHIVE_VALIDATOR_NON_CONSENSUS" {
            return Err(
                "archive validator package must use a non-consensus archive role".to_string(),
            );
        }
        if self.snapshot_interval_blocks != ARCHIVE_SNAPSHOT_INTERVAL_BLOCKS {
            return Err("testnet archive snapshot interval must be 5000 blocks".to_string());
        }
        if self.snapshot_chunk_size_bytes != ARCHIVE_SNAPSHOT_CHUNK_SIZE_BYTES {
            return Err("testnet archive snapshot chunks must be 512 MiB".to_string());
        }
        if self.retain_verified_snapshots_per_class != ARCHIVE_SNAPSHOT_RETENTION_PER_CLASS {
            return Err(
                "testnet archive must retain the latest 2 verified snapshots per class".to_string(),
            );
        }
        if !self.fail_closed_on_verification_error {
            return Err("archive validator must fail closed on verification error".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub snapshot_version: u32,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub genesis_hash: Hash,
    pub snapshot_height: Height,
    pub snapshot_block_id: String,
    pub snapshot_block_hash: Hash,
    pub snapshot_parent_hash: Hash,
    pub snapshot_state_root: Hash,
    pub snapshot_receipt_root: Hash,
    pub snapshot_qc_hash: Hash,
    pub snapshot_epoch: crate::synergy_types::Epoch,
    pub snapshot_cluster_id: ClusterId,
    pub active_validator_set_hash: Hash,
    pub eligible_validator_set_hash: Hash,
    pub cluster_map_hash: Hash,
    pub proposer_schedule_hash: Hash,
    pub protocol_config_hash: Hash,
    pub aegis_pqvm_version: String,
    pub archive_node_id: String,
    pub archive_node_role: String,
    pub archive_node_aegis_key_id: AegisPqKeyId,
    pub snapshot_signing_key_id: AegisPqKeyId,
    pub created_at_unix_ms: u64,
    pub snapshot_interval_blocks: u64,
    pub previous_snapshot_height: Height,
    pub previous_snapshot_manifest_hash: Hash,
    pub content_root: Hash,
    pub chunk_hashes_root: Hash,
    pub state_db_format_version: String,
    pub block_store_format_version: String,
    pub compression_algorithm: String,
    pub chunk_size_bytes: u64,
    pub total_uncompressed_bytes: u64,
    pub total_compressed_bytes: u64,
    pub required_replay_start_height: Height,
    pub required_replay_end_height: Height,
    pub manifest_domain_separator: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotCatalogEntry {
    pub height: Height,
    pub manifest_hash: Hash,
    pub content_root: Hash,
    pub state_root: Hash,
    pub download_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotCatalog {
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub genesis_hash: Hash,
    pub archive_node_id: String,
    pub latest_verified_height: Height,
    pub latest_snapshot_height: Height,
    pub snapshots: Vec<SnapshotCatalogEntry>,
    pub catalog_content_root: Hash,
    pub catalog_created_at_unix_ms: u64,
    pub catalog_signature_key_id: AegisPqKeyId,
}

pub struct ArchiveValidatorNode {
    pub config: ArchiveValidatorConfig,
    pub status: ArchiveNodeStatus,
}

impl ArchiveValidatorNode {
    pub fn new(config: ArchiveValidatorConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            config,
            status: ArchiveNodeStatus::Uninitialized,
        })
    }

    pub fn can_vote(&self) -> bool {
        false
    }

    pub fn can_propose(&self) -> bool {
        false
    }

    pub fn can_count_in_qc(&self) -> bool {
        false
    }

    pub fn verify_finalized_qc(
        &self,
        qc: &QuorumCertificate,
        verifier: &AegisPqvmVerifier,
        validator_set: &crate::synergy_types::ValidatorSet,
        cluster_map: &crate::synergy_types::ClusterMap,
    ) -> Result<(), String> {
        self.config.validate()?;
        verifier
            .verify_qc_checked(qc, validator_set, cluster_map)
            .map_err(|error| error.to_string())
    }

    pub fn sign_manifest(
        &self,
        signer: &mut AegisPqvmSigner,
        manifest: &SnapshotManifest,
    ) -> Result<AegisPqSignature, String> {
        self.config.validate()?;
        if manifest.chain_id != self.config.chain_id
            || manifest.network_id != self.config.network_id
        {
            return Err("snapshot manifest chain/network mismatch".to_string());
        }
        signer
            .sign_domain(
                SYNERGY_ARCHIVE_SNAPSHOT_MANIFEST_V1,
                &manifest.canonical_bytes()?,
                &manifest.snapshot_signing_key_id,
            )
            .map_err(|error| error.to_string())
    }

    pub fn sign_catalog(
        &self,
        signer: &mut AegisPqvmSigner,
        catalog: &SnapshotCatalog,
    ) -> Result<AegisPqSignature, String> {
        self.config.validate()?;
        signer
            .sign_domain(
                SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1,
                &catalog.canonical_bytes()?,
                &catalog.catalog_signature_key_id,
            )
            .map_err(|error| error.to_string())
    }
}

pub fn verify_snapshot_manifest(
    manifest: &SnapshotManifest,
    signature: &AegisPqSignature,
    expected_genesis_hash: Hash,
    verifier: &AegisPqvmVerifier,
) -> Result<(), String> {
    manifest.chain_id.require_testnet_v2()?;
    manifest.network_id.require_testnet_v2()?;
    if manifest.genesis_hash != expected_genesis_hash {
        return Err("snapshot genesis_hash mismatch".to_string());
    }
    if manifest.manifest_domain_separator != SYNERGY_ARCHIVE_SNAPSHOT_MANIFEST_V1 {
        return Err("snapshot manifest domain separator mismatch".to_string());
    }
    if manifest.content_root == Hash::zero() {
        return Err("snapshot content_root missing".to_string());
    }
    verifier
        .verify_domain_signature(
            SYNERGY_ARCHIVE_SNAPSHOT_MANIFEST_V1,
            &manifest.canonical_bytes()?,
            &manifest.archive_node_id,
            &manifest.snapshot_signing_key_id,
            manifest.snapshot_epoch,
            AegisPqKeyRole::ArchiveSnapshotSigner,
            signature,
        )
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aegis_pqvm::AegisPqvmSigner;
    use crate::synergy_types::Epoch;
    use std::path::PathBuf;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crate has repository parent")
            .to_path_buf()
    }

    #[test]
    fn archive_node_cannot_vote_propose_or_count_in_qc() {
        let archive = ArchiveValidatorNode::new(ArchiveValidatorConfig::testnet_default()).unwrap();
        assert!(!archive.can_vote());
        assert!(!archive.can_propose());
        assert!(!archive.can_count_in_qc());
    }

    #[test]
    fn archive_config_enforces_testnet_chain_and_network() {
        let mut config = ArchiveValidatorConfig::testnet_default();
        config.chain_id = ChainId(999);
        assert!(ArchiveValidatorNode::new(config).is_err());
        let mut config = ArchiveValidatorConfig::testnet_default();
        config.network_id = NetworkId("wrong".to_string());
        assert!(ArchiveValidatorNode::new(config).is_err());
    }

    #[test]
    fn snapshot_manifest_must_be_signed_with_real_aegis_pqc() {
        let mut signer = AegisPqvmSigner::initialize_required().unwrap();
        let key_id = signer
            .generate_and_register_key(
                "archive-node-1",
                vec![AegisPqKeyRole::ArchiveSnapshotSigner],
                Epoch(0),
            )
            .unwrap();
        let manifest = SnapshotManifest {
            snapshot_version: 1,
            chain_id: ChainId::synergy_testnet_v2(),
            network_id: NetworkId::synergy_testnet_v2(),
            genesis_hash: Hash::from_domain_bytes("genesis", b"test"),
            snapshot_height: Height(10_000),
            snapshot_block_id: "block".to_string(),
            snapshot_block_hash: Hash::from_domain_bytes("block", b"10000"),
            snapshot_parent_hash: Hash::zero(),
            snapshot_state_root: Hash::from_domain_bytes("state", b"10000"),
            snapshot_receipt_root: Hash::zero(),
            snapshot_qc_hash: Hash::from_domain_bytes("qc", b"10000"),
            snapshot_epoch: Epoch(0),
            snapshot_cluster_id: ClusterId(0),
            active_validator_set_hash: Hash::zero(),
            eligible_validator_set_hash: Hash::zero(),
            cluster_map_hash: Hash::zero(),
            proposer_schedule_hash: Hash::zero(),
            protocol_config_hash: Hash::zero(),
            aegis_pqvm_version: "aegis-pqvm".to_string(),
            archive_node_id: "archive-node-1".to_string(),
            archive_node_role: "ARCHIVE_OBSERVER".to_string(),
            archive_node_aegis_key_id: key_id.clone(),
            snapshot_signing_key_id: key_id,
            created_at_unix_ms: 0,
            snapshot_interval_blocks: ARCHIVE_SNAPSHOT_INTERVAL_BLOCKS,
            previous_snapshot_height: Height(0),
            previous_snapshot_manifest_hash: Hash::zero(),
            content_root: Hash::from_domain_bytes("content", b"snapshot"),
            chunk_hashes_root: Hash::from_domain_bytes("chunks", b"snapshot"),
            state_db_format_version: "v1".to_string(),
            block_store_format_version: "v1".to_string(),
            compression_algorithm: "zstd".to_string(),
            chunk_size_bytes: ARCHIVE_SNAPSHOT_CHUNK_SIZE_BYTES,
            total_uncompressed_bytes: 1,
            total_compressed_bytes: 1,
            required_replay_start_height: Height(10_001),
            required_replay_end_height: Height(10_000),
            manifest_domain_separator: SYNERGY_ARCHIVE_SNAPSHOT_MANIFEST_V1.to_string(),
        };
        let archive = ArchiveValidatorNode::new(ArchiveValidatorConfig::testnet_default()).unwrap();
        let sig = archive.sign_manifest(&mut signer, &manifest).unwrap();
        assert!(verify_snapshot_manifest(
            &manifest,
            &sig,
            manifest.genesis_hash,
            &signer.verifier()
        )
        .is_ok());
        let mut corrupted = manifest.clone();
        corrupted.chain_id = ChainId(999);
        assert!(verify_snapshot_manifest(
            &corrupted,
            &sig,
            manifest.genesis_hash,
            &signer.verifier()
        )
        .is_err());
    }

    #[test]
    fn archive_package_contains_required_linux_and_macos_install_assets() {
        let root = repo_root().join("archive-validator");
        for path in [
            "README.md",
            "setup-archive-validator.sh",
            "uninstall-archive-validator.sh",
            "verify-archive-validator-install.sh",
            "package-archive-validator.sh",
            ".env.example",
            "config/archive-validator.testnet.toml",
            "config/snapshot-policy.testnet.toml",
            "config/archive-api.testnet.toml",
            "config/genesis.testnet.json.template",
            "systemd/synergy-archive-validator.service",
            "systemd/synergy-archive-snapshot-api.service",
            "systemd/synergy-archive-snapshot-worker.service",
            "launchd/io.synergynetwork.archive-validator.plist",
            "launchd/io.synergynetwork.archive-snapshot-api.plist",
            "launchd/io.synergynetwork.archive-snapshot-worker.plist",
            "macos/build-macos-pkg.sh",
            "macos/preinstall",
            "macos/postinstall",
            "macos/uninstall-macos.sh",
            "macos/entitlements.plist",
            "macos/README-GATEKEEPER.md",
            "docs/MACOS_INSTALL.md",
            "docs/SNAPSHOT_VERIFICATION.md",
            "bin/README.md",
        ] {
            assert!(
                root.join(path).exists(),
                "missing archive package asset: {path}"
            );
        }
    }

    #[test]
    fn archive_package_scripts_fail_closed_for_artifacts_and_gatekeeper() {
        let root = repo_root().join("archive-validator");
        let package_script = std::fs::read_to_string(root.join("package-archive-validator.sh"))
            .expect("package script");
        assert!(package_script.contains("synergy-archive-validator-testnet-v2-linux-x64.zip"));
        assert!(package_script.contains("synergy-archive-validator-testnet-v2-macos-universal.zip"));
        assert!(package_script.contains("synergy-archive-validator-testnet-v2.zip"));
        assert!(package_script.contains("Refusing to package private keys"));
        assert!(package_script.contains("snapshots"));
        assert!(package_script.contains("evidence"));

        let macos_script =
            std::fs::read_to_string(root.join("macos/build-macos-pkg.sh")).expect("macos script");
        for required in [
            "DEVELOPER_ID_APPLICATION",
            "DEVELOPER_ID_INSTALLER",
            "notarytool submit",
            "stapler staple",
            "spctl --assess",
            "pkgutil --check-signature",
        ] {
            assert!(
                macos_script.contains(required),
                "macOS package script must require {required}"
            );
        }
    }
}
