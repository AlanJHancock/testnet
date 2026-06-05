use synergy_testnet::aegis_tx_tool::{
    build_fixture_report, sign_with_new_aegis_transaction_key, AegisTxBuildOptions,
};
use synergy_testnet::synergy_types::{ChainId, NetworkId};

fn main() {
    if let Err(error) = run() {
        eprintln!("synergy-node failed closed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let command = args.first().map(String::as_str).unwrap_or("help");
    match command {
        "tx" => run_tx_command(&args)?,
        "dag" => run_dag_command(&args)?,
        "recovery" => run_recovery_command(&args)?,
        "diagnose-sync-target" => {
            require_testnet_args(&args)?;
            let rpc_url = arg_value(&args, "--rpc-url")
                .unwrap_or_else(|| "https://testnet-core-rpc.synergy-network.io".to_string());
            let expected_genesis_hash = arg_value(&args, "--expected-genesis-hash");
            let report = diagnose_sync_target(&rpc_url, expected_genesis_hash.as_deref())?;
            println!("{report}");
        }
        "diagnose-consensus-stall" => {
            require_testnet_args(&args)?;
            print_json(
                synergy_testnet::consensus::diagnostics::diagnose_consensus_stall(
                    &synergy_testnet::rpc::rpc_server::SHARED_CHAIN,
                ),
            )?;
        }
        "diagnose-vote-locks" => {
            require_testnet_args(&args)?;
            let finalized_height = optional_u64_arg(&args, "--finalized-height")?;
            print_json(
                synergy_testnet::consensus::diagnostics::diagnose_vote_locks(finalized_height),
            )?;
        }
        "divergence-status" => {
            require_testnet_args(&args)?;
            print_json(synergy_testnet::consensus::diagnostics::divergence_status(
                &synergy_testnet::rpc::rpc_server::SHARED_CHAIN,
            ))?;
        }
        "quarantine-status" => {
            require_testnet_args(&args)?;
            print_json(synergy_testnet::consensus::diagnostics::quarantine_status())?;
        }
        "self-heal-status" => {
            require_testnet_args(&args)?;
            print_json(synergy_testnet::consensus::diagnostics::self_heal_status())?;
        }
        "self-heal" => {
            require_testnet_args(&args)?;
            match synergy_testnet::consensus::diagnostics::start_self_heal() {
                Ok(report) => print_json(report)?,
                Err(error) => return Err(error),
            }
        }
        "recover-transient-vote-locks" => {
            require_testnet_args(&args)?;
            let finalized_height = optional_u64_arg(&args, "--finalized-height")?;
            let min_age_secs = optional_u64_arg(&args, "--min-age-secs")?.unwrap_or(0);
            let reason = arg_value(&args, "--reason")
                .unwrap_or_else(|| "operator_cli_recover_transient_vote_locks".to_string());
            let report = synergy_testnet::consensus::diagnostics::recover_transient_vote_locks(
                finalized_height,
                min_age_secs,
                &reason,
            )?;
            print_json(report)?;
        }
        "sync-from-canonical-peer" => {
            require_testnet_args(&args)?;
            let options = synergy_testnet::consensus::diagnostics::SyncFromCanonicalPeerOptions {
                canonical_height: optional_u64_arg(&args, "--canonical-height")?,
                canonical_hash: arg_value(&args, "--canonical-hash"),
                source_peer: arg_value(&args, "--source-peer"),
                source_qc_aegis_pqc_verified: arg_flag(&args, "--source-qc-aegis-pqc-verified"),
                parent_continuity_verified: arg_flag(&args, "--parent-continuity-verified"),
                state_root_matches: arg_flag(&args, "--state-root-matches"),
                source_peer_quarantined: !arg_flag(&args, "--source-peer-not-quarantined"),
            };
            match synergy_testnet::consensus::diagnostics::sync_from_canonical_peer_with_options(
                options,
            ) {
                Ok(report) => print_json(report)?,
                Err(error) => return Err(error),
            }
        }
        "create-snapshot" => {
            require_testnet_args(&args)?;
            let options = synergy_testnet::consensus::diagnostics::CreateSnapshotOptions {
                source_node_majority_branch_proven: arg_flag(
                    &args,
                    "--source-node-majority-branch-proven",
                ),
                source_role: arg_value(&args, "--source-role"),
                conflict_height_hash: arg_value(&args, "--conflict-height-hash"),
                snapshot_class: arg_value(&args, "--snapshot-class"),
                allowed_restore_roles: arg_values(&args, "--allowed-role"),
            };
            match synergy_testnet::consensus::diagnostics::create_snapshot_with_options(options) {
                Ok(report) => print_json(report)?,
                Err(error) => return Err(error),
            }
        }
        "list-snapshots" => {
            require_testnet_args(&args)?;
            print_json(synergy_testnet::consensus::diagnostics::list_snapshots())?;
        }
        "verify-snapshot" => {
            require_testnet_args(&args)?;
            let manifest = arg_value(&args, "--manifest")
                .or_else(|| arg_value(&args, "--manifest-path"))
                .ok_or_else(|| "verify-snapshot requires --manifest <path>".to_string())?;
            let snapshot_root = arg_value(&args, "--snapshot-root");
            let report = synergy_testnet::consensus::diagnostics::verify_snapshot_with_options(
                &manifest,
                snapshot_root.as_deref(),
                synergy_testnet::consensus::diagnostics::VerifySnapshotOptions {
                    snapshot_class: arg_value(&args, "--snapshot-class"),
                    target_role: arg_value(&args, "--target-role"),
                },
            )?;
            print_json(report)?;
        }
        "self-heal-from-snapshot" => {
            require_testnet_args(&args)?;
            let manifest = arg_value(&args, "--manifest")
                .or_else(|| arg_value(&args, "--manifest-path"))
                .ok_or_else(|| "self-heal-from-snapshot requires --manifest <path>".to_string())?;
            let snapshot_root = arg_value(&args, "--snapshot-root");
            let report = synergy_testnet::consensus::diagnostics::self_heal_from_snapshot(
                &manifest,
                snapshot_root.as_deref(),
            )?;
            print_json(report)?;
        }
        "quarantine-stopped-validator" => {
            require_testnet_args(&args)?;
            let options = synergy_testnet::consensus::diagnostics::OperatorQuarantineOptions {
                reason: arg_value(&args, "--reason"),
                target_stopped: arg_flag(&args, "--target-stopped"),
                operator_approved_containment: arg_flag(&args, "--operator-approved-containment"),
                quorum_majority_height: optional_u64_arg(&args, "--quorum-majority-height")?,
                quorum_majority_hash: arg_value(&args, "--quorum-majority-hash"),
                local_conflicting_height: optional_u64_arg(&args, "--local-conflicting-height")?,
                local_conflicting_hash: arg_value(&args, "--local-conflicting-hash"),
            };
            let report =
                synergy_testnet::consensus::diagnostics::quarantine_stopped_validator_with_options(
                    options,
                )?;
            print_json(report)?;
        }
        "start-shadow-observe" => {
            require_testnet_args(&args)?;
            let options = synergy_testnet::consensus::diagnostics::StartShadowObserveOptions {
                required_blocks: optional_u64_arg(&args, "--required-blocks")?,
            };
            match synergy_testnet::consensus::diagnostics::start_shadow_observe_with_options(
                options,
            ) {
                Ok(report) => print_json(report)?,
                Err(error) => return Err(error),
            }
        }
        "shadow-status" => {
            require_testnet_args(&args)?;
            print_json(synergy_testnet::consensus::diagnostics::shadow_status())?;
        }
        "rejoin-eligibility" => {
            require_testnet_args(&args)?;
            print_json(synergy_testnet::consensus::diagnostics::rejoin_eligibility())?;
        }
        "request-rejoin" => {
            require_testnet_args(&args)?;
            let options = synergy_testnet::consensus::diagnostics::RejoinRequestOptions {
                common_height: optional_u64_arg(&args, "--common-height")?,
                common_hash: arg_value(&args, "--common-hash"),
                exact_common_height_match: arg_flag(&args, "--exact-common-height-match"),
                latest_finalized_qc_aegis_pqc_verified: arg_flag(
                    &args,
                    "--latest-finalized-qc-aegis-pqc-verified",
                ),
                state_root_matches: arg_flag(&args, "--state-root-matches"),
                rejoin_at_finalized_safe_boundary: arg_flag(
                    &args,
                    "--rejoin-at-finalized-safe-boundary",
                ),
                cluster_marks_pending_reactivation: arg_flag(
                    &args,
                    "--cluster-marks-pending-reactivation",
                ),
                operator_approved_reactivation: arg_flag(&args, "--operator-approved-reactivation"),
            };
            match synergy_testnet::consensus::diagnostics::request_rejoin_with_options(options) {
                Ok(report) => print_json(report)?,
                Err(error) => return Err(error),
            }
        }
        "sync-from-archive" | "self-heal-from-archive" => {
            require_testnet_args(&args)?;
            let archive_url = arg_value(&args, "--archive-url")
                .ok_or_else(|| format!("{command} requires --archive-url <url>"))?;
            let expected_genesis_hash = arg_value(&args, "--expected-genesis-hash")
                .ok_or_else(|| format!("{command} requires --expected-genesis-hash <hash>"))?;
            if command == "self-heal-from-archive" {
                arg_value(&args, "--divergence-height").ok_or_else(|| {
                    "self-heal-from-archive requires --divergence-height <height>".to_string()
                })?;
            }
            return Err(format!(
                "{command} is not yet wired to install archive state. Refusing to mutate local chain data from {archive_url} with expected_genesis_hash={expected_genesis_hash} until catalog, manifest, content root, state root, chunks, and every QC are verified through aegis-pqvm."
            ));
        }
        _ => {
            println!("Commands:");
            println!("  synergy-node tx create-aegis --chain-id 1264 --network-id synergy-testnet-v2 [tx options]");
            println!("  synergy-node tx sign-aegis --chain-id 1264 --network-id synergy-testnet-v2 [tx options]");
            println!("  synergy-node tx submit-aegis --chain-id 1264 --network-id synergy-testnet-v2 [tx options]");
            println!("  synergy-node dag submit-test-fixture --real-aegis-pqvm --chain-id 1264 --network-id synergy-testnet-v2");
            println!(
                "  synergy-node recovery status --chain-id 1264 --network-id synergy-testnet-v2"
            );
            println!("  synergy-node recovery inspect-divergence --target-node-id <id> --target-role validator|relayer|rpc|archive --target-data-dir <dir> --source-state-dir <dir> --chain-id 1264 --network-id synergy-testnet-v2");
            println!("  synergy-node recovery build-plan --target-node-id <id> --target-role validator|relayer|rpc|archive --target-data-dir <dir> --source-state-dir <dir> --source-node <validator-id>... --evidence-path <dir> --rollback-path <dir> --output <plan.json> --chain-id 1264 --network-id synergy-testnet-v2");
            println!("  synergy-node recovery verify-plan --plan <plan.json> --chain-id 1264 --network-id synergy-testnet-v2");
            println!("  synergy-node recovery apply-plan --plan <plan.json> --confirm-target-stopped --chain-id 1264 --network-id synergy-testnet-v2");
            println!("  synergy-node diagnose-sync-target --rpc-url <url> --chain-id 1264 --network-id synergy-testnet-v2 [--expected-genesis-hash <hash>]");
            println!("  synergy-node diagnose-consensus-stall --chain-id 1264 --network-id synergy-testnet-v2");
            println!("  synergy-node diagnose-vote-locks --chain-id 1264 --network-id synergy-testnet-v2 [--finalized-height <height>]");
            println!(
                "  synergy-node divergence-status --chain-id 1264 --network-id synergy-testnet-v2"
            );
            println!(
                "  synergy-node quarantine-status --chain-id 1264 --network-id synergy-testnet-v2"
            );
            println!(
                "  synergy-node self-heal-status --chain-id 1264 --network-id synergy-testnet-v2"
            );
            println!("  synergy-node recover-transient-vote-locks --chain-id 1264 --network-id synergy-testnet-v2 [--finalized-height <height>] [--min-age-secs <seconds>]");
            println!("  synergy-node self-heal --chain-id 1264 --network-id synergy-testnet-v2");
            println!("  synergy-node sync-from-canonical-peer --chain-id 1264 --network-id synergy-testnet-v2 --canonical-height <height> --canonical-hash <hash> --source-qc-aegis-pqc-verified --parent-continuity-verified --state-root-matches --source-peer-not-quarantined [--source-peer <id>]");
            println!("  synergy-node create-snapshot --chain-id 1264 --network-id synergy-testnet-v2 --source-node-majority-branch-proven [--source-role GENESIS_VALIDATOR] [--snapshot-class validator-pruned|support-relayer|support-rpc|indexer-replay|indexer-full|archive-full|archive-bootstrap] [--allowed-role <role> ...] [--conflict-height-hash <hash>]");
            println!(
                "  synergy-node list-snapshots --chain-id 1264 --network-id synergy-testnet-v2"
            );
            println!("  synergy-node verify-snapshot --manifest <path> --chain-id 1264 --network-id synergy-testnet-v2 [--snapshot-root <dir>] [--snapshot-class <class>] [--target-role <role>]");
            println!("  synergy-node self-heal-from-snapshot --manifest <path> --chain-id 1264 --network-id synergy-testnet-v2 [--snapshot-root <dir>]");
            println!("  synergy-node quarantine-stopped-validator --chain-id 1264 --network-id synergy-testnet-v2 --target-stopped --operator-approved-containment --quorum-majority-height <height> --quorum-majority-hash <hash> [--local-conflicting-height <height>] [--local-conflicting-hash <hash>]");
            println!("  synergy-node start-shadow-observe --chain-id 1264 --network-id synergy-testnet-v2 [--required-blocks <blocks>]");
            println!(
                "  synergy-node shadow-status --chain-id 1264 --network-id synergy-testnet-v2"
            );
            println!(
                "  synergy-node rejoin-eligibility --chain-id 1264 --network-id synergy-testnet-v2"
            );
            println!(
                "  synergy-node request-rejoin --chain-id 1264 --network-id synergy-testnet-v2 --common-height <height> --common-hash <hash> --exact-common-height-match --latest-finalized-qc-aegis-pqc-verified --state-root-matches --rejoin-at-finalized-safe-boundary --cluster-marks-pending-reactivation --operator-approved-reactivation"
            );
            println!("  synergy-node sync-from-archive --archive-url <url> --chain-id 1264 --network-id synergy-testnet-v2 --expected-genesis-hash <hash>");
            println!("  synergy-node self-heal-from-archive --archive-url <url> --divergence-height <height> --chain-id 1264 --network-id synergy-testnet-v2 --expected-genesis-hash <hash>");
        }
    }
    Ok(())
}

fn run_recovery_command(args: &[String]) -> Result<(), String> {
    let subcommand = args.get(1).map(String::as_str).unwrap_or("help");
    match subcommand {
        "status" => {
            require_testnet_args(args)?;
            print_json(synergy_testnet::recovery::status())?;
        }
        "inspect-divergence" => {
            require_testnet_args(args)?;
            let input = recovery_build_input_from_args(args)?;
            print_json(synergy_testnet::recovery::inspect_divergence(&input))?;
        }
        "build-plan" => {
            require_testnet_args(args)?;
            let input = recovery_build_input_from_args(args)?;
            let plan = synergy_testnet::recovery::build_plan(input);
            if let Some(output) = arg_value(args, "--output") {
                synergy_testnet::recovery::write_plan(&plan, std::path::Path::new(&output))?;
            }
            print_json(
                serde_json::to_value(&plan)
                    .map_err(|error| format!("serialize recovery plan: {error}"))?,
            )?;
        }
        "verify-plan" => {
            require_testnet_args(args)?;
            let plan_path = arg_value(args, "--plan")
                .ok_or_else(|| "recovery verify-plan requires --plan <plan.json>".to_string())?;
            let content = std::fs::read_to_string(&plan_path)
                .map_err(|error| format!("read recovery plan {plan_path}: {error}"))?;
            let plan: synergy_testnet::recovery::RecoveryPlan = serde_json::from_str(&content)
                .map_err(|error| format!("parse recovery plan {plan_path}: {error}"))?;
            let verification = synergy_testnet::recovery::verify_plan(&plan);
            print_json(
                serde_json::to_value(&verification)
                    .map_err(|error| format!("serialize recovery verification: {error}"))?,
            )?;
            if !verification.valid_for_apply {
                return Err("recovery plan is not valid for apply".to_string());
            }
        }
        "apply-plan" => {
            require_testnet_args(args)?;
            let plan_path = arg_value(args, "--plan")
                .ok_or_else(|| "recovery apply-plan requires --plan <plan.json>".to_string())?;
            let result =
                synergy_testnet::recovery::apply_plan(synergy_testnet::recovery::ApplyPlanInput {
                    plan_path: std::path::PathBuf::from(plan_path),
                    confirm_target_stopped: args.iter().any(|arg| {
                        arg == "--confirm-target-stopped" || arg == "--confirm-target-quarantined"
                    }),
                })?;
            print_json(
                serde_json::to_value(&result)
                    .map_err(|error| format!("serialize recovery apply result: {error}"))?,
            )?;
        }
        _ => {
            println!("Recovery commands:");
            println!(
                "  synergy-node recovery status --chain-id 1264 --network-id synergy-testnet-v2"
            );
            println!("  synergy-node recovery inspect-divergence --target-node-id <id> --target-role validator|relayer|rpc|archive --target-data-dir <dir> --source-state-dir <dir> --chain-id 1264 --network-id synergy-testnet-v2");
            println!("  synergy-node recovery build-plan --target-node-id <id> --target-role validator|relayer|rpc|archive --target-data-dir <dir> --source-state-dir <dir> --source-node <validator-id>... --evidence-path <dir> --rollback-path <dir> --output <plan.json> --chain-id 1264 --network-id synergy-testnet-v2");
            println!("  synergy-node recovery verify-plan --plan <plan.json> --chain-id 1264 --network-id synergy-testnet-v2");
            println!("  synergy-node recovery apply-plan --plan <plan.json> --confirm-target-stopped --chain-id 1264 --network-id synergy-testnet-v2");
        }
    }
    Ok(())
}

fn recovery_build_input_from_args(
    args: &[String],
) -> Result<synergy_testnet::recovery::BuildPlanInput, String> {
    let target_node_id = arg_value(args, "--target-node-id")
        .ok_or_else(|| "missing --target-node-id <id>".to_string())?;
    let target_role = parse_recovery_target_role(
        &arg_value(args, "--target-role")
            .ok_or_else(|| "missing --target-role validator|relayer|rpc|archive".to_string())?,
    )?;
    let chain_id = arg_value(args, "--chain-id")
        .ok_or_else(|| "missing --chain-id 1264".to_string())?
        .parse::<u64>()
        .map_err(|error| format!("invalid --chain-id: {error}"))?;
    let network_id = arg_value(args, "--network-id")
        .ok_or_else(|| "missing --network-id synergy-testnet-v2".to_string())?;
    let target_data_dir = std::path::PathBuf::from(
        arg_value(args, "--target-data-dir").unwrap_or_else(|| "data".to_string()),
    );
    let source_state_dir = arg_value(args, "--source-state-dir").map(std::path::PathBuf::from);
    let source_evidence_dirs = arg_values(args, "--source-evidence-dir")
        .into_iter()
        .map(std::path::PathBuf::from)
        .collect();
    let evidence_path =
        std::path::PathBuf::from(arg_value(args, "--evidence-path").unwrap_or_else(|| {
            format!(
                "data/recovery-evidence/{}",
                chrono::Utc::now().format("%Y%m%dT%H%M%SZ")
            )
        }));
    let rollback_path =
        std::path::PathBuf::from(arg_value(args, "--rollback-path").unwrap_or_else(|| {
            format!(
                "data/recovery-rollback/{}",
                chrono::Utc::now().format("%Y%m%dT%H%M%SZ")
            )
        }));
    Ok(synergy_testnet::recovery::BuildPlanInput {
        target_node_id,
        target_role,
        chain_id,
        network_id,
        genesis_hash: arg_value(args, "--expected-genesis-hash")
            .unwrap_or_else(|| synergy_testnet::recovery::EXPECTED_GENESIS_HASH.to_string()),
        target_data_dir,
        source_state_dir,
        source_evidence_dirs,
        source_nodes_used: arg_values(args, "--source-node"),
        source_common_height: optional_u64_arg(args, "--source-common-height")?,
        source_common_hash: arg_value(args, "--source-common-hash"),
        source_canonical_lock_height: optional_u64_arg(args, "--source-canonical-lock-height")?,
        source_canonical_lock_hash: arg_value(args, "--source-canonical-lock-hash"),
        target_runtime_sha256: arg_value(args, "--target-runtime-sha256").unwrap_or_default(),
        evidence_path,
        rollback_path,
        recovery_type: arg_value(args, "--recovery-type")
            .map(|value| parse_recovery_type(&value))
            .transpose()?,
        conflict_height: optional_u64_arg(args, "--conflict-height")?,
        expected_target_conflict_hash: arg_value(args, "--expected-target-conflict-hash"),
        expected_source_conflict_hash: arg_value(args, "--expected-source-conflict-hash"),
        target_stopped_or_quarantined: args.iter().any(|arg| {
            arg == "--target-stopped-or-quarantined"
                || arg == "--target-stopped"
                || arg == "--target-quarantined"
        }),
    })
}

fn parse_recovery_target_role(
    value: &str,
) -> Result<synergy_testnet::recovery::TargetRole, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "validator" => Ok(synergy_testnet::recovery::TargetRole::Validator),
        "relayer" => Ok(synergy_testnet::recovery::TargetRole::Relayer),
        "rpc" | "rpc-gateway" | "rpc_gateway" => Ok(synergy_testnet::recovery::TargetRole::Rpc),
        "archive" => Ok(synergy_testnet::recovery::TargetRole::Archive),
        other => Err(format!("unsupported --target-role {other}")),
    }
}

fn parse_recovery_type(value: &str) -> Result<synergy_testnet::recovery::RecoveryType, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "no_action" | "no-action" => Ok(synergy_testnet::recovery::RecoveryType::NoAction),
        "transient_cache_prune" | "transient-cache-prune" => {
            Ok(synergy_testnet::recovery::RecoveryType::TransientCachePrune)
        }
        "canonical_state_reconcile" | "canonical-state-reconcile" => {
            Ok(synergy_testnet::recovery::RecoveryType::CanonicalStateReconcile)
        }
        "support_chain_fast_sync" | "support-chain-fast-sync" => {
            Ok(synergy_testnet::recovery::RecoveryType::SupportChainFastSync)
        }
        "archive_snapshot_restore" | "archive-snapshot-restore" => {
            Ok(synergy_testnet::recovery::RecoveryType::ArchiveSnapshotRestore)
        }
        "unsafe_requires_operator_approval" | "unsafe-requires-operator-approval" => {
            Ok(synergy_testnet::recovery::RecoveryType::UnsafeRequiresOperatorApproval)
        }
        other => Err(format!("unsupported --recovery-type {other}")),
    }
}

fn run_tx_command(args: &[String]) -> Result<(), String> {
    require_testnet_args(args)?;
    let subcommand = args.get(1).map(String::as_str).unwrap_or("help");
    match subcommand {
        "create-aegis" | "sign-aegis" => {
            let report = sign_with_new_aegis_transaction_key(tx_options_from_args(args)?)?;
            let mut output = signed_tx_summary(subcommand, &report);
            if args.iter().any(|arg| arg == "--include-signed-transaction") {
                output["signed_transaction"] = serde_json::to_value(&report.transaction)
                    .map_err(|error| format!("failed to serialize signed transaction: {error}"))?;
                output["canonical_tx_bytes_hex"] =
                    serde_json::Value::String(report.canonical_tx_bytes_hex);
            }
            print_json(output)?;
        }
        "submit-aegis" => {
            let report = sign_with_new_aegis_transaction_key(tx_options_from_args(args)?)?;
            let mut output = signed_tx_summary(subcommand, &report);
            if let Some(rpc_url) = arg_value(args, "--rpc-url") {
                let response = submit_aegis_transaction(
                    &rpc_url,
                    "synergy_submitAegisDagTransaction",
                    &report.submission_envelope,
                )?;
                output["live_submission_status"] =
                    serde_json::Value::String("submitted_to_rpc".to_string());
                output["rpc_url"] = serde_json::Value::String(rpc_url);
                output["rpc_response"] = response;
            } else {
                output["live_submission_status"] = serde_json::Value::String(
                    "not_attempted: pass --rpc-url to submit through synergy_submitAegisTransaction"
                        .to_string(),
                );
            }
            print_json(output)?;
        }
        _ => {
            println!("Commands:");
            println!("  synergy-node tx create-aegis --chain-id 1264 --network-id synergy-testnet-v2 [--sender <uma>] [--receiver <uma>] [--nonce <n>] [--amount-nwei <n>] [--gas-limit <n>] [--max-fee-nwei <n>] [--ttl-height <h>] [--read <key>] [--write <key>] [--dependency <tx_id>] [--payload <text>]");
            println!("  synergy-node tx sign-aegis --chain-id 1264 --network-id synergy-testnet-v2 [same options]");
            println!("  synergy-node tx submit-aegis --chain-id 1264 --network-id synergy-testnet-v2 [same options]");
        }
    }
    Ok(())
}

fn run_dag_command(args: &[String]) -> Result<(), String> {
    require_testnet_args(args)?;
    let subcommand = args.get(1).map(String::as_str).unwrap_or("help");
    match subcommand {
        "submit-test-fixture" => {
            if !args.iter().any(|arg| arg == "--real-aegis-pqvm") {
                return Err(
                    "dag submit-test-fixture requires --real-aegis-pqvm; wallet CLI and demo data paths are refused"
                        .to_string(),
                );
            }
            let report = build_fixture_report()?;
            let rpc_url = arg_value(args, "--rpc-url");
            let rpc_submissions = if let Some(rpc_url) = rpc_url.as_deref() {
                report
                    .transactions
                    .iter()
                    .map(|tx| {
                        submit_aegis_transaction(
                            rpc_url,
                            "synergy_submitAegisDagTransaction",
                            &tx.submission_envelope,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                Vec::new()
            };
            print_json(serde_json::json!({
                "command": subcommand,
                "aegis_pqvm_path": "synergy_testnet::crypto::aegis_pqvm::AegisPqvmSigner",
                "wallet_cli_used": false,
                "demo_data_used": false,
                "chain_id": report.chain_id,
                "network_id": report.network_id,
                "key_id": report.key_id,
                "key_role": report.key_role,
                "transactions": report.transactions.iter().map(|tx| {
                    serde_json::json!({
                        "tx_id": tx.tx_id,
                        "key_id": tx.key_id,
                        "key_role": tx.key_role,
                        "signature_verification_result": tx.signature_verification_result,
                        "dag_node_id": tx.dag_node_id,
                        "admission_result": tx.admission_result,
                        "signature_bytes_len": tx.transaction.aegis_pq_signature.signature_bytes.len(),
                    })
                }).collect::<Vec<_>>(),
                "ready_frontier": report.ready_frontier,
                "selected_ancestor_closed_set": report.selected_ancestor_closed_set,
                "tx_order_root": report.tx_order_root,
                "dag_frontier_root": report.dag_frontier_root,
                "live_submission_status": if rpc_url.is_some() { "submitted_to_rpc" } else { "not_attempted: pass --rpc-url to submit through synergy_submitAegisDagTransaction" },
                "rpc_url": rpc_url,
                "rpc_submissions": rpc_submissions,
                "atlas_ingestion_status": if rpc_submissions.is_empty() { report.atlas_ingestion_status } else { "submitted_to_rpc: verify finalized block inclusion and Atlas DAG API from canonical chain data".to_string() },
            }))?;
        }
        _ => {
            println!("Commands:");
            println!("  synergy-node dag submit-test-fixture --real-aegis-pqvm --chain-id 1264 --network-id synergy-testnet-v2 [--rpc-url <url>]");
        }
    }
    Ok(())
}

fn signed_tx_summary(
    command: &str,
    report: &synergy_testnet::aegis_tx_tool::AegisSignedTxReport,
) -> serde_json::Value {
    serde_json::json!({
        "command": command,
        "aegis_pqvm_path": "synergy_testnet::crypto::aegis_pqvm::AegisPqvmSigner",
        "wallet_cli_used": false,
        "tx_id": report.tx_id,
        "key_id": report.key_id,
        "key_role": report.key_role,
        "signature_verification_result": report.signature_verification_result,
        "dag_node_id": report.dag_node_id,
        "admission_result": report.admission_result,
        "signature_bytes_len": report.transaction.aegis_pq_signature.signature_bytes.len(),
        "chain_id": report.transaction.chain_id.0,
        "network_id": report.transaction.network_id.0,
        "sender": report.transaction.sender_uma_or_account,
        "receiver": report.transaction.receiver_uma_or_account,
        "aegis_public_key": report.public_key,
        "key_lifecycle_record": report.lifecycle_record,
        "rpc_transaction": report.rpc_transaction,
    })
}

fn print_json(value: serde_json::Value) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(&value)
            .map_err(|error| format!("failed to serialize JSON report: {error}"))?
    );
    Ok(())
}

fn submit_aegis_transaction(
    rpc_url: &str,
    method: &str,
    envelope: &synergy_testnet::aegis_tx_tool::AegisTxSubmissionEnvelope,
) -> Result<serde_json::Value, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|error| format!("failed to initialize RPC client: {error}"))?;
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": [envelope],
    });
    let response = client
        .post(rpc_url)
        .json(&request)
        .send()
        .map_err(|error| format!("failed to submit Aegis transaction to {rpc_url}: {error}"))?;
    let status = response.status();
    let value = response
        .json::<serde_json::Value>()
        .map_err(|error| format!("failed to parse RPC response: {error}"))?;
    if !status.is_success() {
        return Err(format!("RPC returned HTTP {status}: {value}"));
    }
    Ok(value)
}

fn tx_options_from_args(args: &[String]) -> Result<AegisTxBuildOptions, String> {
    let mut options = AegisTxBuildOptions::default();
    if let Some(sender) = arg_value(args, "--sender") {
        options.sender = sender.clone();
        options.signer_uma_id = sender;
    }
    if let Some(signer_uma_id) = arg_value(args, "--signer-uma-id") {
        options.signer_uma_id = signer_uma_id;
    }
    if let Some(receiver) = arg_value(args, "--receiver") {
        options.receiver = receiver;
    }
    if let Some(nonce) = arg_value(args, "--nonce") {
        options.nonce = nonce
            .parse::<u64>()
            .map_err(|error| format!("invalid --nonce: {error}"))?;
    }
    if let Some(amount) = arg_value(args, "--amount-nwei") {
        options.amount_nwei = amount
            .parse::<u128>()
            .map_err(|error| format!("invalid --amount-nwei: {error}"))?;
    }
    if let Some(gas_limit) = arg_value(args, "--gas-limit") {
        options.gas_limit = gas_limit
            .parse::<u64>()
            .map_err(|error| format!("invalid --gas-limit: {error}"))?;
    }
    if let Some(max_fee) = arg_value(args, "--max-fee-nwei") {
        options.max_fee_nwei = max_fee
            .parse::<u128>()
            .map_err(|error| format!("invalid --max-fee-nwei: {error}"))?;
    }
    if let Some(ttl) = arg_value(args, "--ttl-height") {
        options.ttl_height = ttl
            .parse::<u64>()
            .map_err(|error| format!("invalid --ttl-height: {error}"))?;
    }
    if let Some(epoch) = arg_value(args, "--epoch") {
        options.epoch = epoch
            .parse::<u64>()
            .map_err(|error| format!("invalid --epoch: {error}"))?;
    }
    if let Some(payload) = arg_value(args, "--payload") {
        options.payload = payload.into_bytes();
    }
    options.read_set_hint = arg_values(args, "--read");
    let writes = arg_values(args, "--write");
    if !writes.is_empty() {
        options.write_set_hint = writes;
    }
    options.explicit_dependencies = arg_values(args, "--dependency");
    Ok(options)
}

fn diagnose_sync_target(
    rpc_url: &str,
    expected_genesis_hash: Option<&str>,
) -> Result<String, String> {
    let chain_id_result = rpc_call(rpc_url, "synergy_getChainId", serde_json::json!([]));
    let node_info_result = rpc_call(rpc_url, "synergy_nodeInfo", serde_json::json!([]));
    let latest_block_result = rpc_call(rpc_url, "synergy_getLatestBlock", serde_json::json!([]));
    let genesis_block_result =
        rpc_call(rpc_url, "synergy_getBlockByNumber", serde_json::json!([0]));
    let height_result = rpc_call(rpc_url, "synergy_blockNumber", serde_json::json!([]))
        .or_else(|_| rpc_call(rpc_url, "synergy_getBlockNumber", serde_json::json!([])));

    let chain_id = chain_id_result
        .as_ref()
        .ok()
        .and_then(parse_u64ish)
        .or_else(|| {
            node_info_result
                .as_ref()
                .ok()
                .and_then(|value| {
                    value
                        .get("chainId")
                        .or_else(|| value.get("chain_id"))
                        .cloned()
                })
                .and_then(|value| parse_u64ish(&value))
        });
    let reported_network_id = node_info_result
        .as_ref()
        .ok()
        .and_then(|value| {
            value
                .get("networkId")
                .or_else(|| value.get("network_id"))
                .cloned()
        })
        .and_then(|value| {
            value
                .as_str()
                .map(str::to_string)
                .or_else(|| Some(value.to_string()))
        });
    let latest_height = height_result
        .as_ref()
        .ok()
        .and_then(parse_u64ish)
        .or_else(|| {
            latest_block_result
                .as_ref()
                .ok()
                .and_then(|value| {
                    value
                        .get("block_index")
                        .or_else(|| value.get("height"))
                        .cloned()
                })
                .and_then(|value| parse_u64ish(&value))
        });
    let latest_hash = latest_block_result
        .as_ref()
        .ok()
        .and_then(|value| value.get("hash").and_then(serde_json::Value::as_str))
        .map(str::to_string);
    let genesis_hash = genesis_block_result
        .as_ref()
        .ok()
        .and_then(block_hash_from_value)
        .or_else(|| {
            latest_block_result
                .as_ref()
                .ok()
                .and_then(|value| {
                    value
                        .get("genesis_hash")
                        .or_else(|| value.get("genesisHash"))
                        .and_then(serde_json::Value::as_str)
                })
                .map(str::to_string)
        });
    let genesis_verified = match (expected_genesis_hash, genesis_hash.as_deref()) {
        (Some(expected), Some(actual)) => actual.eq_ignore_ascii_case(expected),
        (Some(_), None) => false,
        (None, Some(_)) => true,
        (None, None) => false,
    };
    let canonical_network_id = genesis_verified.then(|| "synergy-testnet-v2".to_string());
    let usable = chain_id == Some(1264)
        && canonical_network_id.as_deref() == Some("synergy-testnet-v2")
        && latest_height.is_some()
        && genesis_verified;

    Ok(serde_json::json!({
        "source": "rpc",
        "source_url": rpc_url,
        "chain_id": chain_id,
        "network_id": canonical_network_id,
        "reported_network_id": reported_network_id,
        "genesis_hash": genesis_hash,
        "expected_genesis_hash": expected_genesis_hash,
        "genesis_verified": genesis_verified,
        "latest_height": latest_height,
        "latest_hash": latest_hash,
        "latest_qc_hash": latest_block_result
            .as_ref()
            .ok()
            .and_then(|value| value.get("qc_hash").or_else(|| value.get("latest_qc_hash")).cloned()),
        "verification_result": if usable { "accepted" } else { "rejected" },
        "usable_for_sync_target": usable,
        "errors": {
            "chain_id": chain_id_result.err(),
            "node_info": node_info_result.err(),
            "genesis_block": genesis_block_result.err(),
            "latest_block": latest_block_result.err(),
            "height": height_result.err()
        }
    })
    .to_string())
}

fn rpc_call(
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .map_err(|error| format!("failed to build HTTP client: {error}"))?;
    let payload = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        }))
        .send()
        .map_err(|error| format!("{method} request failed: {error}"))?
        .json::<serde_json::Value>()
        .map_err(|error| format!("{method} response parse failed: {error}"))?;
    if let Some(error) = payload.get("error") {
        return Err(format!("{method} returned error: {error}"));
    }
    payload
        .get("result")
        .cloned()
        .ok_or_else(|| format!("{method} response did not include result"))
}

fn block_hash_from_value(value: &serde_json::Value) -> Option<String> {
    value
        .get("hash")
        .or_else(|| value.get("block_hash"))
        .or_else(|| value.get("blockHash"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

fn parse_u64ish(value: &serde_json::Value) -> Option<u64> {
    if let Some(number) = value.as_u64() {
        return Some(number);
    }
    let text = value.as_str()?.trim();
    if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        text.parse::<u64>().ok()
    }
}

fn require_testnet_args(args: &[String]) -> Result<(), String> {
    let chain_id = arg_value(args, "--chain-id")
        .ok_or_else(|| "missing --chain-id 1264".to_string())?
        .parse::<u64>()
        .map_err(|error| format!("invalid --chain-id: {error}"))?;
    ChainId(chain_id).require_testnet_v2()?;
    let network_id = arg_value(args, "--network-id")
        .ok_or_else(|| "missing --network-id synergy-testnet-v2".to_string())?;
    NetworkId(network_id).require_testnet_v2()?;
    Ok(())
}

fn optional_u64_arg(args: &[String], name: &str) -> Result<Option<u64>, String> {
    arg_value(args, name)
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|error| format!("invalid {name}: {error}"))
        })
        .transpose()
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn arg_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|arg| arg == name)
}

fn arg_values(args: &[String], name: &str) -> Vec<String> {
    args.windows(2)
        .filter(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
        .collect()
}
