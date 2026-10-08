//! Protocol attestation ledger.
//!
//! Added 19 Sep 2026 in response to Alan's request: attest, at every stage
//! of the SynQ pipeline (dry-run compile, dry-run execute, deploy-envelope
//! build, mempool admission), which protocol context a piece of source is
//! operating under (SXCP / SCETP / generic) and whether the artifact that
//! gets deployed is provably the same, deterministic bytecode that was
//! actually dry-run tested beforehand.
//!
//! IMPORTANT ARCHITECTURAL FACT this module makes explicit rather than
//! papering over: Forge's dry-run pipeline (`/compile-aivm`,
//! `/aivm/estimate-gas`) compiles source via `compile_to_aivm()` and
//! executes it on the AIVM engine (`aivm::vm::Avm`). The real deploy
//! pipeline (`/submit-mempool`) compiles the SAME source via a SEPARATE
//! backend, `synq_compiler::compile_ir()` ("IR -> QVM bytecode backend"),
//! and what actually executes on-chain later is `quantumvm::QuantumVM`
//! (see `aivm-core::execution::execute_synq_contract`), not AIVM. These are
//! two independently-implemented compiler backends targeting two different
//! VMs for the same SynQ language -- their bytecode outputs are NOT
//! comparable byte-for-byte, and passing every AIVM dry-run/scenario test
//! provides no bytecode-level guarantee about the QVM artifact that is
//! actually deployed. Rather than claim a false "verified identical"
//! result across the two, every stage records which backend produced it,
//! and `get_report` surfaces a `cross_backend_gap` flag whenever a source
//! hash has been dry-run tested on one backend but deployed on the other.
//!
//! What IS independently and honestly verifiable per backend, and what
//! this module checks: whether that backend's own compile is deterministic
//! (same source -> byte-identical bytecode across repeated, independent
//! compiles). Both `compile_aivm_handler` and `submit_mempool_handler`
//! compile twice and record the result via `record_determinism_check`.

use serde::Serialize;
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Which compiler backend / VM target produced a given artifact.
pub const BACKEND_AIVM: &str = "aivm";
pub const BACKEND_QUANTUMVM: &str = "quantumvm";

#[derive(Debug, Clone, Serialize)]
pub struct StageEvent {
    pub stage: &'static str,
    pub backend: &'static str,
    pub timestamp: u64,
    pub bytecode_hash: Option<String>,
    pub detail: Value,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ArtifactRecord {
    pub protocol_hint: String,
    pub stages: Vec<StageEvent>,
    /// backend -> distinct bytecode hashes seen for that backend. More than
    /// one distinct hash for the SAME backend on the SAME source means that
    /// backend's compile is not deterministic for this input.
    pub bytecode_hashes_by_backend: HashMap<String, Vec<String>>,
    /// backend -> explicit two-independent-compiles-match result, when a
    /// determinism self-check was actually run for that backend.
    pub determinism_checked: HashMap<String, bool>,
}

fn ledger() -> &'static Mutex<HashMap<String, ArtifactRecord>> {
    static LEDGER: OnceLock<Mutex<HashMap<String, ArtifactRecord>>> = OnceLock::new();
    LEDGER.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Stable content hash used as the ledger key. Not cryptographically tied
/// to any on-chain hash format -- purely an internal correlation id so
/// independent requests touching the same source text land in the same
/// ledger entry.
pub fn content_hash_hex(bytes: &[u8]) -> String {
    hex::encode(Sha3_256::digest(bytes))
}

/// Heuristic protocol classification from source text. Labelled a hint,
/// not a ground truth: a SynQ contract that consumes SXCP attestations or
/// participates in a SCETP same-chain transfer will typically reference
/// those names in its source (host-function calls, comments, identifiers),
/// but this is a substring heuristic, not static analysis of actual
/// host-function usage.
pub fn classify_protocol_hint(source: &str) -> &'static str {
    let lower = source.to_lowercase();
    let has_sxcp = lower.contains("sxcp");
    let has_scetp = lower.contains("scetp");
    match (has_sxcp, has_scetp) {
        (true, true) => "sxcp+scetp",
        (true, false) => "sxcp",
        (false, true) => "scetp",
        (false, false) => "generic",
    }
}

/// Record one pipeline stage for a given source hash.
pub fn record_stage(
    source_hash: &str,
    protocol_hint: &str,
    stage: &'static str,
    backend: &'static str,
    bytecode_hash: Option<&str>,
    detail: Value,
) {
    let mut guard = match ledger().lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    let entry = guard.entry(source_hash.to_string()).or_default();
    if entry.protocol_hint.is_empty() {
        entry.protocol_hint = protocol_hint.to_string();
    }
    if let Some(hash) = bytecode_hash {
        let seen = entry
            .bytecode_hashes_by_backend
            .entry(backend.to_string())
            .or_default();
        if !seen.iter().any(|h| h == hash) {
            seen.push(hash.to_string());
        }
    }
    entry.stages.push(StageEvent {
        stage,
        backend,
        timestamp: now_ts(),
        bytecode_hash: bytecode_hash.map(|h| h.to_string()),
        detail,
    });
}

/// Record the outcome of an explicit "compile the same source twice
/// independently, compare bytecode hashes" determinism self-check for one
/// backend.
pub fn record_determinism_check(source_hash: &str, backend: &'static str, matched: bool) {
    let mut guard = match ledger().lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    let entry = guard.entry(source_hash.to_string()).or_default();
    entry
        .determinism_checked
        .insert(backend.to_string(), matched);
}

/// Full report for one source hash: stage chain, per-backend determinism
/// verdicts, and the cross-backend gap flag.
pub fn get_report(source_hash: &str) -> Value {
    let guard = match ledger().lock() {
        Ok(g) => g,
        Err(_) => return json!({"source_hash": source_hash, "found": false}),
    };
    let entry = match guard.get(source_hash) {
        Some(e) => e,
        None => return json!({"source_hash": source_hash, "found": false}),
    };

    let backends_seen: Vec<&String> = entry.bytecode_hashes_by_backend.keys().collect();
    let cross_backend_gap = backends_seen.len() > 1;
    let mut deterministic_by_backend: HashMap<String, bool> = HashMap::new();
    for (backend, hashes) in &entry.bytecode_hashes_by_backend {
        // Even without an explicit two-compile self-check, seeing more than
        // one distinct hash for the same backend on the same source is
        // itself proof of non-determinism (or a source-hash collision,
        // vanishingly unlikely at 256 bits).
        let by_repeat_observation = hashes.len() <= 1;
        let verdict = entry
            .determinism_checked
            .get(backend)
            .copied()
            .unwrap_or(by_repeat_observation)
            && by_repeat_observation;
        deterministic_by_backend.insert(backend.clone(), verdict);
    }

    let dry_run_stage = entry
        .stages
        .iter()
        .find(|s| s.stage == "aivm_dry_run_executed");
    let deploy_stage = entry
        .stages
        .iter()
        .find(|s| s.stage == "qvm_deploy_envelope_built");
    let tested_before_deploy = match (dry_run_stage, deploy_stage) {
        (Some(dry_run), Some(deploy)) => dry_run.timestamp <= deploy.timestamp,
        _ => false,
    };

    json!({
        "source_hash": source_hash,
        "found": true,
        "protocol_hint": entry.protocol_hint,
        "backends_seen": backends_seen,
        "cross_backend_gap": cross_backend_gap,
        "cross_backend_gap_note": if cross_backend_gap {
            "This source has been compiled/executed on more than one backend (AIVM dry-run vs QuantumVM deploy). \
             Their bytecode is NOT byte-comparable -- passing AIVM dry-run/scenario tests does not by itself prove \
             anything about the QuantumVM artifact that was actually deployed. See deterministic_by_backend and \
             tested_before_deploy for what IS actually verified."
        } else {
            "Only one backend observed for this source so far."
        },
        "deterministic_by_backend": deterministic_by_backend,
        "dry_run_executed": dry_run_stage.is_some(),
        "deploy_envelope_built": deploy_stage.is_some(),
        "tested_before_deploy": tested_before_deploy,
        "stages": entry.stages,
    })
}

/// Ledger-wide summary across every tracked source hash.
pub fn get_status() -> Value {
    let guard = match ledger().lock() {
        Ok(g) => g,
        Err(_) => return json!({"tracked_artifacts": 0}),
    };
    let mut by_protocol: HashMap<String, u64> = HashMap::new();
    let mut cross_backend_gap_hashes: Vec<String> = Vec::new();
    let mut non_deterministic_hashes: Vec<String> = Vec::new();
    let mut tested_before_deploy_count: u64 = 0;
    let mut deploy_without_dry_run_count: u64 = 0;

    for (source_hash, entry) in guard.iter() {
        *by_protocol.entry(entry.protocol_hint.clone()).or_insert(0) += 1;

        let backends_seen = entry.bytecode_hashes_by_backend.len();
        if backends_seen > 1 {
            cross_backend_gap_hashes.push(source_hash.clone());
        }
        let any_non_deterministic = entry
            .bytecode_hashes_by_backend
            .values()
            .any(|hashes| hashes.len() > 1)
            || entry.determinism_checked.values().any(|matched| !matched);
        if any_non_deterministic {
            non_deterministic_hashes.push(source_hash.clone());
        }

        let dry_run = entry.stages.iter().find(|s| s.stage == "aivm_dry_run_executed");
        let deploy = entry.stages.iter().find(|s| s.stage == "qvm_deploy_envelope_built");
        match (dry_run, deploy) {
            (Some(dry_run), Some(deploy)) if dry_run.timestamp <= deploy.timestamp => {
                tested_before_deploy_count += 1;
            }
            (None, Some(_)) => {
                deploy_without_dry_run_count += 1;
            }
            _ => {}
        }
    }

    json!({
        "tracked_artifacts": guard.len(),
        "by_protocol_hint": by_protocol,
        "cross_backend_gap_count": cross_backend_gap_hashes.len(),
        "cross_backend_gap_source_hashes": cross_backend_gap_hashes,
        "non_deterministic_count": non_deterministic_hashes.len(),
        "non_deterministic_source_hashes": non_deterministic_hashes,
        "tested_before_deploy_count": tested_before_deploy_count,
        "deployed_without_prior_dry_run_count": deploy_without_dry_run_count,
    })
}
