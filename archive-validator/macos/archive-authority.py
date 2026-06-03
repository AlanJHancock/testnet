#!/usr/bin/env python3
"""Synergy Testnet 1264 Archive Validator snapshot authority.

The control plane intentionally delegates PQC operations to the packaged Rust
`aegis-pqvm` CLI and snapshot state validation to the role-bound archive node
runtime. It never packages keys, configs, genesis, or transient node secrets.
"""

from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
import shutil
import socketserver
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable


CHAIN_ID = 1264
NETWORK_ID = "synergy-testnet-v2"
GENESIS_HASH = "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789"
CHUNK_SIZE = 512 * 1024 * 1024
GRACE_SECS = 24 * 60 * 60
CATALOG_DOMAIN = "SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1"
DISTRIBUTION_DOMAIN = "SYNERGY_ARCHIVE_SNAPSHOT_DISTRIBUTION_V1"
DEFAULT_ROOT = Path("/Volumes/Synergy_Archive/archive-validator")
DEFAULT_PUBLISH_ROOT = DEFAULT_ROOT / "snapshots"
DEFAULT_RUNTIME = Path("/usr/local/synergy/bin/synergy-archive-validator-node")
DEFAULT_AEGIS = Path("/usr/local/synergy/bin/aegis-pqvm")

CLASS_POLICY = {
    "validator-pruned": {
        "roles": ["validator", "onboarding_validator", "quarantined_validator"],
        "cadence": 5_000,
        "retain": 3,
    },
    "support-rpc": {"roles": ["rpc", "rpc_gateway"], "cadence": 5_000, "retain": 2},
    "support-relayer": {"roles": ["relayer"], "cadence": 10_000, "retain": 2},
    "indexer-replay": {
        "roles": ["indexer", "explorer", "atlas_indexer", "explorer_indexer"],
        "cadence": 10_000,
        "retain": 2,
    },
    "indexer-full": {
        "roles": ["indexer", "explorer", "atlas_indexer", "explorer_indexer"],
        "cadence": 25_000,
        "retain": 1,
    },
    "archive-full": {
        "roles": ["archive", "archive_validator", "snapshot_authority"],
        "cadence": 50_000,
        "retain": 1,
    },
}

ALLOWED_STATE_FILES = {
    "chain.json",
    "canonical_locks.json",
    "committed_qcs.json",
    "committed_qcs.jsonl",
    "dag_state.json",
    "validator_registry.json",
    "token_state.json",
    "account_state.json",
    "state_checkpoint.json",
}

FORBIDDEN_FRAGMENTS = {
    "config",
    "genesis",
    "key",
    "identity",
    "secret",
    "password",
    "credential",
    "wireguard",
    "wg0",
    "mnemonic",
    "seed",
    ".env",
    "node.env",
    "quorum",
}


def now() -> int:
    return int(time.time())


def json_dump(path: Path, value: Any, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temp, mode)
    os.replace(temp, path)


def json_load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require_executable(path: Path) -> Path:
    if not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError(f"required executable is unavailable: {path}")
    return path


def run(command: list[str], *, env: dict[str, str] | None = None, capture: bool = True) -> str:
    result = subprocess.run(
        command,
        check=False,
        text=True,
        capture_output=capture,
        env=env,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}: {detail}")
    return (result.stdout or "").strip()


def normalize_role(value: str) -> str:
    return value.strip().lower().replace("-", "_").replace(" ", "_")


def require_class_role(snapshot_class: str, role: str) -> str:
    if snapshot_class not in CLASS_POLICY:
        raise RuntimeError(f"unsupported snapshot class: {snapshot_class}")
    normalized = normalize_role(role)
    if normalized not in CLASS_POLICY[snapshot_class]["roles"]:
        raise RuntimeError(
            f"wrong-class restore refused before download or extraction: "
            f"class={snapshot_class} target_role={normalized}"
        )
    return normalized


def layout(root: Path, publish_root: Path) -> None:
    for path in [
        root / "keys",
        root / "workspace" / "config",
        root / "workspace" / "data",
        root / "logs",
        root / "evidence",
        publish_root / "staging",
        publish_root / "failed",
        publish_root / "retired",
        publish_root / "testnet-1264",
    ]:
        path.mkdir(parents=True, exist_ok=True)
    for snapshot_class in CLASS_POLICY:
        (publish_root / "testnet-1264" / snapshot_class).mkdir(parents=True, exist_ok=True)


def identity_path(root: Path) -> Path:
    return root / "keys" / "archive-authority-identity.json"


def init_identity(aegis: Path, root: Path, uma_id: str) -> dict[str, Any]:
    path = identity_path(root)
    if path.exists():
        return {"ok": True, "identity_path": str(path), "created": False}
    output = run(
        [
            str(require_executable(aegis)),
            "init-archive-identity",
            "--output",
            str(path),
            "--uma-id",
            uma_id,
        ]
    )
    value = json.loads(output)
    value["created"] = True
    return value


def sign_json(aegis: Path, root: Path, domain: str, payload: Path, signature: Path) -> dict[str, Any]:
    output = run(
        [
            str(require_executable(aegis)),
            "sign-json",
            "--identity",
            str(identity_path(root)),
            "--domain",
            domain,
            "--input",
            str(payload),
            "--output",
            str(signature),
        ]
    )
    return json.loads(output)


def verify_json(
    aegis: Path,
    domain: str,
    payload: Path,
    signature: Path,
    expected_signer_sha256: str | None = None,
) -> dict[str, Any]:
    command = [
        str(require_executable(aegis)),
        "verify-json",
        "--domain",
        domain,
        "--input",
        str(payload),
        "--signature",
        str(signature),
    ]
    if expected_signer_sha256:
        command += ["--expected-signer-sha256", expected_signer_sha256]
    return json.loads(run(command))


def runtime_env(workspace: Path, source_node: str) -> dict[str, str]:
    env = os.environ.copy()
    env["SYNERGY_PROJECT_ROOT"] = str(workspace)
    env["SYNERGY_CONFIG_PATH"] = str(workspace / "config" / "node.toml")
    env["SYNERGY_SNAPSHOT_SOURCE_NODE_ID"] = source_node
    return env


def runtime_snapshot_args(workspace: Path) -> list[str]:
    return [
        "--chain-id",
        str(CHAIN_ID),
        "--network-id",
        NETWORK_ID,
        "--genesis-hash",
        GENESIS_HASH,
        "--source-workspace",
        str(workspace),
    ]


def verify_source_snapshot(
    runtime: Path,
    workspace: Path,
    source_node: str,
    manifest: Path,
    snapshot_root: Path,
    snapshot_class: str,
    target_role: str,
) -> dict[str, Any]:
    command = [
        str(require_executable(runtime)),
        "verify-snapshot",
        *runtime_snapshot_args(workspace),
        "--manifest",
        str(manifest),
        "--snapshot-root",
        str(snapshot_root),
        "--snapshot-class",
        snapshot_class,
        "--target-role",
        target_role,
    ]
    report = json.loads(run(command, env=runtime_env(workspace, source_node)))
    if report.get("success") is not True:
        raise RuntimeError(f"runtime verify-snapshot failed closed: {report}")
    return report


def iter_chain_blocks(path: Path) -> Iterable[dict[str, Any]]:
    decoder = json.JSONDecoder()
    buffer = ""
    started = False
    with path.open("r", encoding="utf-8") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            buffer += chunk
            while True:
                buffer = buffer.lstrip()
                if not started:
                    if not buffer:
                        break
                    if buffer[0] != "[":
                        raise RuntimeError("snapshot chain.json must be a JSON array")
                    started = True
                    buffer = buffer[1:]
                    continue
                buffer = buffer.lstrip()
                if buffer.startswith("]"):
                    return
                if buffer.startswith(","):
                    buffer = buffer[1:]
                    continue
                if not buffer:
                    break
                try:
                    value, index = decoder.raw_decode(buffer)
                except json.JSONDecodeError:
                    break
                if not isinstance(value, dict):
                    raise RuntimeError("snapshot chain.json block must be a JSON object")
                yield value
                buffer = buffer[index:]
    raise RuntimeError("snapshot chain.json is truncated")


def block_height_hash(value: dict[str, Any]) -> tuple[int, str]:
    height = value.get("block_index", value.get("height"))
    block_hash = value.get("hash", value.get("block_hash"))
    if height is None or not block_hash:
        raise RuntimeError("snapshot chain block missing height/hash")
    return int(height), str(block_hash)


def qc_height_hash(value: dict[str, Any]) -> tuple[int | None, str | None]:
    qc = value.get("qc", value)
    height = qc.get("height", qc.get("block_height", qc.get("block_index")))
    block_hash = qc.get("block_hash", value.get("block_hash"))
    return (int(height) if height is not None else None, str(block_hash) if block_hash else None)


def source_safety_report(snapshot_root: Path, source_manifest: Path, fixture_mode: bool) -> dict[str, Any]:
    signed = json_load(source_manifest)
    manifest = signed.get("manifest", signed)
    if manifest.get("conflict_height_hash"):
        raise RuntimeError("snapshot manifest contains unresolved conflict_height_hash")
    for path in snapshot_root.rglob("*"):
        if not path.is_file():
            continue
        relative = str(path.relative_to(snapshot_root)).lower()
        basename = path.name
        if basename.endswith("manifest.json"):
            continue
        if basename not in ALLOWED_STATE_FILES:
            raise RuntimeError(f"snapshot contains non-approved state file: {relative}")
        if any(fragment in relative for fragment in FORBIDDEN_FRAGMENTS):
            raise RuntimeError(f"snapshot contains forbidden material: {relative}")

    chain_hashes: dict[int, str] = {}
    chain_path = snapshot_root / "chain.json"
    if chain_path.is_file():
        for block in iter_chain_blocks(chain_path):
            height, block_hash = block_height_hash(block)
            prior = chain_hashes.setdefault(height, block_hash)
            if prior != block_hash:
                raise RuntimeError(f"same-height chain conflict at h{height}")

    lock_path = snapshot_root / "canonical_locks.json"
    locks = json_load(lock_path) if lock_path.is_file() else {}
    if not isinstance(locks, dict):
        raise RuntimeError("canonical_locks.json must be a JSON object")
    lock_hashes: dict[int, str] = {}
    for raw_height, entry in locks.items():
        height = int(raw_height)
        block_hash = str(entry.get("hash", entry.get("block_hash", "")))
        if not block_hash:
            raise RuntimeError(f"canonical lock missing hash at h{height}")
        lock_hashes[height] = block_hash
        if height in chain_hashes and chain_hashes[height] != block_hash:
            raise RuntimeError(f"canonical lock/chain conflict at h{height}")

    qc_hashes: dict[int, str] = {}
    qc_path = snapshot_root / "committed_qcs.jsonl"
    if qc_path.is_file():
        with qc_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                height, block_hash = qc_height_hash(json.loads(line))
                if height is None or block_hash is None:
                    raise RuntimeError("committed QC entry missing height/hash")
                prior = qc_hashes.setdefault(height, block_hash)
                if prior != block_hash:
                    raise RuntimeError(f"same-height committed QC conflict at h{height}")
                if height in lock_hashes and lock_hashes[height] != block_hash:
                    raise RuntimeError(f"canonical lock/QC conflict at h{height}")

    snapshot_height = int(manifest.get("snapshot_height", 0))
    h175518_checked = False
    if not fixture_mode and snapshot_height >= 175_518:
        expected = lock_hashes.get(175_518)
        if not expected or chain_hashes.get(175_518) != expected:
            raise RuntimeError("h175518 contamination check failed: canonical lock/chain proof unavailable")
        if 175_518 in qc_hashes and qc_hashes[175_518] != expected:
            raise RuntimeError("h175518 contamination check failed: committed QC conflict")
        h175518_checked = True
    return {
        "snapshot_source_verified": True,
        "snapshot_height": snapshot_height,
        "same_height_chain_conflict_rejected": True,
        "same_height_qc_conflict_rejected": True,
        "canonical_qc_conflict_rejected": True,
        "h175518_contamination_rejected": h175518_checked or fixture_mode,
        "fixture_mode": fixture_mode,
        "keys_configs_genesis_quorum_excluded": True,
    }


def directory_size(path: Path) -> int:
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def free_bytes(path: Path) -> int:
    return shutil.disk_usage(path).free


def enforce_free_space(path: Path, uncompressed_size: int, fixture_mode: bool) -> None:
    safety_margin = 64 * 1024 * 1024 if fixture_mode else 20 * 1024 * 1024 * 1024
    required = uncompressed_size * 2 + safety_margin
    available = free_bytes(path)
    if available < required:
        raise RuntimeError(
            f"insufficient snapshot staging space: required={required} available={available}"
        )


def chunk_archive(archive: Path) -> list[dict[str, Any]]:
    chunks: list[dict[str, Any]] = []
    with archive.open("rb") as source:
        index = 0
        while True:
            content = source.read(CHUNK_SIZE)
            if not content:
                break
            name = f"{archive.name}.part-{index:05d}"
            path = archive.parent / name
            path.write_bytes(content)
            chunks.append({"name": name, "size_bytes": len(content), "sha256": sha256_bytes(content)})
            index += 1
    if not chunks:
        raise RuntimeError("snapshot archive produced no chunks")
    return chunks


def write_checksum_files(directory: Path, archive: Path, chunks: list[dict[str, Any]]) -> None:
    (directory / "archive.sha256").write_text(
        f"{sha256_file(archive)}  {archive.name}\n", encoding="utf-8"
    )
    (directory / "chunk-checksums.sha256").write_text(
        "".join(f"{chunk['sha256']}  {chunk['name']}\n" for chunk in chunks),
        encoding="utf-8",
    )


def reassemble_and_extract(directory: Path, archive_name: str, chunks: list[dict[str, Any]], out: Path) -> Path:
    archive = directory / archive_name
    reassembled = directory / f".{archive_name}.reassembled-{os.getpid()}"
    with reassembled.open("wb") as target:
        for chunk in chunks:
            path = directory / chunk["name"]
            if sha256_file(path) != chunk["sha256"]:
                raise RuntimeError(f"chunk checksum mismatch: {path.name}")
            with path.open("rb") as source:
                shutil.copyfileobj(source, target)
    if sha256_file(reassembled) != sha256_file(archive):
        raise RuntimeError("reassembled archive checksum mismatch")
    run(["zstd", "-t", str(reassembled)])
    tar_path = directory / f".{archive_name}.tar-{os.getpid()}"
    run(["zstd", "-d", "-f", str(reassembled), "-o", str(tar_path)])
    out.mkdir(parents=True, exist_ok=True)
    run(["tar", "-xf", str(tar_path), "-C", str(out)])
    reassembled.unlink(missing_ok=True)
    tar_path.unlink(missing_ok=True)
    return out


def catalog_paths(publish_root: Path) -> tuple[Path, Path]:
    return publish_root / "catalog.json", publish_root / "catalog.json.sig"


def read_catalog(publish_root: Path) -> dict[str, Any]:
    catalog_path, _ = catalog_paths(publish_root)
    if not catalog_path.exists():
        return {
            "schema": "synergy-archive-snapshot-catalog-v1",
            "chain_id": CHAIN_ID,
            "network_id": NETWORK_ID,
            "genesis_hash": GENESIS_HASH,
            "updated_at": now(),
            "snapshots": [],
        }
    catalog = json_load(catalog_path)
    if catalog.get("chain_id") != CHAIN_ID or catalog.get("network_id") != NETWORK_ID:
        raise RuntimeError("catalog chain/network mismatch")
    if catalog.get("genesis_hash") != GENESIS_HASH:
        raise RuntimeError("catalog genesis hash mismatch")
    return catalog


def write_signed_catalog(aegis: Path, root: Path, publish_root: Path, catalog: dict[str, Any]) -> None:
    catalog["updated_at"] = now()
    catalog_path, sig_path = catalog_paths(publish_root)
    json_dump(catalog_path, catalog)
    sign_json(aegis, root, CATALOG_DOMAIN, catalog_path, sig_path)
    verify_json(aegis, CATALOG_DOMAIN, catalog_path, sig_path)


def update_catalog(
    aegis: Path,
    root: Path,
    publish_root: Path,
    entry: dict[str, Any],
) -> None:
    catalog = read_catalog(publish_root)
    snapshots = [
        existing
        for existing in catalog["snapshots"]
        if existing.get("snapshot_id") != entry["snapshot_id"]
        or existing.get("snapshot_class") != entry["snapshot_class"]
    ]
    snapshots.append(entry)
    snapshots.sort(key=lambda value: (value["snapshot_class"], int(value["height"])))
    catalog["snapshots"] = snapshots
    write_signed_catalog(aegis, root, publish_root, catalog)


def package_publish(args: argparse.Namespace, report: dict[str, Any]) -> dict[str, Any]:
    runtime = require_executable(args.runtime)
    aegis = require_executable(args.aegis)
    workspace = args.workspace
    source_node = args.source_node
    snapshot_class = args.snapshot_class
    allowed_roles = CLASS_POLICY[snapshot_class]["roles"]
    primary_role = allowed_roles[0]
    snapshot_root = Path(report["snapshot_path"])
    source_manifest = Path(report["manifest_path"])
    runtime_verify = verify_source_snapshot(
        runtime, workspace, source_node, source_manifest, snapshot_root, snapshot_class, primary_role
    )
    safety = source_safety_report(snapshot_root, source_manifest, args.fixture_mode)
    uncompressed_size = directory_size(snapshot_root)
    enforce_free_space(args.publish_root, uncompressed_size, args.fixture_mode)
    snapshot_height = int(report["snapshot_height"])
    snapshot_id = f"snapshot-{snapshot_height:09d}"
    snapshot_dir = args.publish_root / "testnet-1264" / snapshot_class / snapshot_id
    if snapshot_dir.exists():
        raise RuntimeError(f"published snapshot already exists: {snapshot_dir}")
    stage = args.publish_root / "staging" / f"{snapshot_id}.{snapshot_class}.building-{os.getpid()}"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    archive_name = f"{snapshot_id}.{snapshot_class}.tar.zst"
    archive = stage / archive_name
    tar_path = stage / f".{snapshot_id}.tar"
    run(["tar", "-C", str(snapshot_root.parent), "-cf", str(tar_path), snapshot_root.name])
    run(["zstd", "-T0", "-3", "--long=27", "-f", str(tar_path), "-o", str(archive)])
    tar_path.unlink()
    chunks = chunk_archive(archive)
    write_checksum_files(stage, archive, chunks)
    shutil.copy2(source_manifest, stage / "source-snapshot-manifest.json")
    json_dump(stage / "source-verification.json", {"runtime": runtime_verify, "safety": safety})
    distribution = {
        "schema": "synergy-archive-snapshot-distribution-v1",
        "snapshot_id": snapshot_id,
        "snapshot_class": snapshot_class,
        "allowed_roles": allowed_roles,
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "genesis_hash": GENESIS_HASH,
        "height": snapshot_height,
        "hash": report["snapshot_hash"],
        "created_at": now(),
        "producer": source_node,
        "runtime_name": runtime.name,
        "runtime_sha256": sha256_file(runtime),
        "minimum_compatible_runtime": args.minimum_compatible_runtime,
        "archive_filename": archive_name,
        "archive_sha256": sha256_file(archive),
        "compression": {"algorithm": "zstd", "level": 3, "long": 27},
        "chunk_size": CHUNK_SIZE,
        "chunks": chunks,
        "size_uncompressed": uncompressed_size,
        "size_compressed": archive.stat().st_size,
        "qc_vote_count": report["qc_vote_count"],
        "qc_signers": report["qc_signers"],
        "source_manifest": source_manifest.name,
        "source_manifest_sha256": sha256_file(stage / "source-snapshot-manifest.json"),
        "safety": safety,
        "retention_class": "launch-stabilization",
        "status": "verified-local",
    }
    json_dump(stage / "distribution-manifest.json", distribution)
    sign_json(
        aegis,
        args.root,
        DISTRIBUTION_DOMAIN,
        stage / "distribution-manifest.json",
        stage / "distribution-manifest.sig",
    )
    signature = verify_json(
        aegis,
        DISTRIBUTION_DOMAIN,
        stage / "distribution-manifest.json",
        stage / "distribution-manifest.sig",
    )
    verify_root = Path(tempfile.mkdtemp(prefix="synergy-archive-verify-", dir=str(args.publish_root)))
    try:
        extracted = reassemble_and_extract(stage, archive_name, chunks, verify_root)
        extracted_snapshot = extracted / snapshot_root.name
        extracted_manifest = extracted_snapshot / source_manifest.name
        receiver_verify = verify_source_snapshot(
            runtime,
            workspace,
            source_node,
            extracted_manifest,
            extracted_snapshot,
            snapshot_class,
            primary_role,
        )
    finally:
        shutil.rmtree(verify_root, ignore_errors=True)
    json_dump(stage / "verification-report.json", {"signature": signature, "runtime": receiver_verify})
    json_dump(
        stage / "retention.json",
        {
            "retention_class": "launch-stabilization",
            "minimum_published_replacements": CLASS_POLICY[snapshot_class]["retain"],
            "pinned": False,
            "pin_reasons": [],
            "grace_seconds": GRACE_SECS,
        },
    )
    distribution["status"] = "published"
    json_dump(stage / "distribution-manifest.json", distribution)
    sign_json(
        aegis,
        args.root,
        DISTRIBUTION_DOMAIN,
        stage / "distribution-manifest.json",
        stage / "distribution-manifest.sig",
    )
    verify_json(
        aegis,
        DISTRIBUTION_DOMAIN,
        stage / "distribution-manifest.json",
        stage / "distribution-manifest.sig",
    )
    snapshot_dir.parent.mkdir(parents=True, exist_ok=True)
    os.replace(stage, snapshot_dir)
    entry = {
        "snapshot_id": snapshot_id,
        "snapshot_class": snapshot_class,
        "allowed_roles": allowed_roles,
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "genesis_hash": GENESIS_HASH,
        "height": snapshot_height,
        "hash": report["snapshot_hash"],
        "created_at": distribution["created_at"],
        "producer": source_node,
        "runtime_sha256": distribution["runtime_sha256"],
        "size_compressed": distribution["size_compressed"],
        "size_uncompressed": uncompressed_size,
        "chunk_count": len(chunks),
        "chunk_size": CHUNK_SIZE,
        "archive_sha256": distribution["archive_sha256"],
        "manifest_sha256": sha256_file(snapshot_dir / "distribution-manifest.json"),
        "manifest_signature_status": "AEGIS_PQC_VERIFIED",
        "qc_vote_count": report["qc_vote_count"],
        "qc_signers": report["qc_signers"],
        "status": "published",
        "retention_class": "launch-stabilization",
        "retained_until": None,
        "superseded_by": None,
        "local_path": str(snapshot_dir),
        "mirror_urls": args.mirror_url,
        "object_storage_prefix": None,
        "verification_status": "green",
        "last_verified_at": now(),
        "notes": [],
        "pinned": False,
        "pin_reasons": [],
    }
    update_catalog(aegis, args.root, args.publish_root, entry)
    return {"ok": True, "snapshot": entry, "snapshot_path": str(snapshot_dir)}


def proof_marker_ok(path: Path) -> None:
    value = json_load(path)
    if value.get("source_node_majority_branch_proven") is not True:
        raise RuntimeError("majority-branch proof marker does not assert source proof")
    if value.get("chain_id") != CHAIN_ID or value.get("network_id") != NETWORK_ID:
        raise RuntimeError("majority-branch proof marker chain/network mismatch")
    if value.get("genesis_hash") != GENESIS_HASH:
        raise RuntimeError("majority-branch proof marker genesis mismatch")


def create_snapshot(args: argparse.Namespace) -> dict[str, Any]:
    if not args.fixture_mode:
        proof_marker_ok(args.majority_proof_marker)
    command = [
        str(require_executable(args.runtime)),
        "create-snapshot",
        *runtime_snapshot_args(args.workspace),
        "--source-node-majority-branch-proven",
        "--source-role",
        "ARCHIVE_NODE",
        "--snapshot-class",
        args.snapshot_class,
    ]
    for role in CLASS_POLICY[args.snapshot_class]["roles"]:
        command += ["--allowed-role", role]
    report = json.loads(run(command, env=runtime_env(args.workspace, args.source_node)))
    if report.get("success") is not True:
        raise RuntimeError(f"runtime create-snapshot failed closed: {report}")
    return package_publish(args, report)


def publish_existing_snapshot(args: argparse.Namespace) -> dict[str, Any]:
    if not args.fixture_mode:
        proof_marker_ok(args.majority_proof_marker)
    signed = json_load(args.manifest)
    manifest = signed.get("manifest", signed)
    if manifest.get("snapshot_class") != args.snapshot_class:
        raise RuntimeError("pre-created snapshot manifest class does not match requested class")
    report = {
        "success": True,
        "snapshot_path": str(args.snapshot_root),
        "manifest_path": str(args.manifest),
        "snapshot_height": int(manifest["snapshot_height"]),
        "snapshot_hash": manifest["snapshot_block_hash"],
        "qc_vote_count": int(manifest["qc_evidence"]["vote_count"]),
        "qc_signers": manifest["qc_evidence"]["signer_set"],
    }
    return package_publish(args, report)


def latest_local_canonical_height(workspace: Path) -> int:
    path = workspace / "data" / "canonical_locks.json"
    value = json_load(path)
    if not isinstance(value, dict) or not value:
        raise RuntimeError("archive workspace has no canonical lock height")
    return max(int(height) for height in value)


def worker(args: argparse.Namespace) -> None:
    while True:
        try:
            proof_marker_ok(args.majority_proof_marker)
            local_height = latest_local_canonical_height(args.workspace)
            catalog = read_catalog(args.publish_root)
            for snapshot_class in args.snapshot_class:
                latest = max(
                    (
                        int(entry["height"])
                        for entry in catalog["snapshots"]
                        if entry["snapshot_class"] == snapshot_class
                        and entry["status"] == "published"
                    ),
                    default=None,
                )
                cadence = int(CLASS_POLICY[snapshot_class]["cadence"])
                if latest is not None and local_height - latest < cadence:
                    continue
                create_args = argparse.Namespace(**vars(args))
                create_args.snapshot_class = snapshot_class
                create_args.fixture_mode = False
                result = create_snapshot(create_args)
                print(json.dumps({"worker_snapshot_published": result}, sort_keys=True), flush=True)
                catalog = read_catalog(args.publish_root)
        except Exception as error:
            print(f"synergy-archive worker failed closed: {error}", file=sys.stderr, flush=True)
        if args.once:
            return
        time.sleep(args.interval_secs)


def status(args: argparse.Namespace) -> dict[str, Any]:
    layout(args.root, args.publish_root)
    aegis = require_executable(args.aegis)
    runtime = require_executable(args.runtime)
    smoke = json.loads(run([str(aegis), "smoke-test"]))
    runtime_version = run([str(runtime), "version"])
    catalog_path, sig_path = catalog_paths(args.publish_root)
    catalog_signature = None
    catalog = read_catalog(args.publish_root)
    if catalog_path.exists() or sig_path.exists():
        if not catalog_path.exists() or not sig_path.exists():
            raise RuntimeError("catalog JSON/signature pair is incomplete")
        catalog_signature = verify_json(aegis, CATALOG_DOMAIN, catalog_path, sig_path)
    return {
        "ok": True,
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "genesis_hash": GENESIS_HASH,
        "archive_role": "ARCHIVE_VALIDATOR_NON_CONSENSUS",
        "can_vote": False,
        "can_propose": False,
        "can_count_in_qc": False,
        "aegis": smoke,
        "runtime_version": runtime_version.splitlines(),
        "runtime_sha256": sha256_file(runtime),
        "catalog_signature": catalog_signature,
        "catalog_entries": len(catalog["snapshots"]),
        "snapshot_classes": CLASS_POLICY,
        "publish_root": str(args.publish_root),
        "free_bytes": free_bytes(args.publish_root),
    }


def verify_distribution(args: argparse.Namespace) -> dict[str, Any]:
    directory = args.input
    manifest_path = directory / "distribution-manifest.json"
    sig_path = directory / "distribution-manifest.sig"
    distribution = json_load(manifest_path)
    snapshot_class = distribution.get("snapshot_class", "")
    target_role = require_class_role(snapshot_class, args.target_role)
    if distribution.get("status") != "published":
        raise RuntimeError("snapshot is not published")
    if distribution.get("chain_id") != CHAIN_ID or distribution.get("network_id") != NETWORK_ID:
        raise RuntimeError("snapshot distribution chain/network mismatch")
    if distribution.get("genesis_hash") != GENESIS_HASH:
        raise RuntimeError("snapshot distribution genesis mismatch")
    signature = verify_json(
        args.aegis,
        DISTRIBUTION_DOMAIN,
        manifest_path,
        sig_path,
        args.expected_signer_sha256,
    )
    for chunk in distribution["chunks"]:
        path = directory / chunk["name"]
        if not path.is_file() or sha256_file(path) != chunk["sha256"]:
            raise RuntimeError(f"snapshot chunk verification failed: {path}")
    archive = directory / distribution["archive_filename"]
    if not archive.is_file() or sha256_file(archive) != distribution["archive_sha256"]:
        raise RuntimeError("snapshot archive verification failed")
    extracted = reassemble_and_extract(
        directory, distribution["archive_filename"], distribution["chunks"], args.extract_root
    )
    roots = [path for path in extracted.iterdir() if path.is_dir()]
    if len(roots) != 1:
        raise RuntimeError("snapshot extraction did not produce exactly one snapshot root")
    source_manifest = roots[0] / distribution["source_manifest"]
    runtime_report = verify_source_snapshot(
        args.runtime,
        args.workspace,
        args.source_node,
        source_manifest,
        roots[0],
        snapshot_class,
        target_role,
    )
    return {
        "ok": True,
        "wrong_class_checked_before_extraction": True,
        "signature": signature,
        "runtime": runtime_report,
        "snapshot_root": str(roots[0]),
    }


def mutate_pin(args: argparse.Namespace, pinned: bool) -> dict[str, Any]:
    catalog = read_catalog(args.publish_root)
    changed = False
    for entry in catalog["snapshots"]:
        if entry["snapshot_id"] == args.snapshot_id and entry["snapshot_class"] == args.snapshot_class:
            reasons = set(entry.get("pin_reasons", []))
            if pinned:
                reasons.add(args.reason)
            else:
                reasons.discard(args.reason)
            entry["pin_reasons"] = sorted(reasons)
            entry["pinned"] = bool(reasons)
            changed = True
    if not changed:
        raise RuntimeError("snapshot catalog entry not found")
    write_signed_catalog(args.aegis, args.root, args.publish_root, catalog)
    return {"ok": True, "snapshot_id": args.snapshot_id, "pinned": pinned, "reason": args.reason}


def prune(args: argparse.Namespace) -> dict[str, Any]:
    catalog = read_catalog(args.publish_root)
    actions: list[dict[str, Any]] = []
    timestamp = now()
    for snapshot_class, policy in CLASS_POLICY.items():
        entries = [
            item
            for item in catalog["snapshots"]
            if item["snapshot_class"] == snapshot_class and item["status"] in {"published", "retired"}
        ]
        entries.sort(key=lambda value: int(value["height"]), reverse=True)
        protected = entries[: int(policy["retain"])]
        protected_ids = {item["snapshot_id"] for item in protected}
        for entry in entries:
            if entry["snapshot_id"] in protected_ids or entry.get("pinned"):
                continue
            if entry["status"] == "published":
                actions.append({"snapshot_id": entry["snapshot_id"], "action": "retire"})
                if args.apply:
                    entry["status"] = "retired"
                    entry["retired_at"] = timestamp
                    entry["superseded_by"] = protected[0]["snapshot_id"] if protected else None
            elif timestamp - int(entry.get("retired_at", timestamp)) >= GRACE_SECS:
                actions.append({"snapshot_id": entry["snapshot_id"], "action": "delete"})
                if args.apply:
                    shutil.rmtree(Path(entry["local_path"]), ignore_errors=True)
                    entry["status"] = "deleted"
                    entry["deleted_at"] = timestamp
    if args.apply:
        write_signed_catalog(args.aegis, args.root, args.publish_root, catalog)
    return {"ok": True, "apply": args.apply, "actions": actions}


class PublishedRangeHandler(http.server.SimpleHTTPRequestHandler):
    server_version = "SynergyArchiveSnapshotAPI/1.0"

    def list_directory(self, path: str) -> None:
        self.send_error(403, "directory listing disabled")

    def send_head(self):  # type: ignore[override]
        requested = self.path.split("?", 1)[0].lstrip("/")
        if requested not in {"catalog.json", "catalog.json.sig"} and not requested.startswith(
            "testnet-1264/"
        ):
            self.send_error(404, "published artifact not found")
            return None
        translated = Path(self.translate_path(self.path))
        if not translated.is_file():
            self.send_error(404, "published artifact not found")
            return None
        size = translated.stat().st_size
        start, end = 0, size - 1
        range_header = self.headers.get("Range")
        if range_header:
            if not range_header.startswith("bytes=") or "," in range_header:
                self.send_error(416, "invalid range")
                return None
            first, _, last = range_header[6:].partition("-")
            start = int(first) if first else 0
            end = int(last) if last else size - 1
            if start < 0 or end < start or end >= size:
                self.send_error(416, "range not satisfiable")
                return None
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        else:
            self.send_response(200)
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Content-Length", str(end - start + 1))
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        handle = translated.open("rb")
        handle.seek(start)
        self._range_remaining = end - start + 1
        return handle

    def copyfile(self, source, outputfile):  # type: ignore[override]
        remaining = getattr(self, "_range_remaining", None)
        if remaining is None:
            return super().copyfile(source, outputfile)
        while remaining > 0:
            chunk = source.read(min(1024 * 1024, remaining))
            if not chunk:
                break
            outputfile.write(chunk)
            remaining -= len(chunk)


def serve(args: argparse.Namespace) -> None:
    os.chdir(args.publish_root)
    host, raw_port = args.bind.rsplit(":", 1)
    with socketserver.ThreadingTCPServer((host, int(raw_port)), PublishedRangeHandler) as server:
        server.allow_reuse_address = True
        print(json.dumps({"ok": True, "bind": args.bind, "publish_root": str(args.publish_root)}))
        server.serve_forever()


def record_majority_proof(args: argparse.Namespace) -> dict[str, Any]:
    if not args.evidence_path.exists():
        raise RuntimeError(f"majority proof evidence path does not exist: {args.evidence_path}")
    marker = {
        "source_node_majority_branch_proven": True,
        "chain_id": CHAIN_ID,
        "network_id": NETWORK_ID,
        "genesis_hash": GENESIS_HASH,
        "height": args.height,
        "hash": args.hash,
        "source_evidence_path": str(args.evidence_path),
        "recorded_at": now(),
    }
    json_dump(args.output, marker)
    return {"ok": True, "majority_proof_marker": str(args.output)}


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", type=Path, default=Path(os.environ.get("SYNERGY_ARCHIVE_ROOT", DEFAULT_ROOT)))
    parser.add_argument(
        "--publish-root",
        type=Path,
        default=Path(os.environ.get("SYNERGY_SNAPSHOT_PUBLISH_ROOT", DEFAULT_PUBLISH_ROOT)),
    )
    parser.add_argument("--runtime", type=Path, default=Path(os.environ.get("SYNERGY_ARCHIVE_RUNTIME", DEFAULT_RUNTIME)))
    parser.add_argument("--aegis", type=Path, default=Path(os.environ.get("SYNERGY_AEGIS_CLI", DEFAULT_AEGIS)))


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser()
    sub = command.add_subparsers(dest="command", required=True)
    for name in ["init", "status", "catalog", "prune", "pin", "unpin", "create-snapshot", "publish-snapshot", "verify-distribution", "serve", "worker", "record-majority-proof"]:
        add_common(sub.add_parser(name))
    sub.choices["init"].add_argument("--uma-id", default="archive-validator-01")
    sub.choices["prune"].add_argument("--apply", action="store_true")
    for name in ["pin", "unpin"]:
        sub.choices[name].add_argument("--snapshot-id", required=True)
        sub.choices[name].add_argument("--snapshot-class", choices=CLASS_POLICY, required=True)
        sub.choices[name].add_argument("--reason", required=True)
    create = sub.choices["create-snapshot"]
    create.add_argument("--workspace", type=Path, required=True)
    create.add_argument("--source-node", default="archive-validator-01")
    create.add_argument("--snapshot-class", choices=CLASS_POLICY, required=True)
    create.add_argument("--majority-proof-marker", type=Path)
    create.add_argument("--minimum-compatible-runtime", default="v13.0.58")
    create.add_argument("--mirror-url", action="append", default=[])
    create.add_argument("--fixture-mode", action="store_true")
    publish = sub.choices["publish-snapshot"]
    publish.add_argument("--workspace", type=Path, required=True)
    publish.add_argument("--source-node", default="archive-validator-01")
    publish.add_argument("--snapshot-class", choices=CLASS_POLICY, required=True)
    publish.add_argument("--snapshot-root", type=Path, required=True)
    publish.add_argument("--manifest", type=Path, required=True)
    publish.add_argument("--majority-proof-marker", type=Path)
    publish.add_argument("--minimum-compatible-runtime", default="v13.0.58")
    publish.add_argument("--mirror-url", action="append", default=[])
    publish.add_argument("--fixture-mode", action="store_true")
    verify = sub.choices["verify-distribution"]
    verify.add_argument("--input", type=Path, required=True)
    verify.add_argument("--workspace", type=Path, required=True)
    verify.add_argument("--source-node", default="archive-validator-01")
    verify.add_argument("--target-role", required=True)
    verify.add_argument("--extract-root", type=Path, required=True)
    verify.add_argument("--expected-signer-sha256")
    sub.choices["serve"].add_argument("--bind", default="0.0.0.0:48640")
    worker_command = sub.choices["worker"]
    worker_command.add_argument("--workspace", type=Path, required=True)
    worker_command.add_argument("--source-node", default="archive-validator-01")
    worker_command.add_argument("--majority-proof-marker", type=Path, required=True)
    worker_command.add_argument(
        "--snapshot-class",
        choices=CLASS_POLICY,
        action="append",
        default=["validator-pruned", "support-rpc", "support-relayer", "indexer-replay"],
    )
    worker_command.add_argument("--minimum-compatible-runtime", default="v13.0.58")
    worker_command.add_argument("--mirror-url", action="append", default=[])
    worker_command.add_argument("--interval-secs", type=int, default=300)
    worker_command.add_argument("--once", action="store_true")
    proof = sub.choices["record-majority-proof"]
    proof.add_argument("--height", type=int, required=True)
    proof.add_argument("--hash", required=True)
    proof.add_argument("--evidence-path", type=Path, required=True)
    proof.add_argument("--output", type=Path, required=True)
    return command


def main() -> int:
    args = parser().parse_args()
    layout(args.root, args.publish_root)
    if args.command == "init":
        print(json.dumps(init_identity(args.aegis, args.root, args.uma_id), indent=2, sort_keys=True))
    elif args.command == "status":
        print(json.dumps(status(args), indent=2, sort_keys=True))
    elif args.command == "catalog":
        print(json.dumps(read_catalog(args.publish_root), indent=2, sort_keys=True))
    elif args.command == "create-snapshot":
        if not args.fixture_mode and args.majority_proof_marker is None:
            raise RuntimeError("production snapshot creation requires --majority-proof-marker")
        print(json.dumps(create_snapshot(args), indent=2, sort_keys=True))
    elif args.command == "publish-snapshot":
        if not args.fixture_mode and args.majority_proof_marker is None:
            raise RuntimeError("production snapshot publication requires --majority-proof-marker")
        print(json.dumps(publish_existing_snapshot(args), indent=2, sort_keys=True))
    elif args.command == "verify-distribution":
        print(json.dumps(verify_distribution(args), indent=2, sort_keys=True))
    elif args.command == "pin":
        print(json.dumps(mutate_pin(args, True), indent=2, sort_keys=True))
    elif args.command == "unpin":
        print(json.dumps(mutate_pin(args, False), indent=2, sort_keys=True))
    elif args.command == "prune":
        print(json.dumps(prune(args), indent=2, sort_keys=True))
    elif args.command == "serve":
        serve(args)
    elif args.command == "worker":
        worker(args)
    elif args.command == "record-majority-proof":
        print(json.dumps(record_majority_proof(args), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"synergy-archive failed closed: {error}", file=sys.stderr)
        raise SystemExit(1)
