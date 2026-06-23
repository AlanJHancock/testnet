# Temporary Manual Snapshot Publisher

Status: required until the Archive Validator owns snapshot production and distribution.

## Architecture

The temporary publisher uses a healthy, exact-common-height validator as the source, creates a runtime-signed snapshot, verifies the signed manifest locally, then publishes role-scoped distribution artifacts:

- `validator-pruned`: quarantined validator recovery, Val5 recovery, and non-genesis validator onboarding.
- `support-relayer`: Relayer-1 and Relayer-2 recovery.
- `support-rpc`: row9 RPC Gateway recovery.
- `indexer-full` or `indexer-replay`: Explorer and Atlas recovery.
- `archive-full`: Archive Validator only.

Each distribution contains a `distribution-manifest.json`, a zstd archive, 512 MiB chunks, chunk SHA256s, a whole archive SHA256, and the source runtime `verify-snapshot` report. The receiver rejects a snapshot when the class does not match the target role.

## Source Requirements

Before publishing, prove the source:

- Runs the trusted runtime.
- Matches the active validator cohort at an exact common height/hash.
- Has no `h175518` contamination.
- Has no same-height QC/canonical conflict.
- Has bounded qRPC responsiveness.
- Has current committed/canonical material for the chosen snapshot height.
- Has a valid committed QC with at least `ceil(active_validator_count * 67 / 100)` active validator signers.
- Is not under active recovery or fork ambiguity.

Choose a stable materialized height behind the live tip, not an in-flight head height.

## Commands

Create and verify the runtime snapshot on the source validator first:

```bash
./bin/synergy-testnet-linux-amd64 create-snapshot \
  --chain-id 1264 \
  --network-id synergy-testnet-v2 \
  --genesis-hash f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789 \
  --source-node-majority-branch-proven \
  --source-role GENESIS_VALIDATOR
```

Publish a role-scoped distribution:

```bash
scripts/testnet/manual-snapshot-publisher.sh \
  --snapshot-root /path/to/snapshot-HEIGHT-TIMESTAMP \
  --snapshot-manifest /path/to/snapshot-HEIGHT-TIMESTAMP/snapshot-HEIGHT-manifest.json \
  --snapshot-class support-relayer \
  --allowed-role relayer \
  --out /path/to/distribution/support-relayer-hHEIGHT \
  --source-node Val1 \
  --runtime ./bin/synergy-testnet-linux-amd64 \
  --runtime-sha 79de4ec00a0f0ba8ce8106caf944c4d7aa226ea8060d3ae4257814b2eb5cfc4a
```

Receiver verification and extraction:

```bash
scripts/testnet/manual-snapshot-receiver.sh \
  --input /tmp/synergy-snapshot-distribution/support-relayer-hHEIGHT \
  --snapshot-class support-relayer \
  --target-role relayer \
  --extract-root /tmp/synergy-snapshots \
  --runtime /opt/synergy/testnet/relayer/bin/synergy-testnet-linux-amd64
```

After receiver verification, use the runtime recovery plan or supported self-heal path for the target role. Do not manually edit restored state files.

## Current Launch Recovery Use

For Gate 2, the source is Val1 and the verified snapshot is `snapshot-180167-1780376861` at h180167/hash `9c8c82029be2be3cf63eb7111d1dce395685200764ab42978604b4c5ff593f3d`.

Temporary distributions:

- `support-relayer-h180167`: Relayer-1 and Relayer-2.
- `support-rpc-h180167`: row9 RPC Gateway.

Explorer/Atlas must use `indexer-replay` or `indexer-full`, not the relayer/RPC class.

## Archive Validator Handoff

The Archive Validator will replace this temporary process. It must create signed snapshots every 5,000 blocks by default, retain the latest verified snapshots per class, serve a catalog and chunks over HTTPS or object storage, verify its own snapshots, and expose catalog health to SAM.
