# Synergy Testnet Archive Validator M4 Handoff

This zip is the internal Apple Silicon handoff for the non-consensus Synergy
Testnet 1264 Archive Validator. It includes the archive runtime, Aegis CLI,
snapshot authority controller, role policy, launchd persistence, and checksums.
It does not include private keys, credentials, or a preloaded chain database.

## Install

On the target M4 Mac Mini:

```bash
unzip synergy-archive-validator-testnet-v2-macos-m4.zip
cd synergy-archive-validator-testnet-v2-macos-m4
sudo ./setup-archive-validator-m4.sh \
  --public-host <archive-node-public-host> \
  --yes
sudo ./verify-archive-validator-m4.sh
```

The installer verifies the packaged checksums and Apple Silicon executables,
installs `zstd` through Homebrew if required, creates the archive Aegis identity
locally, installs three launchd services, and starts them persistently:

- `io.synergynetwork.archive-validator`
- `io.synergynetwork.archive-snapshot-api`
- `io.synergynetwork.archive-snapshot-worker`

The archive node syncs chain state into:

```text
/Library/Application Support/Synergy/archive-validator/workspace/data
```

Published snapshots and the signed catalog live under:

```text
/srv/synergy-snapshots
```

## Snapshot Publication Gate

The worker is intentionally fail-closed until current validator-majority proof
has been preserved and recorded. After the archive node reaches validator
parity, preserve the evidence file and run:

```bash
sudo /usr/local/synergy/bin/synergy-archive record-majority-proof \
  --height <validator-common-height> \
  --hash <validator-common-hash> \
  --evidence-path <preserved-validator-monitor-evidence.json> \
  --output "/Library/Application Support/Synergy/archive-validator/evidence/source-majority-branch-proven.json"
```

The worker then publishes verified classes at their configured cadence. For an
operator-triggered snapshot:

```bash
sudo /usr/local/synergy/bin/synergy-archive create-snapshot \
  --workspace "/Library/Application Support/Synergy/archive-validator/workspace" \
  --snapshot-class validator-pruned \
  --majority-proof-marker "/Library/Application Support/Synergy/archive-validator/evidence/source-majority-branch-proven.json"
```

The publisher checks finalized QC proof, class compatibility, manifest
signature, file checksums, state consistency, forbidden material, free space,
zstd integrity, chunk hashes, reconstructed archive hash, and receiver-side
runtime verification before atomically updating the signed catalog.

## Operator Checks

```bash
sudo ./verify-archive-validator-m4.sh
sudo /usr/local/synergy/bin/synergy-archive status
sudo /usr/local/synergy/bin/synergy-archive catalog
sudo /usr/local/synergy/bin/synergy-archive prune
```

Use `prune --apply` only after reviewing the dry run. Published snapshots can be
pinned with `pin` and unpinned with `unpin`; pruning enforces the class retention
minimum and 24-hour retirement grace period.

## Receiver Verification

Receivers must verify the class before extraction:

```bash
/usr/local/synergy/bin/synergy-archive verify-distribution \
  --input <downloaded-snapshot-directory> \
  --workspace <receiver-workspace> \
  --target-role validator \
  --extract-root <temporary-verification-directory>
```

A `support-rpc`, `support-relayer`, or `indexer-replay` receiver uses its own
role. Wrong-class artifacts are rejected before extraction or apply.

## Local Acceptance

The handoff zip can be retested on an Apple Silicon Mac without installing
system services:

```bash
./run-isolated-mac-acceptance.sh
```

The isolated run verifies installer behavior, installed checksums, Aegis PQC
sign/verify, archive-role qRPC startup, signed catalog publication, zstd chunk
reassembly, runtime receiver verification, wrong-class rejection, resumable HTTP
range serving, staging-path denial, and launchd plist syntax.
