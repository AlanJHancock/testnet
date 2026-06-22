# Synergy Archive Validator Node

This package installs a non-consensus Archive Validator Node for Synergy Testnet.

Protocol role: `ARCHIVE_OBSERVER`

The archive node verifies finalized chain data, stores full archival data, creates role-specific signed snapshots, chunks zstd archives at 512 MiB, retains two verified snapshots by class, and serves verified snapshots to new validators, self-healing validators, relayers, observers, RPC nodes, and indexers. It never votes, never proposes, never aggregates QCs, and never counts toward quorum.

Default scheduled snapshot classes: `validator-pruned`, `support-relayer`, `support-observer`, `indexer-replay`, `support-rpc`, and `archive-full`. `archive-full` is created every 15,000 finalized blocks; all other default classes are created every 5,000 finalized blocks.

Linux install:

```bash
unzip synergy-archive-validator-testnet-v2-linux-x64.zip
cd archive-validator
sudo ./setup-archive-validator.sh --chain-id 1264 --network-id synergy-testnet-v2 --genesis-file ./config/genesis.testnet.json.template --expected-genesis-hash <hash> --yes
```

Apple Silicon M4 internal teammate handoff:

```bash
unzip synergy-archive-validator-testnet-v2-macos-m4.zip
cd synergy-archive-validator-testnet-v2-macos-m4
sudo ./setup-archive-validator-m4.sh --public-host <archive-node-public-host> --yes
sudo ./verify-archive-validator-m4.sh
```

The M4 zip includes the Apple Silicon archive runtime, the Aegis CLI, the archive snapshot control plane, checksums, launchd persistence, policy, and handoff instructions. It is an internal operations handoff artifact. A public macOS installer still requires a signed, notarized, and stapled package.

Private keys are not included. Aegis PQC archive peer and snapshot signing identities must be generated or referenced through `aegis-pqvm`.
