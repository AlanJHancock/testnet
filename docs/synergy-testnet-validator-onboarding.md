# Synergy Testnet Validator Onboarding

This guide covers Synergy Testnet chain `1264`. Genesis is immutable after public launch. New validators must join by finalized admission and staking state, not by editing `genesis.testnet.json`.

## Canonical Network Identity

| Field | Value |
| --- | --- |
| Chain ID | `1264` |
| Network ID | `1264` |
| Native CAIP-2 | `synergy:testnet` |
| Reserved EIP-155 | `eip155:1264` reserved and inactive |
| Token | Synergy Testnet Token |
| Symbol | `SNRG` |
| Decimals | `9` |
| Base unit | `nWei` |
| Total supply | `12000000000` SNRG |
| Total supply in nWei | `12000000000000000000` |

The reserved EIP-155 identity must never override the native Synergy identity. EVM/EIP-155 support can only be enabled after the protocol and public RPC surface explicitly support it.

## Required Artifacts

Fetch these files from the official release bundle or canonical distribution endpoint:

- `genesis.testnet.json`
- `network-identifiers.testnet.json`
- `genesis.testnet.hash.txt`
- `network-magic-bytes.testnet.txt`
- `validator-public-manifest.testnet.json`
- `allocation-manifest.testnet.json`
- `release-manifest.testnet.json`

Verify release signatures or checksums when release signing is available. At minimum, compare artifact SHA-256 values against `release-manifest.testnet.json`.

## Verify Genesis Before Start

Run these from the Synergy Testnet repository root:

```bash
./scripts/testnet/synergy-genesis.sh validate \
  --genesis genesis.testnet.json \
  --network-identifiers network-identifiers.testnet.json

./scripts/testnet/synergy-genesis.sh hash \
  --genesis genesis.testnet.json

./scripts/testnet/synergy-genesis.sh diff \
  --genesis genesis.testnet.json \
  --expected-hash "$(cat release-artifacts/testnet/genesis.testnet.hash.txt)"
```

The node must refuse to start or peer if:

- `network.chain_id` is not `1264`.
- `network.network_id` is not `1264`.
- The local `genesis_hash` differs from `network-identifiers.testnet.json`.
- `network_magic_bytes` differs from the published value.
- A peer advertises the same chain ID with a different genesis hash.

## Genesis Validator Preflight

Genesis validator operators should run preflight on the target host before starting consensus:

```bash
./scripts/testnet/synergy-genesis.sh preflight \
  --genesis genesis.testnet.json \
  --network-identifiers network-identifiers.testnet.json \
  --validator-address <validator-address> \
  --operator-address <operator-address> \
  --reward-address <reward-address> \
  --self-stake-nwei <self-stake-nwei> \
  --peer-id <peer-id> \
  --key-dir /path/to/local/keyfiles \
  --listen-address 0.0.0.0:5622 \
  --advertise-address <public-or-sentry-address>:5622 \
  --required-port <bootstrap-or-sentry-host>:5622 \
  --signing-challenge-verified
```

The signing challenge must be performed locally by the node or key manager. Do not print private keys, decrypted key JSON, seed phrases, mnemonic phrases, or wallet private material.

Recommended host checks:

```bash
timedatectl status || systemsetup -getusingnetworktime
ss -ltnp || lsof -nP -iTCP -sTCP:LISTEN
find /path/to/local/keyfiles -type f -perm +077 -print
```

Private material should be readable only by the node operator account. Public manifests and genesis files must contain only public addresses, public keys, peer IDs, validator IDs, commitments, and non-secret metadata.

## New Validator Admission Flow

1. Install the node software.
2. Fetch `network-identifiers.testnet.json` from the official source.
3. Fetch `genesis.testnet.json` from the official source or release bundle.
4. Verify release signatures or checksums if available.
5. Compute the genesis hash locally and compare it to `network-identifiers.testnet.json`.
6. Refuse to start if the hash, chain ID, network ID, or network magic bytes mismatch.
7. Generate validator keys locally or import existing keys through a secure key manager.
   After the checkpointed consensus-signature fork, validator consensus keys must be explicit FN-DSA keys with `consensus_key_type = "FN-DSA"` and a `fn-dsa:<base64>` public key. ML-DSA validator consensus keys, missing metadata, unknown labels, and ambiguous labels such as `pqc` or `aegis` must fail closed.
8. Submit a validator admission transaction or governance proposal with public key material only.
9. Bond at least `min_self_stake_nwei`.
10. Enter `pending` or `eligible` state according to finalized protocol state.
11. Wait for the next eligible epoch boundary.
12. Let cluster assignment and rotation derive deterministically from finalized state.
13. Start with neutral or zero Synergy Score according to protocol rules.
14. Connect through official bootnodes, seed nodes, and sentries. Do not require direct peering with private genesis validator infrastructure.

## Sync Modes

Use full sync when validating from genesis. Use state sync only when the checkpoint, quorum certificate, and state root are from the canonical Synergy Testnet identity.

Persistent peers should be configured sparingly. Prefer official seed/sentry discovery unless operating a dedicated infrastructure role.

## Consensus And DAG Safety

Transactions flow through the cluster-local certified DAG data plane:

```text
transactions
-> encrypted or committed batch
-> DAG vertex
-> availability receipts
-> DAG certificate
-> deterministic ordering cut
-> PoSy proposal
-> validator verification
-> dual-quorum QC finality
```

Only certified available DAG vertices may influence ordering. Cross-cluster traffic carries checkpoints, quorum certificates, and compact commitments, not raw global DAG flood. Validators must independently reconstruct the proposed order from DAG evidence. Proof of Synergy quorum certificates are the finality artifact; the DAG is not.

Synergy Score may influence cluster selection, proposer selection, governance weight, and reward shaping. It must not influence block validity, fork resolution, cryptographic verification, transaction acceptance, or state transition correctness.

## Failure Modes

| Failure | Required behavior |
| --- | --- |
| Wrong genesis hash | Refuse start or peer; report expected and actual hash. |
| Wrong chain ID | Refuse start or peer before consensus. |
| Wrong network magic bytes | Disconnect/refuse during handshake. |
| Wrong validator key | Start as non-validator or refuse validator mode. |
| Duplicate validator key | Refuse validator mode until duplicate is removed. |
| Wrong peer ID | Refuse genesis-validator preflight. |
| Stale genesis | Fetch canonical release and verify hash again. |
| Insufficient stake | Stay pending or reject admission. |
| Pending validator not active | Sync as full node until epoch admission. |
| Synced but not admitted | Do not propose or vote; submit admission and bond stake. |
| Same chain ID, different genesis hash | Treat as fork and disconnect immediately. |
