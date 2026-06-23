# Synergy Testnet Validator Onboarding

This guide covers Synergy Testnet chain `1264`. Genesis is immutable after public launch. New validators must join by finalized admission and staking state, not by editing `genesis.testnet.json`.

## Canonical Network Identity

| Field | Value |
| --- | --- |
| Chain ID | `1264` |
| Runtime Network ID | `synergy-testnet-v2` |
| Genesis `network.network_id` | `1264` |
| Native CAIP-2 | `synergy:testnet` |
| Reserved EIP-155 | `eip155:1264` reserved and inactive |
| Token | Synergy Testnet Token |
| Symbol | `SNRG` |
| Decimals | `9` |
| Base unit | `nWei` |
| Total supply | `12000000000` SNRG |
| Total supply in nWei | `12000000000000000000` |

The reserved EIP-155 identity must never override the native Synergy identity. EVM/EIP-155 support can only be enabled after the protocol and public RPC surface explicitly support it.

The runtime network label is `synergy-testnet-v2` after the checkpointed FN-DSA fork. The immutable genesis document still carries numeric `network.network_id = 1264`; do not rewrite genesis to force the runtime label into that field.

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
- runtime `network_id` is not `synergy-testnet-v2`.
- genesis `network.network_id` is not `1264`.
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

This `preflight` path is only for the five immutable genesis validators already present in `genesis.testnet.json`. Post-genesis validator onboarding must use the read-only `onboarding-dry-run` command below; a new validator must fail any process that tries to add it to genesis.

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

## Activation Boundary Invariant

Validator activation is a finalized-state transition, not a local service toggle.

1. The shadow phase is exactly `1000` finalized blocks.
2. A shadow validator has consensus weight `0`.
3. Shadow votes are ignored by consensus and must not count toward quorum.
4. Block `N` records activation using the validator set, quorum, and weights from `N-1`.
5. The activating validator remains weight `0` during Block `N`.
6. Block `N+1` applies the new validator set, quorum, and weights.

This transition must be deterministic, idempotent, replay-safe, restart-safe, epoch-safe, and fork-safe. Replay from genesis or from a verified canonical snapshot must restore the same `shadow_started_at_height`, `activation_recorded_height`, `activation_effective_height`, validator status, and consensus membership.

## Safe Dry-Run And Activation Checklist

Use the Synergy Node Control Panel `Verify Onboarding` action before any live action. This is the safe dry-run path: it must not start the runtime, restore snapshots, mutate chain state, submit stake, or submit activation.

The repository CLI dry-run gate is:

```bash
./scripts/testnet/synergy-genesis.sh onboarding-dry-run \
  --genesis genesis.testnet.json \
  --network-identifiers network-identifiers.testnet.json \
  --consensus-fork config/consensus-fork-migration.json \
  --runtime-network-id synergy-testnet-v2 \
  --validator-address <new-validator-synv1-address> \
  --consensus-key-type FN-DSA \
  --consensus-public-key "fn-dsa:<base64-public-key>" \
  --local-height <candidate-local-height> \
  --public-head-height <public-chain-head-height> \
  --p2p-port 5622 \
  --qrpc-port 5640 \
  --ws-port 5660 \
  --discovery-port 5680 \
  --metrics-port 6030 \
  --signing-challenge-verified \
  --seed-registration-verified \
  --relayer-peer-visibility-verified \
  --support-node-replay-preflight-verified \
  --funding-verified \
  --bonded-stake-verified \
  --source-majority-proof-verified \
  --shadow-duty-gate-verified
```

The command emits JSON with `mutates_state: false`. Treat any non-zero exit or any `ok: false` check as a launch blocker. It intentionally rejects validators already present in genesis, ML-DSA consensus keys, ambiguous key labels, wrong Testnet identity, non-canonical ports, stale local height, and missing dry-run evidence.

Required dry-run evidence:

1. Chain ID is `1264`.
2. Runtime network ID is `synergy-testnet-v2`.
3. Genesis `network.network_id` is `1264`.
4. Genesis hash matches the canonical Testnet release.
5. Consensus fork metadata matches height `204216`, parent height `204215`, parent hash `e209bd7554a06dfb052d5ff7ffd5664efc05e6cd1c5cadc9d139fa5bb9072816`, consensus algorithm `FN-DSA`, validator key algorithm `FN-DSA-1024`, and parser mode `fail_closed`.
6. Validator address starts with `synv1` and is not added to genesis.
7. Validator consensus key metadata is explicit `FN-DSA`; ML-DSA, unknown, missing, or ambiguous key labels fail closed.
8. P2P is reachable on `5622/tcp`; local qRPC, WS, discovery, and metrics use `5640`, `5660`, `5680`, and `6030` respectively unless an approved port assignment says otherwise.
9. The node is within `2` blocks of public chain head before activation.
10. Seed registration, relayer peer visibility, support-node replay preflight, liquid funding, bonded stake, source-majority proof, shadow observation, and duty-gate proof all pass.

Support-node replay preflight is required before activation. Bootnodes, seed nodes, relayers, RPC Gateway, Explorer/indexer, archive validator, observer, and Atlas API must be able to replay through Block `N` and `N+1` with the candidate in finalized registry state. Non-validator support nodes should run with `strict_validator_allowlist=false` or `SYNERGY_STRICT_VALIDATOR_ALLOWLIST=0`; if a legacy support node remains strict, its allowlist must include the candidate before `activation_effective_block`. Support services must use `validator_vote_threshold = 0` so runtime derives `ceil(active_validator_count * 67 / 100)` from finalized validator state.

The checkpoint `consensus-fork-migration.json` is not the live admission registry. It records the validators active at the checkpointed FN-DSA fork and must not be edited as the normal way to onboard post-genesis validators. After activation, a new validator's consensus key must resolve from finalized validator registry/admission state.

Only after clean dry-run evidence should the operator run `Run Safe Onboarding`. Staking and activation remain separate explicit actions.

Launch validation process:

1. Run `Verify Onboarding` and save the dry-run report.
2. Confirm the report contains only Testnet chain `1264`, runtime network `synergy-testnet-v2`, and the canonical genesis hash.
3. Confirm the candidate remains non-voting during sync and shadow observation.
4. Submit the explicit stake and activation actions only after funding, bonded stake, and source-majority proof pass.
5. Watch the 1000-block shadow window through the activation record block `N`.
6. Verify the candidate is still weight `0` at Block `N`.
7. Verify Block `N+1` applies the updated validator set and quorum.
8. Verify all existing validators, relayers, RPC Gateway, Explorer, Atlas, and monitoring remain at height parity after activation.
9. Record the activation transaction, Block `N`, Block `N+1`, validator-set hash before and after, and qRPC/metrics health evidence.

## Validator 6 Onboarding Proof

Validator 6 was installed through the node control panel path and activated on Testnet chain `1264`.

| Field | Value |
| --- | --- |
| Validator address | `synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx` |
| Activation transaction | `syntxn-3b040f0ada5c31d0f6e3158d584267216b76a55662d84fcc5438a9e4956f9704` |
| Shadow started | Block `314718` |
| Activation recorded | Block `315718` |
| Activation effective | Block `315719` |

Post-activation validation proved the candidate remained non-voting during the 1000-block shadow phase, became active at `N+1`, and was visible in runtime and observer onboarding metrics. The follow-up support-node fix above is now part of the dry-run gate because RPC Gateway, Explorer/indexer, and relayers must also replay the activation boundary without manual per-validator repair.

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
