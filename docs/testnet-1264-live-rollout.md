# Synergy Testnet Chain 1264 Live Rollout

Date: 2026-05-20

This runbook is for Synergy Testnet chain 1264 only.

Canonical identity:
- Product/network name: Synergy Testnet
- chain_id: `1264`
- chain_id_hex: `0x4f0`
- network_id: `synergy-testnet-v2`
- genesis validators: 5
- active validator quorum: dynamic 67% of the active validator set
- cluster_count: 1
- cluster_id: 0
- target block cadence: 2 seconds

## Release Source

Trusted runtime artifacts must come from the public canonical repositories:
- Node source and binaries: `synergy-network-hq/testnet`
- Node Control Panel: `synergy-network-hq/synergy-node-control-panel`
- Atlas, when applicable: `synergy-network-hq/synergy-atlas`

Do not deploy ad hoc local binaries while the public GitHub Actions artifact path is available.

Current deployed release and pending source:
- Node runtime tag: `v12.2.19`
- Node runtime commit: `c3b2585`
- Node GitHub Actions run: `26107094704`
- Control Panel tag: `v12.2.19`
- Control Panel commit: `eb82d19`
- Control Panel GitHub Actions run: `26108441314`
- Latest node source commit: `b019c61` (`fix: wire aegis pqvm transaction submission path`)
- Latest green node tag: `v12.2.25`
- Latest green node GitHub Actions run: `26185757460`
- Latest Control Panel source commit: `342deb9` (`fix: install release validation tools`)
- Control Panel `v12.2.24` workflow run `26185416441` failed before installer build because bundled-asset validation expected `rg` on runners.
- Latest green Control Panel tag: `v12.2.25`
- Latest green Control Panel GitHub Actions run: `26186714962`
- Source newer than `v12.2.25`: `b019c61` adds `synergy_submitAegisTransaction` and Aegis envelope validation for typed transaction-key DAG submission. Do not deploy this change until a new trusted release artifact exists.

Trusted Linux runtime checksum:
- Node `v12.2.25` Linux `synergy-testnet`: `bc74a3ae1a480c5dae351ebed2707c5c34b3bf9046f0b60ea68900bd2caf467a`
- Control Panel `v12.2.25` Linux `.deb`: `03e49542343ff82f77307a8262465f14cb83010613b7c6b946c4b565469cd7b8`

Latest read-only live preflight note:
- Validators 1, 2, 4, and 5 continue advancing.
- Validator 3 is stuck/divergent at height `11668` with canonical lock hash `5b3bed3ac4377db5451fdc68366f31b14103fb867a4d8b756a29472435f444a2` and rejects a conflicting block hash `b8871be5fcb4f3b8069ecfd23287ed9ab1e0c747684c2edeaaf7e52214c0f915`.
- Public RPC latest 50/120/300 block interval averages sampled around 3 seconds, not the 2 second target.
- Do not claim fleet stability until Validator 3 is reconciled with evidence preserved and cadence is remeasured.
- Do not deploy from local binaries. Use synchronized trusted node and Control Panel `v12.2.25` release artifacts only, after fresh preflight and mutation plan.

## 2026-05-20 Evidence-Preserving Repair Notes

Validator 3 repair:
- Pre-repair state: Validator 3 was stuck/divergent at height `11668` on hash `5b3bed3ac4377db5451fdc68366f31b14103fb867a4d8b756a29472435f444a2`.
- Evidence backup: `/home/rob/.synergy/backups/v3-divergence-pre-v12.2.25-20260520T201929Z`.
- Action: installed trusted Control Panel `12.2.25`, verified `.deb` checksum `03e49542343ff82f77307a8262465f14cb83010613b7c6b946c4b565469cd7b8`, replaced the workspace runtime with trusted node checksum `bc74a3ae1a480c5dae351ebed2707c5c34b3bf9046f0b60ea68900bd2caf467a`, cleared only local chain-following state, and restarted from genesis.
- Preserved: validator keys, configs, logs, evidence, and operator identity material.
- Current status at this note: Validator 3 is rebuilding and not yet caught up.

Validator 1 same-height conflict repair:
- During Validator 3 catch-up, Validator 1 accepted a conflicting canonical lock at height `13781`.
- Validator 1 conflicting block: `e5b3540999f5ee8aa29e8aecc3bda503216fe6218eb47cb5a001fd7a11cb51be`.
- Canonical block agreed by Validators 2/4/5 and public RPC: `a1c25fb8821e43fbd3be3718032c527b9b9e67b375b4d62ecf59e00f84cd83a1`.
- Shared parent at height `13780`: `5cb9fb7718ffc2175358bfb7ca87b572b277a5f3f70384d71a35f1d8efc7d3f4`.
- Evidence backup: `/home/justin/.synergy/backups/v1-divergence-13781-pre-v12.2.25-20260520T203850Z`.
- Action: installed trusted Control Panel `12.2.25`, verified `.deb` checksum `03e49542343ff82f77307a8262465f14cb83010613b7c6b946c4b565469cd7b8`, replaced the workspace runtime with trusted node checksum `bc74a3ae1a480c5dae351ebed2707c5c34b3bf9046f0b60ea68900bd2caf467a`, removed only Validator 1 height `13781+` canonical/QC conflict artifacts and volatile proposal/vote caches after backup, and restarted from persisted canonical height `13780`.
- Post-repair proof: height `13905` returned the same hash `00a555dee612ca8b568bff4b23ce4b9ed0b7738717b4409033615845389c34de` on Validator 1, Validator 2, Validator 4, Validator 5, and public RPC.
- Safety note: because Validator 3 is still rebuilding, do not restart or roll the remaining Validators 2/4/5 unless a new preflight proves enough quorum margin or the planned action accepts a temporary finality pause.

Trusted Control Panel Linux package for current repair work:
- `synergy-node-control-panel_12.2.25_amd64.deb`
- digest: `sha256:03e49542343ff82f77307a8262465f14cb83010613b7c6b946c4b565469cd7b8`

Resolved follow-up after v12.2.18:
- Later live sampling showed block cadence drifting to about 3.3 seconds over the latest 50 blocks.
- Root cause: `data/committed_qcs.json` was rewritten and fsynced as a full QC map on every committed block. At about height 400 it had grown to 161 MB, which delayed follower block application and next-leader proposal readiness.
- v12.2.19 changed committed QC persistence to append-only `data/committed_qcs.jsonl`, loads both legacy JSON and JSONL for compatibility, skips duplicate QC appends, and records P2P QCs only after the block extends the local canonical tip.
- v12.2.19 was promoted through the trusted GitHub Actions artifact path, then installed from release artifacts.

## Final Reset / Start Sequence Used

The final v12.2.19 reset preserved validator keys, peer identity keys, configs, WireGuard state, logs, evidence, and service credentials.

Cleared on validator and relayer runtime workspaces:
- `chain.json`
- `committed_qcs.json`
- `committed_qcs.jsonl`
- `canonical_locks.json`
- `consensus_vote_locks.json`
- DAG and token state
- stale proposal/vote/local-finalized caches
- stale per-network state directories moved into timestamped backups

Start sequence:
1. Stopped relayers.
2. Installed Control Panel `12.2.19` on all five validators.
3. Staged validator runtimes from installed package resources.
4. Reset validator runtime state.
5. Started all five genesis validators.
6. Verified QCs and canonical locks from height 1 onward.
7. Updated and restarted relayers with the trusted `v12.2.19` binary.
8. Repointed Atlas to relayer-only local tunnels.
9. Backed up and reset Atlas DB tables.
10. Restarted public RPC and Atlas services.

Final v12.2.19 observation evidence:
- All five validators sampled at height 691 with hash `87a3338b82167705bd3d22cad9173c746042dac0fa4fa2d1470c7b60ab4c3b70`.
- Public RPC sampled at height 917 with hash `cc90af52ad7a99ff01bb095f34589f152eed3733eec34ec015bf12c9e4794e57`.
- Public RPC advanced 299 blocks in 598.025 seconds during the observation window.
- Final short cadence sample observed 18 blocks in 34.842 seconds.
- Atlas DB was reset and reindexed for chain 1264.
- Atlas DAG tables/API were empty after reset because no valid post-reset signed DAG transactions had been submitted; do not inject demo DAG data.
- Inactive pre-v12.2.19 `synergy-testnet` service-host build directories were moved to a retired-builds archive after current-process checks proved the active services were running the v12.2.19 binary.

## Live Service Routing

Relayer local tunnels on the Atlas/RPC host:
- Relay 1 qRPC: `http://127.0.0.1:8640`
- Relay 2 qRPC: `http://127.0.0.1:9640`

Public RPC:
- HTTPS JSON-RPC: `https://testnet-core-rpc.synergy-network.io/rpc`
- Raw public qRPC listener: `0.0.0.0:5641`
- Raw public WS listener: `0.0.0.0:5661`

Atlas API:
- `https://testnet-atlas-api.synergy-network.io/api/v1/network/summary`
- `https://testnet-atlas-api.synergy-network.io/api/v1/blocks`
- `https://testnet-atlas-api.synergy-network.io/api/v1/dag/status`

## Required Preflight Before Future Live Mutation

Capture and attach the following before any reset, restart, installer deployment, release promotion, firewall change, or topology change:
- node, control-panel, and Atlas repo commit/tag
- GitHub Actions run IDs, artifact URLs, and checksums
- all five validator heights, hashes, genesis hashes, runtime binary checksums, and workspace resource versions
- committed QC and canonical-lock file existence/latest height on each validator
- latest block timestamp and validator host wall-clock delta
- relayer height, hash, peers, and runtime checksum
- public RPC height and hash
- Atlas API/indexer height and database latest indexed block
- observer, bootnode, and seed service status
- validator and relayer peer tables
- direct public-to-validator exposure check
- block interval statistics over latest 50, 120, and 300 blocks
- whether Atlas is indexing and whether DAG rows exist
- whether any validator is divergent, lagging, or failing health checks

## Post-Rollout Proof Requirements

Do not describe a future rollout as complete until the final report proves:
- all five validators agree by height/hash
- relayers are synced
- public RPC is synced
- Atlas is synced and current
- latest block timestamps are close to wall clock
- block cadence is near 2 seconds over latest 50/120/300 blocks
- release package and live runtime checksums match
- no direct public-node-to-validator peers exist
- no active deployable material for deprecated environments or chain 1262/1263 identity remains
