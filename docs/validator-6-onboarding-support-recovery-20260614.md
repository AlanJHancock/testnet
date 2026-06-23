# Validator 6 Onboarding Support Recovery - 2026-06-14

## Scope

Validator 6 onboarding completed through the control-panel-installed runtime path. This note records the support-node recovery and hardening work needed after activation so future post-genesis validators do not require manual checkpoint fork edits.

## Validator 6 Activation Evidence

| Field | Value |
| --- | --- |
| Validator address | `synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx` |
| Activation transaction | `syntxn-3b040f0ada5c31d0f6e3158d584267216b76a55662d84fcc5438a9e4956f9704` |
| Shadow started | `314718` |
| Activation recorded | `315718` |
| Activation effective | `315719` |

## Root Causes Fixed

1. Support nodes rejected or lagged post-activation replay because QC verification was effectively using BFT quorum for a six-validator set, while Testnet launch quorum is configured at `4`.
2. Post-fork key resolution treated `config/consensus-fork-migration.json` as the only source for every post-fork validator key. That file is checkpoint metadata, not the ongoing post-genesis validator admission registry.
3. Archive replay exposed a second key-encoding compatibility issue: Val6's finalized admission registry entry stores the consensus public key without a `fn-dsa:` prefix. Height-aware post-fork replay now parses non-genesis unprefixed registry keys as FN-DSA only after the active checkpoint fork applies, then still verifies signer bytes exactly.
4. Generated templates still carried old five-validator assumptions and strict support-node allowlists. Non-validator support nodes must not permanently cap their active validator view at genesis validators.

## Code And Config Changes

- `src/consensus/dual_quorum.rs`
  - Allows configured launch quorum `4` for expanded validator sets while preserving fail-closed behavior for thresholds below `4`.
- `src/consensus/validator_keys.rs`
  - Keeps checkpoint fork registry mandatory for genesis validators.
  - Falls back to finalized validator registry keys for non-genesis validators after the checkpoint fork.
  - Resolves existing post-genesis unprefixed registry keys as FN-DSA only in height-aware post-fork verification.
  - Requires fallback keys to validate as FN-DSA at post-fork heights.
- `scripts/testnet/genesis_tool.py`
  - Adds support-node replay preflight to onboarding dry-run output and activation gating.
  - Emits a `support_node_update_plan` describing support roles, quorum settings, allowlist policy, service env, and checkpoint registry policy.
- `tools/generate_templates.sh` and `templates/*.toml`
  - Generate `validator_cluster_size = 7`, `max_validators = 100`, and current launch ports.
  - Keep `strict_validator_allowlist = true` only for validator templates.
  - Use `strict_validator_allowlist = false` for support/public roles.
- `config/bootnode*.toml`, `config/network-config.toml`, `config/node_config.toml`
  - Set non-validator/default support allowlist mode to non-strict.

## Tests

Run locally from `/Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta`:

```bash
python3 -m unittest scripts/testnet/test_genesis_tool_onboarding.py
cargo test --manifest-path src/Cargo.toml consensus::validator_keys:: -- --test-threads=1
cargo test --manifest-path src/Cargo.toml consensus::dual_quorum:: -- --test-threads=1
```

Results:

- Onboarding dry-run tests: `5 passed`
- Validator key tests: `13 passed`
- Dual quorum tests: `32 passed`

Remote release test on `synergy-vps`:

```bash
cd /opt/synergy/build-testnet-codex-quorum-20260614T204944Z/src
~/.cargo/bin/cargo test --release consensus::validator_keys:: -- --test-threads=1
```

Result: `12 passed`.

Second local validator key regression run after the archive-specific untyped key fix:

```bash
cargo test --manifest-path src/Cargo.toml consensus::validator_keys:: -- --test-threads=1
```

Result: `13 passed`.

## Support Binary Deployment

Built on `synergy-vps` from `/opt/synergy/build-testnet-codex-quorum-20260614T204944Z/src`.

| Binary | SHA-256 |
| --- | --- |
| `synergy-rpc-gateway-node` | `f9b039367c872f67110c66fdb9491043da578baca6cf4a01ffb1cd02b37c2311` |
| `synergy-testnet` | `9c58e9cca3449c50d99c561111a74386ca6d22e79652034be926fb8028c31e49` |

Services changed:

| Host alias | Service | Binary path | Backup suffix | Restart |
| --- | --- | --- | --- | --- |
| `synergy-vps` | `genesisrpc.service` | `/opt/synergy/Node-RPC/bin/synergy-rpc-gateway-node-linux-amd64` | `.pre-codex-dynamic-onboarding-20260614T221033Z` | yes |
| `synergy-vps` | `synergy-node-exp.service` | `/opt/synergy/Node-EXP/bin/synergy-testnet-linux-amd64` | `.pre-codex-dynamic-onboarding-20260614T221033Z` | yes |
| `synergy-relayer1` | `synergy-testnet-relayer.service` | `/opt/synergy/testnet/relayer/bin/synergy-testnet-linux-amd64` | `.pre-codex-dynamic-onboarding-20260614T221106Z` | yes |
| `synergy-relayer2` | `synergy-testnet-relayer.service` | `/opt/synergy/testnet/relayer/bin/synergy-testnet-linux-amd64` | `.pre-codex-dynamic-onboarding-20260614T221106Z` | yes |

No validator services were restarted.

## Archive Validator Replay Recovery

Archive was already restored from the verified snapshot and online, but stalled at local height `316320` while replaying block `316321` after Val6 activation.

Observed blockers:

- Before first patch: `post-fork consensus registry missing validator synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx`
- Before second patch: `validator synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx has an untyped consensus key and is not present in canonical genesis`

Archive binary builds and deployments:

| Time UTC | SHA-256 | Purpose |
| --- | --- | --- |
| `2026-06-14T22:31:12Z` | `1121450a115299ef6fd518512f99f94545efd6a15bc87a041a7130b8f46e66a3` | Initial dynamic post-genesis registry fallback |
| `2026-06-14T22:35:42Z` | `15003b6fef2393bc3eb2b109efccfd8673138cdb91a0271e4f9a0f8b8e056900` | Post-genesis untyped registry key compatibility |

Archive service/config changes on `ssh synergy-archive`:

| Path | Change |
| --- | --- |
| `/usr/local/synergy/bin/synergy-archive-validator-node` | Replaced twice with timestamped backups before each install |
| `/Users/Shared/Synergy/archive-validator/workspace/config/node.toml` | Historical recovery set a fixed validator vote threshold; current configs must use `validator_vote_threshold = 0` so runtime derives dynamic quorum from the active validator set. |
| `/Users/Shared/Synergy/archive-validator/workspace/config/node.toml` | Added Val6 public P2P `157.173.192.45:5622` to `additional_dial_targets` and `persistent_peers` for the next archive restart |

Backups created:

- `/usr/local/synergy/bin/synergy-archive-validator-node.pre-codex-dynamic-onboarding-20260614T223112Z`
- `/Users/Shared/Synergy/archive-validator/workspace/config/node.toml.pre-codex-dynamic-onboarding-20260614T223112Z`
- `/usr/local/synergy/bin/synergy-archive-validator-node.pre-codex-untyped-postgenesis-20260614T223542Z`
- `/Users/Shared/Synergy/archive-validator/workspace/config/node.toml.pre-codex-untyped-postgenesis-20260614T223542Z`
- `/Users/Shared/Synergy/archive-validator/workspace/config/node.toml.pre-codex-add-val6-peer-20260614T224136Z`

Post-recovery archive evidence:

| Time UTC | Archive qRPC | Best peer | Gap | Notes |
| --- | ---: | ---: | ---: | --- |
| `2026-06-14T22:36:53Z` | `316335` | `317781` | `1446` | First successful advancement past blocked `316321` |
| `2026-06-14T22:41:53Z` | `316490` | `317817` | `1327` | No new Val6 key/QC rejection after fresh process startup |

Archive is online and catching up. Snapshot generation/restore still needs verification after archive reaches parity.

## Post-Deploy Verification

Direct qRPC samples:

| Time UTC | Node | Height |
| --- | --- | --- |
| `2026-06-14T22:16:09Z` | Val6 | `317622` |
| `2026-06-14T22:16:09Z` | RPC Gateway | `317622` |
| `2026-06-14T22:16:09Z` | Explorer | `317622` |
| `2026-06-14T22:16:08Z` | Relayer-1 | `317622` |
| `2026-06-14T22:16:09Z` | Relayer-2 | `317618`, catching up and qRPC responsive |
| `2026-06-14T22:18:59Z` | Relayer-2 | `317644`; Val6 was `317645` |

Observer Prometheus sample after scrape:

- Val6 onboarding runtime: up
- Val6 onboarding consensus participant: `1`
- RPC Gateway height gap: `0`
- Explorer height gap: `1`
- Relayer-1 height gap: `0`
- Relayer-2 qRPC up with small scrape-lag gap after restart; direct qRPC was within one block of Val6 at `2026-06-14T22:18:59Z`

## Relayer Memory Follow-Up

The earlier Relayer-1 OOM concern did not reproduce as an active Relayer-1-only leak after the support replay deployment. Both relayers show similar systemd cgroup `MemoryPeak` values from the restart/catch-up window, but current memory is bounded and chain state is capped.

Read-only samples:

| Time UTC | Node | Current RSS | Cgroup current | Cgroup peak | Height/gap | Hot blocks | OOM events | Current swap |
| --- | --- | ---: | ---: | ---: | --- | ---: | ---: | ---: |
| `2026-06-14T22:46:20Z` | Relayer-1 | about `384M` | `570929152` | `11854327808` | height `317825`, gap `0` | `5000` | `0` | `0` |
| `2026-06-14T22:46:20Z` | Relayer-2 | about `475M` | `512561152` | `11766714368` | height `317824`, gap `1` | `5000` | `0` | `0` |
| `2026-06-14T22:46:44Z` to `22:52:05Z` | Relayer-1 | `330M` to `580M`, final `493M` | under `1G` | unchanged | parity or gap `1` | `5000` | `0` | `0` |
| `2026-06-14T22:46:44Z` to `22:52:05Z` | Relayer-2 | `341M` to `787M`, final `390M` | under `1G` | unchanged | parity or small scrape gap | `5000` | `0` | `0` |

Current assessment: the observed high peak is a transient startup/catch-up peak affecting both relayers, not a continuing Relayer-1-only leak. The remaining hardening item is to keep a longer Prometheus/Grafana watch after archive parity and the next installer build, and to alert if cgroup current memory grows monotonically or `synergy_chain_blocks_total` exceeds the `5000` hot-window cap.

## Grafana Onboarding Visibility

Observer Grafana is provisioned from `/var/lib/grafana/dashboards/synergy` into Grafana `org-2`, folder `Synergy`, with a 30 second file polling interval.

Local reproducibility update:

- Updated `/Users/devpup/Desktop/Testnet-Beta/observability/scripts/generate_grafana_dashboards.py` so regenerated dashboards include onboarding jobs, onboarding node/phase/address selectors, and Val6/control-panel onboarding panels.
- Regenerated `/Users/devpup/Desktop/Testnet-Beta/observability/live-config-after/observer/dashboards/*.json`.

Live observer deployment on `ssh synergy-observer`:

| Time UTC | Change |
| --- | --- |
| `2026-06-14T23:05:53Z` | Backed up `/var/lib/grafana/dashboards/synergy` to `/var/lib/grafana/dashboards/synergy.backup.codex-onboarding-dashboard-repro-20260614T230553Z` |
| `2026-06-14T23:05:55Z` to `2026-06-14T23:05:59Z` | Replaced `synergy-validator-onboarding-and-activation-v2.json`, `synergy-consensus-and-finality-v2.json`, `synergy-validator-health-v2.json`, and `synergy-node-resource-usage-v2.json` |

Dashboards that now surface Val6/onboarding:

- `Synergy Validator Onboarding and Activation` (`uid: synergy-validator-onboarding-v2`)
- `Synergy Testnet Consensus and Chain` (`uid: synergy-consensus-finality-v2`)
- `Synergy Validator Health` (`uid: synergy-validator-health-v2`)
- `Synergy Node Resource Usage` (`uid: synergy-node-resource-usage-v2`)

Grafana loaded-resource verification after provisioning:

| Dashboard resource | Namespace | Folder | Resource version |
| --- | --- | --- | ---: |
| `synergy-validator-onboarding-v2` | `org-2` | `synergy` | `1781478385524013` |
| `synergy-consensus-finality-v2` | `org-2` | `synergy` | `1781478385421016` |
| `synergy-validator-health-v2` | `org-2` | `synergy` | `1781478385476015` |
| `synergy-node-resource-usage-v2` | `org-2` | `synergy` | `1781478385345016` |

Val6 Prometheus verification behind those dashboards:

| Metric | Val6 value |
| --- | ---: |
| `synergy_onboarding_runtime_up` | `1` |
| `synergy_onboarding_host_up` | `1` |
| `synergy_onboarding_consensus_participant` | `1` |
| `synergy_onboarding_height_gap` | `0` |
| `synergy_onboarding_peer_count` | `5` |

Browser check reached Grafana at `http://209.145.50.9:3000/d/synergy-validator-onboarding-v2?orgId=2&var-node=validator-6&var-onboarding_phase=active`, but the browser was redirected to `/login`. Operators should ensure they are in the `Synergy Network` organization (`orgId=2`) and open the `Synergy` folder if Val6 is not visible in their current Grafana view.

## Atlas Transaction And DAG Count Validation

Live Atlas/API/database validation on `2026-06-14T23:10Z` showed the transaction counters are aligned:

| Source | Value |
| --- | ---: |
| `transactions` table | `52` |
| `blocks.tx_count` sum | `52` |
| Atlas `/api/v1/network/summary.totalTransactions` | `52` |
| Atlas `/api/v1/dag/status.indexedTransactionCount` | `52` |
| Atlas `/api/v1/dag/status.transactionCount` | `52` |
| Unique DAG transaction references joined to indexed transactions | `52` |
| Missing DAG transaction references | `0` |
| Raw DAG vertex transaction-reference rows | `100` |

The larger DAG count is not a conflicting transaction total. It is the raw number of vertex-to-transaction references. The live DAG UI labels this as `DAG Transaction Links` with the note `Raw vertex references`, while the unique indexed transaction total is shown separately as `Indexed Transactions`.

Val6 funding/stake transaction is indexed:

- `syntxn-3070e6aa0bbe8d6bd8bff4a8bc2b65b112f95ed3f7693f94349dbd52a01b7e93`
- Block `312851`
- Amount `50000000000000` nwei
- Data prefix: `stake:`

Live Atlas DAG browser checks:

- `https://atlas.synergy-network.io/#/dag` renders `Indexed Transactions = 52` and `DAG Transaction Links = 100`.
- Selecting a graph vertex opens a selected-vertex panel with transaction count, parent count, block link, first transaction link, and transaction hash links.
- `https://atlas.synergy-network.io/#/dag/topology` renders the interactive topology and selecting a vertex opens the same transaction-aware detail panel plus a selected-vertex transaction list.
- Browser console check on DAG/topology showed no relevant errors or warnings.

## Remaining Follow-Up

- Include these source changes in the next installer/control-panel release build.
- Continue remaining launch blockers: archive parity/snapshot verification, longer Relayer memory watch, Atlas timestamp/SynID/DAG fixes, and transaction count alignment.

## Val4/Val5 Supported Rejoin Recovery

Live recovery on `2026-06-15T00:31Z` to `2026-06-15T01:45Z` completed the supported snapshot restore and shadow-observe path for the stale/quarantined genesis validators.

Code fixes built into staged helper `/tmp/synergy-testnet-linux-amd64.snapshot-6val`:

- `src/consensus/diagnostics.rs`: post-fork snapshot generation now accepts active validator sets with at least the genesis baseline instead of exactly 5; snapshot QC evidence now marks expanded active sets valid; `start-shadow-observe --required-blocks <N>` can re-arm an already shadowing quarantined validator.
- `src/consensus/self_realign.rs`: signed snapshot verification now treats the active validator count as a minimum genesis baseline and accepts expanded active sets whose QC signers are still members of the active set.
- `src/recovery.rs`: latest committed QC recovery verification now uses the configured Testnet launch quorum for expanded active sets, so 4-of-6 launch QCs pass recovery/head-match verification while preserving the 5-genesis-validator quorum behavior.

Focused tests run locally and on `ssh synergy-vps`:

- `consensus::diagnostics::tests::post_fork_snapshot_active_set_uses_consensus_fork_registry`
- `consensus::self_realign::tests::expanded_active_validator_set_snapshot_accepted`
- `recovery::tests::post_fork_qc_verification_accepts_configured_launch_quorum_for_expanded_set`

Helper build hashes:

- Snapshot verifier helper: `f5a54c3651f43234955d2508f6b323c28cd67363b3e0059b7b964cc4168200af`
- Recovery quorum helper: `303e8fff9d60f19c9c933d0d56e03b647fc08b9b8fcf478733a547b8c5c1a7bf`
- Shadow reset helper: `66b26c379456b5e7404900a67ec67778dcfc61ac6e235ec92426b5de2065c8e4`

Snapshot details:

- Source: Val1, `/home/justin/.synergy/testnet/nodes/validator-workspace/data/snapshots/snapshot-317970-1781484431`
- Manifest: `/home/justin/.synergy/testnet/nodes/validator-workspace/data/snapshots/snapshot-317970-1781484431/snapshot-317970-manifest.json`
- Manifest SHA-256: `20e2af779e2ee55d82e766125ef3dcdc14e6f909ef84d5a12d0c375cfb4d3270`
- Signed manifest hash: `cfdd3787f2f58fdfcb02b1a729ded450dced055334455bcd3b165e233edfb290`
- Snapshot artifact hash: `da974a50953503735b823a6955cb4141f60e5bdceb0dbd37112dc5e93b04a4be`
- Snapshot height/hash: `317970` / `d20c9b145aa583f8ecc9fb80c9d9bcc2c310ef987377af7e60908e86dcb61238`
- Active validator set size: 6, including Val6 `synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx`
- QC vote count/signers: 5 signers, Aegis/PQC verified

Preserved evidence and data changes:

- Val4 partial uncompressed snapshot transfer preserved at `/home/node/.synergy/testnet/nodes/validator-workspace/data/snapshots/snapshot-317970-1781484431.partial-unverified-20260615T005952Z`.
- Val4 self-heal evidence path: `/home/node/.synergy/testnet/nodes/validator-workspace/data/self-heal-evidence/1781486175-snapshot-restore`.
- Val5 self-heal evidence path: `/home/justin/.synergy/testnet/nodes/validator-workspace/data/self-heal-evidence/1781487379-snapshot-restore`.
- `self-heal-from-snapshot` restored only `chain.json`, `canonical_locks.json`, `committed_qcs.json`, `committed_qcs.jsonl`, `dag_state.json`, `validator_registry.json`, and `token_state.json`.
- Keys, configs, genesis, and quorum settings were not copied or mutated.

Current rejoin status:

| Validator | State | Shadow start | Process target | Full epoch required through | Latest observed | Mismatches | Duties |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| Val4 | `SHADOW_OBSERVING` | `319145` | `320145` | `320999` | `319220` | `0` | vote/propose/QC disabled |
| Val5 | `SHADOW_OBSERVING` | `319155` | `320155` | `320999` | `319177` | `0` | vote/propose/QC disabled |

Later parity and onboarding sample:

- `2026-06-15T01:53Z`: Val1 `319253`, Val2 `319253`, Val3 `319253`, Val4 `319253`, Val5 `319253`, Val6 `319253`.
- Val5 caught up after restart and remained in safe shadow observation.
- Val4 and Val5 remained duty-disabled while shadowing; neither was used as a real vote/proposal/QC source.

## Val6 End-To-End Activation Proof

Current status as of `2026-06-15T01:53Z`:

- Address: `synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx`
- Control-panel workspace: `/home/synergyop/.synergy/testnet/nodes/validator-6-control-panel`
- Runtime command: `/opt/Synergy Node Control Panel/resources/binaries/synergy-testnet-linux-amd64 start --config /home/synergyop/.synergy/testnet/nodes/validator-6-control-panel/config/node.toml`
- Config identity: chain ID `1264`, network ID `synergy-testnet-v2`, role `validator`, participation `active`
- Activation transaction: `syntxn-3b040f0ada5c31d0f6e3158d584267216b76a55662d84fcc5438a9e4956f9704`
- Shadow start: `314718`
- Activation recorded: `315718`
- Activation effective: `315719`
- Registry status: `Active`
- Stake: `50000.000000000` SNRG

Consensus participation evidence:

- Recent Val6 local committed QCs included Val6 signatures on consecutive canonical heights including `319262` through `319271`.
- Recent canonical committed blocks on Val1, Val2, and Val6 show Val6 as proposer at heights including `319237`, `319241`, `319245`, `319247`, `319249`, `319253`, `319257`, `319259`, `319261`, `319265`, `319269`, `319271`, `319273`, `319277`, and `319281`.
- Matching example on Val1 and Val2: height `319281`, hash `d53e3768acdf3d449e7d8b6cb9c458e0acc3bc4f44744321ef2ba49ba0f2eb0a`, validator `synv11zghr6nsm3ajl57ywxasw9mr5f844slq4mwx`.

Observed non-blocking churn:

- Val6 logs show some failed proposal attempts with `Insufficient validator votes: 1 votes, 4 required for quorum` after transient leader/vote-lock recovery. Those attempts are not currently launch-blocking because Val6 is also successfully producing canonical blocks and signing recent QCs.
- Block-time optimization is explicitly deferred unless the chain stalls or the observed timing starts interfering with onboarding/rejoin safety.

## Archive Snapshot Worker Follow-Up

Completed on `2026-06-15T04:10Z` after Val6 activation exposed a post-fork recovery verifier gap for validators activated after the original consensus fork registry.

Code changes:

- `src/recovery.rs`: post-fork QC recovery now accepts later activated validators only when their activation effective height can be proven from `activation_effective_height`, `activation_recorded_height + 1`, `shadow_started_at_height + 1000 + 1`, or a committed `validator_activation:` transaction in `dag_state.json`.
- `src/recovery.rs`: untyped post-fork public keys are accepted as FN-DSA only on the proven activated-validator path.
- `archive-validator/macos/archive-authority.py`: `--snapshot-class` now overrides the worker default class list instead of appending to it, allowing the LaunchDaemon to run only launch-critical `validator-pruned` snapshots.

Focused tests:

- `cargo fmt --manifest-path src/Cargo.toml`
- `cargo test --manifest-path src/Cargo.toml post_fork_qc_verification -- --test-threads=1`
- `python3 -m py_compile archive-validator/macos/archive-authority.py`

Archive host changes via `ssh synergy-archive`:

- Built release `synergy-archive-validator-node` locally with external target dir `/Volumes/xcode/synergy-testnet-beta-target` after the default target dir hit local disk pressure.
- Staged release runtime: `/Users/Shared/Synergy/archive-validator/bin/synergy-archive-validator-node.snapshot-fix-20260615T035319Z-release`
- Release runtime SHA-256: `c96a1dbf4ffda204c12babf88499f2163bd29d1ae6bebc337fbf06ccd21dcfb0`
- Installed patched archive control script at `/usr/local/synergy/bin/synergy-archive`; backup: `/usr/local/synergy/bin/synergy-archive.backup-20260615T035319Z`
- Updated LaunchDaemon `/Library/LaunchDaemons/io.synergynetwork.archive-snapshot-worker.plist`; backups:
  - `/Library/LaunchDaemons/io.synergynetwork.archive-snapshot-worker.plist.backup-20260615T035319Z`
  - `/Library/LaunchDaemons/io.synergynetwork.archive-snapshot-worker.plist.backup-20260615T0406-validator-pruned`
- Worker now runs with `--runtime /Users/Shared/Synergy/archive-validator/bin/synergy-archive-validator-node.snapshot-fix-20260615T035319Z-release --snapshot-class validator-pruned`.

Snapshot verification:

- Published `validator-pruned` snapshot `snapshot-000316320`, height `316320`, status `published`, verification `green`, chain ID `1264`, network `synergy-testnet-v2`.
- Published `support-rpc` snapshot `snapshot-000316320` from the scoped release worker proof, status `published`, verification `green`, runtime SHA-256 `c96a1dbf4ffda204c12babf88499f2163bd29d1ae6bebc337fbf06ccd21dcfb0`.
- Catalog signature verifies with AEGIS domain `SYNERGY_ARCHIVE_SNAPSHOT_CATALOG_V1`.

Cleanup:

- Removed failed generated staging directory `snapshot-000316320.validator-pruned.building-46344` after successful publish.
- Removed generated workspace snapshot roots `snapshot-316320-1781491218`, `snapshot-316320-1781495691`, and interrupted `snapshot-316320-1781496185`.
- No live archive workspace state, keys, config, genesis, or published green distributions were removed.

Current archive status:

- Archive status: `ok: true`
- Current archive height: `320506`
- Chain ID: `1264`
- Network ID: `synergy-testnet-v2`
- Genesis hash: `f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789`
- Free space after cleanup: about `62 GiB`
- Snapshot worker: running, scoped to `validator-pruned`, no active child snapshot job immediately after restart because latest `validator-pruned` snapshot is still within cadence.

Control panel readiness conclusion:

- Val6 proves the core consensus onboarding path can fund a validator, run the 1000-block shadow phase, record activation, apply activation at N+1, and participate in consensus.
- The control panel app should not be called fully launch-ready until the public installer path is tested again on a fresh host and proves automatic metrics setup, Grafana onboarding visibility, and installer-first validator setup without manual operator intervention.
