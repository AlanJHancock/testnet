# Synergy Testnet Validator VPN Runtime Recovery

Generated: 2026-07-05T02:28Z

## Scope

- Primary live scope: validators 1-6 and relayers 1-3.
- Validator 7 is intentionally deferred per operator priority.
- SSH access rule used for VPS work: one persistent `ssh synergy-*` session per host; no raw IP SSH or repeated reconnect loops.
- Secret handling: no private keys, sudo passwords, or WireGuard private material recorded here.

## Target State

- Validators 1-6 use the new `sy-validator0` WireGuard interface and have no active or loadable legacy `wg0` configuration.
- Validators bind chain TCP listeners only to VPN addresses:
  - P2P: `10.69.10.N:5622`
  - qRPC: `10.69.10.N:5640`
  - metrics: `10.69.10.N:6030`
- Validators advertise and dial validator identities (`synv1...`) for consensus peer identity; VPN IPs are transport routes only.
- Relayers 1-3 use `sy-validator0`, expose public qRPC as support nodes, and keep P2P on VPN.
- All validators run the same six-validator set, the same runtime build, and compatible allowlist/peer/transport config.

## Completed Infrastructure Changes

- Stopped all six validators before VPN/config work.
- Disabled `wg-quick@wg0` everywhere in the validator/relayer fleet.
- Moved legacy `/etc/wireguard/wg0.conf*` material to timestamped backups under `/var/backups/synergy/retired-wireguard/`.
- Enabled and verified `wg-quick@sy-validator0` across validators 1-6 and relayers 1-3.
- Aligned validator configs to:
  - listen on each node's `10.69.10.N` VPN address,
  - preserve stable `synv1...` public validator identity,
  - use validator identity peer lists,
  - use relayers as support/public-facing nodes, not validator-to-validator intermediaries.
- Aligned relayer configs to map validator identities to validator VPN transports.
- Confirmed relayer3 parity with relayer1/relayer2 for WireGuard tooling, interface behavior, and support-node role.

## Runtime Rollback And Recovery

### Bad Runtime Removed

- Rolled back live fleet from `v15.0.6-shared-view-rotation-20260705`.
- Bad Linux runtime SHA-256: `a54d56ffcde36292bd8ff9f1f70a86dfeceb0299e960cc47d0b0dd99df584e06`.
- Reason: source allowed local same-height leader view offsets, which split live validators into competing leaders and caused canonical lock divergence.

### Stable Runtime Restored

- Restored live fleet to `v15.0.6-validator-peer-liveness-20260705`.
- Stable Linux runtime SHA-256: `cb1d2add7750d1f592b73059cbdb2bb2af39e616ba21090d087aadf9d57020ee`.
- Controlled order used:
  - stopped validators 1-6,
  - stopped relayers 1-3,
  - installed verified runtime,
  - started relayers,
  - started validators.

### Val1 Canonical State Repair

- Val1 diverged after the bad runtime and was repaired by cold restore from a canonical relayer source.
- Bad Val1 lock observed at h772159 with hash prefix `42b64b6a`.
- Canonical fleet lock observed at h772159 with hash prefix `1469b8d2`.
- Corrected restore source preserved historical recovery boundary h175518 and a 128-block canonical tail ending h772183.
- Restore bundle SHA-256 on Val1: `025be54475ee83ed8e28f8fcd67bd686fddd50c3023c85237d9533c4f928fbfa`.
- Restore helper dry run result: `DRY_RUN_GO`.
- Restore helper apply result: `GO`.
- Old Val1 state archive: `/var/backups/synergy/val1-pre-snapshot-restore-20260705T020644Z`.
- Val1 identity/config hash remained unchanged: `83040091235c5c2a480d49c83b61b5d57ec18a5a67f48f83dda5424c5266e5aa`.

## Live Verification

### qRPC Consensus Sample

Sample time: 2026-07-05T02:26:48Z

All validators 1-6 and relayers 1-3 reported canonical height `772347` with block hash prefix `0d56250462e4f1dc446aaa18`.

Validator peer visibility:

| Node | Height | Hash Prefix | Peers | Validator Peers |
| --- | ---: | --- | ---: | ---: |
| val1 | 772347 | `0d56250462e4f1dc446aaa18` | 8 | 5 |
| val2 | 772347 | `0d56250462e4f1dc446aaa18` | 8 | 5 |
| val3 | 772347 | `0d56250462e4f1dc446aaa18` | 8 | 5 |
| val4 | 772347 | `0d56250462e4f1dc446aaa18` | 8 | 5 |
| val5 | 772347 | `0d56250462e4f1dc446aaa18` | 8 | 5 |
| val6 | 772347 | `0d56250462e4f1dc446aaa18` | 12 | 5 |
| relayer1 | 772347 | `0d56250462e4f1dc446aaa18` | n/a | n/a |
| relayer2 | 772347 | `0d56250462e4f1dc446aaa18` | n/a | n/a |
| relayer3 | 772347 | `0d56250462e4f1dc446aaa18` | n/a | n/a |

### Listener/Topology State

- Validators: no public chain TCP listeners detected; P2P/qRPC/metrics are bound to `10.69.10.N`.
- Relayers: P2P is VPN-bound; qRPC is public by design for support-node traffic.
- Legacy `wg0` config: absent from active WireGuard locations after migration.
- Active VPN interface: `sy-validator0` on validators 1-6 and relayers 1-3.

## Block Cadence Findings

The previous 300-second payload timestamp stepping is no longer present on the stable runtime. Recent block timestamp deltas are mostly 2-4 seconds with missed-round outliers.

Sample from relayer2 at 2026-07-05T02:26:52Z, blocks h772312-h772347:

- Minimum delta: 2 seconds.
- Median delta: 3 seconds.
- Mean delta: 6.69 seconds.
- Maximum delta: 41 seconds.

Outliers still correlate with missed vote/proposal rounds rather than synthetic 300-second timestamp increments.

Likely remaining root cause:

- P2P connection bookkeeping still treated incoming VPN socket addresses as separate peers from the stable validator identity.
- When a stable peer was already connected inbound as `10.69.10.x:<ephemeral>`, bootstrap/discovery could redial the same `synv1...` target.
- Duplicate resolution then closed one connection, producing `Connection reset by peer` churn and occasionally dropping vote request/response traffic.
- That churn can cause `Insufficient validator votes: 3 votes, 4 required for quorum` and force a retry round.

## Source Follow-Up

Committed and pushed source fix:

- Commit: `d412a7f` (`Stabilize validator VPN peer sessions`)
- Tag: `v15.0.7-validator-vpn-peer-sessions-20260705`
- GitHub Actions run: `28726956759`

Source changes:

- `src/p2p/networking.rs`
  - Treat `validator_address` as a canonical match when deciding whether a peer is already connected.
  - Avoid redialing a validator identity that is already connected through an inbound VPN socket.
  - Preserve announced stable `synv1...` validator identity as public address instead of canonicalizing it away.
  - Added focused regression coverage for VPN peer identity matching and stable validator public address preservation.
- `src/consensus/consensus_algorithm.rs`
  - Reverted live leader selection behavior to canonical height schedule by ignoring local wall-clock view offsets for same-height leader selection.
  - Preserves fallback to the live set only when the scheduled leader is not live.

Local verification:

- `cargo check -q --lib` passed.
- Focused `cargo test` attempts were blocked by the local macOS arm64 PQC linker issue (`_PQCLEAN_randombytes`), not by test assertion failures.

## Remaining Work

- Keep monitoring cadence and vote-round behavior under the new runtime.
- Do not attempt a one-second block-time config until peer/session churn remains stable over a longer window.

## Completed v15.0.7 Rollout

Official build:

- Tag: `v15.0.7-validator-vpn-peer-sessions-20260705`
- Commit: `d412a7f`
- GitHub Actions run: `28726956759`
- Result: success across linux-amd64, windows-amd64, macos-arm64, and unified `latest.json` publication.
- Linux runtime SHA-256: `50be5f1eba985e2e3dd1597e4876cd4eb19b137e4a0e5df10f7deae1b31de6a3`.

Rollout procedure:

- Staged `synergy-testnet-linux-amd64` on validators 1-6 and relayers 1-3.
- Verified the staged SHA-256 on every host before service changes.
- Stopped validators 1-6 first.
- Stopped relayers 1-3 second.
- Backed up replaced runtime binaries under `/var/backups/synergy/runtime/20260705T0234Z`.
- Installed the verified Linux runtime on all nine hosts.
- Started relayers 1-3 first.
- Started validators 1-6 second.
- Verified every live validator and relayer process is using SHA-256 `50be5f1eba985e2e3dd1597e4876cd4eb19b137e4a0e5df10f7deae1b31de6a3`.

Transient post-start behavior:

- The first minute after restart showed short-lived propagation skew around h772427-h772435.
- The fleet reconverged without further restarts.
- No rollback was performed because all validators and relayers resumed forward progress and re-aligned.

Final live proof:

Sample time: 2026-07-05T02:48:21Z

| Node | Height | Hash Prefix | Peers | Validator Peers |
| --- | ---: | --- | ---: | ---: |
| val1 | 772486 | `118f405e2ff1b5e8389a257d` | 8 | 5 |
| val2 | 772486 | `118f405e2ff1b5e8389a257d` | 8 | 5 |
| val3 | 772486 | `118f405e2ff1b5e8389a257d` | 8 | 5 |
| val4 | 772486 | `118f405e2ff1b5e8389a257d` | 8 | 5 |
| val5 | 772486 | `118f405e2ff1b5e8389a257d` | 8 | 5 |
| val6 | 772486 | `118f405e2ff1b5e8389a257d` | 8 | 5 |
| relayer1 | 772486 | `118f405e2ff1b5e8389a257d` | n/a | n/a |
| relayer2 | 772486 | `118f405e2ff1b5e8389a257d` | n/a | n/a |
| relayer3 | 772486 | `118f405e2ff1b5e8389a257d` | n/a | n/a |

Final convergence re-check:

- Sample time: 2026-07-05T02:50:24Z.
- Validators 1-6 and relayers 1-3 all reported height `772498`.
- All nine endpoints reported block hash prefix `05e18c35902094bc2d755748`.

Post-restart cadence sample:

- Range: h772443-h772486.
- Count: 43 timestamp deltas.
- Minimum delta: 2 seconds.
- Median delta: 3 seconds.
- Mean delta: 3.79 seconds.
- Maximum delta: 8 seconds.

By proposer:

| Proposer | Count | Mean Delta | Max Delta |
| --- | ---: | ---: | ---: |
| val1 | 7 | 2.86s | 4s |
| val2 | 7 | 4.14s | 7s |
| val3 | 8 | 2.25s | 4s |
| val4 | 7 | 3.71s | 8s |
| val5 | 7 | 5.00s | 8s |
| val6 | 7 | 5.00s | 8s |
