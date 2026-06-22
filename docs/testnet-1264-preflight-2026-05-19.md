# Synergy Testnet Chain 1264 Preflight

Captured: 2026-05-19 09:56-10:00 UTC

No live reset, restart, deployment, firewall change, topology change, or release promotion was performed during this preflight.

## Repository And Release State

Node repository:
- canonical repo: `synergy-network-hq/testnet`
- local path: `/Users/devpup/Desktop/Testnet/synergy-testnet`
- current `main`: `e65a43aa2321aaac31847a429ec24e0e4043727e`
- node release tag: `v12.2.13` at `d13ae83a7442fb8c619cb98ca9ccb3274a913137`
- GitHub Actions run: `26082478522`
- run status: success
- jobs: macOS arm64 success, Linux amd64 success, Windows amd64 success, unified `latest.json` success
- release URL: `https://github.com/synergy-network-hq/testnet/releases/tag/v12.2.13`

Node release checksums:
- `synergy-testnet-linux-amd64`: `8b8f739ad4cdf82d86885e7af03774bbca76c6c8dcb3954cfc2eacabe365ea01`
- `synergy-testnet-macos-arm64`: `139068797ced6f27c730f33201800b9ee6ce045f1eced12d8f1572dea355a4e1`
- `synergy-testnet-windows-amd64.exe`: `5419454aa5c9b3d0dc350bf98bc4a2e451c99a25d6667c3a732b14702c77360a`

Control-panel repository:
- canonical repo: `synergy-network-hq/synergy-node-control-panel`
- local path: `/Users/devpup/Desktop/Testnet/synergy-testnet/node-control-panel`
- current release commit: `f74b51351ffdf160448bc792bbbd4929bcea9cdb`
- release tag: `v12.2.13`
- GitHub Actions run: `26090031815`
- current status at preflight write time: in progress
- verified started checks: checkout control panel source, checkout public Testnet node source, and genesis alignment validation passed

Atlas repository:
- canonical repo: `synergy-network-hq/synergy-atlas`
- local path: `/Users/devpup/Desktop/Testnet/explorer-app`
- current commit observed earlier: `3e87c36`

## Validator Plane

All five validators report the same local canonical head:
- height: `1817`
- hash: `fb6462d6105d0b51f9424313ea619f0385fe90be36c33a58d0c5fc497333a211`
- parent hash: `50591fc476913772f6eb66e52c6889b5e944c3ca10c2e6c04cf985561338fb2d`
- timestamp: `1779160986` / `2026-05-19T03:23:06Z`
- genesis hash in peer tables/manifests: `f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789`

Host wall-clock samples:
- validator samples around `1779184360-1779184398`
- local sample around `1779184574`
- latest block timestamp delta at local sample: about `23,588` seconds / `393.13` minutes behind wall clock

Validator runtime checksums:
- Validator 1: `e5b4202694f39139cd58268c14575e8270a8a1257cadee36ad043613eab0e06d`
- Validator 2: `e5b4202694f39139cd58268c14575e8270a8a1257cadee36ad043613eab0e06d`
- Validator 3: `e5b4202694f39139cd58268c14575e8270a8a1257cadee36ad043613eab0e06d`
- Validator 4: `e5b4202694f39139cd58268c14575e8270a8a1257cadee36ad043613eab0e06d`
- Validator 5: `e5b4202694f39139cd58268c14575e8270a8a1257cadee36ad043613eab0e06d`

Validator package/resource drift:
- monitor workspace manifest on validators: `12.2.9+8cf4e10b5aa5`, app version `12.2.9`
- installed `/opt/Synergy Node Control Panel/resources/testnet/runtime/workspace-manifest.json`: `12.2.10+10af72192276`, app version `12.2.10`
- both currently use numeric `network_id: 1264` and do not include `chain_id_hex`
- current control-panel source fixes generate `network_id: synergy-testnet-v2`, `network_native_id: 1264`, and `chain_id_hex: 0x4f0`

Consensus durability files on all validators:
- `committed_qcs.json`: exists, about `649,638,231` bytes, `1820` top-level entries
- `canonical_locks.json`: exists, about `1,049,831` bytes, `1817` entries, latest lock height `1817`

Health finding:
- validators are aligned by height/hash
- validators are not advancing at the sampled time
- latest block timestamp is stale by multiple hours because the old deployed runtime is still active

## Relayers, RPC, Atlas, Observer, Boot/Seed

Relayer 1:
- height/hash: `1817` / `fb6462d6105d0b51f9424313ea619f0385fe90be36c33a58d0c5fc497333a211`
- peers: 8
- includes private validator peers `10.69.0.1-10.69.0.5`, observer `10.69.0.250`, and public support peers on `74.208.227.23`
- process: `/opt/synergy/testnet/relayer/bin/synergy-testnet-linux-amd64`
- checksum: `9d24a29ed5812daff3761ea5a153a3475a35dc5fa379ca68cc80c92f4e8508a3`
- finding: active binary name is stale `testnet` material and must be replaced by the trusted Testnet release

Relayer 2:
- height/hash: `1817` / `fb6462d6105d0b51f9424313ea619f0385fe90be36c33a58d0c5fc497333a211`
- peers: 8
- includes private validator peers `10.69.0.1-10.69.0.5`, observer `10.69.0.250`, and public support peers on `74.208.227.23`
- process: `/opt/synergy/testnet/relayer/bin/synergy-testnet-linux-amd64`
- checksum: `9d24a29ed5812daff3761ea5a153a3475a35dc5fa379ca68cc80c92f4e8508a3`
- finding: active binary name is stale `testnet` material and must be replaced by the trusted Testnet release

Public RPC:
- URL: `https://testnet-core-rpc.synergy-network.io`
- height/hash: `1817` / `fb6462d6105d0b51f9424313ea619f0385fe90be36c33a58d0c5fc497333a211`
- peers: 2
- peers are only `relay1.synergy-network.io:5622` and `relay2.synergy-network.io:5622`
- direct SSH to the RPC/Explorer host failed with the supplied credential path, so DB and process checks remain pending

Atlas API:
- summary URL: `https://testnet-atlas.synergy-network.io/api/v1/network/summary`
- reported chain ID: `1264`
- latest block: `1817`
- average block time from header intervals: `2`
- total transactions: `0`
- active validators: `5`
- peer count: `2`
- indexedAt sample: `2026-05-19T09:56:14.784Z`
- latest block rows show block timestamps from `2026-05-19T03:23:06Z` back by two-second steps
- DAG topology API returned empty arrays: `vertices: []`, `edges: []`

Observer:
- process exists at `/opt/synergy/testnet/observer/bin/synergy-testnet-linux-amd64`
- checksum: `9d24a29ed5812daff3761ea5a153a3475a35dc5fa379ca68cc80c92f4e8508a3`
- local qRPC on `127.0.0.1:5640` was not listening during the sample

Boot/seed hosts:
- boot/seed host 1: seed service and bootnode process present; qRPC `127.0.0.1:5640` not listening
- boot/seed host 2: seed service and bootnode process present; qRPC `127.0.0.1:5640` not listening
- boot/seed host 3: SSH with supplied public root credential path failed during this preflight

## Topology And Public Exposure

Public port scan findings:
- validators 1-5: public service ports `5622`, `5640`, `5660`, `5680`, `5623`, `5641`, `5661`, `5681` closed from the public side
- Relayer 1: public `5622`, `5640`, `5660` open; `5623`, `5641`, `5661`, `5680`, `5681` closed
- Relayer 2: public `5622`, `5640`, `5660` open; `5623`, `5641`, `5661`, `5680`, `5681` closed
- RPC/Explorer host service ports in the direct scan returned closed, while the public HTTPS gateway remains reachable

Peer-table findings:
- validators peer with private validators, relayers, and observer over the private plane
- public RPC peers only with relayers
- relayers peer with private validators and public support nodes
- no direct public RPC-to-validator peer was observed

## Cadence

Header timestamp intervals from public RPC:
- latest 50 blocks: count 50, average `2`, min `2`, max `2`
- latest 120 blocks: count 120, average `2`, min `2`, max `2`
- latest 300 blocks: count 300, average `2`, min `2`, max `2`

Wall-clock cadence:
- latest validator/public height stayed at `1817` across the preflight samples
- effective live production cadence during the sample was `0` blocks over the sampled interval
- header intervals alone are not a valid liveness proof because the deployed old runtime stamps headers by parent timestamp plus two seconds

## Gate Result

Current live mutation is not approved until:

1. Control-panel `v12.2.13` CI installers complete and publish successfully.
2. The mutation plan names the exact trusted artifacts and checksums to install.
3. Backup paths for configs, logs, evidence, and current runtime state are recorded.

Required mutation plan after the installer workflow is green:

1. Install the trusted `v12.2.13` control-panel package on validators and support hosts where applicable.
2. Replace stale live runtime binaries with the CI-built Testnet runtime from the trusted package.
3. Remove/retire active `synergy-testnet-linux-amd64` launch paths from relayers and other support roles.
4. Preserve keys, configs, logs, evidence, WireGuard state, and service credentials.
5. Perform a controlled chain-state reset only after trusted artifacts are installed everywhere, clearing stale chain/QC/canonical-lock/proposal/cache/indexer state as documented in `docs/testnet-1264-live-rollout.md`.
6. Start in the documented order: bootnodes, validators, relayers, RPC/Explorer, Atlas/indexer, observer.
7. Verify validators produce new height-1+ QCs and canonical locks, relayers/RPC/Atlas catch up through relayers, timestamps are near wall clock, and block cadence is near two seconds.
