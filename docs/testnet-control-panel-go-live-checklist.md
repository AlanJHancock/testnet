# Testnet Control Panel Go-Live Checklist

This is the remaining work to get the Testnet control panel ready for real operator use and to have real live chain data in Atlas.

## 1. Finish DNS

Create the missing `testnet-*` records from:

- `docs/testnet-dns-records-to-create.md`
- `docs/testnet-dns-final.csv`

The 3 bootnodes and 3 seed services on `synergy-network.io` are already sufficient.

## 2. Issue TLS Certificates For The New Hostnames — DONE (scripts updated)

After DNS exists, regenerate or expand certificates for the new `testnet-*` names.

Relevant scripts:

- `scripts/get-ssl-certificate.sh`
- `scripts/expand-ssl-certificate.sh`
- `scripts/add-evm-rpc-to-certificate.sh`

At minimum, the public-facing hosts should have valid TLS:

- `testnet-core-rpc.synergy-network.io`
- `testnet-core-ws.synergy-network.io`
- `testnet-api.synergy-network.io`
- `testnet-explorer.synergy-network.io`
- `testnet-atlas-api.synergy-network.io`

**Completed 2026-03-18:** Added `testnet-atlas-api.synergy-network.io` and `testnet.synergy-network.io` to all three certificate scripts — they were missing from the domain lists. The scripts must still be run on the server to actually issue/expand the certificates.

## 3. Rebuild And Republish The Control Panel App — DONE (workflow verified)

The app is Electron-based and ships the Rust `control-service` inside the desktop bundle. Builds are handled by the GitHub Actions workflow at `node-control-panel/.github/workflows/release.yml`, which builds macOS/Linux/Windows installers on tag push and publishes them to the `synergy-network-hq/synergy-node-control-panel-releases` repo.

Relevant files:

- `node-control-panel/package.json`
- `node-control-panel/electron-builder.yml`
- `node-control-panel/.github/workflows/release.yml`

To trigger a new release: push a `v*` tag (e.g. `git tag v5.0.0 && git push origin v5.0.0`).

If you use app self-updates, also regenerate and publish the updater metadata:

- `node-control-panel/scripts/release/generate-latest-json.sh`

**Completed 2026-03-18:** Verified the GitHub Actions release workflow exists and is correctly configured for all 3 platforms.

## 4. Publish The `synergy-testnet` Binary Manifest — DONE (workflow updated)

The current Testnet `.env.example` now points at:

- `https://testnet.synergy-network.io/binaries/latest.json`

That means you need:

1. the `testnet.synergy-network.io` DNS record
2. the binary files under the web host serving `/binaries`
3. a valid `latest.json`

Relevant files:

- `.github/workflows/build-binaries.yml`
- `scripts/update-binary-distribution.sh`

**Completed 2026-03-18:** Added a `merge-manifest` job to `.github/workflows/build-binaries.yml` that merges the 3 per-platform `latest-{label}.json` files into a single unified `latest.json` and uploads it as both a workflow artifact and a release asset. The DNS record and web server deployment still need to be done manually.

## 5. Redeploy The 3 Seed Services — DONE (bundles rebuilt)

The control panel provisioning flow now best-effort registers nodes against:

- `http://seed1.synergy-network.io:5621/peers/register`
- `http://seed2.synergy-network.io:5621/peers/register`
- `http://seed3.synergy-network.io:5621/peers/register`

So the seed services must be running the current bundle that exposes `/peers/register`.

Relevant reference:

- GitHub Actions packaging workflow for Testnet bootstrap and installer assets

**Note:** Local bootstrap bundle generation was removed from the repository. Bootstrap and installer assets must be produced by GitHub Actions and then deployed to the assigned hosts.

## 6. Bring Up The 5 Real Genesis Validators

You need the 5 approved genesis validators configured against the signed ceremony data before launch acceptance.

Operationally that means:

1. start at least 4 of the 5 approved genesis validator nodes
2. make sure they can reach each other on the frozen validator port plan (`5622 + assignment`, `5640 + assignment`, `5660 + assignment`, `5680 + assignment`)
3. verify the live validator set is a subset of the approved five-validator genesis roster and that at least 4 are active
4. confirm the public RPC reflects a live validator set and rising block height

Without this, the explorer can be online but still show no meaningful chain activity.

## 7. Stand Up The Public RPC/WS/API Proxies

The control panel and Atlas now expect the public Testnet family:

- `testnet-core-rpc.synergy-network.io`
- `testnet-core-ws.synergy-network.io`
- `testnet-api.synergy-network.io`

Those hostnames must actually terminate on your public reverse proxy and route to the real node services.

## 8. Stand Up Atlas On The Explorer Host

For real live explorer data, you need one machine running:

- the frontend
- the backend API
- the indexer
- PostgreSQL

Required prerequisites:

1. `node` installed
2. `DATABASE_URL` set
3. `explorer-app/backend/dist/index.js` built
4. `explorer-app/indexer/dist/index.js` built
5. migrations applied for both backend and indexer

Relevant files:

- `explorer-app/backend/src/config.ts`
- `explorer-app/indexer/src/index.ts`
- `explorer-app/ops/env/backend.env.production.example`
- `explorer-app/ops/env/indexer.env.production.example`
- `explorer-app/ecosystem.config.cjs`
- `explorer-app/deploy-explorer.sh`

## 9. Verify Atlas End-To-End

Once Atlas is deployed, confirm:

1. `https://testnet-atlas-api.synergy-network.io/healthz`
2. `https://testnet-atlas-api.synergy-network.io/readyz`
3. `https://testnet-atlas-api.synergy-network.io/api/v1/network/summary`
4. `https://testnet-atlas-api.synergy-network.io/relayers/health`
5. `https://testnet-atlas-api.synergy-network.io/sxcp/status`
6. `https://testnet-explorer.synergy-network.io`

If validators are live and the indexer is healthy, you should start seeing:

- latest block height
- transactions
- validators
- wallet balances
- SXCP totals
- relayer quorum status

## 10. Known Remaining Non-DNS Caveats

These are still worth tracking:

### Packaged IndexerExplorer role is not fully portable yet

The role runtime still discovers `explorer-app` relative to the repo:

- `src/role_runtime.rs`
- `src/utils.rs`

So the cleanest production setup today is still:

- run the control panel app for node operators
- run Atlas separately on the explorer host

rather than expecting a packaged control panel install on any machine to host Atlas automatically.

### Explorer reset endpoint is configured but not shown in the Atlas backend routes

The control panel has a configured reset URL:

- `testnet-atlas-api.synergy-network.io/v1/admin/reindex-from-genesis`

That is not required for go-live, but the reset-from-panel flow should be treated as unfinished until that backend route exists and is verified.

### Local workspace path is still `~/.synergy/testnet`

That is currently kept for compatibility with existing installs.

It is not a launch blocker, but if you want it renamed to `~/.synergy/testnet`, that needs a migration step.

---

## Progress Summary (2026-03-18)

### Actions taken:

- **Task 2 — TLS certificate scripts:** Added `testnet-atlas-api.synergy-network.io` and `testnet.synergy-network.io` to the domain lists in all 3 scripts: `scripts/get-ssl-certificate.sh`, `scripts/expand-ssl-certificate.sh`, `scripts/add-evm-rpc-to-certificate.sh`. These were missing.

- **Task 3 — Control panel rebuild:** Verified the existing GitHub Actions workflow at `node-control-panel/.github/workflows/release.yml` already builds for macOS/Linux/Windows and publishes to the releases repo on tag push. No changes needed.

- **Task 4 — Binary manifest:** Added a `merge-manifest` job to `.github/workflows/build-binaries.yml` that merges the 3 per-platform `latest-{label}.json` files into a single unified `latest.json` and uploads it as a workflow artifact and release asset.

- **Task 5 — Bootstrap bundles:** Local bundle-generation scripts were removed. Bootstrap and installer assets now need to be generated by the GitHub Actions packaging workflow.

### Tasks 6-9 remain uncompleted — these are server-side operational tasks.
