# SynQ Testnet Admission Readiness Proof - 2026-06-15

Scope: local Testnet-Beta source proof for carrying SynQ deploy/call authorization into Synergy chain admission, executing admitted SynQ payloads through Synergy-AIVM, and preserving deterministic receipts/state. This note was updated on 2026-06-17 and does not claim live TESTNET deployment or finalized block inclusion.

## Implemented In This Slice

- `src/synq_admission.rs` verifies versioned `SynQAdmissionEnvelope` deploy and call carriers through `aegis-pqsynq`.
- Deploy carriers remain backward-compatible with hash-only admission, and can now carry executable bytecode, ABI JSON, and manifest JSON when `--synq-bytecode`, `--synq-abi`, and `--synq-manifest` are supplied together.
- Artifact-bearing deploy carriers fail closed during admission if provided bytes do not hash exactly to the verified `aegis-pqsynq` deploy envelope.
- Deploy admission enforces chain `1264`, testnet network alias normalization, `SYNQ_CONTRACT_DEPLOY_V1`, ML-DSA-65 launch policy, signer identity, payload hash, bytecode hash, manifest hash, and ABI hash.
- Call admission enforces chain `1264`, testnet network alias normalization, `SYNQ_CONTRACT_CALL_V1`, ML-DSA-65 launch policy, signer identity, and payload hash.
- `src/bin/synergy-node.rs` accepts `--synq-deploy-envelope`, optional deploy artifact paths, and `--synq-call-envelope` on `tx create-aegis`, `tx sign-aegis`, and `tx submit-aegis` paths. The binary verifies and wraps the signed pqsynq envelope into `SynQAdmissionEnvelope` payload bytes before outer Aegis transaction signing.
- `src/bin/synergy-node.rs` also exposes `synq replay-flow`, a local proof command that reads a signed deploy envelope, executable deploy artifacts, and optional signed call envelopes, wraps them through SynQ admission, batch-signs ordered outer Aegis transactions, executes them through AIVM, and replays the same signed transaction sequence to prove deterministic receipt hashes and state roots.
- `src/aegis_tx_tool.rs` preserves `synq_verification` in the signed Aegis transaction report after outer `aegis-pqvm` verification and DAG admission.
- `src/aegis_tx_tool.rs` can batch-sign an ordered sequence with one generated Aegis transaction key and a shared DAG mempool, linking explicit dependencies so deploy -> call -> call demos are admitted in deterministic order.
- `src/synq_execution.rs` bridges admitted SynQ carriers into Synergy-AIVM execution. Deploys require executable artifacts, validate artifact hashes through AIVM, register the deployed artifact only after AIVM succeeds, and preserve deterministic AIVM receipt summaries.
- `src/synq_execution.rs` derives deployed SynQ contract addresses from the verified deploy envelope using the `SYNERGY_SYNQ_CONTRACT_ADDRESS_V1` domain instead of reusing the signer address.
- `src/synq_receipts.rs` persists a deterministic SynQ receipt/AIVM checkpoint index. The index stores public receipt JSON, transaction-hash aliases, block mappings, AIVM contract state, artifact records, and deployment records. The default path is `data/synq_receipts.json`, overrideable with `SYNERGY_SYNQ_RECEIPT_INDEX_PATH`.
- `src/execution.rs` carries admitted SynQ verification summaries into transaction receipts, invokes the SynQ/AIVM bridge, includes SynQ artifact/deployment state in the state root, and fails closed without balance transfer when AIVM rejects or reverts a SynQ payload.
- `src/rpc/rpc_server.rs` now attaches SynQ verification and Synergy-AIVM receipt summaries to `synergy_getTransactionReceipt`, `synergy_getReceipt`, and `synergy_getBlockReceipts` by materializing committed Aegis carrier payloads through the SynQ/AIVM lane into the persisted index. Replay uses the committed carrier transaction timestamp for pqsynq verification so historical receipts do not become invalid when a signing envelope later expires.
- `aegis-pqvm` exposes ML-DSA detached verification routes needed by the pqsynq-backed path and uses a non-recursive process RNG shim for pqrust compatibility.
- `synergy-aivm/runtime/aivm-core/src/state.rs` serializes deterministic AIVM contract state as ordered entries so Synergy nodes can persist and reload SynQ execution checkpoints without JSON map-key ambiguity.
- `synergy-aivm/runtime/aivm-core/src/synq_runtime.rs` adds a stateful SynQ Counter runtime path for deploy, increment, and get using checked-in SynQ bytecode, ABI, and manifest artifacts.
- The testnet source tree now vendors `synq-language` and `synergy-aivm` as release submodules so local and GitHub release builds use the same SynQ compiler, `aegis-pqsynq`, pqrust, and AIVM sources without absolute workstation paths.
- The AIVM Counter path validates manifest/ABI/bytecode hashes, enforces chain `1264` and ML-DSA-65 policy through the existing artifact validator, meters ordinary gas plus admission PQ-Gas, commits successful state overlays, rolls back failed calls, and emits deterministic stateful receipt hashes.
- Synergy-layer tests now prove deploy -> increment -> get through `execute_block`, replay the same signed carrier bytes from fresh state, and assert matching deterministic state roots and receipt hashes.
- RPC-layer tests now prove committed Aegis carrier data can be queried back as deterministic SynQ/AIVM receipts for Counter deploy -> increment -> get, that persisted receipt lookup works after the hot-chain window no longer contains the transaction, that AIVM state/artifacts/deployments carry forward across a compacted window, and that hash-only deploys fail closed with a structured `SYNQ-AIVM-ARTIFACT` receipt.
- Negative Synergy-layer tests prove hash-only deploys fail closed before AIVM execution and bad call selectors roll back AIVM state.

## Local Proof Commands

The commands below passed locally across 2026-06-15 and 2026-06-16.

```bash
cargo fmt --all --check
cargo check -p synergy-testnet --bin synergy-node
cargo test -p synergy-testnet --lib synq_admission::tests -- --nocapture
cargo test -p synergy-testnet --lib execution::tests -- --nocapture
cargo test -p synergy-testnet --lib aegis_tx_tool::tests -- --nocapture
cargo test --manifest-path /Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta/synq-language/aegis-pqsynq/pqsynq/Cargo.toml --test synq_verifier_tests --locked
cargo test --manifest-path /Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta/aegis-pqvm/Cargo.toml --test integrations_dispatch --test vm_validation --test security_smoke --locked
cargo test --manifest-path /Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta/synq-language/Cargo.toml -p compiler --test artifact_test --locked
cargo test --manifest-path /Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta/synq-language/Cargo.toml -p cli --test integration_test --locked
cargo fmt --manifest-path /Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta/synergy-aivm/runtime/aivm-core/Cargo.toml --all --check
cargo test --manifest-path /Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta/synergy-aivm/runtime/aivm-core/Cargo.toml --locked --lib synq_runtime::tests -- --nocapture
cargo test --manifest-path /Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta/synergy-aivm/runtime/aivm-core/Cargo.toml --locked --all-targets -- --nocapture
cargo run --manifest-path /Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta/synergy-aivm/runtime/aivm-core/Cargo.toml --locked --example counter_state_demo
```

The focused 2026-06-16 Synergy checks passed:

```bash
cargo fmt --all
cargo fmt --all --check
cargo test -p synergy-testnet --lib rpc::rpc_server::tests -- --nocapture
cargo test -p synergy-testnet --lib execution::tests -- --nocapture
cargo check -p synergy-testnet --bin synergy-node
cargo test -p synergy-testnet --lib synq_admission::tests -- --nocapture
cargo test -p synergy-testnet --lib aegis_tx_tool::tests -- --nocapture
cargo fmt --manifest-path /Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta/synergy-aivm/runtime/aivm-core/Cargo.toml --all --check
cargo test --manifest-path /Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta/synergy-aivm/runtime/aivm-core/Cargo.toml --locked --all-targets -- --nocapture
```

The focused 2026-06-17 git-backed checks passed. Current portable release builds use the in-repo submodule paths under `/Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta`:

```bash
CARGO_TARGET_DIR=/Volumes/xcode/cargo-targets/synq-language-git cargo test --manifest-path /Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta/synq-language/compiler/Cargo.toml -- --nocapture
CARGO_TARGET_DIR=/Volumes/xcode/cargo-targets/synq-language-git cargo test --manifest-path /Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta/synq-language/cli/Cargo.toml -- --nocapture
CARGO_TARGET_DIR=/Volumes/xcode/cargo-targets/synq-language-git cargo test --manifest-path /Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta/synq-language/vm/Cargo.toml -- --nocapture
CARGO_TARGET_DIR=/Volumes/xcode/cargo-targets/synq-language-git cargo test --manifest-path /Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta/synq-language/aegis-pqsynq/pqsynq/Cargo.toml --tests -- --nocapture
CARGO_TARGET_DIR=/Volumes/xcode/cargo-targets/synergy-testnet-beta cargo test --manifest-path /Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta/src/Cargo.toml synq -- --nocapture
CARGO_TARGET_DIR=/Volumes/xcode/cargo-targets/synergy-testnet-beta cargo test --manifest-path /Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta/src/Cargo.toml aegis_transaction_sequence_links_dependencies_in_shared_mempool -- --nocapture
```

The 2026-06-17 replay command proved the full local Counter flow from signed deploy envelope through ordered Aegis transactions and AIVM receipts:

```bash
CARGO_TARGET_DIR=/Volumes/xcode/cargo-targets/synergy-testnet-beta cargo run --quiet \
  --manifest-path /Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta/src/Cargo.toml \
  --bin synergy-node -- synq replay-flow \
  --chain-id 1264 \
  --network-id synergy-testnet-v2 \
  --synq-deploy-envelope /tmp/synq-counter-flow.7ddxWA/Counter.deploy.json \
  --synq-bytecode /tmp/synq-counter-flow.7ddxWA/Counter.compiled.synq \
  --synq-manifest /tmp/synq-counter-flow.7ddxWA/Counter.manifest.json \
  --synq-abi /tmp/synq-counter-flow.7ddxWA/Counter.abi.json \
  --synq-call-envelope /tmp/synq-counter-flow.7ddxWA/Counter.increment.json \
  --synq-call-envelope /tmp/synq-counter-flow.7ddxWA/Counter.get.json
```

Replay proof summary:

```json
{
  "all_receipts_succeeded": true,
  "replay_matches": true,
  "get_return": "0000000000000000000000000000000000000000000000000000000000000001",
  "final_state_root": "24d1faaefb8d2521cc2c2891ca2fe07c8cc509987755b3dc30f9ae0c751cd5a8"
}
```

Live RPC probe on 2026-06-17:

```json
{
  "rpc_url": "https://testnet-core-rpc.synergy-network.io",
  "diagnose_sync_target": "accepted",
  "latest_height": 365878,
  "synq_deploy_submit": "rejected",
  "error_code": "SYNQ-DISABLED",
  "error": "SynQ admission requires a release-safe aegis-pqsynq verifier; default launch runtime rejects SynQ carriers fail-closed"
}
```

The local CLI smoke also passed for deploy, increment, and get carrier creation using artifact-bearing deploy admission:

```bash
cargo run -q --manifest-path /Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta/synq-language/Cargo.toml -p cli -- init /tmp/synq-network-ready.4xDMxH/counter
cargo run -q --manifest-path /Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta/synq-language/Cargo.toml -p cli -- build /tmp/synq-network-ready.4xDMxH/counter/contracts/Counter.synq
cargo run -q --manifest-path /Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta/synq-language/Cargo.toml -p cli -- keygen --out-dir /tmp/synq-network-ready.4xDMxH/counter/keys
cargo run -q --manifest-path /Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta/synq-language/Cargo.toml -p cli -- sign-deploy --bytecode Counter.compiled.synq --manifest Counter.manifest.json --abi Counter.abi.json --private-key synq-testnet-mldsa65.private.json --output Counter.deploy.json --nonce 77
cargo run -q --manifest-path /Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta/synq-language/Cargo.toml -p cli -- sign-call --contract Counter --method increment --private-key synq-testnet-mldsa65.private.json --output Counter.increment.json --nonce 78
cargo run -q --manifest-path /Users/devpup/Desktop/Testnet-Beta/synergy-testnet-beta/synq-language/Cargo.toml -p cli -- sign-call --contract Counter --method get --private-key synq-testnet-mldsa65.private.json --output Counter.get.json --nonce 79
cargo run -q -p synergy-testnet --bin synergy-node -- tx create-aegis --chain-id 1264 --network-id synergy-testnet-v2 --synq-deploy-envelope Counter.deploy.json --synq-bytecode Counter.compiled.synq --synq-manifest Counter.manifest.json --synq-abi Counter.abi.json --include-signed-transaction
cargo run -q -p synergy-testnet --bin synergy-node -- tx create-aegis --chain-id 1264 --network-id synergy-testnet-v2 --synq-call-envelope Counter.increment.json --include-signed-transaction
cargo run -q -p synergy-testnet --bin synergy-node -- tx create-aegis --chain-id 1264 --network-id synergy-testnet-v2 --synq-call-envelope Counter.get.json --include-signed-transaction
```

Smoke assertion summary:

```json
{
  "status": "PASS",
  "workspace": "/tmp/synq-network-ready.4xDMxH",
  "checked_reports": [
    "deploy-report.json",
    "increment-report.json",
    "get-report.json"
  ],
  "outer_signature": "verified_through_aegis_pqvm",
  "synq_domains": [
    "SYNQ_CONTRACT_DEPLOY_V1",
    "SYNQ_CONTRACT_CALL_V1"
  ],
  "synq_algorithm": "ML-DSA-65",
  "chain_id": 1264,
  "signed_transaction_payload_present": true
}
```

The AIVM Counter runtime demo produced deterministic local deploy/call state output:

```text
execution_mode=stateful-synq-aivm
deploy_receipt_hash=3e8e556cc9885c31bf5dc64ddf725d145d0b0f075bd8450d3c51a345280f3523
counter_increment_return=1
counter_get_return=1
state_root=297f7b2c46b9ca7ac92780cdc799ffe22a992302049523090765cfca2d53c846
increment_receipt_hash=706dbb40dea86982c54706995f07a3d75828f49ad982065b165e51f3a9813128
get_receipt_hash=9e425dacbb3fbe2958b18e20da29dc9c284183a702959fdd454566d0fe18dd02
```

## Remaining Gaps

- The live public TESTNET RPC was not mutated in this proof. A live deploy submit reached the RPC on 2026-06-17, but the deployed runtime rejected it fail-closed with `SYNQ-DISABLED`; the public node fleet needs the release-safe `aegis-pqsynq` verifier/AIVM build before finalized SynQ deploy/call receipts can be produced.
- Synergy source execution now calls the stateful AIVM SynQ runtime for admitted deploy/call payloads, and local RPC receipt methods materialize committed Aegis carrier data into persisted SynQ/AIVM receipt summaries. This still needs live node verification through actual finalized blocks, public RPC, and Atlas/indexer surfaces.
- The persisted SynQ receipt/AIVM checkpoint index is local-node ready, but it has not yet been rolled out to live TESTNET services or wired into Atlas/indexer backfill and retention policy.
- Artifact-bearing deploy payloads are large because the deploy carrier contains executable bytecode, ABI, and manifest bytes. Production integration needs an explicit artifact availability and size policy before broad live use.
- The first production rollout still needs the deterministic SynQ contract-address derivation rule documented as a public compatibility contract before third-party contracts depend on it.
- The developer shorthand commands `synq deploy --chain 1264` and `synq call Counter.increment/get` are still not production-backed. The current clean path is `synq build`, `synq keygen`, `synq sign-deploy` or `synq sign-call`, then `synergy-node tx create-aegis|submit-aegis --synq-*-envelope`.
