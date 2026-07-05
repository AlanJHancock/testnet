# STS Implementation Map

## Scope

STS is the native Synergy Token System for testnet. It is implemented as runtime state and transaction execution logic, not as a SynQ template, wallet-only ledger, or RPC-only side table.

This branch is `feature/native-sts-token-system-testnet`.

## Current Runtime Slice

- `src/sts.rs` defines the native STS wire payload, class discriminants, deterministic object ID derivation, fungible token registry, balances, snapshots, events, and policy checks.
- `src/lib.rs` exposes `pub mod sts`.
- `src/execution.rs` stores `StsState` inside `ExecutionState`, includes it in the deterministic state root, decodes STS payloads after Aegis authorization, charges native SNRG fees, and applies STS mutations atomically.
- Native SNRG is represented as the gas asset with `token_address = null`; the 41-zero string `00000000000000000000000000000000000000000` is reserved only as a compatibility placeholder for string-only surfaces.
- Non-native STS assets expose `token_address` equal to their deterministic Bech32m object ID, so every user-created fungible token has a non-empty `synb1`, `synb2`, or `synb3` token address.
- `src/sts.rs` enforces protocol-level unsafe-token protections: no native SNRG/Synergy impersonation, bounded uppercase symbols, immutable metadata in this slice, no unenforced allowlist/denylist/transfer-approval flags, bounded mint supply when mint authority exists, duplicate-symbol rejection, and a 1000 bps transfer-fee cap.
- `src/sts.rs` supports token image metadata at creation and `set_fungible_image`, which only the creator can execute and which locks the image after the first set.
- `src/bin/synergy-sts.rs` provides a dedicated `synergy-sts` CLI for building native STS payloads for create, mint, transfer, burn, freeze, thaw, pause, unpause, clawback, snapshot, set-image, and native-info workflows.
- The CLI emits `payload_hex` and payload JSON for signed transaction wrapping; it does not mutate chain state directly or call legacy token-manager RPC write methods.
- `.github/workflows/release-synergy-sts-cli.yml` publishes standalone macOS and Linux CLI binaries to `synergy-network-hq/synergy-sts-cli-releases`.
- `scripts/install-synergy-sts.sh` installs the released CLI on macOS and Linux, verifies release checksums by default, supports pinned versions, and can also install from a local source checkout or an existing binary.
- Atlas indexing support is implemented in `synergy-atlas`: the indexer decodes `synergy-sts-v1:` payloads, derives non-native `synb*` token addresses, materializes STS token definitions/events/balances/images, and the `/tokens` API merges STS assets into the token registry.
- Atlas exposes a wallet-authenticated `POST /tokens/:tokenAddress/image` fallback for the creator wallet to set an omitted image exactly once from the token detail view.

## Implemented Classes

- `synb1` / class `1`: basic fungible tokens.
- `synb2` / class `2`: managed fungible tokens with freeze, pause, and clawback flags.
- `synb3` / class `3`: policy fungible tokens with transfer fee, snapshot, vesting metadata validation, and max-wallet policies.
- `synn1` / class `11`: deterministic NFT collection and instance ID derivation.
- `synn2` / class `12`: deterministic controlled NFT collection and instance ID derivation.
- `synj` / class `21`: deterministic multi-asset collection ID derivation.
- `synk` / class `31`: deterministic credential ID derivation.

## Chain Identity

- STS uses the current Synergy testnet chain ID `1264` and network name `testnet`.
- The wider runtime exposes `SYNERGY_TESTNET_V2_CHAIN_ID = 1264` and `SYNERGY_TESTNET_V2_NETWORK_ID = "synergy-testnet-v2"` in `src/synergy_types.rs`.
- `synergy-sts` fails closed for non-testnet payload construction and emits `chain_id = 1264` in every payload artifact.

## Legacy Paths

- `src/token.rs` remains the legacy in-memory token manager and is not the canonical STS ledger.
- Legacy token registry responses now normalize identity metadata: `SNRG` has no token address, while non-native legacy tokens receive a deterministic `synb1` compatibility address until callers migrate to signed STS transactions.
- Existing token RPC write methods that mutate `TOKEN_MANAGER` directly are not canonical STS write paths.
- `src/address.rs` currently treats several `syn*` prefixes as protocol-controlled addresses; STS token IDs need a separate object-ID validation path before wallet/RPC/Atlas presentation is finalized.

## Follow-Up Integration

- Add RPC methods that submit signed STS payload transactions instead of mutating token state directly.
- Add read RPC methods for STS token definitions, balances, snapshots, and events.
- Add RPC-backed `synergy-sts --submit` flow after signed transaction wrapping is finalized.
- Add SDK builders for `StsSignedPayload` and payload encoding.
- Add wallet signing/submit support for STS payloads.
- Deploy Atlas STS image migrations and indexer/API/frontend changes, then prove a live STS create transaction appears automatically on Atlas after finality.
- Add SynQ/AIVM host functions only after native STS execution is stable.
- Complete native state machines for NFT ownership, multi-asset balances, and credentials.

## Verification Notes

- Baseline `cargo test -p synergy-testnet` failed before STS implementation with one consensus test failure and five SynQ fixture failures caused by missing `Counter.compiled.synq`.
- `cargo check -p synergy-testnet --bin synergy-sts` passes after this slice.
- `cargo test -p synergy-testnet --lib sts::tests` passes with 10 focused STS tests.
- `cargo test -p synergy-testnet --bin synergy-sts` passes with 4 focused CLI tests.
