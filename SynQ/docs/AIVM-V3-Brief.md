# AIVM: Where It Stands, What's Needed to Push Further

**Date:** 2026-08-12
**From:** Alan Hancock
**To:** hootzluh (CTO)
**Branch:** `feature/real-codegen-and-dispatch`

## First — a naming collision worth fixing

There are two unrelated things called "AIVM" in this repo:

1. **Abstract Instruction Virtual Machine** — the deterministic bytecode VM for SynQ smart contracts. This is what this brief is about, and it's live and working.
2. **AI-Powered Virtual Machine** — `src/aivm/*` (distributed AI compute, model registry, on-chain chat). This is dead code: its RPC handlers in `rpc_server.rs` are all commented out with `// TEMPORARILY DISABLED ... for quick compile`. This is presumably what the testnet-v3 landing page's "Next-Gen AI-Powered Virtual Machine" bullet refers to, and it's unrelated to the SynQ execution engine.

Recommend renaming one of these before V3 launch messaging goes out — easy to conflate them externally.

## What's already built (SynQ side — done, tested, live)

- **`SynQ/aivm` crate**: full native implementation per `synq-bytecode-spec.md` and `synq-aivm-execution-spec.md` (both v0.1, in `synq-language/specs/`). 108-byte header w/ SHA-256 hashes, 6 section types, full opcode table (plus extensions beyond spec v0.1: `ModU64`, `Ne`, `Le`, `Ge` — spec should be updated to match), stack-based execution engine, state overlay with commit/rollback, gas + PQ-gas metering, canonical JSON ABI with SHA-256 selectors, SQSP binary signing payload, binary receipts with events. 26 tests pass.
- **Receipt format matches the integration contract**: `state_root_before`/`_after`, `execution_trace_hash`, `aegis_verification_summary` are all real fields in `SynQ/aivm/src/receipt.rs`, not stubs.
- **AST → AIVM codegen**: `compiler/src/aivm_codegen.rs` lowers state vars, locals, arithmetic, comparisons, control flow, logical ops, `caller`, reverts, events into AIVM instructions with jump patching and canonical method selectors.
- **Server endpoint live**: `POST /compile-aivm` at `hanksweb.co.uk/synq/compile-aivm` returns bytecode (hex), ABI, manifest, function table, state var map, all hashes. 3 integration tests pass, 285+ workspace tests pass overall.
- **IDE side-by-side panel**: Forge/demo IDE has an AIVM tab next to QVM for comparison.

Bottom line: the SynQ-side compiler → bytecode → local-execution pipeline is spec-compliant and done. It's not blocked on anything in my toolchain.

## What's blocking it going further (chain side — not something I can fix from SynQ)

Checked the actual chain source (`src/`, top-level of this repo, same branch):

1. **Chain ID mismatch.** `src/synq_admission.rs` (1691 lines) and `src/synq_execution.rs` (698 lines) already exist and are wired into the node (`pub mod synq_admission;` / `pub mod synq_execution;` in `lib.rs`), with passing tests. But they still target `SYNERGY_TESTNET_V2_CHAIN_ID` / chain **1264** (`testnet_1264_for_contract`, policy id `synq-testnet-1264-v1`) — the legacy Testnet-Beta binding. Everything I've built since the V3 pivot (EIP-712 domain `SYNQ-CALL-v3`, wallet auth, Forge) targets chain **1266**. These need to be re-pointed to 1266 / `synergy-testnet-v3` before AIVM contracts can go through real chain admission.
2. **`synergy-aivm` submodule isn't checked out.** It's pinned in `.gitmodules` (commit `d2d8e67`) and referenced by the integration contract as the real chain-embedded runtime (`synergy-aivm/runtime/aivm-core`), but the local working tree has an empty directory for it — can't confirm it currently builds against the node without pulling it in.
3. **No live RPC surface for the real AIVM.** The only AIVM RPC methods in `rpc_server.rs` (`synergy_deployAIVMContract`, `synergy_executeAIVMContract`, etc.) are the disabled ones pointing at the dead AI-compute `AIVMRuntime` (#2 in the naming section above) — not at `synergy-aivm` or SQB artifacts at all. New handlers need to be written against the real runtime; nothing currently exists to deploy/call a SynQ AIVM contract over RPC.

## Suggested next step for chain side

- Re-bind `aegis-pqsynq` / `synq_admission.rs` / `synq_execution.rs` from chain 1264 → 1266 to match the rest of the V3 stack.
- Pull in real `synergy-aivm` submodule content and confirm `aivm-core` builds against the node.
- Write `synergy_deployAIVMContract` / `synergy_executeAIVMContract` (or equivalent) against the real runtime, accepting the SQB/AIVM artifact format the `/compile-aivm` endpoint already emits.

Happy to hand over the exact SQB/AIVM artifact schema and a sample compiled contract to make wiring the RPC handlers faster once you're ready to pick this up.
