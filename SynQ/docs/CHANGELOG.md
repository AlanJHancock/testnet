# SynQ Changelog

All notable changes to the SynQ toolchain are documented here.
Dates are in UTC.

---

## 2026-08-31

### Five PQC Builtins Fixed — kyber_encapsulate/mceliece/hqc No Longer Silently Return `false`

- **Found while auditing the 2026-08-31 AEG1 typed-dispatch fix:** a
  code comment next to it flagged a pre-existing "KNOWN GAP" --
  `kyber_encapsulate`, `mceliece_encapsulate`, `mceliece_decapsulate`,
  `hqc_encapsulate`, and `hqc_decapsulate` all fell through to the
  generic frame-based `AegisCall` opcode with raw un-framed args, which
  reliably failed to parse as an AEG1 frame and silently returned
  `Bool(false)` / garbage bytes -- indistinguishable from a real
  successful (if empty) result.
- **Root cause is structural, not a bug to patch the same way:** AEG1
  (ACTS-15) defines exactly 3 operations -- `MlKemDecaps`, `MlDsaVerify`,
  `FnDsaVerify` -- there is no KEM-encapsulate operation and no
  McEliece/HQC algorithm in the protocol's `Algorithm` enum at all.
  Extending the wire protocol with new operation IDs is a spec decision
  above this fix's authority, so instead of inventing new AEG1 ops, these
  five builtins now hard-revert with an honest, named error.
- **Fix:** new `IrOp::PqcUnsupported(name, args)` / `OpCode::PqcUnsupported`
  (0x85). Immediate encoding `[name_len: u32][name][argc: u8]`. Always
  returns `Err(VMError::RuntimeError(...))` naming the exact builtin and
  citing the AEG1/ACTS-15 limitation -- identical behavior on native and
  wasm builds, since no crypto backend is touched either way. Mirrors the
  existing hard-reject already used for `kyber_decaps` (ACTS-15 §3), just
  for a different reason (no operation slot vs. no secret-key ops on-chain).
- **Test suite:** 5 new tests added to
  `compiler/tests/aegis_ir_pipeline_test.rs`, each compiling a real
  contract through `compile_ir()` and calling it through `QuantumVM`,
  asserting the call `Err`s and the message names the exact builtin. Full
  workspace suite: **358 tests, 0 failures** (28 binaries, 1 pre-existing
  ignored) -- no regressions elsewhere.
- **Live verification:** rebuilt `synq-server` in release mode, restarted
  the live service on hanksweb.co.uk, and ran a real
  `/compile` → `/session/new` → `/session/run` round trip calling
  `kyber_encapsulate` -- got back a clean runtime error naming the builtin
  and AEG1, not a silent false/empty result.
- **Commit:** `72cfcb4` on `phase3-contract-addr-snts01-proto` (12 files
  changed, 215 insertions, 12 deletions).

---

### Caller Display Regression Fixed — `tsynq` HRP Was Showing Instead of `synw`

- **Report:** a live `init()` call in Forge's Debug Console showed
  `success ... LIVE as tsynq1qyz0yq...` — the deprecated `tsynq` HRP —
  when the wallet-standard `synw` HRP was expected.
- **Root cause:** `session_run_handler` and `session_grant_handler` in
  `synq-server/src/main.rs` fell back to the deprecated
  `synq_vm::bech32::encode_address()` (produces `tsynq1...`) whenever a
  call had no explicit `display_tsynq` override from the wallet
  extension — i.e. any call made without a connected wallet supplying
  its own `synw` address. Per the 2026-08-22 decision already recorded
  in `vm/src/bech32.rs` (`tsynq`/`synq` deprecated for human-facing
  display; `synw` is the Forge/wallet-UI standard), this fallback
  should have used `encode_wallet_address()` (`synw1...`) all along.
- **Fix:** switched all 6 real call sites (1 grant creation + 5
  run-response paths) from `encode_address()` to
  `encode_wallet_address()`. Left the one remaining `encode_address()`
  call site (a `vm.rs` unit test) unchanged — it intentionally tests
  the legacy-encode backward-compat path.
- **Verified live:** `POST /session/new` + `/session/run(init)` with no
  `display_tsynq` override now returns
  `caller_tsynq=synw1yx5ney972vcu9tlq89fg5k6rj6zvsda66eu4` (was
  `tsynq1...` before). Full workspace test suite green (84+12 tests)
  before deploy. Deployed via `cargo build --release -p synq-server` +
  `systemctl restart synq-server.service`. Committed (`dbf9a53`).

### synergy-aivm Integration Audit — quantumvm API Drift Found + Fix PR Opened

- **Context:** reviewed the internal `synergy-aivm` repo (private,
  `synergy-network-hq/synergy-aivm`, commit `d2d8e67`) as a candidate
  blueprint for integrating PQC metering/runtime patterns into the main
  Forge chain. Its `runtime/aivm-core` crate is a real, working
  deploy/call harness — canonical `SynQRuntimeReceipt`s with pre/post
  state roots, a two-lane `AivmGasMeter` (ordinary + PQC gas), and STS-9/
  STS-MA/STS-NF token selectors — that wraps our VM via an optional
  `quantumvm` path-dependency. (The rest of that repo — model registry,
  GPU-worker marketplace, federated training — is unrelated stale
  scaffolding from Sep 2025 and not relevant here.)
- **Finding:** `aivm-core`'s usage of `quantumvm` was written against an
  API shape our real `synq-vm` crate never had. Confirmed line-by-line
  against `vm/src/vm.rs` and `vm/src/opcode.rs`:
  - Its `Cargo.toml` dependency key `quantumvm` had no `package =` alias,
    but our crate's own `[package] name` is `synq-vm` — the dependency
    line does not resolve as written.
  - `QuantumVM::with_gas(gas, pq_gas)` does not exist; only `new()` does.
    The real VM exposes two public limit fields instead: `max_steps`
    (execution budget, a step count) and `max_fuel` (PQC-operation
    budget, ACTS-VM-005).
  - `consumed_gas()`/`consumed_pqc_gas()` do not exist; the real
    accessors are `steps_used()` and `fuel_used()`.
  - `VMError::OutOfGas` does not exist. The real, structured variants are
    `FuelExhausted{cost,remaining}` (PQC fuel exhausted) and
    `StepLimitExceeded(usize)` (step budget exhausted) — no
    string-sniffing needed, both already carry typed data.
  - `load_bytecode()`, `execute()`, the `stack` field, and
    `Assembler`/`OpCode` usage were already correct and needed no
    changes.
- **Action:** opened
  [`synergy-aivm#2`](https://github.com/synergy-network-hq/synergy-aivm/pull/2)
  (branch `fix/aivm-core-quantumvm-compat`) against `main` with the 4
  fixes above. Source-verified against our real crate, not build-tested
  end-to-end (no local checkout of aivm-core's full dependency tree) —
  PR description asks Justin to run `cargo check -p aivm-core --features
  synq` before merging. No changes made to `synq-vm` itself; this was
  purely an aivm-core-side fix, so there is no backward-compat impact on
  compile-deployed or SQB-deployed sessions.
- **Still open:** confirm with Justin (once Developer Hub access works)
  whether `aivm-core`'s two-lane gas model (ordinary steps + separate PQC
  fuel) is the intended shape for the "GasMeter/PqGasMeter integration"
  item on the gas/fee estimator backlog, since it maps cleanly onto
  fields our VM already exposes.

### AEG1 Typed Dispatch Fix — dilithium_verify/falcon_verify/kyber_decaps Always Returned false

- **Root cause:** the IR lowering for the convenience builtins `dilithium_verify`,
  `falcon_verify`, and `kyber_decaps` pushed their raw args and emitted the
  frame-based `AegisCall` (0x8F) opcode directly. That opcode pops exactly ONE
  value and parses it as a wire-encoded AEG1 frame — it only ever received the
  last pushed arg (e.g. `publicKey`), which is not a valid frame. Every
  deterministic (non-AIVM-dry-run) call to these builtins therefore always
  failed with an "invalid magic"/"truncated" dispatch error and always
  returned `Bool(false)`, regardless of whether the signature/ciphertext was
  actually valid. Confirmed hitting real production traffic (PQCDemo,
  `verifyMlDsa`) in the `synq-server` logs before the fix.
- **Fix:** new VM opcode `AegisTypedCall` (0x84) — immediate `(op, alg)` bytes
  select the AEG1 operation + algorithm, pops a fixed arg count directly off
  the stack, and builds the `Aeg1Request` in-process (no wire-frame
  encode/decode round trip). Charges real ACTS-15 §4 gas via
  `aeg1::compute_cost()` before dispatch. `IrOp::AegisVerify`/`AegisDecaps` now
  carry `(op, alg, args)` instead of discarding which algorithm was called.
  `dilithium_verify` → op=2/alg=0x11 (ML-DSA-65); `falcon_verify` →
  op=3/alg=0x20 (FN-DSA-512); `kyber_decapsulate`/`kyber_decaps` → op=1/alg=0x02
  (ML-KEM-768, hard-rejected per ACTS-15 §3 — no secret-key op may run
  on-chain).
- **Second bug found in the same pass:** `sphincs_verify` has no AEG1
  operation slot at all (AEG1 only covers ML-KEM/ML-DSA/FN-DSA), so it was
  routed to the legacy `SphincsVerify` opcode via new `IrOp::LegacySphincsVerify`.
  That legacy opcode (shared pop-order convention with legacy
  `DilithiumVerify`/`FalconVerify`) pops args as `[public_key, message,
  signature]`, not source call order — the first draft pushed source order and
  silently swapped `message`↔`signature`, so a genuinely valid SPHINCS+
  signature was rejected while a forged one still (coincidentally) returned
  `false`. Caught by writing real positive+negative signature tests rather
  than trusting one green run.
- **SIR1 binary IR encoding:** tags 0x22/0x23 (old args-only `AegisVerify`/
  `AegisDecaps` shape, no algorithm selector) are retired — `decode()` now
  returns `InvalidTag` instead of misreading bytes meant for the new shape.
  New tags 0x3C/0x3D/0x3E carry the new `(op, alg, args)`/`(op, alg, args)`/
  `(args)` shapes. No real backward-compat path existed for the old shape
  anyway — it never recorded which algorithm was intended.
- **Test suite:** new `compiler/tests/aegis_ir_pipeline_test.rs` (7 tests)
  exercises the real `compile_ir()` → `QuantumVM` pipeline (not hand-assembled
  bytecode) — `dilithium_verify`/`falcon_verify`/`sphincs_verify`
  positive+negative signature cases, plus confirms `kyber_decaps` is hard
  `Err` in the deterministic path. Full workspace suite: **354 tests, 0
  failures** (28 test binaries across vm/compiler/pqc-shims/synq-server/cli) —
  no regressions elsewhere.
- **Live verification:** rebuilt `synq-server` in release mode, restarted the
  `synq-server.service` live on hanksweb.co.uk, and ran a real end-to-end HTTP
  round trip (`/compile` → `/session/new` → `/session/run`) against a fresh
  ML-DSA-65 test vector from `/pqc/test-vector` — a genuinely valid signature
  returned `Bool(true)`, a tampered one correctly returned `Bool(false)`. Log
  confirms the new opcode path (`84 02 11 ...`) and a real `[AEG1] verify
  rejected: InvalidSignature` only on the tampered case.
- **Commit:** `f8df9f9` on `phase3-contract-addr-snts01-proto` (11 files
  changed, 430 insertions, 35 deletions).

---

## 2026-08-02

### V3 Audit Readiness Package
- **Consolidated architecture document:** `docs/SynQ-V3-Architecture.md` — full system overview, component diagram, data flow, crypto profiles, verification layers, V3 testnet parameters. Designed for third-party audit review.
- **Security model document:** `docs/SynQ-V3-Security-Model.md` — trust chain from source to execution, cryptographic profiles, AEG1 wire protocol security, authority model, SQB artifact integrity, known security limitations.
- **Capability matrix:** `docs/SynQ-V3-Capability-Matrix.md` — per-feature implementation status (production / partial / planned / missing) covering compiler, VM, PQC, authority, addressing, assets, verification, SQB, server, IDE.
- **API reference:** `docs/SynQ-V3-API-Reference.md` — all 20 server endpoints with request/response schemas, auth model, error codes.
- **Test coverage report:** `docs/SynQ-V3-Test-Coverage.md` — 203 tests mapped to capabilities by crate.
- **Updated gap analysis:** `docs/synq-spec-gap-analysis.md` — replaces 28 July version. Reflects SSA IR, attributes, structs/enums, bytecode verification, SQB as implemented. Identifies 15 remaining gaps prioritized for future work.
- **Updated VM spec:** v0.2 → v0.3. Adds RevertCodeDyn (0x36), ToString (0x9F), bytecode verification section, SQB format section, SSA IR section, deterministic dispatch (ACTS-15).
- **Updated language spec:** v0.2 → v0.3. Adds dynamic named errors, algebraic enum payloads, IR backend as primary compilation path, compilation response fields, StackFailDemo template.
- **Audit readme:** `docs/audit-readme.md` — index of all audit documents with review instructions.

---

## 2026-08-01

### IR Backend as Primary Compilation Path
- **Primary path switch:** synq-server `/compile` endpoint now uses `compile_ir()` (SSA IR → optimization passes → lowering) instead of direct codegen.
- **Automatic fallback:** `compile()` (direct AST → bytecode) retained as fallback on IR failure.
- **Server simplification:** Removed ~40 lines of redundant IR build/analysis blocks — `compile_ir()` returns `ir_dump` + `warnings` directly.
- **Bug fix:** Asset builtins (`asset_create`/`transfer`/`burn`/`balance`/`owner`) were missing from `PQC_BUILTINS` allowlist — broke asset operations in both compilation paths. Fixed.
- **Bug fix:** IR builder `state_vars` HashMap iteration was non-deterministic — now sorted by address for reproducible bytecode.
- **IR gap analysis:** 22/22 contract patterns pass through `compile_ir()` (100%). New test `ir_gap_test.rs` validates all templates.
- **Test suite:** 203 passed, 0 failed, 1 ignored (7 new IR backend tests).
- **Commit:** e47ef46 on feature/real-codegen-and-dispatch.
- **Server live:** hanksweb.co.uk/synq/compile confirmed working with IR backend.

### Bytecode Verification — Layers 1 and 2
- **Layer 1 (Structural Integrity):** Mandatory hard gate. Validates magic bytes, opcode validity, jump/call target bounds, instruction completeness. Rejects malformed bytecode before execution.
- **Layer 2 (Stack Safety):** Advisory symbolic stack depth analysis. Tracks stack deltas along all code paths, flags underflows, reports maximum stack depth. Warnings surfaced but do not block.
- **IDE integration:** Dynamic VERIFY badge (green/yellow/red) showing Layer 1 and Layer 2 results, instruction count, binary size, jump/call counts.
- **StackFailDemo:** Educational contract demonstrating verification layers.

### AegisCall Deterministic Dispatch (ACTS-15)
- `dispatch_deterministic()` explicitly rejects secret-key operations (ML-KEM decapsulate).
- Permits only public-key operations (ML-DSA verify, FN-DSA verify).
- AEG1 wire protocol enforcement hardened: magic, argc, length bounds.
- `expr_to_string()` helper for runtime error messages (e.g., `VaultError::InsufficientBalance(balance)`).

### RevertCodeDyn (0x36)
- Dynamic named error revert with runtime argument evaluation.
- Runtime values serialized via ToString (0x9F) into error messages.

---

## 2026-07-31

### Weekly Report Migration
- Weekly status reports moved from public repo + Google Drive to private repo `synergy-network-hq/synq-internal` (NDA-safe).
- Friday 11pm Europe/London workflow reconfigured to commit markdown reports directly to private repo.
- `pfayette` added to private repo access (7 authorized members).

### SQB Download Naming
- IDE SQB download button now includes contract name (e.g., `StructValue.sqb`).

---

## 2026-07-30

### SSA IR Instruction Dump in IDE
- Full IR dump displayed in IDE: value IDs with types, CFG blocks with predecessors, all terminators.
- Contract name headers in both IR dump and bytecode disassembly.
- `ir_dump` field in `CompileResponse` from server.

### Linear Asset Tracking — Asset<T> + Opcodes 0x57-0x5B
- New type: `Asset<T>` — linear resource with create, transfer, burn semantics.
- New opcodes: AssetCreate (0x57), AssetTransfer (0x58), AssetBurn (0x59), AssetBalance (0x5A), AssetOwner (0x5B).
- Linearity invariant: Each asset ID consumed exactly once.
- VM asset registry: `AssetRecord` with owner, value, type_tag, active flag.

### Named Error Integration — RevertCode (0x35)
- New opcode: RevertCode (0x35) — structured named error revert.
- New VMError variant: `RevertedNamed { code, message }`.
- Grammar: `revert EnumName::VariantName(args);` syntax.
- Server response: `error_code` and `error_name` fields.

### TupleSet (0xAB) + Struct Field Assignment
- New opcode: TupleSet (0xAB) — struct field assignment.
- Grammar: `field_assign_statement` rule for `obj.field = value;`.

### Governance Authorization + ML-DSA-87 Manifest Signing
- @governance(Scope) attribute added to AST, parser, codegen.
- V3 manifest: ML-DSA-87 signed, includes ABI, state layout, governance/authority scopes.
- JumpIf fix: Authorized=true now correctly jumps to body.

### Struct/Enum Runtime Support
- Struct field access via local type inference.
- Enum variant access resolved to sequential integer tags.
- Runtime TupleGet/MakeTuple for struct value manipulation.

### Wallet Integration (Complete)
- Three-tier: Synergy extension (synw) > device-link JSON > ephemeral Bech32 (syna/sync).
- `_walletProvider()` + `_walletRequest()` for all wallet RPCs.
- EIP-6963 multi-provider discovery.
- MetaMask chain-switch to 1266 via RPC stub.
- V3 EIP-712: chainId 1266, domainTag SYNQ-CALL-v3.

### AEG1 Wire Protocol
- Bounded framing ABI: 1MiB payload, 8 args, 128KiB per arg.
- Operations: ML-KEM decapsulate (1), ML-DSA verify (2), FN-DSA verify (3).
- AegisCall (0x8F) unified opcode; legacy 0x80-0x83 retained.
- NIST/FIPS naming alignment: ML-KEM, ML-DSA, FN-DSA.

### Authority Model + Attributes + Type System
- AuthorityEnvelope (104B): identity + scope_hash + nonce + expiry + caps + reserved.
- Opcodes: LoadAuthority (0x51), AuthRequire (0x52), AuthIdentity (0x53).
- 10 attributes: @public, @authority, @governance, @effects, @requires, @ensures, @fails, @bounded, @manifest, @ai.
- Type aliases: Bytes<N>, Hash32, Hash64, UMAIdentity, ModelId, Height.
- Enums (C-style + algebraic), struct literals, field access.

### V3 Bech32 Addresses
- syna = accounts, sync = contracts, tsynq RETIRED.
- AddrEncode (0x54), AddrDecode (0x55), ContractAddr (0x56).
- `from_any_syn()` decodes syna/synw/sync, rejects tsynq.

---

## Earlier (2026-07-16 through 2026-07-28)

### Compiler & VM Foundations
- Stack-based QVM with I32, U128, U256, Bool, Bytes, Tuple value types.
- pest grammar, precedence-climbing parser, require() → backpatched JumpIf+Revert.
- State{} and impl{} blocks, U256 literals, fn alias.
- ExternCall (0x60) for cross-contract calls (workspace-scoped).
- Transactional atomicity (rollback on revert).
- Real PQC crypto (all 6 algorithms from pqcrypto crates — no stubs).
- Multi-function dispatch table with disjoint parameter addresses.
- EIP-712 session auth with ecrecover.
- Persistent compiler-attestation key (ML-DSA-65, later migrated to ML-DSA-87).
- PR-A through PR-G security hardening series.
- WASM compiler build for browser IDE.

---

## Test Count: 203 passed, 0 failed, 1 ignored
