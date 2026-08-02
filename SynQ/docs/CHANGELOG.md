# SynQ Changelog

All notable changes to the SynQ toolchain are documented here.
Dates are in UTC.

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
