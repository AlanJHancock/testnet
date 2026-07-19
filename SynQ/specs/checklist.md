# SynQ Project Checklist and Roadmap

---

## Phase 1: Language Foundations — COMPLETE

### Language Design
- [x] Defined primitive types: I32, U128, U256, Bool, Bytes
- [x] PQC types: Dilithium, Falcon, Kyber, SPHINCS+, McEliece, HQC
- [x] `pragma synq ^0.9` version declaration
- [x] `contract` blocks with typed state variables

### Language Syntax & Grammar
- [x] pest grammar with precedence-climbing expression parser
- [x] `require(cond, "message")` — compiles to backpatched JumpIf + Revert
- [x] `extern_call("Contract", "fn", args...)` — cross-contract call
- [x] `as caller` identity clause on function definitions
- [x] `requires cap::NAME` capability clause on function definitions
- [x] `caller` builtin → LoadCaller opcode; compile error if used outside `as caller` fn
- [x] `fn` accepted as alias for `function`
- [x] Explicit `return <expr>;` for functions with return values
- [x] Duplicate name rejection at compile time (contracts, functions, variables, params)
- [x] Static call-depth limit: 64 hops (DFS at compile time + runtime guard)

### Documentation
- [x] `SynQ-Language-Specification.md`
- [x] `SynQ-VM-Specification.md` (updated to v0.2)
- [x] `Gas-Model.md`
- [x] `SynQDAO_Example.md` reference implementation
- [x] `Authority-and-Attestation.md` — explicit authority model + source signing
- [x] `CHANGELOG.md`
- [x] `README.md`

---

## Phase 2: Runtime + Compiler + Server — COMPLETE

### QuantumVM (`vm/`)
- [x] Full opcode table: stack, arithmetic, comparison, control flow, memory
- [x] `LoadCaller` (0x50) — authenticated EVM caller as U256
- [x] `ExternCall` (0x60) — cross-contract call with workspace handler
- [x] UMA_ANON sentinel — domain-separated anonymous caller value
- [x] Authentication prologue emitted by compiler for `as caller` functions
- [x] Transactional atomicity: memory snapshot + restore on Revert
- [x] U256 via ruint crate; `LoadImm256` (0x44) for 32-byte constants
- [x] Step limit enforcement (`StepLimitExceeded`)
- [x] Memory cap: 1,024 slots per session
- [x] Call depth limit: 64 hops at runtime
- [x] PQC opcodes: 0x80 ML-DSA-65, 0x81 ML-KEM-768, 0x82 FN-DSA-512, 0x83 SLH-DSA-SHAKE-128s
- [x] Mixed-type arithmetic: I32 auto-promoted to U128

### Compiler (`compiler/`)
- [x] pest grammar (`synq.pest`)
- [x] AST with `as_caller`, `requires`, `ExternCall` statement nodes
- [x] Parser for all grammar productions including `as caller` and `requires cap::NAME`
- [x] Codegen: authentication prologue, ExternCall 4-byte LE encoding
- [x] `extern_contracts` extraction from AST (direct deps, deduplicated)
- [x] `CompileResult` includes `extern_contracts: Vec<String>`
- [x] WASM compiler crate: pure-Rust vendored source, C-backed pqcrypto excluded
- [x] WASM `compile_synq(source)` → JSON; deployed to `/var/www/synq-demo/wasm/`

### Server (`synq-server/`)
- [x] Axum HTTP server on port 3030; nginx reverse proxy at `/synq/`
- [x] Rate limiting: burst 10, 30 req/min per IP (tower-governor)
- [x] Session lifecycle: create, run, nonce fetch, delete, state query
- [x] EIP-712 ContractCall signing for `/session/run`
- [x] High-s secp256k1 normalisation (Coinbase Wallet compatibility)
- [x] ML-DSA-65 persistent compiler key (`/etc/synq/compiler.key`)
- [x] PQC sidecar on all compile responses
- [x] Workspace endpoints: new, get, join, remove, delete
- [x] Workspace auto-registration from `POST /session/new` (with `deploy_order`)
- [x] `POST /compile` tamper-detection: `wasm_extern_contracts` parity check
- [x] `POST /source-nonce` — KMAC128 stateless nonce (NIST SP 800-185)
- [x] `POST /compile/sign-source` — EIP-712 source attestation, `SynQSourceCommitV1` PQC payload
- [x] Replay protection: 120s KMAC128 window; nonce bound to source hash

### PQC Shims (`pqc-shims/`)
- [x] ML-DSA-65 (dilithium) — NIST FIPS 204
- [x] FN-DSA-512 (falcon) — NIST FIPS 206
- [x] SLH-DSA-SHAKE-128s (sphincs) — NIST FIPS 205
- [x] ML-KEM-768 (kyber) — NIST FIPS 203
- [x] Classic-McEliece-348864
- [x] HQC-128
- [x] keygen, sign, verify, encapsulate, decapsulate interfaces unified

### Test Harness
- [x] 38-test functional suite: auth guards, arithmetic, workspace, tamper-detection, duplicate names, source invariants
- [x] 14-test source-signing suite: EIP-712 digest construction, recovered == claimed, fabricated nonce, wrong claimed address, tampered source, wrong private key
- [x] Tests run against live server; all 52 tests pass on clean build

---

## Phase 3: Security Hardening — COMPLETE

- [x] Explicit authority model: `as caller` / `requires cap::NAME` enforced at VM level
- [x] UMA_ANON sentinel prevents zero-address collisions in authentication prologue
- [x] Source attestation chain: nonce → EIP-712 sign → server verify → PQC commit
- [x] WASM tamper-detection: independent AST extern_contracts parity check
- [x] Transactional rollback on auth failure or Revert
- [x] Workspace removal atomicity (session + deploy_order updated together)
- [x] Re-initialisation guard pattern documented and used in reference contracts

---

## Phase 4: Developer Tooling + Demo — IN PROGRESS

- [x] Browser IDE at `https://hanksweb.co.uk/demo/`
- [x] WASM compiler in-browser with ExternCall support
- [x] Workspace panel: multi-contract deploy, dependency hints (amber/teal), deploy_index ordering
- [x] TokenVault + SimpleToken reference templates
- [ ] Source-signing UI flow (EIP-712 wallet prompt before compile)
- [ ] `assertSync()` UI trigger for cross-contract invariant checking
- [ ] CLI deployment tool (`synq-cli`) — partial
- [ ] Testnet dashboard with session / workspace metrics

---

## Phase 5: Synergy Network Integration — PLANNED

- [ ] UMA invariants (U-1 through U-18) integrated into compiler validation
- [ ] SXCP cross-chain attestation: BFT quorum + PQC witness registry
- [ ] `delegatecall` (0x61) — requires capability registry production-hardening
- [ ] On-chain capability registry contract
- [ ] Hybrid signing: ECDSA wallet + ML-DSA-65 Dilithium wrapper
- [ ] PQC account model: DilithiumPublicKey, FalconPublicKey, PQAuth composite keys
- [ ] HSM migration for compiler key (`/etc/synq/compiler.key`)

---

## Phase 6: Testnet Launch — PLANNED

- [ ] Public testnet with PQC-based accounts and contract deployment
- [ ] Canonical `.synq` contract examples + expected bytecode fixtures
- [ ] Fuzz harness for VM opcode execution
- [ ] Synergy PQC Smart Contract Standard draft
- [ ] Whitepaper: PQ-safe on-chain execution model

---

> Quantum-safe by design. Not by patch.
