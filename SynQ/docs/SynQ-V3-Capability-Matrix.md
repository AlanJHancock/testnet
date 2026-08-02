# SynQ V3 — Capability Matrix

**Date:** 2 August 2026  
**Test suite:** 203 passed, 0 failed, 1 ignored

---

## Status Legend

| Status | Meaning |
|--------|---------|
| ✅ Production | Implemented, tested, live on server |
| ⚠️ Partial | Implemented with known limitations |
| 🔧 Planned | Not yet implemented, architecturally supported |
| ❌ Missing | Not implemented, no architectural support yet |

---

## Compiler

| Feature | Status | Notes |
|---------|--------|-------|
| pest grammar parser | ✅ Production | Contracts, state, functions, expressions, attributes, enums, structs |
| Precedence-climbing expression parser | ✅ Production | Arithmetic, comparison, logical operators |
| Semantic analysis | ✅ Production | Type checking, attribute validation, PQC builtin resolution |
| SSA IR builder | ✅ Production | AST → SSA with basic blocks, CFG, predecessors, terminators |
| IR optimization passes | ✅ Production | Phi insertion (Cytron IDF), DCE, constant folding, copy propagation |
| IR → bytecode lowering | ✅ Production | Slot-based SSA deconstruction, phi handling, block linearization |
| Direct codegen (fallback) | ✅ Production | AST → bytecode, used when IR fails |
| Deterministic bytecode | ✅ Production | Sorted dispatch tables, sorted state vars |
| Multi-function dispatch | ✅ Production | Function name → entry address + parameter addresses |
| ExternCall compilation | ✅ Production | Cross-contract calls within workspace |
| WASM compiler build | ✅ Production | Browser-side compilation via synq-compiler-wasm |
| Module system | ❌ Missing | No module/use/import — single-file contracts only |
| Pattern matching | ❌ Missing | No match expressions |
| Generic types | ❌ Missing | No parameterized types (UInt&lt;N&gt;, etc.) |

## VM / Runtime

| Feature | Status | Notes |
|---------|--------|-------|
| Stack-based execution | ✅ Production | I32, U128, U256, Bool, Bytes, Tuple value types |
| U256 full-width arithmetic | ✅ Production | ruint crate, no truncation |
| Arithmetic opcodes (0x10–0x14) | ✅ Production | Add, Sub, Mul, Div, Mod |
| Comparison opcodes (0x20–0x25) | ✅ Production | Lt, Gt, Le, Ge, Eq, Ne |
| Control flow (0x30–0x36) | ✅ Production | Jump, JumpIf, Call, Return, Revert, RevertCode, RevertCodeDyn |
| Memory (0x40–0x44) | ✅ Production | Load, Store, LoadImm, LoadImm128, LoadImm256 |
| Transactional atomicity | ✅ Production | Snapshot/restore on revert |
| Step limit (100,000) | ✅ Production | Configurable |
| Memory cap (1024 slots) | ✅ Production | Hard limit |
| CallFrame stack (1024) | ✅ Production | Hard limit |
| Named errors (RevertCode) | ✅ Production | Enum variant index + message |
| Dynamic revert (RevertCodeDyn) | ✅ Production | Runtime argument evaluation |
| ToString (0x9F) | ✅ Production | Runtime expression to string for error messages |
| TuplePack / TupleGet / TupleSet | ✅ Production | Structs, enum payloads |
| ExternCall (0x60) | ✅ Production | Cross-contract calls |
| Print (0xF0) | ✅ Production | Debug output |
| Halt (0xFF) | ✅ Production | Stop execution |
| Event system (emit) | ❌ Missing | No typed events — Print is only output |
| AIVM layer | ❌ Missing | No AI execution, model validation, or inference receipts |

## PQC / Cryptography

| Feature | Status | Notes |
|---------|--------|-------|
| AEG1 wire protocol | ✅ Production | Bounded framing: 1MiB payload, 8 args, 128KiB/arg |
| AegisCall (0x8F) | ✅ Production | Unified PQC dispatch |
| ML-DSA-65 verify | ✅ Production | pqcrypto-dilithium, algorithm ID 0x11 |
| ML-DSA-87 verify | ✅ Production | pqcrypto-dilithium, algorithm ID 0x12 |
| FN-DSA-512 verify | ✅ Production | pqcrypto-falcon, algorithm ID 0x20 |
| ML-KEM-768 decapsulate | ✅ Production | pqcrypto-kyber, algorithm ID 0x02 |
| Deterministic dispatch (ACTS-15) | ✅ Production | Rejects secret-key ops, allows public-key only |
| ML-DSA-87 compiler attestation | ✅ Production | Persistent or ephemeral keypair |
| Signature sidecar | ✅ Production | Algorithm, mode, public key, signature |
| Public key endpoint | ✅ Production | GET /pubkey |
| Legacy PQC opcodes (0x80–0x83) | ✅ Production | Backward-compatible aliases |
| SPHINCS+ | ✅ Production | Legacy direct-call, not in AEG1 |
| McEliece | ✅ Production | Legacy direct-call, not in AEG1 |
| HQC-128 | ✅ Production | Legacy, catch_unwind on FFI panic |
| FN-DSA-1024 | 🔧 Planned | Algorithm ID 0x21, not yet in AEG1 dispatch |
| ML-KEM-512 / 1024 | 🔧 Planned | Algorithm IDs 0x01, 0x03 |

## Authority & Governance

| Feature | Status | Notes |
|---------|--------|-------|
| AuthorityEnvelope (104B) | ✅ Production | identity + scope_hash + nonce + expiry + caps + reserved |
| AuthRequire (0x52) | ✅ Production | Verifies envelope scope |
| LoadCaller (0x50) | ✅ Production | Pushes caller address |
| LoadAuthority (0x51) | ✅ Production | Pushes current envelope |
| AuthIdentity (0x53) | ✅ Production | Extracts identity from envelope |
| @public attribute | ✅ Production | No authority required |
| @authority(Scope) attribute | ✅ Production | Compile-time + runtime enforcement |
| @governance(Scope) attribute | ✅ Production | Compile-time + runtime enforcement |
| @effects attribute | ✅ Production | Compile-time documentation |
| @requires / @ensures | ✅ Production | Compile-time documentation (not enforced) |
| @fails(ErrorType) attribute | ✅ Production | Compile-time + runtime |
| @bounded(n) attribute | ✅ Production | Compile-time documentation |
| @manifest attribute | ✅ Production | Include in V3 manifest ABI |
| Devnet wildcard | ⚠️ Partial | All-zeros scope = accept any — must be disabled in production |
| Formal verification | ❌ Missing | No proof certificates, spec blocks, or vacuity analysis |
| UMA identity (non-key) | ❌ Missing | Identity field exists but not UMA-resolved |

## Addressing

| Feature | Status | Notes |
|---------|--------|-------|
| syna HRP (accounts) | ✅ Production | Bech32 encoding/decoding |
| sync HRP (contracts) | ✅ Production | Deployment-derived addresses |
| synw HRP (wallets) | ✅ Production | Native wallet support |
| tsynq HRP | ✅ Production | RETIRED — fails closed |
| AddrEncode (0x54) | ✅ Production | Value → syna string |
| AddrDecode (0x55) | ✅ Production | syna/sync/synw → U256 |
| ContractAddr (0x56) | ✅ Production | Deployer + nonce + artifact_hash → sync string |
| to_syna / from_syna builtins | ✅ Production | |
| contract_address builtin | ✅ Production | |
| from_any_syn() | ✅ Production | Decodes syna/synw/sync, rejects tsynq |

## Assets

| Feature | Status | Notes |
|---------|--------|-------|
| AssetCreate (0x57) | ✅ Production | Type tag + value → asset ID |
| AssetTransfer (0x58) | ✅ Production | Old deactivated, new created |
| AssetBurn (0x59) | ✅ Production | Deactivated, value returned |
| AssetBalance (0x5A) | ✅ Production | 0 if inactive |
| AssetOwner (0x5B) | ✅ Production | 0 if inactive |
| Linearity invariant | ✅ Production | Each ID consumed exactly once |
| Linear type enforcement | ⚠️ Partial | Runtime enforced, not compile-time |

## Verification

| Feature | Status | Notes |
|---------|--------|-------|
| Layer 1 (structural) | ✅ Production | Magic, opcodes, jump targets, bounds |
| Layer 2 (stack safety) | ✅ Production | Symbolic stack depth analysis |
| Layer 3 (manifest sig) | ❌ Missing | ML-DSA-87 manifest verification — planned |

## SQB Artifact

| Feature | Status | Notes |
|---------|--------|-------|
| SQB1 format | ✅ Production | 16B header + TLV sections + artifact root |
| Hash binding | ✅ Production | SHA3-256 section hashes → root |
| ML-DSA-87 artifact signature | ✅ Production | Over artifact root |
| CODE section | ✅ Production | QVM bytecode |
| ABI section | ✅ Production | Function signatures, parameter types |
| MANIFEST section | ✅ Production | State layout, governance/authority scopes |
| IR section | ✅ Production | SSA IR dump (optional) |
| EFFECTS section | ✅ Production | Declared effects per function |
| STATE_LAYOUT section | ✅ Production | State variable addresses and types |
| META section | ✅ Production | Compiler version, timestamp, contract name |
| ACTS-VM-001 through 011 | ✅ Production | All 11 requirements addressed |

## Server / API

| Feature | Status | Notes |
|---------|--------|-------|
| POST /compile | ✅ Production | IR backend primary, direct codegen fallback |
| POST /compile-wasm | ✅ Production | WASM compiler for browser |
| POST /attest | ✅ Production | EIP-191 verification + PQC attestation |
| POST /session/new | ✅ Production | Load bytecode into persistent session |
| POST /session/run | ✅ Production | Execute function on session |
| GET /session/:id/nonce | ✅ Production | Get nonce for EIP-712 signing |
| GET /session/:id/state | ✅ Production | Inspect session memory state |
| DELETE /session/:id | ✅ Production | Destroy session |
| POST /workspace/new | ✅ Production | Create multi-contract workspace |
| GET /workspace/:id | ✅ Production | Workspace info |
| POST /workspace/:id/join | ✅ Production | Add contract to workspace |
| POST /workspace/:id/remove | ✅ Production | Remove contract from workspace |
| DELETE /workspace/:id | ✅ Production | Delete workspace |
| POST /source-nonce | ✅ Production | Get nonce for source commit signing |
| POST /compile/sign-source | ✅ Production | Compile + sign source commit |
| GET /pubkey | ✅ Production | Compiler public key |
| GET /health | ✅ Production | Service health check |
| GET /health/ready | ✅ Production | Readiness check (503 near cap) |
| GET /pqc/test-vector | ✅ Production | PQC test vector generation |
| POST /debug/ecrecover | ✅ Production | EVM signature recovery |
| POST /bench-compile | ✅ Production | Benchmark compilation |

## IDE / Demo

| Feature | Status | Notes |
|---------|--------|-------|
| Compile → Test → Deploy flow | ✅ Production | Full pipeline in browser |
| IR dump display | ✅ Production | Full SSA instruction listing |
| Bytecode disassembly | ✅ Production | Opcode-by-opcode view |
| Verify badge (L1 + L2) | ✅ Production | Green/yellow/red status |
| SQB download | ✅ Production | Named .sqb files |
| Wallet integration | ✅ Production | Three-tier (extension, device-link, ephemeral) |
| EIP-6963 discovery | ✅ Production | Multi-provider wallet detection |
| MetaMask chain switch | ✅ Production | Chain 1266 via RPC stub |
| Contract templates | ✅ Production | 10 templates |
| QVM status indicator | ✅ Production | QVM — SynQ Virtual Machine active |

---

End of Capability Matrix
