# Changelog
---

All notable changes to the SynQ smart contract toolchain will be documented in this file. This project follows semantic versioning and adheres to strict standards for the Synergy Network quantum-safe Layer 1 blockchain.

## [0.5.0] - 2026-07-19 — Explicit Authority & Source Attestation
---

### Compiler
- **Grammar expansion (`synq.pest`):** Added `as_caller_clause` and `requires_clause` to function definitions. Contract functions may now explicitly declare `as caller` (enabling identity binding) and `requires cap::NAME` (establishing a capability guard). Both clauses are optional and fully composable.
- **AST modifications (`ast.rs`):** Extended the `FunctionDef` struct with `as_caller: bool` and `requires: Vec<String>` fields to capture the new declarative authority qualifiers.
- **Parser alignment (`parser.rs`):** Added specific parse arms for both `as caller` and `requires cap::NAME` statements, maintaining proper precedence-climbing alignment.
- **Codegen pipeline (`codegen.rs`):** For functions marked `as_caller: true`, the compiler now automatically emits an authentication prologue containing `LoadCaller` (0x50), `LoadImm256(UMA_ANON)`, `Eq`, and `JumpIf(revert)` instructions. This rejects invocations where the VM caller is the UMA anonymous sentinel address. The standard `caller` builtin is gated; referencing it in any non-`as caller` function raises a compile-time error.
- **ExternCall implementation (0x60):** Compiles `extern_call("Contract", "fn", args...)` statements directly to opcode 0x60, encoding a 4-byte LE length-prefixed contract name, a 4-byte LE length-prefixed function name, and a 1-byte argument count.
- **Extern targets extraction:** Added static AST analysis to the compiler library and WASM crate to extract a deduplicated `Vec<String>` of direct `ExternCall` targets.
- **CompileResult structure:** Updated the compile response structure to include the computed `extern_contracts` metadata list.
- **Compiler-level rejections:** Introduced strict duplicate name rejection. The compiler now rejects duplicate contract names, duplicate function names, duplicate variable declarations, and duplicate parameter names at compile time.
- **Static call-depth limit:** Implemented a static 64-hop Depth First Search (DFS) call-depth check at compile time, supplemented by a runtime guard on the `Call` opcode.
- **Syntax alias:** The keyword `fn` is now formally accepted as a syntactic alias for `function`.

### VM
- **Opcode 0x60 `ExternCall` execution:** Reads length-prefixed contract and function names along with argument count from bytecode. Pops the specified arguments in reverse-call order, passes them to the environment's `extern_call_handler` closure, and pushes the returned value (or `I32(0)` if void).
- **Cross-contract routing:** Introduced the `extern_call_handler: Option<Arc<dyn Fn(...)>>` field on `QuantumVM`. The handler locks the workspace map, resolves the target session ID, releases the workspace lock, locks the targets sessions map, and executes the target function under the current caller context. This release-before-lock sequence guarantees deadlock prevention.
- **Stack isolation:** The `call_function` method now explicitly clears the VM stack on entry to prevent state leakage across contract boundaries.
- **`LoadCaller` opcode (0x50):** Pushes the authenticated EVM caller address as a `U256` value, pushing the hashed `UMA_ANON` sentinel if the call context is unauthenticated.
- **Transactional atomicity:** Implemented memory snapshotting prior to external calls, restoring the state in the event of a `Revert`.
- **Step limits:** Added strict execution tracking, triggering an explicit `StepLimitExceeded` error on step exhaustion.

### Server
- **Workspace lifecycle endpoints (`synq-server/src/main.rs`):**
  - `POST /workspace/new` -> Returns `{workspace_id}`. Enforces a 50-workspace capacity limit with LRU eviction.
  - `GET /workspace/:id` -> Returns `{contracts: [{name, session_id, deploy_index}]}`, where `deploy_index` represents join sequence.
  - `DELETE /workspace/:id` -> Atomically removes the workspace and terminates all registered sessions.
  - `POST /workspace/:id/join` -> Binds an existing session to a workspace, stamping it with a `contract_name` and `deploy_index`.
  - `POST /workspace/:id/remove` -> Atomically detaches a contract from a workspace and updates deployment order.
- **Session initialization:** `POST /session/new` now accepts optional `workspace_id` and `contract_name` parameters to perform auto-registration into workspace structures on creation.
- **WASM compiler tamper detection:** `POST /compile` now accepts an optional `wasm_extern_contracts` parameter. The server independently traverses the AST, derives its own extern contracts list, sorts both lists, and rejects the request with a `"Tamper detected"` error if they diverge, preventing browser-side memory modification.
- **Source noncing:** Added `POST /source-nonce` endpoint returning `{nonce, expires_in}`. Generates a stateless KMAC128(key, source_hash_hex || 10s-bucket) nonce (per NIST SP 800-185) valid for 120 seconds. Nonces are bound to the specific source hash to prevent tampering.
- **Attestation signatures:** Added `POST /compile/sign-source` for EIP-712 source attestation. Verifies the KMAC128 nonce, parses and compiles the source code, validates the EIP-712 `SourceCommit` signature, performs `ecrecover`, and outputs an ML-DSA-65 signed `SynQSourceCommitV1` PQC payload.
- **Signature recovery robustness:** Integrated high-s secp256k1 normalization in `ecrecover` to support Coinbase Wallet and other non-standard wallet clients.
- **Data structures:**
  - `Session` extended with `workspace_id`, `contract_name`, and a `used_nonces` tracking set for replay protection.
  - `Workspace` structured to maintain a `contracts` map (`HashMap<String, String>`), a sorted `deploy_order` list (`Vec<String>`), and a `last_used` timestamp.

### PQC Integration Fixes
- **Error propagation (`pqc_integration.rs`):** Replaced unwrap-on-error patterns in keygen match arms (`map_err(|e| return Err(...)).unwrap()`) with proper `?` propagation (`map_err(|e| format!(...))?`), resolving compiler type-inference ambiguities.
- **Signature verification:** Corrected double-wrapped results in `verify_signature` by replacing `Ok(result)` with direct `result` propagation.
- **Key generator binary (`synq-keygen`):** Added `.expect(...)` handling to `dilithium::keygen()` to gracefully process return values.

## [0.4.0] - 2026-07-17 — Multi-Contract Workspace & ExternCall
---
- **Cross-Contract design:** Initialized the opcode 0x60 `ExternCall` specification, enabling secure communication between isolated contract modules.
- **Workspace management:** Introduced server-side endpoints for grouping and referencing multiple compiled contracts within a shared environment.
- **WASM compiler adaptation:** Rebuilt the WASM compilation toolchain to support `ExternCall` codegen using pure-Rust implementations while excluding C-backed pqcrypto dependencies.
- **Standard templates:** Authored `TokenVault` and `SimpleToken` reference contracts to demonstrate secure cross-contract messaging.
- **EIP-712 separator:** Defined the domain separator format: `verifyingContract = keccak256("SynQ:" + name)[12..]`.
- **Attestation blueprint:** Completed initial specification draft for cryptographic source code attestation.

## [0.3.0] - 2026-07-15 — VM Arithmetic & UInt256
---
- **Precision integers:** Switched to the `ruint` crate to handle native `UInt256` calculations; added the `LoadImm256` (0x44) opcode.
- **Type promotions:** Implemented automatic runtime promotion from `I32` to `U128` during mixed-type arithmetic operations.
- **Remainder calculation:** Added the `Rem` (0x14) modulo operator to the instruction set.
- **Error reporting:** Standardized arithmetic overflow/underflow messages to the structured format: `[Op] overflow/underflow: {a} [op] {b}`.
- **JSON serialization:** Configured large integers (128-bit and above) to serialize as quoted strings to preserve precision in JavaScript runtimes.

## [0.2.0] - 2026-07-12 — Server + EIP-712 Session Auth
---
- **Network layer:** Constructed the Axum server framework to manage session lifetimes and enforce API rate limits.
- **Invocation security:** Implemented EIP-712 `ContractCall` signing verification within the `POST /session/run` dispatch pipeline.
- **PQC metadata:** Attached post-quantum signature sidecars to successful compilation responses.
- **Compiler signing:** Configured persistent compiler identity using ML-DSA-65 signing keys.

## [0.1.0] - 2026-07-08 — Language Core
---
- **Syntax definition:** Implemented the initial grammar file using the `pest` library, establishing a robust precedence-climbing parser.
- **Assertion routing:** Backpatched `require()` check branching; defined core control flow opcodes: `Call`, `Return`, and `Revert`.
- **Instruction set:** Formulated the primary opcode table mapping numeric instructions to VM operations.
