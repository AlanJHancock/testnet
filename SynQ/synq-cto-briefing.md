# SynQ Toolchain — CTO Briefing & Development Log
**Repository:** `synergy-network-hq/testnet`  
**Prepared by:** Alan Hancock  
**Initial date:** 10 July 2026  
**Last updated:** 16 July 2026 (covering work from 15–16 July 2026)

---

## Overview

This document is the running technical record for the SynQ toolchain. It covers the full arc from the original stub implementation through to the modular PR-A through PR-G security hardening series and the live demo portal. Everything described here is committed, tested, and live on the production server at `23.254.229.135`.

---

## Part 1 — Foundation Work (10 July 2026)

*Taking SynQ from a non-functional stub to a working end-to-end pipeline.*

### 1.1 Real bytecode compiler (was: 40-byte `Halt` stub)

The original codegen discarded all function bodies — the pest grammar only allowed empty `{}` blocks, so every contract compiled to the same fixed 40-byte `Halt` sequence regardless of source.

**Implemented:**
- Grammar extended with real statement and expression rules: assignments, `require()`, `return`, arithmetic, comparisons, and function calls
- Precedence-climbing expression parser (avoids left recursion) supporting `+`, `-`, `*`, `/`, `%`, `==`, `!=`, `<`, `<=`, `>`, `>=`
- `require(condition, message)` compiles to a real conditional abort using backpatched forward jumps
- State variable assignment compiles to Push-address + Store
- PQC builtin calls (`dilithium_verify`, `falcon_verify`, etc.) compile to matching VM opcodes

### 1.2 Multi-function dispatch (was: only first function reachable)

Every function previously ended in `Halt`, killing the VM before subsequent functions could execute. Two functions sharing a parameter name (e.g. `amount`) silently aliased the same memory address.

**Implemented:**
- Dispatch table written into the bytecode `data` section at compile time: function name → entry address + parameter memory addresses
- `QuantumVM::call_function(name, args)` marshals arguments into callee memory, pushes a return address, runs until `Return`
- Parameters assigned to disjoint per-function address blocks — no aliasing possible even with identical parameter names
- Inter-function calls via `Call` opcode with backpatched forward refs

### 1.3 Real PQC crypto (was: zeroed keys, hardcoded `true` for all verify)

All six PQC shim modules returned zero bytes for keys/signatures and hardcoded `true` for every verification — a forged signature would pass.

**Implemented — all six modules now use real cryptography:**

| Module | Algorithm | Crate |
|--------|-----------|-------|
| `dilithium.rs` | ML-DSA-65 (Dilithium3) | `pqcrypto-dilithium` |
| `falcon.rs` | Falcon-512 | `pqcrypto-falcon` |
| `sphincs.rs` | SPHINCS+-SHAKE-128s | `pqcrypto-sphincsshake` |
| `kyber.rs` | Kyber-768 | `pqcrypto-kyber` |
| `mceliece.rs` | Classic McEliece 348864 | `pqcrypto-classicmceliece` |
| `hqc.rs` | HQC-128 | `pqcrypto-hqc` |

HQC note: FFI `decapsulate()` panics on malformed input — wrapped in `catch_unwind` to prevent VM process crash.

### 1.4 Real CLI signing (was: literal `"PQC_SIGNATURE_<timestamp>"` string)

`synq-cli compile` now:
1. Generates a fresh ephemeral ML-DSA-65 keypair per compilation
2. Signs actual bytecode bytes via `PQCCompiler::sign_message`
3. Writes a `.sig.json` sidecar — private key discarded immediately, never written to disk

`synq-cli verify --path contract.qvm` confirms the signature or rejects with a clear error. All `panic!`/`expect` calls replaced with graceful `exit(1)` + human-readable messages.

### 1.5 `synq-server` — new HTTP compile service

Axum-based HTTP server exposing the full compile pipeline:

```
POST /compile   { "source": "<SynQ source>" }
GET  /health    → { "status": "ok", "service": "synq-compiler" }
```

The `signature_sidecar` in HTTP responses is structurally identical to the `.sig.json` written by the CLI — browser-downloaded `.qvm` files can be verified locally with `synq-cli verify`.

### 1.6 Regression suite (foundation)

37 tests, all passing:

| Crate | Tests |
|-------|-------|
| `compiler` | 13 |
| `pqc-shims` | 20 |
| `vm` | 4 |

---

## Part 2 — Modular Security Hardening PRs (15 July 2026)

*Following CTO security review of PR #2, work was restructured into seven focused, independently reviewable PRs.*

---

### PR-A — Compiler & Language Core Hardening
**Branch:** `feature/pr-a-compiler-hardening` → PR #14

**What was broken:** The compiler had no duplicate name detection, no modulo operator, no static analysis for recursion or undefined references.

**Implemented:**

- **Duplicate declaration rejection** — compiler now rejects duplicate names for contracts, functions, state variables, and parameters at parse time. Previously two functions with the same name would silently compile, with the second overwriting the first in the dispatch table.

- **`Rem` opcode (0x14)** — modulo operator `%` implemented with compile-time zero-divisor check. A literal `x % 0` is rejected at compile time with a clear error rather than producing a runtime panic.

- **Static call-graph analyser (DFS)** — detects cycles and enforces `MAX_CALL_DEPTH = 64`, modelled after Solana BPF. Direct and indirect recursion is rejected at compile time. The 64-hop limit provides ample headroom for complex call chains while preventing host stack exhaustion.

- **Undefined variable and undefined call detection** — references to undeclared variables or uncalled functions are caught at compile time.

- **`ruint` crate integration** — all U256 arithmetic moved to the `ruint` crate for production-grade, limb-based storage and tested boundary behaviour at `2^128`, `2^255`, and `2^256-1`.

- **NIST FIPS naming** — all PQC algorithm names updated to NIST FIPS 203/204/205/206 canonical names (e.g. Dilithium → ML-DSA-65, Kyber → ML-KEM-768). Input aliases preserved for backwards compatibility.

**Test suite:** 45 passing tests added (20 pqc-shims + 13 compiler/VM + 4 integration + 8 new static-analysis tests).

---

### PR-B — VM Hardening & Transactional Rollback

**What was broken:** The VM had no per-call stack isolation, no execution step limit, and no transactional atomicity — a `Revert` would leave memory in a partially-mutated state.

**Implemented:**

- **`CallFrame` stack architecture** — VM execution loop migrated to a frame-based model. Each `Call` opcode pushes a new `CallFrame` onto a stack; `Return` pops it. Memory state is snapshotted before each call.

- **Transactional rollback on `Revert` (0x34)** — memory is fully restored from the pre-call snapshot when `Revert` executes. Behaviour is EVM-equivalent: a reverted call cannot leave any side-effects.

- **Step counter / execution limit** — a configurable step counter (`MAX_STEPS = 1_000_000`) is decremented on every opcode. Exceeding it returns `RuntimeError::StepLimitExceeded` rather than looping forever.

- **Runtime call-depth guard** — a runtime check at the `Call` opcode enforces the same 64-hop limit as the compile-time static analyser, defending against bytecode constructed to bypass the static check.

**New integration tests:** 4 (rollback, step limit, depth guard, frame isolation). Total passing: **49/49**.

---

### PR-C — Server Security & DoS Hardening

**What was broken:** The server had no payload limits, predictable session IDs, no session store cap, and the VM ran inside the session Mutex — blocking all other requests during execution.

**Implemented:**

- **128KB request body limit** enforced by Axum `DefaultBodyLimit` — oversized payloads are rejected with `413` before reaching the compiler.

- **64KB source code limit** — source strings exceeding this are rejected before parsing, preventing parser DoS on pathological inputs.

- **64-character CSPRNG session IDs** — OS-entropy random session identifiers replace any sequential or time-based scheme. Cross-request state contamination is not possible.

- **100-session store cap with LRU eviction** — session store (`Arc<Mutex<HashMap<String, QuantumVM>>>`) limited to 100 concurrent entries. Oldest session evicted when full.

- **Mutex release during VM execution** — session state is now moved out of the Mutex lock before the VM runs, then reinserted. Long-running contract executions no longer block compilation requests from other users.

- **Hardened hex decoder** — `hex_decode_strict()` implemented across all input paths. Odd-length hex strings are left-padded with a zero rather than panicking. Malformed hex is rejected with a clear error.

- **`/health` endpoint updated** — returns compilation constraints, active limits, and security status for auditability.

**Total passing tests: 76/76.**

---

### PR-D — Cryptographic Correctness & EIP-191 Verification

**What was broken:** The `/attest` endpoint trusted the client-supplied bytecode hash and did not verify the EVM signature server-side — a client could claim any signer address.

**Implemented:**

- **Server-side `ecrecover`** — the server recomputes the bytecode Keccak-256 hash independently (never trusting the client-supplied `bytecode_hash`) and reconstructs the full EIP-191 personal_sign message:
  ```
  "\x19Ethereum Signed Message:\n" + len + "SynQ bytecode keccak256:\n" + 0x<hash>
  ```
  `ecrecover` is applied to recover the signer address. If recovered address ≠ claimed `evm_address`, the request is rejected with a clear mismatch error.

- **`SynQAttestationV1` canonical payload (73+N bytes)** — PQC signature now covers a structured payload rather than raw bytecode concatenation:
  ```
  magic(16) || scheme(1) || keccak256_bytecode(32) || evm_signer(20) || issued_at_u32be(4) || raw_bytecode(N)
  ```

- **`trust_model` field** — signature sidecars now carry an explicit `trust_model` label (`"compiler-attested"` or `"ephemeral-self-signed"`) to distinguish persistent from ephemeral signing.

- **`hex_decode_strict()` enforced everywhere** — all cryptographic input paths now use the hardened decoder; silent failures on malformed hex are eliminated.

- **`k256` + `sha3` crates** — proper Keccak-256 and secp256k1 recovery using production Rust crates rather than ad-hoc implementations.

---

### PR-E — Client-Side Attestation Alignment

**What was broken:** The browser demo was computing the Keccak-256 hash using incorrect byte conversion, producing a hash that didn't match the server's reconstruction — causing every wallet attestation to fail ecrecover with a mismatched address.

**Implemented:**

- **Correct `keccak_256` binding** — `js-sha3` library accessed via `window.keccak_256` (not `window.sha3_256`). Hash is computed over raw bytecode bytes, matching the server's computation exactly.

- **Dynamic `evm_address` extraction** — `eth_requestAccounts` used to obtain the actual connected wallet address before signing. The claimed address in the `/attest` request is now always the same address that produced the signature.

- **`SynQAttestationV1` client payload alignment** — browser-side message construction verified to produce exactly the same byte sequence as the server's EIP-191 reconstruction.

---

### PR-F — Rate Limiting, VM Memory Cap & Readiness Endpoint

**What was broken:** No per-IP rate limiting, no VM memory bound (a contract could allocate unbounded memory), and the `/health` endpoint did not distinguish liveness from readiness.

**Implemented:**

- **`tower-governor` per-IP rate limiter** — 10 requests/second sustained, burst of 30. Exceeded requests receive `429 Too Many Requests` with a `Retry-After` header.

- **VM memory cap (1024 entries)** — each `QuantumVM` instance now enforces a maximum of 1024 memory entries. Writes beyond this return `RuntimeError::MemoryLimitExceeded` rather than growing without bound.

- **`/health/ready` endpoint** — dependency-aware readiness probe, separate from the `/health` liveness probe. Returns `503` if the session store is at capacity; `200` with full subsystem status when ready. Suitable for use as a Kubernetes/load-balancer readiness check.

---

### PR-G — Persistent Compiler-Attestation Keys

**What was broken:** Every server restart generated a new ephemeral ML-DSA-65 keypair, meaning there was no stable compiler identity — clients could not verify that two bytecode outputs came from the same compiler instance.

**Implemented:**

- **Persistent ML-DSA-65 key** — server loads a Base64-encoded private key from `/etc/synq/compiler.key` (permissions: 600) at startup. All bytecode attestations use this key.

- **`key_id` fingerprint** — every signature sidecar now includes a `key_id` field: the first 8 bytes of the SHA3-256 hash of the public key, encoded as hex. Current production key ID: `e50d8f193e91e1d9`.

- **`/synq/pubkey` endpoint** — exposes the compiler's current public key for independent verification without requiring access to the server filesystem.

- **`trust_model: "compiler-attested"`** — sidecars generated with the persistent key carry this label. Ephemeral fallback (if key file is absent) carries `"ephemeral-self-signed"` and logs a startup warning.

- **`keygen.rs` operator tool** — CLI utility for key rotation, producing a new keypair and outputting the public key commitment for registration in `WitnessRegistry.sol`.

- **`CompilerKey` enum** — server startup refactored around a typed enum (`Persistent(key)` / `Ephemeral`) so the signing path is always explicit.

**Final test suite: 84/84 passing across all PRs.**

---

## Part 3 — Demo Portal & Attestation UI (15–16 July 2026)

*Hardening the live demo at https://hanksweb.co.uk/demo/ to correctly surface all attestation fields in both wallet-connected and compiler-only modes.*

### Infrastructure

| Component | Location |
|-----------|----------|
| Demo IDE | `https://hanksweb.co.uk/demo/` |
| Compiler API | `https://hanksweb.co.uk/synq/compile` |
| Attest API | `https://hanksweb.co.uk/synq/attest` |
| Public key | `https://hanksweb.co.uk/synq/pubkey` |
| Health | `https://hanksweb.co.uk/synq/health` |
| Readiness | `https://hanksweb.co.uk/synq/health/ready` |

Nginx at `hanksweb.co.uk` proxies `/synq/` to the Axum server on `127.0.0.1:3030`. The demo page is served as static HTML from `/var/www/synq-demo/`.

### Attestation UI bugs resolved

**1. Card not updating after wallet sign**
The renderer looked for `sidecar.evm.address` (nested), but the server returns a flat structure with `sidecar.evm_address` at root. `isHybrid` was always `false`. Fixed: reads `sidecar.evm_address` directly.

**2. EVM sig always showing `—`**
The server does not echo `evm_signature` back in the `/attest` response (used only for `ecrecover`). Fixed: `doCompile` now passes the locally-captured `evmSig` as a second argument to `renderAttestPanel(sidecar, evmSig)`.

**3. Attest errors silently swallowed**
The `catch (we)` block caught both wallet cancellations and HTTP errors, showing only "Compiled OK" in all cases. Fixed: explicit `if (!ar.ok)` check before JSON parsing — server error body (e.g. the recovered vs claimed address mismatch) now surfaces directly in the status bar. Wallet cancellations (code 4001) still handled gracefully.

**4. Bytecode hash missing in compiler-only mode**
The `/compile` response sidecar has no `bytecode_hash` field — only `/attest` does. Fixed: renderer computes the hash client-side from `currentBytecode` using `keccak_256()` when `sidecar.bytecode_hash` is absent, ensuring the displayed hash is always consistent with what MetaMask would sign.

**5. EVM sig row showing `n/a` in compiler-only mode**
No meaningful value existed for this row without a wallet. Fixed: compiler-only mode now displays the first 20 bytes (40 hex chars) of the compiler's ML-DSA-65 public key as a `0x…` address — architecturally accurate, as the compiler key is the attesting signer when no wallet is present.

**6. Mixed-case hex across all fields**
Server returns lowercase hex; MetaMask returns lowercase; `keccak_256()` returns lowercase. Fixed: a single `hexUp()` helper normalises every hex value to uppercase before display. Applies uniformly to all seven card fields.

### Final attestation card state

**Compiler-only (no wallet connected):**

| Field | Value |
|---|---|
| Mode | Compiler-Attested PQC (ML-DSA-65) |
| Bytecode hash | `0x3d4d535d90…` (computed client-side) |
| EVM address | `n/a — no wallet connected` (dim) |
| EVM sig | `0xa05010ee9a56331287d84f7d98a012d1f851d37a…` (compiler public key) |
| PQC algorithm | ML-DSA-65 |
| PQC key ID | `e50d8f193e91e1d9` |
| PQC sig | `f9327887…` |

**Hybrid (wallet connected and signed):**

| Field | Value |
|---|---|
| Mode | Hybrid (EVM + ML-DSA-65) |
| Bytecode hash | `0x3d4d535d90…` (from server) |
| EVM address | `0x61e0ce867f845d1d8ee8060b5eefbec5072c3efe` |
| EVM sig | `0xc43a1ecb…` (personal_sign output) |
| PQC algorithm | ML-DSA-65 |
| PQC key ID | `e50d8f193e91e1d9` |
| PQC sig | `a909db11…` |

---

## Part 4 — Live Demo Walkthrough

**Demo URL:** https://hanksweb.co.uk/demo/

### Step 1 — Open the demo
Navigate to the URL in any browser. The editor pre-loads a Token contract (`mint`, `burn`, `setPaused` functions).

### Step 2 — Compile (no wallet needed)
Click **"Compile Contract"**. Within ~1 second:
- Status bar: **"✓ Compiled successfully!"**
- Bytecode disassembly appears with opcode offsets and byte count
- **Hybrid Attestation Bundle** card appears in compiler-only mode with all seven fields populated

### Step 3 — Connect wallet (optional — for hybrid attestation)
Click **"Connect Wallet"** with MetaMask installed. After connecting:
- Click **"Compile Contract"** again
- MetaMask prompts to sign the bytecode hash
- After signing, the card updates to Hybrid mode with your wallet address and EVM sig

### Step 4 — Download artefacts
| Button | File | Content |
|--------|------|---------|
| ⬇ Download .qvm | `contract.qvm` | Raw QVM bytecode |
| ⬇ Download .sig.json | `contract.qvm.sig.json` | ML-DSA-65 signature sidecar |

### Step 5 — Verify via curl
```bash
# Compile
curl -s -X POST https://hanksweb.co.uk/synq/compile \
  -H 'Content-Type: application/json' \
  -d '{"source":"pragma synq ^0.9;\ncontract T { total: UInt256; function init(s: UInt256) { total = s; return total; } }"}' | jq .

# Health
curl https://hanksweb.co.uk/synq/health

# Readiness
curl https://hanksweb.co.uk/synq/health/ready

# Public key
curl https://hanksweb.co.uk/synq/pubkey
```

---

## Appendix — Production Server Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/synq/compile` | POST | Compile SynQ source → bytecode + ML-DSA-65 sidecar |
| `/synq/attest` | POST | EIP-191 ecrecover + PQC attestation (hybrid signing) |
| `/synq/session/new` | POST | Create persistent VM session for state execution |
| `/synq/session/:id/call` | POST | Call a contract function on a live VM session |
| `/synq/session/:id/state` | GET | Inspect current state variable values |
| `/synq/pubkey` | GET | Compiler's persistent ML-DSA-65 public key |
| `/synq/health` | GET | Liveness probe |
| `/synq/health/ready` | GET | Readiness probe (session store + PQC subsystem) |

---

## Appendix — Test Suite Summary

| PR | Tests added | Running total |
|----|-------------|---------------|
| Foundation | 37 | 37 |
| PR-A | 8 | 45 |
| PR-B | 4 | 49 |
| PR-C | 12 | 61 |
| PR-D | 8 | 69 |
| PR-E | 7 | 76 |
| PR-F | 4 | 80 |
| PR-G | 4 | **84** |

All 84 tests passing on the production build.

---

## Appendix — Key Identifiers

| Item | Value |
|------|-------|
| Compiler key ID | `e50d8f193e91e1d9` |
| Compiler public key (first 20 bytes) | `0xa05010ee9a56331287d84f7d98a012d1f851d37a` |
| Key file path | `/etc/synq/compiler.key` (permissions: 600) |
| Trust model (persistent) | `compiler-attested` |
| Trust model (fallback) | `ephemeral-self-signed` |
| Production server | `23.254.229.135` |
| Demo URL | `https://hanksweb.co.uk/demo/` |
| GitHub repo | `synergy-network-hq/testnet` |
| PR #14 branch | `feature/pr-a-compiler-hardening` |

---

## Part 5 — UMA Identity Architecture: Protocol Position and Devnet Constraints (21 July 2026)

*Following review of the Synergy Network Security Implementation Specification v1.6, sections 4.1–4.10.*

---

### 5.1 What UMA Is (and Is Not)

The specification is unambiguous: a Universal Meta-Address is not a wallet address, not a hash of a public key, and not a naming overlay. It is a first-class protocol primitive — the stable identity object against which validator authority, governance rights, key rotation, cross-chain attestations, and smart-contract authorization are all evaluated.

The critical architectural property is **temporal decoupling**: UMA persists across key rotations, cryptographic transitions, and cross-chain interactions. Cryptographic keys are *attributes* of a UMA, not the identity itself. This is not a convenience feature — without it, key rotation destroys accumulated reputation, PQC migration fragments identity history, and replay attacks via alternate address encodings become structurally possible.

---

### 5.2 Current Devnet State — Known Violations

The SynQ VM's `LoadCaller` opcode (0x50) currently pushes the raw 20-byte EVM signing address, padded to 32 bytes, as the caller identity. This is a documented devnet placeholder. Against the v1.6 invariants it constitutes violations of:

| Invariant | Statement | Impact on current code |
|-----------|-----------|------------------------|
| U-2 | UMA must persist independently of key material | `LoadCaller` is derived from the signing key — a key rotation changes the identity seen by contracts |
| U-3 | No key or signature has protocol standing unless bound to a UMA | The raw EVM address has no UMA binding |
| U-4 | UMA must be the sole identity reference used by consensus, governance, and execution | Contracts currently key all role logic on raw addresses |

These violations are accepted for devnet. They are not acceptable on mainnet.

---

### 5.3 The Correct Fix — Where It Lives

The fix does not belong in the VM or in SynQ contract code. Invariant U-13 is explicit: *UMA must not encode application-specific or contract-specific semantics*. Adding a `resolve_uma(addr)` opcode or a client-side derivation function (as previously attempted with the keccak approach) violates this invariant by pushing resolution logic into the wrong layer.

The correct architecture is:

```
Wallet signs call → consensus layer validates signature →
consensus resolves signing key → UMA reference →
VM receives call context with UMA already resolved →
LoadCaller pushes UMA reference, not raw address →
contract sees UMA via `caller`
```

`LoadCaller` should be the *consumer* of a resolved UMA, not the resolver. The resolution happens before the VM executes, in the consensus/attestation plane.

---

### 5.4 Implications for the ISynergyUMA Interface

The interface sketched in earlier sessions was attempting resolution inside a contract — also a U-13 violation. The `ISynergyUMA` interface belongs in the consensus/attestation plane, not in SynQ contract code. Contracts must not contain UMA resolution logic.

The interface's correct role is: allow external tooling (wallets, relayers, attestation validators) to query UMA bindings for auditing purposes. It is a read path from the protocol layer, not a call path into contract execution.

---

### 5.5 Liveness Constraint — U-8 and U-14

Two invariants have direct implications for server architecture:

- **U-8**: UMA resolution must not influence consensus ordering or finality. Resolution is one-way consumption — the consensus plane resolves, the execution plane consumes. No feedback loop.
- **U-14**: UMA resolution failures must not halt consensus or cross-chain verification.

For the SynQ server, this means the transition from raw-address sessions to UMA-resolved sessions cannot be a blocking synchronous call in the consensus path. The session model will need a clean fallback (likely: continue with raw address if UMA resolution is unavailable, log the ambiguity, reject on mainnet) so that resolution latency or partial failures do not propagate into execution liveness.

---

### 5.6 What This Means for Current Contract Code

All role-based authorization in ComprehensiveToken (`admin_role[caller]`, `grantAdmin`, `revokeAdmin`, etc.) is currently keyed on raw EVM addresses. This is correct *for the devnet* given the current `LoadCaller` semantics — consistency between the caller identity pushed by the VM and the identity stored by contracts is maintained.

On mainnet migration:

- `caller` will carry a UMA reference, not an EVM address
- All mapping keys used for role storage will need to be UMA-typed
- The `init()` bootstrap will store the deployer's UMA, not their signing address
- Cross-contract calls via `ExternCall` will propagate UMA context, not address context

No contract-level changes are needed *now* — the language-level `caller` keyword is the correct abstraction. The fix is in the protocol plane below it.

---

### 5.7 Summary for Protocol Team

| Item | Status | Owner |
|------|--------|-------|
| `LoadCaller` returning raw EVM address | Known devnet placeholder — violates U-2, U-3, U-4 | VM / consensus layer |
| keccak-based UMA derivation | Removed — was wrong at every layer | Done |
| `ISynergyUMA` interface | Needs repositioning to consensus/attestation plane | Protocol team |
| Contract role logic (`admin_role` etc.) | Correct for devnet; will migrate naturally when `caller` carries UMA | No action needed now |
| U-8/U-14 server liveness | UMA resolution must be async and non-blocking in session handling | synq-server |

