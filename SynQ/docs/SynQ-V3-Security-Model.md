# SynQ V3 — Security Model

**Version:** 0.3  
**Date:** 2 August 2026  
**Author:** Alan Hancock

---

## 1. Trust Chain

The SynQ toolchain establishes a trust chain from source code to execution:

```
Source Code
  │
  ▼
Parser (pest grammar) ──▶ AST
  │
  ▼
Semantic Analysis ──▶ Type-checked AST
  │                  ▶ Attribute validation (@public, @authority, @governance, @effects, @fails)
  │                  ▶ PQC builtin resolution
  │                  ▶ Scope hash computation (SHA3-256)
  │
  ▼
IR Builder ──▶ SSA Module
  │            ▶ Deterministic state var ordering (sorted by address)
  │            ▶ SSA validation (every value has exactly one definition)
  │
  ▼
Optimization Passes
  │  ▶ Phi insertion (Cytron IDF)
  │  ▶ Dead code elimination
  │  ▶ Constant folding
  │  ▶ Copy propagation
  │
  ▼
IR Lowering ──▶ QVM Bytecode
  │              ▶ Slot-based SSA deconstruction
  │              ▶ Block linearization (DFS)
  │              ▶ Jump patching
  │
  ▼
Bytecode Verification
  │  ▶ Layer 1: Structural integrity (MANDATORY)
  │  ▶ Layer 2: Stack safety (ADVISORY)
  │  ▶ Layer 3: Manifest signature (PLANNED)
  │
  ▼
Compiler Attestation ──▶ ML-DSA-87 signature over bytecode
  │                       ▶ Persistent or ephemeral keypair
  │                       ▶ Public key served via GET /pubkey
  │
  ▼
SQB Packaging (optional) ──▶ Hash-bound artifact envelope
  │                            ▶ Section hashes → artifact root
  │                            ▶ ML-DSA-87 signature over artifact root
  │
  ▼
VM Execution
  │  ▶ Authority envelope verification (AuthRequire)
  │  ▶ Governance scope enforcement
  │  ▶ AEG1 wire protocol bounds enforcement
  │  ▶ Deterministic dispatch (ACTS-15)
  │  ▶ Transactional atomicity (rollback on revert)
  │  ▶ Step limit (100,000)
  │  ▶ Memory cap (1024 slots)
  │
  ▼
Result + Receipt
```

---

## 2. Cryptographic Profiles

### 2.1 Per-Domain Algorithm Assignment

| Domain | Algorithm | Purpose | Enforced By |
|--------|-----------|---------|-------------|
| Account | ML-DSA-87 | Contract deploy/call signatures, compiler attestation | synq-server, AIVM |
| Consensus | ML-DSA-65 | Validator proposal/validation/finality signing | Consensus layer (separate) |
| P2P identity | (separate) | Node identity | Network layer (separate) |
| ETDAG ingress | ML-KEM-1024 + AES-256-GCM | Encrypted DAG ingress | ETDAG layer (separate) |

### 2.1.1 Why ML-DSA-87 for Accounts

The V3 testnet separates account-domain signatures from consensus signatures. Previously, ML-DSA-65 (the consensus algorithm) was incorrectly used for governed account actions. The correction to ML-DSA-87 ensures:

- Account actions cannot be replayed as consensus messages (different algorithm = different key material)
- Manifest `required_signature_algorithm` is single-sourced and bound to the compiled artifact
- Wrong algorithm/key length fails closed at the VM boundary

### 2.2 Domain Separation

Four domain tags prevent cross-domain replay:

| Domain Tag | Used For |
|-----------|----------|
| SYNQ-DEPLOY-v3 | Contract deployment signatures |
| SYNQ-CALL-v3 | Contract call signatures |
| SYNQ-GOVERNANCE-v3 | Governance authorization signatures |
| SYNQ-ATTEST-v3 | Compiler attestation signatures |

Each domain tag is embedded in the AuthorityEnvelope reserved field (bytes 88–104). A signature for one domain cannot be replayed in another.

### 2.3 PQC Implementation

All PQC operations use real cryptographic implementations from the `pqcrypto` crate family:

| Algorithm | Crate | Status | In AEG1? |
|-----------|-------|--------|----------|
| ML-DSA-65 | pqcrypto-dilithium | Production | Yes (0x11) |
| ML-DSA-87 | pqcrypto-dilithium | Production | Yes (0x12) |
| FN-DSA-512 | pqcrypto-falcon | Production | Yes (0x20) |
| ML-KEM-768 | pqcrypto-kyber | Production | Yes (0x02) |
| SPHINCS+-SHAKE-128s | pqcrypto-sphincsshake | Production | No (legacy) |
| Classic McEliece 348864 | pqcrypto-classicmceliece | Production | No (legacy) |
| HQC-128 | pqcrypto-hqc | Production (catch_unwind on FFI panic) | No (legacy) |

No PQC operations use stubs, zeroed keys, or hardcoded `true` verification. All six modules generate real keys, produce real signatures, and perform real verification.

---

## 3. AEG1 Wire Protocol Security

### 3.1 Bounds Enforcement

| Bound | Value | Enforcement |
|-------|-------|-------------|
| Magic | "AEG1" (4 bytes) | Checked before any parsing |
| Max payload | 1 MiB | Hard reject on overflow |
| Max arguments | 8 | Hard reject on overflow |
| Max per-argument | 128 KiB | Hard reject on overflow |
| Max response | 128 KiB | Hard reject on overflow |
| Argument count | argc byte | Must match actual args parsed |
| Argument lengths | u32_be per arg | Must not exceed remaining payload |

### 3.2 Deterministic Dispatch (ACTS-15)

AegisCall (0x8F) routes through `dispatch_deterministic()`:

- **Allowed:** ML-DSA verify (op=2), FN-DSA verify (op=3) — public inputs only
- **Rejected:** ML-KEM decapsulate (op=1) — requires secret key, non-deterministic
- Rejection produces explicit error, not silent failure
- All allowed operations take only public inputs: message, signature, public key
- Same inputs always produce same outputs (no randomness, no secret state)

### 3.3 Legacy PQC Opcodes

Opcodes 0x80–0x83 are retained as backward-compatible aliases for direct PQC calls (pre-AEG1). They route to the same underlying implementations. New code should use AegisCall (0x8F) exclusively.

SPHINCS+, McEliece, and HQC are NOT part of the AEG1 protocol. They remain accessible only through legacy direct-call opcodes.

---

## 4. Authority Model

### 4.1 AuthorityEnvelope

The AuthorityEnvelope (104 bytes) is the unit of authorization in the QVM:

```
Offset  Size  Field           Description
0       32    identity        UMA identity hash (not raw public key)
32      32    scope_hash       SHA3-256 of scope name
64      8     nonce            Replay protection
72      8     expiry           Validity window (Unix timestamp)
80      8     caps             Capability bitmask
88      16    reserved         V3 domain tag (e.g., "SYNQ-CALL-v3")
```

### 4.2 Scope Hashes

| Scope Type | Hash Formula |
|-----------|-------------|
| Authority | SHA3-256("SYNQ-AUTHORITY-SCOPE-v1:" + scope_name) |
| Governance | SHA3-256("SYNQ-GOVERNANCE-SCOPE-v1:" + scope_name) |

Scope hashes bind authority to specific named scopes. An authority for "Treasury" cannot authorize "Staking" operations.

### 4.3 Runtime Enforcement

| Opcode | Name | Operation |
|--------|------|-----------|
| 0x50 | LoadCaller | Pushes caller address (20 bytes) |
| 0x51 | LoadAuthority | Pushes current AuthorityEnvelope (104 bytes) |
| 0x52 | AuthRequire | Pops envelope + scope_hash, verifies authority |
| 0x53 | AuthIdentity | Pops envelope, pushes identity (32 bytes) |

### 4.4 Devnet Wildcard

An AuthorityEnvelope with all-zeros scope_hash is accepted as a devnet wildcard — it matches any scope. This is a development convenience and must be disabled in production.

### 4.5 Attribute Enforcement

The compiler enforces attribute declarations at compile time:

- `@public` functions: no AuthRequire emitted
- `@authority(Scope)` functions: AuthRequire emitted with computed scope hash
- `@governance(Scope)` functions: AuthRequire emitted with governance scope hash and SYNQ-GOVERNANCE-v3 domain tag
- `@effects(...)` functions: effects recorded in IR analysis warnings
- `@fails(ErrorType)` functions: error type linked to revert opcodes

Legacy `as caller` syntax is retained for backward compatibility but the attribute-based model is the primary authority mechanism.

---

## 5. Bytecode Verification

### 5.1 Layer 1 — Structural Integrity (Hard Gate)

**Mandatory.** If Layer 1 fails, bytecode is rejected and no execution occurs.

Checks:
- Magic bytes: `QVM\0` at offset 0
- Version byte is recognized
- Header fields (code_len, data_len) are within file bounds
- Every opcode byte in the code section is a recognized opcode
- All jump targets (Jump, JumpIf, Call) are within code section bounds
- No truncated instructions (inline immedials have required bytes)
- Data section does not overflow file boundary

### 5.2 Layer 2 — Stack Safety (Advisory)

**Advisory.** Warnings are surfaced but do not block execution.

Checks:
- Symbolic stack depth tracking along all code paths
- Each opcode's stack delta (pop count, push count) is known
- Flags paths where stack depth would go negative (underflow)
- Flags functions where return stack depth doesn't match declared return type
- Reports maximum stack depth (resource planning)

### 5.3 Layer 3 — Manifest Signature (Planned)

**Not yet implemented.** This is the final verification step for full bytecode provenance.

Design:
- Priority: SQB-embedded manifest > request-provided manifest > skip
- Verifies ML-DSA-87 signature over manifest hash
- Checks `required_signature_algorithm` matches account-domain policy (ML-DSA-87)
- Validates governance/authority scope declarations in manifest
- Ensures state layout matches declared ABI

---

## 6. SQB Artifact Integrity

### 6.1 Hash Binding

Every SQB section is individually hashed (SHA3-256). The artifact root is `SHA3-256(hash_1 || ... || hash_N)`. Any tampering with any section changes its hash, which changes the artifact root, which invalidates the ML-DSA-87 signature.

### 6.2 Signature

The optional signature section contains an ML-DSA-87 signature over the 32-byte artifact root. Verification requires:
1. Decode all sections and recompute individual hashes
2. Recompute artifact root from section hashes
3. Verify ML-DSA-87 signature against recomputed root
4. Compare against expected public key

### 6.3 ACTS-VM Compliance

All 11 ACTS-VM requirements are addressed:

| Requirement | How |
|-------------|-----|
| ACTS-VM-001 | Deterministic encoding (fixed section order, u32 LE lengths) |
| ACTS-VM-002 | Bounded artifact (4 MiB max, 256 sections, 1 MiB/section) |
| ACTS-VM-003 | Reject malformed input (magic, bounds, trailing bytes) |
| ACTS-VM-004 | Canonical identifiers (fixed u8 section type enum) |
| ACTS-VM-005 | Deterministic cost model (O(sections + data)) |
| ACTS-VM-006 | Resource isolation (owned Vec, no shared state) |
| ACTS-VM-007 | Capability discovery (flags byte) |
| ACTS-VM-008 | Exhaustive capability enum (section_count + flags) |
| ACTS-VM-009 | Atomic binding (artifact root = SHA3-256 of all hashes) |
| ACTS-VM-010 | Zeroization (decoder zeroes temp buffers) |
| ACTS-VM-011 | ABI versioning (header version + META section) |

---

## 7. Runtime Security

### 7.1 Transactional Atomicity

Before each contract call, the VM snapshots all state (memory, assets, call frame). If execution reverts (Revert, RevertCode, RevertCodeDyn, or runtime error), the snapshot is restored. No partial state mutations survive a revert.

### 7.2 Resource Bounds

| Bound | Value | Enforcement |
|-------|-------|-------------|
| Step limit | 100,000 instructions | Hard halt on overflow |
| Memory | 1024 slots | Hard error on overflow |
| CallFrame stack | 1024 frames | Stack overflow error |
| Session cap | 100 per IP | 429 Too Many Sessions |
| Rate limit | 200 req/min | 429 Too Many Requests |
| Source size | 256 KB | 413 Payload Too Large |
| Body size | 2 MB | 413 Payload Too Large |
| Session TTL | 30 minutes | Expired sessions garbage-collected |

### 7.3 HQC FFI Safety

The HQC-128 crate's `decapsulate()` function panics on malformed input (FFI boundary issue). The `catch_unwind` wrapper prevents a VM process crash, converting the panic to a controlled error.

---

## 8. Known Security Limitations

### 8.1 Layer 3 Not Implemented

Bytecode provenance is incomplete without Layer 3 (manifest signature verification). Currently, bytecode is verified structurally (L1) and for stack safety (L2), but manifest integrity is not verified at load time. This means a modified manifest could be paired with valid bytecode without detection at the VM level.

### 8.2 Devnet Wildcard

The all-zeros scope_hash wildcard is a development convenience. In production, this must be disabled to prevent unauthorized access to governed functions.

### 8.3 No Formal Verification

The `@requires` and `@ensures` attributes are compile-time documentation only. There is no proof-certificate production, vacuity analysis, or independent proof checking. Formal verification is a v7.0 spec requirement not yet implemented.

### 8.4 No Module System

SynQ currently supports single-file contracts only. There is no `module`/`use`/import system. Cross-contract interaction is via ExternCall (0x60) within the same workspace.

### 8.5 Event System

The only output mechanism is Print (0xF0). There is no typed event system (`emit EventName(args)`). The v7.0 spec requires declared events with `@effects(emit: [EventName])`.

### 8.6 No Upgrade Pattern

There is no `@upgrade` attribute or contract migration mechanism. Contract upgrades require full redeployment.

---

End of SynQ V3 Security Model v0.3
