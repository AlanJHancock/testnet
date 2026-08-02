# SynQ Spec v7.0 vs Current Implementation — Gap Analysis (Updated)

**Date:** 2 August 2026  
**Supersedes:** 28 July 2026 version  
**Spec source:** `synergy-network-hq/protocol-documentation`  
**Implementation:** `synergy-network-hq/testnet`, branch `feature/real-codegen-and-dispatch`  
**Test suite:** 203 passed, 0 failed, 1 ignored

---

## Executive Summary

Since the 28 July gap analysis, significant progress has been made. The SSA IR backend is now the primary compilation path, the full attribute system is implemented, structs and enums are working, bytecode verification (Layers 1 and 2) is live, and the SQB binary artifact format is implemented. The toolchain now covers substantially more of the v7.0 spec, though major gaps remain in the AIVM layer, formal verification, module system, and event system.

---

## Previously Reported as Missing — Now Implemented

| Item | 28 July Status | 2 August Status |
|------|---------------|-----------------|
| Attribute system | "CRITICAL — not implemented" | ✅ Production — 10 attributes (@public, @authority, @governance, @effects, @requires, @ensures, @fails, @bounded, @manifest, @ai) |
| SSA IR | "HIGH — no IR layer" | ✅ Production — Full SSA with optimization passes, IR is primary compilation path |
| Bytecode verification | "HIGH — no verifier" | ✅ Production — Layer 1 (structural, mandatory) + Layer 2 (stack safety, advisory) |
| Structs and enums | "HIGH — no user-defined types" | ✅ Production — C-style + algebraic enums, struct literals, field access, field assignment |
| Deployment artifact (.sqb) | "MEDIUM — raw .qvm only" | ✅ Production — SQB1 format with 7 TLV sections, hash binding, ML-DSA-87 signature |
| Named errors | "MEDIUM — no typed errors" | ✅ Production — RevertCode (0x35), RevertCodeDyn (0x36), enum-variant errors |
| Authority model | "CRITICAL — wrong (raw key)" | ⚠️ Partial — AuthorityEnvelope (104B), scope hashes, @authority/@governance — but identity field is not UMA-resolved |
| Effect system | "HIGH — not enforced" | ⚠️ Partial — @effects declared and recorded in IR analysis, but not compile-time enforced |
| Type system | "CRITICAL — limited" | ⚠️ Partial — I32, U128, U256, Bool, Bytes, Tuple, structs, enums — but no parameterized types (UInt<N>, Tensor, etc.) |
| Linear types | "HIGH — no linear types" | ⚠️ Partial — Asset<T> runtime-enforced (create/transfer/burn), but not compile-time linear |

---

## Remaining Gaps

### 1. AIVM Layer (CRITICAL — future)
**Spec:** AIVM is the node-side execution platform above SynQ-VM. Handles artifact admission, UMA/Aegis checks, model validation, AI execution, state journaling, receipt production, consensus output.
**Current:** No AIVM layer. The QVM is the execution platform. No artifact admission beyond L1/L2 verification, no model validation, no AI execution.
**Impact:** The AIVM is the v7.0 north star. Current architecture supports it (deterministic dispatch, AEG1, authority scopes) but the layer itself does not exist.

### 2. Formal Verification (HIGH — future)
**Spec:** Proof-certificate production, vacuity/coverage analysis, independent proof checking, `spec` blocks with `requires`/`ensures`/`modifies`/`fails`/`assume`.
**Current:** `@requires` and `@ensures` are compile-time documentation only. No proof generation or checking.

### 3. Module System (MEDIUM)
**Spec:** `module treasury.risk;`, `use authority::{AuthorityEnvelope, Capability};`, imports.
**Current:** No module system. Single-file contracts only. Cross-contract via ExternCall within workspace.

### 4. Event System (MEDIUM)
**Spec:** `emit EventName(args)`, declared events, `@effects(emit: [EventName])`.
**Current:** No typed events. Print (0xF0) is the only output mechanism.

### 5. Parameterized Types (HIGH)
**Spec:** `UInt<N>`, `Int<N>`, `Bytes<N>`, `Fixed<M,N>`, `Tensor<E,Shape>`, `Result<T,E>`, `Option<T>`, `Capability<S>`.
**Current:** Fixed-size `Bytes<N>` is supported as an alias. No general parameterized types. `Option<T>` is partially supported via OptionNone (0xA4) opcode. No `Result<T,E>`.

### 6. UMA Identity (MEDIUM)
**Spec:** Authority is UMA-based — identity is not raw key material. Key rotation doesn't change identity.
**Current:** AuthorityEnvelope identity field exists (32 bytes) but is not UMA-resolved. The `caller` builtin returns a raw address. Identity is effectively key-derived.

### 7. Compile-Time Effect Enforcement (HIGH)
**Spec:** Compile fails when inference finds undeclared effects or callee effects exceed caller scope.
**Current:** `@effects` attributes are parsed and recorded in IR analysis warnings, but compilation does not fail on undeclared effects.

### 8. Compile-Time Linear Type Enforcement (HIGH)
**Spec:** Copying or dropping a linear value is a compile-time error.
**Current:** Asset<T> linearity is enforced at runtime (deactivation on transfer/burn) but not at compile time. A linear value can be silently dropped in the compiler.

### 9. Layer 3 Verification (HIGH)
**Spec:** Pre-deployment manifest signature verification.
**Current:** Layer 1 (structural) and Layer 2 (stack safety) are implemented. Layer 3 (ML-DSA-87 manifest signature verification) is designed but not implemented.

### 10. Verified Facts / Cross-Chain (MEDIUM — depends on SXCP)
**Spec:** `VerifiedFact<T>` with nullifier, proof_ref, scope_hash. `facts::consume_once()`. `@external_fact`.
**Current:** No fact system. ExternCall is the only cross-contract mechanism.

### 11. Upgrade Pattern (LOW — future)
**Spec:** `@upgrade(from: N, to: N+1, migration: fn, preserves: [invariants])`.
**Current:** Not implemented. No upgrade mechanism.

### 12. Canonical Source Hashing (MEDIUM)
**Spec:** Two conforming parsers must produce the same canonical AST hash.
**Current:** No canonical hashing. No reproducible-build attestation beyond bytecode signatures.

### 13. Generalized Domain Separation (MEDIUM)
**Spec:** Versioned domain tags for all crypto: `SYNQ/AUTH/v1`, `SYNQ/FACT/v1`, `SYNQ/ARTIFACT/v1`, etc.
**Current:** EIP-712 domain exists (SYNQ-CALL-v3, etc.) but is not generalized to all cryptographic operations beyond deploy/call/govern/attest.

### 14. Resource Bounds (MEDIUM)
**Spec:** `@bounded(execution_units: 240_000, storage_writes: 4, events: 2)`. Meters for CPU, memory, storage, crypto, AI, events, state growth.
**Current:** `@bounded(n)` is documentation-only. Step limit is the only runtime meter. No per-resource meters.

### 15. IR Serialization for SQB (LOW)
**Spec:** IR section in SQB artifact contains serialized IR module.
**Current:** IR dump is a text string in the compile response and IDE. Not serialized into the SQB IR section in a structured format.

---

## What Aligns Well

The following are correctly implemented per spec:

- **Determinism** — sorted dispatch tables, sorted state vars, strict UTF-8, no HashMap iteration in codegen
- **PQC crypto** — all six algorithms use real implementations, no stubs
- **AEG1 wire protocol** — bounded, framed, deterministic dispatch (ACTS-15)
- **Transaction atomicity** — snapshot/restore on revert
- **Step/gas limits** — execution is bounded
- **U256** — full-width via ruint, no truncation
- **External calls** — ExternCall pattern is architecturally sound
- **ML-DSA-87 account domain** — correctly separated from ML-DSA-65 consensus
- **Domain separation** — four V3 domain tags prevent cross-domain replay
- **Bech32 addressing** — syna/sync/synw, tsynq retired
- **SQB artifact** — hash-bound, ML-DSA-87 signed, ACTS-VM compliant
- **Bytecode verification** — L1 + L2 implemented
- **SSA IR** — full optimization pipeline, primary compilation path
- **Attribute system** — 10 attributes, compile-time + runtime enforcement for authority
- **Named errors** — enum-variant reverts with structured codes
- **Structs/enums** — field access, field assignment, algebraic variants
- **Wallet integration** — three-tier, EIP-6963, EIP-712 V3

---

## Priority Order for Remaining Work

1. Layer 3 verification (manifest signature) — completes bytecode provenance
2. Compile-time effect enforcement — close the effect system gap
3. Compile-time linear type enforcement — close the linear types gap
4. Event system — emit, declared events, @effects(emit)
5. UMA identity — replace raw key with identity resolution
6. Module system — module, use, imports
7. Parameterized types — Result<T,E>, Option<T>, Bytes<N> generalization
8. Generalized domain separation — all crypto operations
9. Resource bounds — per-resource meters
10. IR serialization — structured IR in SQB
11. Verified facts / SXCP — cross-chain
12. AIVM layer — node-side execution platform
13. Formal verification — proof certificates
14. Upgrade pattern — contract migration

---

End of Gap Analysis (2 August 2026)
