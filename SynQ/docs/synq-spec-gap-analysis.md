# SynQ Spec v7.0 vs Current Implementation — Gap Analysis
**Date:** 28 July 2026
**Spec source:** `synergy-network-hq/protocol-documentation` (committed 25 Jul 2026)

---

## Executive Summary

The CTO has released a comprehensive SynQ v7.0 specification (23 documents) alongside the AIVM Technical Specification v0.1 (14 documents) and Aegis Technical Specification (33 documents). The spec describes an authority-aware, AI-integrated, formally verifiable smart contract language with a multi-layer execution model (AIVM → SynQ-VM). Our current implementation is a working v0.x prototype that demonstrates the basic compiler → VM → server pipeline but covers a fraction of what the spec requires.

---

## What We Have (Current Implementation)

✅ Working PEG grammar parser (contracts, state, functions, expressions)
✅ Stack-based VM (QVM) with arithmetic, logic, control flow, maps, sets, extern_call
✅ Full U256 via ruint crate (no truncation)
✅ PQC shims: ML-DSA-65, Falcon-512, SPHINCS+, Kyber-768, McEliece, HQC-128
✅ HTTP compile server with sessions, workspaces, rate limiting
✅ EIP-712 session auth with ecrecover
✅ Persistent compiler-attestation key (ML-DSA-65, key_id, trust_model)
✅ Loop constructs: while, break, continue
✅ Transactional atomicity (snapshot/restore on Revert)
✅ Deterministic bytecode (sorted dispatch table)
✅ 84/84 tests passing
✅ Demo IDE (compile → test → deploy → state inspection)
✅ Benchmark tool (4 compilation paths, fuel metering)

---

## Major Gaps (Spec v7.0 Requirements We Don't Have)

### 1. Authority Model (CRITICAL)
**Spec:** `AuthorityEnvelope<S>`, `Capability<S>`, UMA identities, `@authority(Scope)` attributes, `authority::require(auth, Scope)?`. Authority is UMA-based, not raw key material. Key rotation doesn't change identity.

**Current:** `caller` builtin → LoadCaller (0x50) returns raw 20-byte EVM address. The spec explicitly calls `require(msg.sender == owner)` an **anti-pattern**.

**Impact:** This is the most fundamental architectural gap. Our entire auth model is wrong per spec.

### 2. Attribute System (CRITICAL)
**Spec:** `@public`, `@authority`, `@effects`, `@requires`, `@ensures`, `@fails`, `@bounded`, `@manifest`, `@ai`, `@external_fact`, `@upgrade`, `@deprecated`. Every public function MUST declare authority, effects, and resource bounds.

**Current:** No attribute system. We have `requires_state` and `modifies` as basic metadata, but no `@`-prefixed attribute grammar or compile-time enforcement.

### 3. Effect System (HIGH)
**Spec:** `@effects(read: [...], write: [...], emit: [...], facts: [...], models: [...])`. Compile fails when inference finds undeclared effects or callee effects exceed caller scope.

**Current:** `requires_state`/`modifies` declarations exist but are not enforced at compile time.

### 4. Type System (CRITICAL)
**Spec:** `UInt<N>`, `Int<N>`, `Bytes<N>`, `Fixed<M,N>`, `Hash32`, `Height`, `Epoch`, `UMAIdentity`, `ModelId`, `Tensor<E,Shape>`, `Asset<T>`, `Capability<S>`, `AuthorityEnvelope<S>`, `VerifiedFact<T>`, `InferenceRequest<I,O>`, `InferenceReceipt<O>`, `Result<T,E>`, `Option<T>`.

**Current:** `u256`, `i32`, `bool`, `str`, `map<K,V>`, `set<T>`. No parameterized types, no linear types, no sum types.

### 5. Linear Types (HIGH)
**Spec:** `linear struct Asset<T>` — consumed exactly once. Copying or dropping is a compile-time error. Assets, capabilities, and facts are linear.

**Current:** No linear type system. All values are freely copyable.

### 6. AIVM Layer (CRITICAL)
**Spec:** AIVM is the node-side execution platform above SynQ-VM. It handles artifact admission, UMA/Aegis checks, model validation, AI execution, state journaling, receipt production, consensus output. SynQ-VM is just the deterministic bytecode kernel inside AIVM.

**Current:** Our VM IS the execution platform. There's no AIVM layer, no artifact admission, no model validation, no AI execution.

### 7. AI Integration (HIGH — per spec, not our current scope)
**Spec:** `ai::infer_native()`, `ai::verify_proof()`, `ai::create_job()`, model registry, inference receipts, AI trust modes (NativeDeterministic, ProofVerified, AttestedReceipt), AI policy gates, bounded agents.

**Current:** No AI integration whatsoever. This may be a later-phase concern.

### 8. SSA IR (HIGH)
**Spec:** Typed SSA with explicit control-flow blocks, authority checks, effect tokens, linear-resource moves, journal operations, fact consumption, AI operations. IR cannot contain implicit host calls.

**Current:** Codegen goes straight from AST to stack bytecode. No IR layer.

### 9. Bytecode Verification (HIGH)
**Spec:** Pre-deployment verification: format, opcodes, control-flow, stack height, linear resources, authority/effect placement, host-function profiles, model/proof profiles, resource bounds.

**Current:** No bytecode verifier. The VM trusts the compiler output.

### 10. Deployment Artifacts (.sqb) (MEDIUM)
**Spec:** `.sqb` is a canonical envelope with hash-bound sections (code, ABI, metadata, effects, models, proofs). All section hashes bound into artifact root.

**Current:** `.qvm` is raw bytecode with a 15-byte header. No sections, no hash binding.

### 11. Verified Facts / Cross-Chain (MEDIUM — depends on SXCP)
**Spec:** `VerifiedFact<T>` with nullifier, proof_ref, scope_hash. `facts::consume_once()`. `@external_fact(source: "chain-a", adapter_profile: "sxcp-chain-a-v4")`.

**Current:** No fact system. extern_call is the only cross-contract mechanism.

### 12. Structs and Enums (HIGH)
**Spec:** User-defined structs, enums with variants, tuples, pattern matching (`match` expressions).

**Current:** No user-defined types. Only primitives and map/set.

### 13. Module System (MEDIUM)
**Spec:** `module treasury.risk;`, `use authority::{AuthorityEnvelope, Capability};`, imports.

**Current:** No module system. Single-file contracts only.

### 14. Event System (MEDIUM)
**Spec:** `emit EventName(args)`, declared events, `@effects(emit: [EventName])`.

**Current:** No events. Print (0xF0) is the only output.

### 15. Error Types (MEDIUM)
**Spec:** `-> Result<T, ErrorType>`, `fail expr` statement, `@fails(ErrorType1, ErrorType2)`.

**Current:** Revert (0x33) with no typed errors. Functions return bool or u256.

### 16. Formal Verification (HIGH — per spec)
**Spec:** Proof-certificate production, vacuity/coverage analysis, independent proof checking, `spec` blocks with `requires`/`ensures`/`modifies`/`fails`/`assume`.

**Current:** No formal verification. `requires_state`/`modifies` are metadata only.

### 17. Resource Bounds (MEDIUM)
**Spec:** `@bounded(execution_units: 240_000, storage_writes: 4, events: 2)`. Meters cover CPU, memory, storage, crypto, AI, events, state growth.

**Current:** Step limit only. No declarative resource bounds.

### 18. Upgrade Pattern (LOW — future)
**Spec:** `@upgrade(from: N, to: N+1, migration: fn, preserves: [invariants])`.

**Current:** Not implemented. No upgrade mechanism.

### 19. Domain Separation (HIGH)
**Spec:** Versioned domain tags for all crypto: `SYNQ/AUTH/v1`, `SYNQ/FACT/v1`, `SYNQ/ARTIFACT/v1`, `AIVM/MODEL/v1`, etc.

**Current:** EIP-712 domain exists but is not generalized to all cryptographic operations.

### 20. Canonical Source Hashing (MEDIUM)
**Spec:** Two conforming parsers must produce the same canonical AST hash. LF line endings, pinned identifier profile.

**Current:** No canonical hashing. No reproducible-build attestation.

---

## What Aligns Well

Our current implementation got these right per the spec:
- **Determinism** — sorted dispatch tables, strict UTF-8, no lossy normalization
- **PQC crypto** — real implementations, not stubs; Aegis-governed profiles
- **Transaction atomicity** — snapshot/restore on Revert
- **Step/gas limits** — execution is bounded
- **U256** — full-width via ruint, no truncation
- **External calls** — extern_call pattern is architecturally sound (though spec wraps it in authority context)
- **Persistent compiler key** — aligns with Option B from the CTO review
- **EIP-712 auth** — ecrecover-based, nonce-gated

---

## Suggested Priority Order (If Aligning to Spec)

1. **Attribute grammar** — add `@`-prefixed attributes to the PEG grammar
2. **Type system expansion** — `UInt<N>`, `Bytes<N>`, `Result<T,E>`, `Option<T>`
3. **Authority model** — replace `caller` with `AuthorityEnvelope<S>` (even as a stub)
4. **Effect declarations** — enforce `@effects` at compile time
5. **Structs and enums** — user-defined types with pattern matching
6. **Event system** — `emit` keyword, declared events
7. **Error types** — `Result<T,E>`, `fail` statement
8. **SSA IR** — intermediate representation between AST and bytecode
9. **Bytecode verifier** — pre-deployment validation
10. **Deployment artifact** — `.sqb` envelope format
11. **Module system** — `module`, `use`, imports
12. **AIVM layer** — execution orchestration above SynQ-VM
13. **AI integration** — model registry, inference receipts (later phase)
14. **Verified facts** — SCETP/SXCP fact consumption (later phase)
15. **Formal verification** — proof certificates, spec blocks (later phase)
