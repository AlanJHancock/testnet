# WASM PQC Deferral — Architecture Decision Record

**Status:** Accepted
**Date:** 2026-07-29
**Deciders:** Alan Hancock (CTO), SynQ Toolchain Team
**Supersedes:** None

## Context

The SynQ compiler is distributed in two execution profiles:

1. **Native server** (`synq-server`, Axum on port 3030) — full PQC capability via the `aegis-pqsynq` facade and `pqrust-*` C-compiled backends (ML-KEM, ML-DSA, FN-DSA, HQC-KEM).
2. **Browser WASM** (`synq-compiler-wasm`, deployed to `hanksweb.co.uk/demo/wasm/`) — in-browser compilation only, served via `wasm-pack build --release --target web`.

The `aegis-pqsynq` crate (`#![no_std]`) provides the canonical PQC facade: algorithm identifiers, key/signature types, transaction and contract envelopes, security policy, canonicalization helpers, `AegisSynQVerifier`, KEM and signature factories. Its PQC implementations depend on `pqrust-*` crates, which compile PQClean C code via `cc` + `build.rs`.

## Problem

`pqrust-*` crates require C cross-compilation (`cc` crate + `build.rs` with PQClean sources). This does not work for `wasm32-unknown-unknown` because:

- PQClean C sources use platform-specific intrinsics (AVX2, NEON, AES-NI) not available in the WASM target.
- `cc` cannot cross-compile C to WASM without a WASM sysroot and emscripten/clang-wasm toolchain — not configured in the current build.
- The `synq-compiler-wasm` crate is built with `wasm-pack` which targets `wasm32-unknown-unknown` with no C toolchain.

The target matrix in the PQSynQ facade specification records `wasm32-unknown-unknown` and `wasm32-wasip1` as compile profiles. Full-feature WASI runtime execution is **not yet a mandatory CI gate** per the spec.

## Decision

**WASM builds defer all PQC operations to the server.** The `synq-compiler-wasm` crate uses a `pqc-shims-stub` (pure-Rust no-op) instead of the real `aegis-pqsynq` crate. This is an intentional architectural decision, not a temporary workaround.

### Scope of Deferral

| Operation | WASM Behavior | Server Behavior |
|---|---|---|
| **Compilation** (parse → codegen → bytecode) | ✅ Full support | ✅ Full support |
| **ML-KEM keygen/encaps/decaps** | ❌ Returns error | ✅ via `pqrust-mlkem` |
| **ML-DSA sign/verify** | ❌ Returns error | ✅ via `pqrust-mldsa` |
| **FN-DSA sign/verify** | ❌ Returns error | ✅ via `pqrust-fndsa` |
| **HQC-KEM** | ❌ Returns error | ✅ via `pqrust-hqckem` |
| **AegisCall (0x8F)** | ❌ Returns `"AegisCall requires native build"` | ✅ Full AEG1 wire protocol |
| **AegisSynQVerifier** | ❌ Not wired in | ✅ Full verification |
| **Authority envelope construction** | ❌ Devnet wildcard only | ✅ Server constructs from EVM address + nonce |
| **EIP-712 signing** | ✅ Handled in JS (browser wallet) | ✅ Server validates signature |
| **Bech32 encoding** | ✅ JS-side (syna/sync) | ✅ VM opcodes 0x54-0x56 |

### Architecture Flow

```
Browser (WASM)                    Server (Native)
┌─────────────────┐               ┌──────────────────────┐
│  synq-compiler- │               │  synq-server (Axum)   │
│  wasm           │               │                       │
│                 │  compile      │  /compile             │
│  compile_synq() ├──────────────►│  /compile-wasm        │
│                 │  HTTP         │  /session/run         │
│  PQC stub      │               │                       │
│  (no-op)       │               │  aegis-pqsynq         │
│                 │               │  pqrust-* (C/PQClean)  │
│  JS wallet     │  EIP-712 sign │  AegisSynQVerifier     │
│  (MetaMask/    ├──────────────►│  AuthorityEnvelope     │
│   Synergy ext) │               │  AEG1 wire protocol    │
└─────────────────┘               └──────────────────────┘
```

### The `pqc-shims-stub` Crate

Located at `synq-compiler-wasm/pqc-shims-stub/`, this crate provides:

- `dilithium` — `keygen()`, `sign()`, `verify()` → no-op, `verify()` returns `false`
- `falcon` — same no-op pattern
- `sphincs` — same no-op pattern
- `kyber` — `keygen()`, `encaps()`, `decaps()` → returns zero-filled `Vec<u8>`
- `mceliece` — same no-op pattern
- `hqc` — same no-op pattern

All stubs are pure Rust with no C dependencies, ensuring the WASM binary remains self-contained.

### WASM VM Opcode Behavior

V3 PQC/authority opcodes in the WASM VM (`vm_inner/vm.rs`) are gated behind `#[cfg(feature = "native")]`:

- `LoadAuthority (0x51)`, `AuthRequire (0x52)`, `AuthIdentity (0x53)` — devnet wildcard (all-zeros envelope accepted)
- `AddrEncode (0x54)`, `AddrDecode (0x55)`, `ContractAddr (0x56)` — placeholder strings (real encoding done JS-side)
- `AegisCall (0x8F)` — returns runtime error `"AegisCall requires native build"`

### Security Implications

- **No PQC keys are generated or stored in the browser.** Ephemeral keys are JS-side ed25519 for EIP-712 signing only.
- **No PQC verification happens in WASM.** The server's `AegisSynQVerifier` is the sole verification authority.
- **The WASM binary cannot perform or attest PQC operations.** This prevents false positives from a compromised client.
- **Server-side authority is always final.** The server constructs `AuthorityEnvelope` from the verified EIP-712 signature and session context.

### Future Path to WASM PQC

If browser-side PQC becomes necessary (e.g., offline signing, client-side verification):

1. Add `wasm32` feature to `pqrust-*` crates that selects pure-Rust implementations (no C, no `build.rs`).
2. Add `aegis-pqsynq` as an optional dependency of `synq-compiler-wasm` under a `pqc-native` feature.
3. Wire `AegisCall (0x8F)` to the real AEG1 protocol in WASM when the feature is enabled.
4. Add `wasm32-unknown-unknown` to CI matrix with the `pqc-native` feature.

Until then, the server-side PQC path is the only supported execution mode.

## Consequences

- ✅ WASM binary stays small (~200KB) and C-free
- ✅ No false PQC attestations from browser
- ✅ Server maintains full PQC authority
- ✅ Compilation (the WASM crate's actual purpose) works fully in-browser
- ❌ No offline PQC signing or verification
- ❌ WASM runtime cannot execute PQC-dependent contract functions (deferred to server)
- ❌ `wasm32-wasip1` full-feature profile is not functional for PQC

## Compliance Statement

This deferral complies with the PQSynQ facade specification Section 5.2, which states: *"Runtime execution for the full WASI target is not yet a mandatory CI gate in the cited matrix."* The `synq-compiler-wasm` crate serves compilation only; all PQC runtime operations are explicitly delegated to the native server.
