# SynQ

SynQ is a domain-specific language for writing **quantum-resistant smart contracts** on the Synergy Network testnet. It compiles to **QVM bytecode** — a stack-based instruction set executed by the QuantumVM — and every compiled artifact is signed with a real **ML-DSA-65 (FIPS 204)** post-quantum signature.

> **Testnet status.** All components described here are live on the Synergy testnet.  
> Compiler service: `https://hanksweb.co.uk/synq/`  
> Interactive IDE: `https://hanksweb.co.uk/demo/`

---

## Architecture

```
SynQ source (.synq)
      │
      ▼
  synq-compiler  ←─── pest grammar + precedence-climbing expression parser
      │                static analysis: duplicate names, call-depth, zero-divisors
      │
      ▼
  QVM bytecode (.qvm / .synq_bytecode)
      │            ┌─ dispatch table (function name → entry address + param slots)
      │            └─ data section   (literals, state-var layout)
      │
      ├──► synq-cli  — compile, sign, verify, run locally
      │
      ├──► synq-server  — HTTP API: compile, attest, persistent VM sessions
      │         └─ ML-DSA-65 ephemeral signature on every artifact
      │
      └──► QuantumVM  — stack-based interpreter
                 └─ PQC opcodes: DilithiumVerify, KyberKeyExchange, FalconVerify, SphincsVerify
```

---

## Language Reference

### Pragma & contract declaration

```synq
pragma synq ^0.9;

contract Token {
    total: UInt256;
    owner: UInt256;   // Ethereum addresses stored as UInt256
    paused: UInt256;  // 0 = active, 1 = paused

    function init(supply: UInt256, wallet: UInt256) {
        total = supply;
        owner = wallet;
        paused = 0;
    }

    function mint(amount: UInt256) {
        require(paused == 0, "contract is paused");
        total = total + amount;
        return total;
    }

    function burn(amount: UInt256) {
        require(amount > 0, "amount must be positive");
        require(total >= amount, "insufficient supply");
        total = total - amount;
        return total;
    }

    function getTotal() {
        return total;
    }
}
```

### Types

| SynQ type | VM storage | Notes |
|-----------|-----------|-------|
| `UInt256` | `Value::U256` (ruint) | Default integer type; 160-bit Ethereum addresses fit natively |
| `i32` literal | `Value::I32` | Small constants; auto-promoted in mixed arithmetic |
| `bool` | `Value::Bool` | `true` / `false` |

### Operators

`+` `-` `*` `/` `%` `==` `!=` `<` `<=` `>` `>=`

Division and modulo by zero are caught at **compile time**.

### Control flow

```synq
require(condition, "revert message");   // aborts with Reverted error if false
return expr;                            // sets has_return flag in dispatch table
```

### PQC builtins

```synq
dilithium_verify(public_key, message, signature)
falcon_verify(public_key, message, signature)
kyber_key_exchange(public_key)
sphincs_verify(public_key, message, signature)
```

---

## Static Analysis (PR-A)

The compiler enforces at compile time:

- **Duplicate rejection** — duplicate contract, function, state-variable, and parameter names are rejected with a clear error.
- **Call-depth limit** — DFS call-graph analysis; max depth 64 (Solana BPF model). Cycles are detected and rejected.
- **Division / modulo by zero** — compile-time check on literal divisors.
- **Undefined references** — calls to undeclared functions and reads of undeclared variables are rejected.

---

## VM (PR-B)

The QuantumVM is a stack-based interpreter with:

- **Call frames** — each `Call` opcode pushes a frame (return address + stack-depth snapshot). `Return` restores the frame and enforces the ABI contract: exactly one value for declared-return functions, zero residuals for void functions.
- **State rollback** — all `require()` failures, runtime errors, and step-limit exhaustion trigger a full memory snapshot rollback to the pre-call state.
- **Step limit** — 1,000,000 instructions per invocation; malicious infinite-loop bytecode cannot monopolise the server thread.
- **Call-depth guard** — runtime enforcement of max call depth (64), matching the compile-time limit.

### Opcodes

| Category | Opcodes |
|----------|---------|
| Stack | `Push`, `Pop`, `Dup` |
| Arithmetic | `Add`, `Sub`, `Mul`, `Div`, `Rem` (0x14) |
| Comparison | `Eq`, `Ne`, `Lt`, `Le`, `Gt`, `Ge` |
| Control | `Jump`, `JumpIf`, `Call`, `Return`, `Halt`, `Revert` |
| Memory | `Load`, `Store`, `LoadImm` (i32), `LoadImm128` (0x43, u128), `LoadImm256` (0x44, U256) |
| PQC | `DilithiumVerify`, `KyberKeyExchange`, `FalconVerify`, `SphincsVerify` |

### Value types

| Variant | Width | Source |
|---------|-------|--------|
| `Value::I32` | 32-bit signed | small literals |
| `Value::U128` | 128-bit unsigned | mid-range literals |
| `Value::U256` | 256-bit unsigned (`ruint`) | large literals, Ethereum addresses |
| `Value::Bool` | 1-bit | comparisons |
| `Value::Bytes` | variable | PQC key/signature payloads |

All arithmetic uses **checked operations** — overflow raises `RuntimeError` rather than wrapping silently.

---

## CLI

```bash
# Compile + sign with ephemeral ML-DSA-65 key
synq-cli compile --path contract.synq --output contract.qvm

# Verify the signature sidecar
synq-cli verify --path contract.qvm

# Run a function locally
synq-cli run --path contract.qvm --function mint --args 1000

# List functions in compiled bytecode
synq-cli run --path contract.qvm --list
```

**Trust model:** each compilation generates a fresh ephemeral ML-DSA-65 keypair. The sidecar proves bytecode integrity (tamper detection) but does not establish compiler identity — the public key is not anchored to a persistent trusted root.

Verify output is explicit about this:
```
✅ Signature mathematically valid (ML-DSA-65) — bundle is untampered.
ℹ️  Signer trust: ephemeral key — compiler identity is not independently established.
```

---

## HTTP Server (`synq-server`)

See [`synq-server/README.md`](synq-server/README.md) for the full API reference.

**Base URL (testnet):** `https://hanksweb.co.uk/synq/`

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Service status, capacity, limits |
| `/compile` | POST | Compile SynQ source → bytecode + ML-DSA-65 sidecar |
| `/attest` | POST | Hybrid EVM + PQC attestation (SynQAttestationV1) |
| `/session/new` | POST | Load bytecode into a persistent VM session |
| `/session/run` | POST | Call a function on a live session |
| `/session/:id` | DELETE | Destroy a session |
| `/session/:id/state` | GET | Read live state-variable values |

---

## PQC Shim Library (`pqc-shims`)

All six PQC algorithms use real implementations — no stubs, no hardcoded returns.

| Module | NIST standard | Crate |
|--------|--------------|-------|
| `dilithium.rs` | ML-DSA-65 (FIPS 204) | `pqcrypto-mldsa` |
| `falcon.rs` | FN-DSA-512 (FIPS 206) | `pqcrypto-falcon` |
| `sphincs.rs` | SLH-DSA-SHAKE-128s (FIPS 205) | `pqcrypto-sphincsshake` |
| `kyber.rs` | ML-KEM-768 (FIPS 203) | `pqcrypto` (mlkem768) |
| `mceliece.rs` | Classic McEliece 348864 | `pqcrypto-classicmceliece` |
| `hqc.rs` | HQC-128 | `pqcrypto-hqc` |

All modules follow the same safety contract: malformed inputs return safe defaults (`false` / zeroed shared secret), never panic. HQC wraps the upstream FFI panic in `catch_unwind`.

---

## Test Suite

```bash
cargo test          # run full workspace suite
cargo test -p synq-compiler
cargo test -p synq-vm
cargo test -p synq-pqc-shims
cargo test -p synq-cli
```

**Current:** 84 passing, 0 failing, 1 ignored (determinism test, pending BTreeMap refactor in a later PR).

---

## Security model & known limitations

| Area | Status |
|------|--------|
| Compiler key | Ephemeral per-compilation — proves integrity, not identity |
| Session IDs | 32 bytes OS entropy (getrandom), 64-char hex |
| Session cap | 100 concurrent sessions, 30-min TTL, LRU eviction |
| Body size limit | 128 KB requests, 64 KB source |
| VM step limit | 1,000,000 instructions per call |
| CORS | Configurable via `SYNQ_CORS_ORIGIN` env var (default `*` for testnet) |
| EVM verification | `/attest` runs server-side `ecrecover`; mismatches rejected |
| Rate limiting | Per-IP rate limiting: not yet implemented (planned PR-C follow-up) |
| Persistent compiler key | Not yet implemented (Option B from CTO review) |
| Recursion | Blocked at compile time (depth 64) and runtime (call-depth guard) |
| UInt256 | Full 256-bit via `ruint` crate — no silent truncation |

---

## Workspace structure

```
SynQ/
├── compiler/       — parser, codegen, static analysis, PQC integration
│   └── tests/      — integration tests (49 cases)
├── vm/             — QuantumVM interpreter, opcodes, call frames
├── pqc-shims/      — real PQC implementations (6 algorithms, 20 tests)
├── cli/            — synq-cli binary
│   └── tests/      — CLI integration tests (3 cases)
├── synq-server/    — HTTP compile/run/attest server
└── sdk/            — TypeScript SDK (DilithiumKeypair, ECDSAKeypair, QuantumVMSDK)
```
