# SynQ V3 — Consolidated Architecture

**Version:** 0.3 (audit-ready)  
**Date:** 2 August 2026  
**Author:** Alan Hancock  
**Repository:** `synergy-network-hq/testnet`, branch `feature/real-codegen-and-dispatch`  
**Live server:** https://hanksweb.co.uk/synq/  
**Demo IDE:** https://hanksweb.co.uk/demo/

---

## 1. System Overview

SynQ is a post-quantum smart contract language, virtual machine, and compiler toolchain for the Synergy Network Testnet-v3. The system compiles SynQ source code into deterministic QVM bytecode, optionally packages it into SQB binary artifacts, and executes it on a stack-based virtual machine with integrated post-quantum cryptography.

### 1.1 Components

```
┌─────────────────────────────────────────────────────────────────┐
│                     SynQ Toolchain                               │
│                                                                  │
│  ┌──────────┐    ┌───────────┐    ┌──────────┐    ┌───────────┐  │
│  │  Parser   │───▶│  Semantic  │───▶│ SSA IR   │───▶│  Codegen  │  │
│  │ (pest)   │    │  Analysis  │    │ Builder   │    │ / Lowerer  │  │
│  └──────────┘    └───────────┘    └──────────┘    └─────┬─────┘  │
│                                                         │        │
│                                          ┌──────────────┘        │
│                                          ▼                      │
│  ┌──────────┐    ┌───────────┐    ┌──────────┐    ┌───────────┐  │
│  │  QVM     │◀──│ Bytecode   │◀──│ Verifier │◀──│  SQB      │  │
│  │ Runtime  │   │ (binary)   │   │ L1 + L2  │   │  Packer   │  │
│  └────┬─────┘   └───────────┘   └──────────┘   └───────────┘  │
│       │                                                         │
│  ┌────▼─────┐    ┌───────────┐    ┌──────────┐                  │
│  │ AEG1     │    │  Authority │   │ Bech32   │                  │
│  │ PQC Shims│    │  + Gov     │   │ Address   │                  │
│  └──────────┘    └───────────┘   └──────────┘                  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              synq-server (Axum, port 3030)                  │  │
│  │  /compile  /attest  /session/*  /workspace/*  /pubkey     │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌────────────────────┐    ┌─────────────────────────────────┐  │
│  │  synq-compiler-wasm│    │  synq-cli                       │  │
│  │  (browser)         │    │  (CLI compile + verify)         │  │
│  └────────────────────┘    └─────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Rust Workspace Crates

| Crate | Path | Purpose |
|-------|------|---------|
| `synq-vm` | `vm/` | Stack-based QVM runtime, opcodes, value types |
| `synq-compiler` | `compiler/` | Parser (pest), AST, semantic analysis, SSA IR, codegen |
| `synq-pqc-shims` | `pqc-shims/` | AEG1 wire protocol, PQC algorithm wrappers |
| `synq-cli` | `cli/` | Command-line compile, sign, verify |
| `synq-server` | `synq-server/` | HTTP API server (Axum), SQB packer, bytecode verifier |
| `synq-compiler-wasm` | `synq-compiler-wasm/` | WASM build of compiler for browser IDE |

### 1.3 Live Infrastructure

| Component | URL / Address | Status |
|-----------|---------------|--------|
| Production server | 23.254.229.135:3030 | Live |
| HTTPS proxy | hanksweb.co.uk/synq/ | nginx reverse proxy |
| Compiler endpoint | hanksweb.co.uk/synq/compile | Live (IR backend primary) |
| WASM compiler | hanksweb.co.uk/synq/compile-wasm | Live |
| RPC stub (MetaMask) | hanksweb.co.uk/synq-rpc/ | Live (chain 1266) |
| Demo IDE | hanksweb.co.uk/demo/ | Live (index.html) |
| Dev IDE | hanksweb.co.uk/demo/demodev.html | Live (dev → prod copy pattern) |
| systemd service | synq-server | Auto-restart enabled |
| systemd service | synq-rpc1266 | Port 8545, MetaMask stub |

---

## 2. Compilation Pipeline

### 2.1 Primary Path: IR Backend

As of 1 August 2026, the primary compilation path is the SSA IR backend:

```
Source → Parser (pest grammar) → AST → Semantic Analysis → IR Builder → SSA Module
    → Optimization Passes (phi insertion, DCE, constant folding, copy propagation)
    → IR Analysis → Lowering to QVM Bytecode → Verification (L1 + L2)
    → Compiler Attestation (ML-DSA-87 signature) → Response
```

The `compile_ir()` function in `compiler/src/lib.rs` is the entry point. On IR failure, it automatically falls back to `CodeGenerator::generate()` (direct AST → bytecode).

### 2.2 Fallback Path: Direct Codegen

```
Source → Parser → AST → Semantic Analysis → CodeGenerator::generate() → QVM Bytecode
```

This path is retained for resilience and handles edge cases the IR builder may not yet cover.

### 2.3 Determinism Guarantees

- State variables sorted by address before IR construction and codegen
- Dispatch tables sorted alphabetically by function name
- PQC builtins resolved to fixed opcode mappings
- Strict UTF-8 validation on all identifiers and binary keys
- HashMap iteration avoided in code generation paths (sorted iteration only)

### 2.4 Compiler Attestation

Every compilation produces an ML-DSA-87 signature over the bytecode:

- **Persistent key mode:** Key loaded from `SYNQ_COMPILER_KEY_PATH`, survives restarts
- **Ephemeral mode:** Fresh keypair per compilation, key discarded after signing
- **Signature sidecar:** `{ algorithm: "ML-DSA-87", mode, public_key, signature, security_level }`
- **Public key endpoint:** `GET /pubkey` serves current compiler public key for independent verification

---

## 3. QVM (SynQ Virtual Machine)

### 3.1 Binary Format

```
QVM\0 (4B magic) + version (1B) + header_len (2B LE) + code_len (4B LE) + data_len (4B LE) = 15B header
Followed by: code section (code_len bytes) + data section (data_len bytes)
```

### 3.2 Value Types

| Type | Size | Description |
|------|------|-------------|
| I32 | 4 bytes | 32-bit signed integer |
| U128 | 16 bytes | 128-bit unsigned integer |
| U256 | 32 bytes | 256-bit unsigned integer (ruint crate, no truncation) |
| Bool | 1 byte | Boolean |
| Bytes | Variable | Byte array |
| Tuple | Variable | Heterogeneous collection (structs, enum payloads) |

### 3.3 Memory Model

- 1024-slot memory cap
- Load on unwritten slot returns I32(0)
- State variables assigned fixed addresses at compile time
- Function parameters assigned disjoint address blocks (no aliasing)
- Transactional atomicity: snapshot before execution, restore on revert

### 3.4 Execution Constraints

| Constraint | Value |
|------------|-------|
| Step limit | 100,000 (configurable) |
| Memory cap | 1024 slots |
| CallFrame stack | 1024 frames |
| Session cap | 100 per IP |
| Rate limit | 200 req/min burst |
| Session TTL | 30 minutes |
| Max source size | 256 KB |
| Max body size | 2 MB |

### 3.5 Opcode Summary

| Range | Category | Opcodes |
|-------|----------|---------|
| 0x01 | Stack | Push |
| 0x10–0x14 | Arithmetic | Add, Sub, Mul, Div, Mod |
| 0x20–0x25 | Comparison | Lt, Gt, Le, Ge, Eq, Ne |
| 0x30–0x36 | Control Flow | Jump, JumpIf, Call, Return, Revert, RevertCode, RevertCodeDyn |
| 0x40–0x44 | Memory | Load, Store, LoadImm, LoadImm128, LoadImm256 |
| 0x50–0x53 | Authority | LoadCaller, LoadAuthority, AuthRequire, AuthIdentity |
| 0x54–0x56 | Bech32 | AddrEncode (syna), AddrDecode (syna/sync/synw), ContractAddr (sync) |
| 0x57–0x5B | Assets | AssetCreate, AssetTransfer, AssetBurn, AssetBalance, AssetOwner |
| 0x60 | External | ExternCall |
| 0x80–0x83 | Legacy PQC | (aliases for backward compat) |
| 0x8F | PQC | AegisCall (unified, AEG1 wire protocol) |
| 0x9F | Debug | ToString |
| 0xA0–0xAB | Tuples | TuplePack, TupleGet, OptionNone, TupleSet |
| 0xF0 | Output | Print |
| 0xFF | Terminal | Halt |

See `SynQ-VM-Specification.md` for full opcode reference.

---

## 4. SSA IR

### 4.1 Architecture

The IR module (`compiler/src/ir/`) implements a typed Static Single Assignment intermediate representation:

| File | Responsibility |
|------|---------------|
| `builder.rs` | AST → SSA IR construction |
| `function.rs` | Function representation, parameters, blocks |
| `blocks.rs` | Basic blocks, CFG, predecessors |
| `instructions.rs` | IR instruction types (Const, BinOp, Store, Load, Call, Branch, Return, etc.) |
| `types.rs` | IR type system (IrType) |
| `module.rs` | Module-level structure (state vars, structs, enums) |
| `analyzer.rs` | IR analysis (effects, auth checks, linear ops, host profiles) |
| `passes.rs` | Optimization passes (phi insertion via Cytron IDF, DCE, constant folding, copy propagation) |
| `lower.rs` | IR → QVM bytecode lowering (slot-based SSA deconstruction, phi handling, block linearization) |

### 4.2 Optimization Passes

1. **Phi insertion** — Cytron iterative dominance frontier algorithm
2. **SSA validation** — verify every value has exactly one definition
3. **Dead code elimination** — remove unreachable blocks and unused values
4. **Constant folding** — evaluate compile-time constant expressions
5. **Copy propagation** — replace value references with their source definitions

### 4.3 IR Analysis Output

The analyzer produces per-function warnings visible in the compile response:
- Block count, instruction count, reachable blocks
- Effect operations (stores, emits)
- Host-function profile declarations
- Authority check count
- Linear resource creates/consumes

### 4.4 IR → Bytecode Lowering

- Slot-based SSA deconstruction (each ValueId maps to a memory slot)
- Phi nodes → store/load on predecessor block edges
- Block linearization via DFS of CFG
- Jump patching for forward references
- Cross-block ValueId resolution for dominator-defined values

---

## 5. SQB Binary Artifact Format

### 5.1 Overview

The SQB (SynQ Binary) format is a canonical, hash-bound envelope wrapping QVM bytecode with ABI, manifest, IR, and metadata sections. It satisfies all 11 ACTS-VM requirements.

### 5.2 Wire Format

```
Header (16 bytes):
  [0..4]   magic           b"SQB1"
  [4]      version         1
  [5]      flags           bit0=manifest, bit1=signature, bit2=ir_dump
  [6..8]   section_count   u16 LE
  [8..12]  chain_id        u32 LE (1266 for Testnet-v3)
  [12..16] timestamp       u32 LE (Unix epoch)

Sections (repeated section_count times):
  [0]      section_type    u8
  [1..5]   data_length     u32 LE
  [5..5+N] data            N bytes
  [5+N..5+N+32] hash       SHA3-256(data)

Artifact Root (32 bytes):
  SHA3-256(hash_1 || hash_2 || ... || hash_N)

Signature (optional, if flags bit1):
  [0..4]   sig_length      u32 LE
  [4..4+S] signature       ML-DSA-87 over artifact root
```

### 5.3 Section Types

| Type ID | Name | Content |
|---------|------|---------|
| 0x01 | CODE | QVM bytecode |
| 0x02 | ABI | Function signatures, parameter types |
| 0x03 | MANIFEST | State layout, governance/authority scopes, required_signature_algorithm |
| 0x04 | IR | SSA IR dump (optional) |
| 0x05 | EFFECTS | Declared effects per function |
| 0x06 | STATE_LAYOUT | State variable addresses and types |
| 0x07 | META | Compiler version, timestamp, contract name |

### 5.4 Bounds

- Max total artifact: 4 MiB
- Max sections: 256
- Max per-section data: 1 MiB
- Atomic binding: artifact root = SHA3-256 of all section hashes; tampering breaks root

---

## 6. Bytecode Verification

### 6.1 Layer 1 — Structural Integrity (MANDATORY, hard gate)

Validates bytecode format before any execution:

- Magic bytes: `QVM\0` at offset 0
- Header fields within bounds (code_len, data_len non-zero, not exceeding file size)
- All opcode bytes are recognized (no unknown opcodes)
- Jump targets within code section bounds
- Call targets within code section bounds
- No truncated instructions (inline immedials have required bytes)
- Data section does not overflow file boundary

**Result:** PASS (proceed) or FAIL (reject — no execution).

### 6.2 Layer 2 — Stack Safety (ADVISORY, symbolic analysis)

Performs symbolic stack depth analysis to detect underflows:

- Walks all code paths from entry, tracking symbolic stack depth
- Each opcode has a known stack delta (pop count, push count)
- Flags paths where stack depth would go negative (underflow)
- Flags functions where return stack depth doesn't match declared return type
- Reports maximum stack depth observed (resource planning)

**Result:** PASS (stack-safe) or WARN (potential underflow detected). Warnings are surfaced but do not block execution.

### 6.3 Layer 3 — Manifest Signature Verification (PLANNED)

Verifies ML-DSA-87 signature on the SQB manifest section:

- Priority: SQB-embedded manifest > request-provided manifest > skip
- Verifies ML-DSA-87 signature over manifest hash
- Checks required_signature_algorithm matches account-domain policy
- Validates governance/authority scope declarations

**Status:** Not yet implemented. This is the final verification step for full bytecode provenance.

---

## 7. Cryptographic Architecture

### 7.1 Domain Separation (V3)

| Domain | Domain Tag | Algorithm | Purpose |
|--------|-----------|-----------|---------|
| Deploy | SYNQ-DEPLOY-v3 | ML-DSA-87 | Contract deployment signatures |
| Call | SYNQ-CALL-v3 | ML-DSA-87 | Contract call signatures |
| Governance | SYNQ-GOVERNANCE-v3 | ML-DSA-87 | Governance authorization |
| Attestation | SYNQ-ATTEST-v3 | ML-DSA-87 | Compiler attestation |
| Consensus | (consensus layer) | ML-DSA-65 | Validator consensus signing |
| ETDAG ingress | (ETDAG layer) | ML-KEM-1024 + AES-256-GCM | Encrypted DAG ingress |

Cross-domain replay is prevented by distinct domain tags. Wrong algorithm/key length fails closed.

### 7.2 AEG1 Wire Protocol

Bounded framing ABI for all VM-accessible PQC operations:

```
AEG1 (4B magic) + op (1B) + alg (1B) + argc (1B) + length-delimited args (u32_be per arg)
```

| Bound | Value |
|-------|-------|
| Max total payload | 1 MiB |
| Max arguments | 8 |
| Max per-argument size | 128 KiB |
| Max response size | 128 KiB |

**Operations:**

| Op | Name | Description |
|----|------|-------------|
| 1 | ML-KEM decapsulate | Key decapsulation (secret-key — rejected in deterministic dispatch) |
| 2 | ML-DSA verify | Signature verification (public-key — allowed) |
| 3 | FN-DSA verify | Signature verification (public-key — allowed) |

**Algorithm IDs:**

| ID | Algorithm | NIST/FIPS Name |
|----|-----------|----------------|
| 0x01 | ML-KEM-512 | Kyber-512 |
| 0x02 | ML-KEM-768 | Kyber-768 |
| 0x03 | ML-KEM-1024 | Kyber-1024 |
| 0x10 | ML-DSA-44 | Dilithium-44 |
| 0x11 | ML-DSA-65 | Dilithium-65 |
| 0x12 | ML-DSA-87 | Dilithium-87 |
| 0x20 | FN-DSA-512 | Falcon-512 |
| 0x21 | FN-DSA-1024 | Falcon-1024 |

### 7.3 Deterministic Dispatch (ACTS-15)

AegisCall (0x8F) uses `dispatch_deterministic()` which:
- Permits only public-key operations (ML-DSA verify, FN-DSA verify)
- Rejects secret-key operations (ML-KEM decapsulate) with explicit error
- Enforces AEG1 wire protocol bounds (magic, argc, length)
- All inputs are public and deterministic — same inputs always produce same outputs

### 7.4 PQC Implementation Status

| Algorithm | Crate | Implementation | AEG1? |
|-----------|-------|---------------|-------|
| ML-DSA-65 | pqcrypto-dilithium | Real (production) | Yes (0x11) |
| ML-DSA-87 | pqcrypto-dilithium | Real (production) | Yes (0x12) |
| FN-DSA-512 | pqcrypto-falcon | Real (production) | Yes (0x20) |
| ML-KEM-768 | pqcrypto-kyber | Real (production) | Yes (0x02) |
| SPHINCS+ | pqcrypto-sphincsshake | Real (production) | No (legacy) |
| McEliece | pqcrypto-classicmceliece | Real (production) | No (legacy) |
| HQC-128 | pqcrypto-hqc | Real (production, catch_unwind on FFI panic) | No (legacy) |

All six PQC modules use real cryptography from the `pqcrypto` crate family. No stubs, no hardcoded `true`, no zeroed keys.

---

## 8. Authority and Governance

### 8.1 AuthorityEnvelope (104 bytes)

```
identity (32B)       — UMA identity hash
scope_hash (32B)     — SHA3-256 of scope name
nonce (8B)           — replay protection
expiry (8B)          — validity window
caps (8B)            — capability bitmask
reserved (16B)        — V3 domain tag (SYNQ-CALL-v3, SYNQ-GOVERNANCE-v3, etc.)
```

### 8.2 Scope Hashes

| Scope Type | Hash Computation |
|-----------|------------------|
| Authority | SHA3-256("SYNQ-AUTHORITY-SCOPE-v1:" + scope_name) |
| Governance | SHA3-256("SYNQ-GOVERNANCE-SCOPE-v1:" + scope_name) |

### 8.3 Attribute System

| Attribute | Description | Enforcement |
|-----------|-------------|-------------|
| `@public` | No authority required | Compile-time + runtime |
| `@authority(Scope)` | Requires authority envelope matching scope | Compile-time + runtime |
| `@governance(Scope)` | Requires governance authorization | Compile-time + runtime |
| `@effects(v1, v2, ...)` | Declares state variables modified | Compile-time documentation |
| `@requires(expr)` | Precondition | Compile-time documentation |
| `@ensures(expr)` | Postcondition | Compile-time documentation |
| `@fails(ErrorType)` | Declares named error type | Compile-time + runtime |
| `@bounded(n)` | Loop bound declaration | Compile-time documentation |
| `@manifest` | Include in V3 manifest ABI | Compile-time |
| `@ai` | AI-optimized hint metadata | Reserved (future) |

### 8.4 Runtime Authority

- `AuthRequire` (0x52): pops envelope + scope_hash, verifies authority
- All-zeros envelope scope = devnet wildcard (accept any scope)
- `LoadCaller` (0x50): pushes caller address
- `LoadAuthority` (0x51): pushes current AuthorityEnvelope
- `AuthIdentity` (0x53): pops envelope, pushes identity (32B)
- Legacy `as caller` syntax retained alongside attribute-based model

---

## 9. Address Model (V3)

### 9.1 Bech32 HRP Assignments

| HRP | Purpose | Status |
|-----|---------|--------|
| `syna` | Accounts | Active |
| `sync` | Contracts | Active |
| `synw` | Native wallets | Active |
| `tsynq` | (legacy) | RETIRED — fails closed |

### 9.2 Opcodes

| Opcode | Name | Operation |
|--------|------|-----------|
| 0x54 | AddrEncode | Pop 20-byte value → push syna string |
| 0x55 | AddrDecode | Pop syna/sync/synw string → push U256 |
| 0x56 | ContractAddr | Pop deployer + nonce + artifact_hash → push sync string |

### 9.3 Builtins

```synq
to_syna(addr: u256) -> string
from_syna(addr: string) -> u256
contract_address(deployer: u256, nonce: u256, artifact_hash: u256) -> string
```

`from_any_syn()` decodes syna/synw/sync to 20 bytes. tsynq is rejected.

---

## 10. EIP-712 Signing (V3)

| Parameter | Value |
|-----------|-------|
| Chain ID | 1266 |
| Network ID | synergy-testnet-v3 |
| Domain tag (calls) | SYNQ-CALL-v3 |
| Domain name | `SynQ · <Contract> · synergy-testnet-v3` |
| ContractCall struct | `{ callSignature, sessionId, nonce, domainTag }` |

EIP-712 typed data signing is used for all contract calls and source commits. The domain tag is embedded in the AuthorityEnvelope reserved field (bytes 88–104).

---

## 11. V3 Testnet Parameters

| Parameter | Value |
|-----------|-------|
| Chain ID | 1266 |
| Network ID | synergy-testnet-v3 |
| PoSy protocol | v2.2 |
| Block target | 2,000 ms |
| Validators | 6, quorum 5/6 |
| Quorum rule | Count: 3*s > 2*n; Weight: 3*w_s > 2*w_total |
| Native token | SNRG |
| Account domain | ML-DSA-87 |
| Consensus domain | ML-DSA-65 |
| ETDAG ingress | ML-KEM-1024 + AES-256-GCM |
| Account HRP | syna |
| Contract HRP | sync |
| Wallet HRP | synw |

### 11.1 Signature Domains

- SYNQ-DEPLOY-v3
- SYNQ-CALL-v3
- SYNQ-GOVERNANCE-v3
- SYNQ-ATTEST-v3

---

## 12. Linear Assets

### 12.1 Asset<T> Model

Linear resources with create, transfer, burn semantics. Each asset ID is consumed exactly once:

| Opcode | Name | Operation |
|--------|------|-----------|
| 0x57 | AssetCreate | Pop type_tag + value → push asset_id (owner = caller) |
| 0x58 | AssetTransfer | Pop new_owner + asset_id → push new_asset_id (old deactivated) |
| 0x59 | AssetBurn | Pop asset_id → push value (asset deactivated) |
| 0x5A | AssetBalance | Pop asset_id → push value (0 if inactive) |
| 0x5B | AssetOwner | Pop asset_id → push owner (0 if inactive) |

### 12.2 Builtins

```synq
asset_create(type_name: string, value: u256) -> u256
asset_transfer(asset_id: u256, to: u256) -> u256
asset_burn(asset_id: u256) -> u256
asset_balance(asset_id: u256) -> u256
asset_owner(asset_id: u256) -> u256
```

### 12.3 Linearity Invariant

Each asset ID can be consumed exactly once. Transfer deactivates the old ID and creates a new one. Burn deactivates and returns the value. The VM asset registry (`AssetRecord`) tracks owner, value, type_tag, and active flag.

---

## 13. Wallet Integration

Three-tier address resolution:

1. **Synergy extension (synw)** — primary, if installed
2. **Device-link JSON** — fallback, manual synw entry
3. **Ephemeral Bech32 (syna/sync)** — demo/dev mode

- `_walletProvider()` + `_walletRequest()` for all wallet RPCs
- EIP-6963 multi-provider discovery for MetaMask
- MetaMask chain-switch to 1266 via RPC stub at hanksweb.co.uk/synq-rpc/
- V3 EIP-712 domain (chainId 1266, domainTag SYNQ-CALL-v3)
- Manual synw (`_manualSynw`) is a separate variable from `walletSyna`

---

## 14. Contract Templates

| Template | Demonstrates |
|----------|-------------|
| TokenVault | ERC-20-style vault, controller-asset pattern |
| SimpleToken | Mint/burn/transfer, self-transfer guard |
| LoopDemo | while/break/continue, overflow-safe sqrtFloor (binary search) |
| V3TypesDemo | Types, enums, attributes, authority/Bech32 builtins |
| GovernanceDemo | @governance scope enforcement |
| AssetDemo | Linear asset create/transfer/burn |
| NamedErrorDemo | Named error reverts with enum variants |
| StructFieldTest | Struct field assignment (TupleSet opcode) |
| StructEnumDemo | Struct field access + enum variant comparison |
| StackFailDemo | Educational contract demonstrating verification layers |

---

## 15. Build and Test

### 15.1 Building

```bash
cd /root/Downloads/synergy-testnet/SynQ
source $HOME/.cargo/env
cargo build --workspace --release
```

### 15.2 Running Tests

```bash
cargo test --workspace
# Result: 203 passed, 0 failed, 1 ignored
```

### 15.3 Server

```bash
systemctl start synq-server   # port 3030
systemctl start synq-rpc1266  # port 8545 (MetaMask stub)
```

### 15.4 Compiler Key

```bash
# Persistent key (recommended for production):
export SYNQ_COMPILER_KEY_PATH=/path/to/ml_dsa_87_key.json

# Without this, server uses ephemeral keys (fresh per compilation)
```

---

End of SynQ V3 Architecture v0.3
