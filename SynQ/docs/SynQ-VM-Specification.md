# SynQ Virtual Machine Specification v0.3

---

## 1. Overview

SynQ VM (QVM) is a stack-based virtual machine for executing post-quantum smart contracts on the Synergy Network Testnet-v3. It supports:

- Stack-based execution with I32, U128, U256, Bool, Bytes, and Tuple value types
- AEG1 wire protocol for PQC operations (ML-KEM, ML-DSA, FN-DSA)
- Authority envelopes and governance scope enforcement
- Linear asset tracking (Asset&lt;T&gt;)
- Named error reverts with structured codes (static + dynamic)
- Bech32 address derivation (syna/sync/synw)
- Per-operation gas accounting with PQC-gas separation
- Transactional atomicity (rollback on revert)
- Step limit and 1024-slot memory cap
- Bytecode verification (Layer 1 structural + Layer 2 stack safety)
- Deterministic dispatch for PQC operations (ACTS-15)

**Binary format:** `QVM\0` magic (4B) + version (1B) + header_len (2B LE) + code_len (4B LE) + data_len (4B LE) = 15-byte header, followed by code and data sections.

---

## 2. Opcode Reference

### 2.1 Core Stack & Arithmetic (0x01–0x14)

| Opcode | Name        | Description |
|--------|-------------|-------------|
| 0x01   | Push        | Push i32 (4B LE inline) |
| 0x10   | Add         | Pop two, push sum |
| 0x11   | Sub         | Pop two, push difference |
| 0x12   | Mul         | Pop two, push product |
| 0x13   | Div         | Pop two, push quotient |
| 0x14   | Mod         | Pop two, push remainder |

### 2.2 Comparison (0x20–0x25)

| Opcode | Name        | Description |
|--------|-------------|-------------|
| 0x20   | Lt          | Pop two, push bool |
| 0x21   | Gt          | Pop two, push bool |
| 0x22   | Le          | Pop two, push bool |
| 0x23   | Ge          | Pop two, push bool |
| 0x24   | Eq          | Pop two, push bool |
| 0x25   | Ne          | Pop two, push bool |

### 2.3 Control Flow (0x30–0x36)

| Opcode | Name          | Description |
|--------|---------------|-------------|
| 0x30   | Jump          | Unconditional jump (4B LE target) |
| 0x31   | JumpIf        | Pop bool, jump if true (4B LE target) |
| 0x32   | Call          | Function call (4B LE target) |
| 0x33   | Return        | Pop return value, halt function |
| 0x34   | Revert        | Pop string, revert with message |
| 0x35   | RevertCode    | Named error revert: error_code (4B LE) + msg_len (4B LE) + message bytes |
| 0x36   | RevertCodeDyn | Dynamic named error revert with runtime argument evaluation |

### 2.4 Memory & Storage (0x40–0x44)

| Opcode | Name        | Description |
|--------|-------------|-------------|
| 0x40   | Load        | Pop address, push value (0 if unwritten) |
| 0x41   | Store       | Pop value, pop address, store |
| 0x42   | LoadImm     | Load raw bytes (4B LE length + data) |
| 0x43   | LoadImm128  | Push 16-byte U128 literal |
| 0x44   | LoadImm256  | Push 32-byte U256 literal |

### 2.5 Authority & Identity (0x50–0x53)

| Opcode | Name          | Description |
|--------|---------------|-------------|
| 0x50   | LoadCaller    | Push caller address onto stack |
| 0x51   | LoadAuthority | Push current AuthorityEnvelope (104B) |
| 0x52   | AuthRequire  | Pop envelope + scope_hash, verify authority. All-zeros scope = devnet wildcard |
| 0x53   | AuthIdentity | Pop envelope, push identity (32B) |

**AuthorityEnvelope (104 bytes):** identity(32B) + scope_hash(32B) + nonce(8B) + expiry(8B) + caps(8B) + reserved(16B, V3 domain tag)

### 2.6 Bech32 Addressing (0x54–0x56)

| Opcode | Name          | Description |
|--------|---------------|-------------|
| 0x54   | AddrEncode    | Pop 20-byte value, push syna string |
| 0x55   | AddrDecode    | Pop syna/sync/synw string, push U256 |
| 0x56   | ContractAddr  | Pop deployer + nonce + artifact_hash, push sync string |

**HRPs:** `syna` = accounts, `sync` = contracts, `synw` = native wallet. `tsynq` is RETIRED and fails closed.

### 2.7 Linear Assets (0x57–0x5B)

| Opcode | Name          | Description |
|--------|---------------|-------------|
| 0x57   | AssetCreate   | Pop type_tag(I32) + value(U256), push asset_id. Owner = caller |
| 0x58   | AssetTransfer | Pop new_owner + asset_id, push new_asset_id. Old asset deactivated |
| 0x59   | AssetBurn     | Pop asset_id, push value. Asset marked inactive |
| 0x5A   | AssetBalance  | Pop asset_id, push value (0 if inactive) |
| 0x5B   | AssetOwner    | Pop asset_id, push owner (0 if inactive) |

**Linearity invariant:** Each asset ID can be consumed exactly once. Transfer deactivates the old ID and creates a new one. Burn deactivates and returns the value.

### 2.8 External Calls (0x60)

| Opcode | Name        | Description |
|--------|-------------|-------------|
| 0x60   | ExternCall  | Call function in another contract (workspace-scoped) |

### 2.9 PQC Operations (0x8F)

| Opcode | Name        | Description |
|--------|-------------|-------------|
| 0x8F   | AegisCall   | Unified PQC dispatch via AEG1 wire protocol (deterministic — ACTS-15) |
| 0x80–0x83 | (legacy) | Retained as aliases for backward compatibility |

See [AEG1 Wire Protocol](#5-aeg1-wire-protocol) below.

### 2.10 Tuples & Structs (0xA0–0xAB)

| Opcode | Name        | Description |
|--------|-------------|-------------|
| 0xA0   | TuplePack   | Pack N values into a Tuple |
| 0xA2   | TupleGet    | Pop tuple + index, push element |
| 0xA4   | OptionNone  | Push None option |
| 0xAB   | TupleSet    | Pop index + value + tuple, push new tuple with element replaced |

### 2.11 Debug & Terminal (0x9F, 0xF0, 0xFF)

| Opcode | Name        | Description |
|--------|-------------|-------------|
| 0x9F   | ToString    | Pop value, push string representation (used for runtime error messages) |
| 0xF0   | Print       | Pop value, emit to output |
| 0xFF   | Halt        | Stop execution |

---

## 3. AEG1 Wire Protocol

The AEG1 protocol provides a bounded, framed ABI for all VM-accessible PQC operations.

**Frame format:** `AEG1` magic (4B) + op (1B) + alg (1B) + argc (1B) + length-delimited args (u32_be per arg)

**Bounds:**
- Max total payload: 1 MiB
- Max arguments: 8
- Max per-argument size: 128 KiB
- Max response size: 128 KiB

**Operations:**

| Op | Description | Deterministic? |
|-----|-------------|---------------|
| 1   | ML-KEM decapsulate | ❌ No (secret key) — rejected by deterministic dispatch |
| 2   | ML-DSA verify | ✅ Yes (public inputs only) |
| 3   | FN-DSA verify | ✅ Yes (public inputs only) |

**Algorithm IDs:**

| ID   | Algorithm | NIST/FIPS Name |
|------|-----------|----------------|
| 0x01 | ML-KEM-512 | Kyber-512 |
| 0x02 | ML-KEM-768 | Kyber-768 |
| 0x03 | ML-KEM-1024 | Kyber-1024 |
| 0x10 | ML-DSA-44 | Dilithium-44 |
| 0x11 | ML-DSA-65 | Dilithium-65 |
| 0x12 | ML-DSA-87 | Dilithium-87 |
| 0x20 | FN-DSA-512 | Falcon-512 |
| 0x21 | FN-DSA-1024 | Falcon-1024 |

**NIST/FIPS naming alignment:** ML-KEM = Kyber, ML-DSA = Dilithium, FN-DSA = Falcon.

SPHINCS+, McEliece, and HQC are NOT part of the AEG1 protocol — they remain legacy direct-call only.

---

## 4. Bytecode Verification

### Layer 1 — Structural Integrity (Mandatory)

Validates bytecode format before execution. Hard gate: if Layer 1 fails, bytecode is rejected.

- Magic bytes: QVM\0
- Header fields within bounds
- All opcodes recognized
- Jump/call targets within code section
- No truncated instructions
- Data section within file boundary

### Layer 2 — Stack Safety (Advisory)

Symbolic stack depth analysis. Warnings surfaced but do not block execution.

- Tracks symbolic stack depth along all code paths
- Flags potential underflows
- Flags return stack depth mismatches
- Reports maximum stack depth

### Layer 3 — Manifest Signature (Planned)

ML-DSA-87 signature verification over manifest hash. Not yet implemented.

---

## 5. Runtime Constraints

| Constraint | Value |
|------------|-------|
| Step limit | Configurable (default: 100,000) |
| Memory cap | 1024 slots |
| CallFrame stack | 1024 frames |
| Session cap | 100 sessions per IP |
| Session TTL | 30 minutes |
| Rate limit | 200 req/min burst |
| Max body size | 2 MB |
| Max source size | 256 KB |
| Transactional atomicity | Full rollback on revert |

---

## 6. V3 Testnet Parameters

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
| Address HRP (accounts) | syna |
| Address HRP (contracts) | sync |
| Address HRP (native wallet) | synw |

**Signature domains:** SYNQ-DEPLOY-v3, SYNQ-CALL-v3, SYNQ-GOVERNANCE-v3, SYNQ-ATTEST-v3

**Governance scope hash:** SHA3-256(`SYNQ-GOVERNANCE-SCOPE-v1:` + scope_name)
**Authority scope hash:** SHA3-256(`SYNQ-AUTHORITY-SCOPE-v1:` + scope_name)

---

## 7. SSA IR

The compiler generates a typed Static Single Assignment (SSA) Intermediate Representation as the primary compilation path between the AST and the stack bytecode backend.

**Features:**
- Explicit control-flow graph (CFG) with basic blocks
- SSA value numbering (every variable assigned exactly once)
- Phi (φ) nodes at merge points (Cytron iterative dominance frontier)
- Typed values (IrType) for compile-time type checking
- Explicit effect operations (stores, emits)
- Authority check nodes (analyzable, not just opcode sequences)
- Linear-resource move tracking
- Host-function profile declarations

**Optimization passes:**
1. Phi insertion (Cytron IDF)
2. SSA validation
3. Dead code elimination
4. Constant folding
5. Copy propagation

**IR → bytecode lowering:**
- Slot-based SSA deconstruction
- Phi handling (store/load on predecessor edges)
- Block linearization (DFS)
- Jump patching
- Cross-block ValueId resolution for dominator-defined values

**IR dump format (shown in IDE):**
```
module ContractName {
  // State variables
  balance: u256 @ addr=0

  fn init() -> bool {
    block_0:{
      v0: u256 = Const(Number(0))
      1 = Store("balance", 0)
      v2: bool = Const(Bool(true))
      3 = Return(Some(2))
    }
  }
}
```

The IR dump includes the contract name header, state variable layout, struct/enum definitions, and full per-function block-by-block instruction listing with value IDs and types.

**IR analysis output (warnings):**
```
[IR] fn init: 1 blocks, 4 insts, 1 reachable, 1 effects, 0 host_profiles, 0 auth_checks, 0 linear_creates, 0 linear_consumes
[VERIFY] Layer 1 passed (structural) + Layer 2 passed (stack safety) | 20 instructions, 0 jumps, 0 calls, 60 bytes code
```

---

## 8. SQB Binary Artifact Format

The SQB format wraps QVM bytecode with ABI, manifest, IR, and metadata in a hash-bound envelope.

**Header (16 bytes):**
```
[0..4]   magic           b"SQB1"
[4]      version         1
[5]      flags           bit0=manifest, bit1=signature, bit2=ir_dump
[6..8]   section_count   u16 LE
[8..12]  chain_id        u32 LE (1266 for Testnet-v3)
[12..16] timestamp       u32 LE (Unix epoch)
```

**Sections (TLV):**
```
[0]      section_type    u8
[1..5]   data_length     u32 LE
[5..5+N] data            N bytes
[5+N..5+N+32] hash       SHA3-256(data)
```

**Artifact Root:** SHA3-256(hash_1 || hash_2 || ... || hash_N)

**Optional ML-DSA-87 signature** over the 32-byte artifact root.

**Bounds:** 4 MiB max file, 256 sections max, 1 MiB per section.

**Section types:** CODE (0x01), ABI (0x02), MANIFEST (0x03), IR (0x04), EFFECTS (0x05), STATE_LAYOUT (0x06), META (0x07).

All 11 ACTS-VM requirements addressed.

---

End of SynQ VM Spec v0.3
