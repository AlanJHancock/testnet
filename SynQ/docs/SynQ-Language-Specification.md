# SynQ Language Specification v0.2

---

## 1. Introduction

SynQ is a post-quantum smart contract language for the Synergy Network. It provides first-class support for NIST-standardized PQC algorithms (ML-KEM, ML-DSA, FN-DSA) through the AEG1 wire protocol, a declarative attribute system for function-level execution guards, linear asset tracking, named errors, and a typed SSA IR.

---

## 2. Data Types

### 2.1 Primitive Types

| Type | Description |
|------|-------------|
| `i32` | 32-bit signed integer |
| `u128` | 128-bit unsigned integer |
| `u256` | 256-bit unsigned integer |
| `bool` | Boolean |
| `bytes` | Variable-length byte array |
| `string` | UTF-8 string |

### 2.2 Type Aliases

| Alias | Underlying Type |
|-------|----------------|
| `Bytes<N>` | Fixed-size byte array of N bytes |
| `Hash32` | `Bytes<32>` |
| `Hash64` | `Bytes<64>` |
| `UMAIdentity` | `Bytes<32>` |
| `ModelId` | `Bytes<32>` |
| `Height` | `u256` |
| `Address` | `u256` (20-byte Bech32-decoded) |

### 2.3 Composite Types

| Type | Description |
|------|-------------|
| `struct` | Named field collection (e.g., `struct Point { x: u256; y: u256 }`) |
| `enum` | C-style or algebraic variants (e.g., `enum Color { Red, Green, Blue }`) |
| `Asset<T>` | Linear resource — create, transfer, burn |

### 2.4 NIST/FIPS PQC Naming

| SynQ Name | NIST/FIPS Name | Former Name |
|-----------|----------------|-------------|
| ML-KEM | ML-KEM | Kyber |
| ML-DSA | ML-DSA | Dilithium |
| FN-DSA | FN-DSA | Falcon |

---

## 3. Attribute System

SynQ supports declarative attributes for function-level execution guards and state modification metadata.

| Attribute | Description |
|-----------|-------------|
| `@public` | No authority required — callable by anyone |
| `@authority(Scope)` | Requires authority envelope matching scope hash |
| `@governance(Scope)` | Requires governance authorization for scope |
| `@effects(v1, v2, ...)` | Declares state variables modified |
| `@requires(expr)` | Precondition (compile-time documentation) |
| `@ensures(expr)` | Postcondition (compile-time documentation) |
| `@fails(ErrorType)` | Declares named error type for revert |
| `@bounded(n)` | Loop bound declaration |
| `@manifest` | Include in V3 manifest ABI |
| `@ai` | AI-optimized hint metadata |

**Scope hash computation:**
- Authority: SHA3-256(`SYNQ-AUTHORITY-SCOPE-v1:` + scope_name)
- Governance: SHA3-256(`SYNQ-GOVERNANCE-SCOPE-v1:` + scope_name)

**Backward compatibility:** Legacy `as caller` syntax is retained alongside the attribute-based model.

---

## 4. Built-in Functions

### 4.1 PQC Operations (AEG1)

```synq
aegis_call(op: u8, alg: u8, args: bytes[]) -> bytes[]
aegis_verify(alg: u8, msg: bytes, sig: bytes, pk: bytes) -> bool
aegis_decaps(alg: u8, ct: bytes, sk: bytes) -> bytes
```

### 4.2 Authority

```synq
authority_check(scope: string) -> bool    // @authority scope enforcement
caller() -> u256                          // Load caller address
```

### 4.3 Bech32 Addressing

```synq
to_syna(addr: u256) -> string             // Encode to syna format
from_syna(addr: string) -> u256           // Decode from syna/sync/synw
contract_address(deployer: u256, nonce: u256, artifact_hash: u256) -> string
```

### 4.4 Linear Assets

```synq
asset_create(type_name: string, value: u256) -> u256   // Returns asset_id
asset_transfer(asset_id: u256, to: u256) -> u256       // Returns new asset_id
asset_burn(asset_id: u256) -> u256                      // Returns burned value
asset_balance(asset_id: u256) -> u256
asset_owner(asset_id: u256) -> u256
```

### 4.5 State & Maps

```synq
map_set(slot, key, value)               // 32-byte big-endian keys
map_get(slot, key) -> value
```

---

## 5. Named Errors

SynQ supports structured named error reverts using enum variants:

```synq
contract Vault {
  enum VaultError { InsufficientBalance, Unauthorized, InvalidAmount, Overflow }

  function withdraw(amount: u256) -> bool {
    if (amount > balance) { revert VaultError::InsufficientBalance; }
    // ...
  }
}
```

**Bytecode:** `RevertCode` (0x35) emits error_code (enum variant index, 4B LE) + msg_len (4B LE) + message.

**Server response:** `error_code` (u32) and `error_name` (string) fields distinguish named errors from string-based `require()` failures.

**Syntax variants:**
- `revert VaultError::InsufficientBalance;` — qualified (compile-time checked)
- `revert InsufficientBalance;` — bare (searches all enum defs)

---

## 6. Struct Field Assignment

```synq
contract Example {
  state { origin: Point }
  struct Point { x: u256; y: u256 }

  @public
  function setOrigin(x: u256, y: u256) -> bool {
    origin.x = x;
    origin.y = y;
    return true;
  }
}
```

**Codegen:** `Push addr → Load → gen_expression(value) → Push field_idx → TupleSet → Push addr → Store`

---

## 7. EIP-712 Signing (V3)

All contract calls and source commits use EIP-712 typed data signing:

| Parameter | Value |
|-----------|-------|
| Chain ID | 1266 |
| Domain tag | SYNQ-CALL-v3 |
| Domain name | `SynQ · <Contract> · synergy-testnet-v3` |

**ContractCall struct:** `{ callSignature, sessionId, nonce, domainTag }`

---

## 8. Contract Templates

| Template | Description |
|----------|-------------|
| TokenVault | ERC-20-style vault with deposit/withdraw, controller-asset pattern |
| SimpleToken | Mint/burn token with transfer, self-transfer guard |
| LoopDemo | while/break/continue with overflow-safe sqrtFloor (binary search) |
| V3TypesDemo | Types, enums, attributes, authority builtins, Bech32 builtins |
| GovernanceDemo | @governance scope enforcement demonstration |
| AssetDemo | Linear asset create/transfer/burn demonstration |
| NamedErrorDemo | Named error reverts with enum variants |
| StructFieldTest | Struct field assignment (TupleSet opcode) |
| StructEnumDemo | Struct field access + enum variant comparison |

---

## 9. Compiler Pipeline

```
Source → Parser (pest grammar) → AST → IR Builder → SSA Module → Analyzer → Codegen → QVM Bytecode
```

**IR output:** Full SSA instruction dump available via `ir_dump` field in compile response, showing per-function block-by-block instructions with value IDs, types, and CFG predecessors.

---

End of SynQ Language Spec v0.2
