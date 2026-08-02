# SynQ Language Specification v0.3

---

## 1. Introduction

SynQ is a post-quantum smart contract language for the Synergy Network Testnet-v3. It provides first-class support for NIST-standardized PQC algorithms (ML-KEM, ML-DSA, FN-DSA) through the AEG1 wire protocol, a declarative attribute system for function-level execution guards, linear asset tracking, named errors, structs and enums, and a typed SSA IR as the primary compilation path.

---

## 2. Data Types

### 2.1 Primitive Types

| Type | Description |
|------|-------------|
| `i32` | 32-bit signed integer |
| `u128` | 128-bit unsigned integer |
| `u256` | 256-bit unsigned integer (full-width, no truncation) |
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
| `struct` | Named field collection with field access and assignment |
| `enum` | C-style or algebraic variants with payloads |
| `Asset<T>` | Linear resource — create, transfer, burn |
| `Tuple` | Heterogeneous collection (structs and enum payloads compile to tuples) |

### 2.4 NIST/FIPS PQC Naming

| SynQ Name | NIST/FIPS Name | Former Name |
|-----------|----------------|-------------|
| ML-KEM | ML-KEM | Kyber |
| ML-DSA | ML-DSA | Dilithium |
| FN-DSA | FN-DSA | Falcon |

---

## 3. Attribute System

SynQ supports declarative attributes for function-level execution guards and state modification metadata.

| Attribute | Description | Enforcement |
|-----------|-------------|-------------|
| `@public` | No authority required — callable by anyone | Compile-time + runtime |
| `@authority(Scope)` | Requires authority envelope matching scope hash | Compile-time + runtime |
| `@governance(Scope)` | Requires governance authorization for scope | Compile-time + runtime |
| `@effects(v1, v2, ...)` | Declares state variables modified | Compile-time documentation |
| `@requires(expr)` | Precondition | Compile-time documentation |
| `@ensures(expr)` | Postcondition | Compile-time documentation |
| `@fails(ErrorType)` | Declares named error type for revert | Compile-time + runtime |
| `@bounded(n)` | Loop bound declaration | Compile-time documentation |
| `@manifest` | Include in V3 manifest ABI | Compile-time |
| `@ai` | AI-optimized hint metadata | Reserved (future) |

**Scope hash computation:**
- Authority: SHA3-256(`SYNQ-AUTHORITY-SCOPE-v1:` + scope_name)
- Governance: SHA3-256(`SYNQ-GOVERNANCE-SCOPE-v1:` + scope_name)

**Backward compatibility:** Legacy `as caller` syntax is retained alongside the attribute-based model. Both `-> T as caller` and `as caller -> T` orderings are supported.

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

**Dynamic reverts:** `RevertCodeDyn` (0x36) supports runtime argument evaluation:
```synq
revert VaultError::InsufficientBalance(balance);
```
The runtime value (e.g., current balance) is evaluated and included in the error message via ToString (0x9F).

**Server response:** `error_code` (u32) and `error_name` (string) fields distinguish named errors from string-based `require()` failures.

**Syntax variants:**
- `revert VaultError::InsufficientBalance;` — qualified (compile-time checked)
- `revert InsufficientBalance;` — bare (searches all enum defs)
- `revert VaultError::InsufficientBalance(arg);` — qualified with runtime arg

---

## 6. Structs and Enums

### 6.1 Struct Definition and Field Access

```synq
struct Point { x: u256; y: u256 }

contract Example {
  state { origin: Point }

  @public
  function setOrigin(x: u256, y: u256) -> bool {
    origin.x = x;
    origin.y = y;
    return true;
  }
}
```

**Codegen:** `Push addr → Load → gen_expression(value) → Push field_idx → TupleSet → Push addr → Store`

### 6.2 Enums (C-style and Algebraic)

```synq
enum Color { Red, Green, Blue }                    // C-style
enum Result { Ok(u256), Err(string) }              // Algebraic with payload
```

Enum variants are resolved to sequential integer tags. Algebraic variants carry payloads compiled as Tuple values.

---

## 7. EIP-712 Signing (V3)

All contract calls and source commits use EIP-712 typed data signing:

| Parameter | Value |
|-----------|-------|
| Chain ID | 1266 |
| Domain tag | SYNQ-CALL-v3 |
| Domain name | `SynQ · <Contract> · synergy-testnet-v3` |

**ContractCall struct:** `{ callSignature, sessionId, nonce, domainTag }`

The domain tag is embedded in the AuthorityEnvelope reserved field (bytes 88–104).

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
| StackFailDemo | Educational contract demonstrating verification layers |

---

## 9. Compiler Pipeline

### 9.1 Primary Path: SSA IR Backend

```
Source → Parser (pest grammar) → AST → Semantic Analysis → IR Builder → SSA Module
    → Optimization Passes (phi insertion, DCE, constant folding, copy propagation)
    → IR Analysis → Lowering to QVM Bytecode → Verification (L1 + L2)
    → Compiler Attestation (ML-DSA-87)
```

The `compile_ir()` function is the entry point. On IR failure, it automatically falls back to direct codegen.

### 9.2 Fallback Path: Direct Codegen

```
Source → Parser → AST → Semantic Analysis → CodeGenerator::generate() → QVM Bytecode
```

### 9.3 Determinism

- State variables sorted by address before IR construction
- Dispatch tables sorted alphabetically by function name
- Strict UTF-8 validation on all identifiers
- No HashMap iteration in code generation paths

---

## 10. Compilation Response

The `/compile` endpoint returns:

| Field | Description |
|-------|-------------|
| `success` | Boolean |
| `bytecode` | Hex-encoded QVM bytecode |
| `contract_name` | Extracted contract name |
| `state_vars` | Array of [name, address] pairs |
| `functions` | Array of function names |
| `abi` | Function signatures and parameter types |
| `manifest` | V3 manifest (ML-DSA-87 signed) |
| `ir_dump` | Full SSA IR instruction listing |
| `warnings` | IR analysis + verification results |
| `verification` | Layer 1 + Layer 2 results, instruction count, code size |
| `signature_sidecar` | ML-DSA-87 compiler attestation |

---

End of SynQ Language Spec v0.3
