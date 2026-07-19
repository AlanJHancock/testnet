# SynQ Authority and Attestation Specification
---

This document outlines the security architecture, compile-time controls, and runtime authorization models implemented in the SynQ smart contract toolchain. The SynQ framework is built for the Synergy Network, a quantum-safe Layer 1 blockchain, with a focus on mitigating classical vector attacks while integrating post-quantum cryptography (PQC) attestation directly into the developer workflow.

## 1. Design Philosophy
---

Synergy smart contracts reject the paradigm of implicit authority. In traditional environments, any contract function can be invoked by any caller, shifting the burden of access control entirely to runtime conditional logic written by the developer (e.g., `require(msg.sender == owner)`). SynQ turns this on its head: any function that modifies state or reads privileged parameters must explicitly declare its access criteria and the capabilities required to run. This rule is absolute, enforced directly at the virtual machine instruction level. The governing principle is: **No authority without declaration.**

This model integrates directly with the Universal Member Authority (UMA) substrate of the Synergy Network. UMA decouples identity continuity from specific cryptographic key material, allowing member accounts to rotate physical keys without losing identity state. In SynQ, the `caller` keyword represents this abstract identity. Because identity lookup is highly critical, using the `caller` builtin inside any function that has not been explicitly marked with the `as caller` clause results in a compile-time error. This prevents developers from accidentally referencing caller metadata without invoking the appropriate security qualifiers.

## 2. Identity Binding: `as caller`
---

When a function is defined with the `as caller` clause, the SynQ compiler injects a specialized authentication prologue at the start of the function's bytecode. This clause is represented in the grammar (`synq.pest`) as part of the function definition rule, parsed into the Abstract Syntax Tree (AST) as a boolean attribute on the `FunctionDef` node.

During the codegen phase (`codegen.rs`), if `as_caller` is true, the compiler emits the following instruction sequence:

```assembly
LoadCaller            ; Push the authenticated EVM caller address to stack as U256
LoadImm256(UMA_ANON)  ; Push the UMA anonymous sentinel value to stack
Eq                    ; Check if caller == UMA_ANON
JumpIf(revert_target) ; Revert the call if the comparison returns true
```

The `UMA_ANON` sentinel is not a raw zero address. Instead, it is a domain-separated cryptographic hash defined as:

$$\text{UMA\_ANON} = \text{keccak256}(\text{"UMA:"} \mathbin{\Vert} 0x0000\dots0000)[0\dots32]$$

This ensures that the sentinel cannot be coincidentally or maliciously produced by a legitimate wallet address. When an unauthenticated transaction is dispatched to the VM, the runtime populates the caller register with `UMA_ANON`. The injected prologue intercepts this sentinel immediately and reverts execution before any state modifications can occur.

## 3. Capabilities: `requires cap::NAME`
---

In addition to identity binding, SynQ supports declarative capability guards using the `requires cap::NAME` clause. Multiple capability requirements can be defined on a single function, where they are parsed as a vector of strings on the AST node.

Currently, capability verification is enforced server-side. When a transaction is submitted to the `/session/run` endpoint, the server inspects the EIP-712 payload. This signed payload contains a list of capabilities that the caller is authorized to exercise. The server verifies that the caller's signature covers the exact capabilities requested by the target function. If the capability name in the bytecode does not match the signed list in the transaction envelope, the server rejects execution. 

Future iterations of the SynQ VM will transition this check to the bytecode layer, emitting dedicated capability validation opcodes that query an on-chain capability registry.

## 4. ExternCall (0x60) and Cross-Contract Authority
---

SynQ implements explicit caller propagation for cross-contract interactions. When contract A makes an `extern_call("ContractB", "functionName", args...)` (compiled to opcode 0x60), the authenticated caller context of contract A is forwarded to contract B.

For example:
- Wallet `0xAlice` calls `TokenVault.deposit()`.
- `TokenVault.deposit()` processes the deposit and internally invokes `SimpleToken.mint()` using `extern_call`.
- Within the execution of `SimpleToken.mint()`, the `LoadCaller` instruction returns `0xAlice`, not the contract address of `TokenVault`.

This is standard call semantics, analogous to the EVM `CALL` execution model rather than `DELEGATECALL`. The security implication of this choice is significant: `SimpleToken.mint()` must declare its authority as `as caller requires cap::Minter` and rely on the fact that `TokenVault` has validated `0xAlice` before dispatching the mint request.

A future `delegatecall` instruction (opcode 0x61) is planned to support executing remote code within the storage context of the calling contract. However, because this requires strict storage layout alignment and introduces reentrancy risks, it remains deferred until the SynQ capability registry is fully production-hardened. It will strictly require the explicit `cap::DelegateExec` capability.

## 5. Source Attestation (SynQSourceCommitV1)
---

To guarantee that the deployed bytecode matches the audited source code, SynQ mandates a multi-step cryptographic source attestation chain. This process binds the compiler, the developer's EVM key, and the resulting post-quantum signature payload.

```
[Client]                                              [Server]
   │                                                     │
   │─── 1. Hash Source ─────────────────────────────────>│
   │                                                     │
   │<── 2. Return Source Nonce (KMAC128) ────────────────│
   │                                                     │
   │─── 3. Sign EIP-712 SourceCommit ───────────────────>│
   │                                                     │
   │─── 4. POST /compile/sign-source ───────────────────>│
   │       (Source, Signature, Nonce)                    │
   │                                                     │
   │                                   [Verify Nonce]    │
   │                                   [Compile & Hash]  │
   │                                   [ecrecover Signer]│
   │                                   [Sign ML-DSA-65]  │
   │                                                     │
   │<── 5. Return CompileResult + SourceCommit Sidecar ──│
```

### The Source Attestation Chain

1. **Hashing:** The client computes the source identifier: `source_hash = keccak256(source_bytes)`.
2. **Nonce Request:** The client sends the hash to `POST /source-nonce`. The server returns a stateless nonce computed as:
   $$\text{nonce} = \text{KMAC128}(\text{server\_key}, \text{source\_hash\_hex} \mathbin{\Vert} \text{10s\_bucket}, 32, \text{"SynQSourceNonce"})$$
   This nonce is valid for 120 seconds (12 temporal buckets) and is cryptographically bound to the source hash. Any attempt to compile different source code using this nonce will fail verification.
3. **EIP-712 Signing:** The client signs a standard `SourceCommit` payload:
   - **Domain Separator:** `{ name: "SynQ · <ContractName>", version: "1", chainId: 1337, verifyingContract: keccak256("SynQ:" + name)[12..] }`
   - **Struct:** `SourceCommit { string sourceHash, string contractName, string nonce }`
4. **Verification & Compilation:** The client submits the payload to `/compile/sign-source`. The server:
   - Recomputes the KMAC128 nonce using the current and previous temporal buckets to verify validity.
   - Compiles the source code and generates the compiled bytecode hash.
   - Recovers the signer's address via `ecrecover`. If `recovered_address != claimed_address`, the request is rejected. High-s signature normalization is applied to support diverse wallet implementations.
   - Issues a post-quantum `SynQSourceCommitV1` payload.

### The Canonical `SynQSourceCommitV1` Payload Structure

```
+---------------------------+----------------------------------------------+
| Field Name                | Size / Format                                |
+---------------------------+----------------------------------------------+
| Magic Bytes & Null        | 19 bytes (b"SynQSourceCommitV1\x00")         |
| Source Hash               | 32 bytes (keccak256 of source text)          |
| Bytecode Hash             | 32 bytes (keccak256 of compiled bytecode)    |
| Author                    | 20 bytes (ecrecovered EVM address)           |
| Issued At                 | 8 bytes (u64 LE Unix epoch timestamp)        |
| Contract Name Length      | 4 bytes (u32 LE)                             |
| Contract Name             | Variable length UTF-8 string                 |
+---------------------------+----------------------------------------------+
```

This canonical payload is signed using the server's persistent ML-DSA-65 compiler key (Key ID: `e50d8f193e91e1d9`). The signature and payload are returned to the client inside the `signature_sidecar` response block, establishing an unbroken chain of custody from local source code to compiled on-chain artifact.

## 6. Tamper Detection: WASM Extern-Contracts Parity
---

To protect developers against malicious local environments (such as compromised browser extensions, local proxy manipulation, or developer-tool memory injection), the compiler implements a strict double-pass verification system.

When compiling in-browser, the client-side WASM compiler parses the AST and returns a sorted, deduplicated list of dependency contracts called `extern_contracts`. This is submitted alongside the compile request as `wasm_extern_contracts`.

Upon receipt, the server independently parses the raw source code and performs a server-side AST walk to generate its own list of external contract dependencies. The server sorts both lists and compares them. If there is any mismatch, the compilation is immediately aborted:

```
Tamper detected: WASM extern_contracts [...] does not match server AST [...]
```

This dual-layer verification ensures that dependency metadata cannot be secretly altered in transit or injected into the browser runtime prior to deployment.

## 7. Defence in Depth Summary
---

The table below outlines the specific attack vectors mitigated by the SynQ toolchain, indicating the responsible mitigation layer and where the rules are enforced:

| Attack Vector | Mitigation Layer | Enforced At |
| :--- | :--- | :--- |
| Unprivileged function invocation | `as caller` prologue insertion | VM (Bytecode Execution) |
| Identity / Key impersonation | `ecrecover` verification | Compiler Server (`/compile/sign-source`) |
| Source code substitution | Nonce bound directly to `source_hash` | Compiler Server (`/source-nonce`) |
| In-browser AST / Metadata injection | `extern_contracts` double-pass parity | Compiler Server (`/compile`) |
| Signature replay attacks | 120s temporal window + single-use tracking | Compiler Server (Database/Session State) |
| Unauthorized capability usage | EIP-712 capability list verification | Runtime Dispatcher (`/session/run`) |
| Cross-contract context hijacking | Explicit caller propagation | VM (Opcode 0x60 Execution) |
