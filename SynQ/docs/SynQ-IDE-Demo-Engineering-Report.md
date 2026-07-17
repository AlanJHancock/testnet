# SynQ IDE Demo — Frontend Engineering Report

**Date:** 17 July 2026
**Author:** Alan Hancock
**Audience:** CTO / Project Stakeholders
**Live demo:** https://hanksweb.co.uk/demo/
**Backend:** https://hanksweb.co.uk/synq/health

---

## 1. Executive Summary

This report details the frontend engineering work completed on the SynQ Smart Contract IDE demo — a static, self-contained HTML developer tool integrated with a live Axum backend. The implementation delivers a fully functional playground that compiles quantum-safe smart contracts written in SynQ syntax, executes them within a persistent virtual machine (QVM) session, and supports real-time state tracking and secure, wallet-signed authenticated transactions. By resolving critical compiler validation bugs, standardising cryptographic signature payloads, and refining VM execution feedback, we have established a production-grade developer experience that showcases the core capabilities of the post-quantum cryptography (PQC) toolchain end-to-end.

---

## 2. Objectives

- **Zero-setup environment:** Write, compile, and run contracts immediately in the browser — no local Rust toolchain required.
- **Hybrid and post-quantum security:** Visualise the co-existence of ML-DSA-65 compiler-level signatures with classic EVM wallet authentication (secp256k1).
- **Robust VM interaction:** Stateful, interactive execution with real-time feedback, accurate contract state representation, and precise error diagnostics.

---

## 3. Work Completed

### Validation & Input Handling

- **Regex engine isolation:** Resolved a critical bug where stateful global regular expressions (`/g` flag) leaked `lastIndex` state across separate validation cycles. Legacy validation rules (`packageDeclaration`, `hasMetadata`, `balancedBraces`) were replaced with explicit nulls to prevent false-positive blocks on valid SynQ code.
- **Type enforcement:** Arg validation tightened from `/^-?\d+$/` to `/^\d+$/` — SynQ has only unsigned types, so negatives are now rejected client-side before the wallet layer is ever reached.
- **UI resilience:** Fixed a fatal `var out` scoping bug — `out` was declared *after* the `if (argError)` block that used it, causing a silent `TypeError` that permanently locked the Run button in spinner state on any validation failure. Added instantaneous border-colour feedback on invalid inputs and pre-flight semantic validation for `setPaused` (values other than `0` or `1` rejected locally — no wallet popup triggered).

### Compilation Results & Status Display

- Panel order fixed: *Compilation Results → Status Line → Test Results → Deployment Results*
- Status line made exclusive to compilation outcomes
- `getCode` ref exposed via `useImperativeHandle` so all exports target the live editor state
- Compiled output downloads with `.qvm` extension; bundle filename anchors re-derived after every redeploy (Synq-*.js filenames are content-hash-based)

### Authenticated Call Flow (EIP-191)

- Integrated MetaMask and Coinbase Wallet with live `eth_accounts` validation on every Run click
- Standardised challenge-response loop:
  1. `GET /session/:id/nonce` — server issues a one-time challenge per session
  2. `personal_sign` with payload `SynQCall:<sessionId>:<functionName>:<nonce>`
  3. `POST /session/run` with `evm_address`, `evm_signature`, `call_nonce`
- Caller-verified badge shown on successful authenticated calls (green monospace, shows wallet address)
- Nonce is server-invalidated on use — replay attacks not possible

### VM State & Error Diagnostics

- Live state panel queries `/session/:id/state` after every execution
- `owner` decoded from UInt256 decimal → 0x-prefixed 40-char hex via browser-native `BigInt`
- `paused` and `initialised` displayed as human-readable Yes/No
- Overflow/underflow errors annotated with boundary context (2²⁵⁶−1) and actionable next-step hints

### Attestation Panel

- Differentiates *Compiler-Attested* (no wallet) from *Hybrid* (compiler + wallet signature) modes
- Compiler fingerprint: `0xA05010EE9A56331287D84F7D98A012D1F851D37A`, Key ID: `e50d8f193e91e1d9`
- All cryptographic hex output normalised consistently; SHA3 routed through `window.keccak_256`
- EIP-191 bytecode hash computed server-side to prevent client-side hash manipulation

---

## 4. Key Technical Challenges Solved

### Coinbase Wallet High-S Signature Rejection

The Rust `k256` crate strictly enforces canonical low-S secp256k1 signatures. Coinbase Wallet frequently outputs high-S values, which caused `ecrecover` to return a wrong address — silently, with no error. Resolution: server-side normalisation before `ecrecover` (`s_canonical = n − s`), establishing parity across all browser wallets.

### Run-Button Deadlock on Bad Input

A `var out` hoisting error meant any `argError` path hit a silent `TypeError` before the button's loading state could reset. The spinner locked permanently until page reload. Fix: declaration moved to top of the execution block so it is always in scope.

### EIP-191 Prefix Reconstruction Mismatch

Authenticated calls initially failed server-side verification despite valid client signatures. The server was not correctly reconstructing the `\x19Ethereum Signed Message:\n<len>` prefix over the raw ASCII payload. Fixed by aligning server-side reconstruction with the exact bytes `personal_sign` produces.

### Smart-Quote Encoding in Source HTML

One validation regex replacement silently failed because the deployed HTML contained Unicode curly quotes (`"` / `"`) rather than straight ASCII quotes — invisible to normal string comparison. Resolved by operating on raw bytes rather than decoded strings.

### Pre-Flight Validation Before Wallet Interaction

Asking a user to approve a `personal_sign` request for a transaction we already know will revert is poor UX and erodes trust. Two layers of pre-flight were added: (1) the arg digit regex now rejects negatives entirely; (2) `setPaused` validates flag range (0 or 1) locally before the nonce fetch and wallet popup fire. This pattern mirrors best practice in production EVM dapps.

---

## 5. Current State

The IDE is fully live at [hanksweb.co.uk/demo](https://hanksweb.co.uk/demo/). The complete user loop works end-to-end:

```
[ Load Demo Contract ] ──> [ Compile ] ──> [ Connect Wallet ]
                                                    │
                                                    ▼
[ Read Live State Panel ] <── [ Run Function ] <── [ Sign Nonce ]
```

All functions in the default `SimpleToken` template (`init`, `mint`, `burn`, `getTotal`, `setPaused`, `getPaused`) compile and execute correctly, with owner-guard enforcement via the `caller` builtin (opcode `0x50`) and live state reflection after every call. MetaMask and Coinbase Wallet are both tested and working.

---

## 6. Strategic Value Demonstrated

1. **PQC signature sidecars live in production** — compiled bytecode is signed with ML-DSA-65 in real time via the persistent compiler key (`/etc/synq/compiler.key`), with no perceptible latency overhead.
2. **EVM wallets control quantum-safe VMs** — proves the hybrid security model: classic wallet identity (secp256k1) authenticates execution of post-quantum contracts via EIP-191 off-chain signing. This is the same pattern that maps onto SXCP relayer attestation.
3. **`caller` semantics implemented** — contracts can enforce owner-only access control using `require(caller == owner, "...")`, a prerequisite for production-grade SynQ contracts and a direct analogue of Solidity's `msg.sender`.
4. **Developer mindshare** — external developers, auditors, and partners can experiment with the SynQ ecosystem immediately, in-browser, with zero setup.

---

## 7. Future Work

| Item | Notes |
|---|---|
| In-browser WASM compilation | Move compile step client-side; eliminate server dependency for offline use |
| Multi-contract sessions | Expand QVM session manager to support interacting contracts |
| EIP-712 structured signing | Replace flat EIP-191 strings with typed structured data for cleaner wallet approval prompts |
| `msg.value` / gas model | Expose fee/gas semantics in the IDE once the VM gas model is finalised |
| Shareable session URLs | Allow users to share a contract + session state via URL fragment |
