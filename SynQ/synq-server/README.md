# synq-server

HTTP compile and execution server for the SynQ toolchain.

**Testnet endpoint:** `https://hanksweb.co.uk/synq/`  
**Demo IDE:** `https://hanksweb.co.uk/demo/`

---

## Architecture

`synq-server` is an Axum-based HTTP server embedding the SynQ compiler and QuantumVM. Each deployed contract gets a persistent session with its own VM instance and isolated memory. Cross-contract calls are routed through workspace-scoped handler closures — no shared memory, call semantics only.

```
Browser / CLI
     │
     ▼
nginx (:443)  ─── /synq/* ──►  synq-server (:3030)
                                    │
                               ┌────┴─────┐
                               │ Compiler │  (AST → bytecode, ML-DSA-65 sidecar)
                               │ Sessions │  (QuantumVM instances, EIP-712 auth)
                               │ Workspaces│ (multi-contract routing)
                               └──────────┘
```

---

## Security Properties

| Property | Detail |
|---|---|
| Session IDs | 32-byte OS entropy, 64-char hex — unguessable |
| Session cap | 100 sessions, LRU eviction, 30-min TTL |
| Workspace cap | 50 workspaces, LRU eviction |
| Body limit | 128 KB per request |
| Source limit | 64 KB SynQ source per compile call |
| VM step limit | 1,000,000 instructions per run |
| Rate limit | Burst 10, 30 req/min per IP (tower-governor) |
| Hex decoding | Strict — rejects odd-length, invalid chars, empty |
| Auth | EIP-712 typed-data; high-s secp256k1 normalisation |
| Tamper detection | WASM extern_contracts parity check on every compile |
| Source attestation | KMAC128 nonce + EIP-712 SourceCommit + ML-DSA-65 PQC commit |

---

## API Reference

### `GET /health/ready`

Dependency-aware readiness check.

```json
{ "ready": true, "reason": "ok", "active_sessions": 2, "max_sessions": 100 }
```

---

### `POST /compile`

Compile SynQ source. Optionally include `wasm_extern_contracts` for tamper-detection.

**Request:**
```json
{
  "source": "pragma synq ^0.9;\ncontract Token { ... }",
  "wasm_extern_contracts": ["SimpleToken"]
}
```

**Response:**
```json
{
  "success": true,
  "bytecode": "0x4d5651...",
  "contract_name": "Token",
  "extern_contracts": ["SimpleToken"],
  "state_vars": [{ "name": "total", "slot": 0, "type": "UInt256" }],
  "signature_sidecar": {
    "algorithm": "ML-DSA-65",
    "key_id": "e50d8f193e91e1d9",
    "bytecode_hash": "0x...",
    "signature": "0x..."
  },
  "errors": [],
  "warnings": []
}
```

If `wasm_extern_contracts` is present and does not match the server's independent AST analysis, the response is:
```json
{ "success": false, "errors": ["Tamper detected: WASM extern_contracts [\"X\"] does not match server AST [\"Y\"]"] }
```

---

### `POST /source-nonce`

Fetch a KMAC128 nonce bound to a source hash. Required before `/compile/sign-source`.

**Request:**
```json
{ "source_hash": "<64-char lowercase hex, no 0x>" }
```

**Response:**
```json
{ "nonce": "<64-char hex>", "expires_in": 110 }
```

Nonces are stateless — derived from `KMAC128(server_key, source_hash_hex || 10s_bucket, 32, "SynQSourceNonce")`. Valid for 120 seconds (12 × 10s buckets). A nonce issued for source hash A will not validate a request posting source hash B.

---

### `POST /compile/sign-source`

Compile SynQ source with EIP-712 wallet attestation. Binds the developer's EVM identity to the exact source text.

**Flow:**
1. Compute `source_hash = keccak256(source_bytes)` locally
2. Fetch nonce from `POST /source-nonce`
3. Sign EIP-712 `SourceCommit` struct with your wallet
4. POST here

**EIP-712 Domain:**
```json
{
  "name": "SynQ · <ContractName>",
  "version": "1",
  "chainId": 1337,
  "verifyingContract": "<keccak256('SynQ:' + ContractName)[12..]>"
}
```

**EIP-712 Type:**
```
SourceCommit(string sourceHash, string contractName, string nonce)
```

**Request:**
```json
{
  "source": "pragma synq ^0.9;\n...",
  "evm_address": "0x<40 hex>",
  "evm_signature": "0x<130 hex — 65 bytes r||s||v>",
  "nonce": "<64-char hex from /source-nonce>"
}
```

**Response:** Same as `/compile`, with `signature_sidecar.source_commit` added:
```json
{
  "source_commit": {
    "author": "0x<wallet address>",
    "source_hash": "0x<32 bytes>",
    "bytecode_hash": "0x<32 bytes>",
    "issued_at": 1753056000,
    "pqc_signature": "0x<ML-DSA-65 signature over SynQSourceCommitV1 payload>"
  }
}
```

**Error cases:**
- `"nonce invalid or expired"` — nonce HMAC does not match, or source hash mismatch (tampered source)
- `"recovered 0x... != claimed 0x..."` — wrong wallet or wrong key used to sign
- `"ecrecover failed"` — malformed signature

---

### `POST /session/new`

Create a new VM session for a compiled contract.

**Request:**
```json
{
  "bytecode": "0x4d5651...",
  "state_vars": [{ "name": "total", "slot": 0, "type": "UInt256" }],
  "contract_name": "SimpleToken",
  "workspace_id": "<optional — auto-registers into workspace>"
}
```

**Response:**
```json
{ "success": true, "session_id": "<64-char hex>", "contract_name": "SimpleToken" }
```

---

### `POST /session/run`

Execute a function on an existing session.

**Request:**
```json
{
  "session_id": "<64-char hex>",
  "function": "deposit",
  "args": [100],
  "evm_address":   "0x<wallet>",
  "evm_signature": "0x<65B EIP-712 ContractCall sig>",
  "call_nonce":    "<server-issued nonce from GET /session/:id/nonce>"
}
```

`evm_address`, `evm_signature`, and `call_nonce` are required together for `as caller` functions. Omitting any one of the three will cause the server to pass no caller identity — the VM's `LoadCaller` pushes UMA_ANON and the authentication prologue reverts.

**Response:**
```json
{
  "success": true,
  "result": { "type": "UInt256", "value": "100" },
  "output": "Return value: 100 (UInt256)",
  "error": null
}
```

---

### `GET /session/:id/nonce`

Issue a one-time call nonce for EIP-712 ContractCall signing.

---

### `DELETE /session/:id`

Terminate a session and release its VM memory.

---

### `GET /session/:id/state`

Return the current memory slot values for a session.

---

### `POST /workspace/new`

Create a new multi-contract workspace.

**Response:** `{ "success": true, "workspace_id": "<64-char hex>" }`

---

### `GET /workspace/:id`

List contracts registered in the workspace, in deployment order.

**Response:**
```json
{
  "success": true,
  "workspace_id": "...",
  "contracts": [
    { "name": "SimpleToken", "session_id": "...", "deploy_index": 0 },
    { "name": "TokenVault",  "session_id": "...", "deploy_index": 1 }
  ]
}
```

---

### `POST /workspace/:id/join`

Register an existing session into a workspace (explicit join).

**Request:** `{ "session_id": "<64-char hex>", "contract_name": "MyContract" }`

---

### `POST /workspace/:id/remove`

Remove a contract from the workspace (does not delete the session).

**Request:** `{ "session_id": "<64-char hex>", "contract_name": "MyContract" }`

---

### `DELETE /workspace/:id`

Delete workspace and terminate all member sessions.

---

### `POST /attest`

Verify an EIP-712 bytecode attestation signature and confirm it was signed by a given wallet.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SYNQ_CORS_ORIGIN` | `*` | CORS allowed origin |
| `SYNQ_PQC_PRIVATE_KEY` | — | Base64-encoded ML-DSA-65 private key (overrides `/etc/synq/compiler.key`) |
| `SYNQ_SOURCE_NONCE_SECRET` | derived from compiler key | 64-char hex KMAC128 key for source nonce derivation |
| `RUST_LOG` | `info` | Log level |

---

## EIP-712 Domain Reference

| Context | `name` | `verifyingContract` |
|---|---|---|
| ContractCall (`/session/run`) | `"SynQ · <ContractName>"` | `keccak256("SynQ:" + name)[12..]` |
| SourceCommit (`/compile/sign-source`) | `"SynQ · <ContractName>"` | `keccak256("SynQ:" + name)[12..]` |
| BytecodeAttestation (`/attest`) | `"SynQ · <ContractName>"` | `keccak256("SynQ:" + name)[12..]` |

All domains: `chainId: 1337` (Synergy devnet sentinel).

---

## Deployment

```bash
# Build
cd /opt/synergy-testnet/SynQ
cargo build --release -p synq-server

# Deploy (copy to systemd ExecStart path)
cp target/release/synq-server /opt/synergy-testnet/SynQ/target/release/synq-server

# Restart
systemctl restart synq-server
systemctl status synq-server
```

The systemd unit's `ExecStart` points to `/opt/synergy-testnet/SynQ/target/release/synq-server`. Always rebuild from this directory — never from `/root`.

---

## Compiler Key

The server generates a persistent ML-DSA-65 key on first startup, stored at `/etc/synq/compiler.key` (mode 600). The key fingerprint is derived as the first 8 bytes of `SHA3-256(public_key)`.

Current testnet `key_id`: `e50d8f193e91e1d9`

> Production: migrate to an HSM-backed key to eliminate the software key extraction risk. The `SynQSourceCommitV1` payload format supports key rotation — the `key_id` field identifies which key signed each commit.
