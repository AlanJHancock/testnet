# SynQ V3 — API Reference

**Base URL:** https://hanksweb.co.uk/synq  
**Server:** synq-server (Axum), port 3030  
**Rate limit:** 200 req/min burst, 200 req/min sustained  
**Session cap:** 100 per IP  
**Session TTL:** 30 minutes  
**Max body:** 2 MB  
**Max source:** 256 KB

---

## Compilation

### POST /compile

Compiles SynQ source code into QVM bytecode. Primary path: SSA IR backend. Fallback: direct codegen.

**Request:**
```json
{
  "source": "pragma synq ^0.9; contract Test { ... }",
  "options": {
    "optimization_level": 1
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| source | string | Yes | SynQ source code (max 256 KB) |
| options.optimization_level | u8 | No | 0 = none, 1 = default |

**Response (200):**
```json
{
  "success": true,
  "bytecode": "0x004d5651010f00...",
  "contract_name": "Test",
  "state_vars": [["value", 0]],
  "functions": ["init", "get"],
  "abi": { ... },
  "manifest": {
    "contract_name": "Test",
    "required_signature_algorithm": "ML-DSA-87",
    "manifest_hash": "...",
    "manifest_signature": "...",
    "governance_scopes": []
  },
  "ir_dump": "module Test { ... }",
  "warnings": [
    "[IR] fn init: 1 blocks, 4 insts, ...",
    "[VERIFY] Layer 1 passed (structural) + Layer 2 passed (stack safety) | ..."
  ],
  "verification": {
    "layer1": "passed",
    "layer2": "passed",
    "instruction_count": 20,
    "code_size_bytes": 60
  },
  "signature_sidecar": {
    "algorithm": "ML-DSA-87",
    "mode": "persistent",
    "public_key": "...",
    "signature": "...",
    "security_level": "Enhanced"
  }
}
```

**Error response (400):**
```json
{
  "success": false,
  "error": "Parse error at line 3: unexpected token '}'",
  "error_code": null,
  "error_name": null
}
```

**Runtime error response (200 with revert):**
```json
{
  "success": true,
  "reverted": true,
  "error": "InsufficientBalance",
  "error_code": 0,
  "error_name": "VaultError::InsufficientBalance"
}
```

---

### POST /compile-wasm

Compiles SynQ source using the WASM compiler build (for browser-side compilation without server round-trip).

**Request:** Same as `/compile`.

**Response:** Same as `/compile`.

---

### POST /compile/sign-source

Two-phase source commit: client first calls `/source-nonce`, then calls this endpoint with the signed nonce.

**Request:**
```json
{
  "source": "pragma synq ^0.9; ...",
  "source_hash": "0x...",
  "signature": "0x...",
  "signer": "0x..."
}
```

**Response:** Same as `/compile` plus `source_commit_hash` field.

---

### POST /source-nonce

Gets a nonce for source commit signing.

**Request:**
```json
{
  "source_hash": "0x..."
}
```

**Response:**
```json
{
  "nonce": "0x...",
  "session_id": "..."
}
```

---

## Sessions

### POST /session/new

Loads compiled bytecode into a fresh persistent VM session.

**Request:**
```json
{
  "bytecode": "0x004d5651...",
  "caller": "syna1...",
  "auth_envelope": "0x..."
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| bytecode | string (hex) | Yes | QVM bytecode with 0x prefix |
| caller | string | No | Caller address (syna format) |
| auth_envelope | string (hex) | No | AuthorityEnvelope (104 bytes) |

**Response:**
```json
{
  "session_id": "abc123...",
  "nonce": "0x..."
}
```

---

### POST /session/run

Calls a function on a persistent session. Requires EIP-712 signed nonce.

**Request:**
```json
{
  "session_id": "abc123...",
  "function": "get",
  "args": [],
  "signature": "0x...",
  "signer": "0x..."
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| session_id | string | Yes | Session ID from /session/new |
| function | string | Yes | Function name to call |
| args | array | Yes | Function arguments |
| signature | string | Yes | EIP-712 signature over ContractCall |
| signer | string | Yes | Signer address |

**EIP-712 ContractCall struct:**
```
ContractCall(string callSignature, string sessionId, string nonce, string domainTag)
domainTag = "SYNQ-CALL-v3"
```

**Response:**
```json
{
  "success": true,
  "result": 42,
  "output": [],
  "gas_used": 15
}
```

---

### GET /session/:id/nonce

Gets the current nonce for EIP-712 signing on a session.

**Response:**
```json
{
  "nonce": "0x..."
}
```

---

### GET /session/:id/state

Inspects the memory state of a session.

**Response:**
```json
{
  "session_id": "abc123...",
  "memory": {
    "0": 42,
    "1": 0
  },
  "assets": []
}
```

---

### DELETE /session/:id

Destroys a session and frees resources.

**Response:** 204 No Content

---

## Workspaces

### POST /workspace/new

Creates a multi-contract workspace for cross-contract calls.

**Request:**
```json
{
  "contracts": [
    { "name": "TokenVault", "bytecode": "0x..." },
    { "name": "SimpleToken", "bytecode": "0x..." }
  ]
}
```

**Response:**
```json
{
  "workspace_id": "ws123...",
  "contracts": ["TokenVault", "SimpleToken"]
}
```

---

### GET /workspace/:id

Returns workspace info including loaded contracts.

**Response:**
```json
{
  "workspace_id": "ws123...",
  "contracts": ["TokenVault", "SimpleToken"],
  "session_count": 2
}
```

---

### POST /workspace/:id/join

Adds a contract to an existing workspace.

**Request:**
```json
{
  "name": "GovernanceDemo",
  "bytecode": "0x..."
}
```

---

### POST /workspace/:id/remove

Removes a contract from a workspace.

**Request:**
```json
{
  "name": "GovernanceDemo"
}
```

---

### DELETE /workspace/:id

Deletes a workspace and all associated sessions.

---

## Attestation

### POST /attest

Performs EIP-191 EVM signature verification and produces a PQC attestation (SynQAttestationV1).

**Request:**
```json
{
  "message": "0x...",
  "signature": "0x...",
  "signer": "0x..."
}
```

**Response:**
```json
{
  "success": true,
  "attestation": {
    "algorithm": "ML-DSA-87",
    "attestation_hash": "0x...",
    "signature": "0x...",
    "public_key": "0x..."
  }
}
```

---

## Utility

### GET /pubkey

Returns the current compiler public key for independent signature verification.

**Response:**
```json
{
  "algorithm": "ML-DSA-87",
  "public_key": "0x...",
  "key_id": "compiler-key-001",
  "mode": "persistent"
}
```

---

### GET /health

Basic health check.

**Response:**
```json
{
  "status": "ok",
  "service": "synq-compiler"
}
```

---

### GET /health/ready

Readiness check. Returns 503 when near session/body cap.

**Response (200):**
```json
{
  "status": "ready",
  "sessions": 12,
  "max_sessions": 100
}
```

**Response (503):**
```json
{
  "status": "overloaded",
  "sessions": 98,
  "max_sessions": 100
}
```

---

### GET /pqc/test-vector

Generates a PQC test vector for a specified algorithm.

**Query params:** `alg=ML-DSA-87`

---

### POST /debug/ecrecover

Recovers an Ethereum address from an EIP-191 signature. Debug endpoint.

---

### POST /bench-compile

Benchmark compilation endpoint. Returns timing metrics for all compilation paths.

---

## Authentication

### EIP-712 Signing (V3)

All session function calls (`/session/run`) require EIP-712 typed data signing:

| Parameter | Value |
|-----------|-------|
| Chain ID | 1266 |
| Domain tag | SYNQ-CALL-v3 |
| Domain name | `SynQ · <Contract> · synergy-testnet-v3` |
| ContractCall struct | `{ callSignature, sessionId, nonce, domainTag }` |

The signature is verified server-side using ecrecover. The nonce is obtained from `GET /session/:id/nonce` and increments after each call.

### AuthorityEnvelope

State-changing functions decorated with `@authority(Scope)` or `@governance(Scope)` require an AuthorityEnvelope (104 bytes) provided at session creation:

```
identity(32B) + scope_hash(32B) + nonce(8B) + expiry(8B) + caps(8B) + reserved(16B)
```

The reserved field (bytes 88–104) carries the V3 domain tag (e.g., "SYNQ-CALL-v3").

---

## Error Codes

| HTTP Status | Condition |
|-------------|-----------|
| 200 | Success (may include revert info) |
| 400 | Bad request (parse error, invalid bytecode) |
| 404 | Session or workspace not found |
| 413 | Payload too large (>2MB body or >256KB source) |
| 429 | Rate limit or session cap exceeded |
| 500 | Internal server error |
| 503 | Service overloaded (health/ready) |

---

End of API Reference
