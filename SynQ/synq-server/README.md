# synq-server

HTTP compile and execution server for the SynQ toolchain.

**Testnet endpoint:** `https://hanksweb.co.uk/synq/`

---

## Security properties (PR-C / PR-D)

- Session IDs: 32-byte OS entropy via `getrandom`, rendered as 64-char hex — unguessable
- Session cap: 100 concurrent sessions, 30-minute TTL, LRU eviction on overflow
- Body limit: 128 KB per request (axum `RequestBodyLimitLayer`)
- Source limit: 64 KB SynQ source per `/compile` call
- VM step limit: 1,000,000 instructions per `/session/run` call
- Mutex discipline: global session-store lock released before VM execution; each session has its own lock
- Hex decoding: strict (`hex_decode_strict`) — rejects odd-length, invalid characters, empty strings
- EVM verification: `/attest` runs server-side ecrecover; mismatches return 400
- CORS: configurable via `SYNQ_CORS_ORIGIN` env var (default `*` for testnet)

---

## API reference

### `GET /health`

Returns service status and current capacity.

```json
{
  "status": "ok",
  "service": "synq-compiler",
  "active_sessions": 2,
  "max_sessions": 100,
  "session_ttl_secs": 1800,
  "signing_algorithm": "ML-DSA-65",
  "max_source_bytes": 65536,
  "max_body_bytes": 131072
}
```

---

### `POST /compile`

Compile SynQ source and sign the bytecode with an ephemeral ML-DSA-65 key.

**Request:**
```json
{ "source": "pragma synq ^0.9;\ncontract Token { ... }" }
```

**Response:**
```json
{
  "success": true,
  "bytecode": "0x4d5651...",
  "signature_sidecar": {
    "mode": "ephemeral",
    "algorithm": "ML-DSA-65",
    "public_key": "a1b2c3...",
    "signature": "d4e5f6...",
    "trust_model": "ephemeral-self-signed",
    "note": "Ephemeral keypair: proves bytecode integrity but does not establish compiler identity."
  },
  "state_vars": [["total", 0], ["owner", 1], ["paused", 2]],
  "errors": [],
  "warnings": []
}
```

---

### `POST /attest`

Hybrid EVM + PQC attestation. Verifies the EVM wallet signature server-side via ecrecover, then wraps the result in a `SynQAttestationV1` canonical payload signed with ML-DSA-65.

**Request:**
```json
{
  "bytecode":      "0x4d5651...",
  "evm_signature": "0xaabbcc...65bytes",
  "evm_address":   "0x742d35cc..."
}
```

The EVM signature must be produced by `personal_sign` over the message:
```
"SynQ bytecode keccak256:\n0x<keccak256_hex_of_raw_bytecode>"
```

**Response:**
```json
{
  "success": true,
  "hybrid_sidecar": {
    "mode": "hybrid",
    "attestation_version": "SynQAttestationV1",
    "scheme": "EIP-191 personal_sign",
    "bytecode_hash": "0xaabbcc...",
    "evm_address": "0x742d35cc...",
    "issued_at": 1752616800,
    "pqc": {
      "algorithm": "ML-DSA-65",
      "public_key": "...",
      "signature": "...",
      "signed_payload": "SynQAttestationV1: magic(16) || scheme(1) || keccak256_bytecode(32) || evm_signer(20) || issued_at_u32be(4) || raw_bytecode"
    },
    "trust_model": "ephemeral-self-signed",
    "note": "Ephemeral keypair: proves integrity of this attestation bundle but does not establish compiler identity. EVM signer address was independently recovered via ecrecover."
  }
}
```

**SynQAttestationV1 canonical payload layout:**

| Bytes | Content |
|-------|---------|
| 0–15 | `b"SynQAttestation\x01"` (magic + version) |
| 16 | Scheme: `0x01` = EIP-191 personal_sign |
| 17–48 | `keccak256(raw_bytecode)` — server-computed |
| 49–68 | Recovered EVM signer address (20 bytes) |
| 69–72 | `issued_at` Unix timestamp (u32 big-endian) |
| 73– | Raw bytecode (variable length) |

---

### `POST /session/new`

Load bytecode into a fresh persistent VM session. Returns a session ID (bearer token — treat as secret).

**Request:**
```json
{
  "bytecode":   "0x4d5651...",
  "state_vars": [["total", 0], ["owner", 1], ["paused", 2]]
}
```

**Response:**
```json
{ "success": true, "session_id": "9ccf05b8e2b550410dad09b..." }
```

---

### `POST /session/run`

Call a function on a live session. State persists between calls.

**Request:**
```json
{
  "session_id": "9ccf05b8...",
  "function":   "mint",
  "args":       ["1000"]
}
```

Arguments may be numbers or strings. Strings are used for values exceeding 2^53 (large UInt256 / Ethereum addresses).

**Response:**
```json
{
  "success": true,
  "result":  { "type": "U256", "value": "1000" },
  "output":  "Return value: 1000",
  "error":   null
}
```

On `require()` failure:
```json
{ "success": false, "error": "require failed: insufficient supply" }
```

---

### `DELETE /session/:id`

Destroy a session and release its VM memory.

```json
{ "success": true }
```

---

### `GET /session/:id/state`

Read the current live values of state variables.

```json
{
  "success": true,
  "state": {
    "total":  "5000",
    "owner":  "887567...",
    "paused": 0
  }
}
```

---

## Running locally

```bash
cargo build --release -p synq-server
SYNQ_CORS_ORIGIN=http://localhost:3000 ./target/release/synq-server
```

Server listens on `0.0.0.0:3030`.

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `SYNQ_CORS_ORIGIN` | `*` | Allowed CORS origin. Set to your domain in production. |
