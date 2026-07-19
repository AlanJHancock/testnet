# SynQ Virtual Machine Specification v0.2

> Updated 2026-07-19 to reflect the implemented QuantumVM (`vm/src/vm.rs`).  
> v0.1 described the target design; v0.2 describes what is deployed on testnet today.

---

## 1. Overview

The SynQ VM (`QuantumVM`) is a stack-based interpreter executing post-quantum-aware smart contracts compiled from SynQ source. It runs inside the `synq-server` process, one VM instance per session. Key properties:

- Stack-based with `Value`-typed operands (I32, U128, U256, Bool, Bytes)
- Addressable memory: up to 1,024 entries per session (slot → Value)
- Explicit authenticated caller context (`LoadCaller`, 0x50)
- Cross-contract calls via `ExternCall` (0x60) with workspace-scoped handler
- Transactional atomicity: memory snapshot before call, restored on `Revert`
- Step limit: configurable; default 1,000,000 instructions per run
- PQC opcodes (0x80–0x83): ML-DSA-65, Falcon-512, SPHINCS+-SHAKE-128s, Kyber-768

---

## 2. Bytecode Format

```
QVM\0                        (4 bytes — magic)
version       : u8           (byte 4)
header_len    : u16 LE       (bytes 5–6 — length of header including magic+version)
flags         : u8           (byte 7)
reserved      : [u8; 7]      (bytes 8–14)
... code section follows at offset header_len
```

The code section begins immediately after the header. All offsets in jump targets and the dispatch table are relative to the start of the code section (offset 0).

---

## 3. Opcode Table

### 3.1 Stack

| Opcode | Mnemonic    | Encoding                  | Description                             |
|--------|-------------|---------------------------|-----------------------------------------|
| 0x01   | Push        | `01 <1B type> <value>`    | Push typed literal onto stack           |
| 0x02   | Pop         | `02`                      | Discard top of stack                    |
| 0x03   | Dup         | `03`                      | Duplicate top of stack                  |
| 0x04   | Swap        | `04`                      | Swap top two stack values               |

### 3.2 Arithmetic

| Opcode | Mnemonic | Description                                          |
|--------|----------|------------------------------------------------------|
| 0x10   | Add      | `a + b` — U256 overflow panics                       |
| 0x11   | Sub      | `a - b` — U256 underflow panics; use `require` guard |
| 0x12   | Mul      | `a * b`                                              |
| 0x13   | Div      | `a / b` — zero divisor is a runtime error            |
| 0x14   | Rem      | `a % b` — modulo                                     |

Mixed-type arithmetic: I32 is promoted to U128 automatically.

### 3.3 Comparison

| Opcode | Mnemonic | Description     |
|--------|----------|-----------------|
| 0x20   | Eq       | `a == b`        |
| 0x21   | Ne       | `a != b`        |
| 0x22   | Lt       | `a < b`         |
| 0x23   | Le       | `a <= b`        |
| 0x24   | Gt       | `a > b`         |
| 0x25   | Ge       | `a >= b`        |

### 3.4 Control Flow

| Opcode | Mnemonic | Encoding                    | Description                                              |
|--------|----------|-----------------------------|----------------------------------------------------------|
| 0x30   | Jump     | `30 <4B LE offset>`         | Unconditional jump to code offset                        |
| 0x31   | JumpIf   | `31 <4B LE offset>`         | Pop Bool; jump if true                                   |
| 0x32   | Call     | `32 <4B LE offset>`         | Push return frame, jump to function entry                |
| 0x33   | Return   | `33`                        | Pop return frame, resume caller                          |
| 0x34   | Revert   | `34 <4B LE msg_len> <msg>`  | Abort execution, restore pre-call memory snapshot        |

### 3.5 Memory

| Opcode | Mnemonic    | Encoding                        | Description                                     |
|--------|-------------|---------------------------------|-------------------------------------------------|
| 0x40   | Load        | `40 <4B LE slot>`               | Push value from memory slot (default I32(0))    |
| 0x41   | Store       | `41 <4B LE slot>`               | Pop and write to memory slot                    |
| 0x42   | LoadImm     | `42 <4B LE value>`              | Push I32 immediate                              |
| 0x43   | LoadImm128  | `43 <16B big-endian u128>`      | Push U128 immediate                             |
| 0x44   | LoadImm256  | `44 <32B big-endian U256>`      | Push U256 immediate                             |

### 3.6 Identity

| Opcode | Mnemonic   | Description                                                                       |
|--------|------------|-----------------------------------------------------------------------------------|
| 0x50   | LoadCaller | Push authenticated EVM caller as U256. Pushes UMA_ANON sentinel if unauthenticated. |

`UMA_ANON` is `keccak256("UMA:" || 0x00...00)[0..32]` — a domain-separated sentinel that cannot be produced by a legitimate wallet address.

### 3.7 Cross-Contract

| Opcode | Mnemonic   | Encoding                                                                                    | Description                                      |
|--------|------------|---------------------------------------------------------------------------------------------|--------------------------------------------------|
| 0x60   | ExternCall | `60 <4B LE cname_len> <cname_bytes> <4B LE fname_len> <fname_bytes> <1B arg_count>`        | Call function on another contract in the workspace |

`ExternCall` pops `arg_count` values from the stack (reversed to call order), invokes the workspace `extern_call_handler`, and pushes the return value. Pushes `I32(0)` for void functions. Propagates the caller's authenticated identity to the target — call semantics, not delegatecall.

### 3.8 PQC Opcodes

| Opcode | Mnemonic        | Algorithm           | Note                              |
|--------|-----------------|---------------------|-----------------------------------|
| 0x80   | DilithiumVerify | ML-DSA-65           | NIST FIPS 204                     |
| 0x81   | KyberKeyExchange| ML-KEM-768          | NIST FIPS 203                     |
| 0x82   | FalconVerify    | FN-DSA-512          | NIST FIPS 206 (draft)             |
| 0x83   | SphincsVerify   | SLH-DSA-SHAKE-128s  | NIST FIPS 205                     |

> PQC opcodes execute natively in `synq-server`. In browser (WASM) mode they throw a `RuntimeError` — contracts using PQC builtins must be deployed to the server VM.

### 3.9 I/O & Halt

| Opcode | Mnemonic | Description                |
|--------|----------|----------------------------|
| 0xF0   | Print    | Emit top of stack to output |
| 0xFF   | Halt     | End execution               |

---

## 4. Value Types

| Type   | Description                                      |
|--------|--------------------------------------------------|
| I32    | 32-bit signed integer (default for uninitialised slots) |
| U128   | 128-bit unsigned integer                         |
| U256   | 256-bit unsigned integer (ruint crate)           |
| Bool   | Boolean; promoted to 0/1 for arithmetic          |
| Bytes  | Variable-length byte array                       |

U256 values exceeding 2^53 are JSON-serialised as quoted strings.

---

## 5. Call Semantics

### 5.1 Internal Calls (`Call` / `Return`)
Function calls within a contract use the `Call` (0x32) opcode to push a return frame onto the call stack and jump to the function entry point. `Return` (0x33) pops the frame and resumes the caller. Maximum call depth: 64 (enforced at compile time via DFS and at runtime).

### 5.2 Cross-Contract Calls (`ExternCall`)
`ExternCall` (0x60) calls a function on a different contract within the same workspace. The target contract runs in its own isolated memory space — no shared slots. The caller's identity (`LoadCaller` context) is forwarded to the target, making the origin wallet visible to the target function's `as caller` prologue.

Deadlock prevention: the workspace lock is dropped before acquiring the session lock for the target.

### 5.3 Atomicity
Before any `ExternCall` or internal `Call` that may `Revert`, the VM takes a snapshot of the current memory. If the callee reverts, the snapshot is restored. This mirrors EVM call-frame revert semantics.

---

## 6. Authentication Model

Functions declared `as caller` emit an authentication prologue at compile time:

```
LoadCaller                ; push EVM address as U256
LoadImm256(UMA_ANON)      ; push the anonymous sentinel
Eq                        ; compare
JumpIf(revert_offset)     ; reject if caller is anonymous
Jump(body_offset)         ; proceed to function body
[revert_offset]:
Revert  "unauthenticated call"
[body_offset]:
...
```

An unauthenticated session has no `evm_address` + `evm_signature` in its `/session/run` request. The VM's `LoadCaller` pushes `UMA_ANON` in that case, and the prologue reverts. No bytecode change is needed to enforce this — it is structural.

---

## 7. Future Opcodes

| Opcode | Mnemonic        | Status   | Notes                                              |
|--------|-----------------|----------|----------------------------------------------------|
| 0x61   | DelegateCall    | Deferred | Executes target bytecode in caller's storage context. Requires strict storage layout alignment and `cap::DelegateExec` capability. Not yet implemented. |

---

## 8. Runtime Limits (testnet)

| Parameter              | Value           |
|------------------------|-----------------|
| Max step count         | 1,000,000       |
| Max memory slots       | 1,024 per session |
| Max call depth         | 64 hops         |
| Max source size        | 64 KB           |
| Max body size          | 128 KB          |
| Max concurrent sessions| 100 (LRU evict) |
| Max workspaces         | 50 (LRU evict)  |

---

*End of SynQ VM Specification v0.2*
