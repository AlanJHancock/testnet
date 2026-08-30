# SynQ Language Specification v1.0

*Supersedes `specs/synq.dsl` (v0.1, March 2026). Written 30 Aug 2026 as the Phase 3
"Gap Merging + Checklist Verification" deliverable — this document describes the
language as it is actually implemented (grammar: `compiler/src/synq.pest`, AST:
`compiler/src/ast.rs`, VM: `vm/src/opcode.rs` + `vm/src/vm.rs`), not the aspirational
v0.1 sketch. Internal AST/attribute comments call this "spec v7.0," so that's the
version tag carried forward here at the language level.*

---

## 0. Status vs the v0.1 draft

The v0.1 doc (co-drafted early on with contributions from Manus and Claude, per the
Phase 3 checklist item) imagined a `quantumscript`-flavoured language: generic PQC
types (`DilithiumKeyPair<L>`), `require_pqc { } or revert(...)` blocks, a `modifier`
keyword, `@extensible` decorators. **None of that syntax exists in the real
implementation.** What actually got built is a more conventional, Solidity-adjacent
contract language (`contract { state {} impl {} }`) — but it ended up *more*
capability-rich than the v0.1 sketch in most areas that matter: structs, enums,
interfaces, roles/capabilities, named errors, indexed event params, and a formal
`@requires`/`@ensures`/`@effects`/`@fails` attribute system for verification metadata.

| v0.1 idea | Kept? | Where it landed |
|---|---|---|
| PQC types as first-class (`DilithiumSignature<L>`) | Partially | `Type::DilithiumPublicKey/Signature` etc. exist as concrete (non-generic) AST types; no user-facing generic parameter `<L>` |
| `verify_dilithium`/`verify_falcon`/`kyber_encapsulate` builtins | Kept, evolved | Real VM opcodes `DilithiumVerify`/`FalconVerify`/`KyberKeyExchange`/`SphincsVerify` (0x80-0x83) — **already wired to real native crypto crates**, not stubs |
| Composite `PQAuth` struct | Superseded | Generalized by the real `struct` language feature — any composite key type is just a regular struct now |
| `require_pqc { } or revert(...)` | Superseded | Generalized `require(expr, "msg")` + named `revert ErrorName(...)` / `revert Enum::Variant(...)` cover this without a PQC-specific block form |
| `modifier` keyword | Superseded | Replaced by `requires cap::X` / `requires role::X` clauses on functions + `role X = cap::A + cap::B;` declarations |
| `@extensible`, `@gas_limit`, `@optimize_gas`, `@gas_cost` | Superseded | Replaced by the spec v7.0 attribute set: `@bounded(n)` (fuel/step bound), `@effects(...)`, `@requires(...)`, `@ensures(...)` |
| `with_gas_limit(n) { ... }` block | Not implemented | No block-scoped gas limit in the current grammar — `@bounded(n)` is per-function only |
| Message-signing domain separation convention | Kept, generalized | Now implemented per-feature as fixed domain tags, e.g. `@governance` uses `SYNQ-GOVERNANCE-v3` |
| `synq`/`synu`/`synx` addressing note | Superseded | See SNTS v1.3 migration tracking — [`address-engine-migration-scope.md`](../../notes/synq-forge-toolchain/address-engine-migration-scope.md) |

**Important correction to earlier framing:** Phase 5 of the project checklist
("Quantum-Safe Blockchain Runtime… implement native precompiles: dilithium_verify,
falcon_verify, kyber_encaps/decaps… define PQ-Gas profile") describes these as not
yet started. They already exist and are wired to real crypto (§8 below) — Phase 5's
real remaining scope is narrower than the checklist implies (harden/complete the
unified AEG1 path, not build precompiles from zero). Flagged as an open item in §11,
not silently marked complete — needs a real audit pass before the checklist itself
is edited.

---

## 1. Source file structure

```
source_file = pragma_directive* | synq_pragma? ~ top_level_item*
top_level_item = struct_definition | enum_definition | interface_definition
                | contract_definition
```

- `pragma_directive`: `@name "value"` — free-form pragma metadata.
- `synq_pragma`: `pragma synq ^1.0;` (or `~`, `>=`, or bare version) — declares the
  minimum/compatible compiler version a source file targets.

## 2. Structs, enums, interfaces

```synq
struct Order {
    buyer: Address;
    amount: u256;
}

enum Status {
    Pending,
    Filled,
    Cancelled(reason: Str),
}

interface IEscrow {
    function release(id: u256) -> Bool;
}

contract Escrow implements IEscrow {
    ...
}
```

- Enum variants may carry payload fields (`Cancelled(reason: Str)`); variants without
  payloads compile to a sequential `I32` tag (`EnumName::VariantName` reads it back).
- A contract can `implements` one or more interfaces (comma-separated); interface
  functions are declared, not implemented, in the `interface` block.

## 3. Contract structure

```synq
contract TokenVault {
    metadata {
        name = "TokenVault";
        version = "1";
    }

    roles {
        role Admin = cap::Pause + cap::Sweep;
    }

    errors {
        error InsufficientFunds(needed: u256);
    }

    events {
        event Deposited(indexed who: Address, amount: u256);
    }

    security {
        reentrancy_guard: true;
    }

    state {
        balances: map<Address, u256>;
    }

    impl {
        @public
        function deposit(amount: u256) as caller
        requires cap::None
        modifies balances[caller]
        {
            balances[caller] = balances[caller] + amount;
            emit Deposited(caller, amount);
        }
    }

    tests {
        function scenario_basic_deposit() { ... }
    }
}
```

Sections (`state`, `events`, `errors`, `roles`, `metadata`, `security`, `impl`,
`tests`) may appear in any order and are all optional — a contract can also mix in
"flat" (legacy) top-level state-variable declarations, function definitions, and
event definitions directly in the contract body for backward compatibility with
pre-section-syntax sources.

- **`tests { }`** functions compile like normal functions but are **not deployed** —
  they exist purely for the scenario-test harness (`AssetDemo.scenario.json`-style
  runs) to call against a live/dry-run instance.
- **`security { }`** entries are `key: value;` pairs (string/bool/number) — currently
  free-form metadata (e.g. `reentrancy_guard: true;`), not yet enforced by the
  compiler/VM itself.

## 4. Type system

**Numeric tower** — full unsigned and signed widths: `u8`..`u256`, `i8`..`i256`
(the AST also recognises legacy `UInt*`/`Int*` spellings). `u256` remains the
standard width for balances/amounts per the standing V3 convention.

**Other primitives:** `Bool`, `Bytes`, `Address`, `Str`.

**Fixed-size / hash types (spec v7.0):** `Bytes<N>` (`bytes_type`), `Hash32`,
`Hash64` (32-/64-byte hash aliases).

**Domain types (spec v7.0):** `UMAIdentity` (32-byte identity handle), `ModelId`
(AI model identifier), `Height` (block height).

**PQC key/signature types:** `DilithiumPublicKey`, `FalconPublicKey`,
`KyberPublicKey`, `DilithiumSignature`, `FalconSignature` — concrete types (no
generic security-level parameter in the current grammar, unlike the v0.1 sketch's
`DilithiumKeyPair<L>`).

**Higher-order / compound types:**
- `Option<T>`, `Result<T, E>`
- `(T, T, ...)` tuples (2+ elements)
- `mapping<K, V>` / `map<K, V>` — supports arbitrary nesting, `map<K, map<K, V>>`
- `set<T>`
- `[T]` arrays
- `Asset<T>` — linear (move-only, non-copyable) asset wrapper, see §9
- `Named(String)` — any user-defined `struct`/`enum` by name

## 5. Roles & capabilities

```synq
role Admin = cap::Minter + cap::Burner;
```

desugars to `requires cap::Minter, cap::Burner` wherever `role::Admin` is required.
A function gates access with:

```synq
function mint(to: Address, amount: u256)
requires cap::Minter
{ ... }
```

`req_body` in a function's `requires` clause is *either* an access-requirement list
(`cap::X`, `role::X`) *or* a state-precondition list (raw expression text, e.g.
`balance_of[caller] >= amount`) — the parser tries access-requirements first. State
preconditions are captured as metadata (`requires_state` on `FunctionDefinition`) for
tooling/test-harness use; they are **not** compiled into bytecode guards — actual
runtime enforcement still has to be written as a `require(...)` statement in the
function body.

## 6. Named errors

```synq
errors {
    error InsufficientFunds(needed: u256);
}
```

Reverted with `revert InsufficientFunds(500);` (bare form) or, if declared inside an
`enum`, with the qualified form `revert ErrorEnum::Variant(args);`. Both compile to
`RevertCode`/`RevertCodeDyn` VM opcodes carrying a numeric error code plus a display
message — richer than a plain `require(false, "msg")`, which only carries a message
(`Revert` opcode, no code).

## 7. Attributes (spec v7.0)

Attributes are declared one per line directly above a function:

```synq
@public
@authority(AdminScope)
@effects(balances, totalSupply)
@requires(balances[caller] >= amount)
@ensures(totalSupply == old(totalSupply) - amount)
@fails(InsufficientFunds)
@bounded(1_000_000)
@manifest
function burn(amount: u256) { ... }
```

| Attribute | Meaning |
|---|---|
| `@public` | Callable from outside the contract |
| `@authority(Scope)` | Requires caller to hold the named authority scope (devnet-friendly: all-zeros scope accepted) |
| `@governance(Scope)` | Strict authority variant — SHA3-256 scope-hash match, `SYNQ-GOVERNANCE-v3` domain tag, no devnet bypass |
| `@effects(var, ...)` | Declares which state variables this function writes (verification/tooling metadata) |
| `@requires(expr)` | State precondition (metadata only, not compiled — same caveat as §6) |
| `@ensures(expr)` | State postcondition (metadata only) |
| `@fails(ErrorName)` | Declares a named error this function may revert with |
| `@bounded(n)` | Declares a step/fuel bound for the function |
| `@manifest` | Function appears in the contract's public manifest/ABI listing |
| `@ai` | Function may perform AI inference; implicitly requires `cap::AI` |

`@requires`/`@ensures`/`@effects` are **metadata only** right now — nothing in the
compiler currently checks a function's body actually satisfies its declared
`@ensures`, and nothing enforces `@effects` lists match real writes. This is exactly
the kind of gap Phase 3's "ensure compiler ↔ VM ↔ SDK interface contracts match" line
is meant to close — currently open, tracked in §11.

## 8. Post-quantum cryptography — two-tier opcode design

**Tier 1 — legacy, algorithm-specific (backward compat), opcodes `0x80`-`0x83`:**
`DilithiumVerify`, `KyberKeyExchange`, `FalconVerify`, `SphincsVerify`. Each pops its
arguments straight off the stack (e.g. Dilithium: signature, message, public key) and
calls a real native crypto crate (`dilithium::verify`, `falcon::verify`,
`sphincs::verify`, `kyber::decaps`) — **these are not stubs**, they run genuine PQC
verification/decapsulation today, gated behind a `native` VM build feature. Each call
charges a flat `AEGIS_MIN_COST` fuel amount.

**Tier 2 — unified AEG1 dispatch (preferred for new contracts), opcode `0x8F`
(`AegisCall`):** pops a single encoded `Aeg1Request` frame, dispatches to the
appropriate PQC shim via `aeg1::process_frame_deterministic`, and pushes back an
`Aeg1Response` frame (`Ok(bytes)` → `Bool(true)` for verify-style calls or
`Bytes(secret)` for decapsulation; `Error(code, msg)` → `Bool(false)`, logged). Cost is
computed **before** dispatch via `aeg1::compute_cost(&req)` — a real per-request PQ-gas
calculation, not a flat charge — with a bounded minimum charge even for malformed
frames (so a bad frame can't be used to probe for free). This is the ACTS-15 /
ACTS-VM-005 "deterministic VM dispatcher with cost model" already referenced in the
VM's own inline spec citations.

There is currently no SynQ-language-level syntax that emits `AegisCall`/`Aeg1Request`
frames directly — only the legacy per-algorithm opcodes are reachable from source via
`Type::Dilithium*`/`Type::Falcon*`/`Type::Kyber*` today. Exposing AEG1 at the language
level (builtins or a dedicated block form) is unstarted and belongs to Phase 5's real
remaining scope — see §0 and §11.

## 9. Assets (linear/move-only values)

`Asset<T>` types back a small set of VM primitives (opcodes `0x57`-`0x5B`):
`AssetCreate` (type_tag + value → new asset_id), `AssetTransfer` (new_owner + asset_id
→ new asset_id — old id is invalidated), `AssetBurn` (asset_id → value, consumes it),
`AssetBalance`, `AssetOwner`. These model non-copyable, ownership-tracked values (think
NFT-like or UTXO-like semantics) distinct from ordinary `u256` balances in a `map`.

## 10. Statements & expressions reference

**Statements:** `let` / `let (a, b) = ...` destructure, plain assignment,
`self.field = ...` / `obj.field = ...`, `map[k] = v` (supports chained
`map[k1][k2] = v` for nested maps), `set.add(v)` / `set.remove(v)`, `if`/`else`,
`while`, `break`, `continue`, `return`, `require(cond, "msg")`, `revert Name(...)`,
`revert Enum::Variant(...)`, `trap [code];` (unconditional abort), `emit Event(...)`,
`extern_call("Contract", "function", args...)` (cross-contract call within the same
workspace), and bare expression statements.

**Expression precedence (low → high):** `||`/`&&` → comparison (`==` `!=` `<` `<=`
`>` `>=`) → `|` → `^` → `&` → `<<`/`>>` → `+`/`-` → `*`/`/`/`%` → unary (`-` `!` `~`)
→ postfix (`.field`, `.method(args)`, `.0` tuple index) → primary (identifiers,
literals, `self.field`, `map[k]`, `Enum::Variant`, `Struct { f: v }`, `Some(x)` /
`None` / `Ok(x)` / `Err(x)`, calls, tuples, parenthesized).

Bitwise/shift operators (`|` `^` `&` `<<` `>>` and unary `~`) operate on the full
256-bit representation regardless of the operand's declared narrower width.

## 11. Open items (Phase 3 checklist, honest state as of 30 Aug 2026)

- [x] **Merge Manus/Claude contributions with DSL spec** — this document.
- [ ] **Extract and reconcile opcode differences** — this doc lists the VM
  (`vm/src/opcode.rs`) opcode set faithfully, but there are at least two other
  bytecode targets in the toolchain (AIVM, used by the hosted dry-run/scenario-test
  endpoint, and the EVM-transpilation path) with their **own, different** opcode
  numbering for overlapping operations (e.g. AIVM's `Ne`/`Le`/`Ge` sit at different
  byte values than this VM's `0x21`/`0x23`/`0x25`). A real reconciliation pass across
  all three needs its own dedicated audit — not attempted here.
- [ ] **Add any missing intrinsics or decorators** — no gaps found in this pass
  beyond what's already noted (no AEG1-level language syntax yet, per §8).
- [ ] **Ensure compiler ↔ VM ↔ SDK interface contracts match** — `@requires`/
  `@ensures`/`@effects` are parsed but not verified against function bodies (§7);
  JS SDK parity with the full spec v7.0 attribute/type set not checked in this pass.
- [ ] **Add core test fixtures for DSL + compiler** — not covered by this
  documentation pass; separate follow-up.
- [ ] **Phase 5 checklist accuracy** — checklist.md still describes PQC precompiles
  as unbuilt; they demonstrably exist and run real crypto (§8, §0). Checklist.md
  itself intentionally left unedited pending a real verification/test-coverage audit
  of the AEG1 path, rather than asserting "done" here.
