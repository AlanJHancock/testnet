# SynQ Changelog

All notable changes to the SynQ toolchain are documented here.
Dates are in UTC.

---

## 2026-07-30

### SSA IR Instruction Dump in IDE
- **Full IR dump:** The IDE now displays the complete SSA IR instruction listing for each compiled contract, including value IDs with types, CFG blocks with predecessor annotations, and all terminators (Branch, Jump, Return, Store).
- **Contract name headers:** Both the IR dump and the bytecode disassembly now show the contract name in their header comments.
- **IR panel:** Replaced the previous summary-stats-only display with a full block-by-block instruction dump. Summary stats retained below the full dump.
- **Server integration:** `ir_dump` field added to `CompileResponse`; server builds IR via `IrBuilder::build()` + `ir::analyze()` and returns `IrModule::dump()` output.
- **Bug fix:** IR builder panic on V3TypesDemo fixed — per-block `ValueId` type lookup instead of module-level.

### Contract Name in IR and Bytecode Headers
- IR dump uses `IrModule::dump()` which includes `module ContractName {` header with state variable layout and struct/enum definitions.
- Bytecode disassembly header now shows `[contract: Name]` from the compile response.
- `formatBytecode()` in the IDE accepts a `contractName` parameter.

---

## 2026-07-29

### Linear Asset Tracking — Asset<T> + Opcodes 0x57-0x5B
- **New type:** `Asset<T>` — linear resource with create, transfer, burn semantics.
- **New opcodes:** AssetCreate (0x57), AssetTransfer (0x58), AssetBurn (0x59), AssetBalance (0x5A), AssetOwner (0x5B).
- **Linearity invariant:** Each asset ID consumed exactly once. Transfer deactivates old ID, creates new. Burn deactivates, returns value.
- **VM asset registry:** `AssetRecord` struct with owner, value, type_tag, active flag. Persists across function calls within a session.
- **Builtins:** `asset_create`, `asset_transfer`, `asset_burn`, `asset_balance`, `asset_owner`.
- **Demo contract:** AssetDemo — create/transfer/burn/balance verification.

### Named Error Integration — RevertCode (0x35)
- **New opcode:** RevertCode (0x35) — structured named error revert with error_code (4B LE) + msg_len (4B LE) + message.
- **New VMError variant:** `RevertedNamed { code, message }` — distinct from string-based `Reverted`.
- **Grammar:** `revert EnumName::VariantName(args);` syntax added (PEG ordered choice before bare `revert`).
- **Server response:** `error_code` (Option<u32>) and `error_name` (Option<String>) fields.
- **Demo contract:** NamedErrorDemo — InsufficientBalance, Unauthorized, InvalidAmount, Overflow.

### TupleSet (0xAB) + Struct Field Assignment
- **New opcode:** TupleSet (0xAB) — pop index + value + tuple, push new tuple with element replaced. Bounds-checked.
- **Grammar:** `field_assign_statement` rule for `obj.field = value;` syntax.
- **AST:** `FieldAssignment { object, field, value }` variant.
- **Codegen:** Push addr → Load → gen_expression → Push field_idx → TupleSet → Push addr → Store.
- **Demo contract:** StructFieldTest — Point struct with x/y assignment and verification.

### Governance Authorization + ML-DSA-87 Manifest Signing
- **@governance(Scope) attribute** added to AST, parser, codegen.
- **Scope hashes:** Governance = SHA3-256(`SYNQ-GOVERNANCE-SCOPE-v1:` + scope), Authority = SHA3-256(`SYNQ-AUTHORITY-SCOPE-v1:` + scope).
- **VM AuthRequire:** All-zeros envelope scope = devnet wildcard (accept any scope).
- **V3 manifest:** ML-DSA-87 signed, includes ABI (functions), state layout (state_vars), governance/authority scopes.
- **Server:** `governance_scopes` field in session, `ManifestFunction` and `ManifestStateVar` structs.
- **JumpIf fix:** Authorized=true now correctly jumps to body (was jumping to revert).
- **Demo contract:** GovernanceDemo.

### Struct/Enum Runtime Support
- Struct field access (`p.x`) via local type inference in `let` statements.
- Enum variant access (`Color::Red`) resolved to sequential integer tags.
- Runtime TupleGet/MakeTuple for struct value manipulation.
- **Demo contract:** StructEnumDemo.

### Wallet Integration (Complete)
- Three-tier address resolution: Synergy extension (synw) > device-link JSON > ephemeral Bech32 (syna/sync).
- `_walletProvider()` abstraction + `_walletRequest()` for all wallet RPCs.
- EIP-6963 multi-provider discovery for MetaMask detection.
- MetaMask chain-switch to 1266 via RPC stub at hanksweb.co.uk/synq-rpc/.
- Manual synw entry: `_manualSynw` variable persists independently of `walletAddress`/`_walletMode`.
- V3 EIP-712: chainId 1266, domainTag SYNQ-CALL-v3.
- `synqWallet()` console diagnostic for provider status.
- Native token ticker standardized to SNRG.

### AEG1 Wire Protocol
- Bounded framing ABI for PQC operations: 1MiB payload, 8 args, 128KiB per arg.
- Operations: ML-KEM decapsulate (1), ML-DSA verify (2), FN-DSA verify (3).
- AegisCall (0x8F) unified opcode; legacy 0x80-0x83 retained as aliases.
- NIST/FIPS naming alignment: ML-KEM, ML-DSA, FN-DSA.
- SPHINCS+, McEliece, HQC NOT in AEG1 (legacy direct-call only).

### Authority Model + Attributes + Type System
- AuthorityEnvelope (104B): identity + scope_hash + nonce + expiry + caps + reserved.
- Opcodes: LoadAuthority (0x51), AuthRequire (0x52), AuthIdentity (0x53).
- 9 attributes: @public, @authority, @governance, @effects, @requires, @ensures, @fails, @bounded, @manifest, @ai.
- Type aliases: Bytes<N>, Hash32, Hash64, UMAIdentity, ModelId, Height.
- Enums (C-style + algebraic), struct literals, field access.
- Function signature: both `-> T as caller` and `as caller -> T` orderings supported.

### V3 Bech32 Addresses
- syna = accounts, sync = contracts, tsynq RETIRED.
- AddrEncode (0x54), AddrDecode (0x55), ContractAddr (0x56).
- Builtins: to_syna(), from_syna(), contract_address().
- `from_any_syn()` decodes syna/synw/sync to 20 bytes.

---

## Earlier (2026-07-16 through 2026-07-28)

### Compiler & VM Foundations
- Stack-based QVM with I32, U128, U256, Bool, Bytes, Tuple value types.
- pest grammar, precedence-climbing parser, require() → backpatched JumpIf+Revert.
- State{} and impl{} blocks, U256 literals, fn alias.
- ExternCall (0x60) for cross-contract calls (workspace-scoped).
- Transactional atomicity (rollback on revert).
- 116 tests passing.

### PR #15
- anyhow crate RUSTSEC-2026-0190 pinned to v1.0.103.

---

## Test Count: 116 (unchanged across all recent changes)
