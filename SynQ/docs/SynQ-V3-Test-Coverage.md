# SynQ V3 — Test Coverage Report

**Date:** 2 August 2026  
**Test suite:** `cargo test --workspace`  
**Result:** 203 passed, 0 failed, 1 ignored  
**Workspace:** 6 crates (vm, compiler, pqc-shims, cli, synq-server, synq-compiler-wasm)

---

## Test Distribution by Crate

| Crate | Tests Passed | Ignored | Focus |
|-------|-------------|---------|-------|
| synq-vm | 50 | 1 | VM opcodes, value types, execution, assets, revert, rollback |
| synq-compiler | 55 | 0 | Parser, codegen, IR builder, IR passes, lowering, gap analysis |
| synq-pqc-shims | 50 | 0 | AEG1 protocol, ML-DSA, FN-DSA, ML-KEM, SPHINCS+, McEliece, HQC |
| synq-cli | 3 | 0 | CLI compile, sign, verify integration |
| synq-server | 12 | 0 | HTTP endpoints, sessions, workspaces, attestation |
| synq-compiler-wasm | 12 | 0 | WASM compilation, browser-compatible output |
| Other (doc-tests, integration) | 21 | 0 | Cross-crate integration, doc-tests |

---

## Capability → Test Mapping

### VM Core

| Capability | Test Names | Count |
|------------|-----------|-------|
| Stack operations (Push, arithmetic) | test_push_arithmetic, test_add, test_sub, test_mul, test_div, test_mod | 6 |
| U256 arithmetic | test_u256_add, test_u256_mul, test_u256_overflow, test_u256_comparison | 4 |
| U128 arithmetic | test_u128_add, test_u128_i32_mixed_add, test_u128_overflow | 3 |
| Comparison opcodes | test_lt, test_gt, test_le, test_ge, test_eq, test_ne | 6 |
| Control flow (jumps, calls) | test_jump, test_jump_if, test_call_return, test_nested_call | 4 |
| Memory (Load/Store) | test_store_load, test_load_unwritten, test_loadimm, test_loadimm256 | 4 |
| Transactional atomicity | test_rollback_on_revert, test_snapshot_restore | 2 |
| Named errors | test_revert_code, test_revert_code_dynamic, test_named_error | 3 |
| ToString | test_to_string, test_expr_to_string | 2 |
| Tuples | test_tuple_pack, test_tuple_get, test_tuple_set | 3 |

### Assets

| Capability | Test Names | Count |
|------------|-----------|-------|
| Asset create | test_asset_create | 1 |
| Asset transfer | test_asset_transfer | 1 |
| Asset burn | test_asset_burn | 1 |
| Asset balance/owner | test_asset_balance, test_asset_owner | 2 |
| Linearity (double-spend) | test_asset_double_transfer_fails | 1 |

### PQC

| Capability | Test Names | Count |
|------------|-----------|-------|
| AEG1 protocol | test_aeg1_frame, test_aeg1_bounds, test_aeg1_magic | 3 |
| ML-DSA verify | test_dilithium_verify_shim, test_dilithium_verify_rejects_forged | 2 |
| FN-DSA verify | test_falcon_verify_shim | 1 |
| ML-KEM decapsulate | test_kyber_decapsulate_shim | 1 |
| SPHINCS+ | test_sphincs_verify_shim | 1 |
| McEliece | test_mceliece_keygen | 1 |
| HQC | test_hqc_decapsulate | 1 |
| Deterministic dispatch | test_dispatch_deterministic, test_reject_secret_key | 2 |

### Authority & Governance

| Capability | Test Names | Count |
|------------|-----------|-------|
| AuthorityEnvelope | test_auth_envelope, test_auth_require | 2 |
| AuthRequire wildcard | test_devnet_wildcard | 1 |
| Governance scope | test_governance_scope | 1 |
| LoadCaller | test_load_caller | 1 |

### Addressing

| Capability | Test Names | Count |
|------------|-----------|-------|
| syna encode/decode | test_syna_encode, test_syna_decode | 2 |
| sync encode | test_sync_encode | 1 |
| ContractAddr | test_contract_address | 1 |
| tsynq rejection | test_tsynq_rejected | 1 |
| from_any_syn | test_from_any_syn | 1 |

### Compiler / IR

| Capability | Test Names | Count |
|------------|-----------|-------|
| Parser | test_parse_contract, test_parse_state, test_parse_functions | 3 |
| Attributes | test_parse_attributes, test_authority_attr, test_governance_attr | 3 |
| Enums | test_parse_enum, test_enum_codegen | 2 |
| Structs | test_parse_struct, test_struct_codegen, test_field_assignment | 3 |
| Direct codegen | test_codegen_basic, test_codegen_arithmetic, test_codegen_control_flow | 3 |
| IR builder | test_ir_build, test_ir_blocks, test_ir_phi | 3 |
| IR passes | test_dce, test_const_fold, test_copy_prop, test_phi_insertion | 4 |
| IR lowering | test_lower_basic, test_lower_phi, test_lower_cross_block | 3 |
| IR gap analysis | test_all_contract_patterns (22 patterns) | 1 |
| Deterministic bytecode | test_deterministic_compile | 1 |
| ExternCall | test_extern_call_codegen | 1 |

### Server

| Capability | Test Names | Count |
|------------|-----------|-------|
| /compile endpoint | test_compile, test_compile_error | 2 |
| /session/* endpoints | test_session_new, test_session_run, test_session_nonce | 3 |
| /workspace/* endpoints | test_workspace_new, test_workspace_join | 2 |
| /attest endpoint | test_attest | 1 |
| /pubkey endpoint | test_pubkey | 1 |
| Rate limiting | test_rate_limit | 1 |
| Session TTL | test_session_expiry | 1 |
| Body size limit | test_body_limit | 1 |

### WASM Compiler

| Capability | Test Names | Count |
|------------|-----------|-------|
| WASM compilation | test_wasm_compile_basic | 1 |
| WASM output format | test_wasm_output | 1 |
| WASM + IDE integration | test_wasm_ide_flow | 1 |

### SQB Artifact

| Capability | Test Names | Count |
|------------|-----------|-------|
| SQB encode/decode | test_sqb_round_trip | 1 |
| SQB hash binding | test_sqb_tamper_detection | 1 |
| SQB signature | test_sqb_signature | 1 |
| ACTS-VM bounds | test_sqb_bounds | 1 |

### Bytecode Verification

| Capability | Test Names | Count |
|------------|-----------|-------|
| Layer 1 (structural) | test_verify_layer1_pass, test_verify_layer1_bad_magic, test_verify_layer1_bad_opcode, test_verify_layer1_bad_jump | 4 |
| Layer 2 (stack safety) | test_verify_layer2_pass, test_verify_layer2_underflow | 2 |

---

## Running the Test Suite

```bash
cd /root/Downloads/synergy-testnet/SynQ
source $HOME/.cargo/env
cargo test --workspace

# Expected output:
# test result: ok. 203 passed; 0 failed; 1 ignored
```

The 1 ignored test is a long-running benchmark test excluded from the default suite.

---

## Test Philosophy

- Every opcode has at least one test
- Every PQC algorithm has a real-crypto test (not mock)
- IR backend has a 22-pattern gap analysis test covering all contract templates
- Server tests exercise real HTTP endpoints (not mocked)
- Determinism tests verify reproducible bytecode across multiple runs
- Verification tests cover both pass and fail cases
- Asset tests include double-spend rejection
- Revert tests include rollback verification

---

End of Test Coverage Report
