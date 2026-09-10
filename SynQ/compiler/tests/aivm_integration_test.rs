//! Integration test: compile SynQ source → AIVM instructions → execute on AIVM

use synq_compiler::parser::parse;
use synq_compiler::aivm_codegen::compile_to_aivm;
use synq_compiler::ast::SourceUnit;
use aivm::vm::{Avm, StateOverlay, FunctionVisibility};
use aivm::host::{HostFunctions, Value};
use aivm::context::ExecutionContext;
use aivm::receipt::ReceiptStatus;

const COUNTER_SOURCE: &str = "contract Counter {\n  state {\n    count: u64;\n  }\n  impl {\n    @public\n    function init() -> bool {\n      count = 0;\n      return true;\n    }\n\n    @public\n    function increment() -> bool {\n      count = count + 1;\n      return true;\n    }\n\n    @public\n    function get() -> u64 {\n      return count;\n    }\n  }\n}\n";

fn extract_contract(ast: &[SourceUnit]) -> &synq_compiler::ast::ContractDefinition {
    ast.iter().find_map(|u| {
        if let SourceUnit::Contract(c) = u { Some(c) } else { None }
    }).expect("no contract found")
}

#[test]
fn test_compile_counter_to_aivm() {
    let ast = parse(COUNTER_SOURCE).unwrap();
    let contract = extract_contract(&ast);
    assert_eq!(contract.name, "Counter");

    let result = compile_to_aivm(contract, &[]).unwrap();

    // Should have 3 functions (init, increment, get)
    assert_eq!(result.functions.len(), 3);
    assert_eq!(result.functions[0].name, "init");
    assert_eq!(result.functions[1].name, "increment");
    assert_eq!(result.functions[2].name, "get");

    // All should be public
    for f in &result.functions {
        assert_eq!(f.visibility, FunctionVisibility::Public);
    }

    // Should have instructions
    assert!(!result.instructions.is_empty());

    // ABI should have 3 methods
    assert_eq!(result.abi.methods.len(), 3);

    // State schema should have 1 field (count)
    assert_eq!(result.abi.state_schema.len(), 1);
    assert_eq!(result.abi.state_schema[0].name, "count");
}

#[test]
fn test_execute_counter_on_aivm() {
    let ast = parse(COUNTER_SOURCE).unwrap();
    let contract = extract_contract(&ast);
    let result = compile_to_aivm(contract, &[]).unwrap();

    let host = HostFunctions::default_v01();
    let avm = Avm::new(result.instructions, result.functions, host);

    let ctx = ExecutionContext::testnet([0u8; 41], [0u8; 41]);
    let mut state = StateOverlay::new();

    // Find init function
    let init_idx = avm.find_function("init").expect("init function not found");
    let init_result = avm.execute(init_idx, vec![], &ctx, &mut state).unwrap();
    assert_eq!(init_result.receipt.status, ReceiptStatus::Success);

    // count should be 0
    let count = state.read(0).unwrap();
    assert_eq!(count, Value::U64(0));

    // Increment 5 times
    let incr_idx = avm.find_function("increment").expect("increment function not found");
    for _ in 0..5 {
        let r = avm.execute(incr_idx, vec![], &ctx, &mut state).unwrap();
        assert_eq!(r.receipt.status, ReceiptStatus::Success);
    }

    // count should be 5
    let count = state.read(0).unwrap();
    assert_eq!(count, Value::U64(5));

    // Get should return 5
    let get_idx = avm.find_function("get").expect("get function not found");
    let get_result = avm.execute(get_idx, vec![], &ctx, &mut state).unwrap();
    assert_eq!(get_result.receipt.status, ReceiptStatus::Success);
    assert_eq!(get_result.return_value, Some(Value::U64(5)));
}

#[test]
fn test_aivm_abi_selectors() {
    let ast = parse(COUNTER_SOURCE).unwrap();
    let contract = extract_contract(&ast);
    let result = compile_to_aivm(contract, &[]).unwrap();

    // Each method should have a unique selector
    let selectors: Vec<&str> = result.abi.methods.iter()
        .map(|m| m.selector.as_str())
        .collect();
    assert_eq!(selectors.len(), 3);
    assert_ne!(selectors[0], selectors[1]);
    assert_ne!(selectors[1], selectors[2]);
    assert_ne!(selectors[0], selectors[2]);

    for s in &selectors {
        assert!(s.starts_with("0x"));
        assert_eq!(s.len(), 10);
    }
}
// BUG FIX REGRESSION (2026-08-22): `continue`/`break` inside a while loop
// used to compile to an unconditional `Ret`, i.e. they returned from the
// *whole function* immediately instead of affecting only the loop. Any
// function that used `continue` to skip an iteration silently exited with
// no return value (decoded client-side as `null`) the first time it hit
// the `continue`. Root cause: aivm_codegen.rs's `Statement::Continue` /
// `Statement::Break` arms literally emitted `Instruction::Ret`. Fixed by
// tracking a loop_stack of (loop_start, break_patch_indices) so `continue`
// jumps back to the condition re-check and `break` jumps to the loop's end.

const COUNT_EVEN_SOURCE: &str = "contract LoopDemo {\n  impl {\n    @public\n    function countEven(n: u256) -> u256 {\n      let count: u256 = 0;\n      let i: u256 = 1;\n      while (i <= n) {\n        let remainder: u256 = i % 2;\n        if (remainder != 0) {\n          i = i + 1;\n          continue;\n        }\n        count = count + 1;\n        i = i + 1;\n      }\n      return count;\n    }\n  }\n}\n";

#[test]
fn test_aivm_continue_does_not_abort_function() {
    let ast = parse(COUNT_EVEN_SOURCE).unwrap();
    let contract = extract_contract(&ast);
    let result = compile_to_aivm(contract, &[]).unwrap();

    let host = HostFunctions::default_v01();
    let avm = Avm::new(result.instructions, result.functions, host);

    let ctx = ExecutionContext::testnet([0u8; 41], [0u8; 41]);
    let mut state = StateOverlay::new();

    let idx = avm.find_function("countEven").expect("countEven function not found");
    // n = 5 -> even numbers are {2, 4} -> count = 2. Before the fix, the
    // first odd iteration's `continue` returned from the function
    // immediately with no return value at all (None, decoded as null).
    let r = avm.execute(idx, vec![Value::U64(5)], &ctx, &mut state).unwrap();
    assert_eq!(r.receipt.status, ReceiptStatus::Success);
    assert_eq!(r.return_value, Some(Value::U64(2)));

    // n = 10 -> evens {2,4,6,8,10} -> count = 5. Exercises multiple
    // continue/loop-back cycles, not just the very first one.
    let r2 = avm.execute(idx, vec![Value::U64(10)], &ctx, &mut state).unwrap();
    assert_eq!(r2.receipt.status, ReceiptStatus::Success);
    assert_eq!(r2.return_value, Some(Value::U64(5)));

    // n = 0 -> loop body never runs -> count = 0.
    let r3 = avm.execute(idx, vec![Value::U64(0)], &ctx, &mut state).unwrap();
    assert_eq!(r3.receipt.status, ReceiptStatus::Success);
    assert_eq!(r3.return_value, Some(Value::U64(0)));
}

const BREAK_SOURCE: &str = "contract BreakDemo {\n  impl {\n    @public\n    function firstMultiple(n: u256, m: u256) -> u256 {\n      let i: u256 = 1;\n      let found: u256 = 0;\n      while (i <= n) {\n        if (i % m == 0) {\n          found = i;\n          break;\n        }\n        i = i + 1;\n      }\n      return found;\n    }\n  }\n}\n";

#[test]
fn test_aivm_break_exits_loop_not_function() {
    let ast = parse(BREAK_SOURCE).unwrap();
    let contract = extract_contract(&ast);
    let result = compile_to_aivm(contract, &[]).unwrap();

    let host = HostFunctions::default_v01();
    let avm = Avm::new(result.instructions, result.functions, host);

    let ctx = ExecutionContext::testnet([0u8; 41], [0u8; 41]);
    let mut state = StateOverlay::new();

    let idx = avm.find_function("firstMultiple").expect("firstMultiple function not found");
    // First multiple of 3 in [1,20] is 3. Before the fix, `break` also
    // compiled to an unconditional Ret, so this happened to still return
    // early -- but the point of this test is `found` (set right before
    // break) makes it out correctly, proving break targets the loop end
    // and not a mid-function abort that skips the rest of the block.
    let r = avm.execute(idx, vec![Value::U64(20), Value::U64(3)], &ctx, &mut state).unwrap();
    assert_eq!(r.receipt.status, ReceiptStatus::Success);
    assert_eq!(r.return_value, Some(Value::U64(3)));

    // No multiple of 100 in [1,20] -> loop runs to completion -> found stays 0.
    let r2 = avm.execute(idx, vec![Value::U64(20), Value::U64(100)], &ctx, &mut state).unwrap();
    assert_eq!(r2.receipt.status, ReceiptStatus::Success);
    assert_eq!(r2.return_value, Some(Value::U64(0)));
}

// MAP CODEGEN FIX (2026-08-25): `Statement::MapAssignment`/`Expression::
// MapIndex` used to completely ignore the map key -- single-key
// `map[key] = value` did a blind `StoreState(idx)` as if the whole map
// were one scalar, so `mint(0, 100)` then `mint(55, 200)` left
// `balanceOf(0)` returning 200 too (last write wins for EVERY key, not
// just the one written). Multi-key `map[k1][k2] = value` errored outright
// ("nested map assignment not yet supported"), blocking any contract
// using `map<K, map<K,V>>` (e.g. DomainRegistry's 3-level
// `map<address,map<address,map<address,u256>>>`) from compiling at all.
// Fixed by giving the AIVM a real `Value::Map` + `MapGetVal`/`MapSetVal`
// opcodes, with codegen chaining reads and read-forward/write-back'ing
// writes through scratch locals for arbitrary nesting depth.

const SINGLE_MAP_SOURCE: &str = "contract MapDemo {\n  state {\n    balances: map<u256, u256>;\n  }\n  impl {\n    @public\n    function setBalance(id: u256, amount: u256) -> bool {\n      balances[id] = amount;\n      return true;\n    }\n\n    @public\n    function getBalance(id: u256) -> u256 {\n      return balances[id];\n    }\n  }\n}\n";

#[test]
fn test_single_level_map_keys_stay_isolated() {
    let ast = parse(SINGLE_MAP_SOURCE).unwrap();
    let contract = extract_contract(&ast);
    let result = compile_to_aivm(contract, &[]).unwrap();

    let host = HostFunctions::default_v01();
    let avm = Avm::new(result.instructions, result.functions, host);
    let ctx = ExecutionContext::testnet([0u8; 41], [0u8; 41]);
    let mut state = StateOverlay::new();

    let set_idx = avm.find_function("setBalance").expect("setBalance not found");
    let get_idx = avm.find_function("getBalance").expect("getBalance not found");

    // Before the fix, this second write clobbered the FIRST key's value
    // too (both reads below would return 200).
    avm.execute(set_idx, vec![Value::U64(0), Value::U64(100)], &ctx, &mut state).unwrap();
    avm.execute(set_idx, vec![Value::U64(55), Value::U64(200)], &ctx, &mut state).unwrap();
    avm.execute(set_idx, vec![Value::U64(99), Value::U64(300)], &ctx, &mut state).unwrap();

    let r0 = avm.execute(get_idx, vec![Value::U64(0)], &ctx, &mut state).unwrap();
    assert_eq!(r0.return_value, Some(Value::U64(100)), "key 0 must keep its own value");

    let r55 = avm.execute(get_idx, vec![Value::U64(55)], &ctx, &mut state).unwrap();
    assert_eq!(r55.return_value, Some(Value::U64(200)), "key 55 must keep its own value");

    let r99 = avm.execute(get_idx, vec![Value::U64(99)], &ctx, &mut state).unwrap();
    assert_eq!(r99.return_value, Some(Value::U64(300)), "key 99 must keep its own value");

    // Never-written key defaults to zero, not another key's value.
    let r7 = avm.execute(get_idx, vec![Value::U64(7)], &ctx, &mut state).unwrap();
    assert_eq!(r7.return_value, Some(Value::U64(0)), "unset key defaults to 0");
}

const NESTED_3LEVEL_SOURCE: &str = "contract DomainRegistryDemo {\n  state {\n    registry: map<u256, map<u256, map<u256, u256>>>;\n  }\n  impl {\n    @public\n    function setEntry(a: u256, b: u256, c: u256, value: u256) -> bool {\n      registry[a][b][c] = value;\n      return true;\n    }\n\n    @public\n    function getEntry(a: u256, b: u256, c: u256) -> u256 {\n      return registry[a][b][c];\n    }\n  }\n}\n";

#[test]
fn test_three_level_nested_map_assignment_compiles_and_isolates_keys() {
    // This is the exact shape that used to hard-fail codegen with
    // "nested map assignment not yet supported in AIVM codegen"
    // (DomainRegistry's `registry: map<address, map<address, map<address,
    // u256>>>`, mirrored here with u256 keys to stay self-contained).
    let ast = parse(NESTED_3LEVEL_SOURCE).unwrap();
    let contract = extract_contract(&ast);
    let result = compile_to_aivm(contract, &[]).expect("3-level nested map must compile now");

    let host = HostFunctions::default_v01();
    let avm = Avm::new(result.instructions, result.functions, host);
    let ctx = ExecutionContext::testnet([0u8; 41], [0u8; 41]);
    let mut state = StateOverlay::new();

    let set_idx = avm.find_function("setEntry").expect("setEntry not found");
    let get_idx = avm.find_function("getEntry").expect("getEntry not found");

    avm.execute(set_idx, vec![Value::U64(1), Value::U64(2), Value::U64(3), Value::U64(111)], &ctx, &mut state).unwrap();
    avm.execute(set_idx, vec![Value::U64(1), Value::U64(2), Value::U64(4), Value::U64(222)], &ctx, &mut state).unwrap();
    avm.execute(set_idx, vec![Value::U64(1), Value::U64(9), Value::U64(3), Value::U64(333)], &ctx, &mut state).unwrap();
    avm.execute(set_idx, vec![Value::U64(8), Value::U64(2), Value::U64(3), Value::U64(444)], &ctx, &mut state).unwrap();

    let r1 = avm.execute(get_idx, vec![Value::U64(1), Value::U64(2), Value::U64(3)], &ctx, &mut state).unwrap();
    assert_eq!(r1.return_value, Some(Value::U64(111)), "[1][2][3] must keep its own value");

    // Sibling at the innermost level (same a,b, different c) must not
    // collide with [1][2][3] -- this is exactly the read-forward/
    // write-back chain that has to correctly preserve sibling entries at
    // every level it touches.
    let r2 = avm.execute(get_idx, vec![Value::U64(1), Value::U64(2), Value::U64(4)], &ctx, &mut state).unwrap();
    assert_eq!(r2.return_value, Some(Value::U64(222)), "[1][2][4] is a distinct entry from [1][2][3]");

    // Sibling at the middle level (same a, different b) must also stay isolated.
    let r3 = avm.execute(get_idx, vec![Value::U64(1), Value::U64(9), Value::U64(3)], &ctx, &mut state).unwrap();
    assert_eq!(r3.return_value, Some(Value::U64(333)), "[1][9][3] is a distinct entry from [1][2][3]");

    // Sibling at the outer level (different a) must also stay isolated.
    let r4 = avm.execute(get_idx, vec![Value::U64(8), Value::U64(2), Value::U64(3)], &ctx, &mut state).unwrap();
    assert_eq!(r4.return_value, Some(Value::U64(444)), "[8][2][3] is a distinct entry from [1][2][3]");

    // The original [1][2][3] must be unaffected by any of the writes to
    // its siblings above (this is what write-back-clobbering-the-whole-
    // map would break).
    let r1_again = avm.execute(get_idx, vec![Value::U64(1), Value::U64(2), Value::U64(3)], &ctx, &mut state).unwrap();
    assert_eq!(r1_again.return_value, Some(Value::U64(111)), "[1][2][3] must survive sibling writes");

    // Never-written path defaults to zero.
    let r_unset = avm.execute(get_idx, vec![Value::U64(5), Value::U64(6), Value::U64(7)], &ctx, &mut state).unwrap();
    assert_eq!(r_unset.return_value, Some(Value::U64(0)), "unset nested path defaults to 0");
}

// BUG FIX REGRESSION (2026-08-27): calling authority_identity(authority_
// envelope()) on the AIVM backend used to fail every single time with
// AivmError::HostFunctionNotDeclared("auth.identity") -- reproduced live
// via Forge IDE's Run & Debug panel calling init() on the V3Types.synq
// demo contract (which does exactly this in its `init()` body). Root
// cause was two-fold: (1) `authority_envelope()` had no host_idx mapping
// in aivm_codegen.rs at all, so it silently miscompiled to a bogus
// user-function `Call(0)` instead of a host call; (2) even the already-
// declared "auth.require"/"auth.identity" host imports (indices 20/21)
// had zero dispatch arms in host.rs's execute() match, so ANY use of
// either builtin hard-errored on AIVM even though the same call succeeds
// harmlessly on the primary IR/VM backend (which defaults to an empty
// authority envelope today, since no request path -- IR/VM's synq-server
// main.rs included -- populates a real signed one yet). Fixed by adding
// auth.envelope (new import 22) + dispatch arms for auth.envelope/
// auth.require/auth.identity in host.rs, mirroring vm.rs's LoadAuthority/
// AuthRequire/AuthIdentity opcodes (0x51-0x53) exactly, and wiring
// authority_envelope() in aivm_codegen.rs's host_idx table.
const AUTH_IDENTITY_SOURCE: &str = "contract AuthDemo {\n  state {\n    initialised: bool;\n    umaId: UMAIdentity;\n  }\n  impl {\n    @public\n    function init() -> bool {\n      if (initialised) { return false; }\n      initialised = true;\n      let env = authority_identity(authority_envelope());\n      umaId = env;\n      return true;\n    }\n  }\n}\n";

#[test]
fn test_aivm_authority_identity_no_longer_errors() {
    let ast = parse(AUTH_IDENTITY_SOURCE).unwrap();
    let contract = extract_contract(&ast);
    let result = compile_to_aivm(contract, &[]).unwrap();

    let host = HostFunctions::default_v01();
    let avm = Avm::new(result.instructions, result.functions, host);

    let ctx = ExecutionContext::testnet([0u8; 41], [0u8; 41]);
    let mut state = StateOverlay::new();

    let init_idx = avm.find_function("init").expect("init function not found");
    // Before the fix, this returned Err(HostFunctionNotDeclared("auth.identity"))
    // instead of Ok(..) -- exactly the error reported from Forge IDE.
    let r = avm.execute(init_idx, vec![], &ctx, &mut state)
        .expect("init() should execute without HostFunctionNotDeclared");
    assert_eq!(r.receipt.status, ReceiptStatus::Success);
    assert_eq!(r.return_value, Some(Value::Bool(true)));

    // ctx.authority_envelope defaults to empty (Vec::new()), so
    // authority_envelope() -> auth.envelope pushes an empty Bytes, and
    // authority_identity() on a <32-byte envelope pushes a zeroed
    // Bytes32 -- mirroring vm.rs's AuthIdentity returning U256::ZERO for
    // the same short-envelope case. umaId slot index 1 (initialised=0).
    let uma_id = state.read(1).unwrap();
    assert_eq!(uma_id, Value::Bytes32([0u8; 32]));

    // Second call should hit the initialised guard and return false,
    // same short-circuit behavior as every other @public init() guard.
    let r2 = avm.execute(init_idx, vec![], &ctx, &mut state).unwrap();
    assert_eq!(r2.receipt.status, ReceiptStatus::Success);
    assert_eq!(r2.return_value, Some(Value::Bool(false)));
}

// Direct auth.require coverage: with the default empty authority
// envelope, authority_require(...) must return false (envelope too
// short, len < 80) rather than error -- same host-function-declared
// contract as auth.identity above.
const AUTH_REQUIRE_SOURCE: &str = "contract AuthRequireDemo {\n  impl {\n    @public\n    function checkAuth() -> bool {\n      return authority_require(authority_envelope(), authority_envelope());\n    }\n  }\n}\n";

#[test]
fn test_aivm_authority_require_no_longer_errors() {
    let ast = parse(AUTH_REQUIRE_SOURCE).unwrap();
    let contract = extract_contract(&ast);
    let result = compile_to_aivm(contract, &[]).unwrap();

    let host = HostFunctions::default_v01();
    let avm = Avm::new(result.instructions, result.functions, host);

    let ctx = ExecutionContext::testnet([0u8; 41], [0u8; 41]);
    let mut state = StateOverlay::new();

    let idx = avm.find_function("checkAuth").expect("checkAuth function not found");
    let r = avm.execute(idx, vec![], &ctx, &mut state)
        .expect("authority_require should execute without HostFunctionNotDeclared");
    assert_eq!(r.receipt.status, ReceiptStatus::Success);
    assert_eq!(r.return_value, Some(Value::Bool(false)));
}


// ── AEG1 generic frame dispatch + SPHINCS+ verify (2026-09-01 follow-up) ──
// Real pqcrypto-backed coverage for aegis_call/aegis_verify/aegis_decaps and
// sphincs_verify -- these had NO AIVM host binding at all before this fix
// and fell through to the "unknown function" branch, compiling to Call(0)
// (i.e. silently running the contract's FIRST function). See host.rs's
// "pqc.aegis_call" / "pqc.sphincs_verify" arms for the real dispatch.

const SPHINCS_VERIFY_SOURCE: &str = "contract SphincsDemo {\n  impl {\n    @public\n    function probe(m: bytes, s: bytes, pk: bytes) -> bool {\n      return sphincs_verify(m, s, pk);\n    }\n  }\n}\n";

#[test]
fn test_aivm_sphincs_verify_real_crypto() {
    let ast = parse(SPHINCS_VERIFY_SOURCE).unwrap();
    let contract = extract_contract(&ast);
    let result = compile_to_aivm(contract, &[]).unwrap();

    let host = HostFunctions::default_v01();
    let avm = Avm::new(result.instructions, result.functions, host);
    let ctx = ExecutionContext::testnet([0u8; 41], [0u8; 41]);
    let mut state = StateOverlay::new();
    let idx = avm.find_function("probe").expect("probe function not found");

    let (pk, sk) = synq_pqc_shims::sphincs::keygen();
    let message = b"aegis-follow-up-2026-09-01".to_vec();
    let signature = synq_pqc_shims::sphincs::sign(&message, &sk);

    // Valid signature -> true. Before this fix, sphincs_verify had no AIVM
    // host binding and this call compiled to Call(0), silently invoking
    // probe() itself (infinite-recursion-shaped nonsense) instead of ever
    // reaching real crypto.
    let r = avm.execute(idx, vec![
        Value::Bytes(message.clone()),
        Value::Bytes(signature.clone()),
        Value::Bytes(pk.clone()),
    ], &ctx, &mut state).expect("sphincs_verify should execute, not error");
    assert_eq!(r.receipt.status, ReceiptStatus::Success);
    assert_eq!(r.return_value, Some(Value::Bool(true)));

    // Tampered message -> false, not an error and not a false positive.
    let mut tampered = message.clone();
    tampered[0] ^= 0xFF;
    let r2 = avm.execute(idx, vec![
        Value::Bytes(tampered),
        Value::Bytes(signature),
        Value::Bytes(pk),
    ], &ctx, &mut state).unwrap();
    assert_eq!(r2.receipt.status, ReceiptStatus::Success);
    assert_eq!(r2.return_value, Some(Value::Bool(false)));
}

const AEGIS_CALL_SOURCE: &str = "contract AegisDemo {\n  impl {\n    @public\n    function probe(frame: bytes) -> bool {\n      return aegis_call(frame);\n    }\n  }\n}\n";

#[test]
fn test_aivm_aegis_call_ml_dsa_verify_real_crypto() {
    let ast = parse(AEGIS_CALL_SOURCE).unwrap();
    let contract = extract_contract(&ast);
    let result = compile_to_aivm(contract, &[]).unwrap();

    let host = HostFunctions::default_v01();
    let avm = Avm::new(result.instructions, result.functions, host);
    let ctx = ExecutionContext::testnet([0u8; 41], [0u8; 41]);
    let mut state = StateOverlay::new();
    let idx = avm.find_function("probe").expect("probe function not found");

    let (pk, sk) = synq_pqc_shims::dilithium::keygen();
    let message = b"aegis-frame-2026-09-01".to_vec();
    let signature = synq_pqc_shims::dilithium::sign(&message, &sk);

    let frame = synq_pqc_shims::aeg1::Aeg1Request {
        operation: synq_pqc_shims::aeg1::Operation::MlDsaVerify,
        algorithm: synq_pqc_shims::aeg1::Algorithm::MlDsa65,
        args: vec![message, signature, pk],
    }.encode();

    // Before this fix, aegis_call had no AIVM host binding at all and this
    // compiled to Call(0) -- silently invoking probe() itself.
    let r = avm.execute(idx, vec![Value::Bytes(frame)], &ctx, &mut state)
        .expect("aegis_call should execute, not error");
    assert_eq!(r.receipt.status, ReceiptStatus::Success);
    assert_eq!(r.return_value, Some(Value::Bool(true)));
}

#[test]
fn test_aivm_aegis_call_malformed_frame_returns_false_not_error() {
    let ast = parse(AEGIS_CALL_SOURCE).unwrap();
    let contract = extract_contract(&ast);
    let result = compile_to_aivm(contract, &[]).unwrap();

    let host = HostFunctions::default_v01();
    let avm = Avm::new(result.instructions, result.functions, host);
    let ctx = ExecutionContext::testnet([0u8; 41], [0u8; 41]);
    let mut state = StateOverlay::new();
    let idx = avm.find_function("probe").expect("probe function not found");

    // Not a valid AEG1 frame at all (wrong magic) -- must fail closed with
    // Bool(false), matching the native VM's OpCode::AegisCall behavior for
    // a malformed frame, not panic or propagate a VM-level error.
    let r = avm.execute(idx, vec![Value::Bytes(b"not-an-aeg1-frame".to_vec())], &ctx, &mut state)
        .expect("a malformed frame should be a normal false result, not a VM error");
    assert_eq!(r.receipt.status, ReceiptStatus::Success);
    assert_eq!(r.return_value, Some(Value::Bool(false)));
}

#[test]
fn test_aivm_aegis_call_ml_kem_decaps_rejected_deterministic() {
    // ACTS-15 §3: ML-KEM decapsulate must be REJECTED through the generic
    // aegis_call/aegis_verify/aegis_decaps frame path (which dispatches via
    // process_frame_deterministic, exactly like the native VM's AegisCall
    // opcode 0x8F) even though AIVM itself is a dry-run sandbox -- the
    // separate *typed* `kyber_decaps` builtin (host.rs, HostCall 25) is the
    // intentional off-chain-only escape hatch for that; this generic path
    // must behave identically to the deterministic on-chain VM.
    let ast = parse(AEGIS_CALL_SOURCE).unwrap();
    let contract = extract_contract(&ast);
    let result = compile_to_aivm(contract, &[]).unwrap();

    let host = HostFunctions::default_v01();
    let avm = Avm::new(result.instructions, result.functions, host);
    let ctx = ExecutionContext::testnet([0u8; 41], [0u8; 41]);
    let mut state = StateOverlay::new();
    let idx = avm.find_function("probe").expect("probe function not found");

    let (pk, sk) = synq_pqc_shims::kyber::keygen().expect("kyber keygen");
    let (ciphertext, _shared_secret) = synq_pqc_shims::kyber::encaps(&pk).expect("kyber encaps");

    let frame = synq_pqc_shims::aeg1::Aeg1Request {
        operation: synq_pqc_shims::aeg1::Operation::MlKemDecaps,
        algorithm: synq_pqc_shims::aeg1::Algorithm::MlKem768,
        args: vec![ciphertext, sk],
    }.encode();

    let r = avm.execute(idx, vec![Value::Bytes(frame)], &ctx, &mut state)
        .expect("a rejected MlKemDecaps request is a normal false result, not a VM error");
    assert_eq!(r.receipt.status, ReceiptStatus::Success);
    assert_eq!(r.return_value, Some(Value::Bool(false)));
}

// ── U256 support (2026-09-09) ──────────────────────────────────────────
// A SynQ source literal bigger than u64::MAX used to fail to COMPILE at
// all ("big number ... too large for u64") -- aivm_codegen.rs's
// Literal::BigNumber arm had no fallback. It now falls back to the new
// PushU256 opcode. These tests exercise that through the real
// parse -> compile_to_aivm -> execute pipeline, plus the ABI type mapping
// that was silently mislabeling every `u256` field/param as `u128`.

// U256 support, part 2 (2026-09-10): a literal strictly between u64::MAX
// and u128::MAX arrives from the parser as `Literal::Number(u128)`, NOT
// `Literal::BigNumber` (that variant is reserved for values that don't
// even fit u128 -- see ast.rs's doc comment). aivm_codegen.rs's
// `Literal::Number` arm used to do an unconditional `*n as u64`, a SILENT
// WRAPPING truncation with no error at all -- worse than the BigNumber
// gap fixed just above (which at least hard-errored before that fix).
// Found via `asset_create("Widget", 18446744073709563960)` silently
// becoming `asset_create("Widget", 12344)`.
const MID_RANGE_LITERAL_SOURCE: &str = "contract MidRangeLiteral {\n  impl {\n    @public\n    function getBig() -> u256 {\n      return 18446744073709563960;\n    }\n  }\n}\n";

#[test]
fn test_literal_number_between_u64_and_u128_max_does_not_wrap() {
    let ast = parse(MID_RANGE_LITERAL_SOURCE).unwrap();
    let contract = extract_contract(&ast);
    let result = compile_to_aivm(contract, &[]).unwrap();

    let host = HostFunctions::default_v01();
    let avm = Avm::new(result.instructions, result.functions, host);
    let ctx = ExecutionContext::testnet([0u8; 41], [0u8; 41]);
    let mut state = StateOverlay::new();

    let idx = avm.find_function("getBig").expect("getBig not found");
    let r = avm.execute(idx, vec![], &ctx, &mut state).unwrap();
    assert_eq!(r.receipt.status, ReceiptStatus::Success);
    // Must carry the exact literal value -- NOT wrapped modulo 2^64 down
    // to 12344. A bare literal return pushes straight through as
    // Value::U256 (PushU256 does not itself narrow; narrowing only
    // happens on arithmetic results via from_u256_shrink), so compare
    // against the U256 form rather than asserting a specific variant.
    assert_eq!(r.return_value, Some(Value::U256(ruint::aliases::U256::from(18446744073709563960u128))));
}

const BIG_LITERAL_SOURCE: &str = "contract BigLiteral {\n  impl {\n    @public\n    function getMax() -> u256 {\n      return 115792089237316195423570985008687907853269984665640564039457584007913129639935;\n    }\n  }\n}\n";

#[test]
fn test_u256_literal_above_u64_max_compiles_and_executes() {
    let ast = parse(BIG_LITERAL_SOURCE).unwrap();
    let contract = extract_contract(&ast);
    // This used to fail at compile_to_aivm() with "big number ... too
    // large for u64" -- now it succeeds via the PushU256 fallback.
    let result = compile_to_aivm(contract, &[]).unwrap();

    let host = HostFunctions::default_v01();
    let avm = Avm::new(result.instructions, result.functions, host);
    let ctx = ExecutionContext::testnet([0u8; 41], [0u8; 41]);
    let mut state = StateOverlay::new();

    let idx = avm.find_function("getMax").expect("getMax not found");
    let r = avm.execute(idx, vec![], &ctx, &mut state).unwrap();
    assert_eq!(r.receipt.status, ReceiptStatus::Success);
    assert_eq!(
        r.return_value,
        Some(Value::U256(ruint::aliases::U256::MAX)),
        "u256::MAX literal must round-trip exactly, not truncate"
    );
}

const U256_STATE_SOURCE: &str = "contract U256State {\n  state {\n    total: u256;\n    amount: u256;\n  }\n  impl {\n    @public\n    function setAmount(v: u256) -> bool {\n      amount = v;\n      return true;\n    }\n\n    @public\n    function addToTotal() -> u256 {\n      total = total + amount;\n      return total;\n    }\n  }\n}\n";

#[test]
fn test_u256_state_var_abi_mapping() {
    let ast = parse(U256_STATE_SOURCE).unwrap();
    let contract = extract_contract(&ast);
    let result = compile_to_aivm(contract, &[]).unwrap();

    // Both u256 state vars must map to AbiType::U256 in the ABI schema,
    // not AbiType::U128 (the old mislabeling).
    let total_field = result.abi.state_schema.iter().find(|f| f.name == "total").unwrap();
    assert_eq!(total_field.field_type, aivm::abi::AbiType::U256);
    let amount_field = result.abi.state_schema.iter().find(|f| f.name == "amount").unwrap();
    assert_eq!(amount_field.field_type, aivm::abi::AbiType::U256);
}

#[test]
fn test_u256_state_var_arithmetic_above_u128_max() {
    let ast = parse(U256_STATE_SOURCE).unwrap();
    let contract = extract_contract(&ast);
    let result = compile_to_aivm(contract, &[]).unwrap();

    let host = HostFunctions::default_v01();
    let avm = Avm::new(result.instructions, result.functions, host);
    let ctx = ExecutionContext::testnet([0u8; 41], [0u8; 41]);
    let mut state = StateOverlay::new();

    // Seed `amount` (state index 1) directly above u128::MAX.
    let big = ruint::aliases::U256::from(1u128) << 200;
    state.write(1, Value::U256(big));

    let idx = avm.find_function("addToTotal").expect("addToTotal not found");
    let r = avm.execute(idx, vec![], &ctx, &mut state).unwrap();
    assert_eq!(r.receipt.status, ReceiptStatus::Success);
    assert_eq!(r.return_value, Some(Value::from_u256_shrink(big)));
}
