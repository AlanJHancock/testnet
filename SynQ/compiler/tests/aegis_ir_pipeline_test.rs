//! End-to-end tests for the typed PQC convenience builtins
//! (dilithium_verify / falcon_verify / sphincs_verify / kyber_decaps)
//! through the REAL compile_ir() -> QuantumVM deterministic execution path.
//!
//! These exist because the IR lowering for these builtins used to push raw
//! args and emit the frame-based AegisCall opcode directly, which popped
//! only the LAST arg, failed to parse it as an AEG1 frame, and always
//! returned Bool(false) -- so every deterministic (non-AIVM) call to any of
//! these builtins silently returned false regardless of whether the input
//! was actually valid. Fixed 2026-08-31 via the new AegisTypedCall opcode
//! (dilithium_verify/falcon_verify/kyber_decaps) and a legacy-opcode route
//! (sphincs_verify, which has no AEG1 operation slot at all).
//!
//! vm/tests/integration_test.rs already covers the underlying legacy
//! opcodes (DilithiumVerify etc.) directly via hand-assembled bytecode --
//! these tests instead go through the FULL pipeline real contracts use:
//! SynQ source -> compile_ir() -> QuantumVM::call_function().

use synq_compiler::compile_ir;
use quantumvm::{QuantumVM, Value};

fn verify_bool(source: &str, func: &str, args: Vec<Value>) -> bool {
    let result = compile_ir(source).expect("compile failed");
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&result.bytecode).expect("load failed");
    let res = vm.call_function(func, &args).expect("call failed");
    match res.expect("no return value") {
        Value::Bool(b) => b,
        other => panic!("expected Bool, got {:?}", other),
    }
}

const DILITHIUM_SRC: &str = r#"
contract DilithiumProbe {
  state { dummy: u256; }
  function verifyIt(message: bytes, signature: bytes, publicKey: bytes) -> bool {
    return dilithium_verify(message, signature, publicKey);
  }
}
"#;

#[test]
fn dilithium_verify_through_ir_pipeline_accepts_valid_signature() {
    let (pk, sk) = synq_pqc_shims::dilithium::keygen();
    let message = b"Hello, quantum world!".to_vec();
    let signature = synq_pqc_shims::dilithium::sign(&message, &sk);
    let ok = verify_bool(DILITHIUM_SRC, "verifyIt", vec![
        Value::Bytes(message), Value::Bytes(signature), Value::Bytes(pk),
    ]);
    assert!(ok, "valid ML-DSA-65 signature must verify true through the real deterministic pipeline");
}

#[test]
fn dilithium_verify_through_ir_pipeline_rejects_forged_signature() {
    let (pk, _sk) = synq_pqc_shims::dilithium::keygen();
    let (_other_pk, other_sk) = synq_pqc_shims::dilithium::keygen();
    let message = b"Hello, quantum world!".to_vec();
    let forged = synq_pqc_shims::dilithium::sign(&message, &other_sk);
    let ok = verify_bool(DILITHIUM_SRC, "verifyIt", vec![
        Value::Bytes(message), Value::Bytes(forged), Value::Bytes(pk),
    ]);
    assert!(!ok, "a signature made with a different keypair must not verify");
}

const FALCON_SRC: &str = r#"
contract FalconProbe {
  state { dummy: u256; }
  function verifyIt(message: bytes, signature: bytes, publicKey: bytes) -> bool {
    return falcon_verify(message, signature, publicKey);
  }
}
"#;

#[test]
fn falcon_verify_through_ir_pipeline_accepts_valid_signature() {
    let (pk, sk) = synq_pqc_shims::falcon::keygen();
    let message = b"Hello, quantum world!".to_vec();
    let signature = synq_pqc_shims::falcon::sign(&message, &sk);
    let ok = verify_bool(FALCON_SRC, "verifyIt", vec![
        Value::Bytes(message), Value::Bytes(signature), Value::Bytes(pk),
    ]);
    assert!(ok, "valid FN-DSA-512 signature must verify true through the real deterministic pipeline");
}

#[test]
fn falcon_verify_through_ir_pipeline_rejects_forged_signature() {
    let (pk, _sk) = synq_pqc_shims::falcon::keygen();
    let (_other_pk, other_sk) = synq_pqc_shims::falcon::keygen();
    let message = b"Hello, quantum world!".to_vec();
    let forged = synq_pqc_shims::falcon::sign(&message, &other_sk);
    let ok = verify_bool(FALCON_SRC, "verifyIt", vec![
        Value::Bytes(message), Value::Bytes(forged), Value::Bytes(pk),
    ]);
    assert!(!ok, "a signature made with a different keypair must not verify");
}

const SPHINCS_SRC: &str = r#"
contract SphincsProbe {
  state { dummy: u256; }
  function verifyIt(message: bytes, signature: bytes, publicKey: bytes) -> bool {
    return sphincs_verify(message, signature, publicKey);
  }
}
"#;

#[test]
fn sphincs_verify_through_ir_pipeline_accepts_valid_signature() {
    let (pk, sk) = synq_pqc_shims::sphincs::keygen();
    let message = b"Hello, quantum world!".to_vec();
    let signature = synq_pqc_shims::sphincs::sign(&message, &sk);
    let ok = verify_bool(SPHINCS_SRC, "verifyIt", vec![
        Value::Bytes(message), Value::Bytes(signature), Value::Bytes(pk),
    ]);
    assert!(ok, "valid SPHINCS+ signature must verify true (legacy-opcode route)");
}

#[test]
fn sphincs_verify_through_ir_pipeline_rejects_forged_signature() {
    let (pk, _sk) = synq_pqc_shims::sphincs::keygen();
    let (_other_pk, other_sk) = synq_pqc_shims::sphincs::keygen();
    let message = b"Hello, quantum world!".to_vec();
    let forged = synq_pqc_shims::sphincs::sign(&message, &other_sk);
    let ok = verify_bool(SPHINCS_SRC, "verifyIt", vec![
        Value::Bytes(message), Value::Bytes(forged), Value::Bytes(pk),
    ]);
    assert!(!ok, "a signature made with a different keypair must not verify");
}

const KYBER_DECAPS_SRC: &str = r#"
contract KyberDecapsProbe {
  state { dummy: u256; }
  function decapsIt(ciphertext: bytes, secretKey: bytes) -> bytes {
    return kyber_decaps(ciphertext, secretKey);
  }
}
"#;

#[test]
fn kyber_decaps_through_ir_pipeline_is_rejected_deterministically() {
    // ACTS-15 §3: ML-KEM decapsulate requires a secret key and must NEVER be
    // reachable from deterministic on-chain execution. It must be rejected
    // as a hard error/revert -- not silently return an empty/false value
    // that could be confused with a legitimate (even if empty) result.
    let (pk, sk) = synq_pqc_shims::kyber::keygen().expect("keygen");
    let (ciphertext, _shared_secret) = synq_pqc_shims::kyber::encaps(&pk).expect("encaps");

    let result = compile_ir(KYBER_DECAPS_SRC).expect("compile failed");
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&result.bytecode).expect("load failed");
    let res = vm.call_function("decapsIt", &[
        Value::Bytes(ciphertext), Value::Bytes(sk),
    ]);
    assert!(res.is_err(), "ML-KEM decaps must be rejected (Err), not silently succeed, in the deterministic VM path -- got {:?}", res);
}

// ── PqcUnsupported: builtins with no AEG1 operation slot at all ───────────
//
// Added 2026-09-01. kyber_encapsulate, mceliece_encapsulate/decapsulate, and
// hqc_encapsulate/decapsulate used to fall through to the generic
// frame-based AegisCall opcode with raw un-framed args, which reliably
// failed to parse as an AEG1 frame and silently returned Bool(false)/empty
// bytes -- indistinguishable from a real "operation completed" result.
// AEG1/ACTS-15 defines only MlKemDecaps/MlDsaVerify/FnDsaVerify, so these
// five now lower to a dedicated opcode that always hard-reverts naming the
// exact builtin, exactly as kyber_decaps already does for its own
// ACTS-15 §3 rejection above.

fn assert_pqc_unsupported(source: &str, func: &str, args: Vec<Value>, builtin_name: &str) {
    let result = compile_ir(source).expect("compile failed");
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&result.bytecode).expect("load failed");
    let res = vm.call_function(func, &args);
    assert!(res.is_err(), "{} must be rejected (Err), not silently return false/empty bytes -- got {:?}", builtin_name, res);
    let err_msg = format!("{:?}", res.unwrap_err());
    assert!(err_msg.contains(builtin_name), "error must name the exact builtin ({}) so callers can tell which unsupported op was hit -- got: {}", builtin_name, err_msg);
    assert!(err_msg.contains("AEG1"), "error must explain the AEG1 protocol limitation -- got: {}", err_msg);
}

const KYBER_ENCAPSULATE_SRC: &str = r#"
contract KyberEncapsulateProbe {
  state { dummy: u256; }
  function encapsIt(publicKey: bytes) -> bytes {
    return kyber_encapsulate(publicKey);
  }
}
"#;

#[test]
fn kyber_encapsulate_through_ir_pipeline_is_rejected_deterministically() {
    let (pk, _sk) = synq_pqc_shims::kyber::keygen().expect("keygen");
    assert_pqc_unsupported(KYBER_ENCAPSULATE_SRC, "encapsIt", vec![Value::Bytes(pk)], "kyber_encapsulate");
}

const MCELIECE_ENCAPSULATE_SRC: &str = r#"
contract McElieceEncapsulateProbe {
  state { dummy: u256; }
  function encapsIt(publicKey: bytes) -> bytes {
    return mceliece_encapsulate(publicKey);
  }
}
"#;

#[test]
fn mceliece_encapsulate_through_ir_pipeline_is_rejected_deterministically() {
    assert_pqc_unsupported(MCELIECE_ENCAPSULATE_SRC, "encapsIt", vec![Value::Bytes(vec![0u8; 32])], "mceliece_encapsulate");
}

const MCELIECE_DECAPSULATE_SRC: &str = r#"
contract McElieceDecapsulateProbe {
  state { dummy: u256; }
  function decapsIt(ciphertext: bytes, secretKey: bytes) -> bytes {
    return mceliece_decapsulate(ciphertext, secretKey);
  }
}
"#;

#[test]
fn mceliece_decapsulate_through_ir_pipeline_is_rejected_deterministically() {
    assert_pqc_unsupported(MCELIECE_DECAPSULATE_SRC, "decapsIt", vec![Value::Bytes(vec![0u8; 32]), Value::Bytes(vec![0u8; 32])], "mceliece_decapsulate");
}

const HQC_ENCAPSULATE_SRC: &str = r#"
contract HqcEncapsulateProbe {
  state { dummy: u256; }
  function encapsIt(publicKey: bytes) -> bytes {
    return hqc_encapsulate(publicKey);
  }
}
"#;

#[test]
fn hqc_encapsulate_through_ir_pipeline_is_rejected_deterministically() {
    assert_pqc_unsupported(HQC_ENCAPSULATE_SRC, "encapsIt", vec![Value::Bytes(vec![0u8; 32])], "hqc_encapsulate");
}

const HQC_DECAPSULATE_SRC: &str = r#"
contract HqcDecapsulateProbe {
  state { dummy: u256; }
  function decapsIt(ciphertext: bytes, secretKey: bytes) -> bytes {
    return hqc_decapsulate(ciphertext, secretKey);
  }
}
"#;

#[test]
fn hqc_decapsulate_through_ir_pipeline_is_rejected_deterministically() {
    assert_pqc_unsupported(HQC_DECAPSULATE_SRC, "decapsIt", vec![Value::Bytes(vec![0u8; 32]), Value::Bytes(vec![0u8; 32])], "hqc_decapsulate");
}
