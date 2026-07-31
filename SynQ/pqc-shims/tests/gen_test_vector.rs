use synq_pqc_shims::dilithium;

#[test]
fn gen_mldsa65_test_vector() {
    let (pk, sk) = dilithium::keygen();
    let msg = b"Hello SynQ PQC!";
    let sig = dilithium::sign(msg, &sk);
    let valid = dilithium::verify(msg, &sig, &pk);
    
    println!("\n=== ML-DSA-65 Test Vector ===");
    println!("message: {}", String::from_utf8_lossy(msg));
    println!("pk_len: {} bytes", pk.len());
    println!("sig_len: {} bytes", sig.len());
    println!("verify: {}", valid);
    println!("pk_hex: {}", hex::encode(&pk));
    println!("sig_hex: {}", hex::encode(&sig));
    assert!(valid);
}
