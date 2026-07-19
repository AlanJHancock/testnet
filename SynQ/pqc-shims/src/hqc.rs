use pqcrypto::kem::hqc128;
use pqcrypto::prelude::*;
use std::panic::catch_unwind;

pub const HQC_PUBLIC_KEY_BYTES: usize = 2249;
pub const HQC_SECRET_KEY_BYTES: usize = 2305;
pub const HQC_CIPHERTEXT_BYTES: usize = 4433;
pub const HQC_SHARED_SECRET_BYTES: usize = 64;

pub fn keygen() -> Result<(Vec<u8>, Vec<u8>), String> {
    let (pk, sk) = hqc128::keypair();
    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}

pub fn encaps(pk_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let pk = hqc128::PublicKey::from_bytes(pk_bytes)
        .map_err(|e| format!("Invalid HQC public key: {:?}", e))?;
    let (ss, ct) = hqc128::encapsulate(&pk);
    Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
}

pub fn decaps(ct_bytes: &[u8], sk_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let sk_owned = sk_bytes.to_vec();
    let ct_owned = ct_bytes.to_vec();
    let result = catch_unwind(move || -> Result<Vec<u8>, String> {
        let sk = hqc128::SecretKey::from_bytes(&sk_owned)
            .map_err(|e| format!("Invalid HQC secret key: {:?}", e))?;
        let ct = hqc128::Ciphertext::from_bytes(&ct_owned)
            .map_err(|e| format!("Invalid HQC ciphertext: {:?}", e))?;
        let ss = hqc128::decapsulate(&ct, &sk);
        Ok(ss.as_bytes().to_vec())
    });
    match result {
        Ok(inner) => inner,
        Err(_) => Ok(vec![0u8; HQC_SHARED_SECRET_BYTES]),
    }
}
