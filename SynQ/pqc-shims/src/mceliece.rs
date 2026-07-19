use pqcrypto::kem::mceliece348864;
use pqcrypto::prelude::*;

pub fn keygen() -> Result<(Vec<u8>, Vec<u8>), String> {
    let (pk, sk) = mceliece348864::keypair();
    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}

pub fn encaps(pk_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let pk = mceliece348864::PublicKey::from_bytes(pk_bytes)
        .map_err(|e| format!("Invalid McEliece public key: {:?}", e))?;
    let (ss, ct) = mceliece348864::encapsulate(&pk);
    Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
}

pub fn decaps(ct_bytes: &[u8], sk_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let sk = mceliece348864::SecretKey::from_bytes(sk_bytes)
        .map_err(|e| format!("Invalid McEliece secret key: {:?}", e))?;
    let ct = mceliece348864::Ciphertext::from_bytes(ct_bytes)
        .map_err(|e| format!("Invalid McEliece ciphertext: {:?}", e))?;
    let ss = mceliece348864::decapsulate(&ct, &sk);
    Ok(ss.as_bytes().to_vec())
}
