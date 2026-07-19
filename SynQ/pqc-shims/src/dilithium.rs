use pqcrypto::sign::mldsa65;
use pqcrypto::prelude::*;

pub const DILITHIUM_PUBLIC_KEY_BYTES: usize = 1952;
pub const DILITHIUM_SECRET_KEY_BYTES: usize = 4032;
pub const DILITHIUM_SIGNATURE_BYTES: usize = 3309;

pub fn keygen() -> Result<(Vec<u8>, Vec<u8>), String> {
    let (pk, sk) = mldsa65::keypair();
    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}

pub fn sign(msg: &[u8], sk_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let sk = mldsa65::SecretKey::from_bytes(sk_bytes)
        .map_err(|e| format!("Invalid secret key: {:?}", e))?;
    let sig = mldsa65::detached_sign(msg, &sk);
    Ok(sig.as_bytes().to_vec())
}

pub fn verify(msg: &[u8], sig_bytes: &[u8], pk_bytes: &[u8]) -> Result<bool, String> {
    let pk = mldsa65::PublicKey::from_bytes(pk_bytes)
        .map_err(|e| format!("Invalid public key: {:?}", e))?;
    let sig = mldsa65::DetachedSignature::from_bytes(sig_bytes)
        .map_err(|e| format!("Invalid signature: {:?}", e))?;
    Ok(mldsa65::verify_detached_signature(&sig, msg, &pk).is_ok())
}
