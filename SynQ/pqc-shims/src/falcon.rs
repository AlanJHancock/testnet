use pqcrypto::sign::falcon512;
use pqcrypto::prelude::*;

pub const FALCON_PUBLIC_KEY_BYTES: usize = 897;
pub const FALCON_SECRET_KEY_BYTES: usize = 1281;
pub const FALCON_SIGNATURE_BYTES: usize = 666;

pub fn keygen() -> Result<(Vec<u8>, Vec<u8>), String> {
    let (pk, sk) = falcon512::keypair();
    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}

pub fn sign(msg: &[u8], sk_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let sk = falcon512::SecretKey::from_bytes(sk_bytes)
        .map_err(|e| format!("Invalid secret key: {:?}", e))?;
    let sig = falcon512::detached_sign(msg, &sk);
    Ok(sig.as_bytes().to_vec())
}

pub fn verify(msg: &[u8], sig_bytes: &[u8], pk_bytes: &[u8]) -> Result<bool, String> {
    let pk = falcon512::PublicKey::from_bytes(pk_bytes)
        .map_err(|e| format!("Invalid public key: {:?}", e))?;
    let sig = falcon512::DetachedSignature::from_bytes(sig_bytes)
        .map_err(|e| format!("Invalid signature: {:?}", e))?;
    Ok(falcon512::verify_detached_signature(&sig, msg, &pk).is_ok())
}
