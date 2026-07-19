use pqcrypto::sign::sphincsshake128ssimple;
use pqcrypto::prelude::*;

pub const SPHINCS_PUBLIC_KEY_BYTES: usize = 32;
pub const SPHINCS_SECRET_KEY_BYTES: usize = 64;
pub const SPHINCS_SIGNATURE_BYTES: usize = 7856;

pub fn keygen() -> Result<(Vec<u8>, Vec<u8>), String> {
    let (pk, sk) = sphincsshake128ssimple::keypair();
    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}

pub fn sign(msg: &[u8], sk_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let sk = sphincsshake128ssimple::SecretKey::from_bytes(sk_bytes)
        .map_err(|e| format!("Invalid secret key: {:?}", e))?;
    let sig = sphincsshake128ssimple::detached_sign(msg, &sk);
    Ok(sig.as_bytes().to_vec())
}

pub fn verify(msg: &[u8], sig_bytes: &[u8], pk_bytes: &[u8]) -> Result<bool, String> {
    let pk = sphincsshake128ssimple::PublicKey::from_bytes(pk_bytes)
        .map_err(|e| format!("Invalid public key: {:?}", e))?;
    let sig = sphincsshake128ssimple::DetachedSignature::from_bytes(sig_bytes)
        .map_err(|e| format!("Invalid signature: {:?}", e))?;
    Ok(sphincsshake128ssimple::verify_detached_signature(&sig, msg, &pk).is_ok())
}
