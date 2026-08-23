#[cfg(feature = "native")]
mod native_impl {
    //! # Kyber PQC Implementation
    //!
    //! Real CRYSTALS-Kyber implementation using the pqcrypto crate.
    //! Provides key encapsulation mechanism for quantum-resistant security.
    
    use pqcrypto::kem::mlkem768;
    use pqcrypto_traits::kem::{PublicKey, SecretKey, Ciphertext, SharedSecret};
    
    // KYBER_PUBLIC_KEY_BYTES/KYBER_SECRET_KEY_BYTES/KYBER_CIPHERTEXT_BYTES/
    // KYBER_SHARED_SECRET_BYTES removed: unreachable (native_impl is private,
    // not re-exported) and referenced nowhere in the workspace, including
    // this file's own tests -- unlike hqc.rs/mceliece.rs's PUBLIC/SECRET
    // pair, which their test modules do assert against.
    
    /// Generate a Kyber-768 keypair for key encapsulation
    pub fn keygen() -> Result<(Vec<u8>, Vec<u8>), String> {
        let (pk, sk) = mlkem768::keypair();
        Ok((
            pk.as_bytes().to_vec(),
            sk.as_bytes().to_vec(),
        ))
    }
    
    /// Encapsulate a shared secret using the recipient's public key
    pub fn encaps(pk_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let pk = mlkem768::PublicKey::from_bytes(pk_bytes)
            .map_err(|e| format!("Failed to create public key: {:?}", e))?;
    
        let (shared_secret, ciphertext) = mlkem768::encapsulate(&pk);
        Ok((
            ciphertext.as_bytes().to_vec(),
            shared_secret.as_bytes().to_vec(),
        ))
    }
    
    /// Decapsulate a shared secret using the recipient's secret key
    pub fn decaps(ct_bytes: &[u8], sk_bytes: &[u8]) -> Result<Vec<u8>, String> {
        let sk = mlkem768::SecretKey::from_bytes(sk_bytes)
            .map_err(|e| format!("Failed to create secret key: {:?}", e))?;
    
        let ct = mlkem768::Ciphertext::from_bytes(ct_bytes)
            .map_err(|e| format!("Failed to create ciphertext: {:?}", e))?;
    
        let shared_secret = mlkem768::decapsulate(&ct, &sk);
        Ok(shared_secret.as_bytes().to_vec())
    }
}

#[cfg(feature = "native")]
pub use native_impl::{keygen, encaps, decaps};

/// WASM stub — KEM operations are server-side only.
#[cfg(feature = "wasm")]
pub fn keygen() -> Result<(Vec<u8>, Vec<u8>), String> {{
    Ok((vec![0u8; 32], vec![0u8; 32]))
}}
#[cfg(feature = "wasm")]
pub fn encaps(_pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {{
    Ok((vec![0u8; 32], vec![0u8; 32]))
}}
#[cfg(feature = "wasm")]
pub fn decaps(_ct: &[u8], _sk: &[u8]) -> Result<Vec<u8>, String> {{
    Ok(vec![0u8; 32])
}}
