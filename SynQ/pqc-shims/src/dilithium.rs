#[cfg(feature = "native")]
mod native_impl {
    //! # Dilithium (ML-DSA-65) Shim
    //!
    //! Real implementation using the `pqcrypto-mldsa` crate's ML-DSA-65
    //! (Dilithium3-equivalent parameter set). Previously this module returned
    //! zeroed keys/signatures and hardcoded `true` for verify() — fixed to
    //! perform genuine key generation, signing, and verification.
    
    use pqcrypto_mldsa::mldsa65;
    use pqcrypto_mldsa::mldsa87;
    use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};
    
    pub const DILITHIUM_PUBLIC_KEY_BYTES: usize = mldsa65::public_key_bytes();
    pub const DILITHIUM_SECRET_KEY_BYTES: usize = mldsa65::secret_key_bytes();
    pub const DILITHIUM_SIGNATURE_BYTES: usize = mldsa65::signature_bytes();
    
    /// Generates a real ML-DSA-65 keypair.
    pub fn keygen() -> (Vec<u8>, Vec<u8>) {
        let (pk, sk) = mldsa65::keypair();
        (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
    }
    
    /// Signs a message with a real ML-DSA-65 secret key.
    /// Returns the signed message (signature-prepended payload the
    /// `pqcrypto` API produces) as raw bytes.
    pub fn sign(msg: &[u8], sk: &[u8]) -> Vec<u8> {
        let secret_key = match mldsa65::SecretKey::from_bytes(sk) {
            Ok(k) => k,
            Err(_) => return vec![0u8; DILITHIUM_SIGNATURE_BYTES],
        };
        let signed = mldsa65::sign(msg, &secret_key);
        signed.as_bytes().to_vec()
    }
    
    /// Verifies a real ML-DSA-65 signed message against a public key.
    /// Malformed inputs safely return `false` rather than panicking.
    pub fn verify(msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
        let public_key = match mldsa65::PublicKey::from_bytes(pk) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let signed_message = match mldsa65::SignedMessage::from_bytes(sig) {
            Ok(s) => s,
            Err(_) => return false,
        };
        match mldsa65::open(&signed_message, &public_key) {
            Ok(recovered_msg) => recovered_msg == msg,
            Err(_) => false,
        }
    }
    
    #[cfg(test)]
    mod tests {
        use super::*;
    
        #[test]
        fn keygen_sign_verify_roundtrip() {
            let (pk, sk) = keygen();
            let msg = b"synergy network dilithium test message";
            let sig = sign(msg, &sk);
            assert!(verify(msg, &sig, &pk));
        }
    
        #[test]
        fn tampered_signature_fails_verification() {
            let (pk, sk) = keygen();
            let msg = b"synergy network dilithium test message";
            let mut sig = sign(msg, &sk);
            // Flip a byte inside the signature payload (skip the message that's
            // prepended in a "signed message" format — corrupt near the end).
            let len = sig.len();
            sig[len - 1] ^= 0xFF;
            assert!(!verify(msg, &sig, &pk));
        }
    
        #[test]
        fn tampered_message_fails_verification() {
            let (pk, sk) = keygen();
            let msg = b"synergy network dilithium test message";
            let sig = sign(msg, &sk);
            assert!(!verify(b"a different message entirely", &sig, &pk));
        }
    
        #[test]
        fn wrong_public_key_fails_verification() {
            let (_pk, sk) = keygen();
            let (other_pk, _other_sk) = keygen();
            let msg = b"synergy network dilithium test message";
            let sig = sign(msg, &sk);
            assert!(!verify(msg, &sig, &other_pk));
        }
    
        #[test]
        fn malformed_inputs_return_safe_defaults_not_panic() {
            assert!(!verify(b"msg", &[0u8; 4], &[0u8; 4]));
            assert_eq!(sign(b"msg", &[0u8; 4]).len(), DILITHIUM_SIGNATURE_BYTES);
        }
    }

    // ── ML-DSA-87 (Dilithium5 / NIST Level 5) — V3 account-domain ──────────

    pub const MLDSA87_PUBLIC_KEY_BYTES: usize = mldsa87::public_key_bytes();
    pub const MLDSA87_SECRET_KEY_BYTES: usize = mldsa87::secret_key_bytes();
    pub const MLDSA87_SIGNATURE_BYTES: usize = mldsa87::signature_bytes();

    /// Generates a real ML-DSA-87 keypair (V3 account-domain).
    pub fn keygen_87() -> (Vec<u8>, Vec<u8>) {
        let (pk, sk) = mldsa87::keypair();
        (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
    }

    /// Signs a message with ML-DSA-87.
    pub fn sign_87(msg: &[u8], sk: &[u8]) -> Vec<u8> {
        let secret_key = match mldsa87::SecretKey::from_bytes(sk) {
            Ok(k)  => k,
            Err(_) => return vec![],
        };
        let signed = mldsa87::sign(msg, &secret_key);
        signed.as_bytes().to_vec()
    }

    /// Verifies an ML-DSA-87 signed message against a public key.
    pub fn verify_87(msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
        let public_key = match mldsa87::PublicKey::from_bytes(pk) {
            Ok(k)  => k,
            Err(_) => return false,
        };
        let signed_message = match mldsa87::SignedMessage::from_bytes(sig) {
            Ok(s)  => s,
            Err(_) => return false,
        };
        match mldsa87::open(&signed_message, &public_key) {
            Ok(recovered_msg) => recovered_msg == msg,
            Err(_)            => false,
        }
    }
}

#[cfg(feature = "native")]
pub use native_impl::{keygen, sign, verify, keygen_87, sign_87, verify_87};

/// WASM stub — returns deterministic zero-filled bytes.
/// PQC signing is performed server-side when running in the browser.
#[cfg(feature = "wasm")]
pub fn keygen() -> (Vec<u8>, Vec<u8>) {{
    (vec![0u8; 32], vec![0u8; 32])
}}
#[cfg(feature = "wasm")]
pub fn sign(_msg: &[u8], _sk: &[u8]) -> Vec<u8> {{
    vec![0u8; 32]
}}
#[cfg(feature = "wasm")]
pub fn verify(_msg: &[u8], _sig: &[u8], _pk: &[u8]) -> bool {{
    false
}}
