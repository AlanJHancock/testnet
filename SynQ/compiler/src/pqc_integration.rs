//! PQC integration — feature-gated.
//! With feature "native": real ML-DSA-65 signing via pqcrypto C crates.
//! With feature "wasm":   stub implementation; signing is server-side.

#[cfg(feature = "native")]
mod native {
    use serde::{Deserialize, Serialize};
    use synq_pqc_shims::kyber::{keygen as kyber_keygen, encaps as kyber_encaps, decaps as kyber_decaps};
    use synq_pqc_shims::dilithium;
    use synq_pqc_shims::falcon;
    use synq_pqc_shims::sphincs;
    use synq_pqc_shims::mceliece::{keygen as mceliece_keygen, encaps as mceliece_encaps, decaps as mceliece_decaps};
    use synq_pqc_shims::hqc::{keygen as hqc_keygen, encaps as hqc_encaps, decaps as hqc_decaps};
    
    // ── NIST PQC algorithm name canonicalisation ─────────────────────────────────
    //
    // NIST finalised three PQC standards in 2024 (FIPS 203/204/205) and one in
    // 2025 (FIPS 206).  The new standardised names replace the submission names
    // used during the competition:
    //
    //   Old submission name  │  NIST FIPS standard  │  Canonical string used here
    //   ─────────────────────┼──────────────────────┼────────────────────────────
    //   Dilithium3           │  FIPS 204 (ML-DSA)   │  "ML-DSA-65"
    //   Falcon-512           │  FIPS 206 (FN-DSA)   │  "FN-DSA-512"
    //   SPHINCS+-SHAKE-128s  │  FIPS 205 (SLH-DSA)  │  "SLH-DSA-SHAKE-128s"
    //   Kyber-768            │  FIPS 203 (ML-KEM)   │  "ML-KEM-768"
    //   Classic McEliece     │  (not yet standardised by NIST; retains name)
    //   HQC-128              │  (NIST round-4 alt KEM; retains name)
    //
    // All legacy submission names ("dilithium", "kyber", etc.) are accepted as
    // aliases so that existing sig.json sidecars remain verifiable.
    
    /// Normalise any accepted spelling of an algorithm name to its NIST canonical
    /// form.  Unknown names are returned unchanged so callers can emit a proper
    /// "unsupported" error.
    pub fn canonical_name(algorithm: &str) -> &'static str {
        match algorithm.to_lowercase().as_str() {
            // ML-DSA-65 (FIPS 204)
            "ml-dsa-65" | "mldsa65" | "dilithium" | "dilithium3" => "ML-DSA-65",
            // FN-DSA-512 (FIPS 206)
            "fn-dsa-512" | "fndsa512" | "falcon" | "falcon512" | "falcon-512" => "FN-DSA-512",
            // SLH-DSA-SHAKE-128s (FIPS 205)
            "slh-dsa-shake-128s" | "slhdsa" | "sphincs" | "sphincsplus" | "sphincs+" => "SLH-DSA-SHAKE-128s",
            // ML-KEM-768 (FIPS 203)
            "ml-kem-768" | "mlkem768" | "kyber" | "kyber768" | "kyber-768" => "ML-KEM-768",
            // Non-NIST (still under standardisation)
            "mceliece" | "classicmceliece" | "classic-mceliece" => "Classic-McEliece-348864",
            "hqc" | "hqc128" | "hqc-128" => "HQC-128",
            _ => "unknown",
        }
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub enum PQCSecurityLevel {
        Basic,
        Enhanced,
        Maximum,
        Military,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PQCKeyPair {
        pub algorithm: String,
        pub public_key: Vec<u8>,
        pub private_key: Vec<u8>,
        pub security_level: PQCSecurityLevel,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PQCSignature {
        pub algorithm: String,
        pub signature: Vec<u8>,
        pub message_hash: Vec<u8>,
        pub security_level: PQCSecurityLevel,
    }
    
    #[derive(Debug)]
    pub struct PQCCompiler {
        security_level: PQCSecurityLevel,
    }
    
    impl PQCCompiler {
        pub fn new(security_level: PQCSecurityLevel) -> Self {
            PQCCompiler { security_level }
        }
    
        pub fn generate_keypair(&self, algorithm: &str) -> Result<PQCKeyPair, String> {
            let canon = canonical_name(algorithm);
            let (pk, sk) = match canon {
                "ML-KEM-768" => {
                    match kyber_keygen() {
                        Ok((pk, sk)) => (pk, sk),
                        Err(e) => return Err(format!("ML-KEM-768 key generation failed: {}", e)),
                    }
                }
                "ML-DSA-65"            => dilithium::keygen().map_err(|e| format!("ML-DSA-65 keygen: {}", e))?,
                "FN-DSA-512"           => falcon::keygen().map_err(|e| format!("FN-DSA-512 keygen: {}", e))?,
                "SLH-DSA-SHAKE-128s"   => sphincs::keygen().map_err(|e| format!("SLH-DSA keygen: {}", e))?,
                "Classic-McEliece-348864" => mceliece_keygen().map_err(|e| format!("McEliece keygen: {}", e))?,
                "HQC-128"              => hqc_keygen().map_err(|e| format!("HQC keygen: {}", e))?,
                _ => return Err(format!("Unsupported PQC algorithm: {}", algorithm)),
            };
            Ok(PQCKeyPair {
                algorithm: canon.to_string(),
                public_key: pk,
                private_key: sk,
                security_level: self.security_level.clone(),
            })
        }
    
        /// Signs a message with a real PQC signature.
        /// The `algorithm` field in the returned struct uses the NIST canonical name.
        pub fn sign_message(&self, private_key: &[u8], message: &[u8], algorithm: &str) -> Result<PQCSignature, String> {
            let canon = canonical_name(algorithm);
            let signature = self.create_signature(private_key, message, canon)?;
            Ok(PQCSignature {
                algorithm: canon.to_string(),
                signature,
                message_hash: self.hash_message(message),
                security_level: self.security_level.clone(),
            })
        }
    
        /// Verifies a real PQC signature.  Accepts both canonical and legacy names.
        pub fn verify_signature(&self, public_key: &[u8], signature: &[u8], message: &[u8], algorithm: &str) -> Result<bool, String> {
            let result = match canonical_name(algorithm) {
                "ML-DSA-65"          => dilithium::verify(message, signature, public_key),
                "FN-DSA-512"         => falcon::verify(message, signature, public_key),
                "SLH-DSA-SHAKE-128s" => sphincs::verify(message, signature, public_key),
                _ => return Err(format!("Unsupported signature algorithm: {}", algorithm)),
            };
            result
        }
    
        pub fn encapsulate_key(&self, public_key: &[u8], algorithm: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
            match canonical_name(algorithm) {
                "ML-KEM-768" => {
                    match kyber_encaps(public_key) {
                        Ok((ct, ss)) => Ok((ct, ss)),
                        Err(e) => Err(format!("ML-KEM-768 encapsulation failed: {}", e)),
                    }
                }
                "Classic-McEliece-348864" => mceliece_encaps(public_key).map_err(|e| format!("McEliece encaps failed: {}", e)),
                "HQC-128"                 => hqc_encaps(public_key).map_err(|e| format!("HQC encaps failed: {}", e)),
                _ => Err(format!("Unsupported KEM algorithm: {}", algorithm)),
            }
        }
    
        pub fn decapsulate_key(&self, ciphertext: &[u8], private_key: &[u8], algorithm: &str) -> Result<Vec<u8>, String> {
            match canonical_name(algorithm) {
                "ML-KEM-768" => {
                    match kyber_decaps(ciphertext, private_key) {
                        Ok(ss) => Ok(ss),
                        Err(e) => Err(format!("ML-KEM-768 decapsulation failed: {}", e)),
                    }
                }
                "Classic-McEliece-348864" => mceliece_decaps(ciphertext, private_key).map_err(|e| format!("McEliece decaps failed: {}", e)),
                "HQC-128"                 => hqc_decaps(ciphertext, private_key).map_err(|e| format!("HQC decaps failed: {}", e)),
                _ => Err(format!("Unsupported KEM algorithm: {}", algorithm)),
            }
        }
    
        fn create_signature(&self, private_key: &[u8], message: &[u8], canon: &str) -> Result<Vec<u8>, String> {
            match canon {
                "ML-DSA-65"          => dilithium::sign(message, private_key).map_err(|e| format!("ML-DSA-65 sign failed: {}", e)),
                "FN-DSA-512"         => falcon::sign(message, private_key).map_err(|e| format!("FN-DSA-512 sign failed: {}", e)),
                "SLH-DSA-SHAKE-128s" => sphincs::sign(message, private_key).map_err(|e| format!("SLH-DSA sign failed: {}", e)),
                _ => Err(format!("Unsupported signature algorithm: {}", canon)),
            }
        }
    
        fn hash_message(&self, message: &[u8]) -> Vec<u8> {
            use sha3::{Sha3_256, Digest};
            let mut hasher = Sha3_256::new();
            hasher.update(message);
            hasher.finalize().to_vec()
        }
    
        pub fn get_supported_algorithms(&self) -> Vec<String> {
            vec![
                "ML-DSA-65".to_string(),
                "FN-DSA-512".to_string(),
                "SLH-DSA-SHAKE-128s".to_string(),
                "ML-KEM-768".to_string(),
                "Classic-McEliece-348864".to_string(),
                "HQC-128".to_string(),
            ]
        }
    
        pub fn get_security_level(&self) -> &PQCSecurityLevel {
            &self.security_level
        }
    }
    
    impl Default for PQCCompiler {
        fn default() -> Self {
            PQCCompiler::new(PQCSecurityLevel::Enhanced)
        }
    }
}

#[cfg(feature = "native")]
pub use native::{PQCCompiler, PQCSecurityLevel, PQCKeyPair, PQCSignature, canonical_name};

// ── WASM stubs ──────────────────────────────────────────────────────────────
#[cfg(not(feature = "native"))]
use serde::{Deserialize, Serialize};

#[cfg(not(feature = "native"))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PQCSecurityLevel { Basic, Enhanced, Maximum, Military }

#[cfg(not(feature = "native"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQCKeyPair {
    pub algorithm:      String,
    pub public_key:     Vec<u8>,
    pub private_key:    Vec<u8>,
    pub security_level: PQCSecurityLevel,
}

#[cfg(not(feature = "native"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQCSignature {
    pub algorithm:      String,
    pub signature:      Vec<u8>,
    pub message_hash:   Vec<u8>,
    pub security_level: PQCSecurityLevel,
}

#[cfg(not(feature = "native"))]
pub fn canonical_name(algorithm: &str) -> &'static str {
    match algorithm.to_lowercase().as_str() {
        "ml-dsa-65" | "dilithium" | "dilithium3" => "ML-DSA-65",
        _ => "unknown",
    }
}

/// No-op compiler stub for WASM — signing is performed server-side.
#[cfg(not(feature = "native"))]
#[derive(Debug)]
pub struct PQCCompiler { security_level: PQCSecurityLevel }

#[cfg(not(feature = "native"))]
impl PQCCompiler {
    pub fn new(security_level: PQCSecurityLevel) -> Self { PQCCompiler { security_level } }
    pub fn generate_keypair(&self, _algorithm: &str) -> Result<PQCKeyPair, String> {
        Err("PQC signing not available in WASM build — use server-side /synq/sign".into())
    }
    pub fn sign_message(&self, _sk: &[u8], _msg: &[u8], _alg: &str) -> Result<PQCSignature, String> {
        Err("PQC signing not available in WASM build — use server-side /synq/sign".into())
    }
    pub fn verify_signature(&self, _pk: &[u8], _sig: &[u8], _msg: &[u8], _alg: &str) -> Result<bool, String> {
        Ok(false)
    }
    pub fn get_security_level(&self) -> &PQCSecurityLevel { &self.security_level }
}

#[cfg(not(feature = "native"))]
impl Default for PQCCompiler {
    fn default() -> Self { PQCCompiler::new(PQCSecurityLevel::Enhanced) }
}
