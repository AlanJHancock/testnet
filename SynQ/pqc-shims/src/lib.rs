//! # SynQ PQC Shims
//!
//! Post-Quantum Cryptography (PQC) implementations for the SynQ programming
//! language using the `pqcrypto` crate family.
//!
//! ## Modules
//!
//! - [`aeg1`] — AEG1 wire protocol (Aegis PQC framing, dispatch, cost model)
//! - [`secret`] — Secret-byte zeroization and side-channel posture (ACTS-VM-010)
//! - [`dilithium`] — ML-DSA (Dilithium) parameter sets: ML-DSA-65, ML-DSA-87
//! - [`falcon`] — FN-DSA (Falcon) parameter set: FN-DSA-512
//! - [`kyber`] — ML-KEM (Kyber) parameter set: ML-KEM-768
//! - [`hqc`] — HQC-KEM parameter sets (optional `hqckem` feature)
//! - [`mceliece`] — Classic McEliece (de-scoped, not in AEG1 profile)
//! - [`sphincs`] — SLH-DSA / SPHINCS+ (de-scoped, not in AEG1 profile)
//!
//! ## ACTS-15 Conformance
//!
//! This crate conforms to ACTS-15 requirements ACTS-VM-001 through
//! ACTS-VM-011. See the [`secret`] module for the ACTS-VM-010 conformance
//! report on zeroization limitations and side-channel non-claims.
//!
//! ## Security Boundary
//!
//! All implementations use the actual cryptographic algorithms from
//! `pqcrypto`. This crate is suitable for production use **when deployed
//! with adequate platform isolation** (TEE, SE, or VM sandboxing). It
//! does NOT claim formal side-channel resistance on every target. See
//! [`secret::CONFORMANCE_REPORT`] for details.

pub mod aeg1;
pub mod dilithium;
pub mod falcon;
pub mod hqc;
pub mod kyber;
pub mod mceliece;
pub mod secret;
pub mod sphincs;

// Re-export the conformance report at the crate root for visibility
pub use secret::{conformance_report, SecretBytes, zeroize_slice, zeroize_vec};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
