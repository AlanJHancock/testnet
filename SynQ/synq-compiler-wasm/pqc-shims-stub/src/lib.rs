//! Pure-Rust no-op stub for synq-pqc-shims — used in WASM builds only.
//!
//! ## ARCHITECTURE DECISION
//!
//! All PQC operations are deferred to the native server. This stub exists
//! because the `pqrust-*` backends require C compilation (PQClean) which
//! cannot target `wasm32-unknown-unknown`. The WASM compiler crate serves
//! in-browser compilation only; PQC signing, verification, key encapsulation,
//! and AEG1 protocol operations are performed exclusively by `synq-server`.
//!
//! See: `docs/PQC_DEFERRAL.md` or `SynQ/docs/WASM_PQC_DEFERRAL.md` for the
//! full Architecture Decision Record.
//!
//! ## SECURITY
//!
//! This stub cannot perform any real cryptographic operation. All `verify()`
//! calls return `false`, all `keygen()` calls return zero-filled vectors,
//! and all `sign()` calls return zero-filled signatures. This ensures the
//! WASM binary can never produce a false positive PQC attestation.

pub mod dilithium {
    pub fn keygen() -> (Vec<u8>, Vec<u8>) { (vec![0u8;32], vec![0u8;32]) }
    pub fn sign(_msg: &[u8], _sk: &[u8]) -> Vec<u8> { vec![0u8;32] }
    pub fn verify(_msg: &[u8], _sig: &[u8], _pk: &[u8]) -> bool { false }
}
pub mod falcon {
    pub fn keygen() -> (Vec<u8>, Vec<u8>) { (vec![0u8;32], vec![0u8;32]) }
    pub fn sign(_msg: &[u8], _sk: &[u8]) -> Vec<u8> { vec![0u8;32] }
    pub fn verify(_msg: &[u8], _sig: &[u8], _pk: &[u8]) -> bool { false }
}
pub mod sphincs {
    pub fn keygen() -> (Vec<u8>, Vec<u8>) { (vec![0u8;32], vec![0u8;32]) }
    pub fn sign(_msg: &[u8], _sk: &[u8]) -> Vec<u8> { vec![0u8;32] }
    pub fn verify(_msg: &[u8], _sig: &[u8], _pk: &[u8]) -> bool { false }
}
pub mod kyber {
    pub fn keygen() -> Result<(Vec<u8>, Vec<u8>), String> { Ok((vec![0u8;32], vec![0u8;32])) }
    pub fn encaps(_pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> { Ok((vec![0u8;32], vec![0u8;32])) }
    pub fn decaps(_ct: &[u8], _sk: &[u8]) -> Result<Vec<u8>, String> { Ok(vec![0u8;32]) }
}
pub mod mceliece {
    pub fn keygen() -> (Vec<u8>, Vec<u8>) { (vec![0u8;32], vec![0u8;32]) }
    pub fn encaps(_pk: &[u8]) -> (Vec<u8>, Vec<u8>) { (vec![0u8;32], vec![0u8;32]) }
    pub fn decaps(_ct: &[u8], _sk: &[u8]) -> Vec<u8> { vec![0u8;32] }
}
pub mod hqc {
    pub fn keygen() -> (Vec<u8>, Vec<u8>) { (vec![0u8;32], vec![0u8;32]) }
    pub fn encaps(_pk: &[u8]) -> (Vec<u8>, Vec<u8>) { (vec![0u8;32], vec![0u8;32]) }
    pub fn decaps(_ct: &[u8], _sk: &[u8]) -> Vec<u8> { vec![0u8;32] }
}
