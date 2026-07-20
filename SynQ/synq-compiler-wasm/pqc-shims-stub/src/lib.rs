//! Pure-Rust no-op stub for synq-pqc-shims — used in WASM builds only.
//! All PQC operations are performed server-side.

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
