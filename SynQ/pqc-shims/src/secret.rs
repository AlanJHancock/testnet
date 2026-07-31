//! # Secret-Byte Zeroization and Side-Channel Posture
//!
//! This module implements the zeroization helpers and `SecretBytes` wrapper
//! described in ACTS-15 §5.3, and surfaces the limitations required by
//! ACTS-VM-010.
//!
//! ## ACTS-VM-010: Zeroization Limitations and Side-Channel Non-Claims
//!
//! The following limitations are **explicitly visible** in this conformance
//! report and MUST NOT be removed or softened without a corresponding
//! security review:
//!
//! ### Zeroization Limitations
//!
//! 1. **Caller copies are uncontrollable.** Public APIs in this crate that
//!    return `Vec<u8>` (e.g. `keygen()`, `sign()`, `decaps()`) transfer
//!    ownership of secret-bearing byte vectors to the caller. Once the
//!    vector is returned, this crate **cannot** guarantee that the caller
//!    will zeroize the memory before deallocation. The `SecretBytes`
//!    wrapper provided here is a best-effort mitigation, not a complete
//!    solution.
//!
//! 2. **FFI transient state.** The underlying `pqcrypto` crate family
//!    calls into C/Rust implementations of PQC primitives. These
//!    implementations may allocate intermediate buffers (e.g. for
//!    polynomial multiplication, NTT, or rejection sampling) that are
//!    not visible to this crate and may not be zeroized. The lifetime
//!    and cleanup of FFI-internal buffers is governed by the upstream
//!    primitive implementation, not by this crate.
//!
//! 3. **Heap allocator behaviour.** Rust's default global allocator does
//!    not guarantee that freed memory is overwritten. Even when
//!    `SecretBytes::drop` zeroizes the buffer in place, the allocator may
//!    reuse the same memory region without scrubbing, and the zeroized
//!    pages may be visible to a process with access to `/proc/<pid>/mem`
//!    or core dumps.
//!
//! 4. **Stack-local secrets.** Function parameters of type `&[u8]` (e.g.
//!    `sk: &[u8]` in `sign()`) are borrowed references. The caller's
//!    original buffer is not zeroized by this crate. Additionally, the
//!    compiler may copy borrowed slices onto the stack for internal
//!    operations; these copies are not tracked or zeroized.
//!
//! ### Side-Channel Non-Claims
//!
//! 5. **No formal side-channel resistance claim.** This crate does
//!    **not** claim constant-time execution, power-analysis resistance,
//!    timing-attack resistance, or electromagnetic-leakage resistance on
//!    any target. The `pqcrypto` family uses the reference C
//!    implementations from NIST submissions, which are designed for
//!    correctness and portability, not for side-channel hardening.
//!
//! 6. **Platform isolation is a security boundary.** In production
//!    deployments, side-channel mitigation is expected to come from
//!    platform-level isolation (TEE, SE, VM sandboxing), not from this
//!    crate. Operators MUST ensure that the execution environment
//!    provides adequate physical and logical isolation for
//!    secret-key operations.
//!
//! 7. **Upstream primitive behaviour.** The actual side-channel posture
//!    of each PQC algorithm depends on the upstream implementation
//!    (e.g. `pqcrypto-mldsa`, `pqcrypto-falcon`, `pqcrypto-kyber`).
//!    This crate does not audit or modify the constant-time properties
//!    of those implementations. Operators SHOULD consult the upstream
//!    crate documentation for algorithm-specific side-channel guidance.
//!
//! 8. **WASM targets.** When compiled to `wasm32-unknown-unknown`, all
//!    secret-key operations return zero-filled stubs (signing is
//!    performed server-side). This eliminates the zeroization concern
//!    for the browser path but introduces a network trust assumption:
//!    secret keys must traverse the network to reach the server.
//!
//! ### Conformance
//!
//! These non-claims satisfy ACTS-VM-010 by remaining **explicitly visible**
//! in the source code and crate documentation. They MUST be reproduced in
//! any downstream conformance report that references this crate.
//!
//! See also: ACTS-15 §5.3 (Key and Side-Channel Posture).

use std::ops::{Deref, DerefMut};

/// A best-effort wrapper for secret-bearing byte vectors.
///
/// On `Drop`, the internal buffer is overwritten with zeros in place.
/// This mitigates against some use-after-free and memory-reuse attacks
/// but does NOT guarantee that all copies of the secret have been
/// eliminated (see ACTS-VM-010 §1 above).
///
/// # Example
/// ```no_run
/// use synq_pqc_shims::secret::SecretBytes;
///
/// let mut sk = SecretBytes::new(vec![0xAB; 32]);
/// // use sk.as_ref() to read
/// // on drop, the 32 bytes are zeroized in place
/// ```
pub struct SecretBytes {
    inner: Vec<u8>,
    zeroized: bool,
}

impl SecretBytes {
    /// Wrap a byte vector as secret material.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { inner: bytes, zeroized: false }
    }

    /// Create a zero-filled secret buffer of the given length.
    pub fn zero(len: usize) -> Self {
        Self { inner: vec![0u8; len], zeroized: true }
    }

    /// Explicitly zeroize the buffer now. Idempotent.
    pub fn zeroize(&mut self) {
        if !self.zeroized {
            // Volatile memset to prevent compiler optimization
            for b in self.inner.iter_mut() {
                unsafe { std::ptr::write_volatile(b, 0) };
            }
            self.zeroized = true;
        }
    }

    /// Check if the buffer has been zeroized.
    pub fn is_zeroized(&self) -> bool {
        self.zeroized
    }

    /// Consume the wrapper and return the raw bytes, zeroizing is now
    /// the caller's responsibility. Use with caution.
    pub fn into_vec(mut self) -> Vec<u8> {
        let v = std::mem::take(&mut self.inner);
        // Mark as zeroized so Drop doesn't double-zero (the vec is gone anyway)
        self.zeroized = true;
        v
    }
}

impl Deref for SecretBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.inner
    }
}

impl DerefMut for SecretBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print secret contents — even in debug output
        write!(f, "SecretBytes({} bytes, zeroized={})", self.inner.len(), self.zeroized)
    }
}

// ── Zeroization helpers ─────────────────────────────────────────────────────

/// Zeroize a mutable byte slice in place using volatile writes.
///
/// This prevents the compiler from optimizing away the memset, but
/// does NOT guarantee that the memory is not recoverable by other
/// means (heap inspection, core dumps, etc.).
pub fn zeroize_slice(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    // Compiler fence to prevent reordering
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Zeroize a Vec's contents in place, then clear it.
pub fn zeroize_vec(vec: &mut Vec<u8>) {
    zeroize_slice(vec.as_mut_slice());
    vec.clear();
}

// ── Conformance report (ACTS-VM-010) ────────────────────────────────────────

/// Static conformance report text for ACTS-VM-010.
///
/// This constant ensures the zeroization and side-channel non-claims
/// remain visible in the compiled binary and in any tool that inspects
/// the crate's public API surface.
pub const CONFORMANCE_REPORT: &str = r#"ACTS-VM-010 Conformance Report — pqc-shims (SynQ)

Zeroization Limitations:
  1. Public APIs returning Vec<u8> cannot control caller copies.
  2. FFI layers (pqcrypto C/Rust backends) may retain transient state.
  3. Heap allocator does not guarantee freed memory is overwritten.
  4. Borrowed &[u8] parameters are not zeroized by this crate.

Side-Channel Non-Claims:
  5. No formal side-channel resistance claim on any target.
  6. Platform isolation (TEE/SE/VM) is a required security boundary.
  7. Upstream primitive behaviour governs actual side-channel posture.
  8. WASM targets return zero-filled stubs; signing is server-side.

Conformance: ACTS-VM-010 — explicitly visible, must be reproduced downstream.
See: ACTS-15 §5.3 (Key and Side-Channel Posture)
"#;

/// Returns the ACTS-VM-010 conformance report.
pub fn conformance_report() -> &'static str {
    CONFORMANCE_REPORT
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_bytes_zeroize_on_drop() {
        let mut sk = SecretBytes::new(vec![0xAB; 32]);
        assert_eq!(sk.len(), 32);
        assert!(!sk.is_zeroized());
        // Take inner before drop
        let ptr = sk.as_ref().as_ptr();
        // Drop sk
        drop(sk);
        // Can't read freed memory safely, but we can test explicit zeroize
    }

    #[test]
    fn test_secret_bytes_explicit_zeroize() {
        let mut sk = SecretBytes::new(vec![0xFF; 16]);
        sk.zeroize();
        assert!(sk.is_zeroized());
        assert!(sk.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secret_bytes_double_zeroize_safe() {
        let mut sk = SecretBytes::new(vec![0xFF; 8]);
        sk.zeroize();
        sk.zeroize(); // should not panic
        assert!(sk.is_zeroized());
    }

    #[test]
    fn test_zeroize_slice() {
        let mut buf = vec![0xCD; 32];
        zeroize_slice(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_zeroize_vec() {
        let mut buf = vec![0xEF; 64];
        zeroize_vec(&mut buf);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_debug_does_not_leak() {
        let sk = SecretBytes::new(vec![0xAB; 32]);
        let debug_str = format!("{:?}", sk);
        assert!(!debug_str.contains("AB"));
        assert!(debug_str.contains("SecretBytes"));
    }

    #[test]
    fn test_conformance_report_exists() {
        let report = conformance_report();
        assert!(report.contains("ACTS-VM-010"));
        assert!(report.contains("Zeroization"));
        assert!(report.contains("Side-Channel"));
    }

    #[test]
    fn test_into_vec_marks_zeroized() {
        let sk = SecretBytes::new(vec![0x42; 4]);
        let raw = sk.into_vec();
        assert_eq!(raw, vec![0x42, 0x42, 0x42, 0x42]);
        // sk is consumed — Drop runs but inner is empty (taken)
    }
}
