//! UMA registry interface — Synergy Network v1.6 §4
//!
//! This module defines the trait that the Synergy consensus layer will
//! implement to supply resolved UMA references to the VM.
//!
//! # Protocol position
//!
//! Per the v1.6 security specification invariants:
//!
//! - U-8:  Resolution must NOT influence consensus ordering or finality.
//!         The registry is consulted by the call-dispatch layer *after*
//!         consensus has settled, in a one-way consumption pattern.
//!
//! - U-13: The VM and SynQ contracts must NOT contain UMA derivation logic.
//!         Contracts receive a pre-resolved UMA via `LoadCaller` (0x50) and
//!         must treat it as an opaque 32-byte identity token.
//!
//! - U-14: Resolution failures must NOT halt consensus or execution.
//!         `resolve` returns `Option<[u8; 32]>` — callers must handle `None`
//!         gracefully (devnet: fall back to padded signing key).
//!
//! # Devnet behaviour
//!
//! On devnet, `NullUmaRegistry` is used.  It always returns `None`, which
//! causes `CallContext::caller_value()` to fall back to the raw EVM signing
//! address.  No code change is needed in the VM or contracts when the real
//! registry is wired — only the registry implementation and the
//! `CallContext` construction site in `synq-server` need updating.

/// Resolves a 20-byte EVM signing address to a 32-byte UMA reference.
///
/// Implemented by the consensus layer.  The VM holds a reference to this
/// trait object so it can look up UMA references without embedding any
/// resolution logic itself.
pub trait UmaRegistry: Send + Sync {
    /// Resolve a signing key to a UMA reference.
    ///
    /// Returns `None` if:
    /// - The signing key has no registered UMA (devnet, anonymous callers)
    /// - The UMA registry is unavailable (U-14: must not halt execution)
    /// - The key has been rotated out and the new key is not yet indexed
    ///
    /// Resolution MUST be deterministic for a given epoch (U-6).
    /// Resolution MUST NOT depend on mutable external services (U-7).
    fn resolve(&self, signing_key: &[u8; 20]) -> Option<[u8; 32]>;

    /// Returns true if this registry is the null/devnet stub.
    /// Used for logging and diagnostic endpoints only — never for auth.
    fn is_devnet_stub(&self) -> bool { false }
}

/// Devnet stub — always returns `None`.
///
/// `CallContext::caller_value()` falls back to the padded EVM signing key
/// when `uma_ref` is `None`, preserving identical devnet behaviour.
pub struct NullUmaRegistry;

impl UmaRegistry for NullUmaRegistry {
    fn resolve(&self, _signing_key: &[u8; 20]) -> Option<[u8; 32]> {
        None
    }
    fn is_devnet_stub(&self) -> bool { true }
}
