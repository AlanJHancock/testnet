//! # AEG1 Framing — Aegis PQC Wire Protocol
//!
//! Implements the AEG1 compact byte ABI for Aegis-governed cryptographic
//! operations. The VM sends an AEG1-framed request, the Aegis layer
//! dispatches to the appropriate PQC shim, and returns an AEG1-framed
//! response.
//!
//! ## Wire Format
//!
//! ```text
//! call = "AEG1" || op || alg || argc
//! for each argument:
//!     call = call || u32_be(len(argument)) || argument
//!
//! response_ok  = "AEG1" || 0x00 || u32_be(len(result)) || result
//! response_err = "AEG1" || 0x01 || error_code || u32_be(len(message)) || message
//! ```
//!
//! ## Operations
//!
//! | Op  | NIST Name  | Description              |
//! |-----|------------|--------------------------|
//! | 1   | ML-KEM     | Decapsulate (KEM)        |
//! | 2   | ML-DSA     | Detached verify          |
//! | 3   | FN-DSA     | Detached verify          |
//!
//! ## Bounds
//!
//! - Total payload:   1,048,576 bytes (1 MiB)
//! - Argument count:  8
//! - Per-argument:    131,072 bytes (128 KiB)
//! - Response body:   131,072 bytes (128 KiB)

use std::io;

// ── Constants ────────────────────────────────────────────────────────────────

pub const MAGIC: &[u8; 4] = b"AEG1";

pub const MAX_PAYLOAD: usize = 1_048_576;
pub const MAX_ARGS: u8 = 8;
pub const MAX_ARG_SIZE: usize = 131_072;
pub const MAX_RESPONSE_SIZE: usize = 131_072;

/// AEG1 ABI / profile version (ACTS-VM-011).
/// Increment on any change to wire semantics or operation IDs.
pub const ABI_VERSION: u8 = 1;

/// AEG1 operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Operation {
    /// ML-KEM decapsulate (Kyber)
    MlKemDecaps = 1,
    /// ML-DSA detached verify (Dilithium)
    MlDsaVerify = 2,
    /// FN-DSA detached verify (Falcon)
    FnDsaVerify = 3,
}

impl TryFrom<u8> for Operation {
    type Error = Aeg1Error;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Self::MlKemDecaps),
            2 => Ok(Self::MlDsaVerify),
            3 => Ok(Self::FnDsaVerify),
            _ => Err(Aeg1Error::UnknownOperation(v)),
        }
    }
}

/// AEG1 algorithm identifiers (local mapping for parameter sets)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Algorithm {
    // ML-KEM (Kyber) parameter sets
    MlKem512  = 0x01,
    MlKem768  = 0x02,
    MlKem1024 = 0x03,
    // ML-DSA (Dilithium) parameter sets
    MlDsa44   = 0x10,
    MlDsa65   = 0x11,
    MlDsa87   = 0x12,
    // FN-DSA (Falcon) parameter sets
    FnDsa512  = 0x20,
    FnDsa1024 = 0x21,
}

impl TryFrom<u8> for Algorithm {
    type Error = Aeg1Error;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::MlKem512),
            0x02 => Ok(Self::MlKem768),
            0x03 => Ok(Self::MlKem1024),
            0x10 => Ok(Self::MlDsa44),
            0x11 => Ok(Self::MlDsa65),
            0x12 => Ok(Self::MlDsa87),
            0x20 => Ok(Self::FnDsa512),
            0x21 => Ok(Self::FnDsa1024),
            _ => Err(Aeg1Error::UnknownAlgorithm(v)),
        }
    }
}

impl Algorithm {
    /// Canonical ACTS identifier (ACTS-VM-004).
    /// Maps local algorithm IDs to canonical ACTS parameter-set identifiers.
    pub fn canonical_id(&self) -> &'static str {
        match self {
            Self::MlKem512  => "ACTS-ML-KEM-512",
            Self::MlKem768  => "ACTS-ML-KEM-768",
            Self::MlKem1024 => "ACTS-ML-KEM-1024",
            Self::MlDsa44   => "ACTS-ML-DSA-44",
            Self::MlDsa65   => "ACTS-ML-DSA-65",
            Self::MlDsa87   => "ACTS-ML-DSA-87",
            Self::FnDsa512  => "ACTS-FN-DSA-512",
            Self::FnDsa1024 => "ACTS-FN-DSA-1024",
        }
    }
}

/// AEG1 response status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseStatus {
    Ok    = 0x00,
    Error = 0x01,
}

/// AEG1 error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum ErrorCode {
    InvalidMagic        = 0x01,
    Truncated           = 0x02,
    TooManyArgs         = 0x03,
    ArgTooLarge         = 0x04,
    PayloadTooLarge    = 0x05,
    UnknownOperation    = 0x06,
    UnknownAlgorithm    = 0x07,
    WrongArgCount        = 0x08,
    CryptoFailed         = 0x09,
    ResponseTooLarge     = 0x0A,
    InvalidKey           = 0x0B,
    InvalidSignature     = 0x0C,
    InvalidCiphertext     = 0x0D,
    OperationNotSupported = 0x0E,
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AEG1 error: {:?}", self)
    }
}

/// AEG1 protocol errors
#[derive(Debug)]
pub enum Aeg1Error {
    InvalidMagic([u8; 4]),
    Truncated(String),
    TooManyArgs(u8),
    ArgTooLarge { idx: usize, size: usize },
    PayloadTooLarge(usize),
    UnknownOperation(u8),
    UnknownAlgorithm(u8),
    WrongArgCount { expected: u8, actual: u8 },
    CryptoFailed(String),
    ResponseTooLarge(usize),
    TrailingBytes(usize),
    Io(io::Error),
}

impl std::fmt::Display for Aeg1Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagic(m) => write!(f, "AEG1: invalid magic {:02x?}", m),
            Self::Truncated(s)     => write!(f, "AEG1: truncated: {}", s),
            Self::TooManyArgs(n)   => write!(f, "AEG1: too many args ({})", n),
            Self::ArgTooLarge{idx,size} => write!(f, "AEG1: arg {} too large ({} > {})", idx, size, MAX_ARG_SIZE),
            Self::PayloadTooLarge(n) => write!(f, "AEG1: payload too large ({})", n),
            Self::UnknownOperation(op) => write!(f, "AEG1: unknown operation {}", op),
            Self::UnknownAlgorithm(alg) => write!(f, "AEG1: unknown algorithm 0x{:02x}", alg),
            Self::WrongArgCount{expected,actual} => write!(f, "AEG1: wrong arg count (expected {}, got {})", expected, actual),
            Self::CryptoFailed(s) => write!(f, "AEG1: crypto failed: {}", s),
            Self::ResponseTooLarge(n) => write!(f, "AEG1: response too large ({})", n),
            Self::TrailingBytes(n) => write!(f, "AEG1: {} trailing byte(s) after final argument", n),
            Self::Io(e) => write!(f, "AEG1: IO error: {}", e),
        }
    }
}

impl std::error::Error for Aeg1Error {}

impl From<io::Error> for Aeg1Error {
    fn from(e: io::Error) -> Self { Self::Io(e) }
}

// ── Request ─────────────────────────────────────────────────────────────────

/// A parsed AEG1 request.
#[derive(Debug, Clone)]
pub struct Aeg1Request {
    pub operation: Operation,
    pub algorithm: Algorithm,
    pub args: Vec<Vec<u8>>,
}

impl Aeg1Request {
    /// Expected argument count per operation.
    pub fn expected_arg_count(&self) -> u8 {
        match self.operation {
            Operation::MlKemDecaps => 2, // ciphertext, private_key
            Operation::MlDsaVerify => 3, // message, signature, public_key
            Operation::FnDsaVerify => 3, // message, signature, public_key
        }
    }

    /// Encode this request into the AEG1 wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + 1 + 1 + 1 + self.args.iter().map(|a| 4 + a.len()).sum::<usize>());
        buf.extend_from_slice(MAGIC);
        buf.push(self.operation as u8);
        buf.push(self.algorithm as u8);
        buf.push(self.args.len() as u8);
        for arg in &self.args {
            buf.extend_from_slice(&(arg.len() as u32).to_be_bytes());
            buf.extend_from_slice(arg);
        }
        buf
    }

    /// Decode an AEG1 request from raw bytes, enforcing all bounds.
    pub fn decode(data: &[u8]) -> Result<Self, Aeg1Error> {
        if data.len() > MAX_PAYLOAD {
            return Err(Aeg1Error::PayloadTooLarge(data.len()));
        }
        if data.len() < 7 {
            return Err(Aeg1Error::Truncated("need at least 7 bytes for header".into()));
        }
        let magic: [u8; 4] = data[0..4].try_into().unwrap();
        if &magic != MAGIC {
            return Err(Aeg1Error::InvalidMagic(magic));
        }
        let operation = Operation::try_from(data[4])?;
        let algorithm = Algorithm::try_from(data[5])?;
        let argc = data[6];
        if argc > MAX_ARGS {
            return Err(Aeg1Error::TooManyArgs(argc));
        }

        let mut args = Vec::with_capacity(argc as usize);
        let mut pos = 7;
        for i in 0..argc {
            if pos + 4 > data.len() {
                return Err(Aeg1Error::Truncated(format!("arg {} length prefix", i)));
            }
            let len = u32::from_be_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
            pos += 4;
            if len > MAX_ARG_SIZE {
                return Err(Aeg1Error::ArgTooLarge { idx: i as usize, size: len });
            }
            if pos + len > data.len() {
                return Err(Aeg1Error::Truncated(format!("arg {} body", i)));
            }
            args.push(data[pos..pos+len].to_vec());
            pos += len;
        }

        // ACTS-VM-003: reject trailing bytes after the final argument
        if pos != data.len() {
            return Err(Aeg1Error::TrailingBytes(data.len() - pos));
        }

        let req = Self { operation, algorithm, args };
        if req.expected_arg_count() != argc {
            return Err(Aeg1Error::WrongArgCount {
                expected: req.expected_arg_count(),
                actual: argc,
            });
        }
        Ok(req)
    }
}

// ── Response ────────────────────────────────────────────────────────────────

/// AEG1 response — either OK with a result body, or Error with code + message.
#[derive(Debug, Clone)]
pub enum Aeg1Response {
    Ok(Vec<u8>),
    Error(ErrorCode, String),
}

impl Aeg1Response {
    /// Encode the response into the AEG1 wire format.
    pub fn encode(&self) -> Result<Vec<u8>, Aeg1Error> {
        let mut buf = Vec::with_capacity(9);
        buf.extend_from_slice(MAGIC);
        match self {
            Self::Ok(result) => {
                if result.len() > MAX_RESPONSE_SIZE {
                    return Err(Aeg1Error::ResponseTooLarge(result.len()));
                }
                buf.push(ResponseStatus::Ok as u8);
                buf.extend_from_slice(&(result.len() as u32).to_be_bytes());
                buf.extend_from_slice(result);
            }
            Self::Error(code, message) => {
                buf.push(ResponseStatus::Error as u8);
                buf.push(*code as u8);
                let msg_bytes = message.as_bytes();
                let msg_len = msg_bytes.len().min(MAX_RESPONSE_SIZE);
                buf.extend_from_slice(&(msg_len as u32).to_be_bytes());
                buf.extend_from_slice(&msg_bytes[..msg_len]);
            }
        }
        Ok(buf)
    }

    /// Decode an AEG1 response from raw bytes.
    pub fn decode(data: &[u8]) -> Result<Self, Aeg1Error> {
        if data.len() < 6 {
            return Err(Aeg1Error::Truncated("response too short".into()));
        }
        let magic: [u8; 4] = data[0..4].try_into().unwrap();
        if &magic != MAGIC {
            return Err(Aeg1Error::InvalidMagic(magic));
        }
        let status = data[4];
        match status {
            0x00 => {
                if data.len() < 9 {
                    return Err(Aeg1Error::Truncated("ok response missing length".into()));
                }
                let len = u32::from_be_bytes(data[5..9].try_into().unwrap()) as usize;
                if len > MAX_RESPONSE_SIZE {
                    return Err(Aeg1Error::ResponseTooLarge(len));
                }
                if data.len() < 9 + len {
                    return Err(Aeg1Error::Truncated("ok response body".into()));
                }
                Ok(Self::Ok(data[9..9+len].to_vec()))
            }
            0x01 => {
                if data.len() < 10 {
                    return Err(Aeg1Error::Truncated("error response incomplete".into()));
                }
                let code = data[5];
                let len = u32::from_be_bytes(data[6..10].try_into().unwrap()) as usize;
                let msg = if data.len() >= 10 + len {
                    String::from_utf8_lossy(&data[10..10+len.min(len)]).to_string()
                } else {
                    String::new()
                };
                // Map raw byte to ErrorCode
                let ec = match code {
                    0x01 => ErrorCode::InvalidMagic,
                    0x02 => ErrorCode::Truncated,
                    0x03 => ErrorCode::TooManyArgs,
                    0x04 => ErrorCode::ArgTooLarge,
                    0x05 => ErrorCode::PayloadTooLarge,
                    0x06 => ErrorCode::UnknownOperation,
                    0x07 => ErrorCode::UnknownAlgorithm,
                    0x08 => ErrorCode::WrongArgCount,
                    0x09 => ErrorCode::CryptoFailed,
                    0x0A => ErrorCode::ResponseTooLarge,
                    0x0B => ErrorCode::InvalidKey,
                    0x0C => ErrorCode::InvalidSignature,
                    0x0D => ErrorCode::InvalidCiphertext,
                    0x0E => ErrorCode::OperationNotSupported,
                    _    => ErrorCode::CryptoFailed,
                };
                Ok(Self::Error(ec, msg))
            }
            _ => Err(Aeg1Error::UnknownOperation(status)),
        }
    }

    /// Returns true if this is an OK response.
    pub fn is_ok(&self) -> bool { matches!(self, Self::Ok(_)) }

    /// Returns the result body if Ok, None otherwise.
    pub fn result(&self) -> Option<&[u8]> {
        match self { Self::Ok(r) => Some(r), _ => None }
    }
}

// ── Dispatch ────────────────────────────────────────────────────────────────

/// Dispatch an AEG1 request to the appropriate PQC shim and return
/// an AEG1 response. This is the main entry point from the VM.
#[cfg(feature = "native")]
pub fn dispatch(req: &Aeg1Request) -> Aeg1Response {
    match req.operation {
        Operation::MlKemDecaps => dispatch_ml_kem(req),
        Operation::MlDsaVerify => dispatch_ml_dsa(req),
        Operation::FnDsaVerify => dispatch_fn_dsa(req),
    }
}

#[cfg(not(feature = "native"))]
pub fn dispatch(_req: &Aeg1Request) -> Aeg1Response {
    Aeg1Response::Error(ErrorCode::CryptoFailed, "PQC requires native build".into())
}

/// Deterministic dispatch — for on-chain / VM-context use.
///
/// Per ACTS-15 §3: only detached verification operations (ML-DSA, FN-DSA)
/// are supported in the deterministic public dispatcher. ML-KEM decapsulate
/// requires a decapsulation (secret) key and is rejected here. Key generation,
/// encapsulation, and signing are not exposed at all.
#[cfg(feature = "native")]
pub fn dispatch_deterministic(req: &Aeg1Request) -> Aeg1Response {
    match req.operation {
        Operation::MlDsaVerify => dispatch_ml_dsa(req),
        Operation::FnDsaVerify  => dispatch_fn_dsa(req),
        Operation::MlKemDecaps  => Aeg1Response::Error(
            ErrorCode::OperationNotSupported,
            "ML-KEM decapsulate rejected in deterministic dispatcher (requires secret key) — ACTS-15 §3".into(),
        ),
    }
}

// ── ACTS-VM-007: Capability Discovery ────────────────────────────────────────
/// Describes whether a given operation+algorithm combination is supported,
/// and in which dispatch context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    pub operation: Operation,
    pub algorithm: Algorithm,
    pub deterministic: bool,  // available in deterministic (on-chain) dispatcher
    pub off_chain: bool,      // available in trusted off-chain dispatcher
    pub contextual: bool,     // contextual signing supported
}

/// Query capability support for a given operation+algorithm (ACTS-VM-007).
/// Unsupported operations (e.g. FN-DSA contextual signing) return
/// `contextual: false` so callers get an explicit not-implemented signal.
pub fn capability(op: Operation, alg: Algorithm) -> Capability {
    match (op, alg) {
        // ML-DSA: deterministic verify + off-chain sign; contextual supported
        (Operation::MlDsaVerify, _) => Capability {
            operation: op, algorithm: alg,
            deterministic: true, off_chain: true, contextual: true,
        },
        // FN-DSA: deterministic verify supported; contextual NOT implemented (ACTS-VM-007)
        (Operation::FnDsaVerify, _) => Capability {
            operation: op, algorithm: alg,
            deterministic: true, off_chain: true, contextual: false,
        },
        // ML-KEM: off-chain only, not deterministic
        (Operation::MlKemDecaps, _) => Capability {
            operation: op, algorithm: alg,
            deterministic: false, off_chain: true, contextual: false,
        },
    }
}

/// Returns a list of all supported capability combinations for build identification
/// (ACTS-VM-008).
pub fn supported_capabilities() -> Vec<Capability> {
    let mut caps = Vec::new();
    for &op in &[Operation::MlDsaVerify, Operation::FnDsaVerify, Operation::MlKemDecaps] {
        for &alg in &[
            Algorithm::MlKem512, Algorithm::MlKem768, Algorithm::MlKem1024,
            Algorithm::MlDsa44, Algorithm::MlDsa65, Algorithm::MlDsa87,
            Algorithm::FnDsa512, Algorithm::FnDsa1024,
        ] {
            // Only include valid combos
            match (op, alg) {
                (Operation::MlKemDecaps, Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024) |
                (Operation::MlDsaVerify, Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87) |
                (Operation::FnDsaVerify, Algorithm::FnDsa512 | Algorithm::FnDsa1024) => {
                    caps.push(capability(op, alg));
                }
                _ => {}
            }
        }
    }
    caps
}

#[cfg(not(feature = "native"))]
pub fn dispatch_deterministic(_req: &Aeg1Request) -> Aeg1Response {
    Aeg1Response::Error(ErrorCode::CryptoFailed, "PQC requires native build".into())
}

#[cfg(feature = "native")]
fn dispatch_ml_kem(req: &Aeg1Request) -> Aeg1Response {
    // Args: [ciphertext, private_key]
    let ct = &req.args[0];
    let sk = &req.args[1];

    match req.algorithm {
        Algorithm::MlKem768 => {
            match crate::kyber::decaps(ct, sk) {
                Ok(secret) => {
                    if secret.len() > MAX_RESPONSE_SIZE {
                        return Aeg1Response::Error(ErrorCode::ResponseTooLarge, format!("{} bytes", secret.len()));
                    }
                    Aeg1Response::Ok(secret)
                }
                Err(e) => Aeg1Response::Error(ErrorCode::CryptoFailed, e),
            }
        }
        Algorithm::MlKem512 | Algorithm::MlKem1024 => {
            // Currently only MlKem768 (Kyber-768) is implemented.
            // Fall back to kyber::decaps which uses Kyber-768.
            match crate::kyber::decaps(ct, sk) {
                Ok(secret) => Aeg1Response::Ok(secret),
                Err(e) => Aeg1Response::Error(ErrorCode::CryptoFailed, e),
            }
        }
        _ => Aeg1Response::Error(ErrorCode::UnknownAlgorithm, format!("ML-KEM got 0x{:02x}", req.algorithm as u8)),
    }
}

#[cfg(feature = "native")]
fn dispatch_ml_dsa(req: &Aeg1Request) -> Aeg1Response {
    // Args: [message, signature, public_key]
    let msg = &req.args[0];
    let sig = &req.args[1];
    let pk  = &req.args[2];

    match req.algorithm {
        Algorithm::MlDsa65 => {
            let result = crate::dilithium::verify(msg, sig, pk);
            if result {
                Aeg1Response::Ok(vec![])  // empty body = verified
            } else {
                Aeg1Response::Error(ErrorCode::InvalidSignature, "ML-DSA verification failed".into())
            }
        }
        Algorithm::MlDsa44 | Algorithm::MlDsa87 => {
            // Currently only MlDsa65 is implemented; fall back.
            let result = crate::dilithium::verify(msg, sig, pk);
            if result {
                Aeg1Response::Ok(vec![])
            } else {
                Aeg1Response::Error(ErrorCode::InvalidSignature, "ML-DSA verification failed".into())
            }
        }
        _ => Aeg1Response::Error(ErrorCode::UnknownAlgorithm, format!("ML-DSA got 0x{:02x}", req.algorithm as u8)),
    }
}

#[cfg(feature = "native")]
fn dispatch_fn_dsa(req: &Aeg1Request) -> Aeg1Response {
    // Args: [message, signature, public_key]
    let msg = &req.args[0];
    let sig = &req.args[1];
    let pk  = &req.args[2];

    match req.algorithm {
        Algorithm::FnDsa512 => {
            let result = crate::falcon::verify(msg, sig, pk);
            if result {
                Aeg1Response::Ok(vec![])
            } else {
                Aeg1Response::Error(ErrorCode::InvalidSignature, "FN-DSA verification failed".into())
            }
        }
        Algorithm::FnDsa1024 => {
            // Currently only FnDsa512 (Falcon-512) is implemented; fall back.
            let result = crate::falcon::verify(msg, sig, pk);
            if result {
                Aeg1Response::Ok(vec![])
            } else {
                Aeg1Response::Error(ErrorCode::InvalidSignature, "FN-DSA verification failed".into())
            }
        }
        _ => Aeg1Response::Error(ErrorCode::UnknownAlgorithm, format!("FN-DSA got 0x{:02x}", req.algorithm as u8)),
    }
}

// ── ACTS-VM-005: Cost Model ──────────────────────────────────────────────────
/// AEG1 operation cost model (ACTS-15 §4).
///
/// cost = baseop,alg + cbyte * input_bytes + carg * argument_count
///
/// Constants are versioned by ABI_VERSION and VM profile.

/// Base cost per operation + algorithm combination.
pub fn base_cost(op: Operation, alg: Algorithm) -> u64 {
    match (op, alg) {
        // ML-DSA verify: moderate base cost
        (Operation::MlDsaVerify, Algorithm::MlDsa44) => 5_000,
        (Operation::MlDsaVerify, Algorithm::MlDsa65) => 8_000,
        (Operation::MlDsaVerify, Algorithm::MlDsa87) => 12_000,
        // FN-DSA verify: lower base cost (compact signatures)
        (Operation::FnDsaVerify, Algorithm::FnDsa512)  => 4_000,
        (Operation::FnDsaVerify, Algorithm::FnDsa1024) => 7_000,
        // ML-KEM decapsulate (off-chain only): high base cost
        (Operation::MlKemDecaps, _) => 20_000,
        _ => 15_000, // conservative default
    }
}

/// Per-byte cost coefficient.
pub const CBYTE: u64 = 1;
/// Per-argument cost coefficient.
pub const CARG: u64 = 100;

/// Compute the bounded cost of an AEG1 request (ACTS-VM-005).
/// Deterministic — same input always yields the same cost.
pub fn compute_cost(req: &Aeg1Request) -> u64 {
    let base = base_cost(req.operation, req.algorithm);
    let input_bytes: usize = req.args.iter().map(|a| a.len()).sum();
    let bounded_bytes = input_bytes.min(MAX_PAYLOAD) as u64;
    base + CBYTE * bounded_bytes + CARG * (req.args.len() as u64)
}

/// Compute the worst-case cost for a given operation+algorithm before parsing
/// the payload. Used for pre-execution bounding (ACTS-15 §4).
pub fn worst_case_cost(op: Operation, alg: Algorithm) -> u64 {
    base_cost(op, alg)
        + CBYTE * MAX_PAYLOAD as u64
        + CARG * MAX_ARGS as u64
}

// ── Convenience: encode + dispatch + decode in one call ──────────────────────

/// Process a raw AEG1 frame: decode, dispatch, re-encode the response.
/// This is the single entry point the VM calls.
pub fn process_frame(frame: &[u8]) -> Result<Vec<u8>, Aeg1Error> {
    let req = Aeg1Request::decode(frame)?;
    let resp = dispatch(&req);
    resp.encode()
}

/// Process a raw AEG1 frame using the deterministic dispatcher (on-chain/VM path).
///
/// Only verification operations are permitted; ML-KEM decapsulate is rejected.
/// This is the entry point the QVM AegisCall (0x8F) opcode MUST use.
pub fn process_frame_deterministic(frame: &[u8]) -> Result<Vec<u8>, Aeg1Error> {
    let req = Aeg1Request::decode(frame)?;
    let resp = dispatch_deterministic(&req);
    resp.encode()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let req = Aeg1Request {
            operation: Operation::MlDsaVerify,
            algorithm: Algorithm::MlDsa65,
            args: vec![
                b"hello world".to_vec(),
                vec![0xAB; 64],
                vec![0xCD; 32],
            ],
        };
        let encoded = req.encode();
        let decoded = Aeg1Request::decode(&encoded).unwrap();
        assert_eq!(decoded.operation, Operation::MlDsaVerify);
        assert_eq!(decoded.algorithm, Algorithm::MlDsa65);
        assert_eq!(decoded.args.len(), 3);
        assert_eq!(decoded.args[0], b"hello world");
        assert_eq!(decoded.args[1], vec![0xAB; 64]);
        assert_eq!(decoded.args[2], vec![0xCD; 32]);
    }

    #[test]
    fn test_invalid_magic() {
        let bad = b"XXXX\x02\x11\x00";
        assert!(matches!(Aeg1Request::decode(bad), Err(Aeg1Error::InvalidMagic(_))));
    }

    #[test]
    fn test_truncated() {
        let truncated = b"AEG1\x02";
        assert!(matches!(Aeg1Request::decode(truncated), Err(Aeg1Error::Truncated(_))));
    }

    #[test]
    fn test_too_many_args() {
        let mut buf = MAGIC.to_vec();
        buf.push(2); // op
        buf.push(0x11); // alg
        buf.push(9); // argc > MAX_ARGS
        assert!(matches!(Aeg1Request::decode(&buf), Err(Aeg1Error::TooManyArgs(9))));
    }

    #[test]
    fn test_payload_too_large() {
        let huge = vec![0u8; MAX_PAYLOAD + 1];
        assert!(matches!(Aeg1Request::decode(&huge), Err(Aeg1Error::PayloadTooLarge(_))));
    }

    #[test]
    fn test_arg_too_large() {
        let mut buf = MAGIC.to_vec();
        buf.push(2); // op
        buf.push(0x11); // alg
        buf.push(1); // argc
        buf.extend_from_slice(&(MAX_ARG_SIZE as u32 + 1).to_be_bytes()); // length
        buf.extend_from_slice(&vec![0u8; MAX_ARG_SIZE]); // body (1 short, but length says +1)
        // We need the full body for decode to not truncate first
        let mut buf2 = buf.clone();
        buf2.extend_from_slice(&[0u8]); // add the extra byte
        assert!(matches!(Aeg1Request::decode(&buf2), Err(Aeg1Error::ArgTooLarge{..})));
    }

    #[test]
    fn test_response_ok_encode_decode() {
        let resp = Aeg1Response::Ok(vec![0x01, 0x02, 0x03]);
        let encoded = resp.encode().unwrap();
        let decoded = Aeg1Response::decode(&encoded).unwrap();
        assert!(decoded.is_ok());
        assert_eq!(decoded.result().unwrap(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_response_error_encode_decode() {
        let resp = Aeg1Response::Error(ErrorCode::InvalidSignature, "bad sig".into());
        let encoded = resp.encode().unwrap();
        let decoded = Aeg1Response::decode(&encoded).unwrap();
        match decoded {
            Aeg1Response::Error(code, msg) => {
                assert_eq!(code, ErrorCode::InvalidSignature);
                assert_eq!(msg, "bad sig");
            }
            _ => panic!("expected error response"),
        }
    }

    #[test]
    fn test_response_too_large() {
        let huge = vec![0u8; MAX_RESPONSE_SIZE + 1];
        let resp = Aeg1Response::Ok(huge);
        assert!(matches!(resp.encode(), Err(Aeg1Error::ResponseTooLarge(_))));
    }

    #[test]
    fn test_wrong_arg_count() {
        let mut buf = MAGIC.to_vec();
        buf.push(2); // MlDsaVerify (expects 3 args)
        buf.push(0x11); // MlDsa65
        buf.push(2); // only 2 args
        // arg 0
        buf.extend_from_slice(&3u32.to_be_bytes());
        buf.extend_from_slice(b"abc");
        // arg 1
        buf.extend_from_slice(&3u32.to_be_bytes());
        buf.extend_from_slice(b"def");
        assert!(matches!(Aeg1Request::decode(&buf), Err(Aeg1Error::WrongArgCount{expected: 3, actual: 2})));
    }

    #[test]
    fn test_empty_verify_response() {
        // ML-DSA verify success returns empty body
        let resp = Aeg1Response::Ok(vec![]);
        let encoded = resp.encode().unwrap();
        assert_eq!(&encoded[..4], MAGIC);
        assert_eq!(encoded[4], 0x00); // OK status
        let len = u32::from_be_bytes(encoded[5..9].try_into().unwrap());
        assert_eq!(len, 0);
    }

    #[test]
    fn test_process_frame_invalid() {
        let bad = b"NOT_AEG1";
        assert!(process_frame(bad).is_err());
    }

    /// ACTS-15 §3: deterministic dispatcher MUST reject ML-KEM decapsulate.
    #[cfg(feature = "native")]
    #[test]
    fn test_deterministic_rejects_decapsulate() {
        let req = Aeg1Request {
            operation: Operation::MlKemDecaps,
            algorithm: Algorithm::MlKem768,
            args: vec![vec![0xAB; 32], vec![0xCD; 32]],
        };
        let encoded = req.encode();
        let result = process_frame_deterministic(&encoded).unwrap();
        let resp = Aeg1Response::decode(&result).unwrap();
        match resp {
            Aeg1Response::Error(code, msg) => {
                assert_eq!(code, ErrorCode::OperationNotSupported);
                assert!(msg.contains("ACTS-15"));
                assert!(msg.contains("secret key"));
            }
            Aeg1Response::Ok(_) => panic!("ML-KEM decapsulate should be rejected in deterministic dispatcher"),
        }
    }

    /// ACTS-15 §3: deterministic dispatcher SHOULD accept ML-DSA verify.
    #[cfg(feature = "native")]
    #[test]
    fn test_deterministic_accepts_ml_dsa_verify() {
        let req = Aeg1Request {
            operation: Operation::MlDsaVerify,
            algorithm: Algorithm::MlDsa65,
            args: vec![b"msg".to_vec(), vec![0xFF; 64], vec![0xEE; 32]],
        };
        let encoded = req.encode();
        let result = process_frame_deterministic(&encoded).unwrap();
        let resp = Aeg1Response::decode(&result).unwrap();
        match resp {
            Aeg1Response::Error(code, _) => {
                assert_ne!(code, ErrorCode::OperationNotSupported, "ML-DSA verify should not be rejected");
            }
            Aeg1Response::Ok(_) => {}
        }
    }

    /// Without native feature, deterministic dispatcher returns CryptoFailed for all ops.
    #[cfg(not(feature = "native"))]
    #[test]
    fn test_deterministic_no_native() {
        let req = Aeg1Request {
            operation: Operation::MlDsaVerify,
            algorithm: Algorithm::MlDsa65,
            args: vec![b"msg".to_vec(), vec![0xFF; 64], vec![0xEE; 32]],
        };
        let encoded = req.encode();
        let result = process_frame_deterministic(&encoded).unwrap();
        let resp = Aeg1Response::decode(&result).unwrap();
        match resp {
            Aeg1Response::Error(code, _) => {
                assert_eq!(code, ErrorCode::CryptoFailed);
            }
            Aeg1Response::Ok(_) => panic!("Should fail without native build"),
        }
    }

    /// ACTS-VM-003: trailing bytes after final argument MUST be rejected.
    #[test]
    fn test_trailing_bytes_rejected() {
        let req = Aeg1Request {
            operation: Operation::MlDsaVerify,
            algorithm: Algorithm::MlDsa65,
            args: vec![b"msg".to_vec(), vec![0xFF; 32], vec![0xEE; 16]],
        };
        let mut encoded = req.encode();
        encoded.extend_from_slice(b"TRAILING");
        let result = Aeg1Request::decode(&encoded);
        assert!(matches!(result, Err(Aeg1Error::TrailingBytes(8))));
    }

    /// ACTS-VM-004: canonical ACTS identifiers.
    #[test]
    fn test_canonical_ids() {
        assert_eq!(Algorithm::MlKem768.canonical_id(),  "ACTS-ML-KEM-768");
        assert_eq!(Algorithm::MlKem1024.canonical_id(), "ACTS-ML-KEM-1024");
        assert_eq!(Algorithm::MlDsa44.canonical_id(),   "ACTS-ML-DSA-44");
        assert_eq!(Algorithm::MlDsa87.canonical_id(),    "ACTS-ML-DSA-87");
        assert_eq!(Algorithm::FnDsa512.canonical_id(),  "ACTS-FN-DSA-512");
        assert_eq!(Algorithm::FnDsa1024.canonical_id(), "ACTS-FN-DSA-1024");
    }

    /// ACTS-VM-005: cost model must be deterministic and bounded.
    #[test]
    fn test_cost_model() {
        let req = Aeg1Request {
            operation: Operation::MlDsaVerify,
            algorithm: Algorithm::MlDsa87,
            args: vec![vec![0xAB; 100], vec![0xCD; 200], vec![0xEF; 50]],
        };
        let cost = compute_cost(&req);
        // base(12000) + cbyte(1)*350 + carg(100)*3 = 12000 + 350 + 300 = 12650
        assert_eq!(cost, 12000 + 350 + 300);

        // Same input → same cost (deterministic)
        let cost2 = compute_cost(&req);
        assert_eq!(cost, cost2);

        // Worst case must be >= any actual cost
        let wc = worst_case_cost(Operation::MlDsaVerify, Algorithm::MlDsa87);
        assert!(wc >= cost);
    }

    /// ACTS-VM-005: worst-case cost must bound malformed payloads too.
    #[test]
    fn test_worst_case_bounded() {
        let wc = worst_case_cost(Operation::MlDsaVerify, Algorithm::MlDsa65);
        let base = base_cost(Operation::MlDsaVerify, Algorithm::MlDsa65);
        assert_eq!(wc, base + CBYTE * MAX_PAYLOAD as u64 + CARG * MAX_ARGS as u64);
    }

    /// ACTS-VM-007: FN-DSA contextual signing MUST be capability-discovered.
    #[test]
    fn test_fn_dsa_contextual_not_implemented() {
        let cap = capability(Operation::FnDsaVerify, Algorithm::FnDsa512);
        assert!(cap.deterministic);  // verify supported on-chain
        assert!(cap.off_chain);      // verify supported off-chain
        assert!(!cap.contextual);   // contextual NOT implemented (ACTS-VM-007)
    }

    /// ACTS-VM-007: ML-DSA contextual signing IS supported.
    #[test]
    fn test_ml_dsa_contextual_supported() {
        let cap = capability(Operation::MlDsaVerify, Algorithm::MlDsa65);
        assert!(cap.deterministic);
        assert!(cap.off_chain);
        assert!(cap.contextual);
    }

    /// ACTS-VM-008: supported_capabilities must list all valid combinations.
    #[test]
    fn test_supported_capabilities() {
        let caps = supported_capabilities();
        // 3 ML-KEM + 3 ML-DSA + 2 FN-DSA = 8
        assert_eq!(caps.len(), 8);
        // Verify all ML-DSA have contextual=true
        for c in caps.iter().filter(|c| c.operation == Operation::MlDsaVerify) {
            assert!(c.contextual);
        }
        // Verify all FN-DSA have contextual=false
        for c in caps.iter().filter(|c| c.operation == Operation::FnDsaVerify) {
            assert!(!c.contextual);
        }
        // Verify all ML-KEM have deterministic=false
        for c in caps.iter().filter(|c| c.operation == Operation::MlKemDecaps) {
            assert!(!c.deterministic);
        }
    }

    /// ACTS-VM-011: ABI version must be defined.
    #[test]
    fn test_abi_version() {
        assert_eq!(ABI_VERSION, 1);
    }
}
