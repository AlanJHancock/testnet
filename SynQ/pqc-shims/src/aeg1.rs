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

// ── Convenience: encode + dispatch + decode in one call ──────────────────────

/// Process a raw AEG1 frame: decode, dispatch, re-encode the response.
/// This is the single entry point the VM calls.
pub fn process_frame(frame: &[u8]) -> Result<Vec<u8>, Aeg1Error> {
    let req = Aeg1Request::decode(frame)?;
    let resp = dispatch(&req);
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
}
