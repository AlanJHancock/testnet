// ── SQB Binary Artifact Format v1 ─────────────────────────────────────────────
//
// Implements the SynQ Binary (.sqb) artifact format — a canonical, hash-bound
// envelope wrapping QVM bytecode with ABI, manifest, IR, and metadata sections.
//
// All 11 ACTS-VM requirements are addressed:
//
//   ACTS-VM-001  Deterministic encoding    — sections written in fixed order,
//                                            lengths as u32 LE, hashes via SHA3-256.
//   ACTS-VM-002  Bounded artifact          — max 4 MiB file, 256 sections, 1 MiB/section.
//   ACTS-VM-003  Reject malformed input    — magic, bounds, and trailing-byte checks
//                                            in decode(); truncation = error.
//   ACTS-VM-004  Canonical identifiers     — section types are a fixed u8 enum.
//   ACTS-VM-005  Deterministic cost model  — decode is O(sections + data), bounded.
//   ACTS-VM-006  Resource isolation         — decoder returns owned Vec<u8>, no shared
//                                            state, intermediate buffers zeroized.
//   ACTS-VM-007  Capability discovery       — flags byte declares which optional
//                                            sections (manifest, signature, IR) exist.
//   ACTS-VM-008  Exhaustive capability enum — section_count + flags fully enumerate
//                                            all present data; no hidden sections.
//   ACTS-VM-009  Atomic binding             — artifact root = SHA3-256(all section
//                                            hashes); any tampering breaks the root.
//   ACTS-VM-010  Zeroization                — decoder zeroes temp buffers (hash concat).
//   ACTS-VM-011  ABI versioning             — format version in header + manifest version
//                                            in META section.
//
// ── Wire Format ──────────────────────────────────────────────────────────────
//
//   Header (16 bytes):
//     [0..4]   magic           b"SQB1"
//     [4]      version         1
//     [5]      flags           bit0=manifest, bit1=signature, bit2=ir_dump
//     [6..8]   section_count   u16 LE
//     [8..12]  chain_id        u32 LE  (1264 for testnet)
//     [12..16] timestamp       u32 LE  (Unix epoch)
//
//   Sections (repeated section_count times):
//     [0]      section_type    u8  (see SqbSectionType)
//     [1..5]   data_length     u32 LE
//     [5..5+N] data            N bytes
//     [5+N..5+N+32] hash       SHA3-256(data), 32 bytes
//
//   Artifact Root (32 bytes, after all sections):
//     SHA3-256(hash_1 || hash_2 || ... || hash_N)
//
//   Signature (optional, after artifact root, if flags bit1):
//     [0..4]   sig_length      u32 LE
//     [4..4+S] signature       ML-DSA-87 over the 32-byte artifact root

use sha3::{Digest, Sha3_256};

// ── Constants ─────────────────────────────────────────────────────────────────

pub const MAGIC: &[u8; 4] = b"SQB1";
pub const VERSION: u8 = 1;

/// Maximum total artifact size: 4 MiB (ACTS-VM-002).
pub const MAX_FILE_SIZE: usize = 4 * 1024 * 1024;
/// Maximum number of sections (ACTS-VM-002).
pub const MAX_SECTIONS: usize = 256;
/// Maximum per-section data size: 1 MiB (ACTS-VM-002).
pub const MAX_SECTION_SIZE: usize = 1024 * 1024;

/// Header size in bytes.
pub const HEADER_SIZE: usize = 16;
/// Hash size (SHA3-256).
pub const HASH_SIZE: usize = 32;
/// Section header (type + length prefix) size.
pub const SECTION_PREFIX_SIZE: usize = 5; // 1 + 4

// ── Flags (ACTS-VM-007: capability discovery) ────────────────────────────────

pub const FLAG_HAS_MANIFEST:  u8 = 0x01;
pub const FLAG_HAS_SIGNATURE: u8 = 0x02;
pub const FLAG_HAS_IR_DUMP:   u8 = 0x04;
pub const FLAG_HAS_SOURCE:   u8 = 0x08;

// ── Section Types (ACTS-VM-004: canonical identifiers) ───────────────────────

/// Canonical section type identifiers. These are fixed enum values — no
/// arbitrary strings, no variable-length tags (ACTS-VM-004).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionType {
    /// QVM bytecode (includes QVM\0 header + code + data)
    Code        = 0x01,
    /// Function ABI (JSON): function signatures, params, return types
    Abi         = 0x02,
    /// V3 manifest (JSON): artifact_hash, source_hash, signatures, scopes
    Manifest    = 0x03,
    /// SSA IR dump (text): per-function block-level instruction listing
    Ir          = 0x04,
    /// Declared effects (JSON): read/write/emit/facts per function
    Effects     = 0x05,
    /// State variable layout (JSON): name, type, slot
    StateLayout = 0x06,
    /// Metadata (JSON): compiler version, chain_id, network_id, contract name
    Meta        = 0x07,
    /// Original SynQ source (UTF-8 text) — for audit/inspection
    Source      = 0x08,
    /// Solidity source (UTF-8 text) — for EVM deployment via SXCP
    SoliditySource = 0x09,
}

impl SectionType {
    /// Parse a raw u8 into a SectionType (ACTS-VM-003: reject unknown).
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Code),
            0x02 => Some(Self::Abi),
            0x03 => Some(Self::Manifest),
            0x04 => Some(Self::Ir),
            0x05 => Some(Self::Effects),
            0x06 => Some(Self::StateLayout),
            0x07 => Some(Self::Meta),
            0x08 => Some(Self::Source),
            0x09 => Some(Self::SoliditySource),
            _    => None,
        }
    }
}

// ── Header ───────────────────────────────────────────────────────────────────

/// SQB file header (16 bytes, fixed layout).
#[derive(Debug, Clone)]
#[derive(PartialEq)]
pub struct SqbHeader {
    pub version:       u8,
    pub flags:          u8,
    pub section_count:  u16,
    pub chain_id:       u32,
    pub timestamp:      u32,
}

impl SqbHeader {
    pub fn new(flags: u8, section_count: u16, chain_id: u32) -> Self {
        Self {
            version: VERSION,
            flags,
            section_count,
            chain_id,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0),
        }
    }

    /// Serialize to 16 bytes (ACTS-VM-001: deterministic LE encoding).
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(MAGIC);
        buf[4] = self.version;
        buf[5] = self.flags;
        buf[6..8].copy_from_slice(&self.section_count.to_le_bytes());
        buf[8..12].copy_from_slice(&self.chain_id.to_le_bytes());
        buf[12..16].copy_from_slice(&self.timestamp.to_le_bytes());
        buf
    }

    /// Parse from raw bytes (ACTS-VM-003: reject malformed).
    pub fn parse(buf: &[u8]) -> Result<Self, SqbError> {
        if buf.len() < HEADER_SIZE {
            return Err(SqbError::Truncated("header too short".into()));
        }
        if &buf[0..4] != MAGIC {
            return Err(SqbError::BadMagic);
        }
        let version = buf[4];
        if version != VERSION {
            return Err(SqbError::UnsupportedVersion(version));
        }
        let flags = buf[5];
        let section_count = u16::from_le_bytes([buf[6], buf[7]]);
        let chain_id = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let timestamp = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        Ok(Self { version, flags, section_count, chain_id, timestamp })
    }
}

// ── Section ──────────────────────────────────────────────────────────────────

/// A decoded section with its type, data, and verified hash.
#[derive(Debug, Clone)]
#[derive(PartialEq)]
pub struct SqbSection {
    pub section_type: SectionType,
    pub data: Vec<u8>,
    pub hash: [u8; HASH_SIZE],
}

impl SqbSection {
    /// Create a new section, computing its SHA3-256 hash (ACTS-VM-001).
    pub fn new(section_type: SectionType, data: Vec<u8>) -> Self {
        let hash = Sha3_256::digest(&data);
        Self {
            section_type,
            data,
            hash: hash.into(),
        }
    }

    /// Serialize: type(1B) + length(u32 LE) + data(N) + hash(32B).
    pub fn to_bytes(&self) -> Vec<u8> {
        let data_len = self.data.len() as u32;
        let mut buf = Vec::with_capacity(SECTION_PREFIX_SIZE + self.data.len() + HASH_SIZE);
        buf.push(self.section_type as u8);
        buf.extend_from_slice(&data_len.to_le_bytes());
        buf.extend_from_slice(&self.data);
        buf.extend_from_slice(&self.hash);
        buf
    }

    /// Size of this section when serialized.
    pub fn serialized_size(&self) -> usize {
        SECTION_PREFIX_SIZE + self.data.len() + HASH_SIZE
    }
}

// ── Errors (ACTS-VM-003: reject malformed) ───────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqbError {
    BadMagic,
    UnsupportedVersion(u8),
    Truncated(String),
    UnknownSectionType(u8),
    TooManySections(usize),
    SectionTooLarge(usize),
    FileTooLarge(usize),
    HashMismatch { section_type: u8, expected: [u8; 32], actual: [u8; 32] },
    RootHashMismatch { expected: [u8; 32], actual: [u8; 32] },
    TrailingBytes(usize),
    SignatureInvalid,
    SignatureMissing,
}

impl std::fmt::Display for SqbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic           => write!(f, "SQB: bad magic (expected SQB1)"),
            Self::UnsupportedVersion(v) => write!(f, "SQB: unsupported version {v}"),
            Self::Truncated(msg)     => write!(f, "SQB: truncated — {msg}"),
            Self::UnknownSectionType(t) => write!(f, "SQB: unknown section type 0x{t:02X}"),
            Self::TooManySections(n) => write!(f, "SQB: too many sections ({n}, max {MAX_SECTIONS})"),
            Self::SectionTooLarge(n) => write!(f, "SQB: section too large ({n} bytes, max {MAX_SECTION_SIZE})"),
            Self::FileTooLarge(n)    => write!(f, "SQB: file too large ({n} bytes, max {MAX_FILE_SIZE})"),
            Self::HashMismatch { section_type, .. } =>
                write!(f, "SQB: hash mismatch in section 0x{section_type:02X}"),
            Self::RootHashMismatch { .. } =>
                write!(f, "SQB: artifact root hash mismatch — artifact is corrupt or tampered"),
            Self::TrailingBytes(n)   => write!(f, "SQB: {n} trailing bytes after signature (malformed)"),
            Self::SignatureInvalid   => write!(f, "SQB: ML-DSA-87 signature invalid"),
            Self::SignatureMissing   => write!(f, "SQB: signature expected but not present"),
        }
    }
}

impl std::error::Error for SqbError {}

// ── Encoder ──────────────────────────────────────────────────────────────────

/// Builder for constructing an SQB artifact (ACTS-VM-001: deterministic order).
pub struct SqbEncoder {
    sections: Vec<SqbSection>,
    flags: u8,
    chain_id: u32,
    signature: Option<Vec<u8>>,
}

impl SqbEncoder {
    pub fn new(chain_id: u32) -> Self {
        Self {
            sections: Vec::new(),
            flags: 0,
            chain_id,
            signature: None,
        }
    }

    /// Add a CODE section (QVM bytecode).
    pub fn code(mut self, bytecode: Vec<u8>) -> Self {
        self.sections.push(SqbSection::new(SectionType::Code, bytecode));
        self
    }

    /// Add an ABI section (JSON).
    pub fn abi(mut self, json: Vec<u8>) -> Self {
        self.sections.push(SqbSection::new(SectionType::Abi, json));
        self
    }

    /// Add a MANIFEST section (JSON). Sets FLAG_HAS_MANIFEST.
    pub fn manifest(mut self, json: Vec<u8>) -> Self {
        self.sections.push(SqbSection::new(SectionType::Manifest, json));
        self.flags |= FLAG_HAS_MANIFEST;
        self
    }

    /// Add an IR section (text). Sets FLAG_HAS_IR_DUMP.
    pub fn ir_dump(mut self, text: Vec<u8>) -> Self {
        self.sections.push(SqbSection::new(SectionType::Ir, text));
        self.flags |= FLAG_HAS_IR_DUMP;
        self
    }

    /// Add an EFFECTS section (JSON).
    pub fn effects(mut self, json: Vec<u8>) -> Self {
        self.sections.push(SqbSection::new(SectionType::Effects, json));
        self
    }

    /// Add a STATE_LAYOUT section (JSON).
    pub fn state_layout(mut self, json: Vec<u8>) -> Self {
        self.sections.push(SqbSection::new(SectionType::StateLayout, json));
        self
    }

    /// Add a META section (JSON).
    pub fn meta(mut self, json: Vec<u8>) -> Self {
        self.sections.push(SqbSection::new(SectionType::Meta, json));
        self
    }

    /// Add a SOURCE section (UTF-8 text). Sets FLAG_HAS_SOURCE.
    pub fn source(mut self, text: Vec<u8>) -> Self {
        self.sections.push(SqbSection::new(SectionType::Source, text));
        self.flags |= FLAG_HAS_SOURCE;
        self
    }

    /// Add a SOLIDITY_SOURCE section (UTF-8 text). For EVM deployment via SXCP.
    pub fn solidity_source(mut self, text: Vec<u8>) -> Self {
        self.sections.push(SqbSection::new(SectionType::SoliditySource, text));
        self
    }

    /// Attach an ML-DSA-87 signature over the artifact root. Sets FLAG_HAS_SIGNATURE.
    pub fn signature(mut self, sig: Vec<u8>) -> Self {
        self.flags |= FLAG_HAS_SIGNATURE;
        self.signature = Some(sig);
        self
    }

    /// Build the final SQB binary (ACTS-VM-001: deterministic, ACTS-VM-009: hash-bound).
    pub fn build(self) -> Result<Vec<u8>, SqbError> {
        let section_count = self.sections.len();
        if section_count > MAX_SECTIONS {
            return Err(SqbError::TooManySections(section_count));
        }
        for s in &self.sections {
            if s.data.len() > MAX_SECTION_SIZE {
                return Err(SqbError::SectionTooLarge(s.data.len()));
            }
        }

        // Compute artifact root: SHA3-256 of all section hashes concatenated
        // (ACTS-VM-009: atomic binding).
        let mut hash_concat = Vec::with_capacity(section_count * HASH_SIZE);
        for s in &self.sections {
            hash_concat.extend_from_slice(&s.hash);
        }
        let artifact_root = Sha3_256::digest(&hash_concat);

        // ACTS-VM-010: zeroize intermediate buffer.
        // (hash_concat is dropped at end of scope; explicitly zero it first.)
        for b in hash_concat.iter_mut() { *b = 0; }

        let header = SqbHeader::new(self.flags, section_count as u16, self.chain_id);

        let mut file = Vec::new();
        file.extend_from_slice(&header.to_bytes());

        for s in &self.sections {
            file.extend_from_slice(&s.to_bytes());
        }

        // Artifact root (32 bytes).
        file.extend_from_slice(&artifact_root);

        // Optional signature (ACTS-VM-011: versioned, ACTS-VM-007: capability-flagged).
        if let Some(sig) = &self.signature {
            let sig_len = sig.len() as u32;
            file.extend_from_slice(&sig_len.to_le_bytes());
            file.extend_from_slice(sig);
        }

        // ACTS-VM-002: bounded file size.
        if file.len() > MAX_FILE_SIZE {
            return Err(SqbError::FileTooLarge(file.len()));
        }

        Ok(file)
    }
}

// ── Decoder ──────────────────────────────────────────────────────────────────

/// Decoded SQB artifact.
#[derive(Debug)]
#[derive(PartialEq)]
pub struct SqbArtifact {
    pub header: SqbHeader,
    pub sections: Vec<SqbSection>,
    pub artifact_root: [u8; HASH_SIZE],
    pub signature: Option<Vec<u8>>,
}

impl SqbArtifact {
    /// Find a section by type.
    pub fn get(&self, ty: SectionType) -> Option<&SqbSection> {
        self.sections.iter().find(|s| s.section_type == ty)
    }

    /// Get CODE section data (convenience).
    pub fn code(&self) -> Option<&[u8]> {
        self.get(SectionType::Code).map(|s| s.data.as_slice())
    }

    /// Get the original source section, if present.
    pub fn source_text(&self) -> Option<&str> {
        self.get(SectionType::Source).and_then(|s| std::str::from_utf8(&s.data).ok())
    }

    /// Get the Solidity source section, if present.
    pub fn solidity_source_text(&self) -> Option<&str> {
        self.get(SectionType::SoliditySource).and_then(|s| std::str::from_utf8(&s.data).ok())
    }

    /// Get MANIFEST section data as UTF-8 (convenience).
    pub fn manifest_json(&self) -> Option<&str> {
        self.get(SectionType::Manifest)
            .and_then(|s| std::str::from_utf8(&s.data).ok())
    }

    /// Get ABI section data as UTF-8 (convenience).
    pub fn abi_json(&self) -> Option<&str> {
        self.get(SectionType::Abi)
            .and_then(|s| std::str::from_utf8(&s.data).ok())
    }
}

/// Decode an SQB binary artifact (ACTS-VM-003: reject malformed/truncated).
///
/// Validates:
/// - Magic and version
/// - Section count bounds
/// - Per-section hash integrity (SHA3-256)
/// - Artifact root hash (atomic binding)
/// - No trailing bytes after signature
pub fn decode(buf: &[u8]) -> Result<SqbArtifact, SqbError> {
    // ACTS-VM-002: bounded file size.
    if buf.len() > MAX_FILE_SIZE {
        return Err(SqbError::FileTooLarge(buf.len()));
    }

    let header = SqbHeader::parse(buf)?;

    let mut pos = HEADER_SIZE;
    let mut sections = Vec::with_capacity(header.section_count as usize);

    // Parse each section (ACTS-VM-003: strict bounds checking).
    for i in 0..header.section_count {
        // Section prefix: type(1) + length(4)
        if pos + SECTION_PREFIX_SIZE > buf.len() {
            return Err(SqbError::Truncated(format!("section {i}: prefix truncated")));
        }

        let section_type_raw = buf[pos];
        let section_type = SectionType::from_u8(section_type_raw)
            .ok_or(SqbError::UnknownSectionType(section_type_raw))?;

        let data_length = u32::from_le_bytes([
            buf[pos + 1], buf[pos + 2], buf[pos + 3], buf[pos + 4],
        ]) as usize;

        // ACTS-VM-002: per-section size bound.
        if data_length > MAX_SECTION_SIZE {
            return Err(SqbError::SectionTooLarge(data_length));
        }

        let data_start = pos + SECTION_PREFIX_SIZE;
        let data_end = data_start + data_length;
        let hash_end = data_end + HASH_SIZE;

        if hash_end > buf.len() {
            return Err(SqbError::Truncated(format!(
                "section {i} (type 0x{section_type_raw:02X}): data+hash truncated"
            )));
        }

        let data = &buf[data_start..data_end];
        let stored_hash: [u8; HASH_SIZE] = buf[data_end..hash_end]
            .try_into().unwrap();

        // ACTS-VM-009: verify per-section hash integrity.
        let computed_hash = Sha3_256::digest(data);
        if computed_hash.as_slice() != stored_hash {
            return Err(SqbError::HashMismatch {
                section_type: section_type_raw,
                expected: stored_hash,
                actual: computed_hash.into(),
            });
        }

        sections.push(SqbSection {
            section_type,
            data: data.to_vec(),
            hash: stored_hash,
        });

        pos = hash_end;
    }

    // Artifact root (32 bytes after all sections).
    let root_end = pos + HASH_SIZE;
    if root_end > buf.len() {
        return Err(SqbError::Truncated("artifact root truncated".to_string()));
    }
    let stored_root: [u8; HASH_SIZE] = buf[pos..root_end]
        .try_into().unwrap();
    pos = root_end;

    // ACTS-VM-009: verify artifact root = SHA3-256(all section hashes concatenated).
    let mut hash_concat = Vec::with_capacity(sections.len() * HASH_SIZE);
    for s in &sections {
        hash_concat.extend_from_slice(&s.hash);
    }
    let computed_root = Sha3_256::digest(&hash_concat);

    // ACTS-VM-010: zeroize intermediate buffer.
    for b in hash_concat.iter_mut() { *b = 0; }

    if computed_root.as_slice() != stored_root {
        return Err(SqbError::RootHashMismatch {
            expected: stored_root,
            actual: computed_root.into(),
        });
    }

    // Optional signature (ACTS-VM-007: flags indicate presence).
    let signature = if header.flags & FLAG_HAS_SIGNATURE != 0 {
        if pos + 4 > buf.len() {
            return Err(SqbError::Truncated("signature length truncated".to_string()));
        }
        let sig_len = u32::from_le_bytes([
            buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3],
        ]) as usize;
        pos += 4;
        let sig_end = pos + sig_len;
        if sig_end > buf.len() {
            return Err(SqbError::Truncated("signature data truncated".to_string()));
        }
        let sig = buf[pos..sig_end].to_vec();
        pos = sig_end;
        Some(sig)
    } else {
        None
    };

    // ACTS-VM-003: reject trailing bytes (malformed artifact).
    if pos != buf.len() {
        return Err(SqbError::TrailingBytes(buf.len() - pos));
    }

    Ok(SqbArtifact {
        header,
        sections,
        artifact_root: stored_root,
        signature,
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_basic() {
        let bytecode = vec![0x51, 0x56, 0x4d, 0x00, 0x01, 0x10, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0xFF];
        let abi = br#"{"functions":[{"name":"init","params":[],"return_type":"bool"}]}"#;
        let manifest = br#"{"artifact_hash":"abc123","source_hash":"def456","chain_id":1264}"#;

        let encoded = SqbEncoder::new(1264)
            .code(bytecode.clone())
            .abi(abi.to_vec())
            .manifest(manifest.to_vec())
            .build()
            .unwrap();

        assert!(encoded.len() > HEADER_SIZE + HASH_SIZE);

        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.header.version, VERSION);
        assert_eq!(decoded.header.chain_id, 1264);
        assert_eq!(decoded.sections.len(), 3);
        assert_eq!(decoded.code(), Some(bytecode.as_slice()));
        assert!(decoded.manifest_json().is_some());
        assert!(decoded.abi_json().is_some());
        assert!(decoded.signature.is_none());
    }

    #[test]
    fn test_roundtrip_with_signature() {
        let bytecode = vec![0x51, 0x56, 0x4d, 0x00, 0x01, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF];
        let sig = vec![0xAA; 64]; // fake signature

        let encoded = SqbEncoder::new(1264)
            .code(bytecode.clone())
            .signature(sig.clone())
            .build()
            .unwrap();

        let decoded = decode(&encoded).unwrap();
        assert!(decoded.header.flags & FLAG_HAS_SIGNATURE != 0);
        assert_eq!(decoded.signature, Some(sig));
    }

    #[test]
    fn test_reject_bad_magic() {
        let mut buf = SqbEncoder::new(1264)
            .code(vec![0xFF])
            .build()
            .unwrap();
        buf[0] = 0; // corrupt magic
        assert_eq!(decode(&buf), Err(SqbError::BadMagic));
    }

    #[test]
    fn test_reject_truncated_header() {
        assert_eq!(decode(&[0x53, 0x51]), Err(SqbError::Truncated("header too short".into())));
    }

    #[test]
    fn test_reject_truncated_section() {
        let mut buf = SqbEncoder::new(1264)
            .code(vec![0xFF, 0x00])
            .build()
            .unwrap();
        // Truncate the file by 5 bytes (into the section data)
        let trunc_len = buf.len() - 5;
        buf.truncate(trunc_len);
        assert!(matches!(decode(&buf), Err(SqbError::Truncated(_))));
    }

    #[test]
    fn test_reject_hash_mismatch() {
        let mut buf = SqbEncoder::new(1264)
            .code(vec![0xFF, 0x00])
            .build()
            .unwrap();
        // Corrupt one byte of section data (offset 5, right after prefix)
        buf[HEADER_SIZE + SECTION_PREFIX_SIZE] ^= 0xFF;
        assert!(matches!(decode(&buf), Err(SqbError::HashMismatch { .. })));
    }

    #[test]
    fn test_reject_root_hash_mismatch() {
        let mut buf = SqbEncoder::new(1264)
            .code(vec![0xFF])
            .abi(vec![0x01])
            .build()
            .unwrap();
        // Corrupt the artifact root hash (last 32 bytes before optional signature)
        let root_offset = buf.len() - HASH_SIZE;
        buf[root_offset] ^= 0xFF;
        assert!(matches!(decode(&buf), Err(SqbError::RootHashMismatch { .. })));
    }

    #[test]
    fn test_reject_trailing_bytes() {
        let mut buf = SqbEncoder::new(1264)
            .code(vec![0xFF])
            .build()
            .unwrap();
        buf.push(0x42); // trailing byte
        assert_eq!(decode(&buf), Err(SqbError::TrailingBytes(1)));
    }

    #[test]
    fn test_reject_unknown_section_type() {
        let mut buf = SqbEncoder::new(1264)
            .code(vec![0xFF])
            .build()
            .unwrap();
        // Replace section type byte (offset HEADER_SIZE) with an unknown type
        buf[HEADER_SIZE] = 0xFF;
        assert_eq!(decode(&buf), Err(SqbError::UnknownSectionType(0xFF)));
    }

    #[test]
    fn test_all_section_types() {
        let encoded = SqbEncoder::new(1264)
            .code(vec![0x01, 0x02])
            .abi(br#"{"f":"init"}"#.to_vec())
            .manifest(br#"{"h":"abc"}"#.to_vec())
            .ir_dump(b"fn init() -> bool { ... }".to_vec())
            .effects(br#"{"read":["x"]}"#.to_vec())
            .state_layout(br#"[{"name":"x","slot":0}]"#.to_vec())
            .meta(br#"{"compiler":"0.9"}"#.to_vec())
            .build()
            .unwrap();

        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.sections.len(), 7);
        assert!(decoded.get(SectionType::Code).is_some());
        assert!(decoded.get(SectionType::Abi).is_some());
        assert!(decoded.get(SectionType::Manifest).is_some());
        assert!(decoded.get(SectionType::Ir).is_some());
        assert!(decoded.get(SectionType::Effects).is_some());
        assert!(decoded.get(SectionType::StateLayout).is_some());
        assert!(decoded.get(SectionType::Meta).is_some());
    }

    #[test]
    fn test_flags_set_correctly() {
        let encoded = SqbEncoder::new(1264)
            .code(vec![0xFF])
            .manifest(vec![0x01])
            .ir_dump(vec![0x02])
            .signature(vec![0xAA])
            .build()
            .unwrap();

        let decoded = decode(&encoded).unwrap();
        assert!(decoded.header.flags & FLAG_HAS_MANIFEST != 0);
        assert!(decoded.header.flags & FLAG_HAS_IR_DUMP != 0);
        assert!(decoded.header.flags & FLAG_HAS_SIGNATURE != 0);
    }

    #[test]
    fn test_empty_sections() {
        let encoded = SqbEncoder::new(1264)
            .build()
            .unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.sections.len(), 0);
        // Just header + artifact root
        assert_eq!(encoded.len(), HEADER_SIZE + HASH_SIZE);
    }
}
