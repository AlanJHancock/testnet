//! AIVM bytecode format per synq-bytecode-spec.md
//!
//! Header: 108 bytes — magic SYNQ + bytecode_version + target_aivm_version +
//!         abi_hash + manifest_hash + code_hash + section_count
//! Sections: type(u16) + length(u32) + data
//! Section types: 1=constants, 2=functions, 3=instructions, 4=exports, 5=imports, 6=metadata

use crate::errors::AivmError;
use sha2::{Digest, Sha256};

/// Magic bytes: ASCII "SYNQ"
pub const MAGIC: [u8; 4] = *b"SYNQ";

/// Current bytecode version
pub const BYTECODE_VERSION: u16 = 1;

/// Current AIVM target version
pub const AIVM_VERSION: u16 = 1;

/// Header size in bytes
pub const HEADER_SIZE: usize = 108;

/// Section type IDs
pub mod section_type {
    pub const CONSTANTS: u16 = 1;
    pub const FUNCTIONS: u16 = 2;
    pub const INSTRUCTIONS: u16 = 3;
    pub const EXPORTS: u16 = 4;
    pub const IMPORTS: u16 = 5;
    pub const METADATA: u16 = 6;
}

/// 32-byte hash
pub type Hash32 = [u8; 32];

/// AIVM bytecode header (108 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytecodeHeader {
    pub magic: [u8; 4],
    pub bytecode_version: u16,
    pub target_aivm_version: u16,
    pub abi_hash: Hash32,
    pub manifest_hash: Hash32,
    pub code_hash: Hash32,
    pub section_count: u32,
}

impl BytecodeHeader {
    /// Encode header to 108 bytes
    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.magic);
        buf[4..6].copy_from_slice(&self.bytecode_version.to_be_bytes());
        buf[6..8].copy_from_slice(&self.target_aivm_version.to_be_bytes());
        buf[8..40].copy_from_slice(&self.abi_hash);
        buf[40..72].copy_from_slice(&self.manifest_hash);
        buf[72..104].copy_from_slice(&self.code_hash);
        buf[104..108].copy_from_slice(&self.section_count.to_be_bytes());
        buf
    }

    /// Decode header from 108 bytes
    pub fn decode(buf: &[u8]) -> Result<Self, AivmError> {
        if buf.len() < HEADER_SIZE {
            return Err(AivmError::TruncatedBytecode);
        }
        let magic = buf[0..4].try_into().unwrap();
        if magic != MAGIC {
            return Err(AivmError::BadMagic);
        }
        let bytecode_version = u16::from_be_bytes([buf[4], buf[5]]);
        if bytecode_version != BYTECODE_VERSION {
            return Err(AivmError::UnsupportedBytecodeVersion(bytecode_version));
        }
        let target_aivm_version = u16::from_be_bytes([buf[6], buf[7]]);
        if target_aivm_version != AIVM_VERSION {
            return Err(AivmError::UnsupportedAivmVersion(target_aivm_version));
        }
        Ok(Self {
            magic,
            bytecode_version,
            target_aivm_version,
            abi_hash: buf[8..40].try_into().unwrap(),
            manifest_hash: buf[40..72].try_into().unwrap(),
            code_hash: buf[72..104].try_into().unwrap(),
            section_count: u32::from_be_bytes([buf[104], buf[105], buf[106], buf[107]]),
        })
    }
}

/// A bytecode section
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub section_type: u16,
    pub data: Vec<u8>,
}

/// A fully decoded AIVM bytecode artifact
#[derive(Debug, Clone)]
pub struct BytecodeArtifact {
    pub header: BytecodeHeader,
    pub sections: Vec<Section>,
}

impl BytecodeArtifact {
    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.sections.len() * 6);
        buf.extend_from_slice(&self.header.encode());
        for section in &self.sections {
            buf.extend_from_slice(&section.section_type.to_be_bytes());
            buf.extend_from_slice(&(section.data.len() as u32).to_be_bytes());
            buf.extend_from_slice(&section.data);
        }
        buf
    }

    /// Decode from bytes
    pub fn decode(bytes: &[u8]) -> Result<Self, AivmError> {
        let header = BytecodeHeader::decode(bytes)?;
        let mut offset = HEADER_SIZE;
        let mut sections = Vec::with_capacity(header.section_count as usize);
        let mut seen_types = std::collections::HashSet::new();

        for _ in 0..header.section_count {
            if offset + 6 > bytes.len() {
                return Err(AivmError::TruncatedBytecode);
            }
            let section_type = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            let length = u32::from_be_bytes([
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
                bytes[offset + 5],
            ]) as usize;
            offset += 6;

            if offset + length > bytes.len() {
                return Err(AivmError::MalformedSection {
                    section_type,
                    reason: format!("section extends past end (offset {}, len {})", offset, length),
                });
            }

            if seen_types.contains(&section_type) {
                return Err(AivmError::DuplicateSection(section_type));
            }
            seen_types.insert(section_type);

            sections.push(Section {
                section_type,
                data: bytes[offset..offset + length].to_vec(),
            });
            offset += length;
        }

        // Validate code hash
        let code_section = sections.iter().find(|s| s.section_type == section_type::INSTRUCTIONS);
        if let Some(code) = code_section {
            let computed: Hash32 = Sha256::digest(&code.data).into();
            if computed != header.code_hash {
                return Err(AivmError::CodeHashMismatch);
            }
        }

        Ok(Self { header, sections })
    }

    /// Get a section by type
    pub fn get_section(&self, stype: u16) -> Option<&Section> {
        self.sections.iter().find(|s| s.section_type == stype)
    }

    /// Compute code hash from instruction bytes
    pub fn compute_code_hash(instructions: &[u8]) -> Hash32 {
        Sha256::digest(instructions).into()
    }

    /// Compute ABI hash from canonical ABI bytes
    pub fn compute_abi_hash(canonical_abi: &[u8]) -> Hash32 {
        Sha256::digest(canonical_abi).into()
    }

    /// Compute manifest hash from canonical manifest bytes
    pub fn compute_manifest_hash(canonical_manifest: &[u8]) -> Hash32 {
        Sha256::digest(canonical_manifest).into()
    }

    /// Build a new artifact from components
    pub fn build(
        abi_canonical: &[u8],
        manifest_canonical: &[u8],
        instructions: &[u8],
        extra_sections: Vec<Section>,
    ) -> Self {
        let abi_hash = Self::compute_abi_hash(abi_canonical);
        let manifest_hash = Self::compute_manifest_hash(manifest_canonical);
        let code_hash = Self::compute_code_hash(instructions);

        let mut sections = vec![
            Section { section_type: section_type::INSTRUCTIONS, data: instructions.to_vec() },
        ];
        sections.extend(extra_sections);

        let section_count = sections.len() as u32;
        let header = BytecodeHeader {
            magic: MAGIC,
            bytecode_version: BYTECODE_VERSION,
            target_aivm_version: AIVM_VERSION,
            abi_hash,
            manifest_hash,
            code_hash,
            section_count,
        };

        Self { header, sections }
    }
}
