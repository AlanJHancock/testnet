//! ABI per synq-abi-spec.md
//!
//! Canonical JSON ABI with SHA-256 method selectors.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// ABI type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AbiType {
    Bool,
    U8,
    U16,
    U32,
    U64,
    U128,
    /// Full 256-bit unsigned integer (2026-09-09, U256 support). Was
    /// previously absent entirely -- `Type::UInt256` mapped to `AbiType::
    /// U128` in `compiler/src/aivm_codegen.rs`, silently mislabeling every
    /// `u256`-declared field/param as 128-bit in the ABI JSON schema.
    U256,
    I32,
    I64,
    Bytes,
    Bytes32,
    Address,
    String,
    Array(Box<AbiType>),
}

impl AbiType {
    /// Get the type string for selector computation
    pub fn type_string(&self) -> String {
        match self {
            AbiType::Bool => "bool".to_string(),
            AbiType::U8 => "u8".to_string(),
            AbiType::U16 => "u16".to_string(),
            AbiType::U32 => "u32".to_string(),
            AbiType::U64 => "u64".to_string(),
            AbiType::U128 => "u128".to_string(),
            AbiType::U256 => "u256".to_string(),
            AbiType::I32 => "i32".to_string(),
            AbiType::I64 => "i64".to_string(),
            AbiType::Bytes => "bytes".to_string(),
            AbiType::Bytes32 => "bytes32".to_string(),
            AbiType::Address => "address".to_string(),
            AbiType::String => "string".to_string(),
            AbiType::Array(inner) => format!("array<{}>", inner.type_string()),
        }
    }

    /// Is this a dynamic-length type?
    pub fn is_dynamic(&self) -> bool {
        match self {
            AbiType::Bytes | AbiType::String | AbiType::Array(_) => true,
            _ => false,
        }
    }

    /// Fixed encoding size in bytes (None for dynamic types)
    pub fn fixed_size(&self) -> Option<usize> {
        match self {
            AbiType::Bool => Some(1),
            AbiType::U8 => Some(1),
            AbiType::U16 => Some(2),
            AbiType::U32 => Some(4),
            AbiType::U64 => Some(8),
            AbiType::U128 => Some(16),
            AbiType::U256 => Some(32),
            AbiType::I32 => Some(4),
            AbiType::I64 => Some(8),
            AbiType::Bytes32 => Some(32),
            AbiType::Address => Some(41),
            AbiType::Bytes | AbiType::String | AbiType::Array(_) => None,
        }
    }
}

/// ABI method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiMethod {
    pub name: String,
    #[serde(rename = "selector")]
    pub selector: String, // lowercase 0x hex, 4 bytes (8 hex chars)
    pub visibility: String, // "public" or "private"
    pub mutability: String, // "view" or "write"
    pub params: Vec<AbiType>,
    pub returns: Vec<AbiType>,
}

/// ABI event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiEvent {
    pub name: String,
    pub fields: Vec<(String, AbiType)>,
}

/// ABI error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiError {
    pub name: String,
    pub fields: Vec<(String, AbiType)>,
}

/// State field in ABI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiStateField {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: AbiType,
}

/// Top-level ABI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Abi {
    pub abi_version: String,
    pub contract: String,
    pub methods: Vec<AbiMethod>,
    pub events: Vec<AbiEvent>,
    pub errors: Vec<AbiError>,
    pub state_schema: Vec<AbiStateField>,
    pub security_requirements: serde_json::Value,
}

impl Abi {
    /// Compute method selector: first 4 bytes of SHA-256(name + "(" + comma_types + ")")
    pub fn compute_selector(name: &str, params: &[AbiType]) -> u32 {
        let type_str: String = params.iter().map(|t| t.type_string()).collect::<Vec<_>>().join(",");
        let input = format!("{}({})", name, type_str);
        let hash = Sha256::digest(input.as_bytes());
        u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
    }

    /// Format selector as lowercase 0x hex
    pub fn selector_hex(selector: u32) -> String {
        format!("0x{:08x}", selector)
    }

    /// Canonical JSON encoding (sorted keys, no whitespace)
    pub fn canonical_json(&self) -> Vec<u8> {
        // Serialize with sorted keys
        let value = serde_json::to_value(self).unwrap();
        canonicalize_json(&value)
    }

    /// Compute ABI hash
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(&self.canonical_json()).into()
    }
}

/// Recursively canonicalize a JSON value: sort object keys, no whitespace
pub fn canonicalize_json(value: &serde_json::Value) -> Vec<u8> {
    let mut buf = Vec::new();
    write_canonical(value, &mut buf);
    buf
}

fn write_canonical(value: &serde_json::Value, buf: &mut Vec<u8>) {
    match value {
        serde_json::Value::Null => buf.extend_from_slice(b"null"),
        serde_json::Value::Bool(b) => buf.extend_from_slice(if *b { b"true" } else { b"false" }),
        serde_json::Value::Number(n) => {
            buf.extend_from_slice(n.to_string().as_bytes());
        }
        serde_json::Value::String(s) => {
            buf.push(b'"');
            // Escape per JSON spec
            for c in s.chars() {
                match c {
                    '"' => buf.extend_from_slice(b"\\\""),
                    '\\' => buf.extend_from_slice(b"\\\\"),
                    '\n' => buf.extend_from_slice(b"\\n"),
                    '\r' => buf.extend_from_slice(b"\\r"),
                    '\t' => buf.extend_from_slice(b"\\t"),
                    c if (c as u32) < 0x20 => {
                        buf.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
                    }
                    c => {
                        let mut tmp = [0u8; 4];
                        buf.extend_from_slice(c.encode_utf8(&mut tmp).as_bytes());
                    }
                }
            }
            buf.push(b'"');
        }
        serde_json::Value::Array(arr) => {
            buf.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 { buf.push(b','); }
                write_canonical(item, buf);
            }
            buf.push(b']');
        }
        serde_json::Value::Object(map) => {
            buf.push(b'{');
            // Sort keys
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, key) in keys.iter().enumerate() {
                if i > 0 { buf.push(b','); }
                buf.push(b'"');
                buf.extend_from_slice(key.as_bytes());
                buf.push(b'"');
                buf.push(b':');
                write_canonical(&map[*key], buf);
            }
            buf.push(b'}');
        }
    }
}
