//! Bech32 encoding/decoding for V3 address model (BIP-173).
//!
//! V3 address formats:
//! - `syna...` — canonical format for standard accounts and operational authorities
//! - `sync...` — canonical format for deployed contract instances
//! - `tsynq...` — RETIRED (replaced by syna...)
//!
//! Internal SynQ binding: `synq-signer:<hex>` (not public Bech32).
//!
//! Contract addresses are deployment-derived:
//!   sync = bech32("sync", keccak256(deployer || nonce || artifact_hash || constructor_hash || network_id)[0..20])

use sha3::{Keccak256, Digest};

/// HRP for standard accounts and operational authorities.
pub const HRP_SYNA: &str = "syna";
/// HRP for deployed contract instances.
pub const HRP_SYNC: &str = "sync";

/// Bech32 character set (5-bit values → chars).
const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Bech32 checksum constant.
const BECH32_CONST: u32 = 1;

/// Convert bytes to 5-bit groups (base32).
fn convert_bits(data: &[u8], from_bits: u8, to_bits: u8, pad: bool) -> Result<Vec<u8>, String> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let maxv: u32 = (1 << to_bits) - 1;
    let max_acc: u32 = (1 << (from_bits + to_bits - 1)) - 1;
    let mut ret = Vec::new();

    for &value in data {
        if (value as u32) >> from_bits != 0 {
            return Err("invalid data".into());
        }
        acc = ((acc << from_bits) | value as u32) & max_acc;
        bits += from_bits as u32;
        while bits >= to_bits as u32 {
            bits -= to_bits as u32;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            ret.push(((acc << (to_bits as u32 - bits)) & maxv) as u8);
        }
    } else if bits >= from_bits as u32 || ((acc << (to_bits as u32 - bits)) & maxv) != 0 {
        return Err("invalid padding".into());
    }
    Ok(ret)
}

/// Bech32 polymod (checksum computation).
fn polymod(values: &[u8]) -> u32 {
    let generators: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = BECH32_CONST;
    for &v in values {
        let b = (chk >> 25) as u8;
        chk = ((chk & 0x1ffffff) << 5) ^ (v as u32);
        for i in 0..5 {
            if (b >> i) & 1 != 0 {
                chk ^= generators[i];
            }
        }
    }
    chk
}

/// Expand the HRP for checksum computation.
fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut ret = Vec::with_capacity(hrp.len() * 2 + 1);
    for c in hrp.bytes() {
        ret.push(c >> 5);
    }
    ret.push(0);
    for c in hrp.bytes() {
        ret.push(c & 31);
    }
    ret
}

/// Compute the Bech32 checksum (6 5-bit groups).
fn create_checksum(hrp: &str, data: &[u8]) -> Vec<u8> {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0u8; 6]);
    let mod_val = polymod(&values) ^ BECH32_CONST;
    let mut ret = Vec::with_capacity(6);
    for i in 0..6 {
        ret.push(((mod_val >> (5 * (5 - i))) & 31) as u8);
    }
    ret
}

/// Verify the Bech32 checksum.
fn verify_checksum(hrp: &str, data: &[u8]) -> bool {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    polymod(&values) == BECH32_CONST
}

/// Encode data as a Bech32 string with the given HRP.
pub fn bech32_encode(hrp: &str, data: &[u8]) -> Result<String, String> {
    let data5 = convert_bits(data, 8, 5, true)?;
    let checksum = create_checksum(hrp, &data5);
    let mut combined = data5;
    combined.extend_from_slice(&checksum);
    let mut result = String::with_capacity(hrp.len() + 1 + combined.len());
    result.push_str(hrp);
    result.push('1');
    for v in &combined {
        result.push(CHARSET[*v as usize] as char);
    }
    Ok(result)
}

/// Decode a Bech32 string, returning (HRP, data bytes).
pub fn bech32_decode(s: &str) -> Result<(String, Vec<u8>), String> {
    if s.len() < 8 || s.len() > 90 {
        return Err(format!("invalid length: {}", s.len()));
    }
    let lower = s.to_lowercase();
    let pos = lower.rfind('1');
    let pos = match pos {
        Some(p) if p >= 1 => p,
        _ => return Err("no separator".into()),
    };
    let hrp = &lower[..pos];
    let data_part = &lower[pos + 1..];
    if hrp.is_empty() || data_part.len() < 6 {
        return Err("invalid structure".into());
    }
    let mut data5 = Vec::with_capacity(data_part.len());
    for c in data_part.bytes() {
        match CHARSET.iter().position(|&x| x == c) {
            Some(idx) => data5.push(idx as u8),
            None => return Err(format!("invalid character: {}", c as char)),
        }
    }
    if !verify_checksum(hrp, &data5) {
        return Err("invalid checksum".into());
    }
    let payload = &data5[..data5.len() - 6];
    let decoded = convert_bits(payload, 5, 8, false)?;
    Ok((hrp.to_string(), decoded))
}

// ── V3 address utilities ─────────────────────────────────────────────────────

/// Encode a 20-byte EVM address as a `syna...` Bech32 string.
pub fn evm_to_syna(addr: &[u8; 20]) -> Result<String, String> {
    bech32_encode(HRP_SYNA, addr)
}

/// Decode a `syna...` Bech32 string to a 20-byte address.
pub fn syna_to_evm(s: &str) -> Result<[u8; 20], String> {
    let (hrp, data) = bech32_decode(s)?;
    if hrp != HRP_SYNA {
        return Err(format!("expected HRP 'syna', got '{}'", hrp));
    }
    if data.len() != 20 {
        return Err(format!("expected 20 bytes, got {}", data.len()));
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&data);
    Ok(addr)
}

/// Encode a 20-byte value as a `sync...` contract address.
pub fn to_sync(addr: &[u8; 20]) -> Result<String, String> {
    bech32_encode(HRP_SYNC, addr)
}

/// Decode a `sync...` Bech32 string to a 20-byte contract address.
pub fn from_sync(s: &str) -> Result<[u8; 20], String> {
    let (hrp, data) = bech32_decode(s)?;
    if hrp != HRP_SYNC {
        return Err(format!("expected HRP 'sync', got '{}'", hrp));
    }
    if data.len() != 20 {
        return Err(format!("expected 20 bytes, got {}", data.len()));
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&data);
    Ok(addr)
}

/// Derive a `sync...` contract address from deployment parameters.
///
/// address = keccak256(deployer_syna[20] || nonce_be[8] || artifact_hash[32] || constructor_hash[32] || network_id)[0..20]
///
/// Then encode as Bech32 with HRP "sync".
pub fn derive_contract_address(
    deployer: &[u8; 20],
    nonce: u64,
    artifact_hash: &[u8; 32],
    constructor_hash: &[u8; 32],
    network_id: &str,
) -> Result<String, String> {
    let mut hasher = Keccak256::new();
    hasher.update(deployer);
    hasher.update(&nonce.to_be_bytes());
    hasher.update(artifact_hash);
    hasher.update(constructor_hash);
    hasher.update(network_id.as_bytes());
    let hash = hasher.finalize();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[0..20]);
    to_sync(&addr)
}

/// Check if a string is a valid syna... address.
pub fn is_syna(s: &str) -> bool {
    syna_to_evm(s).is_ok()
}

/// Check if a string is a valid sync... address.
pub fn is_sync(s: &str) -> bool {
    from_sync(s).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_syna() {
        let addr = [0x42u8; 20];
        let encoded = evm_to_syna(&addr).unwrap();
        assert!(encoded.starts_with("syna1"));
        let decoded = syna_to_evm(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_roundtrip_sync() {
        let addr = [0x99u8; 20];
        let encoded = to_sync(&addr).unwrap();
        assert!(encoded.starts_with("sync1"));
        let decoded = from_sync(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_known_address() {
        // A well-known EVM address (0x0000...0001) should produce a valid syna address
        let addr = [0u8; 19].iter().cloned().chain(std::iter::once(1u8)).collect::<Vec<u8>>();
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&addr);
        let encoded = evm_to_syna(&arr).unwrap();
        assert!(encoded.starts_with("syna1"));
        let decoded = syna_to_evm(&encoded).unwrap();
        assert_eq!(decoded, arr);
    }

    #[test]
    fn test_derive_contract_address() {
        let deployer = [0xABu8; 20];
        let artifact = [0xCDu8; 32];
        let constructor = [0xEFu8; 32];
        let addr1 = derive_contract_address(&deployer, 0, &artifact, &constructor, "synergy-testnet-v3").unwrap();
        let addr2 = derive_contract_address(&deployer, 1, &artifact, &constructor, "synergy-testnet-v3").unwrap();
        assert!(addr1.starts_with("sync1"));
        assert!(addr2.starts_with("sync1"));
        assert_ne!(addr1, addr2, "different nonces must produce different addresses");
    }

    #[test]
    fn test_invalid_checksum_rejected() {
        let addr = [0x42u8; 20];
        let mut encoded = evm_to_syna(&addr).unwrap();
        // Corrupt the last character
        let last = encoded.pop().unwrap();
        let corrupted = if last == 'q' { 'p' } else { 'q' };
        encoded.push(corrupted);
        assert!(syna_to_evm(&encoded).is_err(), "corrupted checksum must be rejected");
    }

    #[test]
    fn test_wrong_hrp_rejected() {
        let addr = [0x42u8; 20];
        let encoded = to_sync(&addr).unwrap();  // sync, not syna
        assert!(syna_to_evm(&encoded).is_err(), "sync address must not decode as syna");
    }

    #[test]
    fn test_case_insensitive() {
        let addr = [0x42u8; 20];
        let encoded = evm_to_syna(&addr).unwrap();
        let upper = encoded.to_uppercase();
        assert_eq!(syna_to_evm(&upper).unwrap(), addr, "uppercase Bech32 must decode");
    }

    #[test]
    fn test_contract_address_deterministic() {
        let deployer = [0x11u8; 20];
        let artifact = [0x22u8; 32];
        let constructor = [0x33u8; 32];
        let a1 = derive_contract_address(&deployer, 5, &artifact, &constructor, "synergy-testnet-v3").unwrap();
        let a2 = derive_contract_address(&deployer, 5, &artifact, &constructor, "synergy-testnet-v3").unwrap();
        assert_eq!(a1, a2, "same inputs must produce same address");
        // Different network → different address
        let a3 = derive_contract_address(&deployer, 5, &artifact, &constructor, "mainnet-beta").unwrap();
        assert_ne!(a1, a3, "different network must produce different address");
    }
}
