//! SNTS-01 network-address encode/decode for AIVM's `addr.encode`/`addr.decode`
//! host functions (import indices 17/18 -- see host.rs's HostFunctions::default_v01
//! and execute_host_call).
//!
//! This is a deliberate, self-contained port of the algorithm in
//! vm::bech32 (encode_network_address/decode_network_address/
//! encode_wallet_address) rather than a cross-crate dependency on the
//! synq-vm crate: the aivm crate has never depended on synq-vm (it's the
//! independent sandbox/dry-run engine, not the deployed-chain VM), and
//! duplicating this self-contained ~100-line algorithm (same approach the
//! browser-side app/lib/ide/address-format.ts mirror already takes) keeps
//! that boundary intact rather than introducing a new inter-crate edge for
//! one function. Any future correctness fix to the algorithm must be
//! applied in both places -- same maintenance tradeoff address-format.ts
//! already accepted.
//!
//! Only the CURRENT, non-gated default wallet encoding ("synw" HRP) is
//! covered here -- NOT the Phase 3 contract-address SNTS-01 migration
//! ("sync" HRP + SHA3-256 derivation), which stays behind Justin's
//! sequencing decision (see vm::bech32::derive_contract_address_snts01's
//! doc comment and notes/synq-forge-toolchain/address-engine-migration-scope.md).
//! addr.contract_address (import index 19) is intentionally left
//! undeclared here.
//!
//! Legacy tsynq1.../synq1... decode is intentionally NOT implemented --
//! decode_network_address returns a clear "not supported" error for those
//! prefixes instead of a generic HostFunctionNotDeclared, since v1.3 of the
//! naming standard already treats that HRP as retired (see
//! notes/synq-forge-toolchain/protocol-naming-standards.md).

use sha2::{Digest, Sha256};

const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc830a3;
const NETWORK_ADDR_TARGET_LEN: usize = 41;
const NETWORK_ZERO_ADDRESS: &str = "syn00000000000000000000000000000000000000";
/// Wallet HRP -- the current default display encoding for a caller/owner
/// identifier (see vm::bech32::HRP_WALLET).
const HRP_WALLET: &str = "synw";

/// Address version per synq-address-format-spec (see vm::bech32::ADDR_VERSION).
const ADDR_VERSION: u8 = 0x01;
/// Network ID for chain 1266 (testnet) -- see vm::bech32::NETWORK_ID_TESTNET.
const NETWORK_ID_TESTNET: [u8; 2] = [0x04, 0xf2];
/// Algorithm ID for ML-DSA-65 (default signer algorithm) -- see
/// vm::bech32::ALGO_ML_DSA_65.
const ALGO_ML_DSA_65: [u8; 2] = [0x01, 0x02];

fn polymod(values: &[u8]) -> u32 {
    let generators: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;
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

fn create_checksum(hrp: &str, data: &[u8]) -> Vec<u8> {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0u8; 6]);
    let mod_val = polymod(&values) ^ BECH32M_CONST;
    let mut ret = Vec::with_capacity(6);
    for i in 0..6 {
        ret.push(((mod_val >> (5 * (5 - i))) & 31) as u8);
    }
    ret
}

fn verify_checksum(hrp: &str, data: &[u8]) -> bool {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    polymod(&values) == BECH32M_CONST
}

/// Extracts `count` 5-bit groups from `bytes`, big-endian bit order --
/// exact port of vm::bech32::extract_base32_values.
fn extract_base32_values(bytes: &[u8], count: usize) -> Vec<u8> {
    let mut values = Vec::with_capacity(count);
    for i in 0..count {
        let bit_offset = i * 5;
        let byte_idx = bit_offset / 8;
        let bit_idx = bit_offset % 8;
        let val = if bit_idx <= 3 {
            (bytes.get(byte_idx).copied().unwrap_or(0) >> (3 - bit_idx)) & 0x1f
        } else {
            let high_bits = (bytes.get(byte_idx).copied().unwrap_or(0) << (bit_idx - 3)) & 0x1f;
            let low_bits = if byte_idx + 1 < bytes.len() {
                bytes[byte_idx + 1] >> (11 - bit_idx)
            } else {
                0
            };
            high_bits | low_bits
        };
        values.push(val);
    }
    values
}

/// Inverse of extract_base32_values -- exact port of
/// vm::bech32::pack_base32_values.
fn pack_base32_values(values: &[u8]) -> Vec<u8> {
    let total_bits = values.len() * 5;
    let mut buf = vec![0u8; (total_bits + 7) / 8];
    for (i, &v) in values.iter().enumerate() {
        let bit_offset = i * 5;
        let byte_idx = bit_offset / 8;
        let bit_idx = bit_offset % 8;
        let v = v & 0x1f;
        if bit_idx <= 3 {
            buf[byte_idx] |= v << (3 - bit_idx);
        } else {
            let high_bits = v >> (bit_idx - 3);
            let low_bits = (v << (11 - bit_idx)) & 0xff;
            buf[byte_idx] |= high_bits;
            if byte_idx + 1 < buf.len() {
                buf[byte_idx + 1] |= low_bits;
            }
        }
    }
    buf
}

/// Encodes a VM 20-byte caller/owner identifier as an SNTS-01 network
/// address with the given HRP -- exact port of
/// vm::bech32::encode_network_address.
pub fn encode_network_address(hrp: &str, id: &[u8; 20]) -> Result<String, String> {
    if *id == [0u8; 20] {
        return Ok(NETWORK_ZERO_ADDRESS.to_string());
    }
    let data_char_count = NETWORK_ADDR_TARGET_LEN
        .checked_sub(hrp.len() + 1 + 6)
        .ok_or_else(|| format!("HRP '{}' too long for a {}-char address", hrp, NETWORK_ADDR_TARGET_LEN))?;
    let data5 = extract_base32_values(id, data_char_count);
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

/// Convenience: encode as a `synw` wallet address -- exact port of
/// vm::bech32::encode_wallet_address.
pub fn encode_wallet_address(id: &[u8; 20]) -> Result<String, String> {
    encode_network_address(HRP_WALLET, id)
}

/// Decodes an SNTS-01 network address (synw1..., syna1..., etc., or the
/// all-zero sentinel) into the VM's 20-byte internal identifier -- exact
/// port of vm::bech32::decode_network_address. Legacy tsynq1.../synq1...
/// addresses are explicitly rejected with a clear message (see module doc).
pub fn decode_network_address(s: &str) -> Result<[u8; 20], String> {
    let trimmed = s.trim();
    if trimmed.starts_with("tsynq1") || trimmed.starts_with("synq1") {
        return Err("legacy tsynq/synq address decode is not supported by the AIVM dry-run sandbox (retired per Synergy Protocol Naming & Encoding Standards v1.3) -- pass a synw/syna-style address instead".to_string());
    }
    if trimmed == NETWORK_ZERO_ADDRESS {
        return Ok([0u8; 20]);
    }
    if trimmed.len() != NETWORK_ADDR_TARGET_LEN {
        return Err(format!("expected a {}-character network address, got {}", NETWORK_ADDR_TARGET_LEN, trimmed.len()));
    }
    if !trimmed.starts_with("syn") {
        return Err("network addresses must start with 'syn'".to_string());
    }
    let lower = trimmed.to_lowercase();
    let pos = match lower.rfind('1') {
        Some(p) if p >= 1 => p,
        _ => return Err("no separator".to_string()),
    };
    let hrp = &lower[..pos];
    let data_part = &lower[pos + 1..];
    if hrp.is_empty() || data_part.len() < 6 {
        return Err("invalid structure".to_string());
    }
    let mut data5 = Vec::with_capacity(data_part.len());
    for c in data_part.bytes() {
        match CHARSET.iter().position(|&x| x == c) {
            Some(idx) => data5.push(idx as u8),
            None => return Err(format!("invalid character: {}", c as char)),
        }
    }
    if !verify_checksum(hrp, &data5) {
        return Err("invalid Bech32m checksum".to_string());
    }
    let len = data5.len();
    data5.truncate(len - 6);
    let mut bytes = pack_base32_values(&data5);
    bytes.resize(20, 0);
    let mut id = [0u8; 20];
    id.copy_from_slice(&bytes[..20]);
    Ok(id)
}

/// Builds the full 41-byte SynqAddress-shaped identity for a decoded
/// 20-byte id, matching synq-server's parse_caller_address construction
/// for a synw-style caller (SynqAddress::from_20_bytes(id, ALGO_ML_DSA_65,
/// NETWORK_ID_TESTNET).to_bytes()) -- so a value round-tripped through
/// addr.decode then addr.encode inside one dry-run reproduces the exact
/// same synw string, and matches what a synw caller override already
/// becomes on ExecutionContext::caller.
pub fn decoded_id_to_address_bytes(id: &[u8; 20]) -> [u8; 41] {
    let mut pk_hash = [0u8; 32];
    pk_hash[0..20].copy_from_slice(id);
    let mut buf = [0u8; 41];
    buf[0] = ADDR_VERSION;
    buf[1..3].copy_from_slice(&NETWORK_ID_TESTNET);
    buf[3..5].copy_from_slice(&ALGO_ML_DSA_65);
    buf[5..37].copy_from_slice(&pk_hash);
    let mut hasher = Sha256::new();
    hasher.update([buf[0]]);
    hasher.update(NETWORK_ID_TESTNET);
    hasher.update(ALGO_ML_DSA_65);
    hasher.update(pk_hash);
    let hash = hasher.finalize();
    buf[37..41].copy_from_slice(&hash[0..4]);
    buf
}
