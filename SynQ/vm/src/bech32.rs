//! SynQ address format — Bech32m encoding per synq-address-format-spec v0.1.
//!
//! Internal address: 41 bytes
//!   [0]    address version (0x01)
//!   [1..3] network ID (0x04f2 for chain 1266)
//!   [3..5] algorithm ID (e.g. 0x0102 for ML-DSA-65)
//!   [5..37] public key hash = SHA-256(public_key_bytes)
//!   [37..41] checksum = first 4 bytes of SHA-256(version || network_id || algo_id || pk_hash)
//!
//! Human encoding: Bech32m with HRP `tsynq` (testnet), `synq` (mainnet reserved).
//!
//! Implementations MUST store and compare internal bytes. Human strings are
//! display and input encoding only.

use sha2::{Sha256, Digest};
use sha3::Sha3_256;

/// HRP for testnet addresses.
pub const HRP_TESTNET: &str = "tsynq";
/// HRP for mainnet addresses (reserved).
pub const HRP_MAINNET: &str = "synq";

/// Address version per spec.
pub const ADDR_VERSION: u8 = 0x01;

/// Network ID for chain 1266 (testnet).
pub const NETWORK_ID_TESTNET: [u8; 2] = 0x04f2u16.to_be_bytes();

/// Algorithm ID for ML-DSA-65 (default).
pub const ALGO_ML_DSA_65: [u8; 2] = 0x0102u16.to_be_bytes();

/// Algorithm ID for contract addresses (no signature algorithm).
pub const ALGO_CONTRACT: [u8; 2] = 0x0000u16.to_be_bytes();

/// Internal address size: 1 + 2 + 2 + 32 + 4 = 41 bytes.
pub const ADDRESS_LEN: usize = 41;

/// Bech32m checksum constant (differs from Bech32's 1).
const BECH32M_CONST: u32 = 0x2bc830a3;

/// Bech32 character set (5-bit values → chars).
const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// ── Bech32m core ─────────────────────────────────────────────────────────────

/// Convert bytes between bit widths.
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
    let mut chk: u32 = 1; // Bech32 and Bech32m both start with 1
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

/// Compute the Bech32m checksum (6 5-bit groups).
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

/// Verify the Bech32m checksum.
fn verify_checksum(hrp: &str, data: &[u8]) -> bool {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    polymod(&values) == BECH32M_CONST
}

/// Encode data as a Bech32m string with the given HRP.
pub fn bech32m_encode(hrp: &str, data: &[u8]) -> Result<String, String> {
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

/// Decode a Bech32m string, returning (HRP, data bytes).
pub fn bech32m_decode(s: &str) -> Result<(String, Vec<u8>), String> {
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
        return Err("invalid Bech32m checksum".into());
    }
    let payload = &data5[..data5.len() - 6];
    let decoded = convert_bits(payload, 5, 8, false)?;
    Ok((hrp.to_string(), decoded))
}

// ── SynQ 41-byte address format ──────────────────────────────────────────────

/// A SynQ internal address (41 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SynqAddress {
    pub version: u8,
    pub network_id: [u8; 2],
    pub algorithm_id: [u8; 2],
    pub pk_hash: [u8; 32],
    pub checksum: [u8; 4],
}

impl SynqAddress {
    /// Total serialized length.
    pub const LEN: usize = 41;

    /// Compute the public key hash from raw public key bytes.
    pub fn pk_hash(public_key: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        hasher.finalize().into()
    }

    /// Compute the checksum from version + network_id + algo_id + pk_hash.
    pub fn compute_checksum(version: u8, network_id: &[u8; 2], algorithm_id: &[u8; 2], pk_hash: &[u8; 32]) -> [u8; 4] {
        let mut input = Vec::with_capacity(37);
        input.push(version);
        input.extend_from_slice(network_id);
        input.extend_from_slice(algorithm_id);
        input.extend_from_slice(pk_hash);
        let mut hasher = Sha256::new();
        hasher.update(&input);
        let hash = hasher.finalize();
        let mut cksum = [0u8; 4];
        cksum.copy_from_slice(&hash[0..4]);
        cksum
    }

    /// Create a new address from public key bytes with the given algorithm.
    pub fn from_public_key(public_key: &[u8], algorithm_id: [u8; 2], network_id: [u8; 2]) -> Self {
        let pk_hash = Self::pk_hash(public_key);
        let checksum = Self::compute_checksum(ADDR_VERSION, &network_id, &algorithm_id, &pk_hash);
        Self {
            version: ADDR_VERSION,
            network_id,
            algorithm_id,
            pk_hash,
            checksum,
        }
    }

    /// Create a new address from a 20-byte internal identifier (truncated pk_hash).
    /// The 20 bytes are zero-padded to 32 bytes for the pk_hash field.
    pub fn from_20_bytes(id: &[u8; 20], algorithm_id: [u8; 2], network_id: [u8; 2]) -> Self {
        let mut pk_hash = [0u8; 32];
        pk_hash[0..20].copy_from_slice(id);
        let checksum = Self::compute_checksum(ADDR_VERSION, &network_id, &algorithm_id, &pk_hash);
        Self {
            version: ADDR_VERSION,
            network_id,
            algorithm_id,
            pk_hash,
            checksum,
        }
    }

    /// Create a contract address from a 20-byte derived identifier.
    pub fn from_contract_id(id: &[u8; 20], network_id: [u8; 2]) -> Self {
        Self::from_20_bytes(id, ALGO_CONTRACT, network_id)
    }

    /// Serialize to 41 bytes.
    pub fn to_bytes(&self) -> [u8; 41] {
        let mut buf = [0u8; 41];
        buf[0] = self.version;
        buf[1..3].copy_from_slice(&self.network_id);
        buf[3..5].copy_from_slice(&self.algorithm_id);
        buf[5..37].copy_from_slice(&self.pk_hash);
        buf[37..41].copy_from_slice(&self.checksum);
        buf
    }

    /// Deserialize from 41 bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, String> {
        if buf.len() != 41 {
            return Err(format!("expected 41 bytes, got {}", buf.len()));
        }
        let version = buf[0];
        if version != ADDR_VERSION {
            return Err(format!("unsupported address version: 0x{:02x}", version));
        }
        let mut network_id = [0u8; 2];
        network_id.copy_from_slice(&buf[1..3]);
        let mut algorithm_id = [0u8; 2];
        algorithm_id.copy_from_slice(&buf[3..5]);
        let mut pk_hash = [0u8; 32];
        pk_hash.copy_from_slice(&buf[5..37]);
        let mut checksum = [0u8; 4];
        checksum.copy_from_slice(&buf[37..41]);

        // Verify checksum
        let expected = Self::compute_checksum(version, &network_id, &algorithm_id, &pk_hash);
        if checksum != expected {
            return Err("address checksum mismatch".into());
        }

        Ok(Self { version, network_id, algorithm_id, pk_hash, checksum })
    }

    /// Encode as a Bech32m string with the testnet HRP.
    pub fn to_tsynq(&self) -> Result<String, String> {
        bech32m_encode(HRP_TESTNET, &self.to_bytes())
    }

    /// Encode as a Bech32m string with the mainnet HRP.
    pub fn to_synq(&self) -> Result<String, String> {
        bech32m_encode(HRP_MAINNET, &self.to_bytes())
    }

    /// Get the 20-byte internal identifier (first 20 bytes of pk_hash).
    /// This is what the VM uses internally for storage and comparison.
    pub fn to_20_bytes(&self) -> [u8; 20] {
        let mut id = [0u8; 20];
        id.copy_from_slice(&self.pk_hash[0..20]);
        id
    }

    /// Check if this is a contract address (algorithm_id == 0x0000).
    pub fn is_contract(&self) -> bool {
        self.algorithm_id == ALGO_CONTRACT
    }
}

// ── Convenience functions (drop-in replacements for old API) ──────────────────

/// Encode a 20-byte internal identifier as a `tsynq...` Bech32m string.
/// Uses ML-DSA-65 algorithm ID by default.
pub fn encode_address(addr: &[u8; 20]) -> Result<String, String> {
    SynqAddress::from_20_bytes(addr, ALGO_ML_DSA_65, NETWORK_ID_TESTNET).to_tsynq()
}

/// Encode a 20-byte internal identifier as a `tsynq...` contract address.
pub fn encode_contract_address(addr: &[u8; 20]) -> Result<String, String> {
    SynqAddress::from_contract_id(addr, NETWORK_ID_TESTNET).to_tsynq()
}

/// Decode a `tsynq...` Bech32m string to a 20-byte internal identifier.
/// Also accepts `synq...` (mainnet) for forward compatibility.
pub fn decode_address(s: &str) -> Result<[u8; 20], String> {
    let (hrp, data) = bech32m_decode(s)?;
    if hrp != HRP_TESTNET && hrp != HRP_MAINNET {
        return Err(format!("expected HRP '{}' or '{}', got '{}'", HRP_TESTNET, HRP_MAINNET, hrp));
    }
    let addr = SynqAddress::from_bytes(&data)?;
    Ok(addr.to_20_bytes())
}

/// Decode any valid SynQ Bech32m address to 20 bytes.
/// Accepts tsynq and synq HRPs.
pub fn from_any_synq(s: &str) -> Result<[u8; 20], String> {
    decode_address(s)
}

/// Check if a string is a valid tsynq/synq address.
pub fn is_valid_address(s: &str) -> bool {
    decode_address(s).is_ok()
}

// ── Network-facing SNTS-01 addresses (synw/syna/etc.) ─────────────────────────
//
// The community-facing Synergy Address Engine (synergy-wts / L1 src/address.rs)
// uses a DIFFERENT, shorter Bech32m format than this VM's own tsynq/synq
// scheme above: SHA3-256(pubkey) truncated to a fixed number of leading bits
// (chosen so the encoded string is exactly 41 characters including the HRP),
// with no embedded version/network/algo/checksum-payload fields -- the
// Bech32m checksum is the only integrity check. Prefixes: `synw` (primary
// wallet), `syna` (standard account), `sync` (custom contract), etc.
//
// Decision (2026-08-22): tsynq/synq (this file's own scheme, above) is
// deprecated for human-facing display. Forge and the wallet UI show/accept
// synw-style addresses; tsynq/synq are kept only as a legacy-input fallback
// for backward compatibility. The functions below let the VM's raw 20-byte
// caller/owner identifiers round-trip through the synw format WITHOUT
// needing the original public key: decoding a synw string recovers exactly
// the leading hash bits that were extracted into it, and re-encoding those
// same bits reproduces the byte-identical original string (verified via a
// Python prototype against real derive_address_from_bytes output).

/// Canonical all-zero / "no wallet" sentinel per the SNTS-01 address spec
/// (`NETWORK_BURN_ADDRESS` in the L1 `src/address.rs`). NOT a real Bech32m
/// string (no `1` separator) -- it's a literal reserved constant, so it's
/// special-cased on both encode and decode rather than round-tripped.
pub const NETWORK_ZERO_ADDRESS: &str = "syn00000000000000000000000000000000000000";

/// Target total character length for SNTS-01 network addresses (HRP + '1' +
/// data + 6-char checksum), per the L1 address spec (`TARGET_ADDRESS_LEN`).
const NETWORK_ADDR_TARGET_LEN: usize = 41;

/// Default HRP used when encoding a VM caller/owner identifier as a network
/// wallet address (the common case: a caller/owner that came from a
/// connected wallet). Callers that know the address represents a different
/// kind (contract, multisig, etc.) should pass the right HRP explicitly.
pub const HRP_WALLET: &str = "synw";

/// Extracts `count` 5-bit groups from `bytes`, big-endian bit order --
/// mirrors `extract_base32_values` in the L1 `src/address.rs` exactly (kept
/// as a separate copy here since this VM crate doesn't depend on that
/// binary crate). Forward direction (bytes -> 5-bit groups); `pack_base32_values`
/// below is its exact inverse.
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

/// Inverse of `extract_base32_values`: packs 5-bit groups back into a byte
/// buffer at the same bit offsets they were extracted from, so decoding a
/// synw-style address and re-encoding it reproduces the identical string.
/// Bits beyond the last full byte covered by `values` are left zero.
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

/// Decodes a Bech32m string, returning (hrp, 5-bit data groups with the
/// trailing 6-character checksum already stripped). Unlike `bech32m_decode`
/// above, this does NOT run the byte-oriented `convert_bits(_, 5, 8, false)`
/// step -- SNTS-01 addresses don't encode a whole number of bytes (e.g. a
/// 30-group synw payload is 150 bits = 18.75 bytes), so the strict
/// byte-padding check in `convert_bits` would reject every valid synw
/// address. Callers that DO want whole bytes (tsynq/synq) use `bech32m_decode`.
fn bech32m_decode_raw_groups(s: &str) -> Result<(String, Vec<u8>), String> {
    if s.len() < 8 || s.len() > 90 {
        return Err(format!("invalid length: {}", s.len()));
    }
    let lower = s.to_lowercase();
    let pos = match lower.rfind('1') {
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
        return Err("invalid Bech32m checksum".into());
    }
    let len = data5.len();
    data5.truncate(len - 6);
    Ok((hrp.to_string(), data5))
}

/// Decodes any SNTS-01 network address (`synw1...`, `syna1...`, etc., or the
/// literal all-zero sentinel) into the VM's 20-byte internal identifier
/// space. Recovers exactly the leading hash bits originally extracted into
/// the address (150 bits / 18.75 bytes for a 4-char HRP like `synw`),
/// zero-padded up to 20 bytes -- a byte-for-byte extraction (not a hash of
/// the address string), so `encode_network_address` is its exact inverse.
pub fn decode_network_address(s: &str) -> Result<[u8; 20], String> {
    if s == NETWORK_ZERO_ADDRESS {
        return Ok([0u8; 20]);
    }
    if s.len() != NETWORK_ADDR_TARGET_LEN {
        return Err(format!(
            "expected a {}-character network address, got {}",
            NETWORK_ADDR_TARGET_LEN,
            s.len()
        ));
    }
    if !s.starts_with("syn") {
        return Err("network addresses must start with 'syn'".into());
    }
    let (_hrp, data5) = bech32m_decode_raw_groups(s)?;
    let mut bytes = pack_base32_values(&data5);
    bytes.resize(20, 0);
    let mut id = [0u8; 20];
    id.copy_from_slice(&bytes[..20]);
    Ok(id)
}

/// Encodes a VM 20-byte caller/owner identifier as an SNTS-01 network
/// address with the given HRP (e.g. `synw` for a wallet). Returns the
/// literal all-zero sentinel when `id` is all-zero (no wallet/no caller) --
/// per spec that sentinel is a reserved constant, not a derived Bech32m
/// string, so it's never round-tripped through the bit-packing below.
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

/// Convenience: encode as a `synw` wallet address -- the common case for a
/// caller/owner identifier, and the new default display HRP replacing
/// `encode_address`'s tsynq output.
pub fn encode_wallet_address(id: &[u8; 20]) -> Result<String, String> {
    encode_network_address(HRP_WALLET, id)
}

/// Accepts either a real SNTS-01 network address (synw/syna/etc., or the
/// all-zero sentinel) or a legacy tsynq/synq address, returning the VM's
/// 20-byte internal identifier either way. Prefer this over `from_any_synq`
/// for new input paths (session caller overrides, deep-link wallet params) --
/// tsynq/synq are accepted here only for backward compatibility with older
/// saved links/sessions that still carry a tsynq address.
pub fn from_any_network_address(s: &str) -> Result<[u8; 20], String> {
    let trimmed = s.trim();
    if trimmed.starts_with("tsynq1") || trimmed.starts_with("synq1") {
        return from_any_synq(trimmed);
    }
    decode_network_address(trimmed)
}

/// HRP for user-deployed SynQ contracts per SNTS v1.3's canonical namespace
/// registry (`sync` = "Custom Contract", the Contract standard). `synq` is
/// reserved there for network-deployed SYSTEM contracts only -- this VM
/// doesn't deploy system contracts, so only the user-contract HRP is wired
/// up here.
pub const HRP_CONTRACT: &str = "sync";

/// SNTS v1.3-conformant contract-address derivation -- SHA3-256 (per the
/// standard) into the SNTS-01 network-address encoding (`encode_network_address`
/// with HRP_CONTRACT = "sync"), instead of `derive_contract_address` below's
/// legacy SHA-256 + deprecated fixed-byte SynqAddress{version,network_id,
/// algorithm_id,pk_hash,checksum} layout (which v1.3's own revision history
/// says was removed as unsupported).
///
/// NOT wired into the live ContractAddr (0x56) opcode by default -- see the
/// `SYNQ_CONTRACT_ADDR_SNTS01` opt-in env var in vm.rs. Every existing
/// deployed-contract address must keep deriving identically (legacy tsynq/
/// SHA-256) until Phase 3's cutover is explicitly sequenced with Justin --
/// this function exists so the new derivation can be reviewed, tested, and
/// switched on for real once that decision is made, not to change runtime
/// behavior silently. See notes/synq-forge-toolchain/address-engine-migration-scope.md
/// ("Real gaps / conflicts" #4) for the full backward-compat / SQB-format
/// considerations before flipping the default.
pub fn derive_contract_address_snts01(
    deployer: &[u8; 20],
    nonce: u64,
    artifact_hash: &[u8; 32],
    constructor_hash: &[u8; 32],
) -> Result<String, String> {
    let mut hasher = Sha3_256::new();
    hasher.update(deployer);
    hasher.update(&nonce.to_be_bytes());
    hasher.update(artifact_hash);
    hasher.update(constructor_hash);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut id = [0u8; 20];
    id.copy_from_slice(&digest[0..20]);
    encode_network_address(HRP_CONTRACT, &id)
}

/// Derive a contract address from deployment parameters.
///
/// pk_hash = SHA-256(deployer[20] || nonce_be[8] || artifact_hash[32] || constructor_hash[32] || network_id)
/// address = SynqAddress { version, network_id, algo_id=0x0000, pk_hash, checksum }
/// Encoded as tsynq Bech32m.
pub fn derive_contract_address(
    deployer: &[u8; 20],
    nonce: u64,
    artifact_hash: &[u8; 32],
    constructor_hash: &[u8; 32],
    network_id: &str,
) -> Result<String, String> {
    let mut hasher = Sha256::new();
    hasher.update(deployer);
    hasher.update(&nonce.to_be_bytes());
    hasher.update(artifact_hash);
    hasher.update(constructor_hash);
    hasher.update(network_id.as_bytes());
    let pk_hash: [u8; 32] = hasher.finalize().into();

    let network_id_bytes = if network_id.contains("mainnet") {
        // Mainnet: we don't have a defined network_id yet, use testnet for now
        NETWORK_ID_TESTNET
    } else {
        NETWORK_ID_TESTNET
    };

    let checksum = SynqAddress::compute_checksum(ADDR_VERSION, &network_id_bytes, &ALGO_CONTRACT, &pk_hash);
    let addr = SynqAddress {
        version: ADDR_VERSION,
        network_id: network_id_bytes,
        algorithm_id: ALGO_CONTRACT,
        pk_hash,
        checksum,
    };
    addr.to_tsynq()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bech32m_not_bech32() {
        // Bech32m constant must be 0x2bc830a3, not 1 (Bech32)
        assert_eq!(BECH32M_CONST, 0x2bc830a3);
    }

    #[test]
    fn test_spec_pk_hash() {
        // Spec test vector: public key 0x010203, SHA-256 should give known hash
        let pk = [0x01, 0x02, 0x03];
        let hash = SynqAddress::pk_hash(&pk);
        assert_eq!(
            hex::encode(hash),
            "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81",
            "pk_hash must match spec test vector"
        );
    }

    #[test]
    fn test_spec_checksum_input_length() {
        // Spec says checksum input is 37 bytes: version(1) + network_id(2) + algo_id(2) + pk_hash(32)
        let pk = [0x01, 0x02, 0x03];
        let pk_hash = SynqAddress::pk_hash(&pk);
        let mut input = Vec::with_capacity(37);
        input.push(ADDR_VERSION);
        input.extend_from_slice(&NETWORK_ID_TESTNET);
        input.extend_from_slice(&ALGO_ML_DSA_65);
        input.extend_from_slice(&pk_hash);
        assert_eq!(input.len(), 37, "checksum input must be 37 bytes per spec");
    }

    #[test]
    fn test_address_from_public_key() {
        let pk = [0x01, 0x02, 0x03];
        let addr = SynqAddress::from_public_key(&pk, ALGO_ML_DSA_65, NETWORK_ID_TESTNET);
        assert_eq!(addr.version, 0x01);
        assert_eq!(addr.network_id, NETWORK_ID_TESTNET);
        assert_eq!(addr.algorithm_id, ALGO_ML_DSA_65);
        // Verify checksum is correct
        let expected_cksum = SynqAddress::compute_checksum(
            addr.version, &addr.network_id, &addr.algorithm_id, &addr.pk_hash
        );
        assert_eq!(addr.checksum, expected_cksum);
    }

    #[test]
    fn test_address_serialization_roundtrip() {
        let pk = [0x01, 0x02, 0x03];
        let addr = SynqAddress::from_public_key(&pk, ALGO_ML_DSA_65, NETWORK_ID_TESTNET);
        let bytes = addr.to_bytes();
        assert_eq!(bytes.len(), 41);
        let recovered = SynqAddress::from_bytes(&bytes).unwrap();
        assert_eq!(addr, recovered);
    }

    #[test]
    fn test_bech32m_encode_decode_roundtrip() {
        let pk = [0x01, 0x02, 0x03];
        let addr = SynqAddress::from_public_key(&pk, ALGO_ML_DSA_65, NETWORK_ID_TESTNET);
        let encoded = addr.to_tsynq().unwrap();
        assert!(encoded.starts_with("tsynq1"), "must use tsynq HRP, got: {}", encoded);

        let (hrp, data) = bech32m_decode(&encoded).unwrap();
        assert_eq!(hrp, HRP_TESTNET);
        assert_eq!(data.len(), 41);

        let recovered = SynqAddress::from_bytes(&data).unwrap();
        assert_eq!(addr, recovered);
    }

    #[test]
    fn test_encode_decode_20_bytes_roundtrip() {
        let id = [0x42u8; 20];
        let encoded = encode_address(&id).unwrap();
        assert!(encoded.starts_with("tsynq1"));
        let decoded = decode_address(&encoded).unwrap();
        assert_eq!(decoded, id);
    }

    #[test]
    fn test_contract_address_roundtrip() {
        let id = [0x99u8; 20];
        let encoded = encode_contract_address(&id).unwrap();
        assert!(encoded.starts_with("tsynq1"));
        let decoded = decode_address(&encoded).unwrap();
        assert_eq!(decoded, id);
    }

    #[test]
    fn test_derive_contract_address() {
        let deployer = [0xABu8; 20];
        let artifact = [0xCDu8; 32];
        let constructor = [0xEFu8; 32];
        let addr1 = derive_contract_address(&deployer, 0, &artifact, &constructor, "synergy-testnet-v3").unwrap();
        let addr2 = derive_contract_address(&deployer, 1, &artifact, &constructor, "synergy-testnet-v3").unwrap();
        assert!(addr1.starts_with("tsynq1"));
        assert!(addr2.starts_with("tsynq1"));
        assert_ne!(addr1, addr2, "different nonces must produce different addresses");
    }

    #[test]
    fn test_invalid_checksum_rejected() {
        let id = [0x42u8; 20];
        let mut encoded = encode_address(&id).unwrap();
        // Corrupt the last character
        let last = encoded.pop().unwrap();
        let corrupted = if last == 'q' { 'p' } else { 'q' };
        encoded.push(corrupted);
        assert!(decode_address(&encoded).is_err(), "corrupted checksum must be rejected");
    }

    #[test]
    fn test_wrong_hrp_rejected() {
        // Encode with tsynq, try to decode with wrong HRP check
        let id = [0x42u8; 20];
        let encoded = encode_address(&id).unwrap();
        // Manually swap HRP to something invalid
        let bad = format!("xxxx1{}", encoded.split('1').nth(1).unwrap());
        assert!(decode_address(&bad).is_err(), "wrong HRP must be rejected");
    }

    #[test]
    fn test_address_to_bytes_spec_compliance() {
        let pk = [0x01, 0x02, 0x03];
        let addr = SynqAddress::from_public_key(&pk, ALGO_ML_DSA_65, NETWORK_ID_TESTNET);
        let bytes = addr.to_bytes();

        // Verify structure per spec
        assert_eq!(bytes[0], 0x01, "address version must be 0x01");
        assert_eq!(&bytes[1..3], &[0x04, 0xf2], "network ID must be 0x04f2 for chain 1266");
        assert_eq!(&bytes[3..5], &[0x01, 0x02], "algorithm ID must be 0x0102 for ML-DSA-65");
        assert_eq!(&bytes[5..37], hex::decode("039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81").unwrap(), "pk_hash must match spec test vector");

        // Verify checksum
        let expected = SynqAddress::compute_checksum(0x01, &[0x04, 0xf2], &[0x01, 0x02], &addr.pk_hash);
        assert_eq!(&bytes[37..41], &expected, "checksum must be SHA-256 first 4 bytes");
    }
}

#[cfg(test)]
mod network_address_tests {
    use super::*;

    #[test]
    fn test_zero_address_encodes_to_sentinel() {
        let id = [0u8; 20];
        let encoded = encode_network_address(HRP_WALLET, &id).unwrap();
        assert_eq!(encoded, NETWORK_ZERO_ADDRESS);
        assert_eq!(encoded.len(), 41);
    }

    #[test]
    fn test_sentinel_decodes_to_zero() {
        let id = decode_network_address(NETWORK_ZERO_ADDRESS).unwrap();
        assert_eq!(id, [0u8; 20]);
    }

    #[test]
    fn test_roundtrip_arbitrary_id() {
        // A non-zero, non-trivial 20-byte id (avoids the all-zero special case).
        let id: [u8; 20] = [
            0x9e, 0x62, 0x91, 0x97, 0x0c, 0xb4, 0x4d, 0xd9, 0x40, 0x08, 0xc7, 0x9b, 0xca, 0xf9,
            0xd8, 0x6f, 0x18, 0xb4, 0xb4, 0x00,
        ];
        let encoded = encode_network_address(HRP_WALLET, &id).unwrap();
        assert!(encoded.starts_with("synw1"), "got: {}", encoded);
        assert_eq!(encoded.len(), 41);
        let decoded = decode_network_address(&encoded).unwrap();
        assert_eq!(decoded, id);
        // Re-encoding the decoded bytes must reproduce the exact same string.
        let reencoded = encode_network_address(HRP_WALLET, &decoded).unwrap();
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn test_matches_l1_address_engine_test_vector() {
        // Cross-checked against L1 src/address.rs::generate_wallet_address()
        // with ZERO_KEY_HEX (32 zero bytes) via a Python prototype of both
        // sides -- this is the exact expected synw string for that key, so
        // if the L1 hashing algorithm or bit-extraction ever drifts from
        // this VM's copy, this test catches it.
        let expected = "synw1ne3fr9cvk3xajsqgc7du47wcduvtfda2r2zr";
        let decoded = decode_network_address(expected).unwrap();
        assert_eq!(
            hex::encode(decoded),
            "9e6291970cb44dd94008c79bcaf9d86f18b4b400"
        );
        let reencoded = encode_network_address(HRP_WALLET, &decoded).unwrap();
        assert_eq!(reencoded, expected);
    }

    #[test]
    fn test_rejects_wrong_length() {
        assert!(decode_network_address("synw1short").is_err());
    }

    #[test]
    fn test_rejects_non_syn_prefix() {
        // Right length, wrong prefix entirely.
        let bogus = "abc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
        assert!(decode_network_address(bogus).is_err());
    }

    #[test]
    fn test_from_any_network_address_accepts_legacy_tsynq() {
        // Backward compatibility: old tsynq deep links must keep working.
        let addr = SynqAddress::from_20_bytes(&[0x11; 20], ALGO_ML_DSA_65, NETWORK_ID_TESTNET);
        let tsynq_str = addr.to_tsynq().unwrap();
        let decoded = from_any_network_address(&tsynq_str).unwrap();
        assert_eq!(decoded, [0x11; 20]);
    }

    #[test]
    fn test_from_any_network_address_accepts_synw() {
        // Last 10 bits must be zero -- a synw address only encodes the
        // leading 150 bits (18.75 bytes) of the 20-byte id by design.
        let id_prefix = [0x22u8; 18];
        let mut id = [0u8; 20];
        id[..18].copy_from_slice(&id_prefix);
        let synw_str = encode_wallet_address(&id).unwrap();
        let decoded = from_any_network_address(&synw_str).unwrap();
        assert_eq!(decoded, id);
    }

    #[test]
    fn test_from_any_network_address_accepts_zero_sentinel() {
        let decoded = from_any_network_address(NETWORK_ZERO_ADDRESS).unwrap();
        assert_eq!(decoded, [0u8; 20]);
    }

    #[test]
    fn test_derive_contract_address_snts01_uses_sync_hrp() {
        let deployer = [0x33u8; 20];
        let artifact_hash = [0x44u8; 32];
        let constructor_hash = [0x55u8; 32];
        let encoded = derive_contract_address_snts01(&deployer, 7, &artifact_hash, &constructor_hash).unwrap();
        assert!(encoded.starts_with("sync1"), "must use sync HRP, got: {}", encoded);
        // Must decode cleanly through the same SNTS-01 network-address path
        // used for synw wallet addresses (encode_network_address is
        // HRP-agnostic).
        let (hrp, _) = bech32m_decode_raw_groups(&encoded).unwrap();
        assert_eq!(hrp, "sync");
    }

    #[test]
    fn test_derive_contract_address_snts01_deterministic_and_nonce_sensitive() {
        let deployer = [0x66u8; 20];
        let artifact_hash = [0x77u8; 32];
        let constructor_hash = [0x88u8; 32];
        let a = derive_contract_address_snts01(&deployer, 1, &artifact_hash, &constructor_hash).unwrap();
        let b = derive_contract_address_snts01(&deployer, 1, &artifact_hash, &constructor_hash).unwrap();
        let c = derive_contract_address_snts01(&deployer, 2, &artifact_hash, &constructor_hash).unwrap();
        assert_eq!(a, b, "same inputs must derive the same address");
        assert_ne!(a, c, "different nonce must derive a different address");
    }

    #[test]
    fn test_legacy_derive_contract_address_unchanged_by_snts01_addition() {
        // Backward compatibility: adding the SNTS-01 path must not touch the
        // legacy tsynq/SHA-256 derivation's output at all.
        let deployer = [0x99u8; 20];
        let artifact_hash = [0xaau8; 32];
        let constructor_hash = [0xbbu8; 32];
        let legacy = derive_contract_address(&deployer, 3, &artifact_hash, &constructor_hash, "synergy-testnet-v3").unwrap();
        assert!(legacy.starts_with("tsynq1"), "legacy path must still emit tsynq, got: {}", legacy);
    }
}
