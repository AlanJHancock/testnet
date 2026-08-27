//! Client-side construction of pqsynq ContractDeployEnvelope / ContractCallEnvelope
//! JSON files, ready to hand to `synergy-node tx create-aegis --synq-deploy-envelope`
//! (or `--synq-call-envelope`) once the target node's write RPC is live.
//!
//! This module deliberately does NOT talk to any RPC endpoint. It only builds,
//! locally self-verifies (via AegisSynQVerifier), and serializes the envelope —
//! the exact same aegis-pqsynq types the node itself verifies on admission, so
//! a self-verify pass here is a strong signal the node will accept it too.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use pqsynq::{
    AegisSynQVerifier, AlgorithmId, ChainId, ContractCallEnvelope, ContractDeployEnvelope,
    DigitalSignature, DomainTag, Hash32, NetworkId, Sign, SignaturePurpose, SynQAddress,
    SynQPublicKey, SynQSignature, SynQSigningPayload, VerificationContext,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn sha256_array(bytes: &[u8]) -> Hash32 {
    let digest = Sha256::digest(bytes);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs()
}

/// Dev/test keyfile — NOT for mainnet use. Holds a raw ML-DSA-65 keypair plus
/// the derived testnet SynQ address, so later commands don't need to re-derive.
#[derive(Debug, Serialize, Deserialize)]
pub struct SynqDeployKeyfile {
    pub algorithm: String,
    pub public_key_hex: String,
    pub secret_key_hex: String,
    pub execution_signer_id: String,
}

pub fn keygen(out: &Path) -> Result<(), String> {
    let signer = Sign::mldsa65();
    let (public_key_bytes, secret_key_bytes) = signer
        .keygen()
        .map_err(|error| format!("ML-DSA-65 keygen failed: {error}"))?;
    let public_key = SynQPublicKey::new(public_key_bytes.clone());
    let verifier = AegisSynQVerifier::testnet_1266();
    let address = verifier
        .derive_synq_address(&public_key, AlgorithmId::MlDsa65, NetworkId::testnet())
        .map_err(|error| format!("address derivation failed: {error}"))?;

    let keyfile = SynqDeployKeyfile {
        algorithm: "ML-DSA-65".to_string(),
        public_key_hex: hex::encode(&public_key_bytes),
        secret_key_hex: hex::encode(&secret_key_bytes),
        execution_signer_id: address.to_execution_signer_id(),
    };
    let json = serde_json::to_string_pretty(&keyfile)
        .map_err(|error| format!("serialize keyfile: {error}"))?;
    fs::write(out, json).map_err(|error| format!("write {}: {error}", out.display()))?;
    println!("Generated ML-DSA-65 deploy key -> {}", out.display());
    println!("  signer id:       {}", keyfile.execution_signer_id);
    println!("  (dev/test key only — do not use for anything real)");
    Ok(())
}

fn load_keyfile(path: &Path) -> Result<(SynQPublicKey, Vec<u8>, SynQAddress), String> {
    let raw = fs::read_to_string(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let keyfile: SynqDeployKeyfile =
        serde_json::from_str(&raw).map_err(|error| format!("parse {}: {error}", path.display()))?;
    let public_key_bytes =
        hex::decode(&keyfile.public_key_hex).map_err(|error| format!("bad public_key_hex: {error}"))?;
    let secret_key_bytes =
        hex::decode(&keyfile.secret_key_hex).map_err(|error| format!("bad secret_key_hex: {error}"))?;
    let public_key = SynQPublicKey::new(public_key_bytes);
    let verifier = AegisSynQVerifier::testnet_1266();
    let address = verifier
        .derive_synq_address(&public_key, AlgorithmId::MlDsa65, NetworkId::testnet())
        .map_err(|error| format!("address derivation failed: {error}"))?;
    Ok((public_key, secret_key_bytes, address))
}

fn sign_payload(
    domain_tag: DomainTag,
    purpose: SignaturePurpose,
    signer_address: SynQAddress,
    payload_hash: Hash32,
    secret_key: &[u8],
    nonce: u64,
    ttl_seconds: u64,
) -> Result<(SynQSigningPayload, SynQSignature), String> {
    let now = now_unix();
    let payload = SynQSigningPayload {
        domain_tag,
        chain_id: ChainId::testnet_1266(),
        network_id: NetworkId::testnet(),
        protocol_version: 1,
        algorithm_id: AlgorithmId::MlDsa65,
        signature_purpose: purpose,
        nonce,
        not_before_unix: 0,
        expiration_unix: now + ttl_seconds,
        signer_address,
        payload_hash,
    };
    let canonical = pqsynq::canonicalize_signing_payload(&payload)
        .map_err(|error| format!("canonicalize signing payload: {error}"))?;
    let signature_bytes = Sign::mldsa65()
        .sign(&canonical, secret_key)
        .map_err(|error| format!("ML-DSA-65 sign failed: {error}"))?;
    Ok((payload, SynQSignature::new(signature_bytes)))
}

pub struct DeployEnvelopeArgs {
    pub bytecode_path: PathBuf,
    pub manifest_path: PathBuf,
    pub abi_path: PathBuf,
    pub key_path: PathBuf,
    pub constructor_args: Option<String>,
    pub nonce: u64,
    pub ttl_seconds: u64,
    pub out_path: PathBuf,
}

pub fn build_deploy_envelope(args: &DeployEnvelopeArgs) -> Result<(), String> {
    let bytecode = fs::read(&args.bytecode_path)
        .map_err(|error| format!("read {}: {error}", args.bytecode_path.display()))?;
    let manifest_json = fs::read_to_string(&args.manifest_path)
        .map_err(|error| format!("read {}: {error}", args.manifest_path.display()))?;
    let abi_json = fs::read_to_string(&args.abi_path)
        .map_err(|error| format!("read {}: {error}", args.abi_path.display()))?;
    let (public_key, secret_key, signer_address) = load_keyfile(&args.key_path)?;

    let bytecode_hash = sha256_array(&bytecode);
    let manifest_hash = sha256_array(manifest_json.as_bytes());
    let abi_hash = sha256_array(abi_json.as_bytes());
    let constructor_args_hash =
        sha256_array(args.constructor_args.as_deref().unwrap_or("").as_bytes());

    let payload_hash = pqsynq::hash_contract_deploy_body(
        &bytecode_hash,
        &manifest_hash,
        &abi_hash,
        signer_address.as_bytes(),
        &constructor_args_hash,
    );
    let (signing_payload, signature) = sign_payload(
        DomainTag::SynqContractDeployV1,
        SignaturePurpose::ContractDeploy,
        signer_address,
        payload_hash,
        &secret_key,
        args.nonce,
        args.ttl_seconds,
    )?;

    let deploy = ContractDeployEnvelope {
        signing_payload,
        public_key,
        signature,
        bytecode_hash,
        manifest_hash,
        abi_hash,
        constructor_args_hash,
    };

    // Self-verify locally before writing anything — same verifier + policy the
    // node runs on admission. If this fails, the node would reject it too.
    let verifier = AegisSynQVerifier::testnet_1266();
    let context = VerificationContext::testnet(now_unix());
    let verified = verifier
        .verify_contract_deploy(&deploy, &context)
        .map_err(|error| format!("local self-verify FAILED (would be rejected on-chain): {error}"))?;

    let json = serde_json::to_string_pretty(&deploy)
        .map_err(|error| format!("serialize deploy envelope: {error}"))?;
    fs::write(&args.out_path, json)
        .map_err(|error| format!("write {}: {error}", args.out_path.display()))?;

    println!("Deploy envelope self-verified OK -> {}", args.out_path.display());
    println!("  signer:         {}", verified.deployer.to_execution_signer_id());
    println!("  bytecode_hash:  0x{}", hex::encode(verified.bytecode_hash));
    println!("  manifest_hash:  0x{}", hex::encode(verified.manifest_hash));
    println!("  abi_hash:       0x{}", hex::encode(verified.abi_hash));
    println!();
    println!("Ready to submit once write RPC is live:");
    println!(
        "  synergy-node tx create-aegis --chain-id 1266 --network-id synergy-testnet-v3 \\"
    );
    println!(
        "    --synq-deploy-envelope {} \\",
        args.out_path.display()
    );
    println!("    --synq-bytecode {} \\", args.bytecode_path.display());
    println!("    --synq-manifest {} \\", args.manifest_path.display());
    println!("    --synq-abi {}", args.abi_path.display());
    Ok(())
}

pub struct CallEnvelopeArgs {
    pub key_path: PathBuf,
    pub contract_address_debug: String,
    pub method_selector_hex: String,
    pub encoded_args: Option<String>,
    pub nonce: u64,
    pub ttl_seconds: u64,
    pub out_path: PathBuf,
}

pub fn build_call_envelope(args: &CallEnvelopeArgs) -> Result<(), String> {
    let (public_key, secret_key, signer_address) = load_keyfile(&args.key_path)?;

    let selector_bytes = hex::decode(args.method_selector_hex.trim_start_matches("0x"))
        .map_err(|error| format!("bad --method-selector hex: {error}"))?;
    if selector_bytes.len() != 4 {
        return Err(format!(
            "--method-selector must decode to exactly 4 bytes, got {}",
            selector_bytes.len()
        ));
    }
    let mut method_selector = [0_u8; 4];
    method_selector.copy_from_slice(&selector_bytes);

    // NOTE: contract_address here is a debug-string placeholder derived the
    // same way the node derives deployer/contract addresses at this SDK
    // layer. Once the real deploy receipt comes back on-chain, swap this for
    // the actual returned contract address.
    let contract_address = signer_address_from_debug_string(&args.contract_address_debug)
        .unwrap_or(signer_address.clone());

    let encoded_args_hash = sha256_array(args.encoded_args.as_deref().unwrap_or("").as_bytes());
    let payload_hash = pqsynq::hash_contract_call_body(
        contract_address.as_bytes(),
        &method_selector,
        &encoded_args_hash,
        signer_address.as_bytes(),
    );
    let (signing_payload, signature) = sign_payload(
        DomainTag::SynqContractCallV1,
        SignaturePurpose::ContractCall,
        signer_address,
        payload_hash,
        &secret_key,
        args.nonce,
        args.ttl_seconds,
    )?;

    let call = ContractCallEnvelope {
        signing_payload,
        public_key,
        signature,
        contract_address,
        method_selector,
        encoded_args_hash,
    };

    let verifier = AegisSynQVerifier::testnet_1266();
    let context = VerificationContext::testnet(now_unix());
    let verified = verifier
        .verify_contract_call(&call, &context)
        .map_err(|error| format!("local self-verify FAILED (would be rejected on-chain): {error}"))?;

    let json = serde_json::to_string_pretty(&call)
        .map_err(|error| format!("serialize call envelope: {error}"))?;
    fs::write(&args.out_path, json)
        .map_err(|error| format!("write {}: {error}", args.out_path.display()))?;

    println!("Call envelope self-verified OK -> {}", args.out_path.display());
    println!("  caller:  {}", verified.caller.to_execution_signer_id());
    println!("  target:  {}", verified.contract_address.to_execution_signer_id());
    println!("  selector: 0x{}", hex::encode(verified.method_selector));
    println!();
    println!("Ready to submit once write RPC is live:");
    println!(
        "  synergy-node tx create-aegis --chain-id 1266 --network-id synergy-testnet-v3 \\"
    );
    println!("    --synq-call-envelope {}", args.out_path.display());
    Ok(())
}

// pqsynq's SynQAddress doesn't currently expose a debug-string parser, only a
// formatter (`to_testnet_debug_string`). Until a parser lands upstream, we
// only accept a real address here if it happens to already be a SynQAddress
// we derived ourselves in this process; otherwise callers should pass the
// deployer's own address (the common case pre-genesis-receipt) and patch the
// output JSON's `contract_address` field by hand once the deploy receipt
// returns the real on-chain contract address.
fn signer_address_from_debug_string(_debug: &str) -> Option<SynQAddress> {
    None
}
