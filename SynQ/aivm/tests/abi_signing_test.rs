//! AIVM ABI and signing tests

use aivm::abi::{Abi, AbiType, AbiMethod, AbiEvent, AbiError, AbiStateField};
use aivm::signing::{SigningPayload, domain, algorithm};
use aivm::manifest::{Manifest, validate_manifest, ManifestValidation};
use aivm::receipt::{Receipt, ReceiptStatus, EventRecord};
use aivm::context::ExecutionContext;

#[test]
fn test_method_selector_computation() {
    // SHA-256("increment()") → first 4 bytes
    let selector = Abi::compute_selector("increment", &[]);
    let hex = Abi::selector_hex(selector);
    assert!(hex.starts_with("0x"));
    assert_eq!(hex.len(), 10); // 0x + 8 hex chars

    // Selector with params: SHA-256("transfer(u64,address)")
    let selector2 = Abi::compute_selector("transfer", &[AbiType::U64, AbiType::Address]);
    assert_ne!(selector, selector2);
}

#[test]
fn test_canonical_json_sorted_keys() {
    let abi = Abi {
        abi_version: "0.1".to_string(),
        contract: "Test".to_string(),
        methods: vec![],
        events: vec![],
        errors: vec![],
        state_schema: vec![],
        security_requirements: serde_json::json!({}),
    };
    let json = abi.canonical_json();
    let json_str = String::from_utf8(json).unwrap();

    // Keys should be sorted
    let abi_idx = json_str.find("\"abi_version\"").unwrap();
    let contract_idx = json_str.find("\"contract\"").unwrap();
    assert!(abi_idx < contract_idx);

    // No whitespace between key-value pairs
    assert!(!json_str.contains(": "));
}

#[test]
fn test_signing_payload_roundtrip() {
    let payload = SigningPayload {
        domain_id: domain::CONTRACT_CALL,
        chain_id: 1266,
        network_id: "synergy-testnet-v3".to_string(),
        protocol_version: 1,
        algorithm_id: algorithm::ML_DSA_65,
        signature_purpose: 0,
        nonce: 12345,
        not_before: 1000,
        expiration: 3600,
        signer_address: vec![0xAA; 41],
        payload_hash: [0xBB; 32],
    };

    let encoded = payload.encode();
    let decoded = SigningPayload::decode(&encoded).unwrap();

    assert_eq!(decoded.domain_id, domain::CONTRACT_CALL);
    assert_eq!(decoded.chain_id, 1266);
    assert_eq!(decoded.network_id, "synergy-testnet-v3");
    assert_eq!(decoded.algorithm_id, algorithm::ML_DSA_65);
    assert_eq!(decoded.nonce, 12345);
    assert_eq!(decoded.not_before, 1000);
    assert_eq!(decoded.expiration, 3600);
    assert_eq!(decoded.signer_address, vec![0xAA; 41]);
    assert_eq!(decoded.payload_hash, [0xBB; 32]);
}

#[test]
fn test_deploy_body_hash() {
    let bytecode_hash = [1u8; 32];
    let manifest_hash = [2u8; 32];
    let abi_hash = [3u8; 32];
    let deployer = vec![0xFF; 41];
    let constructor_args_hash = [4u8; 32];

    let hash1 = SigningPayload::deploy_body_hash(
        &bytecode_hash, &manifest_hash, &abi_hash,
        &deployer, &constructor_args_hash,
    );
    // Same inputs → same hash (deterministic)
    let hash2 = SigningPayload::deploy_body_hash(
        &bytecode_hash, &manifest_hash, &abi_hash,
        &deployer, &constructor_args_hash,
    );
    assert_eq!(hash1, hash2);

    // Different inputs → different hash
    let different_deployer = vec![0x00; 41];
    let hash3 = SigningPayload::deploy_body_hash(
        &bytecode_hash, &manifest_hash, &abi_hash,
        &different_deployer, &constructor_args_hash,
    );
    assert_ne!(hash1, hash3);
}

#[test]
fn test_call_body_hash() {
    let contract_addr = vec![0xCC; 41];
    let selector: u32 = 0x12345678;
    let args_hash = [0xDD; 32];
    let caller = vec![0xEE; 41];

    let hash1 = SigningPayload::call_body_hash(
        &contract_addr, selector, &args_hash, &caller,
    );
    let hash2 = SigningPayload::call_body_hash(
        &contract_addr, selector, &args_hash, &caller,
    );
    assert_eq!(hash1, hash2);

    // Different selector → different hash
    let hash3 = SigningPayload::call_body_hash(
        &contract_addr, 0x87654321, &args_hash, &caller,
    );
    assert_ne!(hash1, hash3);
}

#[test]
fn test_manifest_validation() {
    let manifest = Manifest::testnet_default("TestContract", "0.1.0");
    match validate_manifest(&manifest) {
        ManifestValidation::Valid => {}
        ManifestValidation::Invalid(e) => panic!("expected valid, got {:?}", e),
    }
}

#[test]
fn test_manifest_rejects_wrong_chain_id() {
    let mut manifest = Manifest::testnet_default("TestContract", "0.1.0");
    manifest.required_chain_id = 9999;
    match validate_manifest(&manifest) {
        ManifestValidation::Invalid(aivm::AivmError::ManifestChainIdMismatch { expected: 1266, got: 9999 }) => {}
        other => panic!("expected chain ID mismatch, got {:?}", other),
    }
}

#[test]
fn test_manifest_rejects_wrong_algorithm() {
    let mut manifest = Manifest::testnet_default("TestContract", "0.1.0");
    manifest.required_signature_algorithm = "FN-DSA-512".to_string();
    match validate_manifest(&manifest) {
        ManifestValidation::Invalid(aivm::AivmError::ManifestAlgorithmNotAllowed(_)) => {}
        other => panic!("expected algorithm not allowed, got {:?}", other),
    }
}

#[test]
fn test_receipt_hash_deterministic() {
    let ctx = ExecutionContext::testnet([1u8; 41], [2u8; 41]);
    let receipt1 = Receipt::success(
        &ctx, 100, 50, [0u8; 32], [0u8; 32],
        vec![1, 2, 3],
        vec![],
    );
    let receipt2 = Receipt::success(
        &ctx, 100, 50, [0u8; 32], [0u8; 32],
        vec![1, 2, 3],
        vec![],
    );
    assert_eq!(receipt1.hash(), receipt2.hash());
}

#[test]
fn test_receipt_trap_includes_code() {
    let ctx = ExecutionContext::testnet([1u8; 41], [2u8; 41]);
    let receipt = Receipt::trap(&ctx, 200, 100, [0u8; 32], 5);
    assert_eq!(receipt.status, ReceiptStatus::Reverted);
    assert_eq!(receipt.trap_code, Some(5));
    assert_eq!(receipt.state_root_before, receipt.state_root_after); // rolled back
}
