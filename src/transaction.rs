use crate::crypto::pqc::{PQCAlgorithm, PQCManager, PQCPrivateKey, PQCPublicKey};
use crate::synergy_types::{SYNERGY_TESTNET_V2_CHAIN_ID, SYNERGY_TESTNET_V2_NETWORK_ID};
use bincode::config::standard;
use bincode::{decode_from_slice, encode_to_vec};
use bincode::{Decode, Encode};
use blake3::Hasher;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Transaction {
    #[serde(default)]
    pub chain_id: u64,
    #[serde(default)]
    pub network_id: String,
    pub sender: String,
    pub receiver: String,
    pub amount: u64,
    pub nonce: u64,
    pub signature: Vec<u8>, // Changed from String to Vec<u8> for binary signature data
    #[serde(default)]
    pub signer_public_key: Vec<u8>,
    pub timestamp: u64,
    pub gas_price: u64,
    pub gas_limit: u64,
    pub data: Option<String>,
    pub signature_algorithm: String, // Track which PQC algorithm was used
}

#[derive(Debug, Clone)]
pub struct TransactionValidationResult {
    pub is_valid: bool,
    pub error_message: Option<String>,
}

impl Transaction {
    pub fn new(
        sender: String,
        receiver: String,
        amount: u64,
        nonce: u64,
        signature: Vec<u8>,
        gas_price: u64,
        gas_limit: u64,
        data: Option<String>,
        signature_algorithm: String,
    ) -> Self {
        Transaction {
            chain_id: SYNERGY_TESTNET_V2_CHAIN_ID,
            network_id: SYNERGY_TESTNET_V2_NETWORK_ID.to_string(),
            sender,
            receiver,
            amount,
            nonce,
            signature,
            signer_public_key: Vec::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            gas_price,
            gas_limit,
            data,
            signature_algorithm,
        }
    }

    /// Returns the raw hash (hex string) for internal use (signing, verification)
    pub fn raw_hash(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(&self.chain_id.to_be_bytes());
        hasher.update(&(self.network_id.len() as u64).to_be_bytes());
        hasher.update(self.network_id.as_bytes());
        hasher.update(self.sender.as_bytes());
        hasher.update(self.receiver.as_bytes());
        hasher.update(&self.amount.to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.gas_price.to_le_bytes());
        hasher.update(&self.gas_limit.to_le_bytes());

        if let Some(ref data) = self.data {
            hasher.update(data.as_bytes());
        }

        hex::encode(hasher.finalize().as_bytes())
    }

    /// Returns Synergy-formatted transaction hash with appropriate prefix
    /// Regular transactions: syntxn-<hash>
    /// Cross-chain transactions: synxxn-<hash>
    pub fn hash(&self) -> String {
        let raw_hash = self.raw_hash();

        // Check if this is a cross-chain transaction
        let is_cross_chain = self
            .data
            .as_ref()
            .map(|d| d.starts_with("bridge_transfer:") || d.starts_with("cross_chain:"))
            .unwrap_or(false);

        if is_cross_chain {
            format!("synxxn-{}", raw_hash)
        } else {
            format!("syntxn-{}", raw_hash)
        }
    }

    pub fn sign(
        &mut self,
        private_key: &PQCPrivateKey,
        pqc_manager: &mut PQCManager,
    ) -> Result<(), String> {
        // Get the raw transaction hash (without prefix) for signing
        let message = self.raw_hash();
        let message_bytes =
            hex::decode(&message).map_err(|e| format!("Failed to decode hash: {}", e))?;

        // Sign using the appropriate PQC algorithm
        let signature = match private_key.algorithm {
            PQCAlgorithm::MLDSA => pqc_manager.sign(private_key, &message_bytes)?,
            PQCAlgorithm::FNDSA => pqc_manager.sign(private_key, &message_bytes)?,
            PQCAlgorithm::SLHDSA => pqc_manager.sign(private_key, &message_bytes)?,
            _ => return Err("Unsupported signature algorithm".to_string()),
        };

        self.signature = signature.signature_data;
        self.signature_algorithm = algorithm_name(&private_key.algorithm).to_string();

        Ok(())
    }

    pub fn sign_with_public_key(
        &mut self,
        public_key: &PQCPublicKey,
        private_key: &PQCPrivateKey,
        pqc_manager: &mut PQCManager,
    ) -> Result<(), String> {
        self.sign(private_key, pqc_manager)?;
        self.signer_public_key = public_key.key_data.clone();
        Ok(())
    }

    pub fn verify_signature(&self, public_key: &PQCPublicKey, pqc_manager: &PQCManager) -> bool {
        // Get the raw transaction hash (without prefix) that was signed
        let message = self.raw_hash();
        let message_bytes = hex::decode(&message).unwrap_or_else(|_| Vec::new());

        if message_bytes.is_empty() {
            return false;
        }

        // Create a signature object for verification
        let signature = crate::crypto::pqc::PQCSignature {
            algorithm: public_key.algorithm.clone(),
            signature_data: self.signature.clone(),
            message_hash: message_bytes.clone(),
            public_key_id: public_key.key_id.clone(),
            created_at: self.timestamp,
        };

        // Verify using the appropriate PQC algorithm
        match pqc_manager.verify(public_key, &signature, &message_bytes) {
            Ok(is_valid) => is_valid,
            Err(_) => false,
        }
    }

    pub fn verify_embedded_signature(&self) -> Result<(), String> {
        if self.signer_public_key.is_empty() {
            return Err("Transaction signer public key is missing".to_string());
        }
        if self.signature.is_empty() {
            return Err("Transaction signature is missing".to_string());
        }
        if !crate::address::address_matches_public_key(&self.sender, &self.signer_public_key) {
            return Err("Transaction signer public key does not derive sender address".to_string());
        }
        let algorithm = parse_algorithm_name(&self.signature_algorithm)?;
        let public_key = PQCPublicKey {
            algorithm,
            key_data: self.signer_public_key.clone(),
            key_id: self.sender.clone(),
            created_at: self.timestamp,
        };
        let manager = PQCManager::new();
        if self.verify_signature(&public_key, &manager) {
            Ok(())
        } else {
            Err("Aegis PQC transaction signature verification failed".to_string())
        }
    }

    pub fn validate_for_admission(&self) -> TransactionValidationResult {
        let basic = self.validate();
        if !basic.is_valid {
            return basic;
        }
        if self.chain_id != SYNERGY_TESTNET_V2_CHAIN_ID {
            return TransactionValidationResult {
                is_valid: false,
                error_message: Some(format!(
                    "Transaction chain_id {} does not match Synergy Testnet chain {}",
                    self.chain_id, SYNERGY_TESTNET_V2_CHAIN_ID
                )),
            };
        }
        if self.network_id != SYNERGY_TESTNET_V2_NETWORK_ID {
            return TransactionValidationResult {
                is_valid: false,
                error_message: Some(format!(
                    "Transaction network_id {} does not match {}",
                    self.network_id, SYNERGY_TESTNET_V2_NETWORK_ID
                )),
            };
        }
        let verification = if crate::aegis_tx_tool::is_legacy_aegis_carrier_transaction(self) {
            crate::aegis_tx_tool::validate_legacy_aegis_carrier_transaction(self)
        } else {
            self.verify_embedded_signature()
        };

        match verification {
            Ok(()) => TransactionValidationResult {
                is_valid: true,
                error_message: None,
            },
            Err(error) => TransactionValidationResult {
                is_valid: false,
                error_message: Some(error),
            },
        }
    }

    pub fn validate(&self) -> TransactionValidationResult {
        // Basic validation checks
        if self.sender.is_empty() {
            return TransactionValidationResult {
                is_valid: false,
                error_message: Some("Sender address cannot be empty".to_string()),
            };
        }

        if self.receiver.is_empty() {
            return TransactionValidationResult {
                is_valid: false,
                error_message: Some("Receiver address cannot be empty".to_string()),
            };
        }

        if self.amount == 0 {
            return TransactionValidationResult {
                is_valid: false,
                error_message: Some("Transaction amount must be greater than 0".to_string()),
            };
        }

        if self.gas_price == 0 {
            return TransactionValidationResult {
                is_valid: false,
                error_message: Some("Gas price must be greater than 0".to_string()),
            };
        }

        if self.gas_limit == 0 {
            return TransactionValidationResult {
                is_valid: false,
                error_message: Some("Gas limit must be greater than 0".to_string()),
            };
        }

        if self.signature.is_empty() {
            return TransactionValidationResult {
                is_valid: false,
                error_message: Some("Transaction must be signed".to_string()),
            };
        }

        // Check if signature algorithm is supported
        match self.signature_algorithm.as_str() {
            "mldsa" | "fndsa" | "slhdsa" => {}
            _ => {
                return TransactionValidationResult {
                    is_valid: false,
                    error_message: Some(format!(
                        "Unsupported signature algorithm: {}",
                        self.signature_algorithm
                    )),
                };
            }
        }

        // Check timestamp is not too old (within 1 hour)
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if current_time.saturating_sub(self.timestamp) > 3600 {
            return TransactionValidationResult {
                is_valid: false,
                error_message: Some("Transaction timestamp is too old".to_string()),
            };
        }

        TransactionValidationResult {
            is_valid: true,
            error_message: None,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        encode_to_vec(self, standard())
            .map_err(|e| format!("Failed to serialize transaction: {}", e))
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        decode_from_slice(data, standard())
            .map(|(transaction, _)| transaction)
            .map_err(|e| format!("Failed to deserialize transaction: {}", e))
    }

    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|e| format!("Failed to serialize to JSON: {}", e))
    }

    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("Failed to deserialize from JSON: {}", e))
    }

    /// Actual fee charged for inclusion, using deterministic activity gas.
    /// This is intentionally not `gas_limit * gas_price`; unused gas is refundable.
    pub fn get_fee(&self) -> u64 {
        u64::try_from(self.calculate_gas_fee()).unwrap_or(u64::MAX)
    }

    pub fn get_total_value(&self) -> u64 {
        self.amount.saturating_add(self.get_fee())
    }

    pub fn is_contract_call(&self) -> bool {
        self.data.is_some()
    }

    pub fn get_contract_data(&self) -> Option<&String> {
        self.data.as_ref()
    }

    pub fn get_signature_hex(&self) -> String {
        hex::encode(&self.signature)
    }

    pub fn get_signature_algorithm(&self) -> &str {
        &self.signature_algorithm
    }

    pub fn get_sender(&self) -> &str {
        &self.sender
    }

    pub fn get_receiver(&self) -> &str {
        &self.receiver
    }

    pub fn get_amount(&self) -> u64 {
        self.amount
    }

    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }

    pub fn get_timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn get_gas_price(&self) -> u64 {
        self.gas_price
    }

    pub fn get_gas_limit(&self) -> u64 {
        self.gas_limit
    }

    pub fn minimum_required_gas(&self) -> u64 {
        self.estimate_gas()
    }

    /// Calculate actual gas fee using the gas module. Returns fee in nWei.
    pub fn calculate_gas_fee(&self) -> u128 {
        crate::gas::calculate_total_fee_nwei(self.minimum_required_gas(), self.gas_price)
            .unwrap_or(u128::MAX)
    }

    /// Calculate the maximum fee reserve required before execution.
    pub fn calculate_max_fee_reserve_nwei(&self) -> u128 {
        crate::gas::calculate_total_fee_nwei(self.gas_limit, self.gas_price).unwrap_or(u128::MAX)
    }

    /// Get gas fee as NWei type
    pub fn get_gas_fee_nwei(&self) -> crate::gas::NWei {
        crate::gas::NWei::from_nwei(self.calculate_gas_fee())
    }

    /// Get gas fee in SNRG (for display)
    pub fn get_gas_fee_snrg(&self) -> String {
        self.get_gas_fee_nwei().format_snrg()
    }

    /// Get total cost (amount + gas fee) in nWei
    pub fn get_total_cost_nwei(&self) -> u128 {
        (self.amount as u128) + self.calculate_gas_fee()
    }

    /// Check if sender has sufficient balance for transaction
    /// balance should be in nWei
    pub fn has_sufficient_balance(&self, sender_balance: u128) -> bool {
        sender_balance
            >= (self.amount as u128).saturating_add(self.calculate_max_fee_reserve_nwei())
    }

    /// Set gas price (in nWei per gas unit)
    pub fn set_gas_price(&mut self, gas_price: u64) -> Result<(), String> {
        use crate::gas::GasPrice;
        // Validate gas price
        GasPrice::from_nwei(gas_price)?;
        self.gas_price = gas_price;
        Ok(())
    }

    /// Set gas limit
    pub fn set_gas_limit(&mut self, gas_limit: u64) -> Result<(), String> {
        use crate::gas::GasLimit;
        // Validate gas limit
        GasLimit::new(gas_limit)?;
        self.gas_limit = gas_limit;
        Ok(())
    }

    /// Estimate gas for this transaction based on its type
    pub fn estimate_gas(&self) -> u64 {
        use crate::gas::{calculate_activity_gas, GasComputationInput, GasSchedule};

        let schedule = GasSchedule::default();
        let payload_size = self
            .data
            .as_ref()
            .map(|data| data.len() as u64)
            .unwrap_or(0);
        let mut input = GasComputationInput::new(self.gas_activity_type());
        input.payload_size_bytes = payload_size;

        if let Some(ref data) = self.data {
            if data.starts_with("deploy:") {
                input.contract_bytecode_size = data.len() as u64;
            } else if data.starts_with("validator_activation:")
                || data.starts_with("validator_registration:")
            {
                input.validator_metadata_size_bytes = data.len() as u64;
            } else if data.starts_with("governance_proposal:") {
                input.proposal_size_bytes = data.len() as u64;
            } else if data.starts_with("pqc_key_registration:")
                || data.starts_with("pqc_key_rotation:")
            {
                input.key_material_size_bytes = data.len() as u64;
            } else if data.starts_with("sxcp_proof:") {
                input.proof_size_bytes = data.len() as u64;
            }
        }

        calculate_activity_gas(&schedule, &input)
            .map(|breakdown| breakdown.total_gas)
            .unwrap_or(schedule.base_tx_gas)
    }

    pub fn gas_activity_type(&self) -> crate::gas::GasActivityType {
        use crate::gas::GasActivityType;

        match self.data.as_deref() {
            None => GasActivityType::NativeSnrgTransfer,
            Some(data) if data.starts_with("token_transfer:") => {
                GasActivityType::ScetpSameChainTransfer
            }
            Some(data)
                if data.starts_with("validator_activation:")
                    || data.starts_with("validator_registration:") =>
            {
                GasActivityType::ValidatorRegistration
            }
            Some(data) if data.starts_with("validator_heartbeat:") => {
                GasActivityType::ValidatorHeartbeat
            }
            Some(data) if data.starts_with("stake:") => GasActivityType::StakingBond,
            Some(data)
                if data.starts_with("unstake:") || data.starts_with("withdrawal_request:") =>
            {
                GasActivityType::UnstakeRequest
            }
            Some(data) if data.starts_with("governance_proposal:") => {
                GasActivityType::GovernanceProposal
            }
            Some(data) if data.starts_with("governance_vote:") => GasActivityType::GovernanceVote,
            Some(data) if data.starts_with("deploy:") => GasActivityType::SynqContractDeployment,
            Some(data) if data.starts_with("pqc_key_registration:") => {
                GasActivityType::AegisPqcKeyRegistration
            }
            Some(data) if data.starts_with("pqc_key_rotation:") => {
                GasActivityType::AegisPqcKeyRotation
            }
            Some(data) if data.starts_with("sxcp_intent:") => GasActivityType::SxcpIntentCreation,
            Some(data) if data.starts_with("sxcp_proof:") => GasActivityType::SxcpProofVerification,
            Some(data) if data.starts_with("sxcp_attestation:") => {
                GasActivityType::SxcpRelayerAttestation
            }
            Some(data) if data.starts_with("uma_create:") => GasActivityType::UmaRecordCreation,
            Some(data) if data.starts_with("uma_update:") => GasActivityType::UmaRecordUpdate,
            Some(data) if data.starts_with("sns_register:") => GasActivityType::SnsNameRegistration,
            Some(data) if data.starts_with("sns_update:") => GasActivityType::SnsNameUpdate,
            Some(_) => GasActivityType::SynqContractCall,
        }
    }
}

// Helper function to get algorithm name
fn algorithm_name(algorithm: &PQCAlgorithm) -> &'static str {
    match algorithm {
        PQCAlgorithm::MLKEM1024 => "mlkem1024",
        PQCAlgorithm::MLDSA => "mldsa",
        PQCAlgorithm::FNDSA => "fndsa",
        PQCAlgorithm::SLHDSA => "slhdsa",
        PQCAlgorithm::HQCKEM => "hqckem",
    }
}

// Helper function to parse algorithm name
pub fn parse_algorithm_name(name: &str) -> Result<PQCAlgorithm, String> {
    match name.to_lowercase().as_str() {
        "mlkem" | "mlkem1024" => Ok(PQCAlgorithm::MLKEM1024),
        "mldsa" => Ok(PQCAlgorithm::MLDSA),
        "fndsa" => Ok(PQCAlgorithm::FNDSA),
        "slhdsa" => Ok(PQCAlgorithm::SLHDSA),
        "hqckem" => Ok(PQCAlgorithm::HQCKEM),
        _ => Err(format!("Unknown algorithm: {}", name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_creation() {
        let tx = Transaction::new(
            "sender123".to_string(),
            "receiver456".to_string(),
            1000,
            1,
            vec![0x01, 0x02, 0x03],
            100,
            21000,
            None,
            "mldsa".to_string(),
        );

        assert_eq!(tx.sender, "sender123");
        assert_eq!(tx.receiver, "receiver456");
        assert_eq!(tx.amount, 1000);
        assert_eq!(tx.nonce, 1);
        assert_eq!(tx.signature, vec![0x01, 0x02, 0x03]);
        assert_eq!(tx.gas_price, 100);
        assert_eq!(tx.gas_limit, 21000);
        assert_eq!(tx.signature_algorithm, "mldsa");
    }

    #[test]
    fn test_transaction_hash() {
        let tx1 = Transaction::new(
            "sender123".to_string(),
            "receiver456".to_string(),
            1000,
            1,
            vec![0x01, 0x02, 0x03],
            100,
            21000,
            None,
            "mldsa".to_string(),
        );

        let tx2 = Transaction::new(
            "sender123".to_string(),
            "receiver456".to_string(),
            1000,
            1,
            vec![0x01, 0x02, 0x03],
            100,
            21000,
            None,
            "mldsa".to_string(),
        );

        // Same transaction should have same hash
        assert_eq!(tx1.hash(), tx2.hash());

        let tx3 = Transaction::new(
            "sender123".to_string(),
            "receiver456".to_string(),
            2000, // Different amount
            1,
            vec![0x01, 0x02, 0x03],
            100,
            21000,
            None,
            "mldsa".to_string(),
        );

        // Different transaction should have different hash
        assert_ne!(tx1.hash(), tx3.hash());
    }

    #[test]
    fn test_transaction_validation() {
        let valid_tx = Transaction::new(
            "sender123".to_string(),
            "receiver456".to_string(),
            1000,
            1,
            vec![0x01, 0x02, 0x03],
            100,
            21000,
            None,
            "mldsa".to_string(),
        );

        let result = valid_tx.validate();
        assert!(result.is_valid);
        assert!(result.error_message.is_none());

        let invalid_tx = Transaction::new(
            "".to_string(), // Empty sender
            "receiver456".to_string(),
            1000,
            1,
            vec![0x01, 0x02, 0x03],
            100,
            21000,
            None,
            "mldsa".to_string(),
        );

        let result = invalid_tx.validate();
        assert!(!result.is_valid);
        assert!(result.error_message.is_some());
    }

    #[test]
    fn admission_requires_testnet_context_and_real_pqc_signature() {
        let mut manager = PQCManager::new();
        let (public_key, private_key) = manager
            .generate_keypair(PQCAlgorithm::FNDSA)
            .expect("test keypair should generate");
        let sender = crate::address::generate_wallet_address(&hex::encode(&public_key.key_data));
        let mut tx = Transaction::new(
            sender,
            "receiver456".to_string(),
            1000,
            1,
            Vec::new(),
            100,
            21000,
            None,
            "fndsa".to_string(),
        );
        tx.sign_with_public_key(&public_key, &private_key, &mut manager)
            .expect("test transaction should sign");

        assert!(tx.validate_for_admission().is_valid);

        let mut wrong_chain = tx.clone();
        wrong_chain.chain_id = 999;
        assert!(!wrong_chain.validate_for_admission().is_valid);

        let mut wrong_network = tx.clone();
        wrong_network.network_id = "synergy-testnet".to_string();
        assert!(!wrong_network.validate_for_admission().is_valid);

        let mut tampered = tx.clone();
        tampered.amount = tampered.amount.saturating_add(1);
        assert!(!tampered.validate_for_admission().is_valid);

        let mut missing_key = tx;
        missing_key.signer_public_key.clear();
        assert!(!missing_key.validate_for_admission().is_valid);

        let mut wrong_sender = missing_key;
        wrong_sender.signer_public_key = public_key.key_data;
        wrong_sender.sender = crate::address::generate_wallet_address(&hex::encode([9u8; 32]));
        assert!(!wrong_sender.validate_for_admission().is_valid);
    }

    #[test]
    fn aegis_carrier_transaction_validates_for_p2p_admission() {
        let report = crate::aegis_tx_tool::sign_with_new_aegis_transaction_key(
            crate::aegis_tx_tool::AegisTxBuildOptions::default(),
        )
        .unwrap();

        let validation = report.rpc_transaction.validate_for_admission();

        assert!(
            validation.is_valid,
            "Aegis carrier admission failed: {:?}",
            validation.error_message
        );
        assert!(crate::aegis_tx_tool::is_legacy_aegis_carrier_transaction(
            &report.rpc_transaction
        ));
    }

    #[test]
    fn test_transaction_serialization() {
        let tx = Transaction::new(
            "sender123".to_string(),
            "receiver456".to_string(),
            1000,
            1,
            vec![0x01, 0x02, 0x03],
            100,
            21000,
            None,
            "mldsa".to_string(),
        );

        let serialized = tx.serialize().unwrap();
        let deserialized = Transaction::deserialize(&serialized).unwrap();

        assert_eq!(tx.sender, deserialized.sender);
        assert_eq!(tx.receiver, deserialized.receiver);
        assert_eq!(tx.amount, deserialized.amount);
        assert_eq!(tx.nonce, deserialized.nonce);
        assert_eq!(tx.signature, deserialized.signature);
        assert_eq!(tx.signature_algorithm, deserialized.signature_algorithm);
    }

    #[test]
    fn test_transaction_json() {
        let tx = Transaction::new(
            "sender123".to_string(),
            "receiver456".to_string(),
            1000,
            1,
            vec![0x01, 0x02, 0x03],
            100,
            21000,
            None,
            "mldsa".to_string(),
        );

        let json = tx.to_json().unwrap();
        let deserialized = Transaction::from_json(&json).unwrap();

        assert_eq!(tx.sender, deserialized.sender);
        assert_eq!(tx.receiver, deserialized.receiver);
        assert_eq!(tx.amount, deserialized.amount);
        assert_eq!(tx.nonce, deserialized.nonce);
        assert_eq!(tx.signature, deserialized.signature);
        assert_eq!(tx.signature_algorithm, deserialized.signature_algorithm);
    }

    #[test]
    fn test_transaction_fee_calculation() {
        let tx = Transaction::new(
            "sender123".to_string(),
            "receiver456".to_string(),
            1000,
            1,
            vec![0x01, 0x02, 0x03],
            100,
            21000,
            None,
            "mldsa".to_string(),
        );

        assert_eq!(tx.get_fee(), 100 * 38500);
        assert_eq!(tx.get_total_value(), 1000 + (100 * 38500));
    }

    #[test]
    fn test_algorithm_parsing() {
        assert_eq!(parse_algorithm_name("mldsa").unwrap(), PQCAlgorithm::MLDSA);
        assert_eq!(parse_algorithm_name("fndsa").unwrap(), PQCAlgorithm::FNDSA);
        assert_eq!(
            parse_algorithm_name("slhdsa").unwrap(),
            PQCAlgorithm::SLHDSA
        );
        assert_eq!(
            parse_algorithm_name("mlkem").unwrap(),
            PQCAlgorithm::MLKEM1024
        );
        assert_eq!(
            parse_algorithm_name("mlkem1024").unwrap(),
            PQCAlgorithm::MLKEM1024
        );
        assert_eq!(
            parse_algorithm_name("hqckem").unwrap(),
            PQCAlgorithm::HQCKEM
        );

        assert!(parse_algorithm_name("unknown").is_err());
    }
}
