use crate::genesis::canonical_genesis;
use crate::transaction::Transaction;
use crate::warn;
use hex;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub const SNRG_SYMBOL: &str = "SNRG";
pub const FEE_COLLECTOR_ADDRESS: &str = "synf1y42p7p6jrxrg472ts6jea5y34yg7tgj6qg2j";
pub const DAO_TREASURY_ADDRESS: &str = "synw1pqwglyfjynrxt7ms9nvggntav6x3lx9c2l4r";
pub const TREASURY_RECOVERY_WALLET_ADDRESS: &str = "synw1syv3tnu6r2y5e3u9f0wqmxhavylfxena0z92";
pub const VALIDATOR_REWARDS_POOL_ADDRESS: &str = "synw1at607x35rkmsmvgz069nx0j3q5km93krrvge";
pub const RELIABILITY_BONUS_POOL_ADDRESS: &str = "synw1mct6a33g7hyt6jzkjdwrvxzf644lc4vytqcz";
pub const BURN_SINK_ADDRESS: &str = "synb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqjk5cn";
pub const NETWORK_BURN_ADDRESS: &str = crate::address::NETWORK_BURN_ADDRESS;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    pub total_supply: String,
    pub max_supply: Option<String>,
    pub mintable: bool,
    pub burnable: bool,
    pub created_at: u64,
    pub creator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBalance {
    pub address: String,
    pub token_symbol: String,
    pub balance: u64,
    pub locked_balance: u64,
    pub staked_balance: u64,
    pub last_updated: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenTransfer {
    pub from: String,
    pub to: String,
    pub token_symbol: String,
    pub amount: u64,
    pub fee: u64,
    pub timestamp: u64,
    pub tx_hash: String,
    pub block_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BurnRecordKind {
    ExplicitBurn,
    BurnAddressTransfer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnRecord {
    pub burner: String,
    pub asset_id: String,
    pub amount: u64,
    pub burn_address: String,
    pub fee_charged_nwei: u64,
    pub supply_reduced: bool,
    pub tx_hash: String,
    pub block_height: u64,
    pub kind: BurnRecordKind,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingInfo {
    pub validator_address: String,
    pub staker_address: String,
    pub amount: u64,
    pub stake_start: u64,
    pub stake_end: Option<u64>,
    pub rewards_earned: u64,
    pub is_active: bool,
}

#[derive(Debug, Deserialize)]
struct TestnetProfileMint {
    wallet_address: String,
    amount_nwei: String,
}

#[derive(Debug, Deserialize)]
struct TestnetTokenProfile {
    genesis_mints: Vec<TestnetProfileMint>,
}

fn profile_allocations_enabled() -> bool {
    matches!(
        std::env::var("SYNERGY_ENABLE_PROFILE_ALLOCATIONS")
            .ok()
            .as_deref(),
        Some("1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON")
    )
}

#[derive(Debug)]
pub struct TokenManager {
    tokens: Arc<Mutex<HashMap<String, Token>>>,
    pub balances: Arc<Mutex<HashMap<String, HashMap<String, u64>>>>, // address -> token_symbol -> balance
    _locked_balances: Arc<Mutex<HashMap<String, HashMap<String, u64>>>>, // address -> token_symbol -> locked
    staked_balances: Arc<Mutex<HashMap<String, HashMap<String, u64>>>>, // address -> token_symbol -> staked
    transfers: Arc<Mutex<Vec<TokenTransfer>>>,
    stakes: Arc<Mutex<HashMap<String, Vec<StakingInfo>>>>, // validator -> stakes
    total_supply: Arc<Mutex<HashMap<String, u128>>>,       // token_symbol -> total_supply
    burn_ledger: Arc<Mutex<HashMap<String, u128>>>,        // token_symbol -> burned/locked amount
    burn_records: Arc<Mutex<Vec<BurnRecord>>>,
}

impl Token {
    pub fn new(
        symbol: String,
        name: String,
        decimals: u8,
        total_supply: u128,
        max_supply: Option<u128>,
        mintable: bool,
        burnable: bool,
        creator: String,
    ) -> Self {
        Token {
            symbol,
            name,
            decimals,
            total_supply: total_supply.to_string(),
            max_supply: max_supply.map(|value| value.to_string()),
            mintable,
            burnable,
            created_at: Self::current_timestamp(),
            creator,
        }
    }

    pub fn calculate_amount(&self, raw_amount: u64) -> u64 {
        raw_amount * 10u64.pow(self.decimals as u32)
    }

    pub fn format_amount(&self, amount: u64) -> String {
        let divisor = 10u64.pow(self.decimals as u32);
        let whole = amount / divisor;
        let fractional = amount % divisor;
        format!(
            "{whole}.{fractional:0width$}",
            width = self.decimals as usize
        )
    }

    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

impl TokenManager {
    pub fn new() -> Self {
        let mut manager = TokenManager {
            tokens: Arc::new(Mutex::new(HashMap::new())),
            balances: Arc::new(Mutex::new(HashMap::new())),
            _locked_balances: Arc::new(Mutex::new(HashMap::new())),
            staked_balances: Arc::new(Mutex::new(HashMap::new())),
            transfers: Arc::new(Mutex::new(Vec::new())),
            stakes: Arc::new(Mutex::new(HashMap::new())),
            total_supply: Arc::new(Mutex::new(HashMap::new())),
            burn_ledger: Arc::new(Mutex::new(HashMap::new())),
            burn_records: Arc::new(Mutex::new(Vec::new())),
        };

        // Initialize with SNRG token
        manager.initialize_snrg_token();
        manager
    }

    fn initialize_snrg_token(&mut self) {
        let genesis_token = canonical_genesis()
            .ok()
            .map(|genesis| genesis.token().clone());
        let minimum_supply_cap = required_testnet_supply_cap_floor();
        let snrg_token = Token::new(
            "SNRG".to_string(),
            genesis_token
                .as_ref()
                .map(|token| token.name.clone())
                .unwrap_or_else(|| "Synergy Token".to_string()),
            genesis_token
                .as_ref()
                .map(|token| token.decimals)
                .unwrap_or(9),
            0,
            genesis_token
                .as_ref()
                .map(|token| token.total_supply_cap_nwei)
                .map(|value| value.max(minimum_supply_cap))
                .or(Some(
                    (1_150_000u128 * 10u128.pow(9)).max(minimum_supply_cap),
                )),
            true, // mintable during bootstrap
            true, // burnable
            "genesis".to_string(),
        );

        if let Ok(mut tokens) = self.tokens.lock() {
            tokens.insert("SNRG".to_string(), snrg_token.clone());
        }

        if let Ok(mut supply) = self.total_supply.lock() {
            supply.insert("SNRG".to_string(), 0); // Start with 0 supply
        }

        // Distribute initial supply to genesis accounts
        self.distribute_genesis_supply();
        self.apply_testnet_profile_allocations();

        // Testnet SNRG supply is fixed after genesis bootstrap.
        if let Ok(mut tokens) = self.tokens.lock() {
            if let Some(token) = tokens.get_mut("SNRG") {
                token.mintable = false;
            }
        }
    }

    fn distribute_genesis_supply(&self) {
        if let Ok(genesis) = canonical_genesis() {
            for balance in genesis.balances() {
                if let Ok(_) = self.mint_tokens(&balance.address, "SNRG", balance.balance_nwei) {
                    println!(
                        "✅ Genesis allocation: {} SNRG to {}",
                        balance.balance_nwei, balance.address
                    );
                }
            }
            return;
        }

        println!(
            "⚠️ Could not load canonical genesis for token allocations, using default allocations"
        );
        // Fallback to hardcoded allocations if genesis.json is not available.
        // These MUST match the genesis.json allocations exactly.
        let genesis_allocations = [
            (
                "synu1nd0fvzfhhj4s0te3ks06csfsnpg2hed8vsmh",
                400_000_000_000_000u64,
            ),
            (
                "synw1pckkuqdeep4qz47ww9hnnm6uru2f9r6qtumv",
                150_000_000_000_000u64,
            ),
            (
                "synw1vkn2dq8mftcn7nkdhyv5t0jrv83thf0cakkj",
                200_000_000_000_000u64,
            ),
            (
                "synw1prdr55ggjhupx0d7jycftrl2hzs3k8zuw5ad",
                100_000_000_000_000u64,
            ),
            (
                "synw1f2kpjt9flxl6y4e3uez0zp3hjanamrlew5ja",
                100_000_000_000_000u64,
            ),
            (
                "synv11cv5akg5xa86y8tc5jg84t7a5xhxenaypq36",
                50_000_000_000_000u64,
            ),
            (
                "synv11vwg95ecaryv33lrq6xptrg7vd5yrafturn4",
                50_000_000_000_000u64,
            ),
            (
                "synv113jp4578crnfnwg4d9r342euxfqf8a08s22g",
                50_000_000_000_000u64,
            ),
            (
                "synv11jlm4p4utpvj5ny0g8lnpa0ry65pkfecagnz",
                50_000_000_000_000u64,
            ),
        ];

        for (address, amount) in genesis_allocations {
            if let Ok(_) = self.mint_tokens(address, "SNRG", amount) {
                println!(
                    "✅ Fallback genesis allocation: {} SNRG to {}",
                    amount, address
                );
            }
        }
    }

    fn apply_testnet_profile_allocations(&self) {
        for (address, amount) in load_testnet_profile_allocations() {
            if amount == 0 || address.trim().is_empty() {
                continue;
            }

            let current_balance = self.get_balance(&address, "SNRG");
            if current_balance >= amount {
                continue;
            }

            let missing_amount = amount.saturating_sub(current_balance);
            if let Err(error) = self.mint_tokens(&address, "SNRG", missing_amount) {
                warn!(
                    "token",
                    "Failed to apply Testnet profile allocation",
                    "address" => address,
                    "amount" => missing_amount,
                    "error" => error
                );
            }
        }
    }

    pub fn create_token(
        &self,
        symbol: String,
        name: String,
        decimals: u8,
        total_supply: u64,
        max_supply: Option<u64>,
        mintable: bool,
        burnable: bool,
        creator: String,
    ) -> Result<String, String> {
        if let Ok(mut tokens) = self.tokens.lock() {
            if tokens.contains_key(&symbol) {
                return Err(format!("Token {} already exists", symbol));
            }

            let token = Token::new(
                symbol.clone(),
                name,
                decimals,
                total_supply as u128,
                max_supply.map(u128::from),
                mintable,
                burnable,
                creator.clone(),
            );

            tokens.insert(symbol.clone(), token);

            if let Ok(mut supply) = self.total_supply.lock() {
                supply.insert(symbol.clone(), 0);
            }
            self.update_token_supply_snapshot(&symbol, 0);

            // Mint initial supply to creator
            let _ = self.mint_tokens(&creator, &symbol, total_supply);

            Ok(format!("Token {} created successfully", symbol))
        } else {
            Err("Failed to acquire lock".to_string())
        }
    }

    fn update_token_supply_snapshot(&self, token_symbol: &str, total_supply: u128) {
        if let Ok(mut tokens) = self.tokens.lock() {
            if let Some(token) = tokens.get_mut(token_symbol) {
                token.total_supply = total_supply.to_string();
            }
        }
    }

    pub fn mint_tokens(&self, to: &str, token_symbol: &str, amount: u64) -> Result<String, String> {
        if let Ok(mut tokens) = self.tokens.lock() {
            if let Some(token) = tokens.get(token_symbol) {
                if !token.mintable {
                    return Err("Token is not mintable".to_string());
                }

                if let Some(max_supply) = token
                    .max_supply
                    .as_deref()
                    .and_then(|value| value.parse::<u128>().ok())
                {
                    if let Ok(supply) = self.total_supply.lock() {
                        let current_supply = supply.get(token_symbol).unwrap_or(&0);
                        if *current_supply + amount as u128 > max_supply {
                            return Err("Maximum supply exceeded".to_string());
                        }
                    }
                }
            } else {
                return Err("Token not found".to_string());
            }

            // Update total supply and snapshot while holding tokens lock (mut)
            let new_total = if let Ok(mut supply) = self.total_supply.lock() {
                let current = *supply.get(token_symbol).unwrap_or(&0);
                let new_total = current + amount as u128;
                supply.insert(token_symbol.to_string(), new_total);
                new_total
            } else {
                return Err("Failed to acquire lock".to_string());
            };

            // Update token supply snapshot inline (tokens already locked as mut — no re-lock needed)
            if let Some(token) = tokens.get_mut(token_symbol) {
                token.total_supply = new_total.to_string();
            }

            // Update balance
            if let Ok(mut balances) = self.balances.lock() {
                let address_balances = balances.entry(to.to_string()).or_insert_with(HashMap::new);
                let current_balance = address_balances.get(token_symbol).unwrap_or(&0);
                address_balances.insert(token_symbol.to_string(), current_balance + amount);
            }

            Ok(format!("Minted {} {} to {}", amount, token_symbol, to))
        } else {
            Err("Failed to acquire lock".to_string())
        }
    }

    pub fn burn_tokens(
        &self,
        from: &str,
        token_symbol: &str,
        amount: u64,
    ) -> Result<String, String> {
        self.burn_tokens_with_metadata(from, token_symbol, amount, 0, None, 0)
    }

    pub fn burn_tokens_with_metadata(
        &self,
        from: &str,
        token_symbol: &str,
        amount: u64,
        fee_charged_nwei: u64,
        tx_hash: Option<String>,
        block_height: u64,
    ) -> Result<String, String> {
        if crate::address::is_network_burn_address(from) {
            return Err("Network burn address cannot initiate burns".to_string());
        }
        if let Ok(mut tokens) = self.tokens.lock() {
            if let Some(token) = tokens.get(token_symbol) {
                if !token.burnable {
                    return Err("Token is not burnable".to_string());
                }

                // Check balance
                let current_balance = self.get_balance(from, token_symbol);
                if current_balance < amount {
                    return Err("Insufficient balance".to_string());
                }
            } else {
                return Err("Token not found".to_string());
            }

            // Update balance
            if let Ok(mut balances) = self.balances.lock() {
                if let Some(address_balances) = balances.get_mut(from) {
                    let current = address_balances.get(token_symbol).unwrap_or(&0);
                    address_balances.insert(token_symbol.to_string(), current - amount);
                }
            }

            // Update total supply and snapshot inline (tokens already locked as mut — no re-lock needed)
            let new_total = if let Ok(mut supply) = self.total_supply.lock() {
                let current = *supply.get(token_symbol).unwrap_or(&0);
                let new_total = current.saturating_sub(amount as u128);
                supply.insert(token_symbol.to_string(), new_total);
                new_total
            } else {
                return Err("Failed to acquire lock".to_string());
            };

            if let Some(token) = tokens.get_mut(token_symbol) {
                token.total_supply = new_total.to_string();
            }

            self.record_burn(BurnRecord {
                burner: from.to_string(),
                asset_id: token_symbol.to_string(),
                amount,
                burn_address: NETWORK_BURN_ADDRESS.to_string(),
                fee_charged_nwei,
                supply_reduced: true,
                tx_hash: tx_hash.unwrap_or_else(|| {
                    Self::generate_tx_hash(from, NETWORK_BURN_ADDRESS, token_symbol, amount, fee_charged_nwei)
                }),
                block_height,
                kind: BurnRecordKind::ExplicitBurn,
                timestamp: Token::current_timestamp(),
            })?;

            Ok(format!("Burned {} {} from {}", amount, token_symbol, from))
        } else {
            Err("Failed to acquire lock".to_string())
        }
    }

    pub fn transfer_tokens(
        &self,
        from: &str,
        to: &str,
        token_symbol: &str,
        amount: u64,
        fee: u64,
    ) -> Result<String, String> {
        self.transfer_tokens_internal(from, to, token_symbol, amount, fee, None, 0)
    }

    /// Transfer tokens while recording the originating transaction hash and block height.
    /// This is used by consensus when a transaction is included in a block, so the explorer
    /// can attribute transfers to on-chain transactions.
    pub fn transfer_tokens_with_metadata(
        &self,
        from: &str,
        to: &str,
        token_symbol: &str,
        amount: u64,
        fee: u64,
        tx_hash: String,
        block_height: u64,
    ) -> Result<String, String> {
        self.transfer_tokens_internal(
            from,
            to,
            token_symbol,
            amount,
            fee,
            Some(tx_hash),
            block_height,
        )
    }

    fn transfer_tokens_internal(
        &self,
        from: &str,
        to: &str,
        token_symbol: &str,
        amount: u64,
        fee: u64,
        tx_hash: Option<String>,
        block_height: u64,
    ) -> Result<String, String> {
        if crate::address::is_network_burn_address(from) {
            return Err("Network burn address cannot send funds".to_string());
        }
        if let Some(existing_hash) = tx_hash.as_deref() {
            if self.transfer_hash_exists(existing_hash) {
                return Ok(format!("Transfer {} already processed", existing_hash));
            }
        }

        let current_token_balance = self.get_balance(from, token_symbol);
        let same_asset_fee = token_symbol == SNRG_SYMBOL;
        if same_asset_fee {
            let required = amount
                .checked_add(fee)
                .ok_or_else(|| "Transfer amount plus fee overflow".to_string())?;
            if current_token_balance < required {
                return Err("Insufficient balance for transfer and fee".to_string());
            }
        } else {
            if current_token_balance < amount {
                return Err("Insufficient token balance for transfer".to_string());
            }
            let current_snrg_balance = self.get_balance(from, SNRG_SYMBOL);
            if current_snrg_balance < fee {
                return Err("Insufficient SNRG balance for fee".to_string());
            }
        }

        // Update sender, receiver, and protocol FeeCollector balances atomically under one lock.
        if let Ok(mut balances) = self.balances.lock() {
            if let Some(from_balances) = balances.get_mut(from) {
                let current = from_balances.get(token_symbol).unwrap_or(&0);
                if same_asset_fee {
                    from_balances.insert(token_symbol.to_string(), current - amount - fee);
                } else {
                    from_balances.insert(token_symbol.to_string(), current - amount);
                    let current_snrg = from_balances.get(SNRG_SYMBOL).copied().unwrap_or(0);
                    from_balances.insert(SNRG_SYMBOL.to_string(), current_snrg - fee);
                }
            }

            if let Some(to_balances) = balances.get_mut(to) {
                let current = to_balances.get(token_symbol).unwrap_or(&0);
                to_balances.insert(
                    token_symbol.to_string(),
                    current
                        .checked_add(amount)
                        .ok_or_else(|| "Receiver balance overflow".to_string())?,
                );
            } else {
                let mut new_balances = HashMap::new();
                new_balances.insert(token_symbol.to_string(), amount);
                balances.insert(to.to_string(), new_balances);
            }

            if fee > 0 {
                let fee_collector_balances = balances
                    .entry(FEE_COLLECTOR_ADDRESS.to_string())
                    .or_insert_with(HashMap::new);
                let current_fee_balance = fee_collector_balances
                    .get(SNRG_SYMBOL)
                    .copied()
                    .unwrap_or(0);
                fee_collector_balances.insert(
                    SNRG_SYMBOL.to_string(),
                    current_fee_balance
                        .checked_add(fee)
                        .ok_or_else(|| "FeeCollector balance overflow".to_string())?,
                );
            }
        }

        let tx_hash = tx_hash
            .unwrap_or_else(|| Self::generate_tx_hash(from, to, token_symbol, amount, fee));

        if crate::address::is_network_burn_address(to) {
            self.record_burn(BurnRecord {
                burner: from.to_string(),
                asset_id: token_symbol.to_string(),
                amount,
                burn_address: NETWORK_BURN_ADDRESS.to_string(),
                fee_charged_nwei: fee,
                supply_reduced: false,
                tx_hash: tx_hash.clone(),
                block_height,
                kind: BurnRecordKind::BurnAddressTransfer,
                timestamp: Token::current_timestamp(),
            })?;
        }

        // Record transfer
        let transfer = TokenTransfer {
            from: from.to_string(),
            to: to.to_string(),
            token_symbol: token_symbol.to_string(),
            amount,
            fee,
            timestamp: Token::current_timestamp(),
            tx_hash,
            block_height,
        };

        if let Ok(mut transfers) = self.transfers.lock() {
            transfers.push(transfer);
        }

        Ok(format!(
            "Transferred {} {} from {} to {}",
            amount, token_symbol, from, to
        ))
    }

    pub fn distribute_epoch_fees_from_collector(
        &self,
        epoch_id: u64,
        total_fees_nwei: u64,
    ) -> Result<crate::rewards::EpochFeeDistribution, String> {
        let config = crate::rewards::RewardConfig::default();
        config.validate()?;
        let distribution = crate::rewards::split_epoch_fees(epoch_id, total_fees_nwei as u128, 0)?;

        let collector_balance = self.get_balance(FEE_COLLECTOR_ADDRESS, SNRG_SYMBOL);
        if collector_balance < total_fees_nwei {
            return Err(format!(
                "FeeCollector balance {} below epoch fees {}",
                collector_balance, total_fees_nwei
            ));
        }

        let validator_share = u64::try_from(distribution.validator_share_nwei)
            .map_err(|_| "validator fee share exceeds u64".to_string())?;
        let treasury_share = u64::try_from(distribution.treasury_share_nwei)
            .map_err(|_| "treasury fee share exceeds u64".to_string())?;
        let burn_share = u64::try_from(distribution.burn_share_nwei)
            .map_err(|_| "burn fee share exceeds u64".to_string())?;

        if validator_share > 0 {
            self.transfer_tokens(
                FEE_COLLECTOR_ADDRESS,
                VALIDATOR_REWARDS_POOL_ADDRESS,
                SNRG_SYMBOL,
                validator_share,
                0,
            )?;
        }
        if treasury_share > 0 {
            self.transfer_tokens(
                FEE_COLLECTOR_ADDRESS,
                DAO_TREASURY_ADDRESS,
                SNRG_SYMBOL,
                treasury_share,
                0,
            )?;
        }
        if burn_share > 0 {
            self.burn_tokens(FEE_COLLECTOR_ADDRESS, SNRG_SYMBOL, burn_share)?;
        }

        Ok(distribution)
    }

    fn transfer_hash_exists(&self, tx_hash: &str) -> bool {
        self.transfers
            .lock()
            .map(|transfers| transfers.iter().any(|transfer| transfer.tx_hash == tx_hash))
            .unwrap_or(false)
    }

    fn record_burn(&self, record: BurnRecord) -> Result<(), String> {
        if record.amount == 0 {
            return Err("Burn amount must be greater than zero".to_string());
        }
        if self
            .burn_records
            .lock()
            .map(|records| records.iter().any(|existing| existing.tx_hash == record.tx_hash))
            .unwrap_or(false)
        {
            return Ok(());
        }
        if let Ok(mut ledger) = self.burn_ledger.lock() {
            let total = ledger.entry(record.asset_id.clone()).or_insert(0);
            *total = total
                .checked_add(record.amount as u128)
                .ok_or_else(|| "burn ledger overflow".to_string())?;
        } else {
            return Err("Failed to lock burn ledger".to_string());
        }

        if let Ok(mut records) = self.burn_records.lock() {
            records.push(record);
            Ok(())
        } else {
            Err("Failed to lock burn records".to_string())
        }
    }

    pub fn get_burned_total(&self, token_symbol: &str) -> u128 {
        self.burn_ledger
            .lock()
            .ok()
            .and_then(|ledger| ledger.get(token_symbol).copied())
            .unwrap_or(0)
    }

    pub fn get_burn_records(&self, token_symbol: Option<&str>) -> Vec<BurnRecord> {
        self.burn_records
            .lock()
            .map(|records| {
                records
                    .iter()
                    .filter(|record| {
                        token_symbol
                            .map(|symbol| record.asset_id == symbol)
                            .unwrap_or(true)
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn get_balance(&self, address: &str, token_symbol: &str) -> u64 {
        if let Ok(balances) = self.balances.lock() {
            if let Some(address_balances) = balances.get(address) {
                return address_balances.get(token_symbol).unwrap_or(&0).clone();
            }
        }
        0
    }

    pub fn get_all_balances(&self, address: &str) -> HashMap<String, u64> {
        if let Ok(balances) = self.balances.lock() {
            balances.get(address).cloned().unwrap_or_default()
        } else {
            HashMap::new()
        }
    }

    fn charge_snrg_fee(&self, payer: &str, fee_nwei: u64) -> Result<(), String> {
        if fee_nwei == 0 {
            return Ok(());
        }
        if crate::address::is_network_burn_address(payer) {
            return Err("Network burn address cannot pay transaction fees".to_string());
        }
        if let Ok(mut balances) = self.balances.lock() {
            let payer_balances = balances
                .get_mut(payer)
                .ok_or_else(|| "Fee payer balance not found".to_string())?;
            let current = payer_balances.get(SNRG_SYMBOL).copied().unwrap_or(0);
            if current < fee_nwei {
                return Err("Insufficient SNRG balance for fee".to_string());
            }
            payer_balances.insert(SNRG_SYMBOL.to_string(), current - fee_nwei);

            let collector_balances = balances
                .entry(FEE_COLLECTOR_ADDRESS.to_string())
                .or_insert_with(HashMap::new);
            let collector = collector_balances.get(SNRG_SYMBOL).copied().unwrap_or(0);
            collector_balances.insert(
                SNRG_SYMBOL.to_string(),
                collector
                    .checked_add(fee_nwei)
                    .ok_or_else(|| "FeeCollector balance overflow".to_string())?,
            );
            Ok(())
        } else {
            Err("Failed to acquire lock".to_string())
        }
    }

    pub fn stake_tokens(
        &self,
        staker: &str,
        validator: &str,
        token_symbol: &str,
        amount: u64,
    ) -> Result<String, String> {
        if crate::address::is_network_burn_address(staker)
            || crate::address::is_network_burn_address(validator)
        {
            return Err("Network burn address cannot stake or validate".to_string());
        }
        if !crate::address::is_valid_address(staker) {
            return Err("Invalid staker Synergy address".to_string());
        }
        if !crate::address::is_valid_address(validator) {
            return Err("Invalid validator Synergy address".to_string());
        }

        let current_balance = self.get_balance(staker, token_symbol);
        if current_balance < amount {
            return Err("Insufficient balance for staking".to_string());
        }

        // Move tokens from balance to staked balance
        if let Ok(mut balances) = self.balances.lock() {
            if let Some(staker_balances) = balances.get_mut(staker) {
                let current = staker_balances.get(token_symbol).unwrap_or(&0);
                staker_balances.insert(token_symbol.to_string(), current - amount);
            }
        }

        if let Ok(mut staked) = self.staked_balances.lock() {
            let staker_staked = staked
                .entry(staker.to_string())
                .or_insert_with(HashMap::new);
            let current = staker_staked.get(token_symbol).unwrap_or(&0);
            staker_staked.insert(token_symbol.to_string(), current + amount);
        }

        // Create staking info
        let stake_info = StakingInfo {
            validator_address: validator.to_string(),
            staker_address: staker.to_string(),
            amount,
            stake_start: Token::current_timestamp(),
            stake_end: None,
            rewards_earned: 0,
            is_active: true,
        };

        if let Ok(mut stakes) = self.stakes.lock() {
            let validator_stakes = stakes.entry(validator.to_string()).or_insert_with(Vec::new);
            validator_stakes.push(stake_info);
        }

        Ok(format!(
            "Staked {} {} to validator {}",
            amount, token_symbol, validator
        ))
    }

    pub fn unstake_tokens(
        &self,
        staker: &str,
        validator: &str,
        token_symbol: &str,
        amount: u64,
    ) -> Result<String, String> {
        // Check if staker has enough staked tokens
        let staked_balance = self.get_staked_balance(staker, token_symbol);
        if staked_balance < amount {
            return Err("Insufficient staked balance".to_string());
        }

        // Find and update the stake
        if let Ok(mut stakes) = self.stakes.lock() {
            if let Some(validator_stakes) = stakes.get_mut(validator) {
                for stake in validator_stakes.iter_mut() {
                    if stake.staker_address == staker && stake.is_active {
                        if stake.amount >= amount {
                            stake.amount -= amount;
                            if stake.amount == 0 {
                                stake.is_active = false;
                            }
                            break;
                        }
                    }
                }
            }
        }

        // Move tokens from staked back to balance
        if let Ok(mut balances) = self.balances.lock() {
            if let Some(staker_balances) = balances.get_mut(staker) {
                let current = staker_balances.get(token_symbol).unwrap_or(&0);
                staker_balances.insert(token_symbol.to_string(), current + amount);
            }
        }

        if let Ok(mut staked) = self.staked_balances.lock() {
            if let Some(staker_staked) = staked.get_mut(staker) {
                let current = staker_staked.get(token_symbol).unwrap_or(&0);
                staker_staked.insert(token_symbol.to_string(), current - amount);
            }
        }

        Ok(format!(
            "Unstaked {} {} from validator {}",
            amount, token_symbol, validator
        ))
    }

    pub fn get_staked_balance(&self, address: &str, token_symbol: &str) -> u64 {
        if address == "*" {
            let direct_total = self
                .staked_balances
                .lock()
                .ok()
                .map(|staked| {
                    staked
                        .values()
                        .filter_map(|balances| balances.get(token_symbol))
                        .copied()
                        .sum::<u64>()
                })
                .unwrap_or(0);
            if direct_total > 0 {
                return direct_total;
            }

            return self
                .stakes
                .lock()
                .ok()
                .map(|stakes| {
                    stakes
                        .values()
                        .flatten()
                        .filter(|stake| stake.is_active)
                        .map(|stake| stake.amount)
                        .sum::<u64>()
                })
                .unwrap_or(0);
        }

        if let Ok(staked) = self.staked_balances.lock() {
            if let Some(address_staked) = staked.get(address) {
                let direct = address_staked.get(token_symbol).copied().unwrap_or(0);
                if direct > 0 {
                    return direct;
                }
            }
        }

        self.stakes
            .lock()
            .ok()
            .map(|stakes| {
                stakes
                    .values()
                    .flatten()
                    .filter(|stake| stake.is_active && stake.staker_address == address)
                    .map(|stake| stake.amount)
                    .sum::<u64>()
            })
            .unwrap_or(0)
    }

    /// Distribute rewards to a cluster, then to validators in that cluster based on normalized
    /// integer basis-point Synergy scores.
    /// This implements the PoSy protocol where rewards are awarded to clusters first, then distributed
    /// among validators in the cluster based on their normalized Synergy Scores
    pub fn distribute_cluster_rewards(
        &self,
        cluster_validators: &[(String, u64)], // (validator_address, normalized_synergy_score_bps)
        reward_amount: u64,
    ) -> Result<String, String> {
        const SCORE_BPS_DENOMINATOR: u64 = 10_000;

        // Check rewards pool balance
        let pool_balance = self.get_balance(VALIDATOR_REWARDS_POOL_ADDRESS, SNRG_SYMBOL);
        if pool_balance < reward_amount {
            return Err(format!(
                "Insufficient rewards pool balance: {} < {}",
                pool_balance, reward_amount
            ));
        }

        if cluster_validators.is_empty() {
            return Err("No validators in cluster".to_string());
        }

        let total_score: u64 = cluster_validators.iter().map(|(_, score)| *score).sum();
        if total_score != SCORE_BPS_DENOMINATOR {
            return Err(format!(
                "Invalid normalized score bps: sum = {} (expected 10000)",
                total_score
            ));
        }

        // Deduct total reward from rewards pool
        if let Ok(mut balances) = self.balances.lock() {
            if let Some(pool_balances) = balances.get_mut(VALIDATOR_REWARDS_POOL_ADDRESS) {
                let current = pool_balances.get(SNRG_SYMBOL).unwrap_or(&0);
                if *current < reward_amount {
                    return Err(format!(
                        "Rewards pool balance check failed: {} < {}",
                        current, reward_amount
                    ));
                }
                pool_balances.insert(SNRG_SYMBOL.to_string(), current - reward_amount);
            } else {
                return Err("Rewards pool not found".to_string());
            }
        }

        // Distribute rewards to each validator based on their normalized synergy score
        let mut distributed_count = 0;
        let mut distributed_total = 0u64;
        for (index, (validator_address, normalized_score_bps)) in
            cluster_validators.iter().enumerate()
        {
            let validator_reward = if index + 1 == cluster_validators.len() {
                reward_amount.saturating_sub(distributed_total)
            } else {
                let share = ((reward_amount as u128) * (*normalized_score_bps as u128))
                    / (SCORE_BPS_DENOMINATOR as u128);
                u64::try_from(share).map_err(|_| "validator reward exceeds u64".to_string())?
            };
            distributed_total = distributed_total
                .checked_add(validator_reward)
                .ok_or_else(|| "cluster reward distribution overflow".to_string())?;

            if validator_reward == 0 {
                continue; // Skip validators with zero reward
            }

            // Add reward to validator's balance
            if let Ok(mut balances) = self.balances.lock() {
                let validator_balances = balances
                    .entry(validator_address.clone())
                    .or_insert_with(HashMap::new);
                let current = validator_balances.get(SNRG_SYMBOL).unwrap_or(&0);
                validator_balances.insert(
                    SNRG_SYMBOL.to_string(),
                    current
                        .checked_add(validator_reward)
                        .ok_or_else(|| "validator reward balance overflow".to_string())?,
                );
            }

            // Now distribute validator's reward to their stakers
            if let Err(e) =
                self.distribute_validator_rewards_to_stakers(validator_address, validator_reward)
            {
                warn!("token", "Failed to distribute validator reward to stakers", 
                      "validator" => validator_address.clone(), 
                      "error" => e);
                // Continue with other validators even if one fails
            } else {
                distributed_count += 1;
            }
        }

        Ok(format!(
            "Distributed {} rewards to cluster ({} validators)",
            reward_amount, distributed_count
        ))
    }

    /// Distribute a validator's reward to their stakers (proportional to stake)
    fn distribute_validator_rewards_to_stakers(
        &self,
        validator: &str,
        reward_amount: u64,
    ) -> Result<String, String> {
        // Collect stake data we need (read-only)
        let stake_data: Vec<(String, u64)> = {
            if let Ok(stakes) = self.stakes.lock() {
                if let Some(validator_stakes) = stakes.get(validator) {
                    let active_stakes: Vec<_> = validator_stakes
                        .iter()
                        .filter(|stake| stake.is_active)
                        .collect();

                    if active_stakes.is_empty() {
                        return Ok("No active stakes".to_string());
                    }

                    let total_staked: u64 = active_stakes.iter().map(|stake| stake.amount).sum();
                    if total_staked == 0 {
                        return Ok("No staked tokens".to_string());
                    }

                    // Collect (staker_address, reward_portion) pairs
                    active_stakes
                        .iter()
                        .map(|stake| {
                            let reward_portion = (stake.amount * reward_amount) / total_staked;
                            (stake.staker_address.clone(), reward_portion)
                        })
                        .collect()
                } else {
                    return Err("Validator not found or no active stakes".to_string());
                }
            } else {
                return Err("Failed to lock stakes".to_string());
            }
        }; // stakes lock is dropped here

        let staker_count = stake_data.len();

        // Now update balances and stakes separately, without holding multiple locks
        for (staker_address, reward_portion) in stake_data {
            // Add rewards to staker's balance
            if let Ok(mut balances) = self.balances.lock() {
                if let Some(staker_balances) = balances.get_mut(&staker_address) {
                    let current = staker_balances.get("SNRG").unwrap_or(&0);
                    staker_balances.insert("SNRG".to_string(), current + reward_portion);
                } else {
                    // Create balance entry if it doesn't exist
                    let mut new_balances = HashMap::new();
                    new_balances.insert("SNRG".to_string(), reward_portion);
                    balances.insert(staker_address.clone(), new_balances);
                }
            } // balances lock dropped

            // Update stake rewards
            if let Ok(mut stakes) = self.stakes.lock() {
                if let Some(validator_stakes) = stakes.get_mut(validator) {
                    for s in validator_stakes.iter_mut() {
                        if s.staker_address == staker_address && s.is_active {
                            s.rewards_earned += reward_portion;
                            break;
                        }
                    }
                }
            } // stakes lock dropped
        }

        Ok(format!(
            "Distributed {} rewards to {} stakers",
            reward_amount, staker_count
        ))
    }

    /// Legacy function - distributes rewards to a single validator's stakers
    /// This is kept for backward compatibility but should use distribute_cluster_rewards instead
    pub fn distribute_validator_rewards(
        &self,
        validator: &str,
        reward_amount: u64,
    ) -> Result<String, String> {
        // First, check if rewards pool has sufficient balance
        let pool_balance = self.get_balance(VALIDATOR_REWARDS_POOL_ADDRESS, "SNRG");
        if pool_balance < reward_amount {
            return Err(format!(
                "Insufficient rewards pool balance: {} < {}",
                pool_balance, reward_amount
            ));
        }

        // Collect stake data we need (read-only)
        let stake_data: Vec<(String, u64)> = {
            if let Ok(stakes) = self.stakes.lock() {
                if let Some(validator_stakes) = stakes.get(validator) {
                    let active_stakes: Vec<_> = validator_stakes
                        .iter()
                        .filter(|stake| stake.is_active)
                        .collect();

                    if active_stakes.is_empty() {
                        return Ok("No active stakes".to_string());
                    }

                    let total_staked: u64 = active_stakes.iter().map(|stake| stake.amount).sum();
                    if total_staked == 0 {
                        return Ok("No staked tokens".to_string());
                    }

                    // Collect (staker_address, reward_portion) pairs
                    active_stakes
                        .iter()
                        .map(|stake| {
                            let reward_portion = (stake.amount * reward_amount) / total_staked;
                            (stake.staker_address.clone(), reward_portion)
                        })
                        .collect()
                } else {
                    return Err("Validator not found or no active stakes".to_string());
                }
            } else {
                return Err("Failed to lock stakes".to_string());
            }
        }; // stakes lock is dropped here

        let staker_count = stake_data.len();

        // Deduct total reward amount from rewards pool
        if let Ok(mut balances) = self.balances.lock() {
            if let Some(pool_balances) = balances.get_mut(VALIDATOR_REWARDS_POOL_ADDRESS) {
                let current = pool_balances.get("SNRG").unwrap_or(&0);
                if *current < reward_amount {
                    return Err(format!(
                        "Rewards pool balance check failed during deduction: {} < {}",
                        current, reward_amount
                    ));
                }
                pool_balances.insert("SNRG".to_string(), current - reward_amount);
            } else {
                return Err("Rewards pool not found".to_string());
            }
        } // balances lock dropped

        // Now update balances and stakes separately, without holding multiple locks
        for (staker_address, reward_portion) in stake_data {
            // Add rewards to staker's balance (transferred from rewards pool)
            if let Ok(mut balances) = self.balances.lock() {
                if let Some(staker_balances) = balances.get_mut(&staker_address) {
                    let current = staker_balances.get("SNRG").unwrap_or(&0);
                    staker_balances.insert("SNRG".to_string(), current + reward_portion);
                }
            } // balances lock dropped

            // Update stake rewards
            if let Ok(mut stakes) = self.stakes.lock() {
                if let Some(validator_stakes) = stakes.get_mut(validator) {
                    for s in validator_stakes.iter_mut() {
                        if s.staker_address == staker_address && s.is_active {
                            s.rewards_earned += reward_portion;
                            break;
                        }
                    }
                }
            } // stakes lock dropped
        }

        Ok(format!(
            "Distributed {} rewards from pool to {} stakers",
            reward_amount, staker_count
        ))
    }

    pub fn process_transaction(&self, tx: &Transaction) -> Result<String, String> {
        // Handle token transfers
        if tx
            .data
            .as_ref()
            .map_or(false, |data| data.starts_with("token_transfer:"))
        {
            if let Some(data_str) = &tx.data {
                if let Some(transfer_data) = data_str.strip_prefix("token_transfer:") {
                    if let Ok(transfer_info) =
                        serde_json::from_str::<serde_json::Value>(transfer_data)
                    {
                        if let (Some(to), Some(token_symbol), Some(amount)) = (
                            transfer_info.get("to").and_then(|v| v.as_str()),
                            transfer_info.get("token").and_then(|v| v.as_str()),
                            transfer_info.get("amount").and_then(|v| v.as_u64()),
                        ) {
                            return self.transfer_tokens(
                                &tx.sender,
                                to,
                                token_symbol,
                                amount,
                                tx.get_total_network_fee_u64()?,
                            );
                        }
                    }
                }
            }
        }

        // Handle staking transactions
        if tx
            .data
            .as_ref()
            .map_or(false, |data| data.starts_with("stake:"))
        {
            if let Some(data_str) = &tx.data {
                if let Some(stake_data) = data_str.strip_prefix("stake:") {
                    if let Ok(stake_info) = serde_json::from_str::<serde_json::Value>(stake_data) {
                        if let (Some(validator), Some(token_symbol), Some(amount)) = (
                            stake_info.get("validator").and_then(|v| v.as_str()),
                            stake_info.get("token").and_then(|v| v.as_str()),
                            stake_info.get("amount").and_then(|v| v.as_u64()),
                        ) {
                            self.charge_snrg_fee(&tx.sender, tx.get_total_network_fee_u64()?)?;
                            return self.stake_tokens(&tx.sender, validator, token_symbol, amount);
                        }
                    }
                }
            }
        }

        if tx
            .data
            .as_ref()
            .map_or(false, |data| data.starts_with("burn:"))
        {
            if let Some(data_str) = &tx.data {
                if let Some(burn_data) = data_str.strip_prefix("burn:") {
                    if let Ok(burn_info) = serde_json::from_str::<serde_json::Value>(burn_data) {
                        if let (Some(token_symbol), Some(amount)) = (
                            burn_info
                                .get("asset")
                                .or_else(|| burn_info.get("asset_id"))
                                .or_else(|| burn_info.get("token"))
                                .and_then(|v| v.as_str()),
                            burn_info.get("amount").and_then(|v| v.as_u64()),
                        ) {
                            let fee = tx.get_total_network_fee_u64()?;
                            self.charge_snrg_fee(&tx.sender, fee)?;
                            return self.burn_tokens_with_metadata(
                                &tx.sender,
                                token_symbol,
                                amount,
                                fee,
                                Some(tx.hash()),
                                0,
                            );
                        }
                    }
                }
            }
        }

        // Handle native SNRG transfers submitted through the public
        // synergy_sendTransaction path. These transactions carry the SNRG
        // amount in the canonical amount field and may not include the legacy
        // token_transfer data wrapper used by the local faucet helper.
        if tx.amount > 0 && !tx.receiver.trim().is_empty() {
            return self.transfer_tokens(
                &tx.sender,
                &tx.receiver,
                "SNRG",
                tx.amount,
                tx.get_total_network_fee_u64()?,
            );
        }

        if tx
            .data
            .as_deref()
            .map(|data| data.starts_with("validator_activation:"))
            .unwrap_or(false)
        {
            return Ok("Validator activation handled by validator registry".to_string());
        }

        Err("Unsupported transaction type".to_string())
    }

    /// Process a transaction that has been included in a specific block height.
    /// This records transfer metadata (tx hash + block height) for explorer queries.
    pub fn process_transaction_in_block(
        &self,
        tx: &Transaction,
        block_height: u64,
    ) -> Result<String, String> {
        // Handle token transfers
        if tx
            .data
            .as_ref()
            .map_or(false, |data| data.starts_with("token_transfer:"))
        {
            if let Some(data_str) = &tx.data {
                if let Some(transfer_data) = data_str.strip_prefix("token_transfer:") {
                    if let Ok(transfer_info) =
                        serde_json::from_str::<serde_json::Value>(transfer_data)
                    {
                        if let (Some(to), Some(token_symbol), Some(amount)) = (
                            transfer_info.get("to").and_then(|v| v.as_str()),
                            transfer_info.get("token").and_then(|v| v.as_str()),
                            transfer_info.get("amount").and_then(|v| v.as_u64()),
                        ) {
                            return self.transfer_tokens_with_metadata(
                                &tx.sender,
                                to,
                                token_symbol,
                                amount,
                                tx.get_total_network_fee_u64()?,
                                tx.hash(),
                                block_height,
                            );
                        }
                    }
                }
            }
        }

        // Handle staking transactions
        if tx
            .data
            .as_ref()
            .map_or(false, |data| data.starts_with("stake:"))
        {
            if let Some(data_str) = &tx.data {
                if let Some(stake_data) = data_str.strip_prefix("stake:") {
                    if let Ok(stake_info) = serde_json::from_str::<serde_json::Value>(stake_data) {
                        if let (Some(validator), Some(token_symbol), Some(amount)) = (
                            stake_info.get("validator").and_then(|v| v.as_str()),
                            stake_info.get("token").and_then(|v| v.as_str()),
                            stake_info.get("amount").and_then(|v| v.as_u64()),
                        ) {
                            self.charge_snrg_fee(&tx.sender, tx.get_total_network_fee_u64()?)?;
                            return self.stake_tokens(&tx.sender, validator, token_symbol, amount);
                        }
                    }
                }
            }
        }

        if tx
            .data
            .as_ref()
            .map_or(false, |data| data.starts_with("burn:"))
        {
            if let Some(data_str) = &tx.data {
                if let Some(burn_data) = data_str.strip_prefix("burn:") {
                    if let Ok(burn_info) = serde_json::from_str::<serde_json::Value>(burn_data) {
                        if let (Some(token_symbol), Some(amount)) = (
                            burn_info
                                .get("asset")
                                .or_else(|| burn_info.get("asset_id"))
                                .or_else(|| burn_info.get("token"))
                                .and_then(|v| v.as_str()),
                            burn_info.get("amount").and_then(|v| v.as_u64()),
                        ) {
                            let fee = tx.get_total_network_fee_u64()?;
                            self.charge_snrg_fee(&tx.sender, fee)?;
                            return self.burn_tokens_with_metadata(
                                &tx.sender,
                                token_symbol,
                                amount,
                                fee,
                                Some(tx.hash()),
                                block_height,
                            );
                        }
                    }
                }
            }
        }

        if tx.amount > 0 && !tx.receiver.trim().is_empty() {
            return self.transfer_tokens_with_metadata(
                &tx.sender,
                &tx.receiver,
                "SNRG",
                tx.amount,
                tx.get_total_network_fee_u64()?,
                tx.hash(),
                block_height,
            );
        }

        if tx
            .data
            .as_deref()
            .map(|data| data.starts_with("validator_activation:"))
            .unwrap_or(false)
        {
            return Ok("Validator activation handled by validator registry".to_string());
        }

        Err("Unsupported transaction type".to_string())
    }

    pub fn get_token_info(&self, symbol: &str) -> Option<Token> {
        if let Ok(tokens) = self.tokens.lock() {
            tokens.get(symbol).cloned()
        } else {
            None
        }
    }

    pub fn get_all_tokens(&self) -> Vec<Token> {
        if let Ok(tokens) = self.tokens.lock() {
            tokens.values().cloned().collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_transfer_history(&self, address: &str, limit: usize) -> Vec<TokenTransfer> {
        if let Ok(transfers) = self.transfers.lock() {
            transfers
                .iter()
                .filter(|transfer| transfer.from == address || transfer.to == address)
                .take(limit)
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn replay_chain_transactions(&self, chain: &crate::block::BlockChain) -> (u64, u64) {
        let mut applied = 0u64;
        let mut failed = 0u64;

        for block in &chain.chain {
            for tx in &block.transactions {
                let is_token_transfer = tx
                    .data
                    .as_deref()
                    .map(|data| data.starts_with("token_transfer:"))
                    .unwrap_or(false);
                let is_native_transfer = tx.amount > 0
                    && !tx.receiver.trim().is_empty()
                    && !tx
                        .data
                        .as_deref()
                        .map(|data| data.starts_with("stake:"))
                        .unwrap_or(false);
                let is_validator_activation = tx
                    .data
                    .as_deref()
                    .map(|data| data.starts_with("validator_activation:"))
                    .unwrap_or(false);
                if !is_token_transfer && !is_native_transfer && !is_validator_activation {
                    continue;
                }

                match self.process_transaction_in_block(tx, block.block_index) {
                    Ok(_) => applied += 1,
                    Err(_) => failed += 1,
                }
            }
        }

        (applied, failed)
    }

    pub fn get_staking_info(&self, address: &str) -> Vec<StakingInfo> {
        if let Ok(stakes) = self.stakes.lock() {
            stakes
                .values()
                .flatten()
                .filter(|stake| stake.staker_address == address)
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Ensure the rewards pool has sufficient balance for validator rewards
    /// This should be called on startup to verify the pool is funded
    pub fn ensure_rewards_pool_funded(&self) -> Result<(), String> {
        const MIN_POOL_BALANCE: u64 = 1_000_000_000_000_000_000u64; // 1B SNRG minimum
        const REFILL_AMOUNT: u64 = 2_000_000_000_000_000_000u64; // 2B SNRG refill

        let pool_balance = self.get_balance(VALIDATOR_REWARDS_POOL_ADDRESS, "SNRG");

        if pool_balance < MIN_POOL_BALANCE {
            println!(
                "⚠️ Rewards pool balance low: {} nWei. Initializing...",
                pool_balance
            );

            // Mint tokens to rewards pool if it's empty or low
            match self.mint_tokens(VALIDATOR_REWARDS_POOL_ADDRESS, "SNRG", REFILL_AMOUNT) {
                Ok(_) => {
                    let new_balance = self.get_balance(REWARDS_POOL, "SNRG");
                    println!(
                        "✅ Rewards pool initialized with {} SNRG (balance: {} nWei)",
                        REFILL_AMOUNT / 1_000_000_000,
                        new_balance
                    );
                    Ok(())
                }
                Err(e) => {
                    println!("❌ Failed to initialize rewards pool: {}", e);
                    Err(e)
                }
            }
        } else {
            println!(
                "✅ Rewards pool balance OK: {} SNRG",
                pool_balance / 1_000_000_000
            );
            Ok(())
        }
    }

    /// Get the rewards pool address
    pub fn get_rewards_pool_address() -> &'static str {
        VALIDATOR_REWARDS_POOL_ADDRESS
    }

    /// Get rewards pool balance
    pub fn get_rewards_pool_balance(&self) -> u64 {
        self.get_balance(Self::get_rewards_pool_address(), "SNRG")
    }

    pub fn get_total_stake_for_validator(&self, validator: &str) -> u64 {
        if let Ok(stakes) = self.stakes.lock() {
            if let Some(validator_stakes) = stakes.get(validator) {
                return validator_stakes
                    .iter()
                    .filter(|stake| stake.is_active)
                    .map(|stake| stake.amount)
                    .sum();
            }
        }
        0
    }

    fn generate_tx_hash(from: &str, to: &str, token: &str, amount: u64, fee: u64) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(from.as_bytes());
        hasher.update(to.as_bytes());
        hasher.update(token.as_bytes());
        hasher.update(&amount.to_le_bytes());
        hasher.update(&fee.to_le_bytes());
        hasher.update(&Token::current_timestamp().to_le_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn save_state(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let state = TokenState {
            tokens: self.get_all_tokens(),
            balances: self.balances.lock().unwrap().clone(),
            transfers: self.transfers.lock().unwrap().clone(),
            stakes: self.stakes.lock().unwrap().clone(),
            burn_ledger: self.burn_ledger.lock().unwrap().clone(),
            burn_records: self.burn_records.lock().unwrap().clone(),
        };

        let json = serde_json::to_string_pretty(&state)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load_state(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        if std::path::Path::new(path).exists() {
            let content = std::fs::read_to_string(path)?;
            let state: TokenState = serde_json::from_str(&content)?;

            if let Ok(mut tokens) = self.tokens.lock() {
                for token in state.tokens {
                    tokens.insert(token.symbol.clone(), token);
                }
            }

            if let Ok(mut balances) = self.balances.lock() {
                *balances = state.balances;
            }

            if let Ok(mut transfers) = self.transfers.lock() {
                *transfers = state.transfers;
            }

            if let Ok(mut stakes) = self.stakes.lock() {
                *stakes = state.stakes;
            }
            if let Ok(mut burn_ledger) = self.burn_ledger.lock() {
                *burn_ledger = state.burn_ledger;
            }
            if let Ok(mut burn_records) = self.burn_records.lock() {
                *burn_records = state.burn_records;
            }
        }

        self.reconcile_testnet_profile_allocations();

        Ok(())
    }

    fn reconcile_testnet_profile_allocations(&self) {
        let allocations = load_testnet_profile_allocations();
        if allocations.is_empty() {
            return;
        }

        let mut missing_total = 0u128;
        for (address, amount) in &allocations {
            let current_balance = self.get_balance(address, "SNRG");
            if current_balance < *amount {
                missing_total = missing_total.saturating_add((*amount - current_balance) as u128);
            }
        }

        if missing_total == 0 {
            return;
        }

        let mut updated_supply = None;
        if let Ok(mut supply) = self.total_supply.lock() {
            let total = supply.entry("SNRG".to_string()).or_insert(0);
            *total = total.saturating_add(missing_total);
            updated_supply = Some(*total);
        }

        if let Ok(mut tokens) = self.tokens.lock() {
            if let Some(token) = tokens.get_mut("SNRG") {
                let current_max = token
                    .max_supply
                    .as_deref()
                    .and_then(|value| value.parse::<u128>().ok())
                    .unwrap_or(0);
                let required_max = current_max
                    .max(updated_supply.unwrap_or(0))
                    .max(required_testnet_supply_cap_floor());
                token.max_supply = Some(required_max.to_string());
            }
        }

        if let Some(total_supply) = updated_supply {
            self.update_token_supply_snapshot("SNRG", total_supply);
        }

        if let Ok(mut balances) = self.balances.lock() {
            for (address, amount) in allocations {
                let address_balances = balances.entry(address).or_insert_with(HashMap::new);
                let current_balance = address_balances.get("SNRG").copied().unwrap_or(0);
                if current_balance < amount {
                    address_balances.insert("SNRG".to_string(), amount);
                }
            }
        }
    }
}

fn load_testnet_profile_allocations() -> Vec<(String, u64)> {
    // Per-node profile allocations are not consensus state. Applying them at
    // validator runtime causes each machine to mint a different local token
    // ledger from its own profile.json. Keep the old behavior behind an
    // explicit opt-in for non-network bootstrap tooling only.
    if !profile_allocations_enabled() {
        return Vec::new();
    }

    for path in candidate_testnet_profile_paths() {
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(profile) = serde_json::from_str::<TestnetTokenProfile>(&contents) else {
            continue;
        };
        return profile
            .genesis_mints
            .into_iter()
            .filter_map(|mint| {
                mint.amount_nwei
                    .trim()
                    .parse::<u64>()
                    .ok()
                    .map(|amount| (mint.wallet_address, amount))
            })
            .collect();
    }

    Vec::new()
}

fn required_testnet_supply_cap_floor() -> u128 {
    let canonical_total = canonical_genesis()
        .ok()
        .map(|genesis| {
            genesis
                .balances()
                .iter()
                .map(|balance| balance.balance_nwei as u128)
                .sum::<u128>()
        })
        .unwrap_or(0);

    let profile_total = load_testnet_profile_allocations()
        .into_iter()
        .map(|(_, amount)| amount as u128)
        .sum::<u128>();

    canonical_total.saturating_add(profile_total)
}

fn candidate_testnet_profile_paths() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(project_root) = std::env::var("SYNERGY_PROJECT_ROOT") {
        let root = PathBuf::from(project_root);
        candidates.push(root.join("network").join("profile.json"));
        if let Some(testnet_root) = root.parent().and_then(|parent| parent.parent()) {
            candidates.push(testnet_root.join("network").join("profile.json"));
        }
    }

    candidates.push(PathBuf::from("network/profile.json"));
    candidates.push(PathBuf::from("../../network/profile.json"));
    candidates.push(PathBuf::from("../../../network/profile.json"));

    let mut deduped = Vec::new();
    for candidate in candidates {
        if !deduped.contains(&candidate) {
            deduped.push(candidate);
        }
    }

    deduped
}

#[derive(Serialize, Deserialize)]
struct TokenState {
    tokens: Vec<Token>,
    balances: HashMap<String, HashMap<String, u64>>,
    transfers: Vec<TokenTransfer>,
    stakes: HashMap<String, Vec<StakingInfo>>,
    #[serde(default)]
    burn_ledger: HashMap<String, u128>,
    #[serde(default)]
    burn_records: Vec<BurnRecord>,
}

// Global token manager instance
lazy_static::lazy_static! {
    pub static ref TOKEN_MANAGER: Arc<TokenManager> = Arc::new(TokenManager::new());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    lazy_static::lazy_static! {
        static ref ENV_GUARD: Mutex<()> = Mutex::new(());
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, previous }
        }

        fn remove(key: &'static str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.previous {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn write_test_profile() -> PathBuf {
        let unique = format!(
            "synergy-token-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = std::env::temp_dir().join(unique);
        let network_dir = root.join("network");
        fs::create_dir_all(&network_dir).expect("create temp network dir");
        fs::write(
            network_dir.join("profile.json"),
            r#"{
  "genesis_mints": [
    {
      "wallet_address": "synw1testprofileallocxxxxxxxxxxxxxxxxxxxx",
      "amount_nwei": "42"
    }
  ]
}"#,
        )
        .expect("write test profile");
        root
    }

    fn seed_snrg_balance(manager: &TokenManager, address: &str, amount: u64) {
        let mut balances = manager.balances.lock().unwrap();
        let entry = balances
            .entry(address.to_string())
            .or_insert_with(HashMap::new);
        entry.insert("SNRG".to_string(), amount);
    }

    #[test]
    fn profile_allocations_are_disabled_by_default() {
        let _guard = ENV_GUARD.lock().unwrap();
        let temp_root = write_test_profile();
        let _project_root = EnvVarGuard::set(
            "SYNERGY_PROJECT_ROOT",
            temp_root.to_str().expect("temp path utf8"),
        );
        let _allocations_flag = EnvVarGuard::remove("SYNERGY_ENABLE_PROFILE_ALLOCATIONS");

        assert!(
            load_testnet_profile_allocations().is_empty(),
            "runtime must ignore per-node profile allocations unless explicitly enabled"
        );

        let _ = fs::remove_dir_all(temp_root);
    }

    #[test]
    fn profile_allocations_can_be_enabled_explicitly() {
        let _guard = ENV_GUARD.lock().unwrap();
        let temp_root = write_test_profile();
        let _project_root = EnvVarGuard::set(
            "SYNERGY_PROJECT_ROOT",
            temp_root.to_str().expect("temp path utf8"),
        );
        let _allocations_flag = EnvVarGuard::set("SYNERGY_ENABLE_PROFILE_ALLOCATIONS", "1");

        assert_eq!(
            load_testnet_profile_allocations(),
            vec![("synw1testprofileallocxxxxxxxxxxxxxxxxxxxx".to_string(), 42)]
        );

        let _ = fs::remove_dir_all(temp_root);
    }

    #[test]
    fn native_snrg_transaction_updates_balances_and_transfer_history() {
        let manager = TokenManager::new();
        let sender = "synw1sendernative000000000000000000000000";
        let receiver = "synw1receivernative00000000000000000000";
        seed_snrg_balance(&manager, sender, 100_000);

        let tx = Transaction::new(
            sender.to_string(),
            receiver.to_string(),
            1_500,
            0,
            vec![1, 2, 3],
            2,
            10,
            None,
            "fndsa".to_string(),
        );

        manager
            .process_transaction_in_block(&tx, 77)
            .expect("native SNRG transaction should apply");

        assert_eq!(manager.get_balance(sender, "SNRG"), 21_500);
        assert_eq!(manager.get_balance(receiver, "SNRG"), 1_500);
        assert_eq!(manager.get_balance(FEE_COLLECTOR_ADDRESS, "SNRG"), 77_000);

        let history = manager.get_transfer_history(sender, 10);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].tx_hash, tx.hash());
        assert_eq!(history[0].block_height, 77);

        manager
            .process_transaction_in_block(&tx, 77)
            .expect("replaying same transaction should be idempotent");

        assert_eq!(manager.get_balance(sender, "SNRG"), 21_500);
        assert_eq!(manager.get_balance(receiver, "SNRG"), 1_500);
        assert_eq!(manager.get_balance(FEE_COLLECTOR_ADDRESS, "SNRG"), 77_000);
        assert_eq!(manager.get_transfer_history(sender, 10).len(), 1);
    }

    #[test]
    fn staking_transaction_is_not_intercepted_as_native_transfer() {
        let manager = TokenManager::new();
        let staker = crate::address::generate_wallet_address("staking-transaction-staker");
        let validator =
            crate::address::generate_validator_address("staking-transaction-validator", 1);
        seed_snrg_balance(&manager, &staker, 10_000);

        let tx = Transaction::new(
            staker.clone(),
            validator.clone(),
            3_000,
            0,
            vec![1, 2, 3],
            2,
            10,
            Some(format!(
                "stake:{{\"validator\":\"{}\",\"token\":\"SNRG\",\"amount\":3000}}",
                validator
            )),
            "fndsa".to_string(),
        );

        manager
            .process_transaction(&tx)
            .expect("staking transaction should apply as stake");

        assert_eq!(manager.get_balance(&staker, "SNRG"), 7_000);
        assert_eq!(manager.get_balance(&validator, "SNRG"), 0);
        assert_eq!(manager.get_staked_balance(&staker, "SNRG"), 3_000);
    }

    #[test]
    fn staked_balance_falls_back_to_active_stake_entries() {
        let manager = TokenManager::new();
        let staker = "synw1stakerfallback00000000000000000000";
        let validator = "synv1validatorfallback0000000000000000";

        manager.stakes.lock().unwrap().insert(
            validator.to_string(),
            vec![StakingInfo {
                validator_address: validator.to_string(),
                staker_address: staker.to_string(),
                amount: 50_000,
                stake_start: 1,
                stake_end: None,
                rewards_earned: 0,
                is_active: true,
            }],
        );

        assert_eq!(manager.get_staked_balance(staker, "SNRG"), 50_000);
        assert_eq!(manager.get_staked_balance("*", "SNRG"), 50_000);
    }
}
