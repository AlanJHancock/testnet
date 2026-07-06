use bech32::{ToBase32, Variant};
use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const STS_TESTNET_CHAIN_ID: u64 = 1_264;
pub const STS_TESTNET_NETWORK: &str = "testnet";
pub const STS_PAYLOAD_PREFIX: &[u8] = b"synergy-sts-v1:";
pub const STS_STATE_SNAPSHOT_PATH: &str = "data/sts_state.json";
pub const NATIVE_SNRG_SYMBOL: &str = "SNRG";
pub const NATIVE_SNRG_NAME: &str = "Synergy Token";
pub const NATIVE_SNRG_DECIMALS: u8 = 9;
pub const NATIVE_SNRG_PLACEHOLDER_ADDRESS: &str = "00000000000000000000000000000000000000000";
pub const STS_MAX_DECIMALS: u8 = 9;
pub const STS_MAX_TRANSFER_FEE_BPS: u16 = 1_000;
const STS_STATE_SNAPSHOT_SCHEMA_VERSION: u32 = 1;
const HEX_32_LEN: usize = 64;
const MAX_TOKEN_SYMBOL_LEN: usize = 12;
const MAX_TOKEN_NAME_LEN: usize = 64;
const MAX_STS_URI_LEN: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum TokenClass {
    B1BasicFungible = 1,
    B2ManagedFungible = 2,
    B3PolicyFungible = 3,
    NF1StandardNft = 11,
    NF2ControlledNft = 12,
    MAMultiAsset = 21,
    IDCredential = 31,
}

impl TokenClass {
    pub const fn discriminant(self) -> u8 {
        self as u8
    }

    pub const fn wire(self) -> &'static str {
        match self {
            TokenClass::B1BasicFungible => "b1",
            TokenClass::B2ManagedFungible => "b2",
            TokenClass::B3PolicyFungible => "b3",
            TokenClass::NF1StandardNft => "nf1",
            TokenClass::NF2ControlledNft => "nf2",
            TokenClass::MAMultiAsset => "ma",
            TokenClass::IDCredential => "id",
        }
    }

    pub const fn prefix(self) -> &'static str {
        match self {
            TokenClass::B1BasicFungible => "synb1",
            TokenClass::B2ManagedFungible => "synb2",
            TokenClass::B3PolicyFungible => "synb3",
            TokenClass::NF1StandardNft => "synn1",
            TokenClass::NF2ControlledNft => "synn2",
            TokenClass::MAMultiAsset => "synj",
            TokenClass::IDCredential => "synk",
        }
    }

    pub const fn is_fungible(self) -> bool {
        matches!(
            self,
            TokenClass::B1BasicFungible
                | TokenClass::B2ManagedFungible
                | TokenClass::B3PolicyFungible
        )
    }

    pub fn from_wire(value: &str) -> Result<Self, StsError> {
        match value {
            "b1" => Ok(TokenClass::B1BasicFungible),
            "b2" => Ok(TokenClass::B2ManagedFungible),
            "b3" => Ok(TokenClass::B3PolicyFungible),
            "nf1" => Ok(TokenClass::NF1StandardNft),
            "nf2" => Ok(TokenClass::NF2ControlledNft),
            "ma" => Ok(TokenClass::MAMultiAsset),
            "id" => Ok(TokenClass::IDCredential),
            _ => Err(StsError::InvalidTokenClass),
        }
    }
}

impl Serialize for TokenClass {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.wire())
    }
}

impl<'de> Deserialize<'de> for TokenClass {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TokenClassVisitor;

        impl<'de> Visitor<'de> for TokenClassVisitor {
            type Value = TokenClass;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a stable STS token class string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                TokenClass::from_wire(value).map_err(|error| E::custom(error.to_string()))
            }
        }

        deserializer.deserialize_str(TokenClassVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StsError {
    Unauthorized,
    InvalidAuthority,
    AuthorityRenounced,
    TokenPaused,
    AccountFrozen,
    ClawbackNotEnabled,
    PolicyNotEnabled,
    SupplyOverflow,
    InsufficientBalance,
    InvalidTokenClass,
    InvalidTokenId,
    InvalidMetadataHash,
    InvalidTimestamp,
    CredentialRevoked,
    CredentialExpired,
    CredentialSuspended,
    NonTransferableAsset,
    InvalidAmount,
    InvalidDecimals,
    InvalidMetadata,
    InvalidImage,
    InvalidNetwork,
    ReservedTokenIdentity,
    UnsafeTokenPractice,
    ImageAlreadySet,
}

impl fmt::Display for StsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for StsError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AuthoritySet {
    pub mint_authority: Option<String>,
    pub burn_authority: Option<String>,
    pub freeze_authority: Option<String>,
    pub metadata_authority: Option<String>,
    pub transfer_authority: Option<String>,
    pub compliance_authority: Option<String>,
    pub issuer_authority: Option<String>,
    pub upgrade_authority: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FungibleControlFlags {
    pub can_freeze: bool,
    pub can_pause: bool,
    pub can_clawback: bool,
    pub can_denylist: bool,
    pub can_allowlist: bool,
    pub can_update_metadata: bool,
    pub requires_transfer_approval: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "template", rename_all = "snake_case")]
pub enum FungiblePolicy {
    TransferFeeV1 {
        fee_bps: u16,
        recipient: String,
    },
    SnapshotV1,
    VestingV1 {
        start_at: u64,
        cliff_at: u64,
        end_at: u64,
    },
    MaxWalletV1 {
        max_balance: u128,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateFungibleParams {
    pub class: TokenClass,
    pub creator: String,
    pub creator_nonce: u64,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub initial_supply: u128,
    pub max_supply: Option<u128>,
    pub mint_authority: Option<String>,
    pub metadata_authority: Option<String>,
    pub metadata_uri: Option<String>,
    pub metadata_hash: Option<String>,
    pub metadata_mutable: bool,
    pub image_uri: Option<String>,
    pub image_hash: Option<String>,
    pub flags: FungibleControlFlags,
    pub policies: Vec<FungiblePolicy>,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeSnrgDefinition {
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    pub token_address: Option<String>,
    pub gas_asset: bool,
    pub native: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FungibleDefinition {
    pub token_id: String,
    pub token_address: String,
    pub class: TokenClass,
    pub creator: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: u128,
    pub max_supply: Option<u128>,
    pub authorities: AuthoritySet,
    pub metadata_uri: Option<String>,
    pub metadata_hash: Option<String>,
    pub metadata_mutable: bool,
    pub image_uri: Option<String>,
    pub image_hash: Option<String>,
    pub image_locked: bool,
    pub created_at: u64,
    pub updated_at: u64,
    pub flags: FungibleControlFlags,
    pub policies: Vec<FungiblePolicy>,
    pub paused: bool,
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FungibleBalance {
    pub owner: String,
    pub token_id: String,
    pub balance: u128,
    pub frozen: bool,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StsEvent {
    pub event_type: String,
    pub token_id: Option<String>,
    pub sender: String,
    pub owner: Option<String>,
    pub recipient: Option<String>,
    pub amount: Option<String>,
    pub timestamp: u64,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", content = "data", rename_all = "snake_case")]
pub enum StsTx {
    CreateFungible(CreateFungibleParams),
    MintFungible {
        token_id: String,
        to: String,
        amount: u128,
        timestamp: u64,
    },
    BurnFungible {
        token_id: String,
        from: String,
        amount: u128,
        timestamp: u64,
    },
    TransferFungible {
        token_id: String,
        from: String,
        to: String,
        amount: u128,
        timestamp: u64,
    },
    FreezeFungibleAccount {
        token_id: String,
        owner: String,
        timestamp: u64,
    },
    ThawFungibleAccount {
        token_id: String,
        owner: String,
        timestamp: u64,
    },
    PauseFungible {
        token_id: String,
        timestamp: u64,
    },
    UnpauseFungible {
        token_id: String,
        timestamp: u64,
    },
    ClawbackFungible {
        token_id: String,
        from: String,
        to: String,
        amount: u128,
        timestamp: u64,
    },
    CreateFungibleSnapshot {
        token_id: String,
        timestamp: u64,
    },
    SetFungibleImage {
        token_id: String,
        image_uri: String,
        image_hash: String,
        timestamp: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StsSignedPayload {
    pub version: u8,
    pub chain_id: u64,
    pub network: String,
    pub tx: StsTx,
}

impl StsSignedPayload {
    pub fn new(tx: StsTx) -> Self {
        Self {
            version: 1,
            chain_id: STS_TESTNET_CHAIN_ID,
            network: STS_TESTNET_NETWORK.to_string(),
            tx,
        }
    }

    pub fn require_testnet(&self) -> Result<(), StsError> {
        if self.version != 1 {
            return Err(StsError::InvalidNetwork);
        }
        if self.chain_id != STS_TESTNET_CHAIN_ID || self.network != STS_TESTNET_NETWORK {
            return Err(StsError::InvalidNetwork);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StsProcessedTransaction {
    pub block_height: u64,
    pub block_hash: String,
    pub status: String,
    pub error: Option<String>,
    pub processed_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StsStateSnapshot {
    pub schema_version: u32,
    pub chain_id: u64,
    pub network: String,
    pub latest_block_height: u64,
    pub latest_block_hash: String,
    pub updated_at: u64,
    pub state: StsState,
    #[serde(default)]
    pub processed_transactions: BTreeMap<String, StsProcessedTransaction>,
}

impl StsStateSnapshot {
    pub fn empty_at(block_height: u64, block_hash: &str) -> Self {
        Self {
            schema_version: STS_STATE_SNAPSHOT_SCHEMA_VERSION,
            chain_id: STS_TESTNET_CHAIN_ID,
            network: STS_TESTNET_NETWORK.to_string(),
            latest_block_height: block_height,
            latest_block_hash: block_hash.to_string(),
            updated_at: current_unix_timestamp_seconds(),
            state: StsState::new(),
            processed_transactions: BTreeMap::new(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != STS_STATE_SNAPSHOT_SCHEMA_VERSION {
            return Err(format!(
                "unsupported STS snapshot schema_version {}",
                self.schema_version
            ));
        }
        if self.chain_id != STS_TESTNET_CHAIN_ID || self.network != STS_TESTNET_NETWORK {
            return Err(format!(
                "STS snapshot chain/network mismatch: chain_id={} network={}",
                self.chain_id, self.network
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StsFinalizedTransactionReport {
    pub payload_present: bool,
    pub already_processed: bool,
    pub applied: bool,
    pub status: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StsState {
    pub schema_version: u32,
    pub token_registry: BTreeMap<String, FungibleDefinition>,
    pub fungible_balances: BTreeMap<String, FungibleBalance>,
    pub fungible_snapshots: BTreeMap<String, BTreeMap<String, u128>>,
    pub next_snapshot_id: u64,
    pub events: Vec<StsEvent>,
}

impl StsState {
    pub fn new() -> Self {
        Self {
            schema_version: 1,
            token_registry: BTreeMap::new(),
            fungible_balances: BTreeMap::new(),
            fungible_snapshots: BTreeMap::new(),
            next_snapshot_id: 1,
            events: Vec::new(),
        }
    }

    pub fn apply_signed_payload(
        &mut self,
        sender: &str,
        payload: &StsSignedPayload,
    ) -> Result<Vec<StsEvent>, StsError> {
        payload.require_testnet()?;
        let before = self.events.len();
        let result: Result<(), StsError> = match &payload.tx {
            StsTx::CreateFungible(params) => {
                if sender != params.creator {
                    Err(StsError::Unauthorized)
                } else {
                    self.create_fungible(params.clone()).map(|_| ())
                }
            }
            StsTx::MintFungible {
                token_id,
                to,
                amount,
                timestamp,
            } => self.mint_fungible(sender, token_id, to, *amount, *timestamp),
            StsTx::BurnFungible {
                token_id,
                from,
                amount,
                timestamp,
            } => self.burn_fungible(sender, token_id, from, *amount, *timestamp),
            StsTx::TransferFungible {
                token_id,
                from,
                to,
                amount,
                timestamp,
            } => self.transfer_fungible(sender, token_id, from, to, *amount, *timestamp),
            StsTx::FreezeFungibleAccount {
                token_id,
                owner,
                timestamp,
            } => self.set_fungible_frozen(sender, token_id, owner, true, *timestamp),
            StsTx::ThawFungibleAccount {
                token_id,
                owner,
                timestamp,
            } => self.set_fungible_frozen(sender, token_id, owner, false, *timestamp),
            StsTx::PauseFungible {
                token_id,
                timestamp,
            } => self.set_fungible_paused(sender, token_id, true, *timestamp),
            StsTx::UnpauseFungible {
                token_id,
                timestamp,
            } => self.set_fungible_paused(sender, token_id, false, *timestamp),
            StsTx::ClawbackFungible {
                token_id,
                from,
                to,
                amount,
                timestamp,
            } => self.clawback_fungible(sender, token_id, from, to, *amount, *timestamp),
            StsTx::CreateFungibleSnapshot {
                token_id,
                timestamp,
            } => self.create_fungible_snapshot(sender, token_id, *timestamp),
            StsTx::SetFungibleImage {
                token_id,
                image_uri,
                image_hash,
                timestamp,
            } => self.set_fungible_image(sender, token_id, image_uri, image_hash, *timestamp),
        };
        match result {
            Ok(()) => Ok(self.events[before..].to_vec()),
            Err(error) => {
                self.events.truncate(before);
                Err(error)
            }
        }
    }

    pub fn create_fungible(&mut self, params: CreateFungibleParams) -> Result<String, StsError> {
        validate_timestamp_seconds(params.created_at)?;
        validate_token_identity(&params.name, &params.symbol)?;
        validate_metadata(&params.metadata_uri, &params.metadata_hash)?;
        validate_token_image(&params.image_uri, &params.image_hash)?;
        if !params.class.is_fungible() {
            return Err(StsError::InvalidTokenClass);
        }
        if params.decimals > STS_MAX_DECIMALS {
            return Err(StsError::InvalidDecimals);
        }
        if params
            .max_supply
            .is_some_and(|max_supply| params.initial_supply > max_supply)
        {
            return Err(StsError::SupplyOverflow);
        }
        if params.metadata_mutable
            || params.flags.can_update_metadata
            || params.flags.can_allowlist
            || params.flags.can_denylist
            || params.flags.requires_transfer_approval
            || (params.mint_authority.is_some() && params.max_supply.is_none())
        {
            return Err(StsError::UnsafeTokenPractice);
        }
        validate_fungible_flags(params.class, &params.flags)?;
        validate_fungible_policies(params.class, &params.policies)?;
        if self
            .token_registry
            .values()
            .any(|definition| definition.symbol == params.symbol)
        {
            return Err(StsError::ReservedTokenIdentity);
        }

        let metadata_hash = params
            .metadata_hash
            .clone()
            .unwrap_or_else(|| sha3_256_hex(params.name.as_bytes()));
        let token_id = derive_fungible_token_id(
            STS_TESTNET_CHAIN_ID,
            params.class,
            &params.creator,
            params.creator_nonce,
            &metadata_hash,
            params.created_at,
        );
        if self.token_registry.contains_key(&token_id) {
            return Err(StsError::InvalidTokenId);
        }
        let token_address = sts_object_token_address(params.class, &token_id)?;

        let authorities = AuthoritySet {
            mint_authority: params.mint_authority.clone(),
            metadata_authority: params.metadata_authority.clone(),
            freeze_authority: authority_when(params.flags.can_freeze, &params.creator),
            compliance_authority: authority_when(
                params.flags.can_clawback
                    || params.flags.can_allowlist
                    || params.flags.can_denylist
                    || params.flags.can_pause,
                &params.creator,
            ),
            transfer_authority: authority_when(
                params.flags.requires_transfer_approval,
                &params.creator,
            ),
            ..AuthoritySet::default()
        };
        let definition = FungibleDefinition {
            token_id: token_id.clone(),
            token_address: token_address.clone(),
            class: params.class,
            creator: params.creator.clone(),
            name: params.name,
            symbol: params.symbol,
            decimals: params.decimals,
            total_supply: params.initial_supply,
            max_supply: params.max_supply,
            authorities,
            metadata_uri: params.metadata_uri,
            metadata_hash: Some(metadata_hash),
            metadata_mutable: params.metadata_mutable,
            image_uri: params.image_uri.clone(),
            image_hash: params.image_hash.clone(),
            image_locked: params.image_uri.is_some() || params.image_hash.is_some(),
            created_at: params.created_at,
            updated_at: params.created_at,
            flags: params.flags,
            policies: params.policies,
            paused: false,
            verified: false,
        };
        self.token_registry.insert(token_id.clone(), definition);
        if params.initial_supply > 0 {
            self.credit_balance(
                &token_id,
                &params.creator,
                params.initial_supply,
                params.created_at,
            )?;
        }
        self.push_event(StsEvent {
            event_type: "StsFungibleCreated".to_string(),
            token_id: Some(token_id.clone()),
            sender: params.creator.clone(),
            owner: Some(params.creator),
            recipient: None,
            amount: Some(params.initial_supply.to_string()),
            timestamp: params.created_at,
            attributes: BTreeMap::from([
                ("native".to_string(), "false".to_string()),
                ("token_address".to_string(), token_address),
            ]),
        });
        Ok(token_id)
    }

    pub fn set_fungible_image(
        &mut self,
        caller: &str,
        token_id: &str,
        image_uri: &str,
        image_hash: &str,
        timestamp: u64,
    ) -> Result<(), StsError> {
        validate_timestamp_seconds(timestamp)?;
        validate_sts_object_id(
            fungible_class_from_token_id(token_id).ok_or(StsError::InvalidTokenId)?,
            token_id,
        )?;
        validate_token_image(&Some(image_uri.to_string()), &Some(image_hash.to_string()))?;
        let creator = {
            let definition = self
                .token_registry
                .get_mut(token_id)
                .ok_or(StsError::InvalidTokenId)?;
            if caller != definition.creator {
                return Err(StsError::Unauthorized);
            }
            if definition.image_locked
                || definition.image_uri.is_some()
                || definition.image_hash.is_some()
            {
                return Err(StsError::ImageAlreadySet);
            }
            definition.image_uri = Some(image_uri.to_string());
            definition.image_hash = Some(image_hash.to_string());
            definition.image_locked = true;
            definition.updated_at = timestamp;
            definition.creator.clone()
        };
        self.push_event(StsEvent {
            event_type: "StsFungibleImageSet".to_string(),
            token_id: Some(token_id.to_string()),
            sender: caller.to_string(),
            owner: Some(creator),
            recipient: None,
            amount: None,
            timestamp,
            attributes: BTreeMap::from([
                ("image_uri".to_string(), image_uri.to_string()),
                ("image_hash".to_string(), image_hash.to_string()),
            ]),
        });
        Ok(())
    }

    pub fn mint_fungible(
        &mut self,
        caller: &str,
        token_id: &str,
        to: &str,
        amount: u128,
        timestamp: u64,
    ) -> Result<(), StsError> {
        validate_amount(amount)?;
        validate_timestamp_seconds(timestamp)?;
        self.require_mint_authority(caller, token_id)?;
        self.require_not_paused(token_id)?;
        let definition = self
            .token_registry
            .get(token_id)
            .cloned()
            .ok_or(StsError::InvalidTokenId)?;
        let new_supply = definition
            .total_supply
            .checked_add(amount)
            .ok_or(StsError::SupplyOverflow)?;
        if definition
            .max_supply
            .is_some_and(|max_supply| new_supply > max_supply)
        {
            return Err(StsError::SupplyOverflow);
        }
        self.require_max_wallet(&definition, to, amount)?;
        self.credit_balance(token_id, to, amount, timestamp)?;
        let definition = self
            .token_registry
            .get_mut(token_id)
            .ok_or(StsError::InvalidTokenId)?;
        definition.total_supply = new_supply;
        definition.updated_at = timestamp;
        self.push_event(simple_amount_event(
            "StsFungibleMinted",
            token_id,
            caller,
            None,
            Some(to),
            amount,
            timestamp,
        ));
        Ok(())
    }

    pub fn burn_fungible(
        &mut self,
        caller: &str,
        token_id: &str,
        from: &str,
        amount: u128,
        timestamp: u64,
    ) -> Result<(), StsError> {
        validate_amount(amount)?;
        validate_timestamp_seconds(timestamp)?;
        if caller != from {
            return Err(StsError::Unauthorized);
        }
        self.require_not_paused(token_id)?;
        self.debit_balance(token_id, from, amount, timestamp)?;
        let definition = self
            .token_registry
            .get_mut(token_id)
            .ok_or(StsError::InvalidTokenId)?;
        definition.total_supply = definition
            .total_supply
            .checked_sub(amount)
            .ok_or(StsError::SupplyOverflow)?;
        definition.updated_at = timestamp;
        self.push_event(simple_amount_event(
            "StsFungibleBurned",
            token_id,
            caller,
            Some(from),
            None,
            amount,
            timestamp,
        ));
        Ok(())
    }

    pub fn transfer_fungible(
        &mut self,
        caller: &str,
        token_id: &str,
        from: &str,
        to: &str,
        amount: u128,
        timestamp: u64,
    ) -> Result<(), StsError> {
        validate_amount(amount)?;
        validate_timestamp_seconds(timestamp)?;
        if caller != from {
            return Err(StsError::Unauthorized);
        }
        self.require_not_paused(token_id)?;
        let definition = self
            .token_registry
            .get(token_id)
            .cloned()
            .ok_or(StsError::InvalidTokenId)?;
        self.require_account_not_frozen(token_id, from)?;
        let fee = transfer_fee(&definition, amount)?;
        let net_amount = amount.checked_sub(fee).ok_or(StsError::SupplyOverflow)?;
        self.require_max_wallet(&definition, to, net_amount)?;
        self.debit_balance(token_id, from, amount, timestamp)?;
        self.credit_balance(token_id, to, net_amount, timestamp)?;
        let mut attributes = BTreeMap::new();
        if fee > 0 {
            let fee_recipient =
                transfer_fee_recipient(&definition).ok_or(StsError::PolicyNotEnabled)?;
            self.credit_balance(token_id, fee_recipient, fee, timestamp)?;
            attributes.insert("fee_amount".to_string(), fee.to_string());
            attributes.insert("fee_recipient".to_string(), fee_recipient.to_string());
        }
        self.push_event(StsEvent {
            event_type: "StsFungibleTransferred".to_string(),
            token_id: Some(token_id.to_string()),
            sender: caller.to_string(),
            owner: Some(from.to_string()),
            recipient: Some(to.to_string()),
            amount: Some(amount.to_string()),
            timestamp,
            attributes,
        });
        Ok(())
    }

    pub fn set_fungible_frozen(
        &mut self,
        caller: &str,
        token_id: &str,
        owner: &str,
        frozen: bool,
        timestamp: u64,
    ) -> Result<(), StsError> {
        validate_timestamp_seconds(timestamp)?;
        let definition = self
            .token_registry
            .get(token_id)
            .ok_or(StsError::InvalidTokenId)?;
        if definition.class != TokenClass::B2ManagedFungible || !definition.flags.can_freeze {
            return Err(StsError::PolicyNotEnabled);
        }
        require_authority(caller, &definition.authorities.freeze_authority)?;
        let key = balance_key(token_id, owner);
        let balance = self
            .fungible_balances
            .entry(key)
            .or_insert_with(|| FungibleBalance {
                owner: owner.to_string(),
                token_id: token_id.to_string(),
                balance: 0,
                frozen: false,
                created_at: timestamp,
                updated_at: timestamp,
            });
        balance.frozen = frozen;
        balance.updated_at = timestamp;
        self.push_event(StsEvent {
            event_type: if frozen {
                "StsFungibleAccountFrozen"
            } else {
                "StsFungibleAccountThawed"
            }
            .to_string(),
            token_id: Some(token_id.to_string()),
            sender: caller.to_string(),
            owner: Some(owner.to_string()),
            recipient: None,
            amount: None,
            timestamp,
            attributes: BTreeMap::new(),
        });
        Ok(())
    }

    pub fn set_fungible_paused(
        &mut self,
        caller: &str,
        token_id: &str,
        paused: bool,
        timestamp: u64,
    ) -> Result<(), StsError> {
        validate_timestamp_seconds(timestamp)?;
        let definition = self
            .token_registry
            .get_mut(token_id)
            .ok_or(StsError::InvalidTokenId)?;
        if definition.class != TokenClass::B2ManagedFungible || !definition.flags.can_pause {
            return Err(StsError::PolicyNotEnabled);
        }
        require_authority(caller, &definition.authorities.compliance_authority)?;
        definition.paused = paused;
        definition.updated_at = timestamp;
        self.push_event(StsEvent {
            event_type: if paused {
                "StsFungiblePaused"
            } else {
                "StsFungibleUnpaused"
            }
            .to_string(),
            token_id: Some(token_id.to_string()),
            sender: caller.to_string(),
            owner: None,
            recipient: None,
            amount: None,
            timestamp,
            attributes: BTreeMap::new(),
        });
        Ok(())
    }

    pub fn clawback_fungible(
        &mut self,
        caller: &str,
        token_id: &str,
        from: &str,
        to: &str,
        amount: u128,
        timestamp: u64,
    ) -> Result<(), StsError> {
        validate_amount(amount)?;
        validate_timestamp_seconds(timestamp)?;
        let definition = self
            .token_registry
            .get(token_id)
            .ok_or(StsError::InvalidTokenId)?;
        if definition.class != TokenClass::B2ManagedFungible || !definition.flags.can_clawback {
            return Err(StsError::ClawbackNotEnabled);
        }
        require_authority(caller, &definition.authorities.compliance_authority)?;
        self.debit_balance_for_clawback(token_id, from, amount, timestamp)?;
        self.credit_balance(token_id, to, amount, timestamp)?;
        self.push_event(simple_amount_event(
            "StsFungibleClawedBack",
            token_id,
            caller,
            Some(from),
            Some(to),
            amount,
            timestamp,
        ));
        Ok(())
    }

    pub fn create_fungible_snapshot(
        &mut self,
        caller: &str,
        token_id: &str,
        timestamp: u64,
    ) -> Result<(), StsError> {
        validate_timestamp_seconds(timestamp)?;
        let definition = self
            .token_registry
            .get(token_id)
            .ok_or(StsError::InvalidTokenId)?;
        if definition.class != TokenClass::B3PolicyFungible || !has_snapshot_policy(definition) {
            return Err(StsError::PolicyNotEnabled);
        }
        if caller != definition.creator {
            require_authority(caller, &definition.authorities.mint_authority)?;
        }
        let snapshot_id = self.next_snapshot_id;
        self.next_snapshot_id = self
            .next_snapshot_id
            .checked_add(1)
            .ok_or(StsError::SupplyOverflow)?;
        let balances = self
            .fungible_balances
            .values()
            .filter(|balance| balance.token_id == token_id)
            .map(|balance| (balance.owner.clone(), balance.balance))
            .collect::<BTreeMap<_, _>>();
        self.fungible_snapshots
            .insert(snapshot_key(token_id, snapshot_id), balances);
        let mut attributes = BTreeMap::new();
        attributes.insert("snapshot_id".to_string(), snapshot_id.to_string());
        self.push_event(StsEvent {
            event_type: "StsFungibleSnapshotCreated".to_string(),
            token_id: Some(token_id.to_string()),
            sender: caller.to_string(),
            owner: None,
            recipient: None,
            amount: None,
            timestamp,
            attributes,
        });
        Ok(())
    }

    pub fn fungible_balance(&self, owner: &str, token_id: &str) -> u128 {
        self.fungible_balances
            .get(&balance_key(token_id, owner))
            .map(|balance| balance.balance)
            .unwrap_or(0)
    }

    pub fn fungible_definitions(&self) -> Vec<&FungibleDefinition> {
        self.token_registry.values().collect()
    }

    pub fn fungible_definition(&self, token_ref: &str) -> Option<&FungibleDefinition> {
        let token_ref = token_ref.trim();
        self.token_registry.get(token_ref).or_else(|| {
            self.token_registry
                .values()
                .find(|definition| definition.token_address == token_ref)
        })
    }

    pub fn fungible_balance_entry(&self, owner: &str, token_ref: &str) -> Option<&FungibleBalance> {
        let definition = self.fungible_definition(token_ref)?;
        self.fungible_balances
            .get(&balance_key(&definition.token_id, owner))
    }

    pub fn fungible_balances_for_owner(&self, owner: &str) -> Vec<&FungibleBalance> {
        self.fungible_balances
            .values()
            .filter(|balance| balance.owner == owner)
            .collect()
    }

    pub fn fungible_balances_for_token(&self, token_ref: &str) -> Vec<&FungibleBalance> {
        let Some(definition) = self.fungible_definition(token_ref) else {
            return Vec::new();
        };
        self.fungible_balances
            .values()
            .filter(|balance| balance.token_id == definition.token_id)
            .collect()
    }

    pub fn events_for(
        &self,
        token_ref: Option<&str>,
        owner: Option<&str>,
        limit: usize,
    ) -> Vec<&StsEvent> {
        let token_id = match token_ref {
            Some(token_ref) => match self.fungible_definition(token_ref) {
                Some(definition) => Some(definition.token_id.as_str()),
                None => return Vec::new(),
            },
            None => None,
        };
        let mut events = self
            .events
            .iter()
            .filter(|event| {
                token_id
                    .map(|token_id| event.token_id.as_deref() == Some(token_id))
                    .unwrap_or(true)
            })
            .filter(|event| {
                owner
                    .map(|owner| {
                        event.owner.as_deref() == Some(owner)
                            || event.recipient.as_deref() == Some(owner)
                            || event.sender == owner
                    })
                    .unwrap_or(true)
            })
            .collect::<Vec<_>>();
        events.reverse();
        if limit > 0 && events.len() > limit {
            events.truncate(limit);
        }
        events
    }

    fn credit_balance(
        &mut self,
        token_id: &str,
        owner: &str,
        amount: u128,
        timestamp: u64,
    ) -> Result<(), StsError> {
        let key = balance_key(token_id, owner);
        let balance = self
            .fungible_balances
            .entry(key)
            .or_insert_with(|| FungibleBalance {
                owner: owner.to_string(),
                token_id: token_id.to_string(),
                balance: 0,
                frozen: false,
                created_at: timestamp,
                updated_at: timestamp,
            });
        balance.balance = balance
            .balance
            .checked_add(amount)
            .ok_or(StsError::SupplyOverflow)?;
        balance.updated_at = timestamp;
        Ok(())
    }

    fn debit_balance(
        &mut self,
        token_id: &str,
        owner: &str,
        amount: u128,
        timestamp: u64,
    ) -> Result<(), StsError> {
        let key = balance_key(token_id, owner);
        let balance = self
            .fungible_balances
            .get_mut(&key)
            .ok_or(StsError::InsufficientBalance)?;
        if balance.frozen {
            return Err(StsError::AccountFrozen);
        }
        balance.balance = balance
            .balance
            .checked_sub(amount)
            .ok_or(StsError::InsufficientBalance)?;
        balance.updated_at = timestamp;
        Ok(())
    }

    fn debit_balance_for_clawback(
        &mut self,
        token_id: &str,
        owner: &str,
        amount: u128,
        timestamp: u64,
    ) -> Result<(), StsError> {
        let key = balance_key(token_id, owner);
        let balance = self
            .fungible_balances
            .get_mut(&key)
            .ok_or(StsError::InsufficientBalance)?;
        balance.balance = balance
            .balance
            .checked_sub(amount)
            .ok_or(StsError::InsufficientBalance)?;
        balance.updated_at = timestamp;
        Ok(())
    }

    fn require_mint_authority(&self, caller: &str, token_id: &str) -> Result<(), StsError> {
        let definition = self
            .token_registry
            .get(token_id)
            .ok_or(StsError::InvalidTokenId)?;
        require_authority(caller, &definition.authorities.mint_authority)
    }

    fn require_not_paused(&self, token_id: &str) -> Result<(), StsError> {
        let definition = self
            .token_registry
            .get(token_id)
            .ok_or(StsError::InvalidTokenId)?;
        if definition.paused {
            return Err(StsError::TokenPaused);
        }
        Ok(())
    }

    fn require_account_not_frozen(&self, token_id: &str, owner: &str) -> Result<(), StsError> {
        let frozen = self
            .fungible_balances
            .get(&balance_key(token_id, owner))
            .map(|balance| balance.frozen)
            .unwrap_or(false);
        if frozen {
            Err(StsError::AccountFrozen)
        } else {
            Ok(())
        }
    }

    fn require_max_wallet(
        &self,
        definition: &FungibleDefinition,
        owner: &str,
        incoming_amount: u128,
    ) -> Result<(), StsError> {
        let Some(max_balance) = max_wallet_limit(definition) else {
            return Ok(());
        };
        let current = self.fungible_balance(owner, &definition.token_id);
        let next = current
            .checked_add(incoming_amount)
            .ok_or(StsError::SupplyOverflow)?;
        if next > max_balance {
            return Err(StsError::PolicyNotEnabled);
        }
        Ok(())
    }

    fn push_event(&mut self, event: StsEvent) {
        self.events.push(event);
    }
}

pub fn encode_sts_payload(payload: &StsSignedPayload) -> Result<Vec<u8>, StsError> {
    let json = serde_json::to_vec(payload).map_err(|_| StsError::InvalidMetadata)?;
    let mut bytes = Vec::with_capacity(STS_PAYLOAD_PREFIX.len() + json.len());
    bytes.extend_from_slice(STS_PAYLOAD_PREFIX);
    bytes.extend_from_slice(&json);
    Ok(bytes)
}

pub fn decode_sts_payload(bytes: &[u8]) -> Result<Option<StsSignedPayload>, StsError> {
    if !bytes.starts_with(STS_PAYLOAD_PREFIX) {
        return Ok(None);
    }
    serde_json::from_slice(&bytes[STS_PAYLOAD_PREFIX.len()..])
        .map(Some)
        .map_err(|_| StsError::InvalidMetadata)
}

pub fn transaction_data_may_contain_sts_payload(data: &str) -> bool {
    let trimmed = data.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.starts_with(std::str::from_utf8(STS_PAYLOAD_PREFIX).unwrap_or("")) {
        return true;
    }

    let normalized_hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let sts_prefix_hex = hex::encode(STS_PAYLOAD_PREFIX);
    if normalized_hex
        .to_ascii_lowercase()
        .starts_with(&sts_prefix_hex)
    {
        return true;
    }

    serde_json::from_str::<Value>(trimmed)
        .map(|value| {
            looks_like_sts_signed_payload(&value)
                || value.get("payload_hex").is_some()
                || value.get("payloadHex").is_some()
                || value.get("payload").is_some_and(|payload| {
                    looks_like_sts_signed_payload(payload)
                        || payload
                            .as_str()
                            .is_some_and(transaction_data_may_contain_sts_payload)
                })
        })
        .unwrap_or(false)
}

pub fn extract_sts_payload_from_transaction_data(
    data: &str,
) -> Result<Option<StsSignedPayload>, String> {
    let trimmed = data.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.starts_with(std::str::from_utf8(STS_PAYLOAD_PREFIX).unwrap_or("")) {
        return decode_sts_payload(trimmed.as_bytes()).map_err(|error| error.to_string());
    }

    let normalized_hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let sts_prefix_hex = hex::encode(STS_PAYLOAD_PREFIX);
    if normalized_hex
        .to_ascii_lowercase()
        .starts_with(&sts_prefix_hex)
    {
        let bytes = hex::decode(normalized_hex).map_err(|error| error.to_string())?;
        return decode_sts_payload(&bytes).map_err(|error| error.to_string());
    }

    let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
        return Ok(None);
    };
    extract_sts_payload_from_json_value(&value)
}

pub fn extract_sts_payload_from_json_value(
    value: &Value,
) -> Result<Option<StsSignedPayload>, String> {
    if looks_like_sts_signed_payload(value) {
        return serde_json::from_value::<StsSignedPayload>(value.clone())
            .map(Some)
            .map_err(|error| error.to_string());
    }
    if let Some(payload_hex) = value
        .get("payload_hex")
        .or_else(|| value.get("payloadHex"))
        .and_then(Value::as_str)
    {
        return extract_sts_payload_from_transaction_data(payload_hex);
    }
    if let Some(payload) = value.get("payload") {
        if looks_like_sts_signed_payload(payload) {
            return serde_json::from_value::<StsSignedPayload>(payload.clone())
                .map(Some)
                .map_err(|error| error.to_string());
        }
        if let Some(payload_text) = payload.as_str() {
            return extract_sts_payload_from_transaction_data(payload_text);
        }
    }
    Ok(None)
}

fn looks_like_sts_signed_payload(value: &Value) -> bool {
    value.get("version").is_some() && value.get("chain_id").is_some() && value.get("tx").is_some()
}

pub fn sts_state_snapshot_path() -> PathBuf {
    crate::utils::resolve_data_path(STS_STATE_SNAPSHOT_PATH)
}

pub fn load_sts_state_snapshot() -> Result<Option<StsStateSnapshot>, String> {
    load_sts_state_snapshot_from_path(sts_state_snapshot_path())
}

pub fn load_sts_state_snapshot_from_path(
    path: impl AsRef<Path>,
) -> Result<Option<StsStateSnapshot>, String> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path)
        .map_err(|error| format!("read STS snapshot {}: {error}", path.display()))?;
    let snapshot: StsStateSnapshot = serde_json::from_str(&content)
        .map_err(|error| format!("parse STS snapshot {}: {error}", path.display()))?;
    snapshot.validate()?;
    Ok(Some(snapshot))
}

pub fn save_sts_state_snapshot(snapshot: &StsStateSnapshot) -> Result<(), String> {
    save_sts_state_snapshot_to_path(sts_state_snapshot_path(), snapshot)
}

pub fn save_sts_state_snapshot_to_path(
    path: impl AsRef<Path>,
    snapshot: &StsStateSnapshot,
) -> Result<(), String> {
    snapshot.validate()?;
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create STS snapshot dir {}: {error}", parent.display()))?;
    }
    let tmp_path = path.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(snapshot)
        .map_err(|error| format!("serialize STS snapshot: {error}"))?;
    std::fs::write(&tmp_path, json)
        .map_err(|error| format!("write STS snapshot temp {}: {error}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, path).map_err(|error| {
        format!(
            "replace STS snapshot {} with {}: {error}",
            path.display(),
            tmp_path.display()
        )
    })
}

pub fn finalized_sts_transaction_processed(tx_hash: &str) -> Result<bool, String> {
    finalized_sts_transaction_processed_at_path(sts_state_snapshot_path(), tx_hash)
}

pub fn finalized_sts_transaction_processed_at_path(
    path: impl AsRef<Path>,
    tx_hash: &str,
) -> Result<bool, String> {
    Ok(load_sts_state_snapshot_from_path(path)?
        .map(|snapshot| snapshot.processed_transactions.contains_key(tx_hash))
        .unwrap_or(false))
}

pub fn process_finalized_sts_transaction_data(
    sender: &str,
    data: &str,
    tx_hash: &str,
    block_height: u64,
    block_hash: &str,
) -> Result<StsFinalizedTransactionReport, String> {
    process_finalized_sts_transaction_data_at_path(
        sts_state_snapshot_path(),
        sender,
        data,
        tx_hash,
        block_height,
        block_hash,
    )
}

pub fn process_finalized_sts_transaction_data_at_path(
    path: impl AsRef<Path>,
    sender: &str,
    data: &str,
    tx_hash: &str,
    block_height: u64,
    block_hash: &str,
) -> Result<StsFinalizedTransactionReport, String> {
    let path = path.as_ref();
    let Some(payload) = extract_sts_payload_from_transaction_data(data)? else {
        return Ok(StsFinalizedTransactionReport {
            payload_present: false,
            already_processed: false,
            applied: false,
            status: "not_sts".to_string(),
            error: None,
        });
    };

    let mut snapshot = load_sts_state_snapshot_from_path(path)?
        .unwrap_or_else(|| StsStateSnapshot::empty_at(block_height.saturating_sub(1), ""));
    snapshot.validate()?;
    if snapshot.processed_transactions.contains_key(tx_hash) {
        return Ok(StsFinalizedTransactionReport {
            payload_present: true,
            already_processed: true,
            applied: false,
            status: "already_processed".to_string(),
            error: None,
        });
    }
    if block_height < snapshot.latest_block_height {
        return Err(format!(
            "STS snapshot already advanced to h{}; refusing to apply unseen historical tx {} at h{}",
            snapshot.latest_block_height, tx_hash, block_height
        ));
    }
    if block_height == snapshot.latest_block_height
        && !snapshot.latest_block_hash.is_empty()
        && !block_hash.is_empty()
        && snapshot.latest_block_hash != block_hash
    {
        return Err(format!(
            "STS snapshot h{} hash mismatch: snapshot={} incoming={}",
            block_height, snapshot.latest_block_hash, block_hash
        ));
    }

    let mut candidate = snapshot.state.clone();
    let apply_result = candidate.apply_signed_payload(sender, &payload);
    let processed_at = current_unix_timestamp_seconds();
    let (applied, status, error) = match apply_result {
        Ok(_) => {
            snapshot.state = candidate;
            (true, "applied".to_string(), None)
        }
        Err(error) => (false, "failed".to_string(), Some(error.to_string())),
    };

    snapshot.latest_block_height = block_height;
    if !block_hash.is_empty() {
        snapshot.latest_block_hash = block_hash.to_string();
    }
    snapshot.updated_at = processed_at;
    snapshot.processed_transactions.insert(
        tx_hash.to_string(),
        StsProcessedTransaction {
            block_height,
            block_hash: block_hash.to_string(),
            status: status.clone(),
            error: error.clone(),
            processed_at,
        },
    );
    save_sts_state_snapshot_to_path(path, &snapshot)?;

    Ok(StsFinalizedTransactionReport {
        payload_present: true,
        already_processed: false,
        applied,
        status,
        error,
    })
}

pub fn note_finalized_sts_block(block_height: u64, block_hash: &str) -> Result<bool, String> {
    note_finalized_sts_block_at_path(sts_state_snapshot_path(), block_height, block_hash)
}

pub fn note_finalized_sts_block_at_path(
    path: impl AsRef<Path>,
    block_height: u64,
    block_hash: &str,
) -> Result<bool, String> {
    let path = path.as_ref();
    let mut snapshot = load_sts_state_snapshot_from_path(path)?
        .unwrap_or_else(|| StsStateSnapshot::empty_at(block_height.saturating_sub(1), ""));
    snapshot.validate()?;
    if block_height < snapshot.latest_block_height {
        return Ok(false);
    }
    if block_height == snapshot.latest_block_height {
        if snapshot.latest_block_hash.is_empty() && !block_hash.is_empty() {
            snapshot.latest_block_hash = block_hash.to_string();
            snapshot.updated_at = current_unix_timestamp_seconds();
            save_sts_state_snapshot_to_path(path, &snapshot)?;
            return Ok(true);
        }
        if !block_hash.is_empty()
            && !snapshot.latest_block_hash.is_empty()
            && snapshot.latest_block_hash != block_hash
        {
            return Err(format!(
                "STS snapshot h{} hash mismatch: snapshot={} incoming={}",
                block_height, snapshot.latest_block_hash, block_hash
            ));
        }
        return Ok(false);
    }
    snapshot.latest_block_height = block_height;
    snapshot.latest_block_hash = block_hash.to_string();
    snapshot.updated_at = current_unix_timestamp_seconds();
    save_sts_state_snapshot_to_path(path, &snapshot)?;
    Ok(true)
}

pub fn derive_fungible_token_id(
    chain_id: u64,
    token_class: TokenClass,
    creator_address: &str,
    creator_nonce: u64,
    metadata_hash: &str,
    created_at: u64,
) -> String {
    let hash = sts_hash(
        "synergy-sts-token-v1",
        &[
            &chain_id.to_be_bytes(),
            &[token_class.discriminant()],
            creator_address.as_bytes(),
            &creator_nonce.to_be_bytes(),
            metadata_hash.as_bytes(),
            &created_at.to_be_bytes(),
        ],
    );
    encode_object_id(token_class.prefix(), &hash)
}

pub fn native_snrg_definition() -> NativeSnrgDefinition {
    NativeSnrgDefinition {
        symbol: NATIVE_SNRG_SYMBOL.to_string(),
        name: NATIVE_SNRG_NAME.to_string(),
        decimals: NATIVE_SNRG_DECIMALS,
        token_address: None,
        gas_asset: true,
        native: true,
    }
}

pub fn native_snrg_token_address() -> Option<String> {
    None
}

pub fn sts_object_token_address(
    token_class: TokenClass,
    object_id: &str,
) -> Result<String, StsError> {
    validate_sts_object_id(token_class, object_id)?;
    Ok(object_id.to_string())
}

pub fn validate_sts_object_id(token_class: TokenClass, object_id: &str) -> Result<(), StsError> {
    if object_id.trim().is_empty() {
        return Err(StsError::InvalidTokenId);
    }
    match bech32::decode(object_id) {
        Ok((hrp, _, Variant::Bech32m)) if hrp == token_class.prefix() => Ok(()),
        _ => Err(StsError::InvalidTokenId),
    }
}

pub fn derive_nft_collection_id(
    chain_id: u64,
    token_class: TokenClass,
    creator_address: &str,
    creator_nonce: u64,
    metadata_hash: &str,
    created_at: u64,
) -> Result<String, StsError> {
    if !matches!(
        token_class,
        TokenClass::NF1StandardNft | TokenClass::NF2ControlledNft
    ) {
        return Err(StsError::InvalidTokenClass);
    }
    let hash = sts_hash(
        "synergy-sts-nft-collection-v1",
        &[
            &chain_id.to_be_bytes(),
            &[token_class.discriminant()],
            creator_address.as_bytes(),
            &creator_nonce.to_be_bytes(),
            metadata_hash.as_bytes(),
            &created_at.to_be_bytes(),
        ],
    );
    Ok(encode_object_id(token_class.prefix(), &hash))
}

pub fn derive_nft_instance_id(
    chain_id: u64,
    collection_class: TokenClass,
    collection_id: &str,
    serial_number: u64,
    metadata_hash: &str,
    minted_at: u64,
) -> Result<String, StsError> {
    if !matches!(
        collection_class,
        TokenClass::NF1StandardNft | TokenClass::NF2ControlledNft
    ) {
        return Err(StsError::InvalidTokenClass);
    }
    let hash = sts_hash(
        "synergy-sts-nft-instance-v1",
        &[
            &chain_id.to_be_bytes(),
            collection_id.as_bytes(),
            &serial_number.to_be_bytes(),
            metadata_hash.as_bytes(),
            &minted_at.to_be_bytes(),
        ],
    );
    Ok(encode_object_id(collection_class.prefix(), &hash))
}

pub fn derive_multi_asset_collection_id(
    chain_id: u64,
    creator_address: &str,
    creator_nonce: u64,
    metadata_hash: &str,
    created_at: u64,
) -> String {
    let hash = sts_hash(
        "synergy-sts-multi-asset-v1",
        &[
            &chain_id.to_be_bytes(),
            creator_address.as_bytes(),
            &creator_nonce.to_be_bytes(),
            metadata_hash.as_bytes(),
            &created_at.to_be_bytes(),
        ],
    );
    encode_object_id(TokenClass::MAMultiAsset.prefix(), &hash)
}

pub fn derive_credential_id(
    chain_id: u64,
    issuer_address: &str,
    subject_address: &str,
    issuer_nonce: u64,
    metadata_hash: &str,
    issued_at: u64,
) -> String {
    let hash = sts_hash(
        "synergy-sts-credential-v1",
        &[
            &chain_id.to_be_bytes(),
            issuer_address.as_bytes(),
            subject_address.as_bytes(),
            &issuer_nonce.to_be_bytes(),
            metadata_hash.as_bytes(),
            &issued_at.to_be_bytes(),
        ],
    );
    encode_object_id(TokenClass::IDCredential.prefix(), &hash)
}

pub fn estimate_sts_gas(tx: &StsTx) -> u64 {
    match tx {
        StsTx::CreateFungible(_) => 125_000,
        StsTx::MintFungible { .. } => 60_000,
        StsTx::BurnFungible { .. } => 55_000,
        StsTx::TransferFungible { .. } => 45_000,
        StsTx::FreezeFungibleAccount { .. } | StsTx::ThawFungibleAccount { .. } => 40_000,
        StsTx::PauseFungible { .. } | StsTx::UnpauseFungible { .. } => 35_000,
        StsTx::ClawbackFungible { .. } => 70_000,
        StsTx::CreateFungibleSnapshot { .. } => 95_000,
        StsTx::SetFungibleImage { .. } => 35_000,
    }
}

fn validate_fungible_flags(
    token_class: TokenClass,
    flags: &FungibleControlFlags,
) -> Result<(), StsError> {
    match token_class {
        TokenClass::B1BasicFungible if *flags != FungibleControlFlags::default() => {
            Err(StsError::PolicyNotEnabled)
        }
        TokenClass::B3PolicyFungible
            if flags.can_clawback || flags.can_freeze || flags.can_pause =>
        {
            Err(StsError::PolicyNotEnabled)
        }
        _ => Ok(()),
    }
}

fn validate_fungible_policies(
    token_class: TokenClass,
    policies: &[FungiblePolicy],
) -> Result<(), StsError> {
    if token_class != TokenClass::B3PolicyFungible && !policies.is_empty() {
        return Err(StsError::PolicyNotEnabled);
    }
    for policy in policies {
        match policy {
            FungiblePolicy::TransferFeeV1 { fee_bps, recipient } => {
                if *fee_bps > STS_MAX_TRANSFER_FEE_BPS || recipient.trim().is_empty() {
                    return Err(StsError::PolicyNotEnabled);
                }
            }
            FungiblePolicy::SnapshotV1 => {}
            FungiblePolicy::VestingV1 {
                start_at,
                cliff_at,
                end_at,
            } => {
                validate_timestamp_seconds(*start_at)?;
                validate_timestamp_seconds(*cliff_at)?;
                validate_timestamp_seconds(*end_at)?;
                if start_at > cliff_at || cliff_at > end_at {
                    return Err(StsError::InvalidTimestamp);
                }
            }
            FungiblePolicy::MaxWalletV1 { max_balance } => {
                if *max_balance == 0 {
                    return Err(StsError::PolicyNotEnabled);
                }
            }
        }
    }
    Ok(())
}

fn validate_metadata(uri: &Option<String>, hash: &Option<String>) -> Result<(), StsError> {
    validate_metadata_hash_option(hash.as_deref())?;
    if let Some(uri) = uri {
        if !valid_external_uri(uri) {
            return Err(StsError::InvalidMetadata);
        }
    }
    Ok(())
}

fn validate_token_image(uri: &Option<String>, hash: &Option<String>) -> Result<(), StsError> {
    match (uri.as_deref(), hash.as_deref()) {
        (None, None) => Ok(()),
        (Some(uri), Some(hash)) => {
            if !valid_external_uri(uri) || uri.to_ascii_lowercase().contains(".svg") {
                return Err(StsError::InvalidImage);
            }
            validate_metadata_hash(hash).map_err(|_| StsError::InvalidImage)
        }
        _ => Err(StsError::InvalidImage),
    }
}

fn valid_external_uri(uri: &str) -> bool {
    let allowed =
        uri.starts_with("ipfs://") || uri.starts_with("ar://") || uri.starts_with("https://");
    allowed
        && uri.len() <= MAX_STS_URI_LEN
        && !uri
            .chars()
            .any(|ch| ch.is_ascii_control() || ch.is_ascii_whitespace() || ch == '\\')
}

fn validate_token_identity(name: &str, symbol: &str) -> Result<(), StsError> {
    let name = name.trim();
    let symbol = symbol.trim();
    if name.is_empty()
        || name.len() > MAX_TOKEN_NAME_LEN
        || !name.is_ascii()
        || symbol.len() < 2
        || symbol.len() > MAX_TOKEN_SYMBOL_LEN
        || !symbol.is_ascii()
        || !symbol
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit())
        || !symbol
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_uppercase())
    {
        return Err(StsError::InvalidMetadata);
    }

    let upper_name = name.to_ascii_uppercase();
    if symbol.contains(NATIVE_SNRG_SYMBOL)
        || upper_name.contains(NATIVE_SNRG_SYMBOL)
        || upper_name.contains("SYNERGY")
    {
        return Err(StsError::ReservedTokenIdentity);
    }
    Ok(())
}

fn fungible_class_from_token_id(token_id: &str) -> Option<TokenClass> {
    if token_id.starts_with(TokenClass::B1BasicFungible.prefix()) {
        Some(TokenClass::B1BasicFungible)
    } else if token_id.starts_with(TokenClass::B2ManagedFungible.prefix()) {
        Some(TokenClass::B2ManagedFungible)
    } else if token_id.starts_with(TokenClass::B3PolicyFungible.prefix()) {
        Some(TokenClass::B3PolicyFungible)
    } else {
        None
    }
}

fn validate_metadata_hash_option(hash: Option<&str>) -> Result<(), StsError> {
    if let Some(hash) = hash {
        validate_metadata_hash(hash)?;
    }
    Ok(())
}

fn validate_metadata_hash(hash: &str) -> Result<(), StsError> {
    if hash.len() != HEX_32_LEN || hash.starts_with("0x") {
        return Err(StsError::InvalidMetadataHash);
    }
    if !hash
        .chars()
        .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    {
        return Err(StsError::InvalidMetadataHash);
    }
    Ok(())
}

fn validate_timestamp_seconds(timestamp: u64) -> Result<(), StsError> {
    if timestamp > 9_999_999_999 {
        return Err(StsError::InvalidTimestamp);
    }
    Ok(())
}

fn validate_amount(amount: u128) -> Result<(), StsError> {
    if amount == 0 {
        return Err(StsError::InvalidAmount);
    }
    Ok(())
}

fn require_authority(caller: &str, authority: &Option<String>) -> Result<(), StsError> {
    match authority {
        Some(authority) if authority == caller => Ok(()),
        Some(_) => Err(StsError::Unauthorized),
        None => Err(StsError::AuthorityRenounced),
    }
}

fn authority_when(enabled: bool, creator: &str) -> Option<String> {
    enabled.then(|| creator.to_string())
}

fn transfer_fee(definition: &FungibleDefinition, amount: u128) -> Result<u128, StsError> {
    let Some(FungiblePolicy::TransferFeeV1 { fee_bps, .. }) = definition
        .policies
        .iter()
        .find(|policy| matches!(policy, FungiblePolicy::TransferFeeV1 { .. }))
    else {
        return Ok(0);
    };
    amount
        .checked_mul(*fee_bps as u128)
        .and_then(|value| value.checked_div(10_000))
        .ok_or(StsError::SupplyOverflow)
}

fn transfer_fee_recipient(definition: &FungibleDefinition) -> Option<&str> {
    definition.policies.iter().find_map(|policy| match policy {
        FungiblePolicy::TransferFeeV1 { recipient, .. } => Some(recipient.as_str()),
        _ => None,
    })
}

fn has_snapshot_policy(definition: &FungibleDefinition) -> bool {
    definition
        .policies
        .iter()
        .any(|policy| matches!(policy, FungiblePolicy::SnapshotV1))
}

fn max_wallet_limit(definition: &FungibleDefinition) -> Option<u128> {
    definition.policies.iter().find_map(|policy| match policy {
        FungiblePolicy::MaxWalletV1 { max_balance } => Some(*max_balance),
        _ => None,
    })
}

fn balance_key(token_id: &str, owner: &str) -> String {
    format!("{token_id}:{owner}")
}

fn snapshot_key(token_id: &str, snapshot_id: u64) -> String {
    format!("{token_id}:{snapshot_id}")
}

fn simple_amount_event(
    event_type: &str,
    token_id: &str,
    sender: &str,
    owner: Option<&str>,
    recipient: Option<&str>,
    amount: u128,
    timestamp: u64,
) -> StsEvent {
    StsEvent {
        event_type: event_type.to_string(),
        token_id: Some(token_id.to_string()),
        sender: sender.to_string(),
        owner: owner.map(ToString::to_string),
        recipient: recipient.map(ToString::to_string),
        amount: Some(amount.to_string()),
        timestamp,
        attributes: BTreeMap::new(),
    }
}

fn sts_hash(domain: &str, chunks: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(domain.as_bytes());
    for chunk in chunks {
        hasher.update((chunk.len() as u64).to_be_bytes());
        hasher.update(chunk);
    }
    hasher.finalize().into()
}

fn sha3_256_hex(bytes: &[u8]) -> String {
    let hash: [u8; 32] = Sha3_256::digest(bytes).into();
    hex::encode(hash)
}

fn current_unix_timestamp_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn encode_object_id(prefix: &str, hash: &[u8; 32]) -> String {
    bech32::encode(prefix, hash[..20].to_vec().to_base32(), Variant::Bech32m)
        .expect("static STS object id encoding")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const ALICE: &str = "syn1alice00000000000000000000000000000000";
    const BOB: &str = "syn1bob0000000000000000000000000000000000";
    const FEE: &str = "syn1fee0000000000000000000000000000000000";
    const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn params(class: TokenClass) -> CreateFungibleParams {
        CreateFungibleParams {
            class,
            creator: ALICE.to_string(),
            creator_nonce: 7,
            name: "Test Token".to_string(),
            symbol: "TEST".to_string(),
            decimals: 9,
            initial_supply: 1_000,
            max_supply: Some(2_000),
            mint_authority: Some(ALICE.to_string()),
            metadata_authority: Some(ALICE.to_string()),
            metadata_uri: Some("ipfs://metadata".to_string()),
            metadata_hash: Some(HASH.to_string()),
            metadata_mutable: false,
            image_uri: None,
            image_hash: None,
            flags: FungibleControlFlags::default(),
            policies: Vec::new(),
            created_at: 1_700_000_000,
        }
    }

    fn temp_sts_snapshot_path(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir()
            .join(format!("synergy-sts-{label}-{unique}"))
            .join("data")
            .join("sts_state.json")
    }

    #[test]
    fn token_class_discriminants_and_prefixes_are_stable() {
        assert_eq!(TokenClass::B1BasicFungible.discriminant(), 1);
        assert_eq!(TokenClass::B2ManagedFungible.discriminant(), 2);
        assert_eq!(TokenClass::B3PolicyFungible.discriminant(), 3);
        assert_eq!(TokenClass::NF1StandardNft.discriminant(), 11);
        assert_eq!(TokenClass::NF2ControlledNft.discriminant(), 12);
        assert_eq!(TokenClass::MAMultiAsset.discriminant(), 21);
        assert_eq!(TokenClass::IDCredential.discriminant(), 31);
        assert!(derive_fungible_token_id(
            STS_TESTNET_CHAIN_ID,
            TokenClass::B1BasicFungible,
            ALICE,
            1,
            HASH,
            1
        )
        .starts_with("synb1"));
        assert!(
            derive_multi_asset_collection_id(STS_TESTNET_CHAIN_ID, ALICE, 1, HASH, 1)
                .starts_with("synj")
        );
        assert!(
            derive_credential_id(STS_TESTNET_CHAIN_ID, ALICE, BOB, 1, HASH, 1).starts_with("synk")
        );
    }

    #[test]
    fn native_snrg_has_no_token_address() {
        let native = native_snrg_definition();
        assert_eq!(native.symbol, NATIVE_SNRG_SYMBOL);
        assert_eq!(native.token_address, None);
        assert_eq!(native_snrg_token_address(), None);
        assert_eq!(NATIVE_SNRG_PLACEHOLDER_ADDRESS.len(), 41);
        assert!(NATIVE_SNRG_PLACEHOLDER_ADDRESS.chars().all(|ch| ch == '0'));
    }

    #[test]
    fn validates_metadata_hash_timestamp_and_decimals() {
        assert_eq!(validate_metadata_hash(HASH), Ok(()));
        assert_eq!(
            validate_metadata_hash(
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            Err(StsError::InvalidMetadataHash)
        );
        assert_eq!(
            validate_metadata_hash(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            ),
            Err(StsError::InvalidMetadataHash)
        );
        assert_eq!(
            validate_timestamp_seconds(10_000_000_000),
            Err(StsError::InvalidTimestamp)
        );
        let mut invalid = params(TokenClass::B1BasicFungible);
        invalid.decimals = 10;
        assert_eq!(
            StsState::new().create_fungible(invalid),
            Err(StsError::InvalidDecimals)
        );
    }

    #[test]
    fn b1_create_mint_transfer_and_burn() {
        let mut state = StsState::new();
        let token_id = state
            .create_fungible(params(TokenClass::B1BasicFungible))
            .unwrap();
        let definition = state.token_registry.get(&token_id).unwrap();
        assert_eq!(definition.token_address, token_id);
        assert_ne!(
            definition.token_address, NATIVE_SNRG_PLACEHOLDER_ADDRESS,
            "non-native STS assets must have real object addresses"
        );
        assert!(validate_sts_object_id(TokenClass::B1BasicFungible, &token_id).is_ok());
        assert_eq!(state.fungible_balance(ALICE, &token_id), 1_000);

        state
            .mint_fungible(ALICE, &token_id, BOB, 250, 1_700_000_001)
            .unwrap();
        assert_eq!(state.fungible_balance(BOB, &token_id), 250);

        state
            .transfer_fungible(BOB, &token_id, BOB, ALICE, 100, 1_700_000_002)
            .unwrap();
        assert_eq!(state.fungible_balance(BOB, &token_id), 150);
        assert_eq!(state.fungible_balance(ALICE, &token_id), 1_100);

        state
            .burn_fungible(ALICE, &token_id, ALICE, 50, 1_700_000_003)
            .unwrap();
        assert_eq!(state.fungible_balance(ALICE, &token_id), 1_050);
    }

    #[test]
    fn b2_freeze_pause_and_clawback() {
        let mut create = params(TokenClass::B2ManagedFungible);
        create.flags.can_freeze = true;
        create.flags.can_pause = true;
        create.flags.can_clawback = true;
        let mut state = StsState::new();
        let token_id = state.create_fungible(create).unwrap();

        state
            .transfer_fungible(ALICE, &token_id, ALICE, BOB, 100, 1_700_000_001)
            .unwrap();
        state
            .set_fungible_frozen(ALICE, &token_id, BOB, true, 1_700_000_002)
            .unwrap();
        assert_eq!(
            state.transfer_fungible(BOB, &token_id, BOB, ALICE, 1, 1_700_000_003),
            Err(StsError::AccountFrozen)
        );
        state
            .clawback_fungible(ALICE, &token_id, BOB, ALICE, 10, 1_700_000_004)
            .unwrap();
        state
            .set_fungible_paused(ALICE, &token_id, true, 1_700_000_005)
            .unwrap();
        assert_eq!(
            state.mint_fungible(ALICE, &token_id, BOB, 1, 1_700_000_006),
            Err(StsError::TokenPaused)
        );
    }

    #[test]
    fn b3_fee_snapshot_and_max_wallet() {
        let mut create = params(TokenClass::B3PolicyFungible);
        create.policies = vec![
            FungiblePolicy::TransferFeeV1 {
                fee_bps: 100,
                recipient: FEE.to_string(),
            },
            FungiblePolicy::SnapshotV1,
            FungiblePolicy::MaxWalletV1 { max_balance: 950 },
        ];
        let mut state = StsState::new();
        let token_id = state.create_fungible(create).unwrap();

        state
            .transfer_fungible(ALICE, &token_id, ALICE, BOB, 100, 1_700_000_001)
            .unwrap();
        assert_eq!(state.fungible_balance(BOB, &token_id), 99);
        assert_eq!(state.fungible_balance(FEE, &token_id), 1);
        state
            .create_fungible_snapshot(ALICE, &token_id, 1_700_000_002)
            .unwrap();
        assert_eq!(state.fungible_snapshots.len(), 1);
        assert_eq!(
            state.transfer_fungible(BOB, &token_id, BOB, ALICE, 99, 1_700_000_003),
            Err(StsError::PolicyNotEnabled)
        );
    }

    #[test]
    fn signed_payload_round_trip_and_atomic_rejection() {
        let create =
            StsSignedPayload::new(StsTx::CreateFungible(params(TokenClass::B1BasicFungible)));
        let encoded = encode_sts_payload(&create).unwrap();
        assert_eq!(decode_sts_payload(&encoded).unwrap(), Some(create));
        assert_eq!(decode_sts_payload(b"not-sts").unwrap(), None);

        let mut state = StsState::new();
        let mut invalid =
            StsSignedPayload::new(StsTx::CreateFungible(params(TokenClass::B1BasicFungible)));
        invalid.network = "mainnet".to_string();
        assert_eq!(
            state.apply_signed_payload(ALICE, &invalid),
            Err(StsError::InvalidNetwork)
        );
        assert!(state.token_registry.is_empty());
        assert!(state.events.is_empty());
    }

    #[test]
    fn finalized_sts_snapshot_round_trip_uses_chain_1264() {
        let path = temp_sts_snapshot_path("snapshot-round-trip");
        let mut snapshot = StsStateSnapshot::empty_at(77, "block-hash-77");
        let token_id = snapshot
            .state
            .create_fungible(params(TokenClass::B1BasicFungible))
            .expect("token creates");
        save_sts_state_snapshot_to_path(&path, &snapshot).expect("snapshot saves");

        let restored = load_sts_state_snapshot_from_path(&path)
            .expect("snapshot loads")
            .expect("snapshot exists");
        assert_eq!(restored.chain_id, STS_TESTNET_CHAIN_ID);
        assert_eq!(restored.network, STS_TESTNET_NETWORK);
        assert_eq!(restored.latest_block_height, 77);
        assert_eq!(
            restored
                .state
                .fungible_definition(&token_id)
                .unwrap()
                .symbol,
            "TEST"
        );
    }

    #[test]
    fn finalized_sts_transaction_is_idempotent_by_hash() {
        let path = temp_sts_snapshot_path("finalized-transaction");
        let payload =
            StsSignedPayload::new(StsTx::CreateFungible(params(TokenClass::B1BasicFungible)));
        let data = hex::encode(encode_sts_payload(&payload).expect("payload encodes"));
        let first = process_finalized_sts_transaction_data_at_path(
            &path,
            ALICE,
            &data,
            "syntxn-finalized-sts",
            42,
            "block-hash-42",
        )
        .expect("first apply succeeds");
        assert!(first.payload_present);
        assert!(first.applied);

        let second = process_finalized_sts_transaction_data_at_path(
            &path,
            ALICE,
            &data,
            "syntxn-finalized-sts",
            42,
            "block-hash-42",
        )
        .expect("duplicate apply is safe");
        assert!(second.already_processed);

        let snapshot = load_sts_state_snapshot_from_path(&path)
            .expect("snapshot loads")
            .expect("snapshot exists");
        assert_eq!(snapshot.latest_block_height, 42);
        assert_eq!(snapshot.latest_block_hash, "block-hash-42");
        assert_eq!(snapshot.processed_transactions.len(), 1);
        assert_eq!(snapshot.state.fungible_definitions().len(), 1);
        assert_eq!(snapshot.state.events.len(), 1);
    }

    #[test]
    fn finalized_empty_block_creates_empty_snapshot() {
        let path = temp_sts_snapshot_path("empty-block");
        assert!(note_finalized_sts_block_at_path(&path, 12, "block-hash-12").unwrap());
        assert!(!note_finalized_sts_block_at_path(&path, 12, "block-hash-12").unwrap());
        let snapshot = load_sts_state_snapshot_from_path(&path)
            .expect("snapshot loads")
            .expect("snapshot exists");
        assert_eq!(snapshot.latest_block_height, 12);
        assert_eq!(snapshot.latest_block_hash, "block-hash-12");
        assert!(snapshot.state.token_registry.is_empty());
        assert!(note_finalized_sts_block_at_path(&path, 12, "other-hash").is_err());
    }

    #[test]
    fn create_payload_sender_must_match_declared_creator() {
        let payload =
            StsSignedPayload::new(StsTx::CreateFungible(params(TokenClass::B1BasicFungible)));
        let mut state = StsState::new();
        assert_eq!(
            state.apply_signed_payload(BOB, &payload),
            Err(StsError::Unauthorized)
        );
        assert!(state.token_registry.is_empty());
    }

    #[test]
    fn reserved_and_unsafe_token_creation_is_rejected() {
        let mut state = StsState::new();

        let mut reserved = params(TokenClass::B1BasicFungible);
        reserved.symbol = "SNRGX".to_string();
        assert_eq!(
            state.create_fungible(reserved),
            Err(StsError::ReservedTokenIdentity)
        );

        let mut unsafe_metadata = params(TokenClass::B1BasicFungible);
        unsafe_metadata.metadata_mutable = true;
        assert_eq!(
            state.create_fungible(unsafe_metadata),
            Err(StsError::UnsafeTokenPractice)
        );

        let mut unbounded_mint = params(TokenClass::B1BasicFungible);
        unbounded_mint.max_supply = None;
        assert_eq!(
            state.create_fungible(unbounded_mint),
            Err(StsError::UnsafeTokenPractice)
        );

        let mut duplicate_symbol = params(TokenClass::B1BasicFungible);
        state.create_fungible(duplicate_symbol.clone()).unwrap();
        duplicate_symbol.creator_nonce += 1;
        assert_eq!(
            state.create_fungible(duplicate_symbol),
            Err(StsError::ReservedTokenIdentity)
        );
    }

    #[test]
    fn token_image_can_be_set_by_creator_exactly_once() {
        let mut state = StsState::new();
        let token_id = state
            .create_fungible(params(TokenClass::B1BasicFungible))
            .unwrap();
        assert_eq!(
            state.set_fungible_image(BOB, &token_id, "ipfs://image", HASH, 1_700_000_001),
            Err(StsError::Unauthorized)
        );
        state
            .set_fungible_image(ALICE, &token_id, "ipfs://image", HASH, 1_700_000_001)
            .unwrap();
        let definition = state.token_registry.get(&token_id).unwrap();
        assert_eq!(definition.image_uri.as_deref(), Some("ipfs://image"));
        assert!(definition.image_locked);
        assert_eq!(
            state.set_fungible_image(ALICE, &token_id, "ipfs://image2", HASH, 1_700_000_002),
            Err(StsError::ImageAlreadySet)
        );
    }

    #[test]
    fn query_helpers_resolve_fungible_tokens_by_id_or_address() {
        let mut state = StsState::new();
        let token_id = state
            .create_fungible(params(TokenClass::B1BasicFungible))
            .unwrap();
        let token_address = state
            .fungible_definition(&token_id)
            .unwrap()
            .token_address
            .clone();

        assert_eq!(state.fungible_definitions().len(), 1);
        assert_eq!(
            state
                .fungible_definition(&token_address)
                .map(|definition| definition.token_id.as_str()),
            Some(token_id.as_str())
        );
        assert_eq!(
            state
                .fungible_balance_entry(ALICE, &token_address)
                .map(|balance| balance.balance),
            Some(1_000)
        );
    }

    #[test]
    fn event_queries_filter_by_token_and_owner() {
        let mut state = StsState::new();
        let token_id = state
            .create_fungible(params(TokenClass::B1BasicFungible))
            .unwrap();
        state
            .transfer_fungible(ALICE, &token_id, ALICE, BOB, 100, 1_700_000_001)
            .unwrap();

        let bob_events = state.events_for(Some(&token_id), Some(BOB), 10);
        assert_eq!(
            bob_events.first().map(|event| event.event_type.as_str()),
            Some("StsFungibleTransferred")
        );
    }
}
