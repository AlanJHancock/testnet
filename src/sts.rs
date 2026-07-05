use bech32::{u5, Variant};
use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;
use std::fmt;

pub const STS_TESTNET_CHAIN_ID: u64 = 338_640;
pub const STS_TESTNET_NETWORK: &str = "testnet";
pub const STS_PAYLOAD_PREFIX: &[u8] = b"synergy-sts-v1:";
pub const STS_MAX_DECIMALS: u8 = 9;
const OBJECT_ID_LEN: usize = 41;
const CHECKSUM_LEN: usize = 6;
const SEPARATOR_LEN: usize = 1;
const HEX_32_LEN: usize = 64;

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
    InvalidNetwork,
}

impl fmt::Display for StsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}", self)
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

impl FungiblePolicy {
    pub fn template_name(&self) -> &'static str {
        match self {
            FungiblePolicy::TransferFeeV1 { .. } => "transfer_fee_v1",
            FungiblePolicy::SnapshotV1 => "snapshot_v1",
            FungiblePolicy::VestingV1 { .. } => "vesting_v1",
            FungiblePolicy::MaxWalletV1 { .. } => "max_wallet_v1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataPointer {
    pub name: String,
    pub symbol: String,
    pub metadata_uri: Option<String>,
    pub metadata_hash: Option<String>,
    pub metadata_mutable: bool,
    pub icon_hash: Option<String>,
    pub external_url_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FungibleDefinition {
    pub token_id: String,
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
    pub flags: FungibleControlFlags,
    pub policies: Vec<FungiblePolicy>,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StsSignedPayload {
    pub version: u8,
    pub chain_id: u64,
    pub network: String,
    pub tx: StsTx,
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
        let result = match &payload.tx {
            StsTx::CreateFungible(params) => self.create_fungible(params.clone()),
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
        };
        match result {
            Ok(()) => Ok(self.events[before..].to_vec()),
            Err(error) => {
                self.events.truncate(before);
                Err(error)
            }
        }
    }

    pub fn create_fungible(
        &mut self,
        params: CreateFungibleParams,
    ) -> Result<String, StsError> {
        validate_timestamp_seconds(params.created_at)?;
        validate_metadata(&params.metadata_uri, &params.metadata_hash)?;
        validate_metadata_hash_option(params.metadata_hash.as_deref())?;
        if !params.class.is_fungible() {
            return Err(StsError::InvalidTokenClass);
        }
        if params.decimals > STS_MAX_DECIMALS {
            return Err(StsError::InvalidDecimals);
        }
        if let Some(max_supply) = params.max_supply {
            if params.initial_supply > max_supply {
                return Err(StsError::SupplyOverflow);
            }
        }
        validate_fungible_flags(params.class, &params.flags)?;
        validate_fungible_policies(params.class, &params.policies)?;

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

        let authorities = AuthoritySet {
            mint_authority: params.mint_authority.clone(),
            metadata_authority: params.metadata_authority.clone(),
            freeze_authority: authority_when(params.flags.can_freeze, &params.creator),
            compliance_authority: authority_when(
                params.flags.can_clawback
                    || params.flags.can_allowlist
                    || params.flags.can_denylist,
                &params.creator,
            ),
            transfer_authority: authority_when(params.flags.requires_transfer_approval, &params.creator),
            ..AuthoritySet::default()
        };
        let definition = FungibleDefinition {
            token_id: token_id.clone(),
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
            created_at: params.created_at,
            updated_at: params.created_at,
            flags: params.flags,
            policies: params.policies,
            paused: false,
            verified: false,
        };
        self.token_registry.insert(token_id.clone(), definition);
        if params.initial_supply > 0 {
            self.credit_balance(&token_id, &params.creator, params.initial_supply, params.created_at)?;
        }
        self.push_event(StsEvent {
            event_type: "StsFungibleCreated".to_string(),
            token_id: Some(token_id.clone()),
            sender: params.creator.clone(),
            owner: Some(params.creator),
            recipient: None,
            amount: Some(params.initial_supply.to_string()),
            timestamp: params.created_at,
            attributes: BTreeMap::new(),
        });
        Ok(token_id)
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
            let fee_recipient = transfer_fee_recipient(&definition).ok_or(StsError::PolicyNotEnabled)?;
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
        self.debit_balance(token_id, from, amount, timestamp)?;
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
    subject_commitment: &str,
    schema_id: &str,
    credential_hash: &str,
    issued_at: u64,
) -> String {
    let hash = sts_hash(
        "synergy-sts-credential-v1",
        &[
            &chain_id.to_be_bytes(),
            issuer_address.as_bytes(),
            subject_commitment.as_bytes(),
            schema_id.as_bytes(),
            credential_hash.as_bytes(),
            &issued_at.to_be_bytes(),
        ],
    );
    encode_object_id(TokenClass::IDCredential.prefix(), &hash)
}

pub fn validate_metadata_hash(value: &str) -> Result<(), StsError> {
    if value.starts_with("0x")
        || value.len() != HEX_32_LEN
        || value.chars().any(|ch| !ch.is_ascii_hexdigit() || ch.is_ascii_uppercase())
    {
        return Err(StsError::InvalidMetadataHash);
    }
    Ok(())
}

pub fn validate_timestamp_seconds(value: u64) -> Result<(), StsError> {
    if value > 9_999_999_999 {
        Err(StsError::InvalidTimestamp)
    } else {
        Ok(())
    }
}

pub fn estimate_sts_gas(tx: &StsTx) -> u64 {
    match tx {
        StsTx::CreateFungible(params) => {
            125_000 + metadata_size_gas(&params.metadata_uri) + policy_count_gas(params.policies.len())
        }
        StsTx::MintFungible { .. } => 55_000,
        StsTx::BurnFungible { .. } => 50_000,
        StsTx::TransferFungible { .. } => 48_000,
        StsTx::FreezeFungibleAccount { .. } | StsTx::ThawFungibleAccount { .. } => 45_000,
        StsTx::PauseFungible { .. } | StsTx::UnpauseFungible { .. } => 40_000,
        StsTx::ClawbackFungible { .. } => 62_000,
        StsTx::CreateFungibleSnapshot { .. } => 80_000,
    }
}

fn metadata_size_gas(uri: &Option<String>) -> u64 {
    uri.as_ref().map(|value| value.len() as u64 * 16).unwrap_or(0)
}

fn policy_count_gas(count: usize) -> u64 {
    count as u64 * 7_500
}

fn validate_amount(amount: u128) -> Result<(), StsError> {
    if amount == 0 {
        Err(StsError::InvalidAmount)
    } else {
        Ok(())
    }
}

fn validate_metadata(uri: &Option<String>, hash: &Option<String>) -> Result<(), StsError> {
    if uri.is_some() && hash.is_none() {
        return Err(StsError::InvalidMetadataHash);
    }
    if let Some(uri) = uri {
        if !(uri.starts_with("ipfs://") || uri.starts_with("ar://") || uri.starts_with("https://"))
        {
            return Err(StsError::InvalidMetadata);
        }
    }
    Ok(())
}

fn validate_metadata_hash_option(value: Option<&str>) -> Result<(), StsError> {
    if let Some(value) = value {
        validate_metadata_hash(value)?;
    }
    Ok(())
}

fn validate_fungible_flags(
    token_class: TokenClass,
    flags: &FungibleControlFlags,
) -> Result<(), StsError> {
    match token_class {
        TokenClass::B1BasicFungible => {
            if flags.can_freeze
                || flags.can_pause
                || flags.can_clawback
                || flags.can_denylist
                || flags.can_allowlist
                || flags.requires_transfer_approval
            {
                return Err(StsError::InvalidTokenClass);
            }
            Ok(())
        }
        TokenClass::B2ManagedFungible | TokenClass::B3PolicyFungible => Ok(()),
        _ => Err(StsError::InvalidTokenClass),
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
            FungiblePolicy::TransferFeeV1 { fee_bps, .. } => {
                if *fee_bps > 10_000 {
                    return Err(StsError::PolicyNotEnabled);
                }
            }
            FungiblePolicy::VestingV1 {
                start_at,
                cliff_at,
                end_at,
            } => {
                validate_timestamp_seconds(*start_at)?;
                validate_timestamp_seconds(*cliff_at)?;
                validate_timestamp_seconds(*end_at)?;
                if !(start_at <= cliff_at && cliff_at <= end_at) {
                    return Err(StsError::InvalidTimestamp);
                }
            }
            FungiblePolicy::MaxWalletV1 { max_balance } => {
                if *max_balance == 0 {
                    return Err(StsError::PolicyNotEnabled);
                }
            }
            FungiblePolicy::SnapshotV1 => {}
        }
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

fn transfer_fee(definition: &FungibleDefinition, amount: u128) -> Result<u128, StsError> {
    let Some(fee_bps) = definition.policies.iter().find_map(|policy| match policy {
        FungiblePolicy::TransferFeeV1 { fee_bps, .. } => Some(*fee_bps as u128),
        _ => None,
    }) else {
        return Ok(0);
    };
    amount
        .checked_mul(fee_bps)
        .and_then(|value| value.checked_div(10_000))
        .ok_or(StsError::SupplyOverflow)
}

fn transfer_fee_recipient(definition: &FungibleDefinition) -> Option<&str> {
    definition.policies.iter().find_map(|policy| match policy {
        FungiblePolicy::TransferFeeV1 { recipient, .. } => Some(recipient.as_str()),
        _ => None,
    })
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
        owner: owner.map(str::to_string),
        recipient: recipient.map(str::to_string),
        amount: Some(amount.to_string()),
        timestamp,
        attributes: BTreeMap::new(),
    }
}

fn balance_key(token_id: &str, owner: &str) -> String {
    format!("{token_id}|{owner}")
}

fn snapshot_key(token_id: &str, snapshot_id: u64) -> String {
    format!("{token_id}|{snapshot_id}")
}

fn sha3_256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn sts_hash(domain: &str, fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(domain.as_bytes());
    for field in fields {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

fn encode_object_id(prefix: &str, hash: &[u8; 32]) -> String {
    let data_char_count = OBJECT_ID_LEN - prefix.len() - SEPARATOR_LEN - CHECKSUM_LEN;
    let base32_data = extract_base32_values(hash, data_char_count);
    bech32::encode(prefix, base32_data, Variant::Bech32m)
        .expect("STS object ID Bech32m encoding should not fail")
}

fn extract_base32_values(hash: &[u8], count: usize) -> Vec<u5> {
    let mut values = Vec::with_capacity(count);
    for i in 0..count {
        let bit_offset = i * 5;
        let byte_idx = bit_offset / 8;
        let bit_idx = bit_offset % 8;
        let value = if bit_idx <= 3 {
            (hash[byte_idx] >> (3 - bit_idx)) & 0x1f
        } else {
            let high_bits = (hash[byte_idx] << (bit_idx - 3)) & 0x1f;
            let low_bits = if byte_idx + 1 < hash.len() {
                hash[byte_idx + 1] >> (11 - bit_idx)
            } else {
                0
            };
            high_bits | low_bits
        };
        values.push(u5::try_from_u8(value).expect("5-bit value must be 0..31"));
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "synw1alice000000000000000000000000000000";
    const BOB: &str = "synw1bob00000000000000000000000000000000";
    const FEE: &str = "synw1fee00000000000000000000000000000000";
    const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn b1_params() -> CreateFungibleParams {
        CreateFungibleParams {
            class: TokenClass::B1BasicFungible,
            creator: ALICE.to_string(),
            creator_nonce: 7,
            name: "Testnet Gold".to_string(),
            symbol: "TGLD".to_string(),
            decimals: 9,
            initial_supply: 1_000_000_000,
            max_supply: Some(2_000_000_000),
            mint_authority: Some(ALICE.to_string()),
            metadata_authority: Some(ALICE.to_string()),
            metadata_uri: Some("ipfs://metadata".to_string()),
            metadata_hash: Some(HASH.to_string()),
            metadata_mutable: false,
            flags: FungibleControlFlags::default(),
            policies: Vec::new(),
            created_at: 1_800_000_000,
        }
    }

    #[test]
    fn token_class_has_stable_discriminants_and_prefixes() {
        assert_eq!(TokenClass::B1BasicFungible.discriminant(), 1);
        assert_eq!(TokenClass::B2ManagedFungible.discriminant(), 2);
        assert_eq!(TokenClass::B3PolicyFungible.discriminant(), 3);
        assert_eq!(TokenClass::NF1StandardNft.discriminant(), 11);
        assert_eq!(TokenClass::NF2ControlledNft.discriminant(), 12);
        assert_eq!(TokenClass::MAMultiAsset.discriminant(), 21);
        assert_eq!(TokenClass::IDCredential.discriminant(), 31);
        assert_eq!(TokenClass::B1BasicFungible.prefix(), "synb1");
        assert_eq!(TokenClass::IDCredential.prefix(), "synk");
    }

    #[test]
    fn id_derivation_is_deterministic_and_prefixed() {
        let first = derive_fungible_token_id(
            STS_TESTNET_CHAIN_ID,
            TokenClass::B1BasicFungible,
            ALICE,
            1,
            HASH,
            1_800_000_000,
        );
        let second = derive_fungible_token_id(
            STS_TESTNET_CHAIN_ID,
            TokenClass::B1BasicFungible,
            ALICE,
            1,
            HASH,
            1_800_000_000,
        );
        assert_eq!(first, second);
        assert!(first.starts_with("synb11"));
        assert_eq!(first.len(), OBJECT_ID_LEN);
    }

    #[test]
    fn malformed_hash_timestamp_and_decimals_are_rejected() {
        assert_eq!(
            validate_metadata_hash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            Err(StsError::InvalidMetadataHash)
        );
        assert_eq!(
            validate_metadata_hash("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            Err(StsError::InvalidMetadataHash)
        );
        assert_eq!(
            validate_timestamp_seconds(1_800_000_000_000),
            Err(StsError::InvalidTimestamp)
        );
        let mut params = b1_params();
        params.decimals = 10;
        assert_eq!(
            StsState::new().create_fungible(params),
            Err(StsError::InvalidDecimals)
        );
    }

    #[test]
    fn b1_create_mint_transfer_and_burn_preserve_supply() {
        let mut state = StsState::new();
        let token_id = state.create_fungible(b1_params()).unwrap();
        assert_eq!(state.fungible_balance(ALICE, &token_id), 1_000_000_000);

        state
            .mint_fungible(ALICE, &token_id, BOB, 100_000, 1_800_000_010)
            .unwrap();
        state
            .transfer_fungible(BOB, &token_id, BOB, ALICE, 25_000, 1_800_000_020)
            .unwrap();
        state
            .burn_fungible(ALICE, &token_id, ALICE, 5_000, 1_800_000_030)
            .unwrap();

        let token = state.token_registry.get(&token_id).unwrap();
        assert_eq!(token.total_supply, 1_000_095_000);
        assert_eq!(state.fungible_balance(BOB, &token_id), 75_000);
        assert_eq!(state.fungible_balance(ALICE, &token_id), 1_000_020_000);
    }

    #[test]
    fn b2_freeze_pause_and_clawback_are_declared_and_enforced() {
        let mut params = b1_params();
        params.class = TokenClass::B2ManagedFungible;
        params.flags.can_freeze = true;
        params.flags.can_pause = true;
        params.flags.can_clawback = true;
        let mut state = StsState::new();
        let token_id = state.create_fungible(params).unwrap();
        state
            .transfer_fungible(ALICE, &token_id, ALICE, BOB, 100_000, 1_800_000_010)
            .unwrap();
        state
            .set_fungible_frozen(ALICE, &token_id, BOB, true, 1_800_000_020)
            .unwrap();
        assert_eq!(
            state.transfer_fungible(BOB, &token_id, BOB, ALICE, 1, 1_800_000_030),
            Err(StsError::AccountFrozen)
        );
        state
            .clawback_fungible(ALICE, &token_id, BOB, ALICE, 10_000, 1_800_000_040)
            .unwrap();
        state
            .set_fungible_paused(ALICE, &token_id, true, 1_800_000_050)
            .unwrap();
        assert_eq!(
            state.transfer_fungible(ALICE, &token_id, ALICE, BOB, 1, 1_800_000_060),
            Err(StsError::TokenPaused)
        );
    }

    #[test]
    fn clawback_without_creation_flag_is_rejected() {
        let mut params = b1_params();
        params.class = TokenClass::B2ManagedFungible;
        let mut state = StsState::new();
        let token_id = state.create_fungible(params).unwrap();
        assert_eq!(
            state.clawback_fungible(ALICE, &token_id, ALICE, BOB, 1, 1_800_000_010),
            Err(StsError::ClawbackNotEnabled)
        );
    }

    #[test]
    fn b3_transfer_fee_snapshot_and_max_wallet_policies_apply() {
        let mut params = b1_params();
        params.class = TokenClass::B3PolicyFungible;
        params.max_supply = Some(10_000_000_000);
        params.policies = vec![
            FungiblePolicy::TransferFeeV1 {
                fee_bps: 250,
                recipient: FEE.to_string(),
            },
            FungiblePolicy::SnapshotV1,
            FungiblePolicy::MaxWalletV1 {
                max_balance: 1_000_100_000,
            },
        ];
        let mut state = StsState::new();
        let token_id = state.create_fungible(params).unwrap();
        state
            .transfer_fungible(ALICE, &token_id, ALICE, BOB, 100_000, 1_800_000_010)
            .unwrap();
        assert_eq!(state.fungible_balance(BOB, &token_id), 97_500);
        assert_eq!(state.fungible_balance(FEE, &token_id), 2_500);
        state
            .create_fungible_snapshot(ALICE, &token_id, 1_800_000_020)
            .unwrap();
        assert_eq!(state.fungible_snapshots.len(), 1);
    }

    #[test]
    fn signed_payload_round_trips_and_applies_atomically() {
        let payload = StsSignedPayload::new(StsTx::CreateFungible(b1_params()));
        let encoded = encode_sts_payload(&payload).unwrap();
        let decoded = decode_sts_payload(&encoded).unwrap().unwrap();
        assert_eq!(payload, decoded);

        let mut state = StsState::new();
        let events = state.apply_signed_payload(ALICE, &decoded).unwrap();
        assert_eq!(events.len(), 1);

        let bad = StsSignedPayload {
            chain_id: 1264,
            ..decoded
        };
        let before = state.clone();
        assert_eq!(
            state.apply_signed_payload(ALICE, &bad),
            Err(StsError::InvalidNetwork)
        );
        assert_eq!(state, before);
    }
}
