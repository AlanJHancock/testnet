use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use lazy_static::lazy_static;

pub const BPS_DENOMINATOR: u64 = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RewardConfig {
    pub validator_fee_share_bps: u64,
    pub treasury_fee_share_bps: u64,
    pub burn_fee_share_bps: u64,
    pub network_owned_validator_treasury_share_bps: u64,
    pub network_owned_validator_bonus_pool_share_bps: u64,
    pub phase1_consensus_participation_weight_bps: u64,
    pub phase1_block_proposal_weight_bps: u64,
    pub phase1_validation_accuracy_weight_bps: u64,
    pub phase1_cluster_contribution_weight_bps: u64,
    pub phase1_synergy_score_modifier_weight_bps: u64,
    pub phase2_uptime_weight_bps: u64,
    pub phase2_responsiveness_weight_bps: u64,
    pub phase2_no_jail_slash_weight_bps: u64,
    pub phase2_cluster_stability_weight_bps: u64,
    pub phase2_governance_participation_weight_bps: u64,
    pub min_base_fee_nwei: u64,
    pub max_base_fee_change_per_epoch_bps: u64,
    pub target_epoch_utilization_bps: u64,
    pub adjustment_rate_bps: u64,
    pub target_gas_epoch: u64,
    pub congestion_multiplier_bps: u64,
    pub max_congestion_premium_bps: u64,
    pub bonus_tier_10_epoch_bps: u64,
    pub bonus_tier_50_epoch_bps: u64,
    pub bonus_tier_100_epoch_bps: u64,
    pub bonus_tier_250_epoch_bps: u64,
    pub bonus_tier_500_epoch_bps: u64,
    pub max_reliability_bonus_bps: u64,
    pub high_performance_uptime_threshold_bps: u64,
    pub high_performance_consensus_threshold_bps: u64,
    pub cluster_cooperation_threshold_bps: u64,
    pub governance_participation_threshold_bps: u64,
}

impl Default for RewardConfig {
    fn default() -> Self {
        Self {
            validator_fee_share_bps: 6_500,
            treasury_fee_share_bps: 2_500,
            burn_fee_share_bps: 1_000,
            network_owned_validator_treasury_share_bps: 7_000,
            network_owned_validator_bonus_pool_share_bps: 3_000,
            phase1_consensus_participation_weight_bps: 3_500,
            phase1_block_proposal_weight_bps: 2_000,
            phase1_validation_accuracy_weight_bps: 2_000,
            phase1_cluster_contribution_weight_bps: 1_500,
            phase1_synergy_score_modifier_weight_bps: 1_000,
            phase2_uptime_weight_bps: 3_500,
            phase2_responsiveness_weight_bps: 2_500,
            phase2_no_jail_slash_weight_bps: 2_000,
            phase2_cluster_stability_weight_bps: 1_000,
            phase2_governance_participation_weight_bps: 1_000,
            min_base_fee_nwei: 1,
            max_base_fee_change_per_epoch_bps: 1_250,
            target_epoch_utilization_bps: 6_000,
            adjustment_rate_bps: 1_000,
            target_gas_epoch: 30_000_000,
            congestion_multiplier_bps: 1_000,
            max_congestion_premium_bps: 5_000,
            bonus_tier_10_epoch_bps: 200,
            bonus_tier_50_epoch_bps: 500,
            bonus_tier_100_epoch_bps: 1_000,
            bonus_tier_250_epoch_bps: 1_500,
            bonus_tier_500_epoch_bps: 2_000,
            max_reliability_bonus_bps: 3_000,
            high_performance_uptime_threshold_bps: 9_800,
            high_performance_consensus_threshold_bps: 9_500,
            cluster_cooperation_threshold_bps: 9_500,
            governance_participation_threshold_bps: 8_000,
        }
    }
}

impl RewardConfig {
    pub fn validate(&self) -> Result<(), String> {
        validate_sum(
            "fee shares",
            &[
                self.validator_fee_share_bps,
                self.treasury_fee_share_bps,
                self.burn_fee_share_bps,
            ],
        )?;
        validate_sum(
            "network-owned validator reward shares",
            &[
                self.network_owned_validator_treasury_share_bps,
                self.network_owned_validator_bonus_pool_share_bps,
            ],
        )?;
        validate_sum(
            "phase 1 weights",
            &[
                self.phase1_consensus_participation_weight_bps,
                self.phase1_block_proposal_weight_bps,
                self.phase1_validation_accuracy_weight_bps,
                self.phase1_cluster_contribution_weight_bps,
                self.phase1_synergy_score_modifier_weight_bps,
            ],
        )?;
        validate_sum(
            "phase 2 weights",
            &[
                self.phase2_uptime_weight_bps,
                self.phase2_responsiveness_weight_bps,
                self.phase2_no_jail_slash_weight_bps,
                self.phase2_cluster_stability_weight_bps,
                self.phase2_governance_participation_weight_bps,
            ],
        )?;

        for (name, value) in self.bps_values() {
            if value > BPS_DENOMINATOR {
                return Err(format!("{name} must be <= 10000 bps"));
            }
        }

        if self.min_base_fee_nwei == 0 {
            return Err("min_base_fee_nWei must be >= 1".to_string());
        }
        if self.target_gas_epoch == 0 {
            return Err("target_gas_epoch must be > 0".to_string());
        }

        Ok(())
    }

    fn bps_values(&self) -> [(&'static str, u64); 32] {
        [
            ("validator_fee_share_bps", self.validator_fee_share_bps),
            ("treasury_fee_share_bps", self.treasury_fee_share_bps),
            ("burn_fee_share_bps", self.burn_fee_share_bps),
            (
                "network_owned_validator_treasury_share_bps",
                self.network_owned_validator_treasury_share_bps,
            ),
            (
                "network_owned_validator_bonus_pool_share_bps",
                self.network_owned_validator_bonus_pool_share_bps,
            ),
            (
                "phase1_consensus_participation_weight_bps",
                self.phase1_consensus_participation_weight_bps,
            ),
            (
                "phase1_block_proposal_weight_bps",
                self.phase1_block_proposal_weight_bps,
            ),
            (
                "phase1_validation_accuracy_weight_bps",
                self.phase1_validation_accuracy_weight_bps,
            ),
            (
                "phase1_cluster_contribution_weight_bps",
                self.phase1_cluster_contribution_weight_bps,
            ),
            (
                "phase1_synergy_score_modifier_weight_bps",
                self.phase1_synergy_score_modifier_weight_bps,
            ),
            ("phase2_uptime_weight_bps", self.phase2_uptime_weight_bps),
            (
                "phase2_responsiveness_weight_bps",
                self.phase2_responsiveness_weight_bps,
            ),
            (
                "phase2_no_jail_slash_weight_bps",
                self.phase2_no_jail_slash_weight_bps,
            ),
            (
                "phase2_cluster_stability_weight_bps",
                self.phase2_cluster_stability_weight_bps,
            ),
            (
                "phase2_governance_participation_weight_bps",
                self.phase2_governance_participation_weight_bps,
            ),
            (
                "max_base_fee_change_per_epoch_bps",
                self.max_base_fee_change_per_epoch_bps,
            ),
            (
                "target_epoch_utilization_bps",
                self.target_epoch_utilization_bps,
            ),
            ("adjustment_rate_bps", self.adjustment_rate_bps),
            ("congestion_multiplier_bps", self.congestion_multiplier_bps),
            (
                "max_congestion_premium_bps",
                self.max_congestion_premium_bps,
            ),
            ("bonus_tier_10_epoch_bps", self.bonus_tier_10_epoch_bps),
            ("bonus_tier_50_epoch_bps", self.bonus_tier_50_epoch_bps),
            ("bonus_tier_100_epoch_bps", self.bonus_tier_100_epoch_bps),
            ("bonus_tier_250_epoch_bps", self.bonus_tier_250_epoch_bps),
            ("bonus_tier_500_epoch_bps", self.bonus_tier_500_epoch_bps),
            ("max_reliability_bonus_bps", self.max_reliability_bonus_bps),
            (
                "high_performance_uptime_threshold_bps",
                self.high_performance_uptime_threshold_bps,
            ),
            (
                "high_performance_consensus_threshold_bps",
                self.high_performance_consensus_threshold_bps,
            ),
            (
                "cluster_cooperation_threshold_bps",
                self.cluster_cooperation_threshold_bps,
            ),
            (
                "governance_participation_threshold_bps",
                self.governance_participation_threshold_bps,
            ),
            ("reserved_bps_1", 0),
            ("reserved_bps_2", 0),
        ]
    }
}

fn validate_sum(label: &str, values: &[u64]) -> Result<(), String> {
    let sum = values
        .iter()
        .try_fold(0u64, |acc, value| acc.checked_add(*value))
        .ok_or_else(|| format!("{label} overflow"))?;
    if sum != BPS_DENOMINATOR {
        return Err(format!("{label} must sum to 10000 bps, got {sum}"));
    }
    Ok(())
}

fn weighted_average_bps(components: &[(u64, u64)]) -> Result<u64, String> {
    let weighted_sum = components.iter().try_fold(0u128, |acc, (score, weight)| {
        if *score > BPS_DENOMINATOR || *weight > BPS_DENOMINATOR {
            return None;
        }
        acc.checked_add((*score as u128) * (*weight as u128))
    });

    weighted_sum
        .map(|sum| (sum / (BPS_DENOMINATOR as u128)) as u64)
        .ok_or_else(|| "basis-point weighted average overflow or invalid bps".to_string())
}

fn mul_bps(amount_nwei: u128, bps: u64) -> Result<u128, String> {
    if bps > BPS_DENOMINATOR {
        return Err("bps value exceeds 10000".to_string());
    }
    amount_nwei
        .checked_mul(bps as u128)
        .map(|value| value / (BPS_DENOMINATOR as u128))
        .ok_or_else(|| "basis-point multiplication overflow".to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochFeeDistribution {
    pub epoch_id: u64,
    pub total_fees_nwei: u128,
    pub validator_share_nwei: u128,
    pub treasury_share_nwei: u128,
    pub burn_share_nwei: u128,
    pub rounding_dust_nwei: u128,
    pub distribution_block_height: u64,
    pub timestamp: Option<u64>,
}

pub fn split_epoch_fees(
    epoch_id: u64,
    total_fees_nwei: u128,
    distribution_block_height: u64,
) -> Result<EpochFeeDistribution, String> {
    split_epoch_fees_with_config(
        epoch_id,
        total_fees_nwei,
        distribution_block_height,
        &RewardConfig::default(),
    )
}

pub fn split_epoch_fees_with_config(
    epoch_id: u64,
    total_fees_nwei: u128,
    distribution_block_height: u64,
    config: &RewardConfig,
) -> Result<EpochFeeDistribution, String> {
    config.validate()?;
    let validator_share = mul_bps(total_fees_nwei, config.validator_fee_share_bps)?;
    let burn_share = mul_bps(total_fees_nwei, config.burn_fee_share_bps)?;
    let nominal_treasury = mul_bps(total_fees_nwei, config.treasury_fee_share_bps)?;
    let assigned = validator_share
        .checked_add(burn_share)
        .and_then(|value| value.checked_add(nominal_treasury))
        .ok_or_else(|| "epoch fee shares overflow".to_string())?;
    let dust = total_fees_nwei.saturating_sub(assigned);
    let treasury_share = nominal_treasury
        .checked_add(dust)
        .ok_or_else(|| "treasury dust assignment overflow".to_string())?;

    Ok(EpochFeeDistribution {
        epoch_id,
        total_fees_nwei,
        validator_share_nwei: validator_share,
        treasury_share_nwei: treasury_share,
        burn_share_nwei: burn_share,
        rounding_dust_nwei: dust,
        distribution_block_height,
        timestamp: None,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Phase1Metrics {
    pub consensus_participation_score_bps: u64,
    pub block_proposal_score_bps: u64,
    pub validation_accuracy_score_bps: u64,
    pub cluster_contribution_score_bps: u64,
    pub synergy_score_modifier_bps: u64,
}

pub fn calculate_phase1_score_bps(
    metrics: &Phase1Metrics,
    config: &RewardConfig,
) -> Result<u64, String> {
    config.validate()?;
    weighted_average_bps(&[
        (
            metrics.consensus_participation_score_bps,
            config.phase1_consensus_participation_weight_bps,
        ),
        (
            metrics.block_proposal_score_bps,
            config.phase1_block_proposal_weight_bps,
        ),
        (
            metrics.validation_accuracy_score_bps,
            config.phase1_validation_accuracy_weight_bps,
        ),
        (
            metrics.cluster_contribution_score_bps,
            config.phase1_cluster_contribution_weight_bps,
        ),
        (
            metrics.synergy_score_modifier_bps,
            config.phase1_synergy_score_modifier_weight_bps,
        ),
    ])
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PendingRewardStatus {
    Pending,
    Settled,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SettlementStatus {
    Pending,
    Complete,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum UnreleasedDestination {
    Burn,
    Treasury,
    BonusPool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorPendingReward {
    pub original_epoch_id: u64,
    pub epoch_id: u64,
    pub original_cluster_address: String,
    pub cluster_id: String,
    pub validator_id: String,
    pub reward_payout_address: String,
    pub pending_reward_nwei: u128,
    pub source_emissions_nwei: u128,
    pub source_fee_rewards_nwei: u128,
    pub source_cluster_bonus_nwei: u128,
    pub phase1_score_bps: u64,
    pub consensus_participation_score_bps: u64,
    pub block_proposal_score_bps: u64,
    pub validation_accuracy_score_bps: u64,
    pub cluster_contribution_score_bps: u64,
    pub synergy_score_modifier_bps: u64,
    pub created_at_epoch: u64,
    pub unlock_epoch: u64,
    pub accountability_epoch: u64,
    pub status: PendingRewardStatus,
    pub segment_ids: Vec<String>,
}

pub fn calculate_pending_reward(
    epoch_id: u64,
    cluster_address: &str,
    validator_id: &str,
    reward_payout_address: &str,
    source_emissions_nwei: u128,
    source_fee_rewards_nwei: u128,
    source_cluster_bonus_nwei: u128,
    metrics: &Phase1Metrics,
    config: &RewardConfig,
) -> Result<ValidatorPendingReward, String> {
    let phase1_score_bps = calculate_phase1_score_bps(metrics, config)?;
    let total_source = source_emissions_nwei
        .checked_add(source_fee_rewards_nwei)
        .and_then(|value| value.checked_add(source_cluster_bonus_nwei))
        .ok_or_else(|| "pending reward source overflow".to_string())?;
    let pending_reward_nwei = mul_bps(total_source, phase1_score_bps)?;

    Ok(ValidatorPendingReward {
        original_epoch_id: epoch_id,
        epoch_id,
        original_cluster_address: cluster_address.to_string(),
        cluster_id: cluster_address.to_string(),
        validator_id: validator_id.to_string(),
        reward_payout_address: reward_payout_address.to_string(),
        pending_reward_nwei,
        source_emissions_nwei,
        source_fee_rewards_nwei,
        source_cluster_bonus_nwei,
        phase1_score_bps,
        consensus_participation_score_bps: metrics.consensus_participation_score_bps,
        block_proposal_score_bps: metrics.block_proposal_score_bps,
        validation_accuracy_score_bps: metrics.validation_accuracy_score_bps,
        cluster_contribution_score_bps: metrics.cluster_contribution_score_bps,
        synergy_score_modifier_bps: metrics.synergy_score_modifier_bps,
        created_at_epoch: epoch_id,
        unlock_epoch: epoch_id + 2,
        accountability_epoch: epoch_id + 1,
        status: PendingRewardStatus::Pending,
        segment_ids: Vec::new(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterRewardSettlement {
    pub epoch_id: u64,
    pub cluster_address: String,
    pub cluster_index: u64,
    pub total_cluster_reward_nwei: u128,
    pub total_validator_pending_rewards_nwei: u128,
    pub validator_count: u64,
    pub assignment_hash: String,
    pub rotation_mode: String,
    pub settlement_status: SettlementStatus,
    pub created_block_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidatorPenaltyReason {
    None,
    MinorDowntime,
    MajorDowntime,
    Jailed,
    Slashed,
    DoubleSigning,
    Equivocation,
    InvalidProposal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleasePerformance {
    pub uptime_score_bps: u64,
    pub responsiveness_score_bps: u64,
    pub no_jail_slash_score_bps: u64,
    pub cluster_stability_score_bps: u64,
    pub governance_participation_score_bps: u64,
    pub penalty_reason: ValidatorPenaltyReason,
}

pub fn calculate_release_coefficient(
    performance: &ReleasePerformance,
    config: &RewardConfig,
) -> Result<u64, String> {
    config.validate()?;
    match performance.penalty_reason {
        ValidatorPenaltyReason::Slashed
        | ValidatorPenaltyReason::DoubleSigning
        | ValidatorPenaltyReason::Equivocation
        | ValidatorPenaltyReason::InvalidProposal => return Ok(0),
        _ => {}
    }

    let score = weighted_average_bps(&[
        (
            performance.uptime_score_bps,
            config.phase2_uptime_weight_bps,
        ),
        (
            performance.responsiveness_score_bps,
            config.phase2_responsiveness_weight_bps,
        ),
        (
            performance.no_jail_slash_score_bps,
            config.phase2_no_jail_slash_weight_bps,
        ),
        (
            performance.cluster_stability_score_bps,
            config.phase2_cluster_stability_weight_bps,
        ),
        (
            performance.governance_participation_score_bps,
            config.phase2_governance_participation_weight_bps,
        ),
    ])?;

    let mut coefficient = if score >= 9_800 {
        BPS_DENOMINATOR
    } else if score >= 9_500 {
        9_800 + ((score - 9_500) * 200 / 300)
    } else if score >= 9_000 {
        score
    } else if score >= 8_000 {
        score * 7_500 / BPS_DENOMINATOR
    } else {
        score * 5_000 / BPS_DENOMINATOR
    };

    if matches!(
        performance.penalty_reason,
        ValidatorPenaltyReason::Jailed | ValidatorPenaltyReason::MajorDowntime
    ) {
        coefficient /= 2;
    } else if matches!(
        performance.penalty_reason,
        ValidatorPenaltyReason::MinorDowntime
    ) {
        coefficient = coefficient * 9_000 / BPS_DENOMINATOR;
    }

    Ok(coefficient.min(BPS_DENOMINATOR))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorRewardSettlement {
    pub original_epoch_id: u64,
    pub accountability_epoch: u64,
    pub unlock_epoch: u64,
    pub cluster_id: String,
    pub original_cluster_address: String,
    pub validator_id: String,
    pub reward_payout_address: String,
    pub pending_reward_nwei: u128,
    pub release_coefficient_bps: u64,
    pub final_reward_nwei: u128,
    pub unreleased_reward_nwei: u128,
    pub unreleased_destination: UnreleasedDestination,
    pub settled_block_height: u64,
    pub status: SettlementStatus,
}

pub fn settle_pending_reward(
    pending: &mut ValidatorPendingReward,
    release_coefficient_bps: u64,
    settled_block_height: u64,
) -> Result<ValidatorRewardSettlement, String> {
    if pending.status != PendingRewardStatus::Pending {
        return Err("pending reward already settled".to_string());
    }
    let final_reward = mul_bps(pending.pending_reward_nwei, release_coefficient_bps)?;
    let unreleased = pending
        .pending_reward_nwei
        .checked_sub(final_reward)
        .ok_or_else(|| "unreleased reward underflow".to_string())?;
    pending.status = PendingRewardStatus::Settled;

    Ok(ValidatorRewardSettlement {
        original_epoch_id: pending.original_epoch_id,
        accountability_epoch: pending.accountability_epoch,
        unlock_epoch: pending.unlock_epoch,
        cluster_id: pending.cluster_id.clone(),
        original_cluster_address: pending.original_cluster_address.clone(),
        validator_id: pending.validator_id.clone(),
        reward_payout_address: pending.reward_payout_address.clone(),
        pending_reward_nwei: pending.pending_reward_nwei,
        release_coefficient_bps,
        final_reward_nwei: final_reward,
        unreleased_reward_nwei: unreleased,
        unreleased_destination: UnreleasedDestination::Burn,
        settled_block_height,
        status: SettlementStatus::Complete,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkOwnedValidatorRewardRouting {
    pub epoch_id: u64,
    pub validator_id: String,
    pub total_reward_nwei: u128,
    pub treasury_share_nwei: u128,
    pub bonus_pool_share_nwei: u128,
    pub rounding_dust_nwei: u128,
    pub routing_block_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorMetadata {
    pub validator_id: String,
    pub reward_payout_address: String,
    pub is_network_owned_validator: bool,
}

pub fn route_network_owned_validator_reward(
    epoch_id: u64,
    validator: &ValidatorMetadata,
    reward_nwei: u128,
    routing_block_height: u64,
    config: &RewardConfig,
) -> Result<NetworkOwnedValidatorRewardRouting, String> {
    config.validate()?;
    if !validator.is_network_owned_validator {
        return Err("validator is not marked as network-owned validator".to_string());
    }
    let bonus_pool_share = mul_bps(
        reward_nwei,
        config.network_owned_validator_bonus_pool_share_bps,
    )?;
    let nominal_treasury = mul_bps(
        reward_nwei,
        config.network_owned_validator_treasury_share_bps,
    )?;
    let assigned = bonus_pool_share
        .checked_add(nominal_treasury)
        .ok_or_else(|| "genesis reward routing overflow".to_string())?;
    let dust = reward_nwei.saturating_sub(assigned);
    let treasury_share = nominal_treasury
        .checked_add(dust)
        .ok_or_else(|| "genesis treasury dust overflow".to_string())?;

    Ok(NetworkOwnedValidatorRewardRouting {
        epoch_id,
        validator_id: validator.validator_id.clone(),
        total_reward_nwei: reward_nwei,
        treasury_share_nwei: treasury_share,
        bonus_pool_share_nwei: bonus_pool_share,
        rounding_dust_nwei: dust,
        routing_block_height,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ReliabilityBonusPool {
    pub balance_nwei: u128,
    pub total_funded_nwei: u128,
    pub total_distributed_nwei: u128,
}

impl ReliabilityBonusPool {
    pub fn fund(&mut self, amount_nwei: u128) -> Result<(), String> {
        self.balance_nwei = self
            .balance_nwei
            .checked_add(amount_nwei)
            .ok_or_else(|| "bonus pool balance overflow".to_string())?;
        self.total_funded_nwei = self
            .total_funded_nwei
            .checked_add(amount_nwei)
            .ok_or_else(|| "bonus pool funding overflow".to_string())?;
        Ok(())
    }

    pub fn distribute(&mut self, amount_nwei: u128) -> Result<(), String> {
        if amount_nwei > self.balance_nwei {
            return Err("bonus pool cannot distribute more than balance".to_string());
        }
        self.balance_nwei -= amount_nwei;
        self.total_distributed_nwei = self
            .total_distributed_nwei
            .checked_add(amount_nwei)
            .ok_or_else(|| "bonus pool distribution overflow".to_string())?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReliabilityEligibility {
    pub uptime_bps: u64,
    pub consensus_participation_bps: u64,
    pub cluster_cooperation_bps: u64,
    pub governance_participation_bps: u64,
    pub penalty_reason: ValidatorPenaltyReason,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorReliabilityState {
    pub validator_id: String,
    pub current_streak_epochs: u64,
    pub highest_streak_epochs: u64,
    pub last_high_performance_epoch: Option<u64>,
    pub current_bonus_tier_bps: u64,
    pub eligible_for_bonus: bool,
    pub last_penalty_reason: ValidatorPenaltyReason,
}

impl ValidatorReliabilityState {
    pub fn new(validator_id: impl Into<String>) -> Self {
        Self {
            validator_id: validator_id.into(),
            current_streak_epochs: 0,
            highest_streak_epochs: 0,
            last_high_performance_epoch: None,
            current_bonus_tier_bps: 0,
            eligible_for_bonus: false,
            last_penalty_reason: ValidatorPenaltyReason::None,
        }
    }
}

pub fn bonus_tier_bps(streak_epochs: u64, config: &RewardConfig) -> u64 {
    let tier = if streak_epochs >= 500 {
        config.bonus_tier_500_epoch_bps
    } else if streak_epochs >= 250 {
        config.bonus_tier_250_epoch_bps
    } else if streak_epochs >= 100 {
        config.bonus_tier_100_epoch_bps
    } else if streak_epochs >= 50 {
        config.bonus_tier_50_epoch_bps
    } else if streak_epochs >= 10 {
        config.bonus_tier_10_epoch_bps
    } else {
        0
    };
    tier.min(config.max_reliability_bonus_bps)
}

pub fn is_bonus_eligible(eligibility: &ReliabilityEligibility, config: &RewardConfig) -> bool {
    eligibility.active
        && eligibility.uptime_bps >= config.high_performance_uptime_threshold_bps
        && eligibility.consensus_participation_bps
            >= config.high_performance_consensus_threshold_bps
        && eligibility.cluster_cooperation_bps >= config.cluster_cooperation_threshold_bps
        && eligibility.governance_participation_bps >= config.governance_participation_threshold_bps
        && matches!(eligibility.penalty_reason, ValidatorPenaltyReason::None)
}

pub fn update_reliability_streak(
    state: &mut ValidatorReliabilityState,
    epoch_id: u64,
    eligibility: &ReliabilityEligibility,
    config: &RewardConfig,
) {
    let eligible = is_bonus_eligible(eligibility, config);
    state.last_penalty_reason = eligibility.penalty_reason.clone();

    if eligible {
        state.current_streak_epochs = state.current_streak_epochs.saturating_add(1);
        state.last_high_performance_epoch = Some(epoch_id);
    } else {
        match eligibility.penalty_reason {
            ValidatorPenaltyReason::MinorDowntime => {
                state.current_streak_epochs = state.current_streak_epochs * 9 / 10;
            }
            ValidatorPenaltyReason::None if !eligibility.active => {}
            _ => {
                state.current_streak_epochs = 0;
            }
        }
    }

    state.highest_streak_epochs = state.highest_streak_epochs.max(state.current_streak_epochs);
    state.current_bonus_tier_bps = bonus_tier_bps(state.current_streak_epochs, config);
    state.eligible_for_bonus = eligible;
}

pub fn calculate_reliability_bonus(
    state: &ValidatorReliabilityState,
    base_reward_nwei: u128,
    pool: &ReliabilityBonusPool,
    config: &RewardConfig,
) -> Result<u128, String> {
    config.validate()?;
    if !state.eligible_for_bonus {
        return Ok(0);
    }
    let bonus = mul_bps(base_reward_nwei, state.current_bonus_tier_bps)?;
    Ok(bonus.min(pool.balance_nwei))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorRewardStatus {
    pub current_epoch_id: u64,
    pub validator_id: String,
    pub validator_status: String,
    pub current_epoch_participation_score_bps: u64,
    pub previous_epoch_pending_reward: Option<ValidatorPendingReward>,
    pub accountability_epoch: Option<u64>,
    pub unlock_epoch: Option<u64>,
    pub estimated_release_coefficient_bps: u64,
    pub projected_final_reward_nwei: u128,
    pub projected_unreleased_amount_nwei: u128,
    pub current_reliability_streak: u64,
    pub highest_reliability_streak: u64,
    pub current_bonus_tier_bps: u64,
    pub next_bonus_tier_bps: u64,
    pub epochs_until_next_bonus_tier: u64,
    pub reliability_bonus_eligibility: bool,
    pub uptime_percentage_bps: u64,
    pub consensus_participation_percentage_bps: u64,
    pub responsiveness_score_bps: u64,
    pub cluster_performance_score_bps: u64,
    pub governance_participation_score_bps: u64,
    pub jailing_status: bool,
    pub slashing_status: bool,
    pub pending_settlements: Vec<ValidatorPendingReward>,
    pub completed_settlements: Vec<ValidatorRewardSettlement>,
    pub network_owned_validator_routing: Vec<NetworkOwnedValidatorRewardRouting>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RewardAuditEvent {
    GasFeeCollected {
        epoch_id: u64,
        tx_hash: String,
        fee_nwei: u128,
    },
    EpochFeeDistribution(EpochFeeDistribution),
    ClusterRewardSettlement(ClusterRewardSettlement),
    ValidatorPendingRewardCreated(ValidatorPendingReward),
    ValidatorReleaseCoefficientCalculated {
        accountability_epoch: u64,
        validator_id: String,
        release_coefficient_bps: u64,
    },
    ValidatorRewardSettled(ValidatorRewardSettlement),
    UnreleasedRewardBurned {
        original_epoch_id: u64,
        validator_id: String,
        amount_nwei: u128,
    },
    NetworkOwnedValidatorRewardRouted(NetworkOwnedValidatorRewardRouting),
    ReliabilityBonusPoolFunded {
        epoch_id: u64,
        amount_nwei: u128,
    },
    ReliabilityBonusPaid {
        epoch_id: u64,
        validator_id: String,
        amount_nwei: u128,
    },
    ValidatorReliabilityStreakUpdated(ValidatorReliabilityState),
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RewardLedger {
    pub fee_distributions: HashMap<u64, EpochFeeDistribution>,
    pub cluster_settlements: HashMap<(u64, String), ClusterRewardSettlement>,
    pub pending_rewards: Vec<ValidatorPendingReward>,
    pub reward_settlements: Vec<ValidatorRewardSettlement>,
    pub network_owned_routings: HashMap<(u64, String), NetworkOwnedValidatorRewardRouting>,
    pub reliability_states: HashMap<String, ValidatorReliabilityState>,
    pub bonus_pool: ReliabilityBonusPool,
    pub audit_events: Vec<RewardAuditEvent>,
}

lazy_static! {
    pub static ref REWARD_LEDGER: Arc<Mutex<RewardLedger>> =
        Arc::new(Mutex::new(RewardLedger::default()));
}

impl RewardLedger {
    pub fn distribute_epoch_fees(
        &mut self,
        epoch_id: u64,
        total_fees_nwei: u128,
        distribution_block_height: u64,
    ) -> Result<&EpochFeeDistribution, String> {
        if self.fee_distributions.contains_key(&epoch_id) {
            return Err("epoch fee distribution already executed".to_string());
        }
        let distribution = split_epoch_fees(epoch_id, total_fees_nwei, distribution_block_height)?;
        self.audit_events
            .push(RewardAuditEvent::EpochFeeDistribution(distribution.clone()));
        self.fee_distributions.insert(epoch_id, distribution);
        Ok(self.fee_distributions.get(&epoch_id).expect("inserted"))
    }

    pub fn create_cluster_settlement(
        &mut self,
        settlement: ClusterRewardSettlement,
    ) -> Result<(), String> {
        let key = (settlement.epoch_id, settlement.cluster_address.clone());
        if self.cluster_settlements.contains_key(&key) {
            return Err("cluster reward settlement already exists".to_string());
        }
        self.audit_events
            .push(RewardAuditEvent::ClusterRewardSettlement(
                settlement.clone(),
            ));
        self.cluster_settlements.insert(key, settlement);
        Ok(())
    }

    pub fn add_pending_reward(&mut self, reward: ValidatorPendingReward) -> Result<(), String> {
        if self.pending_rewards.iter().any(|existing| {
            existing.original_epoch_id == reward.original_epoch_id
                && existing.original_cluster_address == reward.original_cluster_address
                && existing.validator_id == reward.validator_id
        }) {
            return Err("pending reward already exists".to_string());
        }
        self.audit_events
            .push(RewardAuditEvent::ValidatorPendingRewardCreated(
                reward.clone(),
            ));
        self.pending_rewards.push(reward);
        Ok(())
    }

    pub fn settle_pending_rewards(
        &mut self,
        unlock_epoch: u64,
        release_coefficients: &HashMap<String, u64>,
        settled_block_height: u64,
    ) -> Result<Vec<ValidatorRewardSettlement>, String> {
        let mut settlements = Vec::new();
        for pending in self
            .pending_rewards
            .iter_mut()
            .filter(|reward| reward.unlock_epoch == unlock_epoch)
        {
            if pending.status != PendingRewardStatus::Pending {
                continue;
            }
            let coefficient = release_coefficients
                .get(&pending.validator_id)
                .copied()
                .unwrap_or(0);
            let settlement = settle_pending_reward(pending, coefficient, settled_block_height)?;
            self.audit_events
                .push(RewardAuditEvent::ValidatorRewardSettled(settlement.clone()));
            if settlement.unreleased_reward_nwei > 0 {
                self.audit_events
                    .push(RewardAuditEvent::UnreleasedRewardBurned {
                        original_epoch_id: settlement.original_epoch_id,
                        validator_id: settlement.validator_id.clone(),
                        amount_nwei: settlement.unreleased_reward_nwei,
                    });
            }
            self.reward_settlements.push(settlement.clone());
            settlements.push(settlement);
        }
        Ok(settlements)
    }

    pub fn record_network_owned_routing(
        &mut self,
        routing: NetworkOwnedValidatorRewardRouting,
    ) -> Result<(), String> {
        let key = (routing.epoch_id, routing.validator_id.clone());
        if self.network_owned_routings.contains_key(&key) {
            return Err("network-owned validator routing already executed".to_string());
        }
        self.bonus_pool.fund(routing.bonus_pool_share_nwei)?;
        self.audit_events
            .push(RewardAuditEvent::ReliabilityBonusPoolFunded {
                epoch_id: routing.epoch_id,
                amount_nwei: routing.bonus_pool_share_nwei,
            });
        self.audit_events
            .push(RewardAuditEvent::NetworkOwnedValidatorRewardRouted(
                routing.clone(),
            ));
        self.network_owned_routings.insert(key, routing);
        Ok(())
    }

    pub fn get_validator_pending_rewards(&self, validator_id: &str) -> Vec<ValidatorPendingReward> {
        self.pending_rewards
            .iter()
            .filter(|reward| reward.validator_id == validator_id)
            .cloned()
            .collect()
    }

    pub fn get_validator_reward_status(
        &self,
        validator_id: &str,
        current_epoch_id: u64,
    ) -> ValidatorRewardStatus {
        let pending: Vec<_> = self
            .pending_rewards
            .iter()
            .filter(|reward| {
                reward.validator_id == validator_id && reward.status == PendingRewardStatus::Pending
            })
            .cloned()
            .collect();
        let completed: Vec<_> = self
            .reward_settlements
            .iter()
            .filter(|settlement| settlement.validator_id == validator_id)
            .cloned()
            .collect();
        let previous_epoch_pending_reward = pending
            .iter()
            .filter(|reward| reward.original_epoch_id + 1 == current_epoch_id)
            .next()
            .cloned();
        let projected = pending.first().cloned();
        let estimated_release = BPS_DENOMINATOR;
        let projected_final = projected
            .as_ref()
            .map(|reward| mul_bps(reward.pending_reward_nwei, estimated_release).unwrap_or(0))
            .unwrap_or(0);
        let projected_unreleased = projected
            .as_ref()
            .map(|reward| reward.pending_reward_nwei.saturating_sub(projected_final))
            .unwrap_or(0);
        let reliability = self
            .reliability_states
            .get(validator_id)
            .cloned()
            .unwrap_or_else(|| ValidatorReliabilityState::new(validator_id));
        let next_tier = next_bonus_tier(reliability.current_streak_epochs);
        let config = RewardConfig::default();
        let network_owned_validator_routing = self
            .network_owned_routings
            .values()
            .filter(|routing| routing.validator_id == validator_id)
            .cloned()
            .collect();

        ValidatorRewardStatus {
            current_epoch_id,
            validator_id: validator_id.to_string(),
            validator_status: "Unknown".to_string(),
            current_epoch_participation_score_bps: 0,
            previous_epoch_pending_reward,
            accountability_epoch: projected.as_ref().map(|reward| reward.accountability_epoch),
            unlock_epoch: projected.as_ref().map(|reward| reward.unlock_epoch),
            estimated_release_coefficient_bps: estimated_release,
            projected_final_reward_nwei: projected_final,
            projected_unreleased_amount_nwei: projected_unreleased,
            current_reliability_streak: reliability.current_streak_epochs,
            highest_reliability_streak: reliability.highest_streak_epochs,
            current_bonus_tier_bps: reliability.current_bonus_tier_bps,
            next_bonus_tier_bps: bonus_tier_bps(next_tier, &config),
            epochs_until_next_bonus_tier: next_tier
                .saturating_sub(reliability.current_streak_epochs),
            reliability_bonus_eligibility: reliability.eligible_for_bonus,
            uptime_percentage_bps: 0,
            consensus_participation_percentage_bps: 0,
            responsiveness_score_bps: 0,
            cluster_performance_score_bps: 0,
            governance_participation_score_bps: 0,
            jailing_status: matches!(
                reliability.last_penalty_reason,
                ValidatorPenaltyReason::Jailed
            ),
            slashing_status: matches!(
                reliability.last_penalty_reason,
                ValidatorPenaltyReason::Slashed
            ),
            pending_settlements: pending,
            completed_settlements: completed,
            network_owned_validator_routing,
        }
    }
}

fn next_bonus_tier(current_streak: u64) -> u64 {
    for tier in [10, 50, 100, 250, 500] {
        if current_streak < tier {
            return tier;
        }
    }
    500
}

pub fn prorate_bonus_claims(
    claims: &[(String, u128)],
    available_nwei: u128,
) -> Result<Vec<(String, u128)>, String> {
    let total_claimed = claims
        .iter()
        .try_fold(0u128, |acc, (_, amount)| acc.checked_add(*amount))
        .ok_or_else(|| "bonus claim total overflow".to_string())?;
    if total_claimed <= available_nwei {
        return Ok(claims.to_vec());
    }
    if total_claimed == 0 {
        return Ok(claims.iter().map(|(id, _)| (id.clone(), 0)).collect());
    }

    let mut paid = 0u128;
    let mut result = Vec::with_capacity(claims.len());
    for (index, (validator_id, claim)) in claims.iter().enumerate() {
        let amount = if index + 1 == claims.len() {
            available_nwei.saturating_sub(paid)
        } else {
            claim
                .checked_mul(available_nwei)
                .ok_or_else(|| "bonus proration overflow".to_string())?
                / total_claimed
        };
        paid = paid
            .checked_add(amount)
            .ok_or_else(|| "bonus paid total overflow".to_string())?;
        result.push((validator_id.clone(), amount));
    }
    Ok(result)
}

pub fn duplicate_guard_key(parts: &[&str]) -> String {
    parts.join(":")
}

pub fn ensure_not_duplicate(seen: &mut HashSet<String>, key: String) -> Result<(), String> {
    if !seen.insert(key) {
        return Err("duplicate reward operation".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn perfect_phase1() -> Phase1Metrics {
        Phase1Metrics {
            consensus_participation_score_bps: 10_000,
            block_proposal_score_bps: 10_000,
            validation_accuracy_score_bps: 10_000,
            cluster_contribution_score_bps: 10_000,
            synergy_score_modifier_bps: 10_000,
        }
    }

    #[test]
    fn reward_config_validates_required_sums() {
        assert!(RewardConfig::default().validate().is_ok());
        let mut config = RewardConfig::default();
        config.validator_fee_share_bps = 6_499;
        assert!(config.validate().is_err());
    }

    #[test]
    fn epoch_fee_split_is_65_25_10_with_treasury_dust() {
        let split = split_epoch_fees(7, 101, 55).unwrap();
        assert_eq!(split.validator_share_nwei, 65);
        assert_eq!(split.burn_share_nwei, 10);
        assert_eq!(split.treasury_share_nwei, 26);
        assert_eq!(split.rounding_dust_nwei, 1);
        assert_eq!(
            split.validator_share_nwei + split.treasury_share_nwei + split.burn_share_nwei,
            split.total_fees_nwei
        );
    }

    #[test]
    fn pending_reward_is_delayed_and_tracks_sources() {
        let pending = calculate_pending_reward(
            10,
            "syngrp1cluster",
            "validator-7",
            "synw1payout",
            1_000,
            500,
            250,
            &perfect_phase1(),
            &RewardConfig::default(),
        )
        .unwrap();
        assert_eq!(pending.pending_reward_nwei, 1_750);
        assert_eq!(pending.accountability_epoch, 11);
        assert_eq!(pending.unlock_epoch, 12);
        assert_eq!(pending.status, PendingRewardStatus::Pending);
        assert_eq!(pending.source_fee_rewards_nwei, 500);
    }

    #[test]
    fn better_phase1_score_earns_higher_pending_reward() {
        let mut weaker = perfect_phase1();
        weaker.block_proposal_score_bps = 5_000;
        let strong = calculate_pending_reward(
            1,
            "cluster",
            "a",
            "payout",
            1_000,
            0,
            0,
            &perfect_phase1(),
            &RewardConfig::default(),
        )
        .unwrap();
        let weak = calculate_pending_reward(
            1,
            "cluster",
            "b",
            "payout",
            1_000,
            0,
            0,
            &weaker,
            &RewardConfig::default(),
        )
        .unwrap();
        assert!(strong.pending_reward_nwei > weak.pending_reward_nwei);
    }

    #[test]
    fn release_coefficient_thresholds_and_penalties_are_enforced() {
        let config = RewardConfig::default();
        let perfect = ReleasePerformance {
            uptime_score_bps: 10_000,
            responsiveness_score_bps: 10_000,
            no_jail_slash_score_bps: 10_000,
            cluster_stability_score_bps: 10_000,
            governance_participation_score_bps: 10_000,
            penalty_reason: ValidatorPenaltyReason::None,
        };
        assert_eq!(
            calculate_release_coefficient(&perfect, &config).unwrap(),
            10_000
        );

        let ninety_two = ReleasePerformance {
            uptime_score_bps: 9_200,
            responsiveness_score_bps: 9_200,
            no_jail_slash_score_bps: 9_200,
            cluster_stability_score_bps: 9_200,
            governance_participation_score_bps: 9_200,
            penalty_reason: ValidatorPenaltyReason::None,
        };
        assert_eq!(
            calculate_release_coefficient(&ninety_two, &config).unwrap(),
            9_200
        );

        let slashed = ReleasePerformance {
            penalty_reason: ValidatorPenaltyReason::Slashed,
            ..perfect
        };
        assert_eq!(calculate_release_coefficient(&slashed, &config).unwrap(), 0);
    }

    #[test]
    fn final_reward_settlement_burns_unreleased_amount_and_is_single_use() {
        let mut pending = calculate_pending_reward(
            5,
            "cluster",
            "validator",
            "payout",
            1_000,
            0,
            0,
            &perfect_phase1(),
            &RewardConfig::default(),
        )
        .unwrap();
        let settlement = settle_pending_reward(&mut pending, 9_000, 99).unwrap();
        assert_eq!(settlement.final_reward_nwei, 900);
        assert_eq!(settlement.unreleased_reward_nwei, 100);
        assert_eq!(
            settlement.unreleased_destination,
            UnreleasedDestination::Burn
        );
        assert!(settle_pending_reward(&mut pending, 9_000, 100).is_err());
    }

    #[test]
    fn network_owned_validator_rewards_route_70_30() {
        let validator = ValidatorMetadata {
            validator_id: "genesis-1".to_string(),
            reward_payout_address: "synw1payout".to_string(),
            is_network_owned_validator: true,
        };
        let routing =
            route_network_owned_validator_reward(1, &validator, 101, 77, &RewardConfig::default())
                .unwrap();
        assert_eq!(routing.treasury_share_nwei, 71);
        assert_eq!(routing.bonus_pool_share_nwei, 30);
        assert_eq!(routing.rounding_dust_nwei, 1);
    }

    #[test]
    fn normal_validator_cannot_use_network_owned_routing() {
        let validator = ValidatorMetadata {
            validator_id: "normal".to_string(),
            reward_payout_address: "synw1payout".to_string(),
            is_network_owned_validator: false,
        };
        assert!(route_network_owned_validator_reward(
            1,
            &validator,
            100,
            77,
            &RewardConfig::default(),
        )
        .is_err());
    }

    #[test]
    fn bonus_pool_accounting_cannot_overpay() {
        let mut pool = ReliabilityBonusPool::default();
        pool.fund(100).unwrap();
        assert!(pool.distribute(101).is_err());
        pool.distribute(40).unwrap();
        assert_eq!(pool.balance_nwei, 60);
        assert_eq!(pool.total_funded_nwei, 100);
        assert_eq!(pool.total_distributed_nwei, 40);
    }

    #[test]
    fn progressive_bonus_tiers_are_calculated() {
        let config = RewardConfig::default();
        assert_eq!(bonus_tier_bps(10, &config), 200);
        assert_eq!(bonus_tier_bps(50, &config), 500);
        assert_eq!(bonus_tier_bps(100, &config), 1_000);
        assert_eq!(bonus_tier_bps(250, &config), 1_500);
        assert_eq!(bonus_tier_bps(500, &config), 2_000);
    }

    #[test]
    fn reliability_streak_increment_decay_and_reset() {
        let config = RewardConfig::default();
        let mut state = ValidatorReliabilityState::new("validator");
        let eligible = ReliabilityEligibility {
            uptime_bps: 9_900,
            consensus_participation_bps: 9_600,
            cluster_cooperation_bps: 9_700,
            governance_participation_bps: 8_500,
            penalty_reason: ValidatorPenaltyReason::None,
            active: true,
        };
        update_reliability_streak(&mut state, 1, &eligible, &config);
        assert_eq!(state.current_streak_epochs, 1);

        state.current_streak_epochs = 100;
        let minor = ReliabilityEligibility {
            penalty_reason: ValidatorPenaltyReason::MinorDowntime,
            ..eligible.clone()
        };
        update_reliability_streak(&mut state, 2, &minor, &config);
        assert_eq!(state.current_streak_epochs, 90);

        let slashed = ReliabilityEligibility {
            penalty_reason: ValidatorPenaltyReason::Slashed,
            ..eligible
        };
        update_reliability_streak(&mut state, 3, &slashed, &config);
        assert_eq!(state.current_streak_epochs, 0);
    }

    #[test]
    fn ledger_rejects_duplicate_settlements_and_queries_pending_rewards() {
        let mut ledger = RewardLedger::default();
        ledger.distribute_epoch_fees(1, 1_000, 10).unwrap();
        assert!(ledger.distribute_epoch_fees(1, 1_000, 11).is_err());

        let pending = calculate_pending_reward(
            1,
            "cluster-a",
            "validator-1",
            "payout",
            100,
            0,
            0,
            &perfect_phase1(),
            &RewardConfig::default(),
        )
        .unwrap();
        ledger.add_pending_reward(pending).unwrap();
        assert_eq!(ledger.get_validator_pending_rewards("validator-1").len(), 1);
    }

    #[test]
    fn bonus_claims_are_prorated_when_pool_is_insufficient() {
        let paid =
            prorate_bonus_claims(&[("a".to_string(), 100), ("b".to_string(), 300)], 200).unwrap();
        assert_eq!(paid, vec![("a".to_string(), 50), ("b".to_string(), 150)]);
    }
}
