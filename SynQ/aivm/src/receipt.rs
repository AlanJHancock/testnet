//! Receipts per synq-receipt-spec.md
//!
//! Canonical binary records for hashing, canonical JSON for RPC/debug.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Receipt status
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptStatus {
    Success = 0,
    Reverted = 1,
    Failed = 2,
}

impl From<u8> for ReceiptStatus {
    fn from(b: u8) -> Self {
        match b {
            0 => ReceiptStatus::Success,
            1 => ReceiptStatus::Reverted,
            _ => ReceiptStatus::Failed,
        }
    }
}

/// Event record per spec
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    pub event_index: u32,
    pub topic_hash: [u8; 32],
    pub data: Vec<u8>,
}

impl EventRecord {
    fn encode_binary(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.event_index.to_be_bytes());
        buf.extend_from_slice(&self.topic_hash);
        buf.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.data);
    }
}

/// Receipt per spec
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub receipt_version: u16,       // 1
    pub chain_id: u64,               // 1264
    pub network_id: String,         // "synergy-testnet"
    pub block_height: u64,
    pub tx_hash: [u8; 32],
    pub contract_address: Vec<u8>,  // SynQ address bytes
    pub caller: Vec<u8>,            // SynQ address bytes
    pub status: ReceiptStatus,
    pub gas_used: u64,
    pub pq_gas_used: u64,
    pub state_root_before: [u8; 32],
    pub state_root_after: [u8; 32],
    pub events: Vec<EventRecord>,
    pub return_data: Vec<u8>,
    pub trap_code: Option<u16>,
    pub execution_trace_hash: [u8; 32],
    pub aegis_verification_summary: Vec<u8>,
}

impl Receipt {
    /// Encode as canonical binary for hashing
    pub fn encode_binary(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.receipt_version.to_be_bytes());
        buf.extend_from_slice(&self.chain_id.to_be_bytes());
        // network_id: length-prefixed
        buf.extend_from_slice(&(self.network_id.len() as u32).to_be_bytes());
        buf.extend_from_slice(self.network_id.as_bytes());
        buf.extend_from_slice(&self.block_height.to_be_bytes());
        buf.extend_from_slice(&self.tx_hash);
        buf.extend_from_slice(&(self.contract_address.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.contract_address);
        buf.extend_from_slice(&(self.caller.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.caller);
        buf.push(self.status as u8);
        buf.extend_from_slice(&self.gas_used.to_be_bytes());
        buf.extend_from_slice(&self.pq_gas_used.to_be_bytes());
        buf.extend_from_slice(&self.state_root_before);
        buf.extend_from_slice(&self.state_root_after);
        // events: count-prefixed
        buf.extend_from_slice(&(self.events.len() as u32).to_be_bytes());
        for event in &self.events {
            event.encode_binary(&mut buf);
        }
        // return_data: length-prefixed
        buf.extend_from_slice(&(self.return_data.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.return_data);
        // trap_code: optional
        match self.trap_code {
            Some(code) => {
                buf.push(1);
                buf.extend_from_slice(&code.to_be_bytes());
            }
            None => {
                buf.push(0);
            }
        }
        buf.extend_from_slice(&self.execution_trace_hash);
        // aegis_verification_summary: length-prefixed
        buf.extend_from_slice(&(self.aegis_verification_summary.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.aegis_verification_summary);
        buf
    }

    /// Compute receipt hash (SHA-256 of canonical binary)
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(&self.encode_binary()).into()
    }

    /// Create a success receipt
    pub fn success(
        ctx: &crate::context::ExecutionContext,
        gas_used: u64,
        pq_gas_used: u64,
        state_root_before: [u8; 32],
        state_root_after: [u8; 32],
        return_data: Vec<u8>,
        events: Vec<EventRecord>,
    ) -> Self {
        Self {
            receipt_version: 1,
            chain_id: ctx.chain_id,
            network_id: ctx.network_id.clone(),
            block_height: ctx.block_height,
            tx_hash: ctx.tx_hash,
            contract_address: ctx.contract_address.to_vec(),
            caller: ctx.caller.to_vec(),
            status: ReceiptStatus::Success,
            gas_used,
            pq_gas_used,
            state_root_before,
            state_root_after,
            events,
            return_data,
            trap_code: None,
            execution_trace_hash: [0u8; 32],
            aegis_verification_summary: Vec::new(),
        }
    }

    /// Create a trap/reverted receipt
    pub fn trap(
        ctx: &crate::context::ExecutionContext,
        gas_used: u64,
        pq_gas_used: u64,
        state_root_before: [u8; 32],
        trap_code: u16,
    ) -> Self {
        Self {
            receipt_version: 1,
            chain_id: ctx.chain_id,
            network_id: ctx.network_id.clone(),
            block_height: ctx.block_height,
            tx_hash: ctx.tx_hash,
            contract_address: ctx.contract_address.to_vec(),
            caller: ctx.caller.to_vec(),
            status: ReceiptStatus::Reverted,
            gas_used,
            pq_gas_used,
            state_root_before,
            state_root_after: state_root_before, // rolled back
            events: Vec::new(),
            return_data: Vec::new(),
            trap_code: Some(trap_code),
            execution_trace_hash: [0u8; 32],
            aegis_verification_summary: Vec::new(),
        }
    }
}
