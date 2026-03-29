//! Conversion utilities for NewPayloadRequest to ethrex Block.

use alloc::vec::Vec;

use anyhow::{Context, Result};
use ethrex_common::types::{
    EncodedTransaction, ExecutionPayload, validate_blob_versioned_hashes, validate_block_hash,
    validate_execution_payload_v1, validate_execution_payload_v2, validate_execution_payload_v3,
};
use ethrex_common::{Address, Bloom, Bytes, H256, types::Block};
use ethrex_crypto::Crypto;
use libssz_merkle::Sha256Hasher;
use stateless_validator_common::new_payload_request::{
    ExecutionPayloadV1, ExecutionPayloadV2, ExecutionPayloadV3, NewPayloadRequest, Withdrawal,
    compute_requests_hash,
};

/// Converts a [`NewPayloadRequest`] into an ethrex [`Block`].
pub fn get_block_from_new_payload_request(
    req: NewPayloadRequest,
    hasher: &impl Sha256Hasher,
    crypto: &dyn Crypto,
) -> Result<Block> {
    match req {
        NewPayloadRequest::Bellatrix(b) => {
            let payload = convert_execution_payload_v1(b.execution_payload);
            validate_execution_payload_v1(&payload).context("V1 payload validation failed")?;
            let block = payload
                .clone()
                .into_block(None, None, None, crypto)
                .context("into_block failed")?;
            validate_block_payload_v1_v2(&payload, &block)
                .context("Block/Payload validation failed")?;
            Ok(block)
        }
        NewPayloadRequest::Capella(c) => {
            let payload = convert_execution_payload_v2(c.execution_payload);
            validate_execution_payload_v2(&payload).context("V2 payload validation failed")?;
            let block = payload
                .clone()
                .into_block(None, None, None, crypto)
                .context("into_block failed")?;
            validate_block_payload_v1_v2(&payload, &block)
                .context("Block/Payload validation failed")?;
            Ok(block)
        }
        NewPayloadRequest::Deneb(d) => {
            let parent_beacon_block_root = Some(H256::from(d.parent_beacon_block_root));
            let payload = convert_execution_payload_v3(d.execution_payload);
            validate_execution_payload_v3(&payload).context("V3 payload validation failed")?;
            let block = payload
                .clone()
                .into_block(parent_beacon_block_root, None, None, crypto)
                .context("into_block failed")?;
            validate_block_payload_v3(&payload, &block, &d.versioned_hashes)
                .context("Block/Payload validation failed")?;
            Ok(block)
        }
        NewPayloadRequest::ElectraFulu(e) => {
            let parent_beacon_block_root = Some(H256::from(e.parent_beacon_block_root));
            let requests_hash = Some(H256::from(compute_requests_hash(
                &e.execution_requests,
                hasher,
            )));
            let payload = convert_execution_payload_v3(e.execution_payload);
            validate_execution_payload_v3(&payload).context("V3 payload validation failed")?;
            let block = payload
                .clone()
                .into_block(parent_beacon_block_root, requests_hash, None, crypto)
                .context("into_block failed")?;
            validate_block_payload_v3(&payload, &block, &e.versioned_hashes)
                .context("Block/Payload validation failed")?;
            Ok(block)
        }
    }
}

fn convert_execution_payload_v1(payload: ExecutionPayloadV1) -> ExecutionPayload {
    ExecutionPayload {
        parent_hash: H256::from(payload.parent_hash),
        fee_recipient: Address::from(payload.fee_recipient),
        state_root: H256::from(payload.state_root),
        receipts_root: H256::from(payload.receipts_root),
        logs_bloom: Bloom::from_slice(&payload.logs_bloom[..]),
        prev_randao: H256::from(payload.prev_randao),
        block_number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: Bytes::from(payload.extra_data.into_inner()),
        base_fee_per_gas: base_fee_to_u64(&payload.base_fee_per_gas),
        block_hash: H256::from(payload.block_hash),
        transactions: payload
            .transactions
            .into_iter()
            .map(|t| EncodedTransaction(Bytes::from(t.into_inner())))
            .collect(),
        withdrawals: None,
        blob_gas_used: None,
        excess_blob_gas: None,
        slot_number: None,
        block_access_list: None,
    }
}

fn convert_execution_payload_v2(payload: ExecutionPayloadV2) -> ExecutionPayload {
    ExecutionPayload {
        parent_hash: H256::from(payload.parent_hash),
        fee_recipient: Address::from(payload.fee_recipient),
        state_root: H256::from(payload.state_root),
        receipts_root: H256::from(payload.receipts_root),
        logs_bloom: Bloom::from_slice(&payload.logs_bloom[..]),
        prev_randao: H256::from(payload.prev_randao),
        block_number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: Bytes::from(payload.extra_data.into_inner()),
        base_fee_per_gas: base_fee_to_u64(&payload.base_fee_per_gas),
        block_hash: H256::from(payload.block_hash),
        transactions: payload
            .transactions
            .into_iter()
            .map(|t| EncodedTransaction(Bytes::from(t.into_inner())))
            .collect(),
        withdrawals: Some(
            payload
                .withdrawals
                .into_iter()
                .map(convert_withdrawal)
                .collect(),
        ),
        blob_gas_used: None,
        excess_blob_gas: None,
        slot_number: None,
        block_access_list: None,
    }
}

fn convert_execution_payload_v3(payload: ExecutionPayloadV3) -> ExecutionPayload {
    ExecutionPayload {
        parent_hash: H256::from(payload.parent_hash),
        fee_recipient: Address::from(payload.fee_recipient),
        state_root: H256::from(payload.state_root),
        receipts_root: H256::from(payload.receipts_root),
        logs_bloom: Bloom::from_slice(&payload.logs_bloom[..]),
        prev_randao: H256::from(payload.prev_randao),
        block_number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: Bytes::from(payload.extra_data.into_inner()),
        base_fee_per_gas: base_fee_to_u64(&payload.base_fee_per_gas),
        block_hash: H256::from(payload.block_hash),
        transactions: payload
            .transactions
            .into_iter()
            .map(|t| EncodedTransaction(Bytes::from(t.into_inner())))
            .collect(),
        withdrawals: Some(
            payload
                .withdrawals
                .into_iter()
                .map(convert_withdrawal)
                .collect(),
        ),
        blob_gas_used: Some(payload.blob_gas_used),
        excess_blob_gas: Some(payload.excess_blob_gas),
        slot_number: None,
        block_access_list: None,
    }
}

fn validate_block_payload_v1_v2(payload: &ExecutionPayload, block: &Block) -> Result<()> {
    validate_block_hash(payload, block)?;
    Ok(())
}

fn validate_block_payload_v3(
    payload: &ExecutionPayload,
    block: &Block,
    versioned_hashes: &[[u8; 32]],
) -> Result<()> {
    validate_block_payload_v1_v2(payload, block)?;

    let versioned_hashes = versioned_hashes
        .iter()
        .copied()
        .map(H256::from)
        .collect::<Vec<_>>();
    validate_blob_versioned_hashes(block, &versioned_hashes)?;

    Ok(())
}

/// Convert our Withdrawal type to ethrex's Withdrawal type.
fn convert_withdrawal(w: Withdrawal) -> ethrex_common::types::Withdrawal {
    ethrex_common::types::Withdrawal {
        index: w.index,
        validator_index: w.validator_index,
        address: Address::from(w.address),
        amount: w.amount,
    }
}

/// Convert base_fee_per_gas from 32-byte little-endian to u64.
fn base_fee_to_u64(base_fee: &[u8; 32]) -> u64 {
    debug_assert!(base_fee[8..].iter().all(|&b| b == 0), "base_fee overflow");
    u64::from_le_bytes(base_fee[..8].try_into().unwrap())
}
