//! ethrex-specific JSON-RPC methods (`ethrex_*` namespace).
//!
//! These are non-standard extensions that ethrex exposes outside the
//! standardized `eth_`/`debug_` namespaces. They live in a dedicated namespace
//! so operators can enable them on a public endpoint (`--http.api ethrex`)
//! without also exposing the whole `debug_` surface.

use ethrex_blockchain::vm::StoreVmDatabase;
use ethrex_common::{
    Address, U256,
    types::{
        BlockHeader, FRAME_RECEIPT_STATUS_SUCCESS, PrefixShape, RING_SIZE, Transaction,
        UTXO_PROOF_TABLE_FORMAT_VERSION, UtxoProofNode, UtxoProofRecord, UtxoProofTable,
        ValidationPrefix, calculate_base_fee_per_blob_gas,
        eip8304::{EncodedIndexEntry, IndexTable, TABLE_SIZES, TABLES_PER_LEVEL, table_multiproof},
        ring_slot,
    },
};
use ethrex_vm::backends::{FrameValidationOutcome, levm::get_max_allowed_gas_limit};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    time::Instant,
};

use crate::{
    rpc::{RpcApiContext, RpcHandler},
    types::block_identifier::{BlockIdentifier, BlockIdentifierOrHash},
    utils::RpcErr,
};

/// `ethrex_getEip8304Table` exposes one canonical EIP-8304 table for devnet
/// inspection and wallet experiments. The first parameter is the table's first
/// block (a JSON-RPC block quantity or tag); the optional second parameter is
/// its table size and defaults to one block.
#[derive(Debug)]
pub struct GetEip8304TableRequest {
    pub first_block: BlockIdentifier,
    pub table_size: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Eip8304TableResult {
    first_block: String,
    end_block: String,
    end_block_hash: String,
    table_size: String,
    level: usize,
    commitment_block: String,
    storage_slot: String,
    entry_count: String,
    table_root: String,
    entries: Vec<Eip8304TableEntry>,
    load_micros: u128,
}

/// Human-readable view of one canonical entry. `positionIndex` is the
/// cumulative log count for transaction entries and the transaction-relative
/// log index for address/topic entries.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Eip8304TableEntry {
    entry_type: &'static str,
    type_id: u16,
    content: String,
    block_number: String,
    transaction_index: Option<String>,
    position_index: Option<String>,
    encoded: String,
}

/// A non-standard, proof-carrying content query over one EIP-8304 table.
/// This is a devnet RPC optimization; it does not alter EIP-8304 table
/// construction, commitments, or consensus processing.
#[derive(Debug)]
pub struct QueryEip8304TableRequest {
    pub first_block: BlockIdentifier,
    pub table_size: u64,
    queries: Vec<Eip8304ContentQuery>,
    candidate_type_ids: Vec<u16>,
}

#[derive(Debug)]
struct Eip8304ContentQuery {
    type_id: u16,
    content: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Eip8304ProvenEntry {
    #[serde(flatten)]
    entry: Eip8304TableEntry,
    leaf_index: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Eip8304ProofNode {
    level: usize,
    node_index: String,
    hash: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Eip8304PostingRange {
    type_id: u16,
    content: String,
    first_index: String,
    end_index_exclusive: String,
    entries: Vec<Eip8304ProvenEntry>,
    lower_boundary: Option<Eip8304ProvenEntry>,
    upper_boundary: Option<Eip8304ProvenEntry>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Eip8304TableQueryResult {
    first_block: String,
    end_block: String,
    end_block_hash: String,
    table_size: String,
    level: usize,
    commitment_block: String,
    storage_slot: String,
    entry_count: String,
    table_root: String,
    queries: Vec<Eip8304PostingRange>,
    transactions: Vec<Eip8304ProvenEntry>,
    candidate_entries: Vec<Eip8304ProvenEntry>,
    proof_format: &'static str,
    proof_nodes: Vec<Eip8304ProofNode>,
    load_micros: u128,
    query_micros: u128,
}

/// Batched UPT request for event positions already discovered through a
/// recipient-first EIP-8304 query.
#[derive(Debug)]
pub struct GetUtxoProofsRequest {
    positions: Vec<UtxoEventPosition>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct UtxoEventPosition {
    block_number: u64,
    transaction_index: u32,
    log_index: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UtxoProofRecordResult {
    position: String,
    index: String,
    source: String,
    recipient: String,
    value: String,
    transaction_index: String,
    transaction_log_index: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UtxoProofNodeResult {
    level: usize,
    node_index: String,
    hash: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UtxoBlockProofResult {
    format_version: u16,
    chain_id: String,
    vault: String,
    block_number: String,
    block_hash: String,
    openings_root: String,
    root_storage_slot: String,
    table_hash: String,
    record_count: String,
    records: Vec<UtxoProofRecordResult>,
    proof_nodes: Vec<UtxoProofNodeResult>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UtxoProofsResult {
    blocks: Vec<UtxoBlockProofResult>,
}

impl RpcHandler for GetEip8304TableRequest {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let params = params
            .as_ref()
            .ok_or(RpcErr::BadParams("No params provided".to_owned()))?;
        if params.is_empty() || params.len() > 2 {
            return Err(RpcErr::BadParams(format!(
                "Expected one or two params and {} were provided",
                params.len()
            )));
        }
        let first_block = BlockIdentifier::parse(params[0].clone(), 0)?;
        let table_size = params
            .get(1)
            .map(|value| parse_quantity(value, 1))
            .transpose()?
            .unwrap_or(1);
        if !TABLE_SIZES.contains(&table_size) {
            return Err(RpcErr::BadParams(format!(
                "tableSize must be one of {TABLE_SIZES:?}"
            )));
        }
        Ok(Self {
            first_block,
            table_size,
        })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let Some(first_block) = self
            .first_block
            .resolve_block_number(&context.storage)
            .await?
        else {
            return Ok(Value::Null);
        };
        if !first_block.is_multiple_of(self.table_size) {
            return Err(RpcErr::BadParams(format!(
                "first block {first_block} is not aligned to table size {}",
                self.table_size
            )));
        }
        let end_block = first_block
            .checked_add(self.table_size - 1)
            .ok_or_else(|| RpcErr::BadParams("table range overflow".to_owned()))?;
        let commitment_block = end_block
            .checked_add(if self.table_size == 1 {
                0
            } else {
                self.table_size / 4
            })
            .ok_or_else(|| RpcErr::BadParams("commitment block overflow".to_owned()))?;
        if context.storage.get_latest_block_number().await? < commitment_block {
            return Ok(Value::Null);
        }
        let Some(end_header) = context.storage.get_block_header(end_block)? else {
            return Ok(Value::Null);
        };
        let end_block_hash = end_header.hash();
        let level = TABLE_SIZES
            .iter()
            .position(|size| *size == self.table_size)
            .ok_or_else(|| RpcErr::Internal("validated EIP-8304 table size vanished".to_owned()))?;
        let started = Instant::now();
        let Some(table) =
            context
                .storage
                .get_or_reconstruct_index_table(level, end_block, end_block_hash)?
        else {
            return Ok(Value::Null);
        };
        let load_micros = started.elapsed().as_micros();
        table_to_value(&table, end_block_hash, commitment_block, load_micros)
    }
}

impl RpcHandler for QueryEip8304TableRequest {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let params = params
            .as_ref()
            .ok_or(RpcErr::BadParams("No params provided".to_owned()))?;
        if !(3..=4).contains(&params.len()) {
            return Err(RpcErr::BadParams(format!(
                "Expected three or four params and {} were provided",
                params.len()
            )));
        }
        let first_block = BlockIdentifier::parse(params[0].clone(), 0)?;
        let table_size = parse_quantity(&params[1], 1)?;
        if !TABLE_SIZES.contains(&table_size) {
            return Err(RpcErr::BadParams(format!(
                "tableSize must be one of {TABLE_SIZES:?}"
            )));
        }
        let raw_queries = params[2]
            .as_array()
            .ok_or_else(|| RpcErr::BadParams("parameter 2 must be a query array".to_owned()))?;
        if raw_queries.is_empty() || raw_queries.len() > 8 {
            return Err(RpcErr::BadParams(
                "parameter 2 must contain between one and eight queries".to_owned(),
            ));
        }
        let queries = raw_queries
            .iter()
            .enumerate()
            .map(|(index, value)| parse_content_query(value, index))
            .collect::<Result<Vec<_>, _>>()?;
        let candidate_type_ids = params
            .get(3)
            .map(parse_candidate_type_ids)
            .transpose()?
            .unwrap_or_default();
        if !candidate_type_ids.is_empty() && (queries.len() != 1 || queries[0].type_id != 5) {
            return Err(RpcErr::BadParams(
                "candidate type proofs require exactly one complete type-5 recipient range"
                    .to_owned(),
            ));
        }
        Ok(Self {
            first_block,
            table_size,
            queries,
            candidate_type_ids,
        })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let Some(first_block) = self
            .first_block
            .resolve_block_number(&context.storage)
            .await?
        else {
            return Ok(Value::Null);
        };
        if !first_block.is_multiple_of(self.table_size) {
            return Err(RpcErr::BadParams(format!(
                "first block {first_block} is not aligned to table size {}",
                self.table_size
            )));
        }
        let end_block = first_block
            .checked_add(self.table_size - 1)
            .ok_or_else(|| RpcErr::BadParams("table range overflow".to_owned()))?;
        let commitment_block = end_block
            .checked_add(if self.table_size == 1 {
                0
            } else {
                self.table_size / 4
            })
            .ok_or_else(|| RpcErr::BadParams("commitment block overflow".to_owned()))?;
        if context.storage.get_latest_block_number().await? < commitment_block {
            return Ok(Value::Null);
        }
        let Some(end_header) = context.storage.get_block_header(end_block)? else {
            return Ok(Value::Null);
        };
        let end_block_hash = end_header.hash();
        let level = TABLE_SIZES
            .iter()
            .position(|size| *size == self.table_size)
            .ok_or_else(|| RpcErr::Internal("validated EIP-8304 table size vanished".to_owned()))?;
        let load_started = Instant::now();
        let Some(table) =
            context
                .storage
                .get_or_reconstruct_index_table(level, end_block, end_block_hash)?
        else {
            return Ok(Value::Null);
        };
        let load_micros = load_started.elapsed().as_micros();
        table_query_to_value(
            &table,
            end_block_hash,
            commitment_block,
            load_micros,
            &self.queries,
            &self.candidate_type_ids,
        )
    }
}

impl RpcHandler for GetUtxoProofsRequest {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let params = params
            .as_ref()
            .ok_or(RpcErr::BadParams("No params provided".to_owned()))?;
        if params.len() != 1 {
            return Err(RpcErr::BadParams(format!(
                "Expected one params array and {} were provided",
                params.len()
            )));
        }
        let values = params[0]
            .as_array()
            .ok_or_else(|| RpcErr::BadParams("parameter 0 must be a position array".to_owned()))?;
        if values.len() > 4096 {
            return Err(RpcErr::BadParams(
                "parameter 0 cannot contain more than 4096 positions".to_owned(),
            ));
        }

        let mut positions = Vec::with_capacity(values.len());
        let mut unique = HashSet::with_capacity(values.len());
        for (index, value) in values.iter().enumerate() {
            let object = value
                .as_object()
                .ok_or_else(|| RpcErr::BadParams(format!("position {index} must be an object")))?;
            let field = |name: &str| {
                object.get(name).ok_or_else(|| {
                    RpcErr::BadParams(format!("position {index}.{name} is required"))
                })
            };
            let block_number = parse_quantity(field("blockNumber")?, 0)?;
            let transaction_index = u32::try_from(parse_quantity(field("transactionIndex")?, 0)?)
                .map_err(|_| {
                RpcErr::BadParams(format!("position {index}.transactionIndex exceeds uint32"))
            })?;
            let log_index =
                u32::try_from(parse_quantity(field("logIndex")?, 0)?).map_err(|_| {
                    RpcErr::BadParams(format!("position {index}.logIndex exceeds uint32"))
                })?;
            let position = UtxoEventPosition {
                block_number,
                transaction_index,
                log_index,
            };
            if !unique.insert(position) {
                return Err(RpcErr::BadParams(format!(
                    "position {index} duplicates an earlier position"
                )));
            }
            positions.push(position);
        }
        Ok(Self { positions })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let latest = context.storage.get_latest_block_number().await?;
        let mut requested_by_block = BTreeMap::<u64, BTreeSet<(u32, u32)>>::new();
        for position in &self.positions {
            requested_by_block
                .entry(position.block_number)
                .or_default()
                .insert((position.transaction_index, position.log_index));
        }

        let chain_id = context.storage.get_chain_config().chain_id;
        let mut blocks = Vec::with_capacity(requested_by_block.len());
        for (block_number, positions) in requested_by_block {
            if latest.saturating_sub(block_number) >= RING_SIZE {
                return Err(RpcErr::BadParams(format!(
                    "block {block_number} has left the recent openings-root ring; batched archive paths are not available in this devnet profile"
                )));
            }
            let header = context
                .storage
                .get_block_header(block_number)?
                .ok_or_else(|| RpcErr::WrongParam(format!("blockNumber {block_number}")))?;
            let block_hash = header.hash();
            let table = match context.storage.get_utxo_proof_table(block_hash)? {
                Some(table) => table,
                None => {
                    let receipts = context.storage.get_receipts_for_block(&block_hash).await?;
                    let table = UtxoProofTable::from_receipts(
                        chain_id,
                        block_number,
                        block_hash,
                        &receipts,
                    )
                    .map_err(|error| RpcErr::Internal(error.to_string()))?;
                    context.storage.store_utxo_proof_table(&table)?;
                    table
                }
            };
            if table.chain_id() != chain_id || table.block_number() != block_number {
                return Err(RpcErr::Internal(
                    "persisted UTXO proof table metadata does not match the canonical chain"
                        .to_owned(),
                ));
            }
            let (records, proof_nodes) = table
                .select_by_event_positions(&positions)
                .map_err(|error| RpcErr::WrongParam(error.to_string()))?;
            blocks.push(UtxoBlockProofResult {
                format_version: UTXO_PROOF_TABLE_FORMAT_VERSION,
                chain_id: format!("0x{:x}", table.chain_id()),
                vault: format!("{:#x}", table.vault()),
                block_number: format!("0x{:x}", table.block_number()),
                block_hash: format!("{:#x}", table.block_hash()),
                openings_root: format!("{:#x}", table.openings_root()),
                root_storage_slot: format!("{:#x}", ring_slot(block_number)),
                table_hash: format!("{:#x}", table.table_hash()),
                record_count: format!("0x{:x}", table.records().len()),
                records: records
                    .into_iter()
                    .map(|(position, record)| utxo_record_to_result(position, record))
                    .collect(),
                proof_nodes: proof_nodes.into_iter().map(utxo_node_to_result).collect(),
            });
        }
        serde_json::to_value(UtxoProofsResult { blocks })
            .map_err(|error| RpcErr::Internal(error.to_string()))
    }
}

fn utxo_record_to_result(position: usize, record: UtxoProofRecord) -> UtxoProofRecordResult {
    UtxoProofRecordResult {
        position: format!("0x{position:x}"),
        index: format!("0x{:x}", record.index),
        source: format!("{:#x}", record.source),
        recipient: format!("{:#x}", record.recipient),
        value: format!("0x{:x}", record.value),
        transaction_index: format!("0x{:x}", record.transaction_index),
        transaction_log_index: format!("0x{:x}", record.transaction_log_index),
    }
}

fn utxo_node_to_result(node: UtxoProofNode) -> UtxoProofNodeResult {
    UtxoProofNodeResult {
        level: node.level,
        node_index: format!("0x{:x}", node.node_index),
        hash: format!("{:#x}", node.hash),
    }
}

fn parse_content_query(value: &Value, index: usize) -> Result<Eip8304ContentQuery, RpcErr> {
    let object = value
        .as_object()
        .ok_or_else(|| RpcErr::BadParams(format!("query {index} must be an object")))?;
    let type_id = object
        .get("typeId")
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| RpcErr::BadParams(format!("query {index}.typeId must be an integer")))?;
    let expected_content_bytes = match type_id {
        2 => 20,
        3..=6 => 32,
        _ => {
            return Err(RpcErr::BadParams(format!(
                "query {index}.typeId must select a log posting (2 through 6)"
            )));
        }
    };
    let content = object
        .get("content")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("0x"))
        .ok_or_else(|| RpcErr::BadParams(format!("query {index}.content must be 0x-prefixed")))?;
    let content = hex::decode(content)
        .map_err(|_| RpcErr::BadParams(format!("query {index}.content is not valid hex")))?;
    if content.len() != expected_content_bytes {
        return Err(RpcErr::BadParams(format!(
            "query {index}.content must contain {expected_content_bytes} bytes"
        )));
    }
    Ok(Eip8304ContentQuery { type_id, content })
}

fn parse_candidate_type_ids(value: &Value) -> Result<Vec<u16>, RpcErr> {
    let values = value
        .as_array()
        .ok_or_else(|| RpcErr::BadParams("parameter 3 must be a type-id array".to_owned()))?;
    if values.is_empty() || values.len() > 5 {
        return Err(RpcErr::BadParams(
            "parameter 3 must contain between one and five type IDs".to_owned(),
        ));
    }
    let mut unique = HashSet::with_capacity(values.len());
    let mut type_ids = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let type_id = value
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .filter(|value| (2..=6).contains(value))
            .ok_or_else(|| {
                RpcErr::BadParams(format!(
                    "parameter 3 item {index} must be a log type ID from 2 through 6"
                ))
            })?;
        if !unique.insert(type_id) {
            return Err(RpcErr::BadParams(format!(
                "parameter 3 item {index} duplicates type ID {type_id}"
            )));
        }
        type_ids.push(type_id);
    }
    Ok(type_ids)
}

fn parse_quantity(value: &Value, index: u64) -> Result<u64, RpcErr> {
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }
    let quantity = value
        .as_str()
        .ok_or_else(|| RpcErr::BadParams(format!("parameter {index} must be a quantity")))?;
    let Some(quantity) = quantity.strip_prefix("0x") else {
        return Err(RpcErr::BadHexFormat(index));
    };
    u64::from_str_radix(quantity, 16).map_err(|_| RpcErr::BadHexFormat(index))
}

fn table_query_to_value(
    table: &IndexTable,
    end_block_hash: ethrex_common::H256,
    commitment_block: u64,
    load_micros: u128,
    queries: &[Eip8304ContentQuery],
    candidate_type_ids: &[u16],
) -> Result<Value, RpcErr> {
    let query_started = Instant::now();
    let entries = table.encoded_entries();
    let ranges = queries
        .iter()
        .map(|query| {
            let mut prefix = Vec::with_capacity(2 + query.content.len());
            prefix.extend_from_slice(&query.type_id.to_be_bytes());
            prefix.extend_from_slice(&query.content);
            let first = entries.partition_point(|entry| entry.as_bytes() < prefix.as_slice());
            let mut end = first;
            while end < entries.len() && entries[end].as_bytes().starts_with(&prefix) {
                end += 1;
            }
            (query, first, end)
        })
        .collect::<Vec<_>>();

    let mut matched_positions: Option<HashSet<Vec<u8>>> = None;
    for (_, first, end) in &ranges {
        let range_positions = entries[*first..*end]
            .iter()
            .filter_map(log_position_key)
            .collect::<HashSet<_>>();
        matched_positions = Some(match matched_positions {
            None => range_positions,
            Some(previous) => previous.intersection(&range_positions).cloned().collect(),
        });
    }
    let matched_positions = matched_positions.unwrap_or_default();
    let target_transactions = matched_positions
        .iter()
        .map(|position| position[..12].to_vec())
        .collect::<HashSet<_>>();
    let transaction_indices = entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            (read_u16(entry.as_bytes(), 0).ok() == Some(1)
                && block_transaction_key(entry)
                    .is_some_and(|key| target_transactions.contains(&key)))
            .then_some(index)
        })
        .collect::<Vec<_>>();
    let candidate_indices = entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            (read_u16(entry.as_bytes(), 0)
                .ok()
                .is_some_and(|type_id| candidate_type_ids.contains(&type_id))
                && entry_position_key(entry).is_some_and(|key| matched_positions.contains(&key)))
            .then_some(index)
        })
        .collect::<Vec<_>>();

    let mut proof_indices = transaction_indices.clone();
    proof_indices.extend(candidate_indices.iter().copied());
    for (_, first, end) in &ranges {
        proof_indices.extend(*first..*end);
        if *first > 0 {
            proof_indices.push(*first - 1);
        }
        if *end < entries.len() {
            proof_indices.push(*end);
        }
    }
    proof_indices.sort_unstable();
    proof_indices.dedup();
    let proof_nodes = table_multiproof(entries, &proof_indices)
        .ok_or_else(|| RpcErr::Internal("could not construct EIP-8304 multiproof".to_owned()))?
        .into_iter()
        .map(|node| Eip8304ProofNode {
            level: node.level,
            node_index: format!("0x{:x}", node.node_index),
            hash: format!("{:#x}", node.hash),
        })
        .collect::<Vec<_>>();

    let posting_ranges = ranges
        .into_iter()
        .map(|(query, first, end)| {
            Ok(Eip8304PostingRange {
                type_id: query.type_id,
                content: format!("0x{}", hex::encode(&query.content)),
                first_index: format!("0x{first:x}"),
                end_index_exclusive: format!("0x{end:x}"),
                entries: (first..end)
                    .map(|index| proven_entry(entries, index))
                    .collect::<Result<Vec<_>, _>>()?,
                lower_boundary: (first > 0)
                    .then(|| proven_entry(entries, first - 1))
                    .transpose()?,
                upper_boundary: (end < entries.len())
                    .then(|| proven_entry(entries, end))
                    .transpose()?,
            })
        })
        .collect::<Result<Vec<_>, RpcErr>>()?;
    let transactions = transaction_indices
        .into_iter()
        .map(|index| proven_entry(entries, index))
        .collect::<Result<Vec<_>, _>>()?;
    let candidate_entries = candidate_indices
        .into_iter()
        .map(|index| proven_entry(entries, index))
        .collect::<Result<Vec<_>, _>>()?;

    let storage_slot = table_storage_slot(table)?;
    let end_block = table
        .end_block()
        .map_err(|error| RpcErr::Internal(error.to_string()))?;
    serde_json::to_value(Eip8304TableQueryResult {
        first_block: format!("0x{:x}", table.first_block()),
        end_block: format!("0x{end_block:x}"),
        end_block_hash: format!("{end_block_hash:#x}"),
        table_size: format!("0x{:x}", table.table_size()),
        level: table.level(),
        commitment_block: format!("0x{commitment_block:x}"),
        storage_slot: format!("0x{storage_slot:x}"),
        entry_count: format!("0x{:x}", table.entry_count()),
        table_root: format!("{:#x}", table.table_root()),
        queries: posting_ranges,
        transactions,
        candidate_entries,
        proof_format: "shared-per-table-v1",
        proof_nodes,
        load_micros,
        query_micros: query_started.elapsed().as_micros(),
    })
    .map_err(|error| RpcErr::Internal(error.to_string()))
}

fn log_position_key(entry: &EncodedIndexEntry) -> Option<Vec<u8>> {
    let encoded = entry.as_bytes();
    if !matches!(read_u16(encoded, 0).ok(), Some(2..=6)) {
        return None;
    }
    let position_offset = encoded.len().checked_sub(16)?;
    Some(encoded.get(position_offset..)?.to_vec())
}

fn entry_position_key(entry: &EncodedIndexEntry) -> Option<Vec<u8>> {
    let encoded = entry.as_bytes();
    if !matches!(read_u16(encoded, 0).ok(), Some(2..=6)) {
        return None;
    }
    let position_offset = encoded.len().checked_sub(16)?;
    Some(encoded.get(position_offset..)?.to_vec())
}

fn block_transaction_key(entry: &EncodedIndexEntry) -> Option<Vec<u8>> {
    let encoded = entry.as_bytes();
    let position = encoded.get(encoded.len().checked_sub(16)?..)?;
    Some(position[..12].to_vec())
}

fn proven_entry(entries: &[EncodedIndexEntry], index: usize) -> Result<Eip8304ProvenEntry, RpcErr> {
    Ok(Eip8304ProvenEntry {
        entry: entry_to_view(&entries[index])?,
        leaf_index: format!("0x{index:x}"),
    })
}

fn table_storage_slot(table: &IndexTable) -> Result<u64, RpcErr> {
    table
        .table_size()
        .checked_mul(TABLES_PER_LEVEL)
        .and_then(|base| {
            base.checked_add((table.first_block() / table.table_size()) % TABLES_PER_LEVEL)
        })
        .ok_or_else(|| RpcErr::Internal("EIP-8304 storage slot overflow".to_owned()))
}

fn table_to_value(
    table: &IndexTable,
    end_block_hash: ethrex_common::H256,
    commitment_block: u64,
    load_micros: u128,
) -> Result<Value, RpcErr> {
    let entries = table
        .encoded_entries()
        .iter()
        .map(entry_to_view)
        .collect::<Result<Vec<_>, _>>()?;
    let storage_slot = table_storage_slot(table)?;
    let end_block = table
        .end_block()
        .map_err(|error| RpcErr::Internal(error.to_string()))?;
    serde_json::to_value(Eip8304TableResult {
        first_block: format!("0x{:x}", table.first_block()),
        end_block: format!("0x{end_block:x}"),
        end_block_hash: format!("{end_block_hash:#x}"),
        table_size: format!("0x{:x}", table.table_size()),
        level: table.level(),
        commitment_block: format!("0x{commitment_block:x}"),
        storage_slot: format!("0x{storage_slot:x}"),
        entry_count: format!("0x{:x}", table.entry_count()),
        table_root: format!("{:#x}", table.table_root()),
        entries,
        load_micros,
    })
    .map_err(|error| RpcErr::Internal(error.to_string()))
}

fn entry_to_view(entry: &EncodedIndexEntry) -> Result<Eip8304TableEntry, RpcErr> {
    let encoded = entry.as_bytes();
    if encoded.len() < 2 {
        return Err(RpcErr::Internal("malformed EIP-8304 entry".to_owned()));
    }
    let type_id = read_u16(encoded, 0)?;
    let (entry_type, content_end, block_offset, has_transaction, has_position) = match type_id {
        0 if encoded.len() == 42 => ("block", 34, 34, false, false),
        1 if encoded.len() == 50 => ("transaction", 34, 34, true, true),
        2 if encoded.len() == 38 => ("log.address", 22, 22, true, true),
        3 if encoded.len() == 50 => ("log.topics[0]", 34, 34, true, true),
        4 if encoded.len() == 50 => ("log.topics[1]", 34, 34, true, true),
        5 if encoded.len() == 50 => ("log.topics[2]", 34, 34, true, true),
        6 if encoded.len() == 50 => ("log.topics[3]", 34, 34, true, true),
        _ => {
            return Err(RpcErr::Internal(format!(
                "malformed EIP-8304 entry type {type_id} with length {}",
                encoded.len()
            )));
        }
    };
    let block_number = read_u64(encoded, block_offset)?;
    let transaction_index = has_transaction
        .then(|| read_u32(encoded, block_offset + 8))
        .transpose()?;
    let position_index = has_position
        .then(|| read_u32(encoded, block_offset + 12))
        .transpose()?;
    Ok(Eip8304TableEntry {
        entry_type,
        type_id,
        content: format!("0x{}", hex::encode(&encoded[2..content_end])),
        block_number: format!("0x{block_number:x}"),
        transaction_index: transaction_index.map(|value| format!("0x{value:x}")),
        position_index: position_index.map(|value| format!("0x{value:x}")),
        encoded: format!("0x{}", hex::encode(encoded)),
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, RpcErr> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| RpcErr::Internal("truncated EIP-8304 u16".to_owned()))?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, RpcErr> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| RpcErr::Internal("truncated EIP-8304 u32".to_owned()))?;
    Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, RpcErr> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| RpcErr::Internal("truncated EIP-8304 u64".to_owned()))?;
    Ok(u64::from_be_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

/// `ethrex_simulateFrameTransaction` — dry-run the EIP-8141 validation prefix
/// (the same check the mempool runs on `eth_sendRawTransaction`) plus a full
/// multi-frame execution, WITHOUT submitting the transaction, so a client can
/// learn whether a frame transaction is valid and how much gas it consumes
/// before sending it.
#[derive(Debug)]
pub struct SimulateFrameTransactionRequest {
    /// Decoded type-`0x06` frame transaction (validated in `parse`).
    pub transaction: Transaction,
    /// Block the simulation runs against. Defaults to `latest`.
    pub block: Option<BlockIdentifierOrHash>,
}

/// Result of `ethrex_simulateFrameTransaction`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SimulateFrameTransactionResult {
    /// Whether the EIP-8141 validation prefix passed — the frame-specific
    /// admission check the mempool runs. This is NECESSARY but not SUFFICIENT
    /// for admission: standard gates (outer signatures, nonce, fees, per-tx gas
    /// cap, paymaster funding) are not all re-checked here. A `false` never
    /// under-rejects (the mempool uses this same prefix simulation).
    valid: bool,
    /// Recognized validation-prefix shape, or `null` if the prefix is
    /// structurally invalid.
    prefix_shape: Option<String>,
    /// The payer (paymaster or self-funded sender) established by the prefix,
    /// or `null` if none was established.
    payer: Option<Address>,
    /// The transaction's max cost (TXPARAM `0x06`), as a `0x`-hex wei value.
    /// Always present — it is a pure function of the transaction fields.
    max_cost: String,
    /// Reason the transaction is invalid — a validation-prefix failure or a
    /// pre-simulation gate such as the per-transaction gas cap. `null` when
    /// `valid` is true.
    violation: Option<String>,
    /// Accurate total gas used across all frames, as `0x`-hex. `null` when the
    /// prefix is invalid, the tx exceeds the simulation gas cap, or the full
    /// execution errored.
    gas_used: Option<String>,
    /// Per-frame gas used and success, when a full execution ran; `null`
    /// otherwise.
    frames: Option<Vec<FrameExecResult>>,
    /// Top-level execution summary: `"success"` (every frame succeeded) or
    /// `"reverted"` (at least one frame did not — see per-frame `frames`).
    /// `null` if the full execution was not run or errored.
    execution_status: Option<String>,
    /// Error string if the full execution could not run or complete (e.g. the
    /// tx exceeds the simulation gas cap, the body reverted the whole tx under
    /// the frame-tx exclusion model, or the payer was underfunded). `null`
    /// otherwise.
    execution_error: Option<String>,
}

/// Per-frame execution outcome for the full-execution step.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FrameExecResult {
    /// Gas used by this frame, as `0x`-hex.
    gas_used: String,
    /// Whether this frame completed successfully (did not revert/halt/skip).
    succeeded: bool,
}

/// Stable wire name for a validation-prefix shape (decoupled from the Rust
/// `Debug` representation, which must not leak into the public API).
fn prefix_shape_name(shape: &PrefixShape) -> &'static str {
    match shape {
        PrefixShape::SelfVerify => "SelfVerify",
        PrefixShape::DeploySelfVerify => "DeploySelfVerify",
        PrefixShape::OnlyVerifyPay => "OnlyVerifyPay",
        PrefixShape::DeployOnlyVerifyPay => "DeployOnlyVerifyPay",
    }
}

impl RpcHandler for SimulateFrameTransactionRequest {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let params = params
            .as_ref()
            .ok_or(RpcErr::BadParams("No params provided".to_owned()))?;
        if params.is_empty() || params.len() > 2 {
            return Err(RpcErr::BadParams(format!(
                "Expected one or two params and {} were provided",
                params.len()
            )));
        }

        let raw: String = serde_json::from_value(params[0].clone())
            .map_err(|error| RpcErr::BadParams(error.to_string()))?;
        let raw = raw
            .strip_prefix("0x")
            .ok_or_else(|| RpcErr::BadParams("rawTx is not 0x-prefixed".to_owned()))?;
        let bytes = hex::decode(raw).map_err(|error| RpcErr::BadParams(error.to_string()))?;

        let transaction = Transaction::decode_canonical(&bytes)
            .map_err(|error| RpcErr::BadParams(error.to_string()))?;
        if !matches!(transaction, Transaction::FrameTransaction(_)) {
            return Err(RpcErr::BadParams(
                "rawTx is not a type-0x06 frame transaction".to_owned(),
            ));
        }

        let block = match params.get(1) {
            Some(value) => Some(BlockIdentifierOrHash::parse(value.clone(), 1)?),
            None => None,
        };

        Ok(SimulateFrameTransactionRequest { transaction, block })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let block = self
            .block
            .clone()
            .unwrap_or(BlockIdentifierOrHash::Identifier(BlockIdentifier::default()));
        let header = match block.resolve_block_header(&context.storage).await? {
            Some(header) => header,
            _ => return Ok(Value::Null),
        };

        let Transaction::FrameTransaction(frame_tx) = &self.transaction else {
            // Guaranteed by `parse`; kept as a defensive guard.
            return Err(RpcErr::BadParams(
                "rawTx is not a type-0x06 frame transaction".to_owned(),
            ));
        };

        // `max_cost` is a pure function of the tx fields and the block's blob base
        // fee (no EVM pass), so it is reported on every path, including structural
        // rejection.
        let blob_schedule = context
            .storage
            .get_chain_config()
            .get_fork_blob_schedule(header.timestamp)
            .unwrap_or_default();
        let blob_base_fee = calculate_base_fee_per_blob_gas(
            header.excess_blob_gas.unwrap_or_default(),
            blob_schedule.base_fee_update_fraction,
        );
        let max_cost = to_hex_u256(frame_tx.max_cost(blob_base_fee));

        // Derive and structurally validate the prefix. A structural error means
        // the transaction is invalid without needing an EVM pass.
        let prefix = match frame_tx.validation_prefix() {
            Ok(prefix) => prefix,
            Err(error) => return structurally_invalid(error.to_string(), max_cost),
        };
        if let Err(error) =
            frame_tx.validate_prefix_structure(&prefix, context.blockchain.options.max_verify_gas)
        {
            return structurally_invalid(error.to_string(), max_cost);
        }
        let prefix_shape = Some(prefix_shape_name(&prefix.shape).to_owned());

        // DoS guard, applied BEFORE any EVM work. Both the prefix simulation and
        // the full execution below run real opcodes bounded only by the tx's own
        // (attacker-controlled) per-frame gas limits — the prefix's MAX_VERIFY_GAS
        // ceiling is enforced only post-hoc, so an uncapped prefix frame would burn
        // unbounded CPU. Gate on the same per-tx cap `eth_estimateGas` uses (and
        // that the mempool checks before its own prefix sim); a tx above it is
        // rejected on submit (EIP-7825 / block gas limit) anyway.
        let fork = context.storage.get_chain_config().fork(header.timestamp);
        let max_allowed = get_max_allowed_gas_limit(header.gas_limit, fork);
        let total_gas_limit = frame_tx.total_gas_limit();
        if total_gas_limit > max_allowed {
            return to_value(SimulateFrameTransactionResult {
                valid: false,
                prefix_shape,
                payer: None,
                max_cost,
                violation: Some(format!(
                    "total gas limit {total_gas_limit} exceeds the per-transaction gas cap {max_allowed} (EIP-7825); not simulated"
                )),
                gas_used: None,
                frames: None,
                execution_status: None,
                execution_error: None,
            });
        }

        // Gas is bounded; run the validation-prefix simulation on a fresh,
        // throwaway state at the requested head — the same machinery the mempool
        // runs. Read-only: never touches the mempool or block building.
        let outcome = self.simulate_prefix(&context, &header, &prefix)?;
        let payer = outcome.accessed_paymaster.map(|(payer, _)| payer);

        if !outcome.passed {
            return to_value(SimulateFrameTransactionResult {
                valid: false,
                prefix_shape,
                payer,
                max_cost,
                violation: Some(
                    outcome
                        .violation
                        .unwrap_or_else(|| "validation prefix did not pass".to_owned()),
                ),
                gas_used: None,
                frames: None,
                execution_status: None,
                execution_error: None,
            });
        }

        // The prefix passed and gas is bounded (checked above); run a full
        // multi-frame execution on a SEPARATE fresh state (the prefix simulation
        // mutated its own throwaway state) for accurate total + per-frame gas.
        let (gas_used, frames, execution_status, execution_error) =
            self.execute_for_gas(&context, &header, frame_tx.sender);

        to_value(SimulateFrameTransactionResult {
            valid: true,
            prefix_shape,
            payer,
            max_cost,
            violation: None,
            gas_used,
            frames,
            execution_status,
            execution_error,
        })
    }
}

impl SimulateFrameTransactionRequest {
    /// Runs the EIP-8141 validation-prefix simulation over a fresh throwaway
    /// state at `header`.
    fn simulate_prefix(
        &self,
        context: &RpcApiContext,
        header: &BlockHeader,
        prefix: &ValidationPrefix,
    ) -> Result<FrameValidationOutcome, RpcErr> {
        let vm_db = StoreVmDatabase::new(context.storage.clone(), header.clone())?;
        let mut vm = context.blockchain.new_evm(vm_db)?;
        // EvmError maps to RpcErr::Vm (-32015) via From, matching eth_call/estimateGas.
        vm.simulate_frame_validation_prefix(
            &self.transaction,
            header,
            prefix,
            None,
            context.blockchain.options.max_verify_gas,
        )
        .map_err(RpcErr::from)
    }

    /// Executes the full transaction on a fresh throwaway state to measure
    /// total and per-frame gas. Returns `(gas_used, frames, status, error)`;
    /// on execution failure returns `(None, None, None, Some(error))` so the
    /// caller can still report the (valid) prefix outcome.
    fn execute_for_gas(
        &self,
        context: &RpcApiContext,
        header: &BlockHeader,
        sender: Address,
    ) -> (
        Option<String>,
        Option<Vec<FrameExecResult>>,
        Option<String>,
        Option<String>,
    ) {
        let vm_db = match StoreVmDatabase::new(context.storage.clone(), header.clone()) {
            Ok(db) => db,
            Err(error) => return (None, None, None, Some(error.to_string())),
        };
        let mut vm = match context.blockchain.new_evm(vm_db) {
            Ok(vm) => vm,
            Err(error) => return (None, None, None, Some(error.to_string())),
        };
        let mut cumulative_gas = 0u64;
        match vm.execute_tx(&self.transaction, header, &mut cumulative_gas, sender) {
            Ok((receipt, report)) => {
                let frames = receipt.frame_receipts.map(|frames| {
                    frames
                        .into_iter()
                        .map(|frame| FrameExecResult {
                            gas_used: format!("0x{:x}", frame.gas_used),
                            succeeded: frame.status == FRAME_RECEIPT_STATUS_SUCCESS,
                        })
                        .collect()
                });
                // For a frame tx the top-level result is Success iff every frame
                // succeeded, else a placeholder Revert (see execute_frame_tx);
                // per-frame detail is in `frames`.
                let status = if report.is_success() {
                    "success"
                } else {
                    "reverted"
                };
                (
                    Some(format!("0x{:x}", report.gas_used)),
                    frames,
                    Some(status.to_owned()),
                    None,
                )
            }
            Err(error) => (None, None, None, Some(error.to_string())),
        }
    }
}

/// Builds the `{valid: false, ...}` response for a structurally invalid prefix
/// (no EVM pass was run, so payer/prefixShape/gas are unknown; `maxCost` is a
/// pure function of the tx fields and is still reported).
fn structurally_invalid(violation: String, max_cost: String) -> Result<Value, RpcErr> {
    to_value(SimulateFrameTransactionResult {
        valid: false,
        prefix_shape: None,
        payer: None,
        max_cost,
        violation: Some(violation),
        gas_used: None,
        frames: None,
        execution_status: None,
        execution_error: None,
    })
}

fn to_hex_u256(value: U256) -> String {
    format!("0x{value:x}")
}

fn to_value(result: SimulateFrameTransactionResult) -> Result<Value, RpcErr> {
    serde_json::to_value(result).map_err(|error| RpcErr::Internal(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethrex_common::{H256, types::eip8304::IndexEntry};
    use serde_json::json;

    #[test]
    fn parses_eip8304_table_request_and_rejects_unknown_size() {
        let request = GetEip8304TableRequest::parse(&Some(vec![json!("0x40"), json!("0x10")]))
            .expect("valid table request");
        assert_eq!(request.table_size, 16);
        assert!(matches!(request.first_block, BlockIdentifier::Number(64)));

        assert!(GetEip8304TableRequest::parse(&Some(vec![json!("0x40"), json!("0x2")])).is_err());
        assert!(GetEip8304TableRequest::parse(&Some(vec![])).is_err());

        let query = QueryEip8304TableRequest::parse(&Some(vec![
            json!("0x40"),
            json!("0x10"),
            json!([{"typeId": 2, "content": format!("{:#x}", Address::zero())}]),
        ]))
        .expect("valid query request");
        assert_eq!(query.table_size, 16);
        assert_eq!(query.queries.len(), 1);
        assert!(query.candidate_type_ids.is_empty());
        let recipient_query = QueryEip8304TableRequest::parse(&Some(vec![
            json!("0x40"),
            json!("0x10"),
            json!([{"typeId": 5, "content": format!("{:#x}", H256::zero())}]),
            json!([2, 3, 4, 6]),
        ]))
        .expect("valid recipient-first query");
        assert_eq!(recipient_query.candidate_type_ids, [2, 3, 4, 6]);
        assert!(
            QueryEip8304TableRequest::parse(&Some(vec![
                json!("0x40"),
                json!("0x10"),
                json!([{"typeId": 1, "content": format!("{:#x}", H256::zero())}]),
            ]))
            .is_err()
        );

        let proofs = GetUtxoProofsRequest::parse(&Some(vec![json!([
            {"blockNumber": "0x40", "transactionIndex": "0x2", "logIndex": "0x3"}
        ])]))
        .expect("valid batched UPT request");
        assert_eq!(
            proofs.positions,
            vec![UtxoEventPosition {
                block_number: 64,
                transaction_index: 2,
                log_index: 3,
            }]
        );
        assert!(
            GetUtxoProofsRequest::parse(&Some(vec![json!([
                {"blockNumber": "0x40", "transactionIndex": "0x2", "logIndex": "0x3"},
                {"blockNumber": "0x40", "transactionIndex": "0x2", "logIndex": "0x3"}
            ])]))
            .is_err()
        );
    }

    #[test]
    fn renders_decoded_entries_and_contract_storage_slot() {
        let address = Address::from_low_u64_be(0x8312);
        let topic = H256::from_low_u64_be(0x8304);
        let transaction_hash = H256::from_low_u64_be(0x1234);
        let table = IndexTable::new(
            4,
            1,
            vec![
                IndexEntry::Transaction {
                    transaction_hash,
                    block_number: 4,
                    transaction_index: 2,
                    cumulative_log_count: 4,
                },
                IndexEntry::LogAddress {
                    address,
                    block_number: 4,
                    transaction_index: 2,
                    log_index: 3,
                },
                IndexEntry::LogTopic2 {
                    topic,
                    block_number: 4,
                    transaction_index: 2,
                    log_index: 3,
                },
                IndexEntry::LogTopic3 {
                    topic: H256::from_low_u64_be(0x5678),
                    block_number: 4,
                    transaction_index: 2,
                    log_index: 3,
                },
            ],
        )
        .expect("valid table");

        let value =
            table_to_value(&table, H256::from_low_u64_be(0x44), 4, 9).expect("serializable table");
        assert_eq!(value["firstBlock"], "0x4");
        assert_eq!(value["storageSlot"], "0x404");
        assert_eq!(value["entryCount"], "0x4");
        assert_eq!(value["loadMicros"], 9);

        let entries = value["entries"].as_array().expect("entries array");
        let address_entry = entries
            .iter()
            .find(|entry| entry["typeId"] == 2)
            .expect("address entry");
        assert_eq!(address_entry["content"], format!("{address:#x}"));
        assert_eq!(address_entry["blockNumber"], "0x4");
        assert_eq!(address_entry["transactionIndex"], "0x2");
        assert_eq!(address_entry["positionIndex"], "0x3");

        let topic_entry = entries
            .iter()
            .find(|entry| entry["typeId"] == 5)
            .expect("topic entry");
        assert_eq!(topic_entry["content"], format!("{topic:#x}"));

        let query_value = table_query_to_value(
            &table,
            H256::from_low_u64_be(0x44),
            4,
            9,
            &[Eip8304ContentQuery {
                type_id: 5,
                content: topic.as_bytes().to_vec(),
            }],
            &[2, 6],
        )
        .expect("serializable query");
        assert_eq!(query_value["queries"].as_array().unwrap().len(), 1);
        assert_eq!(
            query_value["queries"][0]["entries"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(query_value["transactions"].as_array().unwrap().len(), 1);
        assert_eq!(query_value["candidateEntries"].as_array().unwrap().len(), 2);
        assert_eq!(query_value["proofFormat"], "shared-per-table-v1");
        assert_eq!(
            query_value["transactions"][0]["content"],
            format!("{transaction_hash:#x}")
        );
        assert!(!query_value["proofNodes"].as_array().unwrap().is_empty());
    }
}
