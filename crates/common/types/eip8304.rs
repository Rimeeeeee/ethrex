//! Construction, hashing, merging, and scheduling for EIP-8304 index tables.
//!
//! The VM integration consumes the constants and calldata helper in this module.
//! [`INDEX_CONTRACT_ADDRESS`] remains explicitly unset until the EIP assigns it,
//! so the complete execution path stays dormant without a placeholder address.

use crate::{
    Address, H256,
    types::{Block, Receipt},
};
use ethrex_crypto::Crypto;
use libssz_merkle::{Sha2Hasher, Sha256Hasher, merkleize, mix_in_length};

/// Number of blocks covered by the index tables at each protocol level.
pub const TABLE_SIZES: [u64; 5] = [1, 4, 16, 64, 256];

/// Number of table roots retained in each level's system-contract ring buffer.
pub const TABLES_PER_LEVEL: u64 = 1024;

/// Gas made available to each EIP-8304 index-contract system call.
pub const INDEX_CONTRACT_GAS_LIMIT: u64 = 30_000_000;

/// Maximum number of indexed topics in a valid EVM log (`LOG0` through `LOG4`).
pub const MAX_TOPICS_PER_LOG: usize = 4;

/// Local-storage encoding version for [`IndexTable`].
const INDEX_TABLE_STORAGE_VERSION: u8 = 1;

/// System caller used for EIP-8304 index-contract updates.
pub use crate::constants::SYSTEM_ADDRESS;

/// EIP-8304 has not assigned the index contract an address yet.
///
/// Keeping the unresolved value explicit prevents an experimental placeholder
/// from accidentally becoming a consensus constant. Change this to a concrete
/// `Address` once the EIP finalizes `INDEX_CONTRACT_ADDRESS`.
/// This is to be replaced with the actual address once it is finalized in the EIP-8304 specification.
pub const INDEX_CONTRACT_ADDRESS: Option<Address> = None;

/// Build the 96-byte calldata for the index contract's `set` operation.
///
/// `first_block` and `table_size` occupy full 32-byte big-endian words; the
/// final word is the table root.
pub fn index_contract_calldata(first_block: u64, table_size: u64, table_root: H256) -> [u8; 96] {
    let mut calldata = [0u8; 96];
    calldata[24..32].copy_from_slice(&first_block.to_be_bytes());
    calldata[56..64].copy_from_slice(&table_size.to_be_bytes());
    calldata[64..].copy_from_slice(table_root.as_bytes());
    calldata
}

/// EIP-8304 index-entry type identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum IndexEntryType {
    Block = 0,
    Transaction = 1,
    LogAddress = 2,
    LogTopic0 = 3,
    LogTopic1 = 4,
    LogTopic2 = 5,
    LogTopic3 = 6,
}

/// A typed EIP-8304 index entry before canonical binary encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IndexEntry {
    Block {
        block_hash: H256,
        block_number: u64,
    },
    Transaction {
        transaction_hash: H256,
        block_number: u64,
        transaction_index: u32,
        cumulative_log_count: u32,
    },
    LogAddress {
        address: Address,
        block_number: u64,
        transaction_index: u32,
        log_index: u32,
    },
    LogTopic0 {
        topic: H256,
        block_number: u64,
        transaction_index: u32,
        log_index: u32,
    },
    LogTopic1 {
        topic: H256,
        block_number: u64,
        transaction_index: u32,
        log_index: u32,
    },
    LogTopic2 {
        topic: H256,
        block_number: u64,
        transaction_index: u32,
        log_index: u32,
    },
    LogTopic3 {
        topic: H256,
        block_number: u64,
        transaction_index: u32,
        log_index: u32,
    },
}

impl IndexEntry {
    pub const fn entry_type(&self) -> IndexEntryType {
        match self {
            Self::Block { .. } => IndexEntryType::Block,
            Self::Transaction { .. } => IndexEntryType::Transaction,
            Self::LogAddress { .. } => IndexEntryType::LogAddress,
            Self::LogTopic0 { .. } => IndexEntryType::LogTopic0,
            Self::LogTopic1 { .. } => IndexEntryType::LogTopic1,
            Self::LogTopic2 { .. } => IndexEntryType::LogTopic2,
            Self::LogTopic3 { .. } => IndexEntryType::LogTopic3,
        }
    }

    /// Fixed byte length of this entry's canonical representation.
    pub const fn encoded_len(&self) -> usize {
        match self {
            Self::Block { .. } => 42,
            Self::LogAddress { .. } => 38,
            Self::Transaction { .. }
            | Self::LogTopic0 { .. }
            | Self::LogTopic1 { .. }
            | Self::LogTopic2 { .. }
            | Self::LogTopic3 { .. } => 50,
        }
    }

    /// Encode according to EIP-8304.
    ///
    /// Every integer, including the two-byte entry type, is big-endian so
    /// ordinary bytewise ordering is the table's canonical ordering.
    pub fn encode(&self) -> EncodedIndexEntry {
        let mut encoded = Vec::with_capacity(self.encoded_len());
        encoded.extend_from_slice(&(self.entry_type() as u16).to_be_bytes());

        match self {
            Self::Block {
                block_hash,
                block_number,
            } => {
                encoded.extend_from_slice(block_hash.as_bytes());
                encoded.extend_from_slice(&block_number.to_be_bytes());
            }
            Self::Transaction {
                transaction_hash,
                block_number,
                transaction_index,
                cumulative_log_count,
            } => {
                encoded.extend_from_slice(transaction_hash.as_bytes());
                append_position(
                    &mut encoded,
                    *block_number,
                    *transaction_index,
                    *cumulative_log_count,
                );
            }
            Self::LogAddress {
                address,
                block_number,
                transaction_index,
                log_index,
            } => {
                encoded.extend_from_slice(address.as_bytes());
                append_position(&mut encoded, *block_number, *transaction_index, *log_index);
            }
            Self::LogTopic0 {
                topic,
                block_number,
                transaction_index,
                log_index,
            }
            | Self::LogTopic1 {
                topic,
                block_number,
                transaction_index,
                log_index,
            }
            | Self::LogTopic2 {
                topic,
                block_number,
                transaction_index,
                log_index,
            }
            | Self::LogTopic3 {
                topic,
                block_number,
                transaction_index,
                log_index,
            } => {
                encoded.extend_from_slice(topic.as_bytes());
                append_position(&mut encoded, *block_number, *transaction_index, *log_index);
            }
        }

        debug_assert_eq!(encoded.len(), self.encoded_len());
        EncodedIndexEntry(encoded)
    }
}

fn append_position(
    encoded: &mut Vec<u8>,
    block_number: u64,
    transaction_index: u32,
    final_index: u32,
) {
    encoded.extend_from_slice(&block_number.to_be_bytes());
    encoded.extend_from_slice(&transaction_index.to_be_bytes());
    encoded.extend_from_slice(&final_index.to_be_bytes());
}

/// Canonically encoded index entry.
///
/// The inner bytes are private so invalid, non-canonical encodings cannot be
/// inserted into an [`IndexTable`] through the public API. Derived ordering is
/// lexicographic byte ordering, as required by EIP-8304.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EncodedIndexEntry(Vec<u8>);

impl EncodedIndexEntry {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for EncodedIndexEntry {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Errors which would violate an index table's structural invariants.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IndexTableError {
    #[error("unsupported EIP-8304 table size {0}")]
    UnsupportedTableSize(u64),
    #[error("first block {first_block} is not aligned to table size {table_size}")]
    MisalignedFirstBlock { first_block: u64, table_size: u64 },
    #[error("index entry count {0} does not fit in u64")]
    EntryCountOverflow(usize),
    #[error("block contains {transactions} transactions but {receipts} receipts")]
    TransactionReceiptCountMismatch {
        transactions: usize,
        receipts: usize,
    },
    #[error("transaction index {0} does not fit in u32")]
    TransactionIndexOverflow(usize),
    #[error("log index {0} does not fit in u32")]
    LogIndexOverflow(usize),
    #[error("cumulative log count does not fit in u32")]
    CumulativeLogCountOverflow,
    #[error(
        "transaction {transaction_index} log {log_index} has {topic_count} topics; at most {MAX_TOPICS_PER_LOG} are supported"
    )]
    TooManyLogTopics {
        transaction_index: u32,
        log_index: u32,
        topic_count: usize,
    },
    #[error(
        "lower table {table_index} has size {actual}; expected all lower tables to have size {expected}"
    )]
    LowerTableSizeMismatch {
        table_index: usize,
        expected: u64,
        actual: u64,
    },
    #[error(
        "lower table {table_index} starts at block {actual}; expected adjacent table starting at {expected}"
    )]
    NonAdjacentLowerTable {
        table_index: usize,
        expected: u64,
        actual: u64,
    },
    #[error("table block range overflowed u64")]
    TableRangeOverflow,
    #[error("merged index entry count overflowed usize")]
    MergedEntryCountOverflow,
    #[error("malformed persisted EIP-8304 table: {0}")]
    MalformedStoredTable(&'static str),
    #[error("persisted EIP-8304 table root does not match its entries")]
    StoredTableRootMismatch,
}

/// An EIP-8304 index table with canonical, lexicographically sorted entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexTable {
    first_block: u64,
    table_size: u64,
    encoded_entries: Vec<EncodedIndexEntry>,
    entry_count: u64,
    table_root: H256,
}

impl IndexTable {
    /// Generate the level-0 table after all transactions and receipts for a
    /// block have been produced.
    ///
    /// The parent block entry is omitted for genesis. Each transaction records
    /// the cumulative number of logs preceding it, while each address/topic
    /// entry uses a log index relative to that transaction.
    pub fn from_block(
        block: &Block,
        receipts: &[Receipt],
        crypto: &dyn Crypto,
    ) -> Result<Self, IndexTableError> {
        let transactions = &block.body.transactions;
        if transactions.len() != receipts.len() {
            return Err(IndexTableError::TransactionReceiptCountMismatch {
                transactions: transactions.len(),
                receipts: receipts.len(),
            });
        }

        let mut entries = Vec::new();
        let block_number = block.header.number;

        if block_number > 0 {
            entries.push(IndexEntry::Block {
                block_hash: block.header.parent_hash,
                block_number: block_number - 1,
            });
        }

        let mut cumulative_log_count = 0u32;
        for (transaction_index, (transaction, receipt)) in
            transactions.iter().zip(receipts).enumerate()
        {
            let transaction_index = u32::try_from(transaction_index)
                .map_err(|_| IndexTableError::TransactionIndexOverflow(transaction_index))?;

            entries.push(IndexEntry::Transaction {
                transaction_hash: transaction.hash(crypto),
                block_number,
                transaction_index,
                cumulative_log_count,
            });

            for (log_index, log) in receipt.logs.iter().enumerate() {
                let log_index = u32::try_from(log_index)
                    .map_err(|_| IndexTableError::LogIndexOverflow(log_index))?;
                if log.topics.len() > MAX_TOPICS_PER_LOG {
                    return Err(IndexTableError::TooManyLogTopics {
                        transaction_index,
                        log_index,
                        topic_count: log.topics.len(),
                    });
                }

                entries.push(IndexEntry::LogAddress {
                    address: log.address,
                    block_number,
                    transaction_index,
                    log_index,
                });
                for (topic_index, topic) in log.topics.iter().copied().enumerate() {
                    let topic_entry = match topic_index {
                        0 => IndexEntry::LogTopic0 {
                            topic,
                            block_number,
                            transaction_index,
                            log_index,
                        },
                        1 => IndexEntry::LogTopic1 {
                            topic,
                            block_number,
                            transaction_index,
                            log_index,
                        },
                        2 => IndexEntry::LogTopic2 {
                            topic,
                            block_number,
                            transaction_index,
                            log_index,
                        },
                        3 => IndexEntry::LogTopic3 {
                            topic,
                            block_number,
                            transaction_index,
                            log_index,
                        },
                        _ => unreachable!("topic count was checked above"),
                    };
                    entries.push(topic_entry);
                }
            }

            let receipt_log_count = u32::try_from(receipt.logs.len())
                .map_err(|_| IndexTableError::CumulativeLogCountOverflow)?;
            cumulative_log_count = cumulative_log_count
                .checked_add(receipt_log_count)
                .ok_or(IndexTableError::CumulativeLogCountOverflow)?;
        }

        Self::new(block_number, TABLE_SIZES[0], entries)
    }

    /// Construct a table, canonicalize its entry ordering, and calculate its
    /// EIP-8304 SSZ table root.
    pub fn new(
        first_block: u64,
        table_size: u64,
        entries: Vec<IndexEntry>,
    ) -> Result<Self, IndexTableError> {
        let mut encoded_entries: Vec<_> = entries.iter().map(IndexEntry::encode).collect();
        encoded_entries.sort_unstable();

        Self::from_sorted_entries(first_block, table_size, encoded_entries)
    }

    /// Merge four adjacent lower-level tables without reading or rebuilding
    /// their source blocks.
    ///
    /// The inputs must have the same size, cover consecutive ranges, and begin
    /// on the next level's boundary. Their already-sorted encoded entries are
    /// combined with a four-way merge and hashed into the new table root.
    pub fn merge(lower_tables: [&Self; 4]) -> Result<Self, IndexTableError> {
        let lower_size = lower_tables[0].table_size;
        let table_size = lower_size
            .checked_mul(4)
            .ok_or(IndexTableError::TableRangeOverflow)?;
        if !TABLE_SIZES.contains(&table_size) {
            return Err(IndexTableError::UnsupportedTableSize(table_size));
        }

        let first_block = lower_tables[0].first_block;
        validate_table_identity(first_block, table_size)?;

        let mut merged_len = 0usize;
        for (table_index, table) in lower_tables.iter().enumerate() {
            if table.table_size != lower_size {
                return Err(IndexTableError::LowerTableSizeMismatch {
                    table_index,
                    expected: lower_size,
                    actual: table.table_size,
                });
            }
            let expected = first_block
                .checked_add(
                    lower_size
                        .checked_mul(table_index as u64)
                        .ok_or(IndexTableError::TableRangeOverflow)?,
                )
                .ok_or(IndexTableError::TableRangeOverflow)?;
            if table.first_block != expected {
                return Err(IndexTableError::NonAdjacentLowerTable {
                    table_index,
                    expected,
                    actual: table.first_block,
                });
            }
            merged_len = merged_len
                .checked_add(table.encoded_entries.len())
                .ok_or(IndexTableError::MergedEntryCountOverflow)?;
        }

        let mut cursors = [0usize; 4];
        let mut encoded_entries = Vec::with_capacity(merged_len);
        while encoded_entries.len() < merged_len {
            let mut selected_table: Option<usize> = None;
            for table_index in 0..lower_tables.len() {
                if cursors[table_index] == lower_tables[table_index].encoded_entries.len() {
                    continue;
                }
                match selected_table {
                    Some(selected)
                        if lower_tables[selected].encoded_entries[cursors[selected]]
                            <= lower_tables[table_index].encoded_entries[cursors[table_index]] => {}
                    _ => selected_table = Some(table_index),
                }
            }

            let selected_table = selected_table.expect("merged length guarantees an entry");
            encoded_entries.push(
                lower_tables[selected_table].encoded_entries[cursors[selected_table]].clone(),
            );
            cursors[selected_table] += 1;
        }

        Self::from_sorted_entries(first_block, table_size, encoded_entries)
    }

    fn from_sorted_entries(
        first_block: u64,
        table_size: u64,
        encoded_entries: Vec<EncodedIndexEntry>,
    ) -> Result<Self, IndexTableError> {
        validate_table_identity(first_block, table_size)?;
        debug_assert!(encoded_entries.windows(2).all(|pair| pair[0] <= pair[1]));

        let entry_count = u64::try_from(encoded_entries.len())
            .map_err(|_| IndexTableError::EntryCountOverflow(encoded_entries.len()))?;
        let table_root = calculate_table_root(&encoded_entries);

        Ok(Self {
            first_block,
            table_size,
            encoded_entries,
            entry_count,
            table_root,
        })
    }

    pub const fn first_block(&self) -> u64 {
        self.first_block
    }

    pub const fn table_size(&self) -> u64 {
        self.table_size
    }

    pub fn encoded_entries(&self) -> &[EncodedIndexEntry] {
        &self.encoded_entries
    }

    pub const fn entry_count(&self) -> u64 {
        self.entry_count
    }

    pub const fn table_root(&self) -> H256 {
        self.table_root
    }

    /// Protocol level corresponding to this table's size.
    pub fn level(&self) -> usize {
        TABLE_SIZES
            .iter()
            .position(|size| *size == self.table_size)
            .expect("IndexTable construction validates table_size")
    }

    /// Last block covered by this table.
    pub fn end_block(&self) -> Result<u64, IndexTableError> {
        self.first_block
            .checked_add(self.table_size - 1)
            .ok_or(IndexTableError::TableRangeOverflow)
    }

    /// Encode this table for local persistence.
    ///
    /// This is deliberately not a consensus encoding. The root is stored as an
    /// integrity check and recomputed when loading.
    pub fn encode_storage(&self) -> Vec<u8> {
        let entries_len: usize = self
            .encoded_entries
            .iter()
            .map(|entry| 2 + entry.as_bytes().len())
            .sum();
        let mut encoded = Vec::with_capacity(1 + 8 + 8 + 8 + 32 + entries_len);
        encoded.push(INDEX_TABLE_STORAGE_VERSION);
        encoded.extend_from_slice(&self.first_block.to_be_bytes());
        encoded.extend_from_slice(&self.table_size.to_be_bytes());
        encoded.extend_from_slice(&self.entry_count.to_be_bytes());
        encoded.extend_from_slice(self.table_root.as_bytes());
        for entry in &self.encoded_entries {
            let entry_len = u16::try_from(entry.as_bytes().len())
                .expect("EIP-8304 entries are at most 50 bytes");
            encoded.extend_from_slice(&entry_len.to_be_bytes());
            encoded.extend_from_slice(entry.as_bytes());
        }
        encoded
    }

    /// Decode and validate a locally persisted table.
    pub fn decode_storage(encoded: &[u8]) -> Result<Self, IndexTableError> {
        const HEADER_LEN: usize = 1 + 8 + 8 + 8 + 32;
        if encoded.len() < HEADER_LEN {
            return Err(IndexTableError::MalformedStoredTable("truncated header"));
        }
        if encoded[0] != INDEX_TABLE_STORAGE_VERSION {
            return Err(IndexTableError::MalformedStoredTable(
                "unsupported storage version",
            ));
        }

        let first_block = u64::from_be_bytes(
            encoded[1..9]
                .try_into()
                .map_err(|_| IndexTableError::MalformedStoredTable("invalid first block"))?,
        );
        let table_size = u64::from_be_bytes(
            encoded[9..17]
                .try_into()
                .map_err(|_| IndexTableError::MalformedStoredTable("invalid table size"))?,
        );
        validate_table_identity(first_block, table_size)?;
        let entry_count = u64::from_be_bytes(
            encoded[17..25]
                .try_into()
                .map_err(|_| IndexTableError::MalformedStoredTable("invalid entry count"))?,
        );
        let stored_root = H256::from_slice(&encoded[25..57]);
        let entry_capacity = usize::try_from(entry_count)
            .map_err(|_| IndexTableError::MalformedStoredTable("entry count exceeds usize"))?;
        // Every entry takes at least a two-byte length plus 38 payload bytes.
        // Reject an impossible count before reserving attacker/corruption-sized
        // memory based solely on local database metadata.
        if entry_capacity > encoded.len().saturating_sub(HEADER_LEN) / 40 {
            return Err(IndexTableError::MalformedStoredTable(
                "entry count exceeds encoded payload",
            ));
        }
        let mut entries = Vec::with_capacity(entry_capacity);
        let mut offset = HEADER_LEN;
        while offset < encoded.len() {
            let length_end = offset
                .checked_add(2)
                .ok_or(IndexTableError::MalformedStoredTable(
                    "entry offset overflow",
                ))?;
            let length_bytes =
                encoded
                    .get(offset..length_end)
                    .ok_or(IndexTableError::MalformedStoredTable(
                        "truncated entry length",
                    ))?;
            let entry_len = u16::from_be_bytes(
                length_bytes
                    .try_into()
                    .map_err(|_| IndexTableError::MalformedStoredTable("invalid entry length"))?,
            ) as usize;
            offset = length_end;
            let entry_end =
                offset
                    .checked_add(entry_len)
                    .ok_or(IndexTableError::MalformedStoredTable(
                        "entry offset overflow",
                    ))?;
            let entry = encoded
                .get(offset..entry_end)
                .ok_or(IndexTableError::MalformedStoredTable("truncated entry"))?;
            validate_encoded_entry(entry)?;
            entries.push(EncodedIndexEntry(entry.to_vec()));
            offset = entry_end;
        }

        if entries.len() != entry_capacity {
            return Err(IndexTableError::MalformedStoredTable(
                "entry count does not match payload",
            ));
        }
        if !entries.windows(2).all(|pair| pair[0] <= pair[1]) {
            return Err(IndexTableError::MalformedStoredTable(
                "entries are not sorted",
            ));
        }
        let calculated_root = calculate_table_root(&entries);
        if calculated_root != stored_root {
            return Err(IndexTableError::StoredTableRootMismatch);
        }

        Ok(Self {
            first_block,
            table_size,
            encoded_entries: entries,
            entry_count,
            table_root: calculated_root,
        })
    }
}

fn validate_encoded_entry(encoded: &[u8]) -> Result<(), IndexTableError> {
    let type_bytes = encoded
        .get(..2)
        .ok_or(IndexTableError::MalformedStoredTable(
            "entry has no type id",
        ))?;
    let type_id = u16::from_be_bytes(
        type_bytes
            .try_into()
            .map_err(|_| IndexTableError::MalformedStoredTable("invalid type id"))?,
    );
    let expected_len = match type_id {
        0 => 42,
        1 | 3..=6 => 50,
        2 => 38,
        _ => {
            return Err(IndexTableError::MalformedStoredTable(
                "unknown entry type id",
            ));
        }
    };
    if encoded.len() != expected_len {
        return Err(IndexTableError::MalformedStoredTable(
            "entry has invalid encoded length",
        ));
    }
    Ok(())
}

fn validate_table_identity(first_block: u64, table_size: u64) -> Result<(), IndexTableError> {
    if !TABLE_SIZES.contains(&table_size) {
        return Err(IndexTableError::UnsupportedTableSize(table_size));
    }
    if !first_block.is_multiple_of(table_size) {
        return Err(IndexTableError::MisalignedFirstBlock {
            first_block,
            table_size,
        });
    }
    Ok(())
}

/// Calculate the EIP-8304 table root from canonical encoded entries.
///
/// Each entry is first SHA-256 hashed. Those hashes are treated as the leaves
/// of `List[Hash32, entry_count]`: they are SSZ-merkleized with a limit equal to
/// the entry count, then the count is mixed into the root using SSZ's
/// little-endian length node.
pub fn calculate_table_root(entries: &[EncodedIndexEntry]) -> H256 {
    let entry_hashes: Vec<_> = entries
        .iter()
        .map(|entry| Sha2Hasher.hash(entry.as_bytes()))
        .collect();
    let merkle_root = merkleize(&Sha2Hasher, &entry_hashes, Some(entry_hashes.len()));
    H256(mix_in_length(&Sha2Hasher, &merkle_root, entry_hashes.len()))
}

/// A table whose root is due to be committed while processing `commit_block`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ScheduledIndexTable {
    level: usize,
    first_block: u64,
    table_size: u64,
    commit_block: u64,
}

impl ScheduledIndexTable {
    pub const fn level(&self) -> usize {
        self.level
    }

    pub const fn first_block(&self) -> u64 {
        self.first_block
    }

    pub const fn table_size(&self) -> u64 {
        self.table_size
    }

    pub const fn commit_block(&self) -> u64 {
        self.commit_block
    }
}

/// Return all index tables due for commitment at the end of `block_number`.
///
/// Level 0 is due immediately. A higher-level table covering
/// `first_block..first_block + table_size - 1` is due after an additional
/// `table_size / 4` blocks. `is_active_at_first_block` must evaluate EIP-8304
/// activation using the timestamp of the supplied block number; candidates for
/// which it returns `false` are skipped.
pub fn tables_due_for_commitment(
    block_number: u64,
    mut is_active_at_first_block: impl FnMut(u64) -> bool,
) -> Vec<ScheduledIndexTable> {
    TABLE_SIZES
        .iter()
        .copied()
        .enumerate()
        .filter_map(|(level, table_size)| {
            let first_block = if level == 0 {
                block_number
            } else {
                let commit_offset = table_size.checked_add(table_size / 4)?.checked_sub(1)?;
                let first_block = block_number.checked_sub(commit_offset)?;
                first_block
                    .is_multiple_of(table_size)
                    .then_some(first_block)?
            };

            is_active_at_first_block(first_block).then_some(ScheduledIndexTable {
                level,
                first_block,
                table_size,
                commit_block: block_number,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Bytes, NativeCrypto,
        types::{BlockBody, BlockHeader, LegacyTransaction, Log, Transaction, TxType},
    };

    fn repeated_hash(byte: u8) -> H256 {
        H256::repeat_byte(byte)
    }

    fn transaction(nonce: u64) -> Transaction {
        Transaction::LegacyTransaction(LegacyTransaction {
            nonce,
            ..Default::default()
        })
    }

    fn block(number: u64, transactions: Vec<Transaction>) -> Block {
        Block {
            header: BlockHeader {
                number,
                parent_hash: repeated_hash(0x99),
                ..Default::default()
            },
            body: BlockBody {
                transactions,
                ..BlockBody::empty()
            },
        }
    }

    fn receipt(logs: Vec<Log>) -> Receipt {
        Receipt::new(TxType::Legacy, true, 0, logs)
    }

    fn entry_type_id(entry: &EncodedIndexEntry) -> u16 {
        u16::from_be_bytes(entry.as_bytes()[..2].try_into().unwrap())
    }

    fn encoded_u32(entry: &EncodedIndexEntry, start: usize) -> u32 {
        u32::from_be_bytes(entry.as_bytes()[start..start + 4].try_into().unwrap())
    }

    #[test]
    fn constants_match_eip() {
        assert_eq!(TABLE_SIZES, [1, 4, 16, 64, 256]);
        assert_eq!(TABLES_PER_LEVEL, 1024);
        let mut expected_system_address = [0xff; 20];
        expected_system_address[19] = 0xfe;
        assert_eq!(SYSTEM_ADDRESS, Address::from(expected_system_address));
        assert_eq!(INDEX_CONTRACT_ADDRESS, None);
        assert_eq!(INDEX_CONTRACT_GAS_LIMIT, 30_000_000);
    }

    #[test]
    fn index_contract_calldata_uses_three_big_endian_words() {
        let root = repeated_hash(0xab);
        let calldata = index_contract_calldata(0x0102_0304_0506_0708, 0x1112_1314_1516_1718, root);

        assert_eq!(calldata.len(), 96);
        assert_eq!(&calldata[..24], &[0; 24]);
        assert_eq!(&calldata[24..32], &0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(&calldata[32..56], &[0; 24]);
        assert_eq!(&calldata[56..64], &0x1112_1314_1516_1718u64.to_be_bytes());
        assert_eq!(&calldata[64..], root.as_bytes());
    }

    #[test]
    fn activation_uses_the_dedicated_timestamp() {
        let config = crate::types::ChainConfig::default();
        assert!(!config.is_eip8304_activated(u64::MAX));

        let config = crate::types::ChainConfig {
            eip8304_time: Some(100),
            ..Default::default()
        };
        assert!(!config.is_eip8304_activated(99));
        assert!(config.is_eip8304_activated(100));
        assert!(config.is_eip8304_activated(101));
    }

    #[test]
    fn block_entry_encoding_is_big_endian() {
        let entry = IndexEntry::Block {
            block_hash: repeated_hash(0xaa),
            block_number: 0x0102_0304_0506_0708,
        };
        let encoded = entry.encode();

        assert_eq!(encoded.as_bytes().len(), 42);
        assert_eq!(&encoded.as_bytes()[..2], &[0x00, 0x00]);
        assert_eq!(&encoded.as_bytes()[2..34], &[0xaa; 32]);
        assert_eq!(
            &encoded.as_bytes()[34..],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn transaction_entry_encoding_is_big_endian() {
        let entry = IndexEntry::Transaction {
            transaction_hash: repeated_hash(0xbb),
            block_number: 0x0102_0304_0506_0708,
            transaction_index: 0x1112_1314,
            cumulative_log_count: 0x2122_2324,
        };
        let encoded = entry.encode();

        assert_eq!(encoded.as_bytes().len(), 50);
        assert_eq!(&encoded.as_bytes()[..2], &[0x00, 0x01]);
        assert_eq!(&encoded.as_bytes()[2..34], &[0xbb; 32]);
        assert_eq!(
            &encoded.as_bytes()[34..],
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22,
                0x23, 0x24,
            ]
        );
    }

    #[test]
    fn log_address_entry_encoding_is_big_endian() {
        let entry = IndexEntry::LogAddress {
            address: Address::repeat_byte(0xcc),
            block_number: 9,
            transaction_index: 2,
            log_index: 3,
        };
        let encoded = entry.encode();

        assert_eq!(encoded.as_bytes().len(), 38);
        assert_eq!(&encoded.as_bytes()[..2], &[0x00, 0x02]);
        assert_eq!(&encoded.as_bytes()[2..22], &[0xcc; 20]);
        assert_eq!(&encoded.as_bytes()[22..30], &9u64.to_be_bytes());
        assert_eq!(&encoded.as_bytes()[30..34], &2u32.to_be_bytes());
        assert_eq!(&encoded.as_bytes()[34..], &3u32.to_be_bytes());
    }

    #[test]
    fn topic_entry_type_ids_cover_all_four_positions() {
        let entries = [
            IndexEntry::LogTopic0 {
                topic: repeated_hash(0),
                block_number: 1,
                transaction_index: 2,
                log_index: 3,
            },
            IndexEntry::LogTopic1 {
                topic: repeated_hash(1),
                block_number: 1,
                transaction_index: 2,
                log_index: 3,
            },
            IndexEntry::LogTopic2 {
                topic: repeated_hash(2),
                block_number: 1,
                transaction_index: 2,
                log_index: 3,
            },
            IndexEntry::LogTopic3 {
                topic: repeated_hash(3),
                block_number: 1,
                transaction_index: 2,
                log_index: 3,
            },
        ];

        for (entry, expected_id) in entries.iter().zip(3u16..=6) {
            let encoded = entry.encode();
            assert_eq!(encoded.as_bytes().len(), 50);
            assert_eq!(&encoded.as_bytes()[..2], &expected_id.to_be_bytes());
        }
    }

    #[test]
    fn single_block_generation_indexes_parent_transactions_and_actual_log_topics() {
        let block = block(10, vec![transaction(0), transaction(1)]);
        let receipts = vec![
            receipt(vec![
                Log {
                    address: Address::repeat_byte(0xa0),
                    topics: Vec::new(),
                    data: Bytes::new(),
                },
                Log {
                    address: Address::repeat_byte(0xa1),
                    topics: vec![repeated_hash(0x10), repeated_hash(0x11)],
                    data: Bytes::new(),
                },
            ]),
            receipt(vec![Log {
                address: Address::repeat_byte(0xb0),
                topics: vec![
                    repeated_hash(0x20),
                    repeated_hash(0x21),
                    repeated_hash(0x22),
                    repeated_hash(0x23),
                ],
                data: Bytes::new(),
            }]),
        ];

        let table = IndexTable::from_block(&block, &receipts, &NativeCrypto).unwrap();

        assert_eq!(table.first_block(), 10);
        assert_eq!(table.table_size(), 1);
        assert_eq!(table.entry_count(), 12);
        assert!(
            table
                .encoded_entries()
                .windows(2)
                .all(|pair| pair[0] <= pair[1])
        );

        let block_entry = table
            .encoded_entries()
            .iter()
            .find(|entry| entry_type_id(entry) == IndexEntryType::Block as u16)
            .unwrap();
        assert_eq!(
            &block_entry.as_bytes()[2..34],
            block.header.parent_hash.as_bytes()
        );
        assert_eq!(&block_entry.as_bytes()[34..], &9u64.to_be_bytes());

        let mut transaction_positions: Vec<_> = table
            .encoded_entries()
            .iter()
            .filter(|entry| entry_type_id(entry) == IndexEntryType::Transaction as u16)
            .map(|entry| (encoded_u32(entry, 42), encoded_u32(entry, 46)))
            .collect();
        transaction_positions.sort_unstable();
        assert_eq!(transaction_positions, [(0, 0), (1, 2)]);

        let mut log_positions: Vec<_> = table
            .encoded_entries()
            .iter()
            .filter(|entry| entry_type_id(entry) == IndexEntryType::LogAddress as u16)
            .map(|entry| (encoded_u32(entry, 30), encoded_u32(entry, 34)))
            .collect();
        log_positions.sort_unstable();
        assert_eq!(log_positions, [(0, 0), (0, 1), (1, 0)]);

        let topic_counts: Vec<_> = (IndexEntryType::LogTopic0 as u16
            ..=IndexEntryType::LogTopic3 as u16)
            .map(|topic_type| {
                table
                    .encoded_entries()
                    .iter()
                    .filter(|entry| entry_type_id(entry) == topic_type)
                    .count()
            })
            .collect();
        assert_eq!(topic_counts, [2, 2, 1, 1]);
        assert_eq!(
            table.table_root(),
            calculate_table_root(table.encoded_entries())
        );
    }

    #[test]
    fn genesis_generation_omits_parent_entry() {
        let block = block(0, Vec::new());
        let table = IndexTable::from_block(&block, &[], &NativeCrypto).unwrap();

        assert_eq!(table.entry_count(), 0);
        assert!(table.encoded_entries().is_empty());
    }

    #[test]
    fn single_block_generation_validates_receipts_and_topic_count() {
        let block = block(1, vec![transaction(0)]);
        assert_eq!(
            IndexTable::from_block(&block, &[], &NativeCrypto),
            Err(IndexTableError::TransactionReceiptCountMismatch {
                transactions: 1,
                receipts: 0,
            })
        );

        let receipts = [receipt(vec![Log {
            address: Address::zero(),
            topics: vec![H256::zero(); MAX_TOPICS_PER_LOG + 1],
            data: Bytes::new(),
        }])];
        assert_eq!(
            IndexTable::from_block(&block, &receipts, &NativeCrypto),
            Err(IndexTableError::TooManyLogTopics {
                transaction_index: 0,
                log_index: 0,
                topic_count: 5,
            })
        );
    }

    #[test]
    fn table_root_hashes_entries_and_mixes_in_count() {
        assert_eq!(
            calculate_table_root(&[]),
            H256::from_slice(
                &hex::decode("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b")
                    .unwrap()
            )
        );

        let entry = IndexEntry::Block {
            block_hash: repeated_hash(0xaa),
            block_number: 7,
        }
        .encode();
        let entry_hash = Sha2Hasher.hash(entry.as_bytes());
        let mut length_node = [0u8; 32];
        length_node[..8].copy_from_slice(&1u64.to_le_bytes());
        let mut root_preimage = [0u8; 64];
        root_preimage[..32].copy_from_slice(&entry_hash);
        root_preimage[32..].copy_from_slice(&length_node);

        assert_eq!(
            calculate_table_root(std::slice::from_ref(&entry)),
            H256(Sha2Hasher.hash(&root_preimage))
        );

        let second_entry = IndexEntry::Block {
            block_hash: repeated_hash(0xbb),
            block_number: 8,
        }
        .encode();
        let second_hash = Sha2Hasher.hash(second_entry.as_bytes());
        let mut pair_preimage = [0u8; 64];
        pair_preimage[..32].copy_from_slice(&entry_hash);
        pair_preimage[32..].copy_from_slice(&second_hash);
        let pair_root = Sha2Hasher.hash(&pair_preimage);
        length_node[..8].copy_from_slice(&2u64.to_le_bytes());
        root_preimage[..32].copy_from_slice(&pair_root);
        root_preimage[32..].copy_from_slice(&length_node);
        assert_eq!(
            calculate_table_root(&[entry, second_entry]),
            H256(Sha2Hasher.hash(&root_preimage))
        );
    }

    #[test]
    fn merge_combines_four_sorted_lower_tables_without_blocks() {
        let lower_tables = [
            IndexTable::new(
                0,
                1,
                vec![IndexEntry::Block {
                    block_hash: repeated_hash(0xff),
                    block_number: 0,
                }],
            )
            .unwrap(),
            IndexTable::new(
                1,
                1,
                vec![IndexEntry::Block {
                    block_hash: repeated_hash(0x00),
                    block_number: 1,
                }],
            )
            .unwrap(),
            IndexTable::new(
                2,
                1,
                vec![IndexEntry::Block {
                    block_hash: repeated_hash(0x80),
                    block_number: 2,
                }],
            )
            .unwrap(),
            IndexTable::new(
                3,
                1,
                vec![IndexEntry::Block {
                    block_hash: repeated_hash(0x40),
                    block_number: 3,
                }],
            )
            .unwrap(),
        ];
        let mut expected_entries: Vec<_> = lower_tables
            .iter()
            .flat_map(|table| table.encoded_entries().iter().cloned())
            .collect();
        expected_entries.sort_unstable();

        let merged = IndexTable::merge([
            &lower_tables[0],
            &lower_tables[1],
            &lower_tables[2],
            &lower_tables[3],
        ])
        .unwrap();

        assert_eq!(merged.first_block(), 0);
        assert_eq!(merged.table_size(), 4);
        assert_eq!(merged.entry_count(), 4);
        assert_eq!(merged.encoded_entries(), expected_entries);
        assert_eq!(merged.table_root(), calculate_table_root(&expected_entries));
    }

    #[test]
    fn merge_rejects_non_adjacent_or_misaligned_lower_tables() {
        let table = |first_block| IndexTable::new(first_block, 1, Vec::new()).unwrap();
        let non_adjacent = [table(0), table(1), table(3), table(4)];
        assert_eq!(
            IndexTable::merge([
                &non_adjacent[0],
                &non_adjacent[1],
                &non_adjacent[2],
                &non_adjacent[3],
            ]),
            Err(IndexTableError::NonAdjacentLowerTable {
                table_index: 2,
                expected: 2,
                actual: 3,
            })
        );

        let misaligned = [table(1), table(2), table(3), table(4)];
        assert_eq!(
            IndexTable::merge([
                &misaligned[0],
                &misaligned[1],
                &misaligned[2],
                &misaligned[3],
            ]),
            Err(IndexTableError::MisalignedFirstBlock {
                first_block: 1,
                table_size: 4,
            })
        );
    }

    #[test]
    fn scheduling_applies_level_delays_and_activation_at_first_block() {
        let due_at_zero = tables_due_for_commitment(0, |_| true);
        assert_eq!(due_at_zero.len(), 1);
        assert_eq!(due_at_zero[0].level(), 0);
        assert_eq!(due_at_zero[0].first_block(), 0);
        assert_eq!(due_at_zero[0].commit_block(), 0);

        let due_at_four = tables_due_for_commitment(4, |_| true);
        assert_eq!(due_at_four.len(), 2);
        assert_eq!(due_at_four[0].table_size(), 1);
        assert_eq!(due_at_four[0].first_block(), 4);
        assert_eq!(due_at_four[1].table_size(), 4);
        assert_eq!(due_at_four[1].first_block(), 0);

        for (commit_block, expected_level, expected_size) in
            [(19, 2, 16), (79, 3, 64), (319, 4, 256)]
        {
            let due = tables_due_for_commitment(commit_block, |_| true);
            assert!(due.iter().any(|schedule| {
                schedule.level() == expected_level
                    && schedule.table_size() == expected_size
                    && schedule.first_block() == 0
            }));
        }

        let activation_block = 4;
        let due_at_four =
            tables_due_for_commitment(4, |first_block| first_block >= activation_block);
        assert_eq!(due_at_four.len(), 1);
        assert_eq!(due_at_four[0].level(), 0);
        assert_eq!(due_at_four[0].first_block(), activation_block);
        assert!(tables_due_for_commitment(3, |_| false).is_empty());
    }

    #[test]
    fn higher_level_schedules_only_at_the_exact_delay_boundary() {
        for (level, table_size) in TABLE_SIZES.iter().copied().enumerate().skip(1) {
            let commit_block = table_size - 1 + table_size / 4;
            assert!(
                !tables_due_for_commitment(commit_block - 1, |_| true)
                    .iter()
                    .any(|schedule| schedule.level() == level)
            );
            let due = tables_due_for_commitment(commit_block, |_| true);
            let schedule = due
                .iter()
                .find(|schedule| schedule.level() == level)
                .unwrap();
            assert_eq!(schedule.first_block(), 0);
            assert_eq!(schedule.table_size(), table_size);
            assert_eq!(schedule.commit_block(), commit_block);
            assert!(
                !tables_due_for_commitment(commit_block + 1, |_| true)
                    .iter()
                    .any(|schedule| schedule.level() == level)
            );
        }
    }

    #[test]
    fn table_constructor_sorts_encoded_entries_and_derives_count() {
        let entries = vec![
            IndexEntry::Transaction {
                transaction_hash: repeated_hash(0),
                block_number: 4,
                transaction_index: 0,
                cumulative_log_count: 0,
            },
            IndexEntry::Block {
                block_hash: repeated_hash(0xff),
                block_number: 3,
            },
            IndexEntry::LogAddress {
                address: Address::zero(),
                block_number: 4,
                transaction_index: 0,
                log_index: 0,
            },
        ];

        let table = IndexTable::new(4, 1, entries).unwrap();

        assert_eq!(table.first_block(), 4);
        assert_eq!(table.table_size(), 1);
        assert_eq!(table.entry_count(), 3);
        assert_eq!(
            table.table_root(),
            calculate_table_root(table.encoded_entries())
        );
        assert!(
            table
                .encoded_entries()
                .windows(2)
                .all(|pair| pair[0] <= pair[1])
        );
        assert_eq!(table.encoded_entries()[0].as_bytes()[..2], [0x00, 0x00]);
        assert_eq!(table.encoded_entries()[1].as_bytes()[..2], [0x00, 0x01]);
        assert_eq!(table.encoded_entries()[2].as_bytes()[..2], [0x00, 0x02]);
    }

    #[test]
    fn table_constructor_rejects_invalid_size_and_alignment() {
        assert_eq!(
            IndexTable::new(0, 2, Vec::new()),
            Err(IndexTableError::UnsupportedTableSize(2))
        );
        assert_eq!(
            IndexTable::new(3, 4, Vec::new()),
            Err(IndexTableError::MisalignedFirstBlock {
                first_block: 3,
                table_size: 4,
            })
        );
    }

    #[test]
    fn persisted_table_round_trips_and_detects_corruption() {
        let table = IndexTable::new(
            4,
            1,
            vec![
                IndexEntry::Block {
                    block_hash: repeated_hash(0x42),
                    block_number: 3,
                },
                IndexEntry::LogAddress {
                    address: Address::repeat_byte(0x24),
                    block_number: 4,
                    transaction_index: 1,
                    log_index: 2,
                },
            ],
        )
        .unwrap();
        let encoded = table.encode_storage();
        assert_eq!(IndexTable::decode_storage(&encoded).unwrap(), table);

        let mut corrupt = encoded;
        *corrupt.last_mut().unwrap() ^= 1;
        assert_eq!(
            IndexTable::decode_storage(&corrupt),
            Err(IndexTableError::StoredTableRootMismatch)
        );
    }
}
