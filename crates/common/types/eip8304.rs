//! Core data types and canonical entry encoding for EIP-8304 index tables.
//!
//! Table construction from blocks/receipts, SSZ root calculation, multi-block
//! merging, and the index-contract system call are intentionally separate
//! follow-up steps. This module establishes the consensus-facing constants and
//! byte encodings they will share.

use crate::{Address, H256};

/// Number of blocks covered by the index tables at each protocol level.
pub const TABLE_SIZES: [u64; 5] = [1, 4, 16, 64, 256];

/// Number of table roots retained in each level's system-contract ring buffer.
pub const TABLES_PER_LEVEL: u64 = 1024;

/// System caller used for EIP-8304 index-contract updates.
pub use crate::constants::SYSTEM_ADDRESS;

/// EIP-8304 has not assigned the index contract an address yet.
///
/// Keeping the unresolved value explicit prevents an experimental placeholder
/// from accidentally becoming a consensus constant. Change this to a concrete
/// `Address` once the EIP finalizes `INDEX_CONTRACT_ADDRESS`.
/// This is to be replaced with the actual address once it is finalized in the EIP-8304 specification.
pub const INDEX_CONTRACT_ADDRESS: Option<Address> = None;

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
    /// Construct a table and canonicalize its entry ordering.
    ///
    /// `table_root` is supplied by the caller for now. SSZ root calculation is
    /// deliberately left for the next implementation stage.
    pub fn new(
        first_block: u64,
        table_size: u64,
        entries: Vec<IndexEntry>,
        table_root: H256,
    ) -> Result<Self, IndexTableError> {
        if !TABLE_SIZES.contains(&table_size) {
            return Err(IndexTableError::UnsupportedTableSize(table_size));
        }
        if !first_block.is_multiple_of(table_size) {
            return Err(IndexTableError::MisalignedFirstBlock {
                first_block,
                table_size,
            });
        }

        let entry_count = u64::try_from(entries.len())
            .map_err(|_| IndexTableError::EntryCountOverflow(entries.len()))?;
        let mut encoded_entries: Vec<_> = entries.iter().map(IndexEntry::encode).collect();
        encoded_entries.sort_unstable();

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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repeated_hash(byte: u8) -> H256 {
        H256::repeat_byte(byte)
    }

    #[test]
    fn constants_match_eip() {
        assert_eq!(TABLE_SIZES, [1, 4, 16, 64, 256]);
        assert_eq!(TABLES_PER_LEVEL, 1024);
        let mut expected_system_address = [0xff; 20];
        expected_system_address[19] = 0xfe;
        assert_eq!(SYSTEM_ADDRESS, Address::from(expected_system_address));
        assert_eq!(INDEX_CONTRACT_ADDRESS, None);
    }

    #[test]
    fn activation_uses_the_dedicated_timestamp() {
        let mut config = crate::types::ChainConfig::default();
        assert!(!config.is_eip8304_activated(u64::MAX));

        config.eip8304_time = Some(100);
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

        let table = IndexTable::new(4, 1, entries, repeated_hash(0x42)).unwrap();

        assert_eq!(table.first_block(), 4);
        assert_eq!(table.table_size(), 1);
        assert_eq!(table.entry_count(), 3);
        assert_eq!(table.table_root(), repeated_hash(0x42));
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
            IndexTable::new(0, 2, Vec::new(), H256::zero()),
            Err(IndexTableError::UnsupportedTableSize(2))
        );
        assert_eq!(
            IndexTable::new(3, 4, Vec::new(), H256::zero()),
            Err(IndexTableError::MisalignedFirstBlock {
                first_block: 3,
                table_size: 4,
            })
        );
    }
}
