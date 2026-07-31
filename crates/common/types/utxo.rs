//! Experimental native-UTXO frame payload types.
//!
//! Native UTXO spends reuse the EIP-8141 outer transaction and frame encoding.
//! Only `Frame::data` has the UTXO-specific RLP payload defined in this module.
//! The constants and encoding are experimental until the research proposal is
//! turned into a standards-track EIP.

use std::{collections::HashSet, sync::LazyLock};

use bytes::{BufMut, Bytes};
use ethereum_types::{Address, H160, H256, U256};
use ethrex_rlp::{
    decode::{RLPDecode, decode_rlp_item},
    encode::RLPEncode,
    error::RLPDecodeError,
    structs::{Decoder, Encoder},
};

use crate::{
    types::{FRAME_SIG_SCHEME_ARBITRARY, FrameTransaction, Log},
    utils::keccak,
};

/// Experimental reserved address for the native UTXO vault.
///
/// EIP-8141 reserves `0x8141` for its expiry verifier. The native-UTXO
/// research post does not assign a vault address, so `0x8142` is
/// prototype allocation and MUST NOT be treated as a mainnet assignment.
pub const UTXO_VAULT: Address = H160([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x81, 0x42,
]);

/// Number of recent per-block openings roots retained by the protocol.
pub const UTXO_RING_SIZE: u64 = 8192;

/// Vault storage slot containing the next globally assigned UTXO index.
pub const NEXT_INDEX_SLOT: u64 = 0;
/// Solidity-compatible mapping base slot for `spent_bits[word_index]`.
pub const SPENT_BITMAP_MAPPING_SLOT: u64 = 1;
/// Solidity-compatible mapping base slot for recent openings roots.
pub const OPENINGS_RING_MAPPING_SLOT: u64 = 2;
/// Solidity-compatible mapping base slot for sealed batch roots.
pub const BATCH_ROOT_MAPPING_SLOT: u64 = 3;

/// Canonical event signature used by ordinary vault deposits and settlement.
pub const UTXO_CREATED_EVENT_SIGNATURE: &[u8] = b"UtxoCreated(address,address,uint64,uint256)";
/// Topic zero for `UtxoCreated(address,address,uint64,uint256)`.
pub static UTXO_CREATED_TOPIC: LazyLock<H256> =
    LazyLock::new(|| keccak(UTXO_CREATED_EVENT_SIGNATURE));

/// Experimental domain separators for actor signing and the two Merkle trees.
/// These values must be standardized before use on a persistent network.
pub const UTXO_FRAME_DOMAIN: &[u8] = b"ethrex/native-utxo/frame/v0";
pub const UTXO_LEAF_DOMAIN: &[u8] = b"ethrex/native-utxo/leaf/v0";
pub const UTXO_NODE_DOMAIN: &[u8] = b"ethrex/native-utxo/node/v0";
pub const UTXO_BATCH_DOMAIN: &[u8] = b"ethrex/native-utxo/batch/v0";

// These experimental limits are consensus-facing DoS bounds. They deliberately
// live beside the encoding and must be frozen or changed behind a fork before
// this prototype is used by a persistent network.
pub const MAX_INPUTS: usize = 64;
pub const MAX_UTXO_OUTPUTS: usize = 64;
pub const MAX_ACCOUNT_OUTPUTS: usize = 64;
pub const MAX_ACTORS: usize = 64;
pub const MAX_OPENING_PROOF_DEPTH: usize = 32;
pub const MAX_BATCH_PROOF_DEPTH: usize = 13;
pub const MAX_UTXO_FRAME_DATA_SIZE: usize = 128 * 1024;

// Experimental native-execution gas schedule. These are consensus constants:
// changing any value requires a fork. Calldata and outer signature validation
// remain charged by EIP-8141; this schedule prices the additional protocol work.
/// Fixed decoding, digest, validation, approval, and settlement overhead.
pub const UTXO_GAS_BASE: u64 = 5_000;
/// Actor binding against an already-validated outer signature.
pub const UTXO_GAS_PER_ACTOR: u64 = 500;
/// Opening-leaf hashing, root/spent reads, and a worst-case spent-word update.
pub const UTXO_GAS_PER_INPUT: u64 = 25_000;
/// One domain-separated Merkle parent hash and path-position step.
pub const UTXO_GAS_PER_PROOF_NODE: u64 = 60;
/// Global-index assignment, discovery log, and openings-tree contribution.
pub const UTXO_GAS_PER_UTXO_OUTPUT: u64 = 3_000;
/// Vault debit plus a conservative possible new-account balance credit.
pub const UTXO_GAS_PER_ACCOUNT_OUTPUT: u64 = 35_000;
/// Cold read and worst-case zero-to-nonzero update of `next_utxo_index`.
pub const UTXO_GAS_NEXT_INDEX_WRITE: u64 = 22_100;

/// `change_kind` value selecting `utxo_outputs`.
pub const CHANGE_KIND_UTXO: u8 = 0;
/// `change_kind` value selecting `account_outputs`.
pub const CHANGE_KIND_ACCOUNT: u8 = 1;

/// Actor authorized by one entry in the outer EIP-8141 signature list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoActor {
    /// Zero-based index of the actor's signature in the outer frame
    /// transaction's `signatures` list.
    ///
    /// This is an experimental explicit-linking mechanism. The research post
    /// describes `actors` as addresses and could instead resolve the matching
    /// signature by signer address and UTXO digest.
    pub signature_index: u64,
    /// Address that must have authorized the witness-free UTXO transition.
    pub actor_address: Address,
}

/// One UTXO input and its replaceable existence witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoInput {
    /// Globally unique, monotonically assigned UTXO identifier.
    ///
    /// This field is part of the actor-signed transition.
    pub index: u64,
    /// Number of the block whose `UtxoCreated` log created this UTXO.
    ///
    /// This field is part of the actor-signed transition and selects the
    /// openings root against which the witness is checked.
    pub creation_block: u64,

    /// Account recorded as the creator of the UTXO.
    ///
    /// This is a replaceable witness field. It is trusted only after the
    /// opening proof succeeds and is not included in the actor digest.
    pub source: Address,
    /// Amount of ETH, in wei, committed by the proven opening.
    ///
    /// This is a replaceable witness field and is not included in the actor
    /// digest.
    pub value: U256,
    /// Address authorized to spend the proven opening.
    ///
    /// This is a replaceable witness field. Verification must prove it and
    /// require it to be present in the payload's actor list.
    pub recipient: Address,
    /// Zero-based leaf position of this opening in its creation block's
    /// openings tree. Its bits determine left/right proof ordering.
    pub opening_position: u64,
    /// Merkle siblings proving the opening leaf up to the creation block's
    /// openings root.
    pub opening_siblings: Vec<H256>,
    /// Sealed batch containing the creation block's openings root.
    ///
    /// This is currently explicit witness metadata, although it can be derived
    /// from `creation_block` once the fork-relative batching rule is fixed.
    pub batch_number: u64,
    /// Position of the creation block's openings root inside its sealed batch.
    ///
    /// This can also be derived from `creation_block` once batching is fixed.
    pub batch_position: u64,
    /// Merkle siblings proving the block openings root up to its sealed batch
    /// root. This is empty while the block root is still available in the
    /// recent-root ring.
    pub batch_siblings: Vec<H256>,
}

/// A newly created UTXO output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoOutput {
    /// Address authorized to consume the newly created UTXO.
    pub recipient: Address,
    /// Fixed output amount in wei. A designated change output uses zero here
    /// and receives its final value during settlement.
    pub value: U256,
}

/// An output credited to an ordinary Ethereum account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoAccountOutput {
    /// Ethereum account whose balance is credited during settlement.
    pub recipient: Address,
    /// Fixed output amount in wei. A designated change output uses zero here
    /// and receives its final value during settlement.
    pub value: U256,
}

/// Opening reconstructed from a canonical `UtxoCreated` discovery log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoOpening {
    pub index: u64,
    pub source: Address,
    pub recipient: Address,
    pub value: U256,
}

/// Decoded native-UTXO payload carried by `Frame::data`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoFramePayload {
    /// Addresses authorizing consumption of the inputs, currently paired with
    /// explicit indices into the outer EIP-8141 signature list.
    pub actors: Vec<UtxoActor>,
    /// Existing UTXOs consumed atomically by this transition.
    pub inputs: Vec<UtxoInput>,
    /// New UTXOs created and kept backed by the vault.
    pub utxo_outputs: Vec<UtxoOutput>,
    /// ETH payments leaving the vault for ordinary Ethereum accounts.
    pub account_outputs: Vec<UtxoAccountOutput>,
    /// Output collection containing the change entry.
    ///
    /// The exact numeric mapping is not yet specified by the research post and
    /// must be frozen before semantic validation is implemented.
    pub change_kind: u8,
    /// Zero-based index of the change entry in the collection selected by
    /// `change_kind`.
    pub change_index: u64,
    /// Zero for a self-funded spend; otherwise the address expected to approve
    /// payment and receive the signed sponsor repayment.
    pub payer: Address,
    /// Maximum outer transaction fee per gas authorized by every actor.
    pub signed_max_fee_per_gas: U256,
    /// Maximum outer priority fee per gas authorized by every actor.
    pub signed_max_priority_fee_per_gas: U256,
    /// Maximum total EIP-8141 transaction gas authorized by every actor.
    pub signed_max_gas: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SignedUtxoInput {
    index: u64,
    creation_block: u64,
}

impl RLPEncode for SignedUtxoInput {
    fn encode(&self, buf: &mut dyn BufMut) {
        Encoder::new(buf)
            .encode_field(&self.index)
            .encode_field(&self.creation_block)
            .finish();
    }
}

impl UtxoFramePayload {
    /// Decode and apply the bounds that are safe to check without state access.
    pub fn decode_frame_data(data: &Bytes) -> Result<Self, RLPDecodeError> {
        if data.len() > MAX_UTXO_FRAME_DATA_SIZE {
            return Err(RLPDecodeError::Custom(format!(
                "native UTXO frame data exceeds {MAX_UTXO_FRAME_DATA_SIZE} bytes"
            )));
        }

        Self::decode(data.as_ref())
    }

    /// Canonically encode the actor-authorized transition without replaceable
    /// opening and batch witnesses.
    pub fn signed_payload(&self, chain_id: u64) -> Vec<u8> {
        let signed_inputs = self
            .inputs
            .iter()
            .map(|input| SignedUtxoInput {
                index: input.index,
                creation_block: input.creation_block,
            })
            .collect::<Vec<_>>();

        let mut encoded = Vec::new();
        Encoder::new(&mut encoded)
            .encode_field(&chain_id)
            .encode_field(&self.actors)
            .encode_field(&signed_inputs)
            .encode_field(&self.utxo_outputs)
            .encode_field(&self.account_outputs)
            .encode_field(&self.change_kind)
            .encode_field(&self.change_index)
            .encode_field(&self.payer)
            .encode_field(&self.signed_max_fee_per_gas)
            .encode_field(&self.signed_max_priority_fee_per_gas)
            .encode_field(&self.signed_max_gas)
            .finish();
        encoded
    }

    /// Digest placed in each actor signature's explicit EIP-8141 `msg`.
    pub fn frame_digest(&self, chain_id: u64) -> H256 {
        let signed_payload = self.signed_payload(chain_id);
        let mut preimage = Vec::with_capacity(UTXO_FRAME_DOMAIN.len() + signed_payload.len());
        preimage.extend_from_slice(UTXO_FRAME_DOMAIN);
        preimage.extend_from_slice(&signed_payload);
        keccak(&preimage)
    }

    /// Consensus gas charged by the protocol-defined native frame execution.
    ///
    /// The formula is deliberately state-independent and conservative: each
    /// input pays for a cold root read and worst-case fresh spent-word write,
    /// even when accesses share a word or are already warm. This keeps mempool
    /// and block validation deterministic without consulting mutable account
    /// state solely to quote gas.
    pub fn native_execution_gas(&self) -> Result<u64, String> {
        fn component(count: usize, per_item: u64, name: &str) -> Result<u64, String> {
            u64::try_from(count)
                .ok()
                .and_then(|count| count.checked_mul(per_item))
                .ok_or_else(|| format!("native UTXO {name} gas overflow"))
        }

        let proof_nodes = self.inputs.iter().try_fold(0_usize, |total, input| {
            total
                .checked_add(input.opening_siblings.len())
                .and_then(|total| total.checked_add(input.batch_siblings.len()))
                .ok_or("native UTXO proof-node count overflow")
        })?;

        let mut gas = UTXO_GAS_BASE;
        for (count, per_item, name) in [
            (self.actors.len(), UTXO_GAS_PER_ACTOR, "actor"),
            (self.inputs.len(), UTXO_GAS_PER_INPUT, "input"),
            (proof_nodes, UTXO_GAS_PER_PROOF_NODE, "proof"),
            (
                self.utxo_outputs.len(),
                UTXO_GAS_PER_UTXO_OUTPUT,
                "UTXO output",
            ),
            (
                self.account_outputs.len(),
                UTXO_GAS_PER_ACCOUNT_OUTPUT,
                "account output",
            ),
        ] {
            gas = gas
                .checked_add(component(count, per_item, name)?)
                .ok_or_else(|| format!("native UTXO {name} gas total overflow"))?;
        }
        if !self.utxo_outputs.is_empty() {
            gas = gas
                .checked_add(UTXO_GAS_NEXT_INDEX_WRITE)
                .ok_or("native UTXO next-index gas overflow")?;
        }
        Ok(gas)
    }

    /// Bind every unique actor to the explicitly indexed, already
    /// cryptographically validated EIP-8141 signature entry.
    pub fn validate_actor_signatures(&self, tx: &FrameTransaction) -> Result<H256, String> {
        if self.actors.is_empty() {
            return Err("native UTXO frame must contain at least one actor".into());
        }

        let digest = self.frame_digest(tx.chain_id);
        let mut actor_addresses = HashSet::with_capacity(self.actors.len());
        for actor in &self.actors {
            if actor.actor_address == Address::zero() {
                return Err("native UTXO actor must not be the zero address".into());
            }
            if !actor_addresses.insert(actor.actor_address) {
                return Err(format!(
                    "duplicate native UTXO actor {:#x}",
                    actor.actor_address
                ));
            }

            let signature_index = usize::try_from(actor.signature_index)
                .map_err(|_| "native UTXO actor signature index does not fit usize")?;
            let signature = tx.signatures.get(signature_index).ok_or_else(|| {
                format!(
                    "native UTXO actor signature index {} is out of bounds",
                    actor.signature_index
                )
            })?;
            if signature.scheme == FRAME_SIG_SCHEME_ARBITRARY {
                return Err(format!(
                    "native UTXO actor signature {} must use a protocol-validated scheme",
                    actor.signature_index
                ));
            }
            if signature.msg.as_ref() != digest.as_bytes() {
                return Err(format!(
                    "native UTXO actor signature {} does not sign the UTXO frame digest",
                    actor.signature_index
                ));
            }
            if signature.signer.unwrap_or(tx.sender) != actor.actor_address {
                return Err(format!(
                    "native UTXO actor signature {} resolves to the wrong signer",
                    actor.signature_index
                ));
            }
        }
        Ok(digest)
    }

    /// Validate output shape, signed fee caps, payer repayment, and value
    /// conservation after all input openings have been proven.
    pub fn validate_outputs_and_conservation(&self, tx: &FrameTransaction) -> Result<U256, String> {
        if self.inputs.is_empty() {
            return Err("native UTXO frame must consume at least one input".into());
        }
        if !tx.blob_versioned_hashes.is_empty() {
            return Err(
                "native UTXO frames do not support blob fees in the current payload format".into(),
            );
        }
        if U256::from(tx.max_fee_per_gas) > self.signed_max_fee_per_gas {
            return Err("outer max_fee_per_gas exceeds the actor-signed cap".into());
        }
        if U256::from(tx.max_priority_fee_per_gas) > self.signed_max_priority_fee_per_gas {
            return Err("outer max_priority_fee_per_gas exceeds the actor-signed cap".into());
        }
        let total_gas_limit = tx.total_gas_limit();
        if total_gas_limit > self.signed_max_gas {
            return Err("outer transaction gas exceeds the actor-signed cap".into());
        }

        for output in &self.utxo_outputs {
            if output.recipient == Address::zero() {
                return Err("native UTXO output recipient must not be zero".into());
            }
        }
        for output in &self.account_outputs {
            if output.recipient == Address::zero() {
                return Err("native UTXO account output recipient must not be zero".into());
            }
        }

        let change_index = usize::try_from(self.change_index)
            .map_err(|_| "native UTXO change index does not fit usize")?;
        match self.change_kind {
            CHANGE_KIND_UTXO => {
                let change = self
                    .utxo_outputs
                    .get(change_index)
                    .ok_or("native UTXO change index is outside utxo_outputs")?;
                if !change.value.is_zero() {
                    return Err("native UTXO change output must have signed value zero".into());
                }
            }
            CHANGE_KIND_ACCOUNT => {
                let change = self
                    .account_outputs
                    .get(change_index)
                    .ok_or("native UTXO change index is outside account_outputs")?;
                if !change.value.is_zero() {
                    return Err("native UTXO change output must have signed value zero".into());
                }
            }
            _ => return Err("native UTXO change kind must select UTXO or account outputs".into()),
        }

        let input_total = checked_sum(self.inputs.iter().map(|input| input.value), "input")?;
        let fixed_utxo_total = checked_sum(
            self.utxo_outputs
                .iter()
                .enumerate()
                .filter(|(index, _)| self.change_kind != CHANGE_KIND_UTXO || *index != change_index)
                .map(|(_, output)| output.value),
            "UTXO output",
        )?;
        let fixed_account_total = checked_sum(
            self.account_outputs
                .iter()
                .enumerate()
                .filter(|(index, _)| {
                    self.change_kind != CHANGE_KIND_ACCOUNT || *index != change_index
                })
                .map(|(_, output)| output.value),
            "account output",
        )?;
        let fixed_output_total = fixed_utxo_total
            .checked_add(fixed_account_total)
            .ok_or("native UTXO fixed output total overflow")?;
        let maximum_fee = U256::from(tx.max_fee_per_gas)
            .checked_mul(U256::from(total_gas_limit))
            .ok_or("native UTXO maximum fee overflow")?;

        let required_total = if self.payer == Address::zero() {
            fixed_output_total
                .checked_add(maximum_fee)
                .ok_or("native UTXO self-funded required total overflow")?
        } else {
            // Sponsorship must be safe independently of payer code: one fixed,
            // actor-signed output repays at least the transaction's maximum gas
            // charge. The later EIP-8141 payment frame still approves the exact
            // signed payer, but it need not correctly reimplement this payload
            // parser or minimum-repayment calculation.
            let has_repayment_output = self
                .utxo_outputs
                .iter()
                .enumerate()
                .filter(|(index, _)| self.change_kind != CHANGE_KIND_UTXO || *index != change_index)
                .map(|(_, output)| (output.recipient, output.value))
                .chain(
                    self.account_outputs
                        .iter()
                        .enumerate()
                        .filter_map(|(index, output)| {
                            (self.change_kind != CHANGE_KIND_ACCOUNT || index != change_index)
                                .then_some((output.recipient, output.value))
                        }),
                )
                .any(|(recipient, value)| {
                    recipient == self.payer && !value.is_zero() && value >= maximum_fee
                });
            if !has_repayment_output {
                return Err(
                    "sponsored native UTXO frame lacks a fixed payer output covering the maximum transaction fee"
                        .into(),
                );
            }
            fixed_output_total
        };

        if input_total < required_total {
            return Err("native UTXO inputs do not cover outputs and required fee".into());
        }
        Ok(input_total - required_total)
    }

    /// Resolve the designated change output using the transaction's actual fee.
    ///
    /// Self-funded spends deduct the actual protocol fee from the input value.
    /// Sponsored spends do not: their signed fixed outputs already include the
    /// payer repayment and the payer account covers the protocol fee.
    pub fn settlement_change(&self, actual_fee: U256) -> Result<U256, String> {
        let change_index = usize::try_from(self.change_index)
            .map_err(|_| "native UTXO change index does not fit usize")?;
        match self.change_kind {
            CHANGE_KIND_UTXO if change_index < self.utxo_outputs.len() => {}
            CHANGE_KIND_ACCOUNT if change_index < self.account_outputs.len() => {}
            CHANGE_KIND_UTXO => {
                return Err("native UTXO change index is outside utxo_outputs".into());
            }
            CHANGE_KIND_ACCOUNT => {
                return Err("native UTXO change index is outside account_outputs".into());
            }
            _ => return Err("native UTXO change kind must select UTXO or account outputs".into()),
        }

        let input_total = checked_sum(self.inputs.iter().map(|input| input.value), "input")?;
        let fixed_utxo_total = checked_sum(
            self.utxo_outputs
                .iter()
                .enumerate()
                .filter(|(index, _)| self.change_kind != CHANGE_KIND_UTXO || *index != change_index)
                .map(|(_, output)| output.value),
            "UTXO output",
        )?;
        let fixed_account_total = checked_sum(
            self.account_outputs
                .iter()
                .enumerate()
                .filter(|(index, _)| {
                    self.change_kind != CHANGE_KIND_ACCOUNT || *index != change_index
                })
                .map(|(_, output)| output.value),
            "account output",
        )?;
        let fixed_output_total = fixed_utxo_total
            .checked_add(fixed_account_total)
            .ok_or("native UTXO fixed output total overflow")?;
        let fee = if self.payer == Address::zero() {
            actual_fee
        } else {
            U256::zero()
        };

        input_total
            .checked_sub(fixed_output_total)
            .and_then(|remainder| remainder.checked_sub(fee))
            .ok_or_else(|| "native UTXO settlement change underflow".into())
    }
}

fn checked_sum(values: impl IntoIterator<Item = U256>, description: &str) -> Result<U256, String> {
    values.into_iter().try_fold(U256::zero(), |sum, value| {
        sum.checked_add(value)
            .ok_or_else(|| format!("native UTXO {description} total overflow"))
    })
}

/// Solidity mapping slot `keccak256(uint256(key) || uint256(base_slot))`.
pub fn utxo_mapping_storage_slot(key: U256, base_slot: u64) -> H256 {
    let mut preimage = [0_u8; 64];
    preimage[..32].copy_from_slice(&key.to_big_endian());
    preimage[32..].copy_from_slice(&U256::from(base_slot).to_big_endian());
    keccak(preimage)
}

/// Storage word containing the spent flag for `index`.
pub fn spent_bitmap_storage_slot(index: u64) -> H256 {
    utxo_mapping_storage_slot(U256::from(index >> 8), SPENT_BITMAP_MAPPING_SLOT)
}

/// Check and set `index` inside its already-loaded 256-bit spent word.
pub fn check_and_set_spent_bit(current_word: U256, index: u64) -> Result<U256, String> {
    // The low byte is the bit position within this index's 256-bit word.
    let bit_position = usize::from((index & 0xff) as u8);
    let bit_mask = U256::one() << bit_position;
    if !(current_word & bit_mask).is_zero() {
        return Err(format!("native UTXO input {index} is already spent"));
    }
    Ok(current_word | bit_mask)
}

/// Build the canonical discovery log for a newly assigned UTXO.
///
/// `source` and `recipient` are indexed as topics 1 and 2. The non-indexed
/// `uint64 index` and `uint256 value` occupy two 32-byte ABI words in `data`.
pub fn utxo_created_log(source: Address, recipient: Address, index: u64, value: U256) -> Log {
    fn address_topic(address: Address) -> H256 {
        let mut topic = [0_u8; 32];
        topic[12..].copy_from_slice(address.as_bytes());
        H256(topic)
    }

    let mut data = [0_u8; 64];
    data[..32].copy_from_slice(&U256::from(index).to_big_endian());
    data[32..].copy_from_slice(&value.to_big_endian());
    Log {
        address: UTXO_VAULT,
        topics: vec![
            *UTXO_CREATED_TOPIC,
            address_topic(source),
            address_topic(recipient),
        ],
        data: Bytes::copy_from_slice(&data),
    }
}

/// Decode a canonical creation log, ignoring unrelated logs.
///
/// A log under the vault with the creation signature is considered canonical
/// input to the openings tree, so malformed topics or data are rejected rather
/// than silently skipped.
pub fn decode_utxo_created_log(log: &Log) -> Result<Option<UtxoOpening>, String> {
    if log.address != UTXO_VAULT || log.topics.first() != Some(&*UTXO_CREATED_TOPIC) {
        return Ok(None);
    }
    if log.topics.len() != 3 {
        return Err("native UTXO creation log must contain exactly three topics".into());
    }
    if log.data.len() != 64 {
        return Err("native UTXO creation log data must contain two ABI words".into());
    }

    let decode_address_topic = |topic: &H256| -> Result<Address, String> {
        if topic.as_bytes()[..12] != [0_u8; 12] {
            return Err("native UTXO address topic is not canonically padded".into());
        }
        Ok(Address::from_slice(&topic.as_bytes()[12..]))
    };
    let source = decode_address_topic(&log.topics[1])?;
    let recipient = decode_address_topic(&log.topics[2])?;
    if source == Address::zero() || recipient == Address::zero() {
        return Err("native UTXO creation log addresses must not be zero".into());
    }

    let index = u64::try_from(U256::from_big_endian(&log.data[..32]))
        .map_err(|_| "native UTXO creation log index exceeds uint64")?;
    let value = U256::from_big_endian(&log.data[32..]);
    Ok(Some(UtxoOpening {
        index,
        source,
        recipient,
        value,
    }))
}

/// Ring storage slot containing the recent openings root for `block_number`.
pub fn openings_ring_storage_slot(block_number: u64) -> H256 {
    utxo_mapping_storage_slot(
        U256::from(block_number % UTXO_RING_SIZE),
        OPENINGS_RING_MAPPING_SLOT,
    )
}

/// Storage slot containing the sealed root for `batch_number`.
pub fn batch_root_storage_slot(batch_number: u64) -> H256 {
    utxo_mapping_storage_slot(U256::from(batch_number), BATCH_ROOT_MAPPING_SLOT)
}

/// Hash the opening committed by one `UtxoCreated` leaf.
pub fn utxo_opening_leaf(input: &UtxoInput) -> H256 {
    utxo_opening_leaf_fields(input.index, input.source, input.recipient, input.value)
}

/// Hash one reconstructed opening into its per-block tree leaf.
pub fn utxo_opening_leaf_fields(
    index: u64,
    source: Address,
    recipient: Address,
    value: U256,
) -> H256 {
    let mut opening = Vec::new();
    Encoder::new(&mut opening)
        .encode_field(&index)
        .encode_field(&source)
        .encode_field(&recipient)
        .encode_field(&value)
        .finish();

    let mut preimage = Vec::with_capacity(UTXO_LEAF_DOMAIN.len() + opening.len());
    preimage.extend_from_slice(UTXO_LEAF_DOMAIN);
    preimage.extend_from_slice(&opening);
    keccak(&preimage)
}

/// Build the per-block openings root from receipt logs in consensus order.
///
/// Empty blocks commit zero. Non-empty trees are padded on the right with zero
/// hashes to the next power of two and use `UTXO_NODE_DOMAIN` at every branch.
/// The research post does not fix a padding rule, so this is an experimental
/// consensus choice that must be standardized before persistent deployment.
pub fn utxo_openings_root_from_logs<'a>(
    logs: impl IntoIterator<Item = &'a Log>,
) -> Result<H256, String> {
    let mut leaves = Vec::new();
    for log in logs {
        if let Some(opening) = decode_utxo_created_log(log)? {
            leaves.push(utxo_opening_leaf_fields(
                opening.index,
                opening.source,
                opening.recipient,
                opening.value,
            ));
        }
    }
    padded_merkle_root(leaves, UTXO_NODE_DOMAIN)
}

/// Seal exactly one 8192-block era into its permanent batch root.
pub fn utxo_batch_root_from_openings_roots(roots: Vec<H256>) -> Result<H256, String> {
    let expected =
        usize::try_from(UTXO_RING_SIZE).map_err(|_| "native UTXO ring size does not fit usize")?;
    if roots.len() != expected {
        return Err(format!(
            "native UTXO batch requires {expected} openings roots"
        ));
    }
    padded_merkle_root(roots, UTXO_BATCH_DOMAIN)
}

fn padded_merkle_root(mut nodes: Vec<H256>, domain: &[u8]) -> Result<H256, String> {
    if nodes.is_empty() {
        return Ok(H256::zero());
    }
    let padded_len = nodes
        .len()
        .checked_next_power_of_two()
        .ok_or("native UTXO Merkle tree size overflow")?;
    nodes.resize(padded_len, H256::zero());

    while nodes.len() > 1 {
        let mut parents = Vec::with_capacity(nodes.len() / 2);
        for pair in nodes.chunks_exact(2) {
            let mut preimage = Vec::with_capacity(domain.len() + 64);
            preimage.extend_from_slice(domain);
            preimage.extend_from_slice(pair[0].as_bytes());
            preimage.extend_from_slice(pair[1].as_bytes());
            parents.push(keccak(&preimage));
        }
        nodes = parents;
    }
    nodes
        .pop()
        .ok_or_else(|| "native UTXO Merkle tree unexpectedly empty".into())
}

/// Fold an opening proof into its per-block openings root.
pub fn utxo_openings_root(input: &UtxoInput) -> Result<H256, String> {
    fold_merkle_path(
        utxo_opening_leaf(input),
        input.opening_position,
        &input.opening_siblings,
        UTXO_NODE_DOMAIN,
    )
}

/// Fold the creation block's openings root into its sealed batch root.
pub fn utxo_batch_root(input: &UtxoInput, openings_root: H256) -> Result<H256, String> {
    fold_merkle_path(
        openings_root,
        input.batch_position,
        &input.batch_siblings,
        UTXO_BATCH_DOMAIN,
    )
}

fn fold_merkle_path(
    mut node: H256,
    position: u64,
    siblings: &[H256],
    domain: &[u8],
) -> Result<H256, String> {
    if siblings.len() < u64::BITS as usize && position >= (1_u64 << siblings.len()) {
        return Err("native UTXO Merkle position exceeds proof depth".into());
    }
    for (depth, sibling) in siblings.iter().enumerate() {
        let (left, right) = if (position >> depth) & 1 == 0 {
            (node, *sibling)
        } else {
            (*sibling, node)
        };
        let mut preimage = Vec::with_capacity(domain.len() + 64);
        preimage.extend_from_slice(domain);
        preimage.extend_from_slice(left.as_bytes());
        preimage.extend_from_slice(right.as_bytes());
        node = keccak(&preimage);
    }
    Ok(node)
}

fn decode_bounded_list<T: RLPDecode>(
    encoded: &[u8],
    maximum: usize,
    field: &str,
) -> Result<Vec<T>, RLPDecodeError> {
    let (is_list, mut payload, remaining) = decode_rlp_item(encoded)?;
    if !is_list {
        return Err(RLPDecodeError::UnexpectedString);
    }
    if !remaining.is_empty() {
        return Err(RLPDecodeError::MalformedData);
    }

    let mut values = Vec::new();
    while !payload.is_empty() {
        if values.len() == maximum {
            return Err(RLPDecodeError::Custom(format!(
                "native UTXO field '{field}' exceeds maximum length {maximum}"
            )));
        }
        let before = payload.len();
        let (value, rest) = T::decode_unfinished(payload)?;
        if rest.len() >= before {
            return Err(RLPDecodeError::MalformedData);
        }
        values.push(value);
        payload = rest;
    }
    Ok(values)
}

impl RLPEncode for UtxoActor {
    fn encode(&self, buf: &mut dyn BufMut) {
        Encoder::new(buf)
            .encode_field(&self.signature_index)
            .encode_field(&self.actor_address)
            .finish();
    }
}

impl RLPDecode for UtxoActor {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (signature_index, decoder) = decoder.decode_field("signature_index")?;
        let (actor_address, decoder) = decoder.decode_field("actor_address")?;
        Ok((
            Self {
                signature_index,
                actor_address,
            },
            decoder.finish()?,
        ))
    }
}

impl RLPEncode for UtxoInput {
    fn encode(&self, buf: &mut dyn BufMut) {
        Encoder::new(buf)
            .encode_field(&self.index)
            .encode_field(&self.creation_block)
            .encode_field(&self.source)
            .encode_field(&self.value)
            .encode_field(&self.recipient)
            .encode_field(&self.opening_position)
            .encode_field(&self.opening_siblings)
            .encode_field(&self.batch_number)
            .encode_field(&self.batch_position)
            .encode_field(&self.batch_siblings)
            .finish();
    }
}

impl RLPDecode for UtxoInput {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (index, decoder) = decoder.decode_field("index")?;
        let (creation_block, decoder) = decoder.decode_field("creation_block")?;
        let (source, decoder) = decoder.decode_field("source")?;
        let (value, decoder) = decoder.decode_field("value")?;
        let (recipient, decoder) = decoder.decode_field("recipient")?;
        let (opening_position, decoder) = decoder.decode_field("opening_position")?;
        let (opening_siblings, decoder) = decoder.get_encoded_item_ref()?;
        let opening_siblings = decode_bounded_list(
            opening_siblings,
            MAX_OPENING_PROOF_DEPTH,
            "opening_siblings",
        )?;
        let (batch_number, decoder) = decoder.decode_field("batch_number")?;
        let (batch_position, decoder) = decoder.decode_field("batch_position")?;
        let (batch_siblings, decoder) = decoder.get_encoded_item_ref()?;
        let batch_siblings =
            decode_bounded_list(batch_siblings, MAX_BATCH_PROOF_DEPTH, "batch_siblings")?;

        Ok((
            Self {
                index,
                creation_block,
                source,
                value,
                recipient,
                opening_position,
                opening_siblings,
                batch_number,
                batch_position,
                batch_siblings,
            },
            decoder.finish()?,
        ))
    }
}

impl RLPEncode for UtxoOutput {
    fn encode(&self, buf: &mut dyn BufMut) {
        Encoder::new(buf)
            .encode_field(&self.recipient)
            .encode_field(&self.value)
            .finish();
    }
}

impl RLPDecode for UtxoOutput {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (recipient, decoder) = decoder.decode_field("recipient")?;
        let (value, decoder) = decoder.decode_field("value")?;
        Ok((Self { recipient, value }, decoder.finish()?))
    }
}

impl RLPEncode for UtxoAccountOutput {
    fn encode(&self, buf: &mut dyn BufMut) {
        Encoder::new(buf)
            .encode_field(&self.recipient)
            .encode_field(&self.value)
            .finish();
    }
}

impl RLPDecode for UtxoAccountOutput {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (recipient, decoder) = decoder.decode_field("recipient")?;
        let (value, decoder) = decoder.decode_field("value")?;
        Ok((Self { recipient, value }, decoder.finish()?))
    }
}

impl RLPEncode for UtxoFramePayload {
    fn encode(&self, buf: &mut dyn BufMut) {
        Encoder::new(buf)
            .encode_field(&self.actors)
            .encode_field(&self.inputs)
            .encode_field(&self.utxo_outputs)
            .encode_field(&self.account_outputs)
            .encode_field(&self.change_kind)
            .encode_field(&self.change_index)
            .encode_field(&self.payer)
            .encode_field(&self.signed_max_fee_per_gas)
            .encode_field(&self.signed_max_priority_fee_per_gas)
            .encode_field(&self.signed_max_gas)
            .finish();
    }
}

impl RLPDecode for UtxoFramePayload {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;

        let (actors, decoder) = decoder.get_encoded_item_ref()?;
        let actors = decode_bounded_list(actors, MAX_ACTORS, "actors")?;

        let (inputs, decoder) = decoder.get_encoded_item_ref()?;
        let inputs = decode_bounded_list(inputs, MAX_INPUTS, "inputs")?;

        let (utxo_outputs, decoder) = decoder.get_encoded_item_ref()?;
        let utxo_outputs = decode_bounded_list(utxo_outputs, MAX_UTXO_OUTPUTS, "utxo_outputs")?;

        let (account_outputs, decoder) = decoder.get_encoded_item_ref()?;
        let account_outputs =
            decode_bounded_list(account_outputs, MAX_ACCOUNT_OUTPUTS, "account_outputs")?;

        let (change_kind, decoder) = decoder.decode_field("change_kind")?;
        let (change_index, decoder) = decoder.decode_field("change_index")?;
        let (payer, decoder) = decoder.decode_field("payer")?;
        let (signed_max_fee_per_gas, decoder) = decoder.decode_field("signed_max_fee_per_gas")?;
        let (signed_max_priority_fee_per_gas, decoder) =
            decoder.decode_field("signed_max_priority_fee_per_gas")?;
        let (signed_max_gas, decoder) = decoder.decode_field("signed_max_gas")?;

        Ok((
            Self {
                actors,
                inputs,
                utxo_outputs,
                account_outputs,
                change_kind,
                change_index,
                payer,
                signed_max_fee_per_gas,
                signed_max_priority_fee_per_gas,
                signed_max_gas,
            },
            decoder.finish()?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        FRAME_SIG_SCHEME_SECP256K1, Frame, FrameMode, FrameSignature, FrameTransaction,
    };

    fn sample_payload() -> UtxoFramePayload {
        UtxoFramePayload {
            actors: vec![UtxoActor {
                signature_index: 0,
                actor_address: Address::from_low_u64_be(0xa11ce),
            }],
            inputs: vec![UtxoInput {
                index: 42,
                creation_block: 100,
                source: Address::from_low_u64_be(0x5),
                value: U256::from(1_000_000u64),
                recipient: Address::from_low_u64_be(0xa11ce),
                opening_position: 1,
                opening_siblings: vec![H256::from_low_u64_be(7)],
                batch_number: 0,
                batch_position: 0,
                batch_siblings: Vec::new(),
            }],
            utxo_outputs: vec![
                UtxoOutput {
                    recipient: Address::from_low_u64_be(0xb0b),
                    value: U256::from(500_000u64),
                },
                UtxoOutput {
                    recipient: Address::from_low_u64_be(0xa11ce),
                    value: U256::zero(),
                },
            ],
            account_outputs: vec![UtxoAccountOutput {
                recipient: Address::from_low_u64_be(0xca11),
                value: U256::from(100_000u64),
            }],
            change_kind: 0,
            change_index: 1,
            payer: Address::zero(),
            signed_max_fee_per_gas: U256::from(100u64),
            signed_max_priority_fee_per_gas: U256::from(2u64),
            signed_max_gas: 100_000,
        }
    }

    fn sample_transaction(payload: &UtxoFramePayload) -> FrameTransaction {
        let mut tx = FrameTransaction {
            chain_id: 1,
            sender: Address::from_low_u64_be(0xa11ce),
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            ..Default::default()
        };
        let digest = payload.frame_digest(tx.chain_id);
        tx.signatures.push(FrameSignature {
            scheme: FRAME_SIG_SCHEME_SECP256K1,
            signer: Some(Address::from_low_u64_be(0xa11ce)),
            msg: Bytes::copy_from_slice(digest.as_bytes()),
            signature: Bytes::new(),
        });
        tx
    }

    #[test]
    fn utxo_payload_roundtrip() {
        let payload = sample_payload();
        let encoded = payload.encode_to_vec();
        let decoded = UtxoFramePayload::decode_frame_data(&Bytes::from(encoded))
            .expect("sample payload should decode");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn rejects_excess_opening_proof_depth() {
        let mut payload = sample_payload();
        payload.inputs[0].opening_siblings = vec![H256::zero(); MAX_OPENING_PROOF_DEPTH + 1];
        let encoded = payload.encode_to_vec();
        let err = UtxoFramePayload::decode_frame_data(&Bytes::from(encoded))
            .expect_err("over-depth proof must be rejected");
        assert!(err.to_string().contains("opening_siblings"));
    }

    #[test]
    fn actor_digest_excludes_replaceable_witnesses() {
        let payload = sample_payload();
        let expected = payload.frame_digest(1);

        let mut refreshed = payload.clone();
        refreshed.inputs[0].source = Address::from_low_u64_be(0x999);
        refreshed.inputs[0].value = U256::from(999_999u64);
        refreshed.inputs[0].recipient = Address::from_low_u64_be(0x888);
        refreshed.inputs[0].opening_position = 0;
        refreshed.inputs[0].opening_siblings = vec![H256::from_low_u64_be(123); 3];
        refreshed.inputs[0].batch_number = 7;
        refreshed.inputs[0].batch_position = 9;
        refreshed.inputs[0].batch_siblings = vec![H256::from_low_u64_be(456); 2];

        assert_eq!(refreshed.frame_digest(1), expected);

        refreshed.inputs[0].index += 1;
        assert_ne!(refreshed.frame_digest(1), expected);
    }

    #[test]
    fn actor_signature_must_bind_signer_and_utxo_digest() {
        let payload = sample_payload();
        let mut tx = sample_transaction(&payload);
        assert_eq!(
            payload.validate_actor_signatures(&tx).unwrap(),
            payload.frame_digest(tx.chain_id)
        );

        tx.signatures[0].msg = Bytes::from_static(&[1_u8; 32]);
        assert!(
            payload
                .validate_actor_signatures(&tx)
                .unwrap_err()
                .contains("does not sign")
        );
    }

    #[test]
    fn validates_output_conservation_and_fee_caps() {
        let payload = sample_payload();
        let tx = sample_transaction(&payload);
        let remaining = payload
            .validate_outputs_and_conservation(&tx)
            .expect("sample inputs cover fixed outputs and maximum fee");
        assert!(remaining > U256::zero());

        let mut insufficient = payload;
        insufficient.inputs[0].value = U256::from(1u64);
        assert!(
            insufficient
                .validate_outputs_and_conservation(&tx)
                .unwrap_err()
                .contains("do not cover")
        );
    }

    #[test]
    fn sponsored_repayment_covers_the_maximum_transaction_fee() {
        let mut payload = sample_payload();
        payload.payer = payload.account_outputs[0].recipient;
        let tx = sample_transaction(&payload);
        let maximum_fee = U256::from(tx.max_fee_per_gas)
            .checked_mul(U256::from(tx.total_gas_limit()))
            .unwrap();
        assert!(maximum_fee > U256::zero());

        payload.account_outputs[0].value = maximum_fee - U256::one();
        assert!(
            payload
                .validate_outputs_and_conservation(&tx)
                .unwrap_err()
                .contains("covering the maximum transaction fee")
        );

        payload.account_outputs[0].value = maximum_fee;
        payload
            .validate_outputs_and_conservation(&tx)
            .expect("a fixed payer output covering max cost must be accepted");
    }

    #[test]
    fn native_execution_gas_prices_every_bounded_work_item() {
        let mut payload = sample_payload();
        assert_eq!(payload.native_execution_gas().unwrap(), 93_660);

        payload.inputs[0]
            .opening_siblings
            .push(H256::from_low_u64_be(8));
        assert_eq!(payload.native_execution_gas().unwrap(), 93_720);

        payload.utxo_outputs.push(UtxoOutput {
            recipient: Address::from_low_u64_be(0xd00d),
            value: U256::from(1u64),
        });
        assert_eq!(payload.native_execution_gas().unwrap(), 96_720);
    }

    #[test]
    fn merkle_paths_use_position_bits_and_storage_domains_do_not_collide() {
        let payload = sample_payload();
        let input = &payload.inputs[0];
        let leaf = utxo_opening_leaf(input);
        let sibling = input.opening_siblings[0];

        let mut left_preimage = Vec::from(UTXO_NODE_DOMAIN);
        left_preimage.extend_from_slice(sibling.as_bytes());
        left_preimage.extend_from_slice(leaf.as_bytes());
        assert_eq!(utxo_openings_root(input).unwrap(), keccak(&left_preimage));

        assert_ne!(spent_bitmap_storage_slot(0), openings_ring_storage_slot(0));
        assert_ne!(openings_ring_storage_slot(0), batch_root_storage_slot(0));
    }

    #[test]
    fn spent_bitmap_check_and_set_is_atomic_per_word() {
        let word = check_and_set_spent_bit(U256::zero(), 257).unwrap();
        assert!(word.bit(1));
        assert!(
            check_and_set_spent_bit(word, 257)
                .unwrap_err()
                .contains("already spent")
        );
        assert!(check_and_set_spent_bit(word, 258).unwrap().bit(2));
    }

    #[test]
    fn settlement_change_uses_actual_fee_only_when_self_funded() {
        let mut payload = sample_payload();
        assert_eq!(
            payload.settlement_change(U256::from(25_000u64)).unwrap(),
            U256::from(375_000u64)
        );

        payload.payer = Address::from_low_u64_be(0xca11);
        assert_eq!(
            payload.settlement_change(U256::from(25_000u64)).unwrap(),
            U256::from(400_000u64)
        );
    }

    #[test]
    fn utxo_created_log_has_canonical_topics_and_data() {
        let source = Address::from_low_u64_be(0xa11ce);
        let recipient = Address::from_low_u64_be(0xb0b);
        let log = utxo_created_log(source, recipient, 42, U256::from(123_456u64));

        assert_eq!(log.address, UTXO_VAULT);
        assert_eq!(log.topics[0], *UTXO_CREATED_TOPIC);
        assert_eq!(&log.topics[1].as_bytes()[12..], source.as_bytes());
        assert_eq!(&log.topics[2].as_bytes()[12..], recipient.as_bytes());
        assert_eq!(U256::from_big_endian(&log.data[..32]), U256::from(42u64));
        assert_eq!(
            U256::from_big_endian(&log.data[32..]),
            U256::from(123_456u64)
        );
    }

    #[test]
    fn creation_logs_build_the_openings_root_in_log_order() {
        let first = utxo_created_log(
            Address::from_low_u64_be(1),
            Address::from_low_u64_be(2),
            7,
            U256::from(11u64),
        );
        let second = utxo_created_log(
            Address::from_low_u64_be(3),
            Address::from_low_u64_be(4),
            8,
            U256::from(13u64),
        );
        let unrelated = Log {
            address: Address::from_low_u64_be(9),
            topics: Vec::new(),
            data: Bytes::new(),
        };

        let first_opening = decode_utxo_created_log(&first).unwrap().unwrap();
        assert_eq!(first_opening.index, 7);
        let left = utxo_opening_leaf_fields(
            first_opening.index,
            first_opening.source,
            first_opening.recipient,
            first_opening.value,
        );
        let right = utxo_opening_leaf_fields(
            8,
            Address::from_low_u64_be(3),
            Address::from_low_u64_be(4),
            U256::from(13u64),
        );
        let mut preimage = Vec::from(UTXO_NODE_DOMAIN);
        preimage.extend_from_slice(left.as_bytes());
        preimage.extend_from_slice(right.as_bytes());

        assert_eq!(
            utxo_openings_root_from_logs([&unrelated, &first, &second]).unwrap(),
            keccak(preimage)
        );
        assert_eq!(
            utxo_openings_root_from_logs(std::iter::empty()).unwrap(),
            H256::zero()
        );
    }

    #[test]
    fn completed_ring_seals_with_thirteen_batch_levels() {
        let ring_len = usize::try_from(UTXO_RING_SIZE).unwrap();
        let roots = vec![H256::zero(); ring_len];
        let mut expected = H256::zero();
        for _ in 0..MAX_BATCH_PROOF_DEPTH {
            let mut preimage = Vec::from(UTXO_BATCH_DOMAIN);
            preimage.extend_from_slice(expected.as_bytes());
            preimage.extend_from_slice(expected.as_bytes());
            expected = keccak(preimage);
        }
        assert_eq!(
            utxo_batch_root_from_openings_roots(roots).unwrap(),
            expected
        );
        assert!(utxo_batch_root_from_openings_roots(Vec::new()).is_err());
    }

    #[test]
    fn recognizes_only_verify_frames_targeting_utxo_vault() {
        let frame = Frame {
            mode: FrameMode::Verify as u8,
            target: Some(UTXO_VAULT),
            ..Default::default()
        };
        assert!(frame.is_native_utxo());

        let mut wrong_mode = frame.clone();
        wrong_mode.mode = FrameMode::Default as u8;
        assert!(!wrong_mode.is_native_utxo());

        let mut wrong_target = frame;
        wrong_target.target = Some(Address::from_low_u64_be(0x8143));
        assert!(!wrong_target.is_native_utxo());
    }

    #[test]
    fn rejects_more_than_one_utxo_frame_per_transaction() {
        let utxo_frame = Frame {
            mode: FrameMode::Verify as u8,
            target: Some(UTXO_VAULT),
            ..Default::default()
        };
        let tx = FrameTransaction {
            sender: Address::from_low_u64_be(1),
            frames: vec![utxo_frame.clone(), utxo_frame],
            ..Default::default()
        };

        let error = tx
            .validate_static_constraints()
            .expect_err("multiple UTXO frames must be rejected");
        assert!(error.contains("more than one native UTXO frame"));
    }

    #[test]
    fn rejects_sender_frames_in_native_utxo_transactions() {
        let tx = FrameTransaction {
            sender: Address::from_low_u64_be(1),
            frames: vec![
                Frame {
                    mode: FrameMode::Verify as u8,
                    target: Some(UTXO_VAULT),
                    ..Default::default()
                },
                Frame {
                    mode: FrameMode::Sender as u8,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        let error = tx
            .validate_static_constraints()
            .expect_err("UTXO authorization must not enable SENDER frames");
        assert!(error.contains("must not contain SENDER frames"));
    }
}
