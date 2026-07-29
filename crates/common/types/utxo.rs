//! Experimental native-UTXO frame payload types.
//!
//! Native UTXO spends reuse the EIP-8141 outer transaction and frame encoding.
//! Only `Frame::data` has the UTXO-specific RLP payload defined in this module.
//! The constants and encoding are experimental until the research proposal is
//! turned into a standards-track EIP.

use std::sync::LazyLock;

use bytes::{BufMut, Bytes};
use ethereum_types::{Address, H160, H256, U256};
use ethrex_rlp::{
    decode::{RLPDecode, decode_rlp_item},
    encode::RLPEncode,
    error::RLPDecodeError,
    structs::{Decoder, Encoder},
};

use crate::utils::keccak;

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

/// Canonical event signature used by ordinary vault deposits and settlement.
pub const UTXO_CREATED_EVENT_SIGNATURE: &[u8] = b"UtxoCreated(address,address,uint64,uint256)";
/// Topic zero for `UtxoCreated(address,address,uint64,uint256)`.
pub static UTXO_CREATED_TOPIC: LazyLock<H256> =
    LazyLock::new(|| keccak(UTXO_CREATED_EVENT_SIGNATURE));

/// Domain separators reserved for later signing and Merkle-tree work.
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
    use crate::types::{Frame, FrameMode, FrameTransaction};

    fn sample_payload() -> UtxoFramePayload {
        UtxoFramePayload {
            actors: vec![UtxoActor {
                signature_index: 1,
                actor_address: Address::from_low_u64_be(0xa11ce),
            }],
            inputs: vec![UtxoInput {
                index: 42,
                creation_block: 100,
                source: Address::from_low_u64_be(0x5),
                value: U256::from(1_000_000u64),
                recipient: Address::from_low_u64_be(0xa11ce),
                opening_position: 3,
                opening_siblings: vec![H256::from_low_u64_be(7)],
                batch_number: 0,
                batch_position: 0,
                batch_siblings: Vec::new(),
            }],
            utxo_outputs: vec![UtxoOutput {
                recipient: Address::from_low_u64_be(0xb0b),
                value: U256::from(500_000u64),
            }],
            account_outputs: vec![UtxoAccountOutput {
                recipient: Address::from_low_u64_be(0xca11),
                value: U256::from(100_000u64),
            }],
            change_kind: 0,
            change_index: 0,
            payer: Address::zero(),
            signed_max_fee_per_gas: U256::from(100u64),
            signed_max_priority_fee_per_gas: U256::from(2u64),
            signed_max_gas: 100_000,
        }
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
}
