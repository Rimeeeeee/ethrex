//! EIP-8312 UTXO frames: constants, the spend payload, and the spend hash.
//!
//! A UTXO is a one-shot payment object: created by a deposit to the vault system
//! contract, spent whole by a signed, value-conserving frame (EIP-8141 frame
//! mode `UTXO`). A UTXO's opening is kept in history and proven against
//! per-block openings roots; the only permanent state per UTXO is one spent bit.
//!
//! Spec: `EIPS/eip-8312.md` (Draft) at commit
//! `a5da3f608c6dfbf353bea264054d99fc164ab10c`. Divergences from that text are
//! recorded in `docs/eip-8312.md`; the one visible here is the frame-mode number
//! (the spec's `UTXO_MODE = 3` is EIP-7906's POST_TX in this client, so UTXO
//! takes mode 5 — see [`crate::types::FrameMode`]).
//!
//! This module holds only what is decidable from transaction bytes: the wire
//! shape, the static bounds, and the signing hash. Proof verification, spent
//! bits, conservation, and settlement live in the VM.

use bytes::Bytes;
use ethrex_rlp::{
    decode::RLPDecode,
    encode::RLPEncode,
    error::RLPDecodeError,
    structs::{Decoder, Encoder},
};
use serde::{Deserialize, Serialize};

use crate::{
    Address, H256, U256,
    types::{Log, Receipt},
    utils::keccak,
};
use libssz_merkle::{Sha2Hasher, Sha256Hasher};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Vault system contract address (`address(0x8312)`). Holds every unspent
/// UTXO's value; its code handles deposits only, and every other write to its
/// storage or balance is performed by the protocol directly.
pub const UTXO_VAULT_U64: u64 = 0x8312;

/// Returns the `UTXO_VAULT` address (0x…8312).
pub fn utxo_vault() -> Address {
    Address::from_low_u64_be(UTXO_VAULT_U64)
}

/// Spend-hash domain prefix. `0x81` lies outside the EIP-2718 transaction type
/// space (`<= 0x7f`), so a spend-hash preimage cannot collide with the signing
/// payload of any transaction type.
pub const SPEND_MAGIC: u8 = 0x81;

/// Openings-root ring length: the vault keeps one openings root per block for
/// the last `RING_SIZE` blocks, at `SLOT_RING_BASE + (block_number % RING_SIZE)`.
pub const RING_SIZE: u64 = 8192;

/// Batch commitment interval. `RING_SIZE == BATCH_SIZE` is what guarantees a
/// batch is sealed before any of its ring slots is overwritten, so a ring proof
/// can always be upgraded to a batch proof with no gap. The equality is relied
/// on by the window checks; keep them equal.
pub const BATCH_SIZE: u64 = 8192;

const _: () = assert!(RING_SIZE == BATCH_SIZE);

/// Depth of a batch tree: a batch always has exactly `BATCH_SIZE` leaves (the
/// openings roots of its blocks), so a batch path is exactly `log2(BATCH_SIZE)`
/// siblings. A witness's `batch_siblings` is either empty (ring proof) or
/// exactly this long (batch proof).
pub const BATCH_PATH_LEN: usize = BATCH_SIZE.trailing_zeros() as usize;

/// Maximum openings-tree depth a witness may claim. A block's openings tree
/// cannot be deeper than this in any realistic block, and the bound keeps proof
/// verification cost statically bounded.
pub const MAX_SIBLINGS: usize = 32;

/// `keccak256("UtxoCreated(address,address,uint64,uint256)")` — topic 0 of the
/// vault's creation log. Wallets MUST match this in addition to the vault
/// address; matching a recipient topic alone would let a future log shape under
/// the vault spoof a payment.
pub const UTXO_CREATED_TOPIC: H256 = H256([
    0x3b, 0x19, 0x24, 0x14, 0x65, 0xa4, 0x7b, 0xc1, 0x87, 0xf1, 0xd9, 0xc7, 0xdb, 0x70, 0x83, 0x48,
    0x55, 0xa9, 0x07, 0x18, 0x37, 0x42, 0xa4, 0xb6, 0x3a, 0xa8, 0x24, 0xc5, 0x76, 0x29, 0x6f, 0x5e,
]);

/// Version of the experimental self-contained UTXO Proof Table archive object.
pub const UTXO_PROOF_TABLE_FORMAT_VERSION: u16 = 2;

/// Domain from the UPT v2 proposal, separating a block-table content hash from
/// every other SHA-256 commitment.
pub const UTXO_PROOF_TABLE_HASH_DOMAIN: &[u8] = b"UPT_BLOCK_V2\0";

/// The opening fields authenticated by the native UTXO openings root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UtxoOpening {
    pub index: u64,
    pub source: Address,
    pub recipient: Address,
    pub value: U256,
}

/// Decode the canonical four-topic `UtxoCreated` event used by deposits and
/// settlement outputs. Malformed or foreign logs are not native openings.
pub fn decode_utxo_created_log(log: &Log) -> Option<UtxoOpening> {
    if log.address != utxo_vault()
        || log.topics.len() != 4
        || log.topics[0] != UTXO_CREATED_TOPIC
        || log.data.len() != 32
        || log.topics[1].as_bytes()[..12] != [0; 12]
        || log.topics[2].as_bytes()[..12] != [0; 12]
        || log.topics[3].as_bytes()[..24] != [0; 24]
    {
        return None;
    }
    Some(UtxoOpening {
        index: u64::from_be_bytes(log.topics[3].as_bytes()[24..].try_into().ok()?),
        source: Address::from_slice(&log.topics[1].as_bytes()[12..]),
        recipient: Address::from_slice(&log.topics[2].as_bytes()[12..]),
        value: U256::from_big_endian(&log.data),
    })
}

/// Regular-gas components of `utxo_frame_gas`, per the EIP's schedule. The
/// state-gas components depend on the live EIP-8037 per-byte cost, so the VM adds
/// them; admission uses [`Spend::admission_gas`], which sums both with the
/// canonical state values (policy may be conservative, consensus may not).
pub const GAS_UTXO_FRAME: u64 = 13_000;
pub const GAS_UTXO_INPUT: u64 = 16_048;
pub const GAS_UTXO_SIBLING: u64 = 42;
pub const GAS_UTXO_OUT: u64 = 2_131;
pub const GAS_UTXO_ACCOUNT_OUT: u64 = 9_000;
/// Canonical EIP-8037 values at the pinned per-state-byte cost. levm asserts at
/// compile time that its derived values agree with these.
pub const GAS_UTXO_SPENT_STATE: u64 = 383;
pub const GAS_NEW_ACCOUNT_STATE: u64 = 183_600;

impl Spend {
    /// `utxo_frame_gas` for admission purposes: every component of the EIP's
    /// schedule, both gas dimensions summed. Computable from the frame alone —
    /// no state reads and no signature checks — which is what lets a node reject
    /// an over-budget transaction before doing any expensive work.
    pub fn admission_gas(&self) -> u64 {
        let mut siblings: u64 = 0;
        for input in &self.inputs {
            siblings = siblings
                .saturating_add(u64::try_from(input.siblings.len()).unwrap_or(u64::MAX))
                .saturating_add(u64::try_from(input.batch_siblings.len()).unwrap_or(u64::MAX));
        }
        let inputs = u64::try_from(self.inputs.len()).unwrap_or(u64::MAX);
        let utxo_outs = u64::try_from(self.utxo_outs.len()).unwrap_or(u64::MAX);
        let account_outs = u64::try_from(self.account_outs.len()).unwrap_or(u64::MAX);

        GAS_UTXO_FRAME
            .saturating_add(GAS_UTXO_INPUT.saturating_mul(inputs))
            .saturating_add(GAS_UTXO_SIBLING.saturating_mul(siblings))
            .saturating_add(GAS_UTXO_SPENT_STATE.saturating_mul(inputs))
            .saturating_add(GAS_UTXO_OUT.saturating_mul(utxo_outs))
            .saturating_add(
                GAS_UTXO_ACCOUNT_OUT
                    .saturating_add(GAS_NEW_ACCOUNT_STATE)
                    .saturating_mul(account_outs),
            )
    }
}

/// EIP-8312 mempool admission budget for transactions carrying UTXO frames,
/// replacing the general frame-transaction verify bound for them. Policy, not
/// consensus: operator-tunable, and admission acceptance confers no consensus
/// meaning.
///
/// Counts the actor-signature validation cost plus the combined `utxo_frame_gas`
/// of the transaction's UTXO frames, with both EIP-8037 gas dimensions summed
/// (conservative, which is acceptable for a policy bound). A sponsored
/// transaction's validation prefix stays under the ordinary frame-transaction
/// bound instead — the two lanes are disjoint.
///
/// Note the ceiling this implies, faithful to the EIP but worth stating: each
/// account output carries a full `GAS_NEW_ACCOUNT_STATE` reserve, so a spend with
/// two or more fresh-account outputs exceeds the default and is unrelayable
/// despite being consensus-valid. Raised upstream as author feedback.
pub const MAX_UTXO_VERIFY_GAS: u64 = 400_000;

/// One output of a spend: `[recipient, value]`. The entry designated by
/// `change_index` is signed with `value == 0` and receives the remainder at
/// settlement.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendOutput {
    pub recipient: Address,
    pub value: U256,
}

/// One input of a spend:
/// `[index, creation_block, source, recipient, value, position, siblings, batch_siblings]`.
///
/// `index` and `creation_block` are **signed**; the remaining fields are the
/// **witness**, proven rather than trusted. Because the witness is outside the
/// spend hash, anyone may refresh it (for example upgrade a ring proof to a
/// batch proof) without invalidating a signature — a substituted witness either
/// proves the same opening or fails, since the signed `index` pins it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendInput {
    pub index: u64,
    pub creation_block: u64,
    pub source: Address,
    pub recipient: Address,
    pub value: U256,
    pub position: u64,
    pub siblings: Vec<H256>,
    pub batch_siblings: Vec<H256>,
}

/// The RLP payload of a UTXO frame's `data`:
/// `[actors, inputs, utxo_outs, account_outs, change_index, payer,
///   max_fee_per_gas, max_priority_fee_per_gas, max_gas_limit]`.
///
/// `payer` is empty for a self-funded spend (the vault fronts the maximum cost
/// and becomes the transaction's payer) or a 20-byte sponsor address.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spend {
    pub actors: Vec<Address>,
    pub inputs: Vec<SpendInput>,
    pub utxo_outs: Vec<SpendOutput>,
    pub account_outs: Vec<SpendOutput>,
    pub change_index: u64,
    /// Empty = self-funded; 20 bytes = sponsor address. Kept as raw bytes
    /// because the empty and 20-byte forms are distinct: a 20-byte zero address
    /// is *not* self-funded. (The spec's pseudocode conflates them; flagged to
    /// the authors as a consensus-split ambiguity.)
    pub payer: Bytes,
    pub max_fee_per_gas: U256,
    pub max_priority_fee_per_gas: U256,
    pub max_gas_limit: u64,
}

impl RLPEncode for SpendOutput {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.recipient)
            .encode_field(&self.value)
            .finish();
    }
}

impl RLPDecode for SpendOutput {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (recipient, decoder) = decoder.decode_field("recipient")?;
        let (value, decoder) = decoder.decode_field("value")?;
        let rest = decoder.finish()?;
        Ok((SpendOutput { recipient, value }, rest))
    }
}

impl RLPEncode for SpendInput {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.index)
            .encode_field(&self.creation_block)
            .encode_field(&self.source)
            .encode_field(&self.recipient)
            .encode_field(&self.value)
            .encode_field(&self.position)
            .encode_field(&self.siblings)
            .encode_field(&self.batch_siblings)
            .finish();
    }
}

impl RLPDecode for SpendInput {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (index, decoder) = decoder.decode_field("index")?;
        let (creation_block, decoder) = decoder.decode_field("creation_block")?;
        let (source, decoder) = decoder.decode_field("source")?;
        let (recipient, decoder) = decoder.decode_field("recipient")?;
        let (value, decoder) = decoder.decode_field("value")?;
        let (position, decoder) = decoder.decode_field("position")?;
        let (siblings, decoder) = decoder.decode_field("siblings")?;
        let (batch_siblings, decoder) = decoder.decode_field("batch_siblings")?;
        let rest = decoder.finish()?;
        Ok((
            SpendInput {
                index,
                creation_block,
                source,
                recipient,
                value,
                position,
                siblings,
                batch_siblings,
            },
            rest,
        ))
    }
}

impl RLPEncode for Spend {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.actors)
            .encode_field(&self.inputs)
            .encode_field(&self.utxo_outs)
            .encode_field(&self.account_outs)
            .encode_field(&self.change_index)
            .encode_field(&self.payer)
            .encode_field(&self.max_fee_per_gas)
            .encode_field(&self.max_priority_fee_per_gas)
            .encode_field(&self.max_gas_limit)
            .finish();
    }
}

impl RLPDecode for Spend {
    fn decode_unfinished(rlp: &[u8]) -> Result<(Self, &[u8]), RLPDecodeError> {
        let decoder = Decoder::new(rlp)?;
        let (actors, decoder) = decoder.decode_field("actors")?;
        let (inputs, decoder) = decoder.decode_field("inputs")?;
        let (utxo_outs, decoder) = decoder.decode_field("utxo_outs")?;
        let (account_outs, decoder) = decoder.decode_field("account_outs")?;
        let (change_index, decoder) = decoder.decode_field("change_index")?;
        let (payer, decoder) = decoder.decode_field("payer")?;
        let (max_fee_per_gas, decoder) = decoder.decode_field("max_fee_per_gas")?;
        let (max_priority_fee_per_gas, decoder) =
            decoder.decode_field("max_priority_fee_per_gas")?;
        let (max_gas_limit, decoder) = decoder.decode_field("max_gas_limit")?;
        let rest = decoder.finish()?;
        Ok((
            Spend {
                actors,
                inputs,
                utxo_outs,
                account_outs,
                change_index,
                payer,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                max_gas_limit,
            },
            rest,
        ))
    }
}

/// Static validity of a decoded spend: every rule checkable without state.
///
/// Stringly-typed to match the surrounding `validate_static_constraints`
/// convention (the caller prefixes the frame index).
impl Spend {
    /// Decode a UTXO frame's `data`. Rejects trailing bytes after the payload
    /// and inside every nested list (the `Decoder::finish` calls above), so a
    /// frame's data is exactly one spend and nothing more.
    pub fn decode_frame_data(data: &Bytes) -> Result<Self, String> {
        Self::decode(data).map_err(|e| format!("invalid spend payload: {e}"))
    }

    /// The outputs in canonical order: `utxo_outs` followed by `account_outs`.
    /// `change_index` indexes into this concatenation.
    pub fn outputs(&self) -> impl Iterator<Item = &SpendOutput> {
        self.utxo_outs.iter().chain(self.account_outs.iter())
    }

    /// Total number of outputs.
    pub fn output_count(&self) -> usize {
        self.utxo_outs.len() + self.account_outs.len()
    }

    /// Whether this is a self-funded spend (empty `payer`), in which case the
    /// vault fronts the transaction's maximum cost and becomes its payer.
    ///
    /// Tested on the *length*, never on a numeric zero: a 20-byte zero address
    /// is a (nonsensical, and rejected) sponsor, not a self-funded marker.
    pub fn is_self_funded(&self) -> bool {
        self.payer.is_empty()
    }

    /// The sponsor named by this spend, if any.
    pub fn sponsor(&self) -> Option<Address> {
        (self.payer.len() == 20).then(|| Address::from_slice(&self.payer))
    }

    /// Static bounds and shape rules, per EIP-8312 §Constraints. Rules that need
    /// state (proof verification, spent bits, conservation) or the transaction
    /// envelope (fee-cap comparison, sender checks) are enforced elsewhere.
    pub fn validate_static(&self) -> Result<(), String> {
        // Actors: at least one, pairwise distinct.
        if self.actors.is_empty() {
            return Err("spend has no actors".to_string());
        }
        for (i, actor) in self.actors.iter().enumerate() {
            if self.actors[..i].contains(actor) {
                return Err(format!("spend actor {actor:#x} appears more than once"));
            }
        }

        // Inputs: at least one, strictly increasing indices (which statically
        // excludes spending one UTXO twice within a frame), bounded witnesses.
        if self.inputs.is_empty() {
            return Err("spend has no inputs".to_string());
        }
        for (i, input) in self.inputs.iter().enumerate() {
            if i > 0 && input.index <= self.inputs[i - 1].index {
                return Err(format!(
                    "spend input indices must be strictly increasing (input {i}: {} after {})",
                    input.index,
                    self.inputs[i - 1].index
                ));
            }
            if input.siblings.len() > MAX_SIBLINGS {
                return Err(format!(
                    "spend input {i}: {} siblings exceeds the {MAX_SIBLINGS} limit",
                    input.siblings.len()
                ));
            }
            // `position` selects a leaf in a tree of depth `len(siblings)`.
            if input.siblings.len() < 64 && input.position >= (1u64 << input.siblings.len()) {
                return Err(format!(
                    "spend input {i}: position {} out of range for a depth-{} path",
                    input.position,
                    input.siblings.len()
                ));
            }
            // A batch path is either absent (ring proof) or exactly the batch
            // tree's depth.
            if !input.batch_siblings.is_empty() && input.batch_siblings.len() != BATCH_PATH_LEN {
                return Err(format!(
                    "spend input {i}: batch path must be empty or {BATCH_PATH_LEN} siblings, got {}",
                    input.batch_siblings.len()
                ));
            }
        }

        // Outputs: change index in range; the change entry is signed with value
        // zero and every other output with a non-zero value; no zero recipients.
        let output_count = self.output_count();
        if self.change_index >= output_count as u64 {
            return Err(format!(
                "spend change_index {} out of range for {output_count} outputs",
                self.change_index
            ));
        }
        for (j, out) in self.outputs().enumerate() {
            if out.recipient == Address::zero() {
                return Err(format!(
                    "spend output {j} has the zero address as recipient"
                ));
            }
            let is_change = j as u64 == self.change_index;
            if is_change && !out.value.is_zero() {
                return Err(format!(
                    "spend change output {j} must be signed with value zero, got {}",
                    out.value
                ));
            }
            if !is_change && out.value.is_zero() {
                return Err(format!("spend output {j} must have a non-zero value"));
            }
        }

        // Payer: empty (self-funded) or a 20-byte address that is neither the
        // vault nor the zero address. The vault is excluded because it is the
        // payer the protocol assigns for self-funded spends; the zero address is
        // excluded so that the two encodings of "no sponsor" cannot be confused.
        match self.payer.len() {
            0 => {}
            20 => {
                let sponsor = Address::from_slice(&self.payer);
                if sponsor == utxo_vault() {
                    return Err("spend payer must not be the vault".to_string());
                }
                if sponsor == Address::zero() {
                    return Err(
                        "spend payer must not be the zero address (use an empty payer for a self-funded spend)"
                            .to_string(),
                    );
                }
            }
            other => {
                return Err(format!("spend payer must be 0 or 20 bytes, got {other}"));
            }
        }

        Ok(())
    }

    /// The spend hash actors sign: `keccak256(SPEND_MAGIC || rlp([...]))`, where
    /// per-input witness fields are replaced by the signed pair
    /// `[index, creation_block]` so that refreshing a witness does not
    /// invalidate a signature.
    pub fn spend_hash(&self, chain_id: u64) -> H256 {
        let signed_inputs: Vec<SignedInput> = self
            .inputs
            .iter()
            .map(|input| SignedInput {
                index: input.index,
                creation_block: input.creation_block,
            })
            .collect();

        let mut payload = Vec::new();
        Encoder::new(&mut payload)
            .encode_field(&chain_id)
            .encode_field(&self.actors)
            .encode_field(&signed_inputs)
            .encode_field(&self.utxo_outs)
            .encode_field(&self.account_outs)
            .encode_field(&self.change_index)
            .encode_field(&self.payer)
            .encode_field(&self.max_fee_per_gas)
            .encode_field(&self.max_priority_fee_per_gas)
            .encode_field(&self.max_gas_limit)
            .finish();

        let mut preimage = Vec::with_capacity(1 + payload.len());
        preimage.push(SPEND_MAGIC);
        preimage.extend_from_slice(&payload);
        keccak(&preimage)
    }
}

/// The signed projection of an input: `[index, creation_block]`. Only these two
/// fields enter the spend hash.
struct SignedInput {
    index: u64,
    creation_block: u64,
}

impl RLPEncode for SignedInput {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.index)
            .encode_field(&self.creation_block)
            .finish();
    }
}

// ---------------------------------------------------------------------------
// Vault storage layout
//
// Slot regions are disjoint by construction, given `index < 2**64` and
// `block_number < 2**64`:
//   next-index  : 0
//   ring        : 1 .. 1 + RING_SIZE            (8193 at most)
//   batch roots : 2**128 .. 2**128 + 2**51      (block/8192 < 2**64/2**13)
//   spent bits  : 2**129 .. 2**129 + 2**56      (index>>8 < 2**64/2**8)
// ---------------------------------------------------------------------------

/// Counter of assigned UTXO indices.
pub const SLOT_NEXT_INDEX: u64 = 0;
/// Base of the per-block openings-root ring.
pub const SLOT_RING_BASE: u64 = 1;

/// Base of the batch-root region (`2**128`).
pub fn slot_batch_base() -> U256 {
    U256::one() << 128
}

/// Base of the spent-bit bitfield region (`2**129`).
pub fn slot_spent_base() -> U256 {
    U256::one() << 129
}

/// Vault slot holding block `block_number`'s openings root.
pub fn ring_slot(block_number: u64) -> U256 {
    U256::from(SLOT_RING_BASE) + U256::from(block_number % RING_SIZE)
}

/// Vault slot holding the batch root of the batch containing `block_number`.
pub fn batch_slot_for_block(block_number: u64) -> U256 {
    slot_batch_base() + U256::from(block_number / BATCH_SIZE)
}

/// Vault slot holding the batch root of batch `batch_index`.
pub fn batch_slot(batch_index: u64) -> U256 {
    slot_batch_base() + U256::from(batch_index)
}

/// The `(slot, bit_mask)` pair addressing a UTXO's spent bit: bit
/// `index & 0xFF` of the word at `SLOT_SPENT_BASE + (index >> 8)`. A slot packs
/// 256 flags, which is why a spend is charged 1/256 of a new slot's state gas.
pub fn spent_bit_location(index: u64) -> (U256, U256) {
    let slot = slot_spent_base() + U256::from(index >> 8);
    let mask = U256::one() << (index & 0xFF) as usize;
    (slot, mask)
}

/// Whether `word` (the value of a spent-bit slot) marks `index` as spent.
pub fn is_spent(word: U256, index: u64) -> bool {
    let (_, mask) = spent_bit_location(index);
    !(word & mask).is_zero()
}

/// Whether a block is the last of its batch, i.e. the block at whose end the
/// batch root is sealed.
pub fn seals_batch(block_number: u64) -> bool {
    block_number % BATCH_SIZE == BATCH_SIZE - 1
}

// ---------------------------------------------------------------------------
// Openings tree
//
// ONE definition, shared by root construction (block end), proof verification
// (frame execution), and mempool policy. EIP-8272's forged-roots hole came from
// commitment logic living in more than one place; do not duplicate these.
// ---------------------------------------------------------------------------

/// A UTXO's openings-tree leaf:
/// `keccak256(index_be8 ++ source ++ recipient ++ value_be32)` — 80 bytes of
/// preimage. Leaves are keccak of 80 bytes while interior nodes are keccak of
/// 64, so a leaf can never be reinterpreted as an interior node (and vice
/// versa) without a preimage: that domain separation is what makes the
/// all-zeros empty-tree sentinel unforgeable, since no leaf can hash to zero.
pub fn opening_leaf(index: u64, source: Address, recipient: Address, value: U256) -> H256 {
    let mut preimage = [0u8; 80];
    preimage[..8].copy_from_slice(&index.to_be_bytes());
    preimage[8..28].copy_from_slice(source.as_bytes());
    preimage[28..48].copy_from_slice(recipient.as_bytes());
    preimage[48..80].copy_from_slice(&value.to_big_endian());
    keccak(preimage)
}

/// Merkle root of a block's openings, per EIP-8312.
///
/// Empty input is the all-zeros sentinel. Otherwise the leaf list is padded with
/// all-zeros leaves until its length is a power of two, then folded bottom-up
/// with `parent = keccak256(left ++ right)`.
///
/// The power-of-two padding is load-bearing and is NOT the same as padding each
/// odd level with one zero: for five leaves the former pairs `e` against
/// `keccak(0‖0)` at the second level while the latter pairs it against a raw
/// zero word, producing a different root. Pairing is positional — never sorted
/// or commutative — so that the position-bit [`fold`] verifier accepts a proof
/// for every leaf.
pub fn merkle_root(leaves: &[H256]) -> H256 {
    if leaves.is_empty() {
        return H256::zero();
    }
    let mut level: Vec<H256> = leaves.to_vec();
    while !level.len().is_power_of_two() {
        level.push(H256::zero());
    }
    while level.len() > 1 {
        level = level
            .chunks_exact(2)
            .map(|pair| hash_pair(pair[0], pair[1]))
            .collect();
    }
    level[0]
}

/// `keccak256(left ++ right)` — one interior node of the openings tree.
pub fn hash_pair(left: H256, right: H256) -> H256 {
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(left.as_bytes());
    preimage[32..].copy_from_slice(right.as_bytes());
    keccak(preimage)
}

/// Recompute a root from `node` and its `siblings`, taking the side to hash on
/// from the low bit of `position` at each level (bit set = `node` is the right
/// child). Used for both the in-block openings path and the batch path.
pub fn fold(node: H256, position: u64, siblings: &[H256]) -> H256 {
    let mut node = node;
    let mut position = position;
    for sibling in siblings {
        node = if position & 1 == 1 {
            hash_pair(*sibling, node)
        } else {
            hash_pair(node, *sibling)
        };
        position >>= 1;
    }
    node
}

/// The sibling path proving `leaves[position]` under [`merkle_root`], or `None`
/// if `position` is out of range. Provided so that root construction and witness
/// construction cannot drift apart; nodes are ordered leaf-to-root, matching
/// [`fold`].
pub fn merkle_proof(leaves: &[H256], position: usize) -> Option<Vec<H256>> {
    if position >= leaves.len() {
        return None;
    }
    let mut level: Vec<H256> = leaves.to_vec();
    while !level.len().is_power_of_two() {
        level.push(H256::zero());
    }
    let mut idx = position;
    let mut proof = Vec::new();
    while level.len() > 1 {
        proof.push(level[idx ^ 1]);
        level = level
            .chunks_exact(2)
            .map(|pair| hash_pair(pair[0], pair[1]))
            .collect();
        idx /= 2;
    }
    Some(proof)
}

/// One self-contained UTXO opening joined to its EIP-8304 event position.
/// Records are stored in ascending global-index order; their array offset is
/// the opening position and is therefore not duplicated in this structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UtxoProofRecord {
    pub index: u64,
    pub source: Address,
    pub recipient: Address,
    pub value: U256,
    pub transaction_index: u32,
    pub transaction_log_index: u32,
}

impl UtxoProofRecord {
    pub const ENCODED_LEN: usize = 88;

    pub fn opening_leaf(&self) -> H256 {
        opening_leaf(self.index, self.source, self.recipient, self.value)
    }

    fn encode_into(&self, encoded: &mut Vec<u8>) {
        encoded.extend_from_slice(&self.index.to_be_bytes());
        encoded.extend_from_slice(self.source.as_bytes());
        encoded.extend_from_slice(self.recipient.as_bytes());
        encoded.extend_from_slice(&self.value.to_big_endian());
        encoded.extend_from_slice(&self.transaction_index.to_be_bytes());
        encoded.extend_from_slice(&self.transaction_log_index.to_be_bytes());
    }

    fn decode(encoded: &[u8]) -> Result<Self, UtxoProofTableError> {
        if encoded.len() != Self::ENCODED_LEN {
            return Err(UtxoProofTableError::Malformed("invalid record length"));
        }
        Ok(Self {
            index: u64::from_be_bytes(
                encoded[..8]
                    .try_into()
                    .map_err(|_| UtxoProofTableError::Malformed("invalid record index"))?,
            ),
            source: Address::from_slice(&encoded[8..28]),
            recipient: Address::from_slice(&encoded[28..48]),
            value: U256::from_big_endian(&encoded[48..80]),
            transaction_index: u32::from_be_bytes(
                encoded[80..84]
                    .try_into()
                    .map_err(|_| UtxoProofTableError::Malformed("invalid transaction index"))?,
            ),
            transaction_log_index: u32::from_be_bytes(
                encoded[84..88]
                    .try_into()
                    .map_err(|_| UtxoProofTableError::Malformed("invalid transaction log index"))?,
            ),
        })
    }
}

/// One node in a shared openings-tree multiproof. `level == 0` addresses the
/// padded leaf layer and increasing levels approach the root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UtxoProofNode {
    pub level: usize,
    pub node_index: usize,
    pub hash: H256,
}

/// Block-scoped UTXO Proof Table retained outside Ethereum state.
/// Its contents remain untrusted until a wallet verifies `openings_root`
/// against the native vault and folds the selected records to that root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoProofTable {
    chain_id: u64,
    vault: Address,
    block_number: u64,
    block_hash: H256,
    openings_root: H256,
    records: Vec<UtxoProofRecord>,
    internal_nodes: Vec<H256>,
    event_position_index: BTreeMap<(u32, u32), usize>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum UtxoProofTableError {
    #[error("UTXO proof table contains too many transactions or logs")]
    PositionOverflow,
    #[error("UTXO proof table indexes are duplicate or non-consecutive")]
    NonConsecutiveIndexes,
    #[error("UTXO proof table contains duplicate event positions")]
    DuplicateEventPositions,
    #[error("malformed UTXO proof table: {0}")]
    Malformed(&'static str),
    #[error("stored UTXO proof table root does not match its records")]
    RootMismatch,
    #[error("stored UTXO proof table internal nodes do not match its records")]
    InternalNodesMismatch,
}

impl UtxoProofTable {
    const STORAGE_HEADER_LEN: usize = 2 + 32 + 20 + 8 + 32 + 32 + 4 + 4;

    /// Build the block UPT from canonical receipts. This parser is shared with
    /// consensus root construction through [`decode_utxo_created_log`] and
    /// [`opening_leaf`], preventing the archive and accepted root from drifting.
    pub fn from_receipts(
        chain_id: u64,
        block_number: u64,
        block_hash: H256,
        receipts: &[Receipt],
    ) -> Result<Self, UtxoProofTableError> {
        let mut records = Vec::new();
        for (transaction_index, receipt) in receipts.iter().enumerate() {
            let transaction_index = u32::try_from(transaction_index)
                .map_err(|_| UtxoProofTableError::PositionOverflow)?;
            for (transaction_log_index, log) in receipt.logs.iter().enumerate() {
                let Some(opening) = decode_utxo_created_log(log) else {
                    continue;
                };
                records.push(UtxoProofRecord {
                    index: opening.index,
                    source: opening.source,
                    recipient: opening.recipient,
                    value: opening.value,
                    transaction_index,
                    transaction_log_index: u32::try_from(transaction_log_index)
                        .map_err(|_| UtxoProofTableError::PositionOverflow)?,
                });
            }
        }
        records.sort_unstable_by_key(|record| record.index);
        u32::try_from(records.len()).map_err(|_| UtxoProofTableError::PositionOverflow)?;
        Self::STORAGE_HEADER_LEN
            .checked_add(
                records
                    .len()
                    .checked_mul(UtxoProofRecord::ENCODED_LEN)
                    .ok_or(UtxoProofTableError::PositionOverflow)?,
            )
            .and_then(|offset| u32::try_from(offset).ok())
            .ok_or(UtxoProofTableError::PositionOverflow)?;
        let event_position_index = validate_records(&records)?;
        let leaves = records
            .iter()
            .map(UtxoProofRecord::opening_leaf)
            .collect::<Vec<_>>();
        let openings_root = merkle_root(&leaves);
        let internal_nodes = opening_internal_nodes(&leaves);
        u32::try_from(internal_nodes.len()).map_err(|_| UtxoProofTableError::PositionOverflow)?;
        Ok(Self {
            chain_id,
            vault: utxo_vault(),
            block_number,
            block_hash,
            openings_root,
            records,
            internal_nodes,
            event_position_index,
        })
    }

    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub const fn vault(&self) -> Address {
        self.vault
    }

    pub const fn block_number(&self) -> u64 {
        self.block_number
    }

    pub const fn block_hash(&self) -> H256 {
        self.block_hash
    }

    pub const fn openings_root(&self) -> H256 {
        self.openings_root
    }

    pub fn records(&self) -> &[UtxoProofRecord] {
        &self.records
    }

    pub fn internal_nodes(&self) -> &[H256] {
        &self.internal_nodes
    }

    pub fn table_hash(&self) -> H256 {
        let encoded = self.encode_canonical_ssz();
        let mut preimage = Vec::with_capacity(UTXO_PROOF_TABLE_HASH_DOMAIN.len() + encoded.len());
        preimage.extend_from_slice(UTXO_PROOF_TABLE_HASH_DOMAIN);
        preimage.extend_from_slice(&encoded);
        H256(Sha2Hasher.hash(&preimage))
    }

    /// Canonical SSZ serialization used by the UPT v2 `table_hash`. Both lists
    /// contain fixed-size elements, so the two offsets are sufficient and the
    /// still-open maximum-list bounds do not affect serialized bytes.
    pub fn encode_canonical_ssz(&self) -> Vec<u8> {
        let records_offset = u32::try_from(Self::STORAGE_HEADER_LEN)
            .expect("the fixed UPT header length fits uint32");
        let records_bytes = self
            .records
            .len()
            .checked_mul(UtxoProofRecord::ENCODED_LEN)
            .expect("UPT record byte length fits usize");
        let internal_nodes_offset = usize::try_from(records_offset)
            .expect("uint32 fits usize")
            .checked_add(records_bytes)
            .and_then(|offset| u32::try_from(offset).ok())
            .expect("UPT construction bounds its record list to uint32");
        let internal_node_bytes = self
            .internal_nodes
            .len()
            .checked_mul(32)
            .expect("UPT internal-node byte length fits usize");
        let capacity = usize::try_from(internal_nodes_offset)
            .expect("uint32 fits usize")
            .checked_add(internal_node_bytes)
            .expect("UPT canonical encoding length fits usize");
        let mut encoded = Vec::with_capacity(capacity);
        encoded.extend_from_slice(&UTXO_PROOF_TABLE_FORMAT_VERSION.to_le_bytes());
        encoded.extend_from_slice(&U256::from(self.chain_id).to_little_endian());
        encoded.extend_from_slice(self.vault.as_bytes());
        encoded.extend_from_slice(&self.block_number.to_le_bytes());
        encoded.extend_from_slice(self.block_hash.as_bytes());
        encoded.extend_from_slice(self.openings_root.as_bytes());
        encoded.extend_from_slice(&records_offset.to_le_bytes());
        encoded.extend_from_slice(&internal_nodes_offset.to_le_bytes());
        for record in &self.records {
            encoded.extend_from_slice(&record.index.to_le_bytes());
            encoded.extend_from_slice(record.source.as_bytes());
            encoded.extend_from_slice(record.recipient.as_bytes());
            encoded.extend_from_slice(&record.value.to_little_endian());
            encoded.extend_from_slice(&record.transaction_index.to_le_bytes());
            encoded.extend_from_slice(&record.transaction_log_index.to_le_bytes());
        }
        for node in &self.internal_nodes {
            encoded.extend_from_slice(node.as_bytes());
        }
        encoded
    }

    /// Select records by event position and construct one minimal shared
    /// openings-tree multiproof for all selected records in this block.
    pub fn select_by_event_positions(
        &self,
        positions: &BTreeSet<(u32, u32)>,
    ) -> Result<(Vec<(usize, UtxoProofRecord)>, Vec<UtxoProofNode>), UtxoProofTableError> {
        let mut selected = positions
            .iter()
            .map(|position| {
                let index = *self.event_position_index.get(position).ok_or(
                    UtxoProofTableError::Malformed(
                        "requested event position is not a UTXO opening",
                    ),
                )?;
                Ok((index, self.records[index]))
            })
            .collect::<Result<Vec<_>, UtxoProofTableError>>()?;
        selected.sort_unstable_by_key(|(index, _)| *index);
        let indices = selected.iter().map(|(index, _)| *index).collect::<Vec<_>>();
        let proof = self.stored_opening_multiproof(&indices)?;
        Ok((selected, proof))
    }

    fn stored_opening_multiproof(
        &self,
        indices: &[usize],
    ) -> Result<Vec<UtxoProofNode>, UtxoProofTableError> {
        if indices.iter().any(|index| *index >= self.records.len()) {
            return Err(UtxoProofTableError::Malformed("invalid opening selection"));
        }
        if indices.is_empty() || self.records.len() <= 1 {
            return Ok(Vec::new());
        }
        let width = self.records.len().next_power_of_two();
        let height = width.trailing_zeros() as usize;
        let mut known = indices.iter().copied().collect::<BTreeSet<_>>();
        let mut proof = BTreeMap::new();
        for level in 0..height {
            for index in &known {
                let sibling = *index ^ 1;
                if known.contains(&sibling) {
                    continue;
                }
                let hash = if level == 0 {
                    self.records
                        .get(sibling)
                        .map(UtxoProofRecord::opening_leaf)
                        .unwrap_or_default()
                } else {
                    let depth = height - level;
                    let heap_index = (1usize << depth) - 1 + sibling;
                    *self
                        .internal_nodes
                        .get(heap_index)
                        .ok_or(UtxoProofTableError::InternalNodesMismatch)?
                };
                proof.insert((level, sibling), hash);
            }
            known = known.into_iter().map(|index| index / 2).collect();
        }
        Ok(proof
            .into_iter()
            .map(|((level, node_index), hash)| UtxoProofNode {
                level,
                node_index,
                hash,
            })
            .collect())
    }

    /// Local persistence encoding. The RPC exposes typed fields; this compact
    /// fixed-width format is deliberately independent of JSON serialization.
    pub fn encode_storage(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(
            Self::STORAGE_HEADER_LEN
                + self.records.len() * UtxoProofRecord::ENCODED_LEN
                + self.internal_nodes.len() * 32,
        );
        encoded.extend_from_slice(&UTXO_PROOF_TABLE_FORMAT_VERSION.to_be_bytes());
        let mut chain_id = [0u8; 32];
        chain_id[24..].copy_from_slice(&self.chain_id.to_be_bytes());
        encoded.extend_from_slice(&chain_id);
        encoded.extend_from_slice(self.vault.as_bytes());
        encoded.extend_from_slice(&self.block_number.to_be_bytes());
        encoded.extend_from_slice(self.block_hash.as_bytes());
        encoded.extend_from_slice(self.openings_root.as_bytes());
        encoded.extend_from_slice(&(self.records.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&(self.internal_nodes.len() as u32).to_be_bytes());
        for record in &self.records {
            record.encode_into(&mut encoded);
        }
        for node in &self.internal_nodes {
            encoded.extend_from_slice(node.as_bytes());
        }
        encoded
    }

    pub fn decode_storage(encoded: &[u8]) -> Result<Self, UtxoProofTableError> {
        if encoded.len() < Self::STORAGE_HEADER_LEN {
            return Err(UtxoProofTableError::Malformed("truncated header"));
        }
        let version = u16::from_be_bytes(
            encoded[..2]
                .try_into()
                .map_err(|_| UtxoProofTableError::Malformed("invalid version"))?,
        );
        if version != UTXO_PROOF_TABLE_FORMAT_VERSION {
            return Err(UtxoProofTableError::Malformed("unsupported version"));
        }
        if encoded[2..26] != [0; 24] {
            return Err(UtxoProofTableError::Malformed("chain ID exceeds uint64"));
        }
        let chain_id = u64::from_be_bytes(
            encoded[26..34]
                .try_into()
                .map_err(|_| UtxoProofTableError::Malformed("invalid chain ID"))?,
        );
        let vault = Address::from_slice(&encoded[34..54]);
        if vault != utxo_vault() {
            return Err(UtxoProofTableError::Malformed("unexpected vault"));
        }
        let block_number = u64::from_be_bytes(
            encoded[54..62]
                .try_into()
                .map_err(|_| UtxoProofTableError::Malformed("invalid block number"))?,
        );
        let block_hash = H256::from_slice(&encoded[62..94]);
        let openings_root = H256::from_slice(&encoded[94..126]);
        let record_count = u32::from_be_bytes(
            encoded[126..130]
                .try_into()
                .map_err(|_| UtxoProofTableError::Malformed("invalid record count"))?,
        ) as usize;
        let internal_count = u32::from_be_bytes(
            encoded[130..134]
                .try_into()
                .map_err(|_| UtxoProofTableError::Malformed("invalid node count"))?,
        ) as usize;
        let expected_len = Self::STORAGE_HEADER_LEN
            .checked_add(
                record_count
                    .checked_mul(UtxoProofRecord::ENCODED_LEN)
                    .ok_or(UtxoProofTableError::Malformed("record length overflow"))?,
            )
            .and_then(|length| {
                internal_count
                    .checked_mul(32)
                    .and_then(|nodes| length.checked_add(nodes))
            })
            .ok_or(UtxoProofTableError::Malformed("table length overflow"))?;
        if encoded.len() != expected_len {
            return Err(UtxoProofTableError::Malformed("payload length mismatch"));
        }
        let mut offset = Self::STORAGE_HEADER_LEN;
        let mut records = Vec::with_capacity(record_count);
        for _ in 0..record_count {
            let end = offset + UtxoProofRecord::ENCODED_LEN;
            records.push(UtxoProofRecord::decode(&encoded[offset..end])?);
            offset = end;
        }
        let event_position_index = validate_records(&records)?;
        let mut internal_nodes = Vec::with_capacity(internal_count);
        for _ in 0..internal_count {
            internal_nodes.push(H256::from_slice(&encoded[offset..offset + 32]));
            offset += 32;
        }
        let leaves = records
            .iter()
            .map(UtxoProofRecord::opening_leaf)
            .collect::<Vec<_>>();
        if merkle_root(&leaves) != openings_root {
            return Err(UtxoProofTableError::RootMismatch);
        }
        if opening_internal_nodes(&leaves) != internal_nodes {
            return Err(UtxoProofTableError::InternalNodesMismatch);
        }
        Ok(Self {
            chain_id,
            vault,
            block_number,
            block_hash,
            openings_root,
            records,
            internal_nodes,
            event_position_index,
        })
    }
}

fn validate_records(
    records: &[UtxoProofRecord],
) -> Result<BTreeMap<(u32, u32), usize>, UtxoProofTableError> {
    if records.windows(2).any(|pair| {
        pair[0]
            .index
            .checked_add(1)
            .is_none_or(|next| pair[1].index != next)
    }) {
        return Err(UtxoProofTableError::NonConsecutiveIndexes);
    }
    let mut positions = BTreeMap::new();
    for (index, record) in records.iter().enumerate() {
        if positions
            .insert(
                (record.transaction_index, record.transaction_log_index),
                index,
            )
            .is_some()
        {
            return Err(UtxoProofTableError::DuplicateEventPositions);
        }
    }
    Ok(positions)
}

/// Heap-prefix internal-node representation required by UPT v2. Leaf hashes
/// remain recomputable from records and are intentionally not duplicated.
fn opening_internal_nodes(leaves: &[H256]) -> Vec<H256> {
    if leaves.len() <= 1 {
        return Vec::new();
    }
    let width = leaves.len().next_power_of_two();
    let mut heap = vec![H256::zero(); width * 2 - 1];
    heap[width - 1..width - 1 + leaves.len()].copy_from_slice(leaves);
    for index in (0..width - 1).rev() {
        heap[index] = hash_pair(heap[index * 2 + 1], heap[index * 2 + 2]);
    }
    heap.truncate(width - 1);
    heap
}

/// Minimal shared proof for multiple openings. When both children are selected,
/// neither is repeated as a proof node; their parent is computed directly.
pub fn opening_multiproof(leaves: &[H256], indices: &[usize]) -> Option<Vec<UtxoProofNode>> {
    if indices.iter().any(|index| *index >= leaves.len()) {
        return None;
    }
    if indices.is_empty() || leaves.len() <= 1 {
        return Some(Vec::new());
    }
    let width = leaves.len().next_power_of_two();
    let mut layer = leaves.to_vec();
    layer.resize(width, H256::zero());
    let mut layers = vec![layer.clone()];
    while layer.len() > 1 {
        layer = layer
            .chunks_exact(2)
            .map(|pair| hash_pair(pair[0], pair[1]))
            .collect();
        layers.push(layer.clone());
    }

    let mut known = indices.iter().copied().collect::<BTreeSet<_>>();
    let mut proof = BTreeMap::new();
    for (level, layer) in layers.iter().take(layers.len() - 1).enumerate() {
        for index in &known {
            let sibling = *index ^ 1;
            if !known.contains(&sibling) {
                proof.insert((level, sibling), layer[sibling]);
            }
        }
        known = known.into_iter().map(|index| index / 2).collect();
    }
    Some(
        proof
            .into_iter()
            .map(|((level, node_index), hash)| UtxoProofNode {
                level,
                node_index,
                hash,
            })
            .collect(),
    )
}

#[cfg(test)]
mod proof_table_tests {
    use super::*;
    use crate::types::TxType;

    fn address_topic(address: Address) -> H256 {
        let mut topic = [0u8; 32];
        topic[12..].copy_from_slice(address.as_bytes());
        H256(topic)
    }

    fn index_topic(index: u64) -> H256 {
        let mut topic = [0u8; 32];
        topic[24..].copy_from_slice(&index.to_be_bytes());
        H256(topic)
    }

    fn created_log(index: u64, source: Address, recipient: Address, value: U256) -> Log {
        Log {
            address: utxo_vault(),
            topics: vec![
                UTXO_CREATED_TOPIC,
                address_topic(source),
                address_topic(recipient),
                index_topic(index),
            ],
            data: Bytes::copy_from_slice(&value.to_big_endian()),
        }
    }

    #[test]
    fn canonical_log_decoder_rejects_the_old_three_topic_shape() {
        let source = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);
        let value = U256::from(99u64);
        let canonical = created_log(7, source, recipient, value);
        assert_eq!(
            decode_utxo_created_log(&canonical),
            Some(UtxoOpening {
                index: 7,
                source,
                recipient,
                value,
            })
        );

        let mut legacy = canonical;
        legacy.topics.pop();
        let mut legacy_data = [0u8; 64];
        legacy_data[24..32].copy_from_slice(&7u64.to_be_bytes());
        legacy_data[32..].copy_from_slice(&value.to_big_endian());
        legacy.data = Bytes::copy_from_slice(&legacy_data);
        assert_eq!(decode_utxo_created_log(&legacy), None);
    }

    #[test]
    fn proof_table_round_trips_and_selects_one_shared_opening_proof() {
        let source = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);
        let foreign = Log {
            address: Address::repeat_byte(0xff),
            topics: Vec::new(),
            data: Bytes::new(),
        };
        let receipts = vec![
            Receipt::new(
                TxType::Legacy,
                true,
                0,
                vec![
                    foreign,
                    created_log(10, source, recipient, U256::from(100u64)),
                    created_log(11, source, recipient, U256::from(200u64)),
                ],
            ),
            Receipt::new(
                TxType::Legacy,
                true,
                0,
                vec![created_log(12, recipient, source, U256::from(300u64))],
            ),
        ];
        let table = UtxoProofTable::from_receipts(31_337, 5, H256::repeat_byte(0x33), &receipts)
            .expect("valid proof table");
        assert_eq!(table.records().len(), 3);
        assert_eq!(table.records()[0].transaction_log_index, 1);
        assert_eq!(
            table.openings_root(),
            merkle_root(
                &table
                    .records()
                    .iter()
                    .map(UtxoProofRecord::opening_leaf)
                    .collect::<Vec<_>>()
            )
        );

        let encoded = table.encode_storage();
        assert_eq!(UtxoProofTable::decode_storage(&encoded).unwrap(), table);
        assert_ne!(table.table_hash(), H256::zero());

        let requested = BTreeSet::from([(0, 1), (1, 0)]);
        let (selected, proof) = table.select_by_event_positions(&requested).unwrap();
        assert_eq!(
            selected
                .iter()
                .map(|(_, record)| record.index)
                .collect::<Vec<_>>(),
            [10, 12]
        );
        assert_eq!(proof.len(), 2);
        assert_eq!(proof[0].level, 0);
        assert_eq!(proof[0].node_index, 1);
        assert_eq!(proof[1].level, 0);
        assert_eq!(proof[1].node_index, 3);

        let mut corrupt = encoded;
        corrupt[UtxoProofTable::STORAGE_HEADER_LEN + 48] ^= 1;
        assert_eq!(
            UtxoProofTable::decode_storage(&corrupt),
            Err(UtxoProofTableError::RootMismatch)
        );
    }
}
