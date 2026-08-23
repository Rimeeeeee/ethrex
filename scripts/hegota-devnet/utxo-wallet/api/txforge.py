#!/usr/bin/env python3
"""txforge Ã¢â‚¬â€ transaction forging for the EIP-8312 PoC devnet (ethrex frame transactions).

Reads one JSON command on stdin, writes one JSON result on stdout.
Requires: eth-account, eth-keys, eth-hash (see .venv).

Commands:
  ping            {}                                        -> {chainId, block, vaultBalance, nextIndex}
  genkey          {n}                                       -> {keys: [{key, address}]}
  transfer        {key, to, valueWei}                       -> {txHash}
  deploySponsor   {key}                                     -> {address, txHash}
  deposit         {key, recipient, valueWei}                -> {txHash, block, index}
  spend           {actorKeys, inputs, utxoOuts, accountOuts, changeIndex}
                  inputs: [{index, creationBlock, source, recipient, valueWei}]
                  outs:   [{recipient, valueWei}]
                                                              -> {txHash, block, gasUsed, status, created}
  sponsoredSpend  same as spend + {payer, sponsorCodeAddr}  -> same
  multiSponsoredSpend {sponsorKey, routes: [spend]}         -> same + {routes}

All spend commands build the witness from on-chain logs, sign, and submit a
type-0x06 frame transaction per the ethrex EIP-8312 PoC encoding.
"""
import json
import sys
import time
import urllib.request

from eth_account import Account
from eth_keys import keys as eth_keys
from eth_hash.auto import keccak
from eth_utils import to_checksum_address

VAULT = bytes(18) + b"\x83\x12"
VAULT_HEX = "0x" + VAULT.hex()
UTXO_CREATED_TOPIC = bytes.fromhex("3b19241465a47bc187f1d9c7db70834855a907183742a4b63aa824c576296f5e")
SPEND_MAGIC = 0x81
FRAME_TX_TYPE = 0x06
MODE_VERIFY = 1
MODE_UTXO = 5
SIG_SCHEME_SECP256K1 = 1
# sponsor runtime: PUSH1 1 (scope=payer) PUSH1 0 PUSH1 0 APPROVE Ã¢â‚¬â€ from the PoC tests
SPONSOR_RUNTIME = bytes.fromhex("600160006000aa")
SPONSOR_INITCODE = bytes.fromhex("6007 600c 6000 39 6007 6000 f3".replace(" ", "")) + SPONSOR_RUNTIME

# ---------------------------------------------------------------- RLP

def rlp_uint(v: int) -> bytes:
    if v == 0:
        return b"\x80"
    b = v.to_bytes((v.bit_length() + 7) // 8, "big")
    if len(b) == 1 and b[0] < 0x80:
        return b
    return bytes([0x80 + len(b)]) + b

def rlp_bytes(data: bytes) -> bytes:
    if len(data) == 0:
        return b"\x80"
    if len(data) == 1 and data[0] < 0x80:
        return data
    if len(data) <= 55:
        return bytes([0x80 + len(data)]) + data
    lb = len(data).to_bytes((len(data).bit_length() + 7) // 8, "big")
    return bytes([0xB7 + len(lb)]) + lb + data

def rlp_addr(addr: bytes | None) -> bytes:
    if addr is None:
        return b"\x80"  # RLP null: no target / no signer
    assert len(addr) == 20
    return bytes([0x80 + 20]) + addr

def rlp_list(items: list[bytes]) -> bytes:
    payload = b"".join(items)
    if len(payload) <= 55:
        return bytes([0xC0 + len(payload)]) + payload
    lb = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([0xF7 + len(lb)]) + lb + payload

def addr_of(a) -> bytes:
    if isinstance(a, str):
        a = a[2:] if a.startswith("0x") else a
        return bytes.fromhex(a)
    return a

# ---------------------------------------------------------------- openings tree (mirrors utxo.rs)

def opening_leaf(index: int, source: bytes, recipient: bytes, value: int) -> bytes:
    return keccak(index.to_bytes(8, "big") + source + recipient + value.to_bytes(32, "big"))

def hash_pair(left: bytes, right: bytes) -> bytes:
    return keccak(left + right)

def pad_pow2(leaves: list[bytes]) -> list[bytes]:
    out = list(leaves)
    while len(out) & (len(out) - 1):
        out.append(b"\x00" * 32)
    return out

def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return b"\x00" * 32
    level = pad_pow2(leaves)
    while len(level) > 1:
        level = [hash_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]

def merkle_proof(leaves: list[bytes], position: int) -> list[bytes]:
    level = pad_pow2(leaves)
    idx, proof = position, []
    while len(level) > 1:
        proof.append(level[idx ^ 1])
        level = [hash_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        idx //= 2
    return proof

# ---------------------------------------------------------------- RPC

class Rpc:
    def __init__(self, url: str):
        self.url = url
        self._id = 0
        self.last_wait_meta = None

    def call(self, method: str, params: list):
        self._id += 1
        req = urllib.request.Request(
            self.url,
            data=json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": self._id}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            out = json.loads(resp.read())
        if "error" in out:
            raise RuntimeError(f"{method}: {out['error']}")
        return out["result"]

    def wait_receipt(self, tx_hash: str, timeout_s: int = 180, confirmations: int = 0,
                     raw_tx: str | None = None):
        if confirmations < 0:
            raise ValueError("confirmations must be non-negative")
        started = time.monotonic()
        deadline = started + timeout_s
        last_receipt = None
        orphaned_hashes = set()
        resubmissions = 0
        first_receipt_ms = None
        first_canonical_receipt_ms = None

        def resubmit_after_reorg():
            nonlocal resubmissions
            if raw_tx is None:
                return
            try:
                returned_hash = self.call("eth_sendRawTransaction", [raw_tx])
                if returned_hash.lower() != tx_hash.lower():
                    raise RuntimeError(
                        f"reorg resubmission returned {returned_hash}, expected {tx_hash}"
                    )
                resubmissions += 1
            except RuntimeError as error:
                # A peer may have already restored the transaction to its pool.
                message = str(error).lower()
                if not any(marker in message for marker in (
                    "already known", "known transaction", "already imported"
                )):
                    raise

        while time.monotonic() < deadline:
            receipt = self.call("eth_getTransactionReceipt", [tx_hash])
            if receipt is not None:
                elapsed_ms = round((time.monotonic() - started) * 1000, 3)
                if first_receipt_ms is None:
                    first_receipt_ms = elapsed_ms
                last_receipt = receipt
                block_number = int(receipt["blockNumber"], 16)
                canonical_block = self.call("eth_getBlockByNumber", [hex(block_number), False])
                canonical = (
                    canonical_block is not None
                    and canonical_block["hash"].lower() == receipt["blockHash"].lower()
                )
                if canonical:
                    if first_canonical_receipt_ms is None:
                        first_canonical_receipt_ms = elapsed_ms
                    head = int(self.call("eth_blockNumber", []), 16)
                    if head >= block_number + confirmations:
                        # Close the race between the head/receipt reads above.
                        final_receipt = self.call("eth_getTransactionReceipt", [tx_hash])
                        final_block = self.call("eth_getBlockByNumber", [hex(block_number), False])
                        if (
                            final_receipt is not None
                            and final_receipt["blockHash"].lower() == receipt["blockHash"].lower()
                            and final_block is not None
                            and final_block["hash"].lower() == receipt["blockHash"].lower()
                        ):
                            self.last_wait_meta = {
                                "confirmations": confirmations,
                                "confirmedAtHead": head,
                                "reorgs": len(orphaned_hashes),
                                "resubmissions": resubmissions,
                                "firstReceiptMs": first_receipt_ms,
                                "firstCanonicalReceiptMs": first_canonical_receipt_ms,
                                "waitMs": round((time.monotonic() - started) * 1000, 3),
                            }
                            return final_receipt
                else:
                    orphan_hash = receipt["blockHash"].lower()
                    if orphan_hash not in orphaned_hashes:
                        orphaned_hashes.add(orphan_hash)
                        resubmit_after_reorg()
                    last_receipt = None
            elif last_receipt is not None:
                orphan_hash = last_receipt["blockHash"].lower()
                if orphan_hash not in orphaned_hashes:
                    orphaned_hashes.add(orphan_hash)
                    resubmit_after_reorg()
                last_receipt = None
            # Poll quickly enough to prepare the next workload transaction for
            # a three-second devnet slot without waiting most of another slot.
            time.sleep(0.5)
        raise TimeoutError(
            f"canonical receipt timeout for {tx_hash}: "
            f"confirmations={confirmations} reorgs={len(orphaned_hashes)} "
            f"resubmissions={resubmissions}"
        )

# ---------------------------------------------------------------- tx builders

def gas_params(rpc: Rpc):
    gp = int(rpc.call("eth_gasPrice", []), 16)
    priority = 1_000_000_000
    return priority, max(gp * 2, priority * 2)

def send_legacy_like(rpc: Rpc, key: str, to: bytes | None, value: int, data: bytes, gas: int,
                     nonce: int | None = None, confirmations: int = 0) -> dict:
    acct = Account.from_key(key)
    chain_id = int(rpc.call("eth_chainId", []), 16)
    if nonce is None:
        nonce = int(rpc.call("eth_getTransactionCount", [acct.address, "latest"]), 16)
    priority, max_fee = gas_params(rpc)
    tx = {
        "chainId": chain_id, "nonce": nonce, "gas": gas,
        "maxFeePerGas": max_fee, "maxPriorityFeePerGas": priority,
        "value": value, "data": data, "type": 2,
    }
    if to is not None:
        tx["to"] = to_checksum_address("0x" + to.hex())
    signed = acct.sign_transaction(tx)
    raw_hex = "0x" + signed.raw_transaction.hex()
    tx_hash = rpc.call("eth_sendRawTransaction", [raw_hex])
    receipt = rpc.wait_receipt(tx_hash, confirmations=confirmations, raw_tx=raw_hex)
    return {"txHash": tx_hash, "receipt": receipt, "confirmation": rpc.last_wait_meta}

def encode_frame(mode: int, flags: int, target: bytes | None, gas_limit: int, value: int, data: bytes) -> bytes:
    return rlp_list([rlp_uint(mode), rlp_uint(flags), rlp_addr(target), rlp_uint(gas_limit), rlp_uint(value), rlp_bytes(data)])

def encode_sig_entry(scheme: int, signer: bytes | None, msg: bytes, sig: bytes) -> bytes:
    return rlp_list([rlp_uint(scheme), rlp_addr(signer), rlp_bytes(msg), rlp_bytes(sig)])

def encode_envelope(chain_id: int, nonce_keys: list[int], nonce_seq: int, sender: bytes,
                    frames: list[bytes], signatures: list[bytes],
                    max_priority: int, max_fee: int) -> bytes:
    return bytes([FRAME_TX_TYPE]) + rlp_list([
        rlp_uint(chain_id),
        rlp_list([rlp_uint(k) for k in nonce_keys]),
        rlp_uint(nonce_seq),
        rlp_addr(sender),
        rlp_list(frames),
        rlp_list(signatures),
        rlp_uint(max_priority),
        rlp_uint(max_fee),
        rlp_uint(0),             # max_fee_per_blob_gas
        rlp_list([]),            # blob_versioned_hashes
        rlp_list([]),            # recent_root_references
    ])

# ---------------------------------------------------------------- spend construction

def encode_output(out: dict) -> bytes:
    return rlp_list([rlp_addr(addr_of(out["recipient"])), rlp_uint(int(out["valueWei"]))])

def encode_input_full(inp: dict) -> bytes:
    return rlp_list([
        rlp_uint(inp["index"]),
        rlp_uint(inp["creationBlock"]),
        rlp_addr(addr_of(inp["source"])),
        rlp_addr(addr_of(inp["recipient"])),
        rlp_uint(int(inp["valueWei"])),
        rlp_uint(inp["position"]),
        rlp_list([rlp_bytes(s) for s in inp["siblings"]]),
        rlp_list([rlp_bytes(s) for s in inp.get("batchSiblings", [])]),
    ])

def encode_input_signed(inp: dict) -> bytes:
    return rlp_list([rlp_uint(inp["index"]), rlp_uint(inp["creationBlock"])])

def encode_spend(actors: list[bytes], inputs: list[dict], utxo_outs: list[dict], account_outs: list[dict],
                 change_index: int, payer: bytes, max_fee: int, max_priority: int, max_gas_limit: int) -> bytes:
    return rlp_list([
        rlp_list([rlp_addr(a) for a in actors]),
        rlp_list([encode_input_full(i) for i in inputs]),
        rlp_list([encode_output(o) for o in utxo_outs]),
        rlp_list([encode_output(o) for o in account_outs]),
        rlp_uint(change_index),
        rlp_bytes(payer),
        rlp_uint(max_fee),
        rlp_uint(max_priority),
        rlp_uint(max_gas_limit),
    ])

def spend_hash(chain_id: int, actors: list[bytes], inputs: list[dict], utxo_outs: list[dict],
               account_outs: list[dict], change_index: int, payer: bytes,
               max_fee: int, max_priority: int, max_gas_limit: int) -> bytes:
    payload = rlp_list([
        rlp_uint(chain_id),
        rlp_list([rlp_addr(a) for a in actors]),
        rlp_list([encode_input_signed(i) for i in inputs]),
        rlp_list([encode_output(o) for o in utxo_outs]),
        rlp_list([encode_output(o) for o in account_outs]),
        rlp_uint(change_index),
        rlp_bytes(payer),
        rlp_uint(max_fee),
        rlp_uint(max_priority),
        rlp_uint(max_gas_limit),
    ])
    return keccak(bytes([SPEND_MAGIC]) + payload)

def block_openings(rpc: Rpc, block: int) -> list[dict]:
    """All UtxoCreated openings of a block, index-ordered, from on-chain logs."""
    logs = rpc.call("eth_getLogs", [{
        "address": VAULT_HEX,
        "topics": ["0x" + UTXO_CREATED_TOPIC.hex()],
        "fromBlock": hex(block), "toBlock": hex(block),
    }])
    openings = []
    for lg in logs:
        data = bytes.fromhex(lg["data"][2:])
        openings.append({
            "index": int.from_bytes(data[:32], "big"),
            "valueWei": int.from_bytes(data[32:64], "big"),
            "source": bytes.fromhex(lg["topics"][1][2:])[-20:],
            "recipient": bytes.fromhex(lg["topics"][2][2:])[-20:],
        })
    openings.sort(key=lambda o: o["index"])
    return openings

def attach_witness(rpc: Rpc, inp: dict) -> dict:
    openings = block_openings(rpc, inp["creationBlock"])
    leaves = [opening_leaf(o["index"], o["source"], o["recipient"], o["valueWei"]) for o in openings]
    positions = [o["index"] for o in openings]
    if inp["index"] not in positions:
        raise RuntimeError(f"input #{inp['index']}: no UtxoCreated log in block {inp['creationBlock']}")
    pos = positions.index(inp["index"])
    out = dict(inp)
    out["position"] = pos
    out["siblings"] = merkle_proof(leaves, pos)
    out["batchSiblings"] = []
    return out

def utxo_frame_gas(inputs: list[dict], n_utxo_outs: int, n_account_outs: int) -> int:
    gas = 13_000
    for inp in inputs:
        gas += 16_048 + 42 * (len(inp["siblings"]) + len(inp.get("batchSiblings", []))) + 383
    gas += 2_012 * n_utxo_outs
    gas += (9_000 + 183_600) * n_account_outs
    return gas

def sign_secp256k1(key: str, digest: bytes) -> bytes:
    sig = eth_keys.PrivateKey(bytes.fromhex(key[2:] if key.startswith("0x") else key)).sign_msg_hash(digest)
    return bytes([sig.v]) + sig.r.to_bytes(32, "big") + sig.s.to_bytes(32, "big")

def run_spend(rpc: Rpc, cmd: dict, sponsored: bool) -> dict:
    chain_id = int(rpc.call("eth_chainId", []), 16)
    priority, max_fee = gas_params(rpc)
    actor_keys = cmd["actorKeys"]
    actors = [addr_of(Account.from_key(k).address) for k in actor_keys]
    inputs = [attach_witness(rpc, i) for i in cmd["inputs"]]
    utxo_outs = cmd.get("utxoOuts", [])
    account_outs = cmd.get("accountOuts", [])
    change_index = int(cmd["changeIndex"])
    max_gas_limit = 400_000

    # Sponsored: the sponsor is a funded EOA and the tx sender itself; it signs
    # the envelope and its default code APPROVEs (SelfVerify prefix, scope 3).
    sponsor_addr = None
    if sponsored:
        sponsor_addr = addr_of(Account.from_key(cmd["sponsorKey"]).address)
    payer = sponsor_addr if sponsored else b""

    shash = spend_hash(chain_id, actors, inputs, utxo_outs, account_outs,
                       change_index, payer, max_fee, priority, max_gas_limit)
    actor_entries = [
        encode_sig_entry(SIG_SCHEME_SECP256K1, actor, shash, sign_secp256k1(k, shash))
        for k, actor in zip(actor_keys, actors)
    ]

    spend_rlp = encode_spend(actors, inputs, utxo_outs, account_outs,
                             change_index, payer, max_fee, priority, max_gas_limit)
    frame_gas = utxo_frame_gas(inputs, len(utxo_outs), len(account_outs)) + 2_000

    if sponsored:
        sender = sponsor_addr
        nonce_keys = [0]
        nonce_seq = int(rpc.call("eth_getTransactionCount", ["0x" + sender.hex(), "latest"]), 16)
        frames = [
            encode_frame(MODE_VERIFY, 0x03, sender, 90_000, 0, b""),
            encode_frame(MODE_UTXO, 0, None, frame_gas, 0, spend_rlp),
        ]
        # sig_hash: entries with empty msg are elided (signature bytes emptied),
        # entries with an explicit msg (the actors' spend-hash entries) are verbatim.
        sponsor_entry_blank = encode_sig_entry(SIG_SCHEME_SECP256K1, None, b"", b"")
        pre_image = encode_envelope(chain_id, nonce_keys, nonce_seq, sender, frames,
                                    [sponsor_entry_blank] + actor_entries, priority, max_fee)
        sig_hash = keccak(pre_image)
        sponsor_entry = encode_sig_entry(SIG_SCHEME_SECP256K1, None, b"",
                                         sign_secp256k1(cmd["sponsorKey"], sig_hash))
        signatures = [sponsor_entry] + actor_entries
    else:
        sender = VAULT
        nonce_keys = []
        nonce_seq = 0
        frames = [encode_frame(MODE_UTXO, 0, None, frame_gas, 0, spend_rlp)]
        signatures = actor_entries

    raw = encode_envelope(chain_id, nonce_keys, nonce_seq, sender, frames, signatures, priority, max_fee)
    tx_hash = rpc.call("eth_sendRawTransaction", ["0x" + raw.hex()])
    receipt = rpc.wait_receipt(
        tx_hash,
        confirmations=int(cmd.get("confirmations", 0)),
        raw_tx="0x" + raw.hex(),
    )
    created = []
    for lg in receipt.get("logs", []):
        if lg["address"].lower() == VAULT_HEX and lg["topics"][0].lower() == "0x" + UTXO_CREATED_TOPIC.hex():
            data = bytes.fromhex(lg["data"][2:])
            created.append({
                "index": int.from_bytes(data[:32], "big"),
                "valueWei": str(int.from_bytes(data[32:64], "big")),
                "recipient": "0x" + bytes.fromhex(lg["topics"][2][2:])[-20:].hex(),
            })
    return {
        "txHash": tx_hash,
        "block": int(receipt["blockNumber"], 16),
        "gasUsed": int(receipt["gasUsed"], 16),
        "status": receipt.get("status"),
        "created": created,
        "confirmation": rpc.last_wait_meta,
    }

def created_from_log(lg: dict, block: int) -> dict:
    data = bytes.fromhex(lg["data"][2:])
    return {
        "index": int.from_bytes(data[:32], "big"),
        "valueWei": str(int.from_bytes(data[32:64], "big")),
        "source": "0x" + bytes.fromhex(lg["topics"][1][2:])[-20:].hex(),
        "recipient": "0x" + bytes.fromhex(lg["topics"][2][2:])[-20:].hex(),
        "creationBlock": block,
        "txHash": lg.get("transactionHash"),
        "blockHash": lg.get("blockHash"),
        "logIndex": int(lg.get("logIndex", "0x0"), 16),
    }

def run_multi_sponsored_spend(rpc: Rpc, cmd: dict) -> dict:
    """Atomically execute several independently signed UTXO routes in one block.

    EIP-8312 permits only one self-funded UTXO frame per transaction. A funded
    EOA therefore sponsors this envelope, while every route remains authorized
    by the wallet that owns its input. This guarantees mixed A->B routes and all
    of their outputs share one receipt and one block.
    """
    routes = cmd.get("routes", [])
    if not routes:
        raise RuntimeError("multiSponsoredSpend requires at least one route")

    chain_id = int(rpc.call("eth_chainId", []), 16)
    priority, max_fee = gas_params(rpc)
    sponsor_key = cmd["sponsorKey"]
    sponsor_addr = addr_of(Account.from_key(sponsor_key).address)
    # The outer frame transaction uses max(sum(frame gas), calldata-floor gas).
    # With 70-100 UTXO outputs the calldata floor can exceed 500k even though the
    # individual frame limits sum to less than 500k. Actors bind this cap in each
    # spend signature, so leave enough headroom for the largest benchmark shape.
    max_gas_limit = 750_000
    actor_entries = []
    frames = [encode_frame(MODE_VERIFY, 0x03, sponsor_addr, 90_000, 0, b"")]
    frame_gas_limits = [90_000]
    route_output_counts = []

    for route_index, route in enumerate(routes):
        actor_keys = route["actorKeys"]
        actors = [addr_of(Account.from_key(k).address) for k in actor_keys]
        inputs = [attach_witness(rpc, item) for item in route["inputs"]]
        utxo_outs = route.get("utxoOuts", [])
        account_outs = route.get("accountOuts", [])
        change_index = int(route["changeIndex"])
        if not utxo_outs:
            raise RuntimeError(f"route {route_index}: at least one UTXO output is required")

        shash = spend_hash(
            chain_id, actors, inputs, utxo_outs, account_outs, change_index,
            sponsor_addr, max_fee, priority, max_gas_limit,
        )
        actor_entries.extend([
            encode_sig_entry(SIG_SCHEME_SECP256K1, actor, shash, sign_secp256k1(key, shash))
            for key, actor in zip(actor_keys, actors)
        ])
        spend_rlp = encode_spend(
            actors, inputs, utxo_outs, account_outs, change_index, sponsor_addr,
            max_fee, priority, max_gas_limit,
        )
        frame_gas = utxo_frame_gas(inputs, len(utxo_outs), len(account_outs)) + 2_000
        frames.append(encode_frame(MODE_UTXO, 0, None, frame_gas, 0, spend_rlp))
        frame_gas_limits.append(frame_gas)
        route_output_counts.append(len(utxo_outs))

    nonce_keys = [0]
    nonce_seq = int(rpc.call("eth_getTransactionCount", ["0x" + sponsor_addr.hex(), "latest"]), 16)
    sponsor_entry_blank = encode_sig_entry(SIG_SCHEME_SECP256K1, None, b"", b"")
    pre_image = encode_envelope(
        chain_id, nonce_keys, nonce_seq, sponsor_addr, frames,
        [sponsor_entry_blank] + actor_entries, priority, max_fee,
    )
    sponsor_entry = encode_sig_entry(
        SIG_SCHEME_SECP256K1, None, b"", sign_secp256k1(sponsor_key, keccak(pre_image)),
    )
    raw = encode_envelope(
        chain_id, nonce_keys, nonce_seq, sponsor_addr, frames,
        [sponsor_entry] + actor_entries, priority, max_fee,
    )
    if cmd.get("buildOnly"):
        return {
            "txHash": "0x" + keccak(raw).hex(),
            "rawTransaction": "0x" + raw.hex(),
            "nonceSeq": nonce_seq,
            "frameGasLimits": frame_gas_limits,
            "signedMaxGasLimit": max_gas_limit,
        }
    tx_hash = rpc.call("eth_sendRawTransaction", ["0x" + raw.hex()])
    receipt = rpc.wait_receipt(
        tx_hash,
        confirmations=int(cmd.get("confirmations", 0)),
        raw_tx="0x" + raw.hex(),
    )
    block = int(receipt["blockNumber"], 16)
    created = [
        created_from_log(log, block)
        for log in receipt.get("logs", [])
        if log["address"].lower() == VAULT_HEX
        and log["topics"][0].lower() == "0x" + UTXO_CREATED_TOPIC.hex()
    ]
    if len(created) != sum(route_output_counts):
        raise RuntimeError(
            f"multiSponsoredSpend created {len(created)} UTXOs; expected {sum(route_output_counts)}"
        )

    route_results = []
    cursor = 0
    for route_index, output_count in enumerate(route_output_counts):
        route_created = created[cursor:cursor + output_count]
        route_results.append({"route": route_index, "created": route_created})
        cursor += output_count
    return {
        "txHash": tx_hash,
        "block": block,
        "gasUsed": int(receipt["gasUsed"], 16),
        "status": receipt.get("status"),
        "created": created,
        "routes": route_results,
        "confirmation": rpc.last_wait_meta,
    }

# ---------------------------------------------------------------- commands

def main():
    cmd = json.load(sys.stdin)
    rpc = Rpc(cmd["rpc"])
    op = cmd["op"]

    if op == "ping":
        out = {
            "chainId": int(rpc.call("eth_chainId", []), 16),
            "block": int(rpc.call("eth_blockNumber", []), 16),
            "vaultBalance": int(rpc.call("eth_getBalance", [VAULT_HEX, "latest"]), 16),
            "nextIndex": int(rpc.call("eth_getStorageAt", [VAULT_HEX, "0x0", "latest"]), 16),
        }
    elif op == "addressOf":
        out = {"address": Account.from_key(cmd["key"]).address}
    elif op == "genkey":
        out = {"keys": [{"key": a.key.hex(), "address": a.address} for a in (Account.create() for _ in range(int(cmd["n"])))]}
    elif op == "transfer":
        # 21,000 regular + up to 183,600 state gas if the recipient is a fresh account
        r = send_legacy_like(
            rpc, cmd["key"], addr_of(cmd["to"]), int(cmd["valueWei"]), b"", 250_000,
            cmd.get("nonce"), int(cmd.get("confirmations", 0)),
        )
        out = {"txHash": r["txHash"], "block": int(r["receipt"]["blockNumber"], 16), "status": r["receipt"].get("status"), "confirmation": r["confirmation"]}
    elif op == "deploySponsor":
        r = send_legacy_like(
            rpc, cmd["key"], None, 0, SPONSOR_INITCODE, 2_000_000,
            cmd.get("nonce"), int(cmd.get("confirmations", 0)),
        )
        out = {"txHash": r["txHash"], "address": r["receipt"]["contractAddress"], "status": r["receipt"].get("status"), "confirmation": r["confirmation"]}
    elif op == "deposit":
        # A deposit updates the global index plus opening state and emits a
        # LOG3. Fresh-state deposits estimate around 136k gas on this devnet;
        # keep enough headroom for state-dependent variation.
        r = send_legacy_like(
            rpc, cmd["key"], VAULT, int(cmd["valueWei"]), addr_of(cmd["recipient"]), 250_000,
            cmd.get("nonce"), int(cmd.get("confirmations", 0)),
        )
        receipt = r["receipt"]
        index = None
        for lg in receipt.get("logs", []):
            if lg["address"].lower() == VAULT_HEX and lg["topics"][0].lower() == "0x" + UTXO_CREATED_TOPIC.hex():
                index = int.from_bytes(bytes.fromhex(lg["data"][2:])[:32], "big")
        out = {
            "txHash": r["txHash"],
            "block": int(receipt["blockNumber"], 16),
            "gasUsed": int(receipt["gasUsed"], 16),
            "status": receipt.get("status"),
            "index": index,
            "confirmation": r["confirmation"],
        }
    elif op == "spend":
        out = run_spend(rpc, cmd, sponsored=False)
    elif op == "sponsoredSpend":
        out = run_spend(rpc, cmd, sponsored=True)
    elif op == "multiSponsoredSpend":
        out = run_multi_sponsored_spend(rpc, cmd)
    elif op == "waitReceipt":
        receipt = rpc.wait_receipt(cmd["txHash"])
        created = []
        for lg in receipt.get("logs", []):
            if lg["address"].lower() == VAULT_HEX and lg["topics"][0].lower() == "0x" + UTXO_CREATED_TOPIC.hex():
                data = bytes.fromhex(lg["data"][2:])
                created.append({
                    "index": int.from_bytes(data[:32], "big"),
                    "valueWei": str(int.from_bytes(data[32:64], "big")),
                    "source": "0x" + bytes.fromhex(lg["topics"][1][2:])[-20:].hex(),
                    "recipient": "0x" + bytes.fromhex(lg["topics"][2][2:])[-20:].hex(),
                })
        out = {"block": int(receipt["blockNumber"], 16), "status": receipt.get("status"), "created": created}
    elif op == "block":
        out = {"block": int(rpc.call("eth_blockNumber", []), 16)}
    else:
        raise RuntimeError(f"unknown op {op}")

    json.dump(out, sys.stdout)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        json.dump({"error": str(e)}, sys.stdout)
        sys.exit(1)
