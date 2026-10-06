#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["eth-hash[pycryptodome]==0.7.1"]
# ///
"""Drive a disposable ethrex/Reth execution devnet through the Engine API."""
import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

from eth_hash.auto import keccak

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "hegota-testnet"))
from frametx import Frame, FrameTx  # noqa: E402

ZERO = "0x" + "00" * 32
CHAIN_ID = 82727906
GAS_LIMIT = 30_000_000
SENDER = "0x" + "aa" * 20
WRITER = "0x" + "00" * 18 + "7910"
ASSERTION = "0x" + "00" * 18 + "7911"
ROOT = "0x" + "00" * 18 + "8272"
NONCE_MANAGER = "0x" + "00" * 18 + "8250"
ROOT_HASH = "da160390a838ee04013b2ff3abf4decc9aa3cc6c2f59dd90ca176c2b850be4e3"
TOPIC = (1 << 256) - 1


def word(value):
    return value.to_bytes(32, "big")


def push(value):
    data = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    return bytes([0x5f + len(data)]) + data


def assertion_code():
    """Check the slot, event count, full-word topic view, and EVENTDATACOPY."""
    checks = [
        (push(1) + push(int(WRITER, 16)) + push(0) + b"\xb8", push(0) + b"\x35"),
        (push(0x0c) + push(0) + b"\xb7", push(1)),
        (push(0x0b) + push(TOPIC) + push(0) + b"\xb8", push(1)),
        (push(0x0b) + push(0x1234) + push(0) + b"\xb8", push(0)),
        (push(32) + push(0) + push(0) + push(0) + b"\xb9" + push(0) + b"\x51",
         push(0) + b"\x35"),
    ]
    code = bytearray()
    fixups = []
    for actual, expected in checks:
        code.extend(actual + expected + b"\x14\x15\x61\x00\x00\x57")
        fixups.append(len(code) - 3)
    code.append(0)
    failure = len(code)
    code.extend(b"\x5b\x60\x00\x60\x00\xfd")
    for offset in fixups:
        code[offset:offset + 2] = failure.to_bytes(2, "big")
    return bytes(code)


def genesis():
    alloc = json.loads((HERE / "system-alloc.json").read_text())
    runtime = bytes.fromhex((HERE.parent / "hegota-testnet/recent_root/main.hex")
                            .read_text().strip().removeprefix("0x"))
    assert keccak(runtime).hex() == ROOT_HASH
    # This permissive sender is exclusively for a disposable local devnet.
    # It authorizes anyone to use its prefunded balance without a signature.
    writer = (push(0) + b"\x35" + push(0) + b"\x55" + push(0) + b"\x35" +
              push(0) + b"\x52" + push(TOPIC) * 2 + push(0x1234) +
              push(32) + push(0) + b"\xa3\x00")
    for address, code, balance in [
        (SENDER, bytes.fromhex("600360006000aa00"), 10**25),
        (WRITER, writer, 0), (ASSERTION, assertion_code(), 0),
        (ROOT, runtime, 0), (NONCE_MANAGER, bytes.fromhex("60006000fd"), 0),
        ("0x" + "00" * 18 + "8141",
         bytes.fromhex("60083614600a575f5ffd5b5f3560c01c4211601657005b5f5ffd"), 0),
    ]:
        alloc[address] = {"balance": str(balance), "nonce": "0x1", "code": "0x" + code.hex()}
    config = {name + "Block": 0 for name in (
        "homestead", "eip150", "eip155", "eip158", "byzantium", "constantinople",
        "petersburg", "istanbul", "berlin", "london", "mergeNetsplit")}
    config.update({name + "Time": 0 for name in (
        "shanghai", "cancun", "prague", "osaka", "amsterdam", "bogota")})
    config.update(chainId=CHAIN_ID, terminalTotalDifficulty=0,
                  terminalTotalDifficultyPassed=True, focilTime=(1 << 64) - 1,
                  depositContractAddress="0x00000000219ab540356cbb839cbe05303d7705fa")
    return {"config": config, "alloc": alloc, "coinbase": "0x" + "00" * 20,
            "difficulty": "0x0", "gasLimit": hex(GAS_LIMIT), "nonce": "0x0",
            "timestamp": hex(1_700_000_000), "extraData": "0x", "mixHash": ZERO,
            "baseFeePerGas": "0x3b9aca00", "blobGasUsed": "0x0",
            "excessBlobGas": "0x0", "slotNumber": "0x0"}


class RpcError(RuntimeError):
    pass


class Node:
    def __init__(self, name, port, authport, secret):
        self.name, self.port, self.authport, self.secret = name, port, authport, secret
        self.process = None

    def rpc(self, method, params=(), engine=False):
        headers = {"Content-Type": "application/json"}
        if engine:
            def b64(value):
                return base64.urlsafe_b64encode(value).rstrip(b"=")
            signing = b64(b'{"alg":"HS256","typ":"JWT"}') + b"." + b64(
                json.dumps({"iat": int(time.time())}).encode())
            headers["Authorization"] = "Bearer " + (signing + b"." + b64(
                hmac.new(self.secret, signing, hashlib.sha256).digest())).decode()
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.authport if engine else self.port}",
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                        "params": list(params)}).encode(), headers)
        with urllib.request.urlopen(request, timeout=45) as response:
            result = json.load(response)
        if "error" in result:
            raise RpcError(f"{self.name} {method}: {result['error']}")
        return result["result"]


class Devnet:
    def __init__(self, nodes, directory):
        self.nodes, self.directory = nodes, directory
        self.blocks = []
        self.head = nodes[0].rpc("eth_getBlockByNumber", ["latest", False])
        other = nodes[1].rpc("eth_getBlockByNumber", ["latest", False])
        self.compare_headers(self.head, other)
        for node in nodes:
            code = node.rpc("eth_getCode", [ROOT, "latest"])
            assert keccak(bytes.fromhex(code[2:])).hex() == ROOT_HASH
        self.genesis_hash = self.head["hash"]
        self.save_report()
        print(f"PASS shared genesis {self.genesis_hash}", flush=True)

    @staticmethod
    def compare_headers(left, right):
        for field in ("hash", "stateRoot", "receiptsRoot", "transactionsRoot",
                      "gasUsed", "gasLimit", "blockAccessListHash", "slotNumber"):
            assert left.get(field) == right.get(field), (field, left.get(field), right.get(field))

    def save_report(self):
        report = {"genesisHash": self.genesis_hash, "recentRootCodeHash": "0x" + ROOT_HASH,
                  "rethTarget": "ce5d5648f3", "revmTarget": "035f51522b90080440c9ed60337c80823c0b3f43",
                  "clients": {n.name: n.rpc("web3_clientVersion") for n in self.nodes},
                  "blocks": self.blocks}
        (self.directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    def build(self, producer, expected=(), label="empty", status=1, storage=None):
        choice = {"headBlockHash": self.head["hash"], "safeBlockHash": self.genesis_hash,
                  "finalizedBlockHash": self.genesis_hash}
        attributes = {"timestamp": hex(int(self.head["timestamp"], 16) + 12),
                      "prevRandao": ZERO, "suggestedFeeRecipient": "0x" + "bb" * 20,
                      "withdrawals": [], "parentBeaconBlockRoot": ZERO,
                      "slotNumber": hex(int(self.head.get("slotNumber", "0x0"), 16) + 1),
                      "targetGasLimit": hex(GAS_LIMIT)}
        result = producer.rpc("engine_forkchoiceUpdatedV4", [choice, attributes], True)
        assert result["payloadStatus"]["status"] == "VALID", result
        payload_id = result["payloadId"]
        deadline = time.monotonic() + 15
        while True:
            time.sleep(0.5)
            envelope = producer.rpc("engine_getPayloadV6", [payload_id], True)
            payload = envelope["executionPayload"]
            tx_hashes = ["0x" + keccak(bytes.fromhex(tx[2:])).hex()
                         for tx in payload["transactions"]]
            if all(tx in tx_hashes for tx in expected):
                break
            if time.monotonic() >= deadline:
                raise AssertionError(f"{producer.name}: expected {expected}, payload has {tx_hashes}")
        for node in self.nodes:
            verdict = node.rpc("engine_newPayloadV5", [payload, [], ZERO,
                               envelope.get("executionRequests", [])], True)
            assert verdict["status"] == "VALID", (node.name, label, verdict)
        choice["headBlockHash"] = payload["blockHash"]
        for node in self.nodes:
            result = node.rpc("engine_forkchoiceUpdatedV4", [choice, None], True)
            assert result["payloadStatus"]["status"] == "VALID", (node.name, result)
        headers = [n.rpc("eth_getBlockByNumber", ["latest", False]) for n in self.nodes]
        self.compare_headers(*headers)
        self.head = headers[0]
        receipts = []
        for tx_hash in expected:
            pair = [n.rpc("eth_getTransactionReceipt", [tx_hash]) for n in self.nodes]
            assert all(receipt and int(receipt["status"], 16) == status for receipt in pair), pair
            # Provider-specific optional fields may differ; consensus receipt fields must agree.
            for field in ("gasUsed", "cumulativeGasUsed", "logs", "logsBloom", "payer"):
                assert pair[0].get(field) == pair[1].get(field), (field, pair)
            def consensus_frames(receipt):
                assert receipt.get("frameReceipts"), receipt
                frames = []
                for frame in receipt["frameReceipts"]:
                    assert int(frame["gasUsed"], 16) == (int(frame["executionGasUsed"], 16) +
                                                        int(frame["stateGasUsed"], 16)), frame
                    frames.append({**frame, "logs": [
                        {key: log[key] for key in ("address", "topics", "data")}
                        for log in frame["logs"]]})
                return frames
            assert consensus_frames(pair[0]) == consensus_frames(pair[1]), pair
            receipts.append(pair[0])
        if storage is not None:
            values = [int(n.rpc("eth_getStorageAt", [WRITER, "0x0", "latest"]), 16)
                      for n in self.nodes]
            assert values == [storage, storage], values
        self.blocks.append({"label": label, "producer": producer.name,
                            "hash": self.head["hash"], "number": self.head["number"],
                            "slot": self.head["slotNumber"], "stateRoot": self.head["stateRoot"],
                            "receiptsRoot": self.head["receiptsRoot"], "receipts": receipts})
        self.save_report()
        print(f"PASS {label}: {producer.name} block {self.head['number']} {self.head['hash']}", flush=True)
        return self.head

    def submit(self, node, body=(), key=0, sequence=None, roots=()):
        if sequence is None:
            sequence = int(node.rpc("eth_getTransactionCount", [SENDER, "latest"]), 16)
        prefix = list(roots) + [Frame(1, 3, None, 40_000, 0, b"", state_limit=200_000)]
        tx = FrameTx(CHAIN_ID, [key], sequence, SENDER, prefix + list(body), [],
                     1_000_000_000, 100_000_000_000)
        raw = tx.raw()
        tx_hash = node.rpc("eth_sendRawTransaction", ["0x" + raw.hex()])
        assert tx_hash == "0x" + keccak(raw).hex()
        return tx_hash

    @staticmethod
    def body(value, expected):
        return [Frame(0, 0, WRITER, 80_000, 0, word(value), state_limit=200_000),
                Frame(3, 0, ASSERTION, 80_000, 0, word(expected))]

    def verify(self):
        reth, ethrex = self.nodes
        self.build(reth, label="empty from reth")
        self.build(ethrex, label="empty from ethrex")
        tx = self.submit(reth, self.body(1, 1))
        self.build(reth, [tx], "assertion success from reth", storage=1)
        tx = self.submit(ethrex, self.body(2, 2))
        self.build(ethrex, [tx], "assertion success from ethrex", storage=2)
        for node in self.nodes:
            tx = self.submit(node, self.body(3, 4))
            self.build(node, [tx], "assertion rollback from " + node.name, status=0, storage=2)
        tx = self.submit(ethrex, self.body(5, 5), key=77, sequence=0)
        self.build(ethrex, [tx], "keyed nonce and assertions", storage=5)
        for node in self.nodes:
            try:
                self.submit(node, self.body(5, 5), key=77, sequence=0)
            except RpcError:
                print(f"PASS {node.name} rejected a consumed keyed nonce", flush=True)
            else:
                raise AssertionError(f"{node.name} admitted a consumed keyed nonce")
        salt, root = word(42), keccak(b"ethrex-reth-local-root")
        tx = self.submit(reth, [Frame(2, 0, ROOT, 100_000, 0, salt + root, state_limit=300_000)])
        head = self.build(reth, [tx], "recent-root write")
        slot = int(head["slotNumber"], 16)
        source = keccak(bytes.fromhex(SENDER[2:]) + salt)
        tuple_data = source + slot.to_bytes(8, "big") + root
        verifier = Frame(1, 0, ROOT, 40_000, 0, tuple_data)
        tx = self.submit(ethrex, self.body(6, 6), roots=[verifier])
        self.build(ethrex, [tx], "canonical recent-root verification with assertions", storage=6)
        tx = self.submit(reth, self.body(7, 7), roots=[verifier])
        self.build(reth, [tx], "recent-root verification admitted by reth", storage=7)
        for node in self.nodes:
            invalid = Frame(1, 0, ROOT, 40_000, 0, source + slot.to_bytes(8, "big") + word(0))
            try:
                self.submit(node, self.body(8, 8), roots=[invalid])
            except RpcError:
                print(f"PASS {node.name} rejected unwritten recent root", flush=True)
            else:
                raise AssertionError(f"{node.name} admitted an unwritten root")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reth", type=Path, required=True)
    parser.add_argument("--ethrex", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--port-base", type=int, default=19500)
    parser.add_argument("--keep-running", action="store_true")
    args = parser.parse_args()
    directory = (args.work_dir or Path(".devnet") / (time.strftime("%Y%m%d-%H%M%S") + "-" +
                                                   secrets.token_hex(3))).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    genesis_path, jwt_path = directory / "genesis.json", directory / "jwt.hex"
    genesis_path.write_text(json.dumps(genesis(), indent=2) + "\n")
    secret = secrets.token_bytes(32)
    jwt_path.write_text(secret.hex())
    nodes = [Node("reth", args.port_base + 45, args.port_base + 51, secret),
             Node("ethrex", args.port_base + 145, args.port_base + 151, secret)]
    commands = [
        [str(args.reth.resolve()), "node", "--chain", str(genesis_path), "--datadir", str(directory / "reth"),
         "--http", "--http.addr", "127.0.0.1", "--http.port", str(nodes[0].port),
         "--http.api", "eth,net,web3,debug,txpool", "--authrpc.addr", "127.0.0.1",
         "--authrpc.port", str(nodes[0].authport), "--authrpc.jwtsecret", str(jwt_path),
         "--disable-discovery", "--port", str(args.port_base + 3)],
        [str(args.ethrex.resolve()), "--network", str(genesis_path), "--datadir", str(directory / "ethrex"),
         "--syncmode", "full",
         "--http.addr", "127.0.0.1", "--http.port", str(nodes[1].port),
         "--http.api", "eth,net,web3,debug,txpool,ethrex", "--authrpc.addr", "127.0.0.1",
         "--authrpc.port", str(nodes[1].authport), "--authrpc.jwtsecret", str(jwt_path),
         "--p2p.addr", "127.0.0.1", "--p2p.port", str(args.port_base + 103),
         "--discovery.port", str(args.port_base + 103), "--p2p.discv4", "false",
         "--p2p.discv5", "false"],
    ]
    logs = []
    environment = os.environ.copy()
    # Unoptimized VM futures can exceed Rust's default 2 MiB worker stack.
    environment.setdefault("RUST_MIN_STACK", str(16 * 1024 * 1024))
    print(f"Devnet artifacts: {directory}", flush=True)
    try:
        for node, command in zip(nodes, commands):
            log = (directory / (node.name + ".log")).open("w")
            logs.append(log)
            node.process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                            env=environment)
        deadline = time.monotonic() + 120
        for node in nodes:
            while True:
                if node.process.poll() is not None:
                    raise RuntimeError(f"{node.name} exited:\n" +
                                       (directory / (node.name + ".log")).read_text()[-6000:])
                try:
                    node.rpc("eth_blockNumber")
                    break
                except (OSError, ValueError, RpcError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError(f"{node.name} did not start; see {directory}")
                    time.sleep(0.5)
        devnet = Devnet(nodes, directory)
        devnet.verify()
        print("PASS all two-client checks; report.json contains block hashes and receipts.", flush=True)
        if args.keep_running:
            print(f"RPC reth: http://127.0.0.1:{nodes[0].port}; ethrex: http://127.0.0.1:{nodes[1].port}", flush=True)
            while True:
                time.sleep(6)
                devnet.build(nodes[len(devnet.blocks) % 2])
    except KeyboardInterrupt:
        pass
    finally:
        for node in nodes:
            if node.process and node.process.poll() is None:
                node.process.terminate()
        for node in nodes:
            if node.process:
                try:
                    node.process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    node.process.kill()
                    node.process.wait()
        for log in logs:
            log.close()


if __name__ == "__main__":
    main()
