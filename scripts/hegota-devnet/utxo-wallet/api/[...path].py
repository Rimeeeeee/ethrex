from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_RPC = "https://rpc1.hegota.ethrex.xyz"
VAULT = "0x0000000000000000000000000000000000008312"
INDEX = "0x0000000000000000000000000000000000008304"
TOPIC = "0x3b19241465a47bc187f1d9c7db70834855a907183742a4b63aa824c576296f5e"
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
UINT_RE = re.compile(r"^(0|[1-9][0-9]*)$")
KEY_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")
TXFORGE = Path(__file__).with_name("txforge.py")
MAX_REQUEST_BYTES = 64 * 1024
FORGE_TIMEOUT_SECONDS = 55

rpc_url = os.environ.get("UTXO_RPC", DEFAULT_RPC).strip()
wallet_key = os.environ.get("UTXO_WALLET_KEY") or None


def json_response(handler: BaseHTTPRequestHandler, status: int, value) -> None:
    payload = json.dumps(value, separators=(",", ":")).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def error_response(handler: BaseHTTPRequestHandler, error: Exception, status: int = 400) -> None:
    json_response(handler, status, {"error": str(error)})


def is_address(value) -> bool:
    return isinstance(value, str) and ADDRESS_RE.fullmatch(value) is not None


def parse_block(value, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a non-negative block number")
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str) and re.fullmatch(r"(0x[0-9a-fA-F]+|[0-9]+)", value):
        return int(value, 0)
    raise ValueError(f"{name} must be a non-negative block number")


def positive_wei(value, name: str = "valueWei") -> int:
    if not isinstance(value, str) or UINT_RE.fullmatch(value) is None or int(value) <= 0:
        raise ValueError(f"{name} must be a positive integer string")
    return int(value)


def rpc_measured(method: str, params: list) -> dict:
    started = time.perf_counter()
    request = urllib.request.Request(
        rpc_url,
        data=json.dumps({
            "jsonrpc": "2.0",
            "id": int(time.time() * 1000),
            "method": method,
            "params": params,
        }).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            body = json.loads(raw)
    except urllib.error.URLError as exc:
        raise RuntimeError(f"{method}: RPC request failed: {exc.reason}") from exc
    if body.get("error"):
        raise RuntimeError(f"{method}: {body['error']}")
    return {
        "result": body["result"],
        "elapsedMs": round((time.perf_counter() - started) * 1000, 3),
        "responseBytes": len(raw),
    }


def rpc_call(method: str, params: list):
    return rpc_measured(method, params)["result"]


def forge(command: dict) -> dict:
    payload = json.dumps({"rpc": rpc_url, **command}).encode()
    try:
        completed = subprocess.run(
            [sys.executable, str(TXFORGE)],
            input=payload,
            capture_output=True,
            timeout=FORGE_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("transaction forge timed out; wait for the receipt and retry") from exc
    stdout = completed.stdout.decode(errors="replace").strip()
    stderr = completed.stderr.decode(errors="replace").strip()
    try:
        result = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"txforge returned invalid JSON: {stderr or stdout}") from exc
    if result.get("error"):
        raise RuntimeError(result["error"])
    if completed.returncode != 0:
        raise RuntimeError(stderr or f"txforge exited with code {completed.returncode}")
    return result


def wallet_address() -> str | None:
    if not wallet_key:
        return None
    return forge({"op": "addressOf", "key": wallet_key})["address"].lower()


def opening_from_log(log: dict) -> dict | None:
    data = log.get("data", "")
    topics = log.get("topics", [])
    if len(data) < 130 or len(topics) < 3:
        return None
    raw = data[2:]
    word = lambda offset: int(raw[offset:offset + 64], 16)
    topic_address = lambda topic: "0x" + topic[-40:].lower()
    return {
        "index": word(0),
        "valueWei": str(word(64)),
        "source": topic_address(topics[1]),
        "recipient": topic_address(topics[2]),
        "creationBlock": int(log["blockNumber"], 16),
        "txHash": log.get("transactionHash"),
        "blockHash": log.get("blockHash"),
        "logIndex": int(log.get("logIndex", "0x0"), 16),
    }


def spent(index: int) -> bool:
    slot = (1 << 129) + index // 256
    word = int(rpc_call("eth_getStorageAt", [
        VAULT, hex(slot), "latest"
    ]), 16)
    return bool(word & (1 << (index & 255)))


def max_self_funded_fee() -> int:
    gas_price = int(rpc_call("eth_gasPrice", []), 16)
    max_fee_per_gas = max(gas_price * 2, 2_000_000_000)
    return max_fee_per_gas * 400_000


def enrich_discovered_utxos(utxos: list[dict], head: int) -> dict:
    started = time.perf_counter()
    for item in utxos:
        item["spent"] = spent(item["index"])
        item["spendable"] = item["creationBlock"] < head and not item["spent"]
    spent_check_ms = round((time.perf_counter() - started) * 1000, 3)
    started = time.perf_counter()
    fee_reserve = max_self_funded_fee()
    for item in utxos:
        item["selfFundedFeeReserveWei"] = str(fee_reserve)
        item["maxSelfFundedOutputWei"] = str(max(int(item["valueWei"]) - fee_reserve, 0))
    return {
        "spentCheckMs": spent_check_ms,
        "metadataMs": round((time.perf_counter() - started) * 1000, 3),
    }


def scan_logs(body: dict) -> dict:
    address = body.get("address")
    if not is_address(address):
        raise ValueError("address must be a 20-byte hex address")
    head = int(rpc_call("eth_blockNumber", []), 16)
    start = parse_block(body.get("fromBlock", 0), "fromBlock")
    requested_to = body.get("toBlock")
    end_block = head if requested_to in (None, "") else min(parse_block(requested_to, "toBlock"), head)
    if start > end_block:
        return {"method": "receiptLogs", "address": address.lower(), "fromBlock": start, "toBlock": end_block, "head": head, "utxos": [], "metrics": {"discoveryMs": 0, "providerRpcMs": 0, "responseBytes": 0, "rpcCalls": 0, "chunks": 0, "logsReturned": 0}}

    discovery_started = time.perf_counter()
    utxos = []
    rpc_calls = 0
    response_bytes = 0
    provider_rpc_ms = 0.0
    chunks = 0
    for start_block in range(start, end_block + 1, 2000):
        stop_block = min(start_block + 1999, end_block)
        response = rpc_measured("eth_getLogs", [{
            "address": VAULT,
            "topics": [TOPIC, None, "0x" + address[2:].lower().zfill(64)],
            "fromBlock": hex(start_block),
            "toBlock": hex(stop_block),
        }])
        rpc_calls += 1
        chunks += 1
        response_bytes += response["responseBytes"]
        provider_rpc_ms += response["elapsedMs"]
        for log in response["result"]:
            item = opening_from_log(log)
            if not item or item["recipient"] != address.lower():
                continue
            utxos.append(item)
    discovery_ms = round((time.perf_counter() - discovery_started) * 1000, 3)
    utxos.sort(key=lambda item: item["index"])
    enrichment = enrich_discovered_utxos(utxos, head)
    wallet_total_ms = round(discovery_ms + enrichment["spentCheckMs"] + enrichment["metadataMs"], 3)
    return {
        "method": "receiptLogs",
        "address": address.lower(),
        "fromBlock": start,
        "toBlock": end_block,
        "head": head,
        "utxos": utxos,
        "metrics": {
            "discoveryMs": discovery_ms,
            "providerRpcMs": round(provider_rpc_ms, 3),
            "responseBytes": response_bytes,
            "rpcCalls": rpc_calls,
            "chunks": chunks,
            "logsReturned": len(utxos),
            "walletTotalMs": wallet_total_ms,
            "walletRpcCalls": rpc_calls + len(utxos) + 1,
            **enrichment,
        },
    }


def table_position(entry: dict) -> tuple[int, int, int]:
    return (int(entry["blockNumber"], 16), int(entry["transactionIndex"], 16), int(entry["positionIndex"], 16))


def matching_positions(table: dict, type_id: int, content: str) -> dict:
    expected = content.lower()
    return {
        table_position(entry): entry
        for entry in table["entries"]
        if entry["typeId"] == type_id and entry["content"].lower() == expected
    }


def request_table(first_block: int, table_size: int, head: int) -> tuple:
    table_response = rpc_measured("ethrex_getEip8304Table", [hex(first_block), hex(table_size)])
    if table_response["result"] is None:
        return None, table_response, None
    root_response = rpc_measured("eth_getStorageAt", [
        INDEX, table_response["result"]["storageSlot"], hex(head)
    ])
    if root_response["result"].lower() != table_response["result"]["tableRoot"].lower():
        raise RuntimeError(f"EIP-8304 table root mismatch for {first_block}/{table_size}")
    return table_response["result"], table_response, root_response


def scan_tables(body: dict) -> dict:
    address = body.get("address")
    if not is_address(address):
        raise ValueError("address must be a 20-byte hex address")
    head = int(rpc_call("eth_blockNumber", []), 16)
    start = parse_block(body.get("fromBlock", 0), "fromBlock")
    requested_to = body.get("toBlock")
    end_block = head if requested_to in (None, "") else min(parse_block(requested_to, "toBlock"), head)
    if start > end_block:
        return {"method": "eip8304Tables", "address": address.lower(), "fromBlock": start, "toBlock": end_block, "head": head, "utxos": [], "complete": True, "missingBlocks": [], "tables": [], "metrics": {"discoveryMs": 0, "providerRpcMs": 0, "providerTableLoadMicros": 0, "responseBytes": 0, "rpcCalls": 0, "tablesLoaded": 0, "entriesExamined": 0, "matchedPositions": 0, "rootChecks": 0, "receiptsFetched": 0}}

    discovery_started = time.perf_counter()
    padded_recipient = "0x" + address[2:].lower().zfill(64)
    positions = {}
    missing_blocks = []
    tables = []
    cursor = start
    rpc_calls = 0
    response_bytes = 0
    provider_rpc_ms = 0.0
    provider_table_load_micros = 0
    entries_examined = 0
    root_checks = 0
    while cursor <= end_block:
        selected = None
        for size in (256, 64, 16, 4, 1):
            table_end = cursor + size - 1
            commitment = table_end + (0 if size == 1 else size // 4)
            if cursor % size != 0 or table_end > end_block or commitment > head:
                continue
            candidate, table_response, root_response = request_table(cursor, size, head)
            rpc_calls += 1
            response_bytes += table_response["responseBytes"]
            provider_rpc_ms += table_response["elapsedMs"]
            if root_response is not None:
                rpc_calls += 1
                root_checks += 1
                response_bytes += root_response["responseBytes"]
                provider_rpc_ms += root_response["elapsedMs"]
            if candidate is not None:
                selected = candidate
                break
        if selected is None:
            missing_blocks.append(cursor)
            cursor += 1
            continue
        size = int(selected["tableSize"], 16)
        tables.append({
            "firstBlock": int(selected["firstBlock"], 16),
            "tableSize": size,
            "tableRoot": selected["tableRoot"],
            "entryCount": int(selected["entryCount"], 16),
            "loadMicros": selected["loadMicros"],
        })
        provider_table_load_micros += int(selected.get("loadMicros", 0))
        entries_examined += len(selected["entries"])
        addresses = matching_positions(selected, 2, VAULT)
        topic0 = matching_positions(selected, 3, TOPIC)
        recipients = matching_positions(selected, 5, padded_recipient)
        for key, entry in recipients.items():
            if key in addresses and key in topic0:
                positions[key] = entry
        cursor += size

    positions_by_block = {}
    for entry in positions.values():
        positions_by_block.setdefault(int(entry["blockNumber"], 16), []).append(entry)
    utxos = []
    receipts_fetched = 0
    for block, block_positions in positions_by_block.items():
        response = rpc_measured("eth_getBlockReceipts", [hex(block)])
        rpc_calls += 1
        receipts_fetched += len(response["result"])
        response_bytes += response["responseBytes"]
        provider_rpc_ms += response["elapsedMs"]
        for position in block_positions:
            transaction_index = int(position["transactionIndex"], 16)
            log_index = int(position["positionIndex"], 16)
            receipt = response["result"][transaction_index]
            raw_log = receipt["logs"][log_index]
            log = {
                **raw_log,
                "blockNumber": raw_log.get("blockNumber", hex(block)),
                "blockHash": raw_log.get("blockHash", receipt.get("blockHash")),
                "transactionHash": raw_log.get("transactionHash", receipt.get("transactionHash")),
            }
            item = opening_from_log(log)
            if item is None or item["recipient"] != address.lower() or log["address"].lower() != VAULT:
                raise RuntimeError("EIP-8304 position did not resolve to the requested UtxoCreated log")
            utxos.append(item)
    discovery_ms = round((time.perf_counter() - discovery_started) * 1000, 3)
    utxos.sort(key=lambda item: item["index"])
    enrichment = enrich_discovered_utxos(utxos, head)
    wallet_total_ms = round(discovery_ms + enrichment["spentCheckMs"] + enrichment["metadataMs"], 3)
    return {
        "method": "eip8304Tables", "address": address.lower(), "fromBlock": start,
        "toBlock": end_block, "head": head, "utxos": utxos,
        "complete": not missing_blocks, "missingBlocks": missing_blocks, "tables": tables,
        "metrics": {
            "discoveryMs": discovery_ms, "providerRpcMs": round(provider_rpc_ms, 3),
            "providerTableLoadMicros": provider_table_load_micros, "responseBytes": response_bytes,
            "rpcCalls": rpc_calls, "tablesLoaded": len(tables), "entriesExamined": entries_examined,
            "matchedPositions": len(positions), "rootChecks": root_checks,
            "receiptsFetched": receipts_fetched, "walletTotalMs": wallet_total_ms,
            "walletRpcCalls": rpc_calls + len(utxos) + 1, **enrichment,
        },
    }


def result_identity(result: dict) -> str:
    canonical = sorted([
        [item["creationBlock"], item["txHash"], item["logIndex"], item["index"], item["source"], item["recipient"], item["valueWei"]]
        for item in result["utxos"]
    ], key=lambda value: json.dumps(value, separators=(",", ":")))
    return hashlib.sha256(json.dumps(canonical, separators=(",", ":")).encode()).hexdigest()


def compare_discovery(body: dict) -> dict:
    head = int(rpc_call("eth_blockNumber", []), 16)
    frozen = {**body, "toBlock": min(parse_block(body["toBlock"], "toBlock"), head) if body.get("toBlock") not in (None, "") else head}
    order = ("tables", "logs") if body.get("order") == "tablesFirst" else ("logs", "tables")
    results = {}
    for method in order:
        results[method] = scan_tables(frozen) if method == "tables" else scan_logs(frozen)
    log_identity = result_identity(results["logs"])
    table_identity = result_identity(results["tables"])
    return {
        "targetHead": head, "fromBlock": frozen.get("fromBlock", 0), "toBlock": frozen["toBlock"],
        "sameResults": log_identity == table_identity,
        "receiptLogResultHash": "0x" + log_identity, "eip8304ResultHash": "0x" + table_identity,
        "receiptLogs": results["logs"], "eip8304Tables": results["tables"],
    }


def scan(body: dict) -> dict:
    return scan_tables(body) if body.get("method") == "tables" else scan_logs(body)


def scan_created(body: dict) -> dict:
    address = body.get("address")
    if not is_address(address):
        raise ValueError("address must be a 20-byte hex address")
    head = int(rpc_call("eth_blockNumber", []), 16)
    start = parse_block(body.get("fromBlock", 0), "fromBlock")
    requested_to = body.get("toBlock")
    end_block = head if requested_to in (None, "") else min(parse_block(requested_to, "toBlock"), head)
    if start > end_block:
        return {"address": address.lower(), "fromBlock": start, "toBlock": end_block, "head": head, "utxos": []}

    utxos = []
    for start_block in range(start, end_block + 1, 2000):
        stop_block = min(start_block + 1999, end_block)
        logs = rpc_call("eth_getLogs", [{
            "address": VAULT,
            "topics": [TOPIC, "0x" + address[2:].lower().zfill(64), None],
            "fromBlock": hex(start_block),
            "toBlock": hex(stop_block),
        }])
        for log in logs:
            item = opening_from_log(log)
            if not item or item["source"] != address.lower():
                continue
            item["spent"] = spent(item["index"])
            item["spendable"] = item["creationBlock"] < head and not item["spent"]
            utxos.append(item)
    utxos.sort(key=lambda item: item["index"])
    return {
        "address": address.lower(),
        "fromBlock": start,
        "toBlock": end_block,
        "head": head,
        "utxos": utxos,
    }


def check_inputs(body: dict) -> list[dict]:
    raw_inputs = body.get("inputs")
    if raw_inputs is None and isinstance(body.get("input"), dict):
        raw_inputs = [body["input"]]
    if not isinstance(raw_inputs, list) or not raw_inputs:
        raise ValueError("inputs is required")
    if len(raw_inputs) > 64:
        raise ValueError("a spend cannot contain more than 64 inputs")
    seen = set()
    for input_item in raw_inputs:
        if not isinstance(input_item, dict):
            raise ValueError("each input must be an object")
        if not isinstance(input_item.get("index"), int) or not isinstance(input_item.get("creationBlock"), int):
            raise ValueError("each input must include index and creationBlock")
        if not is_address(input_item.get("source")) or not is_address(input_item.get("recipient")):
            raise ValueError("each input source and recipient must be addresses")
        key = (input_item["index"], input_item["creationBlock"])
        if key in seen:
            raise ValueError("the same UTXO was selected more than once")
        seen.add(key)
    return raw_inputs


def verified_inputs(input_items: list[dict], owner: str) -> list[dict]:
    verified = []
    for input_item in input_items:
        if input_item["recipient"].lower() != owner:
            raise ValueError(f"selected UTXO belongs to {input_item['recipient']}, not the imported wallet")
        positive_wei(str(input_item["valueWei"]), "input.valueWei")
        exact = scan({
            "address": owner,
            "fromBlock": input_item["creationBlock"],
            "toBlock": input_item["creationBlock"],
        })
        current = next((item for item in exact["utxos"] if item["index"] == input_item["index"]), None)
        if not current:
            raise ValueError(f"selected UTXO #{input_item['index']} was not found in its creation block")
        if current["spent"]:
            raise ValueError(f"selected UTXO #{input_item['index']} is already spent")
        if current["source"] != input_item["source"].lower() or current["valueWei"] != str(input_item["valueWei"]):
            raise ValueError(f"selected UTXO #{input_item['index']} metadata does not match the chain")
        verified.append(current)
    return sorted(verified, key=lambda item: item["index"])


def create_fresh_utxo(body: dict) -> dict:
    if not wallet_key:
        raise ValueError("fresh UTXO creation is disabled; import a wallet first")
    recipient = body.get("recipient")
    if not is_address(recipient):
        raise ValueError("recipient must be a 20-byte hex address")
    value = positive_wei(body.get("valueWei"))
    owner = wallet_address()
    before = int(rpc_call("eth_getBalance", [owner, "latest"]), 16)
    result = forge({
        "op": "deposit",
        "key": wallet_key,
        "recipient": recipient.lower(),
        "valueWei": str(value),
    })
    if result.get("status") != "0x1":
        raise RuntimeError(f"fresh UTXO deposit reverted: {result.get('txHash')}")
    after = int(rpc_call("eth_getBalance", [owner, "latest"]), 16)
    return {
        **result,
        "source": owner,
        "recipient": recipient.lower(),
        "valueWei": str(value),
        "accountBalanceBeforeWei": str(before),
        "accountBalanceAfterWei": str(after),
    }


def send_utxo(body: dict) -> dict:
    if not wallet_key:
        raise ValueError("sending is disabled; import a wallet first")
    input_items = check_inputs(body)
    recipient = body.get("recipient")
    if not is_address(recipient):
        raise ValueError("recipient must be a 20-byte hex address")
    amount = positive_wei(body.get("valueWei"))
    owner = wallet_address()
    current = verified_inputs(input_items, owner)
    input_value = sum(int(item["valueWei"]) for item in current)
    if amount > input_value:
        raise ValueError("valueWei cannot exceed the selected UTXO value")
    return forge({
        "op": "spend",
        "actorKeys": [wallet_key],
        "inputs": current,
        "utxoOuts": [
            {"recipient": recipient.lower(), "valueWei": str(amount)},
            {"recipient": owner, "valueWei": "0"},
        ],
        "accountOuts": [],
        "changeIndex": 1,
    })


def redeem_utxo(body: dict) -> dict:
    if not wallet_key:
        raise ValueError("redemption is disabled; import a wallet first")
    input_items = check_inputs(body)
    owner = wallet_address()
    current = verified_inputs(input_items, owner)
    input_value = sum(int(item["valueWei"]) for item in current)
    fee_reserve = max_self_funded_fee()
    default_value = max(input_value - fee_reserve, 0)
    requested = default_value if body.get("valueWei") in (None, "") else positive_wei(body["valueWei"])
    if requested <= 0:
        raise ValueError("the selected UTXOs are too small to cover the self-funded conversion fee")
    if requested > input_value:
        raise ValueError("redemption value cannot exceed the selected UTXO value")
    before = int(rpc_call("eth_getBalance", [owner, "latest"]), 16)
    result = forge({
        "op": "spend",
        "actorKeys": [wallet_key],
        "inputs": current,
        "utxoOuts": [{"recipient": owner, "valueWei": "0"}],
        "accountOuts": [{"recipient": owner, "valueWei": str(requested)}],
        "changeIndex": 0,
    })
    after = int(rpc_call("eth_getBalance", [owner, "latest"]), 16)
    return {
        **result,
        "account": owner,
        "accountBalanceBeforeWei": str(before),
        "accountBalanceAfterWei": str(after),
    }


def read_json(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length", "0"))
    if length > MAX_REQUEST_BYTES:
        raise ValueError("request body too large")
    raw = handler.rfile.read(length) if length else b"{}"
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid JSON body") from exc
    if not isinstance(value, dict):
        raise ValueError("JSON body must be an object")
    return value


def handle_get(path: str):
    if path == "/api/status":
        address = wallet_address()
        account_balance = "0"
        if address:
            account_balance = str(int(rpc_call("eth_getBalance", [address, "latest"]), 16))
        return {
            "rpc": rpc_url,
            "defaultRpc": DEFAULT_RPC,
            "vault": VAULT,
            "head": int(rpc_call("eth_blockNumber", []), 16),
            "configured": bool(address),
            "address": address,
            "accountBalanceWei": account_balance,
        }
    raise FileNotFoundError("unknown endpoint")


def handle_post(path: str, body: dict):
    global rpc_url, wallet_key

    if path == "/api/rpc":
        candidate = body.get("url")
        if not isinstance(candidate, str) or not re.fullmatch(r"https?://[^\s]+", candidate.strip(), re.I):
            raise ValueError("RPC URL must start with http:// or https://")
        previous = rpc_url
        rpc_url = candidate.strip()
        try:
            chain_id = rpc_call("eth_chainId", [])
        except Exception:
            rpc_url = previous
            raise ValueError("RPC URL did not respond")
        return {"rpc": rpc_url, "chainId": chain_id}

    if path == "/api/import":
        candidate = body.get("key")
        if not isinstance(candidate, str) or KEY_RE.fullmatch(candidate) is None:
            raise ValueError("private key must be exactly 32 bytes in hex")
        previous = wallet_key
        wallet_key = candidate if candidate.startswith("0x") else "0x" + candidate
        try:
            address = wallet_address()
        except Exception:
            wallet_key = previous
            raise
        return {"configured": True, "address": address}

    if path == "/api/lock":
        wallet_key = None
        return {"configured": False, "address": None}

    if path == "/api/scan":
        return scan(body)
    if path == "/api/compare-discovery":
        return compare_discovery(body)
    if path == "/api/table":
        first_block = parse_block(body.get("firstBlock"), "firstBlock")
        table_size = parse_block(body.get("tableSize", 1), "tableSize")
        return rpc_call("ethrex_getEip8304Table", [hex(first_block), hex(table_size)])
    if path == "/api/created":
        return scan_created(body)
    if path == "/api/deposit":
        return create_fresh_utxo(body)
    if path == "/api/send":
        return send_utxo(body)
    if path == "/api/redeem":
        return redeem_utxo(body)
    raise FileNotFoundError("unknown endpoint")


class handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_GET(self):
        try:
            json_response(self, 200, handle_get(urlparse(self.path).path))
        except FileNotFoundError as exc:
            error_response(self, exc, 404)
        except Exception as exc:
            error_response(self, exc)
    def do_POST(self):
        try:
            path = urlparse(self.path).path
            json_response(self, 200, handle_post(path, read_json(self)))
        except FileNotFoundError as exc:
            error_response(self, exc, 404)
        except Exception as exc:
            error_response(self, exc)
