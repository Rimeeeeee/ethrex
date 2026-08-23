#!/usr/bin/env python3
"""Wait for and verify the combined EIP-8304/EIP-8312 devnet activation."""
import json
import os
import sys
import time
import urllib.request

INDEX_ADDRESS = "0x0000000000000000000000000000000000008304"
UTXO_VAULT = "0x0000000000000000000000000000000000008312"


def rpc(url: str, method: str, params: list):
    request = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        body = json.load(response)
    if body.get("error"):
        raise RuntimeError(f"{method}: {body['error']}")
    return body["result"]


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify-devnet.sh <rpc-url>")
    url = sys.argv[1]
    timeout = int(os.environ.get("VERIFY_TIMEOUT_SECONDS", "1200"))
    config = rpc(url, "debug_chainConfig", [])
    print("chain configuration")
    print(json.dumps({key: config.get(key) for key in (
        "eip8304Time", "utxoFramesTime", "hegotaTime", "bogotaTime"
    )}, indent=2))

    print("waiting for both activation transitions")
    deadline = time.monotonic() + timeout
    while True:
        index_code = rpc(url, "eth_getCode", [INDEX_ADDRESS, "latest"])
        vault_code = rpc(url, "eth_getCode", [UTXO_VAULT, "latest"])
        if index_code != "0x" and vault_code != "0x":
            break
        if time.monotonic() >= deadline:
            raise TimeoutError(f"activation timeout: index_code={index_code} vault_code={vault_code}")
        time.sleep(5)

    print(f"EIP-8304 runtime bytes: {(len(index_code) - 2) // 2}")
    print(f"EIP-8312 runtime bytes: {(len(vault_code) - 2) // 2}")
    head = rpc(url, "eth_blockNumber", [])
    table = rpc(url, "ethrex_getEip8304Table", [head, "0x1"])
    if table is None:
        raise RuntimeError(f"one-block EIP-8304 table is unavailable at {head}")
    summary = {key: table.get(key) for key in (
        "firstBlock", "endBlock", "entryCount", "tableRoot", "storageSlot", "loadMicros"
    )}
    print(f"latest block: {head}")
    print("latest one-block EIP-8304 table")
    print(json.dumps(summary, indent=2))
    committed_root = rpc(url, "eth_getStorageAt", [INDEX_ADDRESS, table["storageSlot"], head])
    if committed_root.lower() != table["tableRoot"].lower():
        raise RuntimeError(
            f"table root mismatch: RPC table={table['tableRoot']} contract={committed_root}"
        )
    print("table root matches the index-contract storage slot")
    query = rpc(url, "ethrex_queryEip8304Table", [
        head,
        "0x1",
        [{"typeId": 2, "content": UTXO_VAULT}],
    ])
    if query is None or query.get("tableRoot", "").lower() != table["tableRoot"].lower():
        raise RuntimeError("proof-query RPC did not return the inspected table root")
    ranges = query.get("queries", [])
    if len(ranges) != 1:
        raise RuntimeError("proof-query RPC did not return exactly one requested range")
    print("proof-query RPC")
    print(json.dumps({
        "matchingEntries": len(ranges[0].get("entries", [])),
        "transactionProofs": len(query.get("transactions", [])),
        "deduplicatedProofNodes": len(query.get("proofNodes", [])),
        "queryMicros": query.get("queryMicros"),
    }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"verification failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
