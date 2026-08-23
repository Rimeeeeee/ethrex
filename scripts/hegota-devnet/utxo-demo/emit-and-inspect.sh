#!/usr/bin/env bash
set -euo pipefail

# Start four inspectors at the same chain head. Emit these pairs sequentially:
#   FUNDED_1 -> INSPECT_1, wait INTERVAL_BLOCKS
#   FUNDED_2 -> INSPECT_2, wait INTERVAL_BLOCKS
#   FUNDED_3 -> INSPECT_3, wait INTERVAL_BLOCKS
#   FUNDED_4 -> INSPECT_4
# Then spend the first UTXO from INSPECT_1 to INSPECT_2, wait 50 blocks, and
# spend the third UTXO from INSPECT_3 to INSPECT_4. Finally emit a 0.05 ETH
# UTXO to INSPECT_4 and redeem it into an ordinary ETH account output for
# INSPECT_3; FUNDED_4 sponsors this final redemption so INSPECT_3 receives the
# full 0.05 ETH account output.
#
# Every inspector classifies every UtxoCreated log it sees as required (its
# recipient) or unrelated (another recipient). No creation block, UTXO index,
# witness, or spend state is persisted. Each inspector's summary records the
# watch duration until its required log was first observed.
#
# Resume mode: set SKIP_EMISSIONS=1 and DEPOSIT_TX_1..DEPOSIT_TX_4 to reuse
# already-mined emission transactions. Their receipt logs are read at startup
# and the resulting witness metadata is kept only in memory.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${WALLETS_FILE:-$SCRIPT_DIR/wallets.env}"
PY="${PY:-$SCRIPT_DIR/.venv/bin/python3}"
TXFORGE="${TXFORGE:-$SCRIPT_DIR/devnet/txforge.py}"
LOG_DIR="${LOG_DIR:-$SCRIPT_DIR/logs}"

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Missing $CONFIG_FILE; copy wallets.env.example to wallets.env and edit it." >&2
  exit 1
fi
if [[ ! -x "$PY" ]]; then
  echo "Python venv not found at $PY" >&2
  echo "Create it with: python3 -m venv .venv && .venv/bin/pip install eth-account eth-keys eth-hash" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$CONFIG_FILE"

: "${RPC:?RPC is required}"
: "${INTERVAL_BLOCKS:=20}"
: "${UTXO_VALUE_WEI:=10000000000000000}"

VAULT=0x0000000000000000000000000000000000008312
UTXO_CREATED_TOPIC=0x3b19241465a47bc187f1d9c7db70834855a907183742a4b63aa824c576296f5e
mkdir -p "$LOG_DIR"

json_value() {
  "$PY" -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

rpc_call() {
  local method="$1"
  local params_json="$2"
  "$PY" - "$RPC" "$method" "$params_json" <<'PY'
import json
import sys
import urllib.request

rpc, method, params_json = sys.argv[1:]
request = urllib.request.Request(
    rpc,
    data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                     "params": json.loads(params_json)}).encode(),
    headers={"Content-Type": "application/json"},
)
with urllib.request.urlopen(request, timeout=60) as response:
    body = json.load(response)
if body.get("error"):
    raise SystemExit(f"{method} failed: {body['error']}")
print(json.dumps(body["result"]))
PY
}

rpc_result() {
  rpc_call "$1" "$2" | "$PY" -c '
import json,sys
value = json.load(sys.stdin)
if isinstance(value, str):
    print(value)
else:
    json.dump(value, sys.stdout, separators=(",", ":"))
'
}

address_from_key() {
  printf '{"rpc":"%s","op":"addressOf","key":"%s"}' "$RPC" "$1" |
    "$PY" "$TXFORGE" | json_value address
}

require_address_match() {
  local label="$1" configured="$2" key="$3" derived
  derived="$(address_from_key "$key")"
  if [[ "${derived,,}" != "${configured,,}" ]]; then
    echo "$label key/address mismatch: configured=$configured derived=$derived" >&2
    exit 1
  fi
}

balance_wei() {
  rpc_result eth_getBalance "[\"$1\",\"latest\"]" |
    "$PY" -c 'import sys; print(int(sys.stdin.read().strip(),16))'
}

validate_wallets() {
  local i addr key balance addr_var key_var
  for i in 1 2 3 4; do
    addr_var="FUNDED_${i}_ADDRESS"
    key_var="FUNDED_${i}_PRIVATE_KEY"
    addr="${!addr_var}"
    key="${!key_var}"
    require_address_match "FUNDED_$i" "$addr" "$key"
  done
  for i in 1 2 3 4; do
    addr_var="INSPECT_${i}_ADDRESS"
    key_var="INSPECT_${i}_PRIVATE_KEY"
    addr="${!addr_var}"
    key="${!key_var}"
    require_address_match "INSPECT_$i" "$addr" "$key"
    balance="$(balance_wei "$addr")"
    if [[ "$balance" != 0 ]]; then
      echo "INSPECT_$i has non-zero ETH balance: $balance wei" >&2
      exit 1
    fi
  done
  if [[ "$(balance_wei "$FUNDED_1_ADDRESS")" -lt "$UTXO_VALUE_WEI" ]]; then
    echo "FUNDED_1 does not have enough ETH for the UTXO value." >&2
    exit 1
  fi
}

append_matching_logs() {
  local from_block="$1" to_block="$2"
  local logs_json
  logs_json="$(rpc_result eth_getLogs "[{\"address\":\"$VAULT\",\"topics\":[\"$UTXO_CREATED_TOPIC\"],\"fromBlock\":\"$(printf '0x%x' "$from_block")\",\"toBlock\":\"$(printf '0x%x' "$to_block")\"}]")"
  "$PY" - "$logs_json" "$LOG_DIR" "$WATCH_START_BLOCK" "$WATCH_START_EPOCH" \
    "$FUNDED_1_ADDRESS" "$FUNDED_2_ADDRESS" "$FUNDED_3_ADDRESS" "$FUNDED_4_ADDRESS" \
    "$INSPECT_1_ADDRESS" "$INSPECT_2_ADDRESS" "$INSPECT_3_ADDRESS" "$INSPECT_4_ADDRESS" <<'PY'
import json
import os
import sys
import time
from datetime import datetime, timezone

logs = json.loads(sys.argv[1])
log_dir = sys.argv[2]
watch_start_block = int(sys.argv[3], 0)
watch_start_epoch = float(sys.argv[4])
funders = [a.lower() for a in sys.argv[5:9]]
inspectors = [a.lower() for a in sys.argv[9:13]]
stamp = datetime.now(timezone.utc).isoformat()
observed_epoch = time.time()

def write(name, category, log, inspector_index, required):
    record = {
        "observedAt": stamp,
        "category": category,
        "required": required,
        "inspector": inspectors[inspector_index],
        "watchStartBlock": watch_start_block,
        "observedThroughBlock": int(log.get("blockNumber", "0x0"), 0),
        "watchDurationSeconds": round(observed_epoch - watch_start_epoch, 3),
        "log": log,
    }
    with open(os.path.join(log_dir, name), "a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")

for log in logs:
    topics = log.get("topics", [])
    source = topics[1][-40:].lower() if len(topics) > 1 else ""
    recipient = topics[2][-40:].lower() if len(topics) > 2 else ""
    source = "0x" + source if source else ""
    recipient = "0x" + recipient if recipient else ""
    for index, address in enumerate(inspectors):
        required = recipient == address
        if required:
            name = f"inspect-wallet-{index + 1}-required.jsonl"
            category = f"inspect_wallet_{index + 1}_required"
        else:
            name = f"inspect-wallet-{index + 1}-unrequired.jsonl"
            category = f"inspect_wallet_{index + 1}_unrequired"
        write(name, category, log, index, required)

    # Keep a separate global copy of logs emitted by each configured spender.
    # This is intentionally redundant with the per-inspector files.
    for index, address in enumerate(funders):
        if source == address:
            write(f"spender-wallet-{index + 1}.jsonl",
                  f"spender_wallet_{index + 1}", log, 0, False)

    # Any event from an unknown source is retained as an unnecessary/global log.
    if source not in funders:
        write("unrelated-utxo-logs.jsonl", "unrelated_utxo_log", log, 0, False)

now = time.time()
for index, address in enumerate(inspectors, start=1):
    path = os.path.join(log_dir, f"inspect-wallet-{index}-summary.json")
    required_path = os.path.join(log_dir, f"inspect-wallet-{index}-required.jsonl")
    first_required_block = None
    first_required_duration = None
    if os.path.exists(required_path):
        with open(required_path, encoding="utf-8") as f:
            for line in f:
                record = json.loads(line)
                if record.get("required"):
                    first_required_block = record["observedThroughBlock"]
                    first_required_duration = record["watchDurationSeconds"]
                    break
    summary = {
        "inspector": address,
        "watchStartBlock": watch_start_block,
        "watchStartTime": datetime.fromtimestamp(watch_start_epoch, timezone.utc).isoformat(),
        "lastObservedAt": datetime.fromtimestamp(now, timezone.utc).isoformat(),
        "lastObservedBlock": int(logs[-1].get("blockNumber", "0x0"), 0) if logs else watch_start_block,
        "firstRequiredLogBlock": first_required_block,
        "requiredLogFound": first_required_block is not None,
        "watchDurationSeconds": first_required_duration if first_required_block is not None else round(now - watch_start_epoch, 3),
        "watchDurationBlocks": ((first_required_block or watch_start_block) - watch_start_block),
        "finalObservationDurationSeconds": round(now - watch_start_epoch, 3),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")
PY
}

for i in 1 2 3 4; do
  funded_address_var="FUNDED_${i}_ADDRESS"
  funded_key_var="FUNDED_${i}_PRIVATE_KEY"
  inspect_address_var="INSPECT_${i}_ADDRESS"
  inspect_key_var="INSPECT_${i}_PRIVATE_KEY"
  [[ -n "${!funded_address_var:-}" ]] || { echo "$funded_address_var is required" >&2; exit 1; }
  [[ -n "${!funded_key_var:-}" ]] || { echo "$funded_key_var is required" >&2; exit 1; }
  [[ -n "${!inspect_address_var:-}" ]] || { echo "$inspect_address_var is required" >&2; exit 1; }
  [[ -n "${!inspect_key_var:-}" ]] || { echo "$inspect_key_var is required" >&2; exit 1; }
done

validate_wallets

vault_code="$(rpc_result eth_getCode "[\"$VAULT\",\"latest\"]")"
if [[ "$vault_code" == "0x" ]]; then
  echo "EIP-8312 is not active: $VAULT has no code on $RPC" >&2
  exit 1
fi
chain_id="$(rpc_result eth_chainId '[]')"
echo "chain id: $chain_id"

echo "RPC: $RPC"
echo "emission order: FUNDED_1->INSPECT_1, FUNDED_2->INSPECT_2, FUNDED_3->INSPECT_3, FUNDED_4->INSPECT_4"
echo "follow-up UTXO sends: INSPECT_1->INSPECT_2, then 50 blocks, INSPECT_3->INSPECT_4"
echo "redemption: FUNDED_4->INSPECT_4 0.05 ETH, then INSPECT_4->INSPECT_3 account ETH"
echo "value: $UTXO_VALUE_WEI wei"
echo "interval: $INTERVAL_BLOCKS blocks"
echo "logs: $LOG_DIR"

WATCH_START_BLOCK="$(rpc_result eth_blockNumber '[]')"
WATCH_START_EPOCH="$(date +%s.%N)"
last_scanned="$WATCH_START_BLOCK"
declare -a DEPOSIT_JSON=()

emit_pair() {
  local pair="$1" key_var="FUNDED_${1}_PRIVATE_KEY" recipient_var="INSPECT_${1}_ADDRESS"
  local value="${2:-$UTXO_VALUE_WEI}"
  local key="${!key_var}" recipient="${!recipient_var}" deposit_json deposit_tx current

  deposit_json="$(printf '{"rpc":"%s","op":"deposit","key":"%s","recipient":"%s","valueWei":"%s"}' \
    "$RPC" "$key" "$recipient" "$value" | "$PY" "$TXFORGE")"
  if ! deposit_tx="$(printf '%s' "$deposit_json" | json_value txHash 2>/dev/null)"; then
    echo "UTXO emission $pair failed: $deposit_json" >&2
    exit 1
  fi
  echo "emitted pair $pair: $deposit_tx"
  # Keep the receipt response only in memory for the later spend witness.
  # It is not written to disk as creation metadata.
  DEPOSIT_JSON[$pair]="$deposit_json"

  current="$(rpc_result eth_blockNumber '[]')"
  if (( current > last_scanned )); then
    append_matching_logs "$((last_scanned + 1))" "$current"
    last_scanned="$current"
  fi
}

load_existing_pair() {
  local pair="$1" tx_var="DEPOSIT_TX_${1}" tx_hash receipt_json deposit_json
  tx_hash="${!tx_var:-}"
  if [[ -z "$tx_hash" ]]; then
    echo "$tx_var is required when SKIP_EMISSIONS=1" >&2
    exit 1
  fi

  receipt_json="$(printf '{"rpc":"%s","op":"waitReceipt","txHash":"%s"}' \
    "$RPC" "$tx_hash" | "$PY" "$TXFORGE")"
  deposit_json="$($PY -c '
import json, sys
tx_hash, raw = sys.argv[1:]
receipt = json.loads(raw)
if receipt.get("status") not in ("0x1", 1):
    raise SystemExit(f"emission transaction failed: {tx_hash}")
created = receipt.get("created", [])
if not created:
    raise SystemExit(f"no UtxoCreated log found in emission transaction: {tx_hash}")
item = created[0]
print(json.dumps({
    "txHash": tx_hash,
    "block": int(receipt["block"]),
    "index": int(item["index"]),
    "valueWei": str(item["valueWei"]),
    "source": item["source"],
    "recipient": item["recipient"],
}))
' "$tx_hash" "$receipt_json")"
  DEPOSIT_JSON[$pair]="$deposit_json"
  echo "reused pair $pair: $tx_hash"
}

wait_and_scan() {
  local blocks="$1" target current
  target=$((last_scanned + blocks))
  while :; do
    current="$(rpc_result eth_blockNumber '[]')"
    if (( current >= target )); then
      break
    fi
    sleep 5
  done
  if (( current > last_scanned )); then
    append_matching_logs "$((last_scanned + 1))" "$current"
    last_scanned="$current"
  fi
}

spend_inspector_utxo() {
  local sender_pair="$1" recipient_pair="$2"
  local sender_key_var="INSPECT_${sender_pair}_PRIVATE_KEY"
  local sender_addr_var="INSPECT_${sender_pair}_ADDRESS"
  local recipient_addr_var="INSPECT_${recipient_pair}_ADDRESS"
  local source_addr_var="FUNDED_${sender_pair}_ADDRESS"
  local sender_key="${!sender_key_var}"
  local sender_addr="${!sender_addr_var}"
  local recipient_addr="${!recipient_addr_var}"
  local source_addr="${!source_addr_var}"
  local deposit_json="${DEPOSIT_JSON[$sender_pair]}"
  local creation_block utxo_index input spend_json spend_tx current

  creation_block="$(printf '%s' "$deposit_json" | json_value block)"
  utxo_index="$(printf '%s' "$deposit_json" | json_value index)"
  input="$($PY -c '
import json, sys
index, block, source, recipient, value = sys.argv[1:]
print(json.dumps({
    "index": int(index),
    "creationBlock": int(block),
    "source": source,
    "recipient": recipient,
    "valueWei": value,
}))
' "$utxo_index" "$creation_block" "$source_addr" "$sender_addr" "$UTXO_VALUE_WEI")"

  spend_json="$($PY -c '
import json, sys
rpc, key, recipient, raw_input, sender = sys.argv[1:]
print(json.dumps({
    "rpc": rpc,
    "op": "spend",
    "actorKeys": [key],
    "inputs": [json.loads(raw_input)],
    "utxoOuts": [
        {"recipient": recipient, "valueWei": "1000000000000000"},
        {"recipient": sender, "valueWei": "0"},
    ],
    "accountOuts": [],
    "changeIndex": 1,
}))
' "$RPC" "$sender_key" "$recipient_addr" "$input" "$sender_addr" | "$PY" "$TXFORGE")"

  if ! spend_tx="$(printf '%s' "$spend_json" | json_value txHash 2>/dev/null)"; then
    echo "UTXO send INSPECT_${sender_pair}->INSPECT_${recipient_pair} failed: $spend_json" >&2
    exit 1
  fi
  echo "UTXO send INSPECT_${sender_pair}->INSPECT_${recipient_pair}: $spend_tx"

  current="$(rpc_result eth_blockNumber '[]')"
  if (( current > last_scanned )); then
    append_matching_logs "$((last_scanned + 1))" "$current"
    last_scanned="$current"
  fi
}

redeem_inspector4_to3() {
  local sender_key="$INSPECT_4_PRIVATE_KEY"
  local sender_addr="$INSPECT_4_ADDRESS"
  local recipient_addr="$INSPECT_3_ADDRESS"
  local source_addr="$FUNDED_4_ADDRESS"
  local deposit_json="${DEPOSIT_JSON[4]}"
  local creation_block utxo_index input spend_json spend_tx current before after
  local started_at started_epoch completed_epoch

  creation_block="$(printf '%s' "$deposit_json" | json_value block)"
  utxo_index="$(printf '%s' "$deposit_json" | json_value index)"
  input="$($PY -c '
import json, sys
index, block, source, recipient, value = sys.argv[1:]
print(json.dumps({
    "index": int(index),
    "creationBlock": int(block),
    "source": source,
    "recipient": recipient,
    "valueWei": value,
}))
' "$utxo_index" "$creation_block" "$source_addr" "$sender_addr" "50000000000000000")"

  before="$(balance_wei "$recipient_addr")"
  started_at="$(date --iso-8601=seconds)"
  started_epoch="$(date +%s.%N)"
  spend_json="$($PY -c '
import json, sys
rpc, key, recipient, raw_input, sender, sponsor_key = sys.argv[1:]
print(json.dumps({
    "rpc": rpc,
    "op": "sponsoredSpend",
    "actorKeys": [key],
    "inputs": [json.loads(raw_input)],
    "utxoOuts": [{"recipient": sender, "valueWei": "0"}],
    "accountOuts": [{"recipient": recipient, "valueWei": "50000000000000000"}],
    "changeIndex": 0,
    "sponsorKey": sponsor_key,
}))
' "$RPC" "$sender_key" "$recipient_addr" "$input" "$sender_addr" "$FUNDED_4_PRIVATE_KEY" | "$PY" "$TXFORGE")"

  if ! spend_tx="$(printf '%s' "$spend_json" | json_value txHash 2>/dev/null)"; then
    echo "redemption INSPECT_4->INSPECT_3 failed: $spend_json" >&2
    exit 1
  fi
  completed_epoch="$(date +%s.%N)"
  after="$(balance_wei "$recipient_addr")"
  echo "redeemed INSPECT_4 UTXO to INSPECT_3 account: $spend_tx"

  # Preserve the complete receipt, including non-UTXO transfer logs, and the
  # balance/duration evidence for this redemption.
  receipt="$(rpc_result eth_getTransactionReceipt "[\"$spend_tx\"]")"
  "$PY" - "$LOG_DIR/redemption-4-to-3.json" "$started_at" "$started_epoch" \
    "$completed_epoch" "$spend_tx" "$before" "$after" "$WATCH_START_BLOCK" "$receipt" <<'PY'
import json, sys
from datetime import datetime, timezone

path, started_at, started_epoch, completed_epoch, tx_hash, before, after, watch_start_block, raw_receipt = sys.argv[1:]
receipt = json.loads(raw_receipt)
watch_start_block = int(watch_start_block, 0)
redemption_block = int(receipt.get("blockNumber", "0x0"), 0)
record = {
    "operation": "inspect_wallet_4_redeems_to_inspect_wallet_3_account",
    "startedAt": started_at,
    "completedAt": datetime.now(timezone.utc).isoformat(),
    "durationSeconds": round(float(completed_epoch) - float(started_epoch), 3),
    "txHash": tx_hash,
    "watchStartBlock": watch_start_block,
    "redemptionBlock": redemption_block,
    "watchDurationBlocks": redemption_block - watch_start_block,
    "recipient": "INSPECT_3",
    "balanceBeforeWei": before,
    "balanceAfterWei": after,
    "balanceIncreaseWei": int(after) - int(before),
    "receipt": receipt,
}
with open(path, "a", encoding="utf-8") as f:
    f.write(json.dumps(record, separators=(",", ":")) + "\n")
PY

  current="$(rpc_result eth_blockNumber '[]')"
  if (( current > last_scanned )); then
    append_matching_logs "$((last_scanned + 1))" "$current"
    last_scanned="$current"
  fi
}

if [[ "${SKIP_EMISSIONS:-0}" == "1" ]]; then
  for pair in 1 2 3 4; do
    load_existing_pair "$pair"
  done
else
  for pair in 1 2 3 4; do
    if [[ -n "${MAX_SENDS:-}" && "$pair" -gt "$MAX_SENDS" ]]; then
      break
    fi
    emit_pair "$pair"
    if [[ "$pair" -lt 4 && ( -z "${MAX_SENDS:-}" || "$pair" -lt "$MAX_SENDS" ) ]]; then
      wait_and_scan "$INTERVAL_BLOCKS"
    fi
  done
fi

if [[ -z "${MAX_SENDS:-}" || "$MAX_SENDS" -ge 4 ]]; then
  spend_inspector_utxo 1 2
  wait_and_scan 50
  spend_inspector_utxo 3 4
  emit_pair 4 50000000000000000
  redeem_inspector4_to3
else
  echo "MAX_SENDS=$MAX_SENDS: follow-up and redemption spends skipped; use MAX_SENDS=4."
fi

echo "watch complete; summaries: $LOG_DIR/inspect-wallet-{1,2,3,4}-summary.json"
