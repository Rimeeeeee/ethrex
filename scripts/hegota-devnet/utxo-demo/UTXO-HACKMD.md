# ethrex EIP-8312 UTXO watcher experiment

## What this experiment is designed to show

This experiment demonstrates:

1. Four wallets emitting UTXOs to four zero-balance inspector wallets.
2. All inspectors beginning their watch from the same chain head.
3. UTXO discovery by scanning `UtxoCreated` logs.
4. Required versus unrelated logs for each inspector.
5. UTXO-to-UTXO transfers.
6. Redemption of a UTXO into a normal ETH account balance.
7. Watch duration and discovery latency.

The experiment is intended for an EIP-8312-enabled ethrex devnet.

## Network requirements

Use an RPC endpoint where the EIP-8312 vault is active:

```text
RPC:      https://rpc1.hegota.ethrex.xyz
Chain ID: 3151908 (0x301824)
Vault:    0x0000000000000000000000000000000000008312
```

Verify activation:

```bash
curl -s "$RPC" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_getCode","params":["0x0000000000000000000000000000000000008312","latest"]}'
```

The result must not be `0x`.

## Wallet roles

The user provides eight wallets:

| Role | Purpose |
|---|---|
| `FUNDED_1` | Emits the first UTXO to `INSPECT_1` |
| `FUNDED_2` | Emits the second UTXO to `INSPECT_2` |
| `FUNDED_3` | Emits the third UTXO to `INSPECT_3` |
| `FUNDED_4` | Emits the fourth UTXO and sponsors the final redemption |
| `INSPECT_1` | Receives and later spends a UTXO to `INSPECT_2` |
| `INSPECT_2` | Watches for its own UTXO |
| `INSPECT_3` | Receives a UTXO and later receives normal ETH |
| `INSPECT_4` | Receives UTXOs and redeems one to `INSPECT_3` |

The four funded wallets must have ETH. The four inspector wallets must begin with zero ETH.

## Event being watched

The script filters logs from the UTXO vault using:

```text
UtxoCreated(address source, address recipient, uint64 index, uint256 value)
topic0:
0x3b19241465a47bc187f1d9c7db70834855a907183742a4b63aa824c576296f5e
```

The log fields are:

```text
topics[1]       source/sender
topics[2]       UTXO recipient
data[0:32]      UTXO index
data[32:64]     UTXO value in wei
```

## Transaction sequence

All inspectors start watching at the same block `B0):

```text
B0:              all inspectors begin watching

B0:              FUNDED_1 -> INSPECT_1, 0.01 ETH UTXO
B0 + 20 blocks:  FUNDED_2 -> INSPECT_2, 0.01 ETH UTXO
B0 + 40 blocks:  FUNDED_3 -> INSPECT_3, 0.01 ETH UTXO
B0 + 60 blocks:  FUNDED_4 -> INSPECT_4, 0.01 ETH UTXO

after emissions: INSPECT_1 -> INSPECT_2, 0.001 ETH UTXO
wait 50 blocks
                 INSPECT_3 -> INSPECT_4, 0.001 ETH UTXO

final:            FUNDED_4 -> INSPECT_4, 0.05 ETH UTXO
                 INSPECT_4 -> INSPECT_3, 0.05 ETH normal account output
```

The final redemption is sponsored by `FUNDED_4), allowing `INSPECT_3` to receive the full `0.05 ETH` as a normal account balance.

## Shell script

Copy the following into a file named `emit-and-inspect.sh`:

```bash
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
```

The script calls a companion `txforge.py` transaction builder. The builder must support the operations `addressOf`, `deposit`, `waitReceipt`, `spend`, and `sponsoredSpend`, and must implement EIP-8312 type-`0x06` transaction encoding. The shell script itself does not replace that transaction builder.

## Wallet configuration

Create a file named `wallets.env` beside the script:

```bash
RPC=https://rpc1.hegota.ethrex.xyz
INTERVAL_BLOCKS=20
UTXO_VALUE_WEI=10000000000000000

FUNDED_1_ADDRESS=0x...
FUNDED_1_PRIVATE_KEY=0x...
FUNDED_2_ADDRESS=0x...
FUNDED_2_PRIVATE_KEY=0x...
FUNDED_3_ADDRESS=0x...
FUNDED_3_PRIVATE_KEY=0x...
FUNDED_4_ADDRESS=0x...
FUNDED_4_PRIVATE_KEY=0x...

INSPECT_1_ADDRESS=0x...
INSPECT_1_PRIVATE_KEY=0x...
INSPECT_2_ADDRESS=0x...
INSPECT_2_PRIVATE_KEY=0x...
INSPECT_3_ADDRESS=0x...
INSPECT_3_PRIVATE_KEY=0x...
INSPECT_4_ADDRESS=0x...
INSPECT_4_PRIVATE_KEY=0x...
```

Never publish `wallets.env`.

## How to run

The directory should contain:

```text
emit-and-inspect.sh
wallets.env
txforge.py
.venv/bin/python3
```

Install the Python dependencies:

```bash
python3 -m venv .venv
.venv/bin/pip install eth-account eth-keys eth-hash
chmod +x emit-and-inspect.sh
bash -n emit-and-inspect.sh
```

Run a fresh experiment:

```bash
MAX_SENDS=4 \
LOG_DIR="$PWD/logs/fresh-run" \
bash emit-and-inspect.sh
```

Use a new `LOG_DIR` for each run. `MAX_SENDS=4` is required for the follow-up transfers and final redemption.

## Resume mode

If the first four emission transactions already succeeded, skip creating four new UTXOs:

```bash
SKIP_EMISSIONS=1 \
MAX_SENDS=4 \
DEPOSIT_TX_1=0x... \
DEPOSIT_TX_2=0x... \
DEPOSIT_TX_3=0x... \
DEPOSIT_TX_4=0x... \
LOG_DIR="$PWD/logs/resume-run" \
bash emit-and-inspect.sh
```

Resume mode reads the four existing receipts and recovers the UTXO index, creation block, value, source, and recipient in memory for witness construction. It does not create replacement initial UTXOs.

## Output files

For each inspector:

```text
inspect-wallet-1-required.jsonl
inspect-wallet-1-unrequired.jsonl
inspect-wallet-1-summary.json
```

The same files are produced for inspectors 2, 3, and 4.

Additional files:

```text
spender-wallet-N.jsonl
unrelated-utxo-logs.jsonl
redemption-4-to-3.json
```

A required log is one whose `topics[2]` matches that inspector. An unrequired log belongs to another recipient. The redemption file contains the complete receipt, balance before/after, balance increase, transaction duration, and block duration.

## Log analysis from the completed run

The analyzed run used the four existing emission transactions and resumed from block `98653`.

| Inspector | First required block | Watch duration | Result |
|---|---:|---:|---|
| Inspector 1 | `98660` | 7 blocks / 40.314 seconds | Found |
| Inspector 2 | `98660` | 7 blocks / 40.314 seconds | Found |
| Inspector 3 | `98713` | 60 blocks / 357.861 seconds | Found |
| Inspector 4 | `98713` | 60 blocks / 357.861 seconds | Found |

The first follow-up spend occurred at block `98660`:

```text
INSPECT_1 -> INSPECT_2
INSPECT_2 received: 0.001 ETH UTXO
INSPECT_1 received: approximately 0.008943926 ETH change
```

The second follow-up spend occurred at block `98713`:

```text
INSPECT_3 -> INSPECT_4
INSPECT_4 received: 0.001 ETH UTXO
INSPECT_3 received: approximately 0.008943902 ETH change
```

The block difference was 53 blocks, satisfying the requested 50-block delay.

### Final redemption

The final redemption transaction succeeded:

```text
Transaction:
0x330dbc8dd62d4de7864b55f1cbec8f80df4db2740634e1626b7f363dc0f03e9b

Status:              SUCCESS
Redemption block:    98719
INSPECT_3 before:    0 wei
INSPECT_3 after:     50000000000000000 wei
Balance increase:    0.05 ETH
```

The receipt confirmed:

- Type-`0x06` transaction.
- `FUNDED_4` as payer/sponsor.
- A zero-valued change UTXO returned to `INSPECT_4`.
- An ETH transfer log crediting `INSPECT_3`.

## What was achieved

The experiment demonstrated that:

1. A wallet can receive an ETH UTXO while its normal account balance remains zero.
2. UTXO ownership is discovered from `UtxoCreated` logs.
3. Multiple wallets can independently classify required and unrelated logs from the same chain range.
4. UTXOs can be transferred between zero-balance inspector wallets.
5. A UTXO can be redeemed into a normal ETH account balance.
6. A sponsor can pay redemption gas so the recipient receives the full UTXO value.
7. Discovery duration can be measured in both blocks and wall-clock time.

## Security note

The logs do not contain private keys, but they contain sensitive information:

- Wallet addresses and relationships.
- Transaction hashes and block hashes.
- UTXO values and change values.
- Watch timestamps and discovery timing.
- Payer/sponsor information.
- Balance before/after redemption.

Before sharing logs publicly, redact addresses, hashes, timestamps, balances, and payer fields if the wallet activity should remain private. Never publish `wallets.env`.

## Limitations

- The RPC must have EIP-8312 activated.
- The shell script depends on a compatible EIP-8312 `txforge.py` builder.
- The script is one process that scans once and classifies logs for all inspectors; it models independent wallet discovery but does not run four separate OS processes.
- Follow-up witness metadata is held in memory and is not persisted as a wallet database.
- The script does not implement restart-safe scan checkpoints.
- Inspector wallets cannot be reused unchanged after a completed run because `INSPECT_3` receives normal ETH during redemption.
