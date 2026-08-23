# EIP-8304 + EIP-8312 devnet

This directory launches a three-EL Hegota Kurtosis network using the local
`ethrex:local` Docker image, then schedules the experimental EIP-8304 index and
EIP-8312 UTXO frames on future timestamps shared by every EL.

The consensus network uses three-second slots (`seconds_per_slot: 3` and
`slot_duration_ms: 3000`) so 100- and 150-block experiments finish quickly.
Slot duration is part of genesis and cannot change inside an existing enclave;
remove and recreate an older six-second enclave before running these windows.

```bash
export KURTOSIS_BIN=/mnt/c/Users/YOUR_WINDOWS_USERNAME/Downloads/kurtosis/kurtosis.exe
"$KURTOSIS_BIN" enclave stop eip8304-utxo
"$KURTOSIS_BIN" enclave rm eip8304-utxo --force
SKIP_IMAGE_BUILD=1 scripts/eip8304-utxo-devnet/start-devnet.sh
```

The EIP-8304 address in this branch is the devnet-only
`0x0000000000000000000000000000000000008304`. It is not the unresolved
canonical address from the draft EIP.

No deployment transaction or Solidity compilation is needed. At the scheduled
activation, ethrex installs the EIP's 117-byte runtime from
`crates/vm/system_contracts.rs` with nonce 1, then applies table-root system
calls at the end of each block.

## Prerequisites

- Docker
- Kurtosis
- GNU make
- Python 3
- WSL/Linux shell when running from Windows

On this Windows checkout the Kurtosis CLI is currently at
`C:\Users\YOUR_WINDOWS_USERNAME\Downloads\kurtosis\kurtosis.exe`. From WSL, export:

```bash
export KURTOSIS_BIN=/mnt/c/Users/YOUR_WINDOWS_USERNAME/Downloads/kurtosis/kurtosis.exe
```

Start Docker Desktop and enable WSL integration before launching the script.

## Start

One command builds the Docker image and launches the network:

```bash
cd /mnt/d/bogota/ethrex
scripts/eip8304-utxo-devnet/start-devnet.sh
```

To make the image build an explicit separate step:

```bash
cd /mnt/d/bogota/ethrex
make build-image TAG=local
SKIP_IMAGE_BUILD=1 scripts/eip8304-utxo-devnet/start-devnet.sh
```

The script builds `ethrex:local`, checks out the repository-pinned
`ethereum-package`, launches the enclave, patches `eip8304Time` and
`utxoFramesTime` into all three EL genesis files, and restarts them before the
activation boundary.

By default the launcher passes that pinned commit to Kurtosis as a GitHub
package locator. This avoids a native-Windows Kurtosis limitation when hashing
the upstream package's Linux symlink under `.agents`. Linux-native Kurtosis
users can opt into the local checkout with `KURTOSIS_PACKAGE=ethereum-package`.

The two benchmark EOAs are funded through `additional_preloaded_contracts`
rather than `prefunded_accounts`. Genesis-generator 6.1.4 renders an unquoted
multi-account JSON object into `values.env`; bash brace expansion otherwise
silently retains only the final account and the generator later fails in `jq`.

Set `ACTIVATION_LEAD_SECONDS` or `UTXO_DELAY_SECONDS` to change the defaults:

```bash
ACTIVATION_LEAD_SECONDS=1200 UTXO_DELAY_SECONDS=120 \
  scripts/eip8304-utxo-devnet/start-devnet.sh
```

## Verify

Use `kurtosis enclave inspect eip8304-utxo` to find a published EL RPC URL, then:

```bash
scripts/eip8304-utxo-devnet/verify-devnet.sh http://127.0.0.1:<rpc-port>
```

The verifier checks both system-contract runtimes, reads the latest one-block
table through `ethrex_getEip8304Table`, and confirms its root equals the value in
the EIP-8304 index contract's reported storage slot. It waits up to 20 minutes
for both scheduled activations; override this with `VERIFY_TIMEOUT_SECONDS`.

## Read a table for any block

The devnet enables ethrex's devnet-only table method. A one-block table is the
most direct block-by-block view:

```bash
RPC=http://127.0.0.1:<rpc-port>
BLOCK=0x2a
curl -sS "$RPC" -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ethrex_getEip8304Table\",\"params\":[\"$BLOCK\",\"0x1\"]}" | \
  python3 -m json.tool
```

The second parameter can be `0x1`, `0x4`, `0x10`, `0x40`, or `0x100`. Larger
tables must start on a matching boundary and become available after their EIP
commitment delay. The response decodes every entry and includes its table root,
contract storage slot, covered block range, and server-side load time.

Wallet discovery uses the separate `ethrex_queryEip8304Table` extension. Its
third parameter is an array of `{typeId, content}` posting keys. Ethrex
binary-searches each key in the canonical sorted table and returns only the
matching ranges, their adjacent non-match boundaries, compact deduplicated SSZ
proof nodes, proven transaction entries, and one proven type-7 full-log
commitment for each position in the intersection. Type 7 is an experimental
format extension and changes the committed table roots; this devnet must not be
described as byte-for-byte compatible with the draft EIP-8304 table format.

After verifying those proofs, the wallet calls `ethrex_getEip8304Logs` once
with the selected positions. The RPC returns only the raw logs at those
positions. Each payload is SHA-256 committed as
`EIP8304_LOG_V1 || address || topic_count || topics || data_length || data`, so
the wallet can verify the source, recipient, UTXO index, and value without
downloading or trusting a complete transaction receipt.

## Wallet

The Orbit wallet can discover the same UTXO set in two ways:

- current path: recipient-filtered `eth_getLogs`, then decode receipt logs;
- extended EIP-8304 path: verify posting-range and log-commitment proofs plus
  every table root, intersect positions, then fetch only the selected raw logs.

Table queries, historical root checks, and proof results are cached across
wallet scans. Selected raw logs are deliberately fetched again for each scan so
the measured warm path does not silently become an all-RAM result. Uncached
tables and payload batches use bounded parallelism
(`UTXO_DISCOVERY_CONCURRENCY`, default 8).

Start it against the published EL RPC endpoint:

```bash
cd /mnt/d/bogota/ethrex
python3 -m venv scripts/hegota-devnet/.venv
scripts/hegota-devnet/.venv/bin/pip install -r \
  scripts/hegota-devnet/utxo-wallet/requirements.txt
export UTXO_RPC=http://127.0.0.1:<rpc-port>
export UTXO_PYTHON=/mnt/d/bogota/ethrex/scripts/hegota-devnet/.venv/bin/python
node scripts/hegota-devnet/utxo-wallet/server.mjs
```

Open `http://127.0.0.1:8090`. The Discovery Lab switches the wallet between
receipt logs and tables, compares both at a frozen head, shows request/time/byte
metrics, and displays a decoded table for a selected block.

## Five-case randomized benchmark

Create a private benchmark configuration and fill it with the two funded
devnet accounts plus four disposable inspector accounts:

```bash
cd /mnt/d/bogota/ethrex
cp scripts/eip8304-utxo-devnet/benchmark.env.example \
  scripts/eip8304-utxo-devnet/benchmark.env
chmod 600 scripts/eip8304-utxo-devnet/benchmark.env
```

Then run:

```bash
node scripts/eip8304-utxo-devnet/run-wallet-benchmark.mjs \
  --env scripts/eip8304-utxo-devnet/benchmark.env
```

If your existing private `scripts/hegota-devnet/utxo-demo/wallets.env` already
contains `RPC`, funded accounts 1/2, and inspectors 1â€“4, it can be used directly:

```bash
UTXO_RPC=http://127.0.0.1:<rpc-port> \
UTXO_PYTHON=/mnt/d/bogota/ethrex/scripts/hegota-devnet/.venv/bin/python \
BENCHMARK_SEED=8304 \
UTXOS_PER_BLOCK=100 \
  node scripts/eip8304-utxo-devnet/run-wallet-benchmark.mjs \
  --env scripts/hegota-devnet/utxo-demo/wallets.env
```

The explicit `UTXO_RPC` takes precedence over an older `RPC=` entry in that
private file, preventing a local experiment from silently targeting a public
Hegota endpoint.

Each of five cases waits a seeded random interval, alternates between funded
accounts 1 and 2, and deposits a safe random amount to inspector 1 or 2. That
inspector spends 55–75% through one atomic fan-out transaction containing at
least `UTXOS_PER_BLOCK=100` positive-value outputs for inspector 3 or 4, plus a
change UTXO. Because the fan-out is one transaction, all outputs are guaranteed
to share a block. The script independently counts the block's `UtxoCreated`
logs and aborts unless the block, transaction, and destination-wallet discovery
all meet the configured minimum. It also checks both result-set hashes, verifies
table completeness and roots, and aborts on insufficient funded balance.
Only the exact fan-out block contributes to the reported discovery timings;
the one-UTXO deposit is bootstrap state and its checks are recorded separately.

Every run creates an ignored `results/<timestamp>/` directory with:

- `summary.json`: full configuration, balances, routes, transactions and metrics;
- `cases.jsonl`: one durable record per completed case;
- `comparison.csv`: ten rowsâ€”five receipt-log and five table measurements.
- `report.html`: a dependency-free grouped latency chart and metrics table.

The most useful presentation is a grouped bar chart of `source_discovery_ms` by
case and method, with adjacent charts for `wallet_total_ms`, `wallet_rpc_calls`,
and `response_bytes`. Show a
correctness badge for the result hashes, and a separate transaction table for
inclusion latency and gas. Also report provider RPC time, EIP table load time,
tables/entries examined, receipts fetched, block-range length, and the seed.
These distinguish index efficiency from network latency and make the run
reproducible.

The root equality check detects table/RPC inconsistencies, but the wallet reads
both the table and contract storage from the same endpoint. A production
trustless wallet would additionally authenticate the storage value against a
trusted block header (for example by verifying an account/storage proof).

## Mixed-address 100/150-block item lookup

`run-mixed-window-benchmark.mjs` continuously submits one atomic activity
transaction at a time. Each transaction contains four independently signed
EIP-8312 routes, one from every inspector wallet, and creates a seeded random
70-100 UTXOs in a single block. The first block is explicitly mixed as
`A1->A2`, `A2->A3`, `A3->A1`, and `A4->A2`; subsequent destinations are random
and always differ from their source.

A funded EOA sponsors each multi-frame transaction. Two carrier UTXOs per
wallet are alternated, allowing consecutive activity blocks without trying to
spend an opening in its creation block. Destination outputs carry a small
positive value and each route returns a change carrier to its source.

The script remembers one output from the first activity block. At 100 blocks it
locates that exact `(transaction hash, UTXO index)` through both filtered
receipt logs and root-verified EIP-8304 tables. It repeats the lookup over 150
blocks, alternating which method runs first. Result-set hashes must match and
the item must appear exactly once through both paths. Discovery benchmarking
does not perform per-UTXO spent-state enrichment, so the reported time measures
log/table lookup rather than thousands of unrelated storage reads.

The report records a cold run plus median and p95 after discarded warmups. It
also records provider time, RPC calls, bytes, candidate UTXOs, table sizes,
table/query time, returned versus full-table entries, proof bytes and
verification time, cache hits, matching positions, selected logs, route
mix, block gaps, gas, and inclusion time.

Run against a fresh three-second-slot devnet:

```bash
cd /mnt/d/bogota/ethrex

UTXO_RPC=http://127.0.0.1:<rpc-port> \
UTXO_PYTHON=/mnt/d/bogota/ethrex/scripts/hegota-devnet/.venv/bin/python \
BENCHMARK_SEED=8304 \
MIXED_MIN_UTXOS=70 \
MIXED_MAX_UTXOS=100 \
MIXED_FIRST_WINDOW_BLOCKS=100 \
MIXED_SECOND_WINDOW_BLOCKS=150 \
MIXED_CARRIER_ETH=1.0 \
MIXED_OUTPUT_VALUE_WEI=1000000000000 \
MIXED_WAIT_TIMEOUT_MS=600000 \
MIXED_CONFIRMATIONS=3 \
DISCOVERY_WARMUPS=2 \
DISCOVERY_REPETITIONS=7 \
UTXO_DISCOVERY_CONCURRENCY=8 \
node scripts/eip8304-utxo-devnet/run-mixed-window-benchmark.mjs \
  --env scripts/hegota-devnet/utxo-demo/wallets.env
```

Every run writes `activity.jsonl`, `checkpoints.json`, `summary.json`,
`comparison.csv`, and `report.html` under `results/mixed-<timestamp>/`.

Multi-route spends bind a 750,000-gas transaction cap. This is intentionally
higher than the sum of their frame gas limits because the frame transaction's
calldata-floor gas can become the effective total limit for 70-100 outputs. If
a short devnet reorganization removes a receipt, the benchmark detects the
non-canonical block hash, resubmits the identical transaction, and accepts its
outputs only after `MIXED_CONFIRMATIONS` canonical child blocks. Reorg and
resubmission counts are stored in `activity.jsonl`, `summary.json`, and the HTML
report. `firstCanonicalReceiptMs` measures initial canonical inclusion, while
`confirmationWaitMs` includes the configured confirmation depth. If
a partial run fails after writing `activity.jsonl`, reconstruct and fully
simulate its next transaction without submitting or spending funds:

```bash
UTXO_RPC=http://127.0.0.1:<rpc-port> \
UTXO_PYTHON=/mnt/d/bogota/ethrex/scripts/hegota-devnet/.venv/bin/python \
BENCHMARK_SEED=8304 \
node scripts/eip8304-utxo-devnet/diagnose-last-mixed-run.mjs \
  --results scripts/eip8304-utxo-devnet/results/<mixed-result-dir> \
  --env scripts/hegota-devnet/utxo-demo/wallets.env
```

## Sparse 100+ block wallet benchmark

The dense benchmark above is deliberately unfavorable to EIP-8304: all 100
matches are already in one block. The sparse benchmark models wallet history
instead. It creates two bootstrap UTXOs outside the measured range, then moves
those live UTXOs randomly among inspectors 1-4. Each event consumes one UTXO
and creates exactly one replacement UTXO. The destination may be the same
wallet or a different wallet.

By default five events are separated by a seeded random 25-30 block gap, so the generated
event history spans at least 100 blocks. All four wallets then scan the same
aligned 144-block range. After the range closes, the script waits 16 more blocks
so aggregated EIP-8304 tables are committed. This lets the table wallet use
16/64-block tables and fetch only the proven log payloads at matching
positions. It is a relevant sparse-discovery workload, although it does not
assume that tables must beat a locally indexed `eth_getLogs` implementation.

Run it against an already-active devnet:

```bash
cd /mnt/d/bogota/ethrex

UTXO_RPC=http://127.0.0.1:<rpc-port> \
UTXO_PYTHON=/mnt/d/bogota/ethrex/scripts/hegota-devnet/.venv/bin/python \
BENCHMARK_SEED=8304 \
SPARSE_EVENTS=5 \
SPARSE_MIN_GAP_BLOCKS=25 \
SPARSE_MAX_GAP_BLOCKS=30 \
SPARSE_SCAN_BLOCKS=144 \
SPARSE_TABLE_SETTLEMENT_BLOCKS=16 \
SPARSE_WAIT_TIMEOUT_MS=900000 \
DISCOVERY_WARMUPS=2 \
DISCOVERY_REPETITIONS=7 \
UTXO_DISCOVERY_CONCURRENCY=8 \
node scripts/eip8304-utxo-devnet/run-sparse-wallet-benchmark.mjs \
  --env scripts/hegota-devnet/utxo-demo/wallets.env
```

At a three-second slot time this run takes roughly 8-11 minutes, mainly because
the sparse block gaps are real chain blocks. The output is written under
`results/sparse-<timestamp>/` as `events.jsonl`, `summary.json`,
`comparison.csv`, and `report.html`.

For a long-range sparse run, place two events 100-1,000 blocks apart and allow
256-block tables to settle:

```bash
SPARSE_EVENTS=2 \
SPARSE_MIN_GAP_BLOCKS=100 \
SPARSE_MAX_GAP_BLOCKS=1000 \
SPARSE_SCAN_BLOCKS=1024 \
SPARSE_TABLE_SETTLEMENT_BLOCKS=64 \
DISCOVERY_WARMUPS=2 \
DISCOVERY_REPETITIONS=7 \
UTXO_DISCOVERY_CONCURRENCY=8 \
node scripts/eip8304-utxo-devnet/run-sparse-wallet-benchmark.mjs \
  --env scripts/hegota-devnet/utxo-demo/wallets.env
```

At three-second slots this 1,024-block preset takes roughly 55-60 minutes. The
generated history is reused for every warmup and measured
scan, so additional repetitions do not require additional blocks or funds.

## Image-build network failures

An unrestricted cargo-chef workspace build resolves the L2 `aligned_layer`
Git dependency while preparing the otherwise L1 image. That dependency has
deeply nested Git submodules, so a transient GitHub TLS disconnect can surface
as either `early EOF` or the misleading follow-on message
`revision ... not found`.

The Dockerfile now cooks only the `ethrex` binary dependency graph, forces Git
HTTP/1.1, and retries a cached Cargo fetch three times. Re-run the normal build
after a transient failure:

```bash
cd /mnt/d/bogota/ethrex
make build-image TAG=local
docker image inspect ethrex:local --format '{{.Id}}'
SKIP_IMAGE_BUILD=1 scripts/eip8304-utxo-devnet/start-devnet.sh
```

Do not set `SKIP_IMAGE_BUILD=1` if the preceding image build failed. The
launcher checks that `ethrex:local` exists and exits before starting Kurtosis
if it does not. The scripts use Python 3 for JSON processing, so `jq` is not
required.

If a build reports `Read-only file system`, `Input/output error`, or `SIGBUS`,
check free space with `df -h /mnt/c /mnt/d`. Docker Desktop normally stores its
Linux disk image on `C:`. Free at least 20 GiB there, or move Docker's disk image
to `D:` in Docker Desktop under **Settings > Resources > Advanced**, then
restart Docker Desktop before building again. Those messages are host-storage
failures, not compiler diagnostics.

## Stop

```bash
"${KURTOSIS_BIN:-kurtosis}" enclave stop eip8304-utxo
"${KURTOSIS_BIN:-kurtosis}" enclave rm eip8304-utxo --force
```
