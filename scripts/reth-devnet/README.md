# ethrex + Reth frame-EIP devnet

The [recorded validation run](VALIDATION.md) passed all 10 mixed-client blocks.

This is a disposable two-client **execution-layer devnet**. A Python driver acts
as the Engine API controller, alternates block production between ethrex and
Reth, imports every payload on both clients, and compares consensus fields.
It does not start a beacon node or validators and does not test P2P propagation.

## Version target

| Component | Pin |
|---|---|
| ethrex base | upstream `hegota-testnet`, `536d7953ac61a67c72bc04935843c694ae1a7bd6` |
| Reth | `frames-eips`, `ce5d5648f3` |
| Reth revm | `035f51522b90080440c9ed60337c80823c0b3f43` |
| Reth alloy | `22793fde0bf9d1480698584c14c7d335d32a926d` |
| Recent-root runtime | 320 bytes, keccak `da160390a838ee04013b2ff3abf4decc9aa3cc6c2f59dd90ca176c2b850be4e3` |

The wire format is type `0x06` with `nonce_keys`, `nonce_seq`, per-frame
`[execution,state]` limits, and canonical EIP-8272 VERIFY frames (no separate
recent-root envelope field). POST_TX is mode 3. TXTRACE/TXDIFF/EVENTDATACOPY are
`0xb7`/`0xb8`/`0xb9`. These draft implementations are pinned for compatibility;
this profile is not a declaration of final EIP compliance.

RPC frame receipts follow Reth/Alloy's shape: `gasUsed` is execution plus state,
and `executionGasUsed` and `stateGasUsed` expose the separate dimensions.

## Build and run (Linux / WSL)

Use the existing Reth checkout with its lockfile; do not update dependencies.
Reth requires Rust 1.96 or newer; the build script uses nightly. ethrex uses
stable (1.93 or newer). Native build prerequisites include a C/C++ toolchain,
CMake, OpenSSL development headers, and libclang; adjust `LIBCLANG_PATH` if needed.
Install `uv` to run the Python script and its pinned Keccak dependency.
When building a Windows checkout in WSL, put `BUILD_ROOT` on the Linux filesystem
(for example `$HOME/.cache/ethrex-reth-devnet`) to avoid slow native-library builds.

```bash
export RETH_DIR=/path/to/reth-frames-eips
bash scripts/reth-devnet/build.sh
uv run scripts/reth-devnet/devnet.py \
  --reth .devnet-build/reth/target/debug/reth \
  --ethrex .devnet-build/ethrex/target/debug/ethrex \
  --keep-running
```

The runner first verifies a shared genesis and exact predeploy code, empty
blocks from each client, successful and reverted assertions from each client,
keyed nonces, recent-root writes, canonical verification with assertions, and
rejection of an unwritten root. It checks matching block hashes, state and
receipt roots, gas, block access list hashes, per-frame receipts, and storage.

`--keep-running` produces alternating empty blocks after verification. Omit it
for a smoke test that shuts down its own processes. Ctrl+C stops the two processes
started by the runner. Each run creates a fresh `.devnet/<timestamp>-<random>`
directory with genesis, JWT, client logs, data directories, and `report.json`.
`--work-dir` must name a directory that does not yet exist. `--port-base` changes
all ports if the defaults are occupied.

The runner starts ethrex in full-sync mode and supplies a 16 MiB Rust worker
stack when `RUST_MIN_STACK` is unset, so unoptimized VM payload imports can run.

| Service | Default endpoint |
|---|---|
| Reth JSON-RPC | `http://127.0.0.1:19545` |
| ethrex JSON-RPC | `http://127.0.0.1:19645` |
| Reth Engine API | `http://127.0.0.1:19551` |
| ethrex Engine API | `http://127.0.0.1:19651` |

The genesis prefunds a permissive contract sender at `0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`.
Anyone can spend its balance. Use it only for this disposable local network.

## Shared genesis and Engine API

Both clients use the same generated genesis: Amsterdam and Bogota activate at
0; `focilTime` is `18446744073709551615` to defer FOCIL. The optional ethrex
extensions (`payerTxparamTime`, `derivedSlotTime`, and `aaVopsSlotCount`) remain
unset. ethrex maps `bogotaTime` to Hegota. An omitted `focilTime` preserves the
original ethrex behavior of activating FOCIL with Hegota.

The driver uses `engine_forkchoiceUpdatedV4`, `engine_getPayloadV6`, and
`engine_newPayloadV5`, including `slotNumber`, `targetGasLimit`, execution
requests, and the serialized block access list. This allows frames without
requiring Reth's branch to implement FOCIL. A full consensus devnet must use a
consensus client that supports the same Engine API methods and fork schedule.

`system-alloc.json` contains standard system predeploy bytecode and initial
request-queue state. Frame-specific predeploys and test contracts are added by
the runner. No private key or existing node data is used.
