# Local validation, 2026-10-06

The runner completed against the pinned Reth `frames-eips` checkout and this
ethrex branch. All 10 produced blocks were imported by both clients with matching
hashes, state roots, receipt roots, transaction roots, gas, block access list
hashes, and slot numbers. Frame receipts matched in status, execution gas, state
gas, and log contents. Matching block hashes include the full header commitment.

The run exercised empty blocks from each producer, successful assertions from
each producer, included failed assertions that preserve the previous storage
value, a non-zero keyed nonce, recent-root writes, and canonical recent-root
verification admitted by each client's mempool. Assertions also checked the
full-word topic view, signature-topic exclusion, event count, and EVENTDATACOPY.
Both clients rejected replay of a consumed keyed nonce and an unwritten root.

The EIP integration regression filter passed 443 tests, including all 41
EIP-7906 assertion tests and the existing EIP-8141/8250/8272 tests. The FOCIL
profile-2 regression filter passed another 43 tests. Library suites passed
192 common-type tests, 38 LEVM tests, 130 RPC tests, and 18 VM tests. The
recent-root mini-EVM also passed its 12 boundary and rejection cases plus the
storage-write reference vector. Rust formatting passed `cargo fmt --all -- --check`.

```bash
export RUST_MIN_STACK=16777216
cargo +stable test -p ethrex-test --test ethrex_tests eip --locked
cargo +stable test -p ethrex-test --test ethrex_tests focil_profile2 --locked
cargo +stable test -p ethrex-common -p ethrex-levm -p ethrex-vm -p ethrex-rpc --lib --locked
```

The pins, client version strings, checked fields, and block hashes are recorded
in [validation.json](validation.json). ethrex's version string contains Vergen
fallback values because the tested executable was built from a Windows-created
worktree in WSL; the source base and Reth dependency pins are recorded separately.

This was an execution-layer compatibility run controlled through the Engine
API. It does not establish consensus-client interoperability, P2P propagation,
stress performance, or compatibility with later revisions of the draft EIPs.
