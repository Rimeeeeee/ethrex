# Authenticated discovery (experimental devnet profile)

The new path verifies this chain locally:

`trusted block hash -> header stateRoot -> account/storage proofs -> table roots -> selected entries/openings`

Supply a reference hash from your consensus/light client or a trusted checkpoint.
Fetching an arbitrary hash from the same untrusted RPC does not establish trust.
The node needs the reference state and the requested branch's recent data.
Existing single-table RPCs and the existing demo scan remain compatible.

## Wallet usage

Run the Node wallet server, then POST to `/api/authenticated-discovery`:

```json
{
  "address": "0x0000000000000000000000000000000000000042",
  "referenceBlockHash": "<your trusted 32-byte block hash>",
  "referenceBlockNumber": 100,
  "chainId": "0x7a69",
  "fromBlock": 80,
  "toBlock": 99
}
```

Or import `scanAuthenticated` from `server.mjs` and pass the same object.
The number is checked against the authenticated header. Chain ID is caller
configuration, not a trust claim derived from the provider's response.
This API is on the Node server, not the separate Python/Vercel demo backend.

The result contains `authenticated: true`, `spentStatusVerified: false` and
the verified creation records. It does not establish spendability or current
spent status. It excludes blockHash and UPT tableHash metadata because the
opening proof does not authenticate those availability-object hashes.

## Batched TLI RPC

`ethrex_queryEip8304Tables` takes one object:

```json
{
  "referenceBlockHash": "<trusted hash>",
  "tables": [{"firstBlock": "0x50", "tableSize": "0x10"}],
  "queries": [
    {"typeId": 2, "content": "0x0000000000000000000000000000000000008312"},
    {"typeId": 5, "content": "0x0000000000000000000000000000000000000000000000000000000000000042"}
  ]
}
```

Filters use AND semantics. Type 2 is the emitter address; types 3 through 6
are topics 0 through 3. Up to eight filters are supported, including multiple
constraints on one topic. Tables must be aligned, non-overlapping ranges of
1, 4, 16, 64 or 256 blocks. The response sorts tables by first block.

For each table, the server chooses the smallest matching posting range.
Example: Bob appears in 10 logs; a token address appears in 10,000. The proof
contains Bob's complete 10-entry range with adjacent boundaries. For every
candidate it proves whether the exact token-address entry at that event's
position exists. An excluded candidate includes its insertion-point neighbors,
proving absence. Missing topics work the same way. Every candidate is accounted
for, so the server cannot hide a match by simply removing it from the response.

Entries are encoded once in `entries`, indexed by their sorted table position.
`candidates`, `matches`, and boundaries refer to these indices. They share one
Merkle multiproof per table. `seedQuery` refers to the original filter order.
For an absent key, `index` is its insertion position; entries at `index-1` and
`index` prove absence when those indices exist. `firstIndex` and
`endIndexExclusive` describe the complete seed range, not pagination offsets.
The client derives matching positions itself before accepting `matches`.
Related fields are membership evidence; omission of an optional related field
is not itself a proof that the field is absent.

One `indexProof` proves all requested commitment slots against the supplied
RLP `referenceHeader`. The slot for a table is
`size * 1024 + (firstBlock / size) % 1024`. Its commitment block is
`firstBlock + size - 1 + (size == 1 ? 0 : size / 4)`.
The server verifies that each local table root equals that slot's actual value.
The wallet verifies the account and storage Merkle Patricia proofs independently.

This implements flat AND queries over indexed log fields. It does not add OR,
recursive query expressions, receipt-data proofs, or paginated selective proofs.

## Batched opening RPC

`ethrex_getAuthenticatedUtxoProofs` takes:

```json
{
  "referenceBlockHash": "<the same trusted hash>",
  "positions": [{"blockNumber": "0x50", "transactionIndex": "0x0", "logIndex": "0x0"}]
}
```

Positions come from the verified TLI results. `logIndex` is relative to that
transaction, not the block-wide index returned by some Ethereum log APIs.
The response batches opening multiproofs and a `vaultProof` for all relevant
ring slots, `1 + blockNumber % 8192`. The wallet ties each opening's source,
recipient and index back to its authenticated TLI topics.

Both endpoints resolve ancestors from the exact reference hash, even if it is
not currently canonical. They never substitute a block at the same height.

## Bounds and cache behavior

- At most 32 tables or opening blocks per request; at most 4096 opening positions.
- At most 4096 seed candidates per table and 32768 selected entries per TLI batch.
- Responses above 8 MiB are rejected. No truncated or partial success is returned.
- This profile covers the 8192-block reference window. TLI roots must also still
  exist in their level's 1024-slot ring. Smaller tables can expire sooner.
  Narrow the request or choose available larger aligned tables when necessary.
  The wallet fails closed if any requested range is unavailable; archive fallback
  and automatic subdivision of oversized proofs are not implemented.
- Default shared cache budgets are 64 MiB for TLI and 32 MiB for UPT. Operators
  embedding `Store` can call `set_proof_cache_budgets(tliBytes, uptBytes)`; zero
  disables retention. There is no new CLI flag.
- TLI charges reserve space for lazy Merkle nodes and position maps immediately.
  A first proof request still initializes those structures; subsequent requests
  reuse them. Oversized objects are served without being retained in the cache.
- Budgets use conservative memory estimates, not exact allocator/RSS accounting.
  In-flight request clones can keep evicted objects alive.

## Verification

The Rust RPC tests produce the checked-in `test/authenticated-fixture.json`
using real storage tries. The Node tests consume that exact wire response,
including rejection of a nonmatching candidate, and exercise tampered roots,
omitted matches, altered openings, wrong slots, and missing trie nodes.

```sh
cargo test -p ethrex-rpc ethrex:: --lib --offline
cargo test -p ethrex-storage proof_cache --lib --offline
cargo test -p ethrex-common eip8304 --lib --offline
cargo test -p ethrex-common proof_table_tests --lib --offline
node scripts/hegota-devnet/utxo-wallet/test/authenticated.test.mjs
node scripts/hegota-devnet/utxo-wallet/test/eip8304-discovery.test.mjs
```

Regenerate the fixture only for an intentional wire change using
`ETHREX_UPDATE_AUTH_FIXTURE=1 cargo test -p ethrex-rpc authenticated_rpc_fixture --lib`.
The fixture has synthetic genesis commitments; it tests serialization and
verification against real trie proofs, not live network consensus execution.
