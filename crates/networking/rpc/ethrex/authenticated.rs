//! Bounded, fork-pinned proof serving. The client must obtain the reference
//! hash independently and verify the returned header and state/table proofs.
use super::*;
use crate::types::account_proof::{AccountProof, StorageProof};
use ethrex_common::{
    BigEndianHash, H256,
    types::{eip8304::INDEX_CONTRACT_ADDRESS, utxo_vault},
};
use ethrex_rlp::encode::RLPEncode;
use ethrex_storage::Store;
use serde_json::{Map, json};

const MAX_TABLES: usize = 32;
const MAX_CANDIDATES: usize = 4096;
const MAX_SELECTED_ENTRIES: usize = 32768;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

fn bad(message: &str) -> RpcErr {
    RpcErr::BadParams(message.to_owned())
}
fn object(params: &Option<Vec<Value>>) -> Result<&Map<String, Value>, RpcErr> {
    let params = params
        .as_ref()
        .filter(|p| p.len() == 1)
        .ok_or_else(|| bad("expected one request object"))?;
    params[0]
        .as_object()
        .ok_or_else(|| bad("expected one request object"))
}
fn field<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a Value, RpcErr> {
    object
        .get(name)
        .ok_or_else(|| bad(&format!("missing {name}")))
}
fn reference_hash(object: &Map<String, Value>) -> Result<H256, RpcErr> {
    serde_json::from_value(field(object, "referenceBlockHash")?.clone())
        .map_err(|_| bad("referenceBlockHash must be a 32-byte hash"))
}
fn bounded_response(value: Value) -> Result<Value, RpcErr> {
    if serde_json::to_vec(&value)
        .map_err(|e| RpcErr::Internal(e.to_string()))?
        .len()
        > MAX_RESPONSE_BYTES
    {
        return Err(bad(
            "proof response exceeds 8 MiB; request fewer tables or positions",
        ));
    }
    Ok(value)
}

#[derive(Debug)]
pub(crate) struct QueryTablesRequest {
    reference: H256,
    tables: Vec<(u64, u64)>,
    queries: Vec<Eip8304ContentQuery>,
}

impl RpcHandler for QueryTablesRequest {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let object = object(params)?;
        let reference = reference_hash(object)?;
        let values = field(object, "tables")?
            .as_array()
            .filter(|v| !v.is_empty() && v.len() <= MAX_TABLES)
            .ok_or_else(|| bad("tables must contain between 1 and 32 ranges"))?;
        let mut tables = Vec::with_capacity(values.len());
        for value in values {
            let range = value
                .as_object()
                .ok_or_else(|| bad("table range must be an object"))?;
            let first = parse_quantity(field(range, "firstBlock")?, 0)?;
            let size = parse_quantity(field(range, "tableSize")?, 0)?;
            if !TABLE_SIZES.contains(&size)
                || first % size != 0
                || first.checked_add(size).is_none()
            {
                return Err(bad("unsupported, unaligned or overflowing table range"));
            }
            tables.push((first, size));
        }
        tables.sort_unstable();
        if tables.windows(2).any(|w| w[0].0 + w[0].1 > w[1].0) {
            return Err(bad("table ranges must not overlap"));
        }
        let values = field(object, "queries")?
            .as_array()
            .filter(|v| !v.is_empty() && v.len() <= 8)
            .ok_or_else(|| bad("queries must contain between 1 and 8 AND filters"))?;
        let queries = values
            .iter()
            .enumerate()
            .map(|(i, v)| parse_content_query(v, i))
            .collect::<Result<Vec<_>, _>>()?;
        let mut unique = HashSet::new();
        if queries
            .iter()
            .any(|q| !unique.insert((q.type_id, q.content.clone())))
        {
            return Err(bad("duplicate query filter"));
        }
        Ok(Self {
            reference,
            tables,
            queries,
        })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let header = reference_header(&context.storage, self.reference)?;
        let mut tables = Vec::with_capacity(self.tables.len());
        let mut roots = BTreeMap::new();
        let mut remaining = MAX_SELECTED_ENTRIES;
        let oldest = self.tables[0].0;
        ensure_recent(header.number, oldest)?;
        let hashes = branch_hashes(&context.storage, self.reference, oldest)?;
        for &(first, size) in &self.tables {
            let end = first + size - 1;
            let commitment = commitment_block(first, size)?;
            if commitment > header.number || header.number - commitment >= size * TABLES_PER_LEVEL {
                return Err(bad(
                    "table is not committed or its root has expired at referenceBlockHash",
                ));
            }
            let end_hash = *hashes
                .get(&end)
                .ok_or_else(|| bad("table is after the reference block"))?;
            let level = TABLE_SIZES
                .iter()
                .position(|s| *s == size)
                .ok_or_else(|| bad("invalid size"))?;
            let table = context
                .storage
                .get_or_reconstruct_index_table(level, end, end_hash)?
                .ok_or_else(|| bad("EIP-8304 is not active for the requested table"))?;
            let slot = H256::from_low_u64_be(table_storage_slot(&table)?);
            if roots.insert(slot, table.table_root()).is_some() {
                return Err(bad("tables alias the same commitment slot"));
            }
            tables.push(selective_table(&table, &self.queries, &mut remaining)?);
        }
        let address =
            INDEX_CONTRACT_ADDRESS.ok_or_else(|| bad("index contract is not configured"))?;
        let proof = commitment_proof(&context.storage, &header, address, &roots).await?;
        bounded_response(json!({
            "format": "ethrex-authenticated-tli-v1",
            "referenceHeader": format!("0x{}", hex::encode(header.encode_to_vec())),
            "indexProof": proof, "tables": tables
        }))
    }
}

fn commitment_block(first: u64, size: u64) -> Result<u64, RpcErr> {
    first
        .checked_add(size - 1)
        .and_then(|end| end.checked_add(if size == 1 { 0 } else { size / 4 }))
        .ok_or_else(|| bad("commitment block overflow"))
}
fn ensure_recent(reference: u64, block: u64) -> Result<(), RpcErr> {
    if block > reference || reference - block >= RING_SIZE {
        return Err(bad(
            "requested block is outside the 8192-block reference window",
        ));
    }
    Ok(())
}
fn reference_header(store: &Store, hash: H256) -> Result<BlockHeader, RpcErr> {
    store
        .get_block_header_by_hash(hash)?
        .ok_or_else(|| bad("unknown referenceBlockHash"))
}
fn branch_hashes(
    store: &Store,
    reference: H256,
    oldest: u64,
) -> Result<BTreeMap<u64, H256>, RpcErr> {
    let mut hashes = BTreeMap::new();
    for ancestor in store.ancestors(reference) {
        let (hash, header) = ancestor?;
        hashes.insert(header.number, hash);
        if header.number <= oldest {
            return Ok(hashes);
        }
    }
    Err(bad("reference block ancestry is unavailable"))
}

async fn commitment_proof(
    store: &Store,
    header: &BlockHeader,
    address: Address,
    roots: &BTreeMap<H256, H256>,
) -> Result<AccountProof, RpcErr> {
    let slots = roots.keys().copied().collect::<Vec<_>>();
    let proof = store
        .get_account_proof(header.state_root, address, &slots)
        .await?
        .ok_or_else(|| bad("reference state is unavailable"))?;
    for slot in &proof.storage_proof {
        if roots.get(&slot.key).copied() != Some(H256::from_uint(&slot.value)) {
            return Err(bad(
                "table root does not match the commitment at referenceBlockHash",
            ));
        }
    }
    if proof.storage_proof.len() != roots.len() {
        return Err(bad("missing commitment proof"));
    }
    Ok(AccountProof {
        address,
        account_proof: proof.proof,
        balance: proof.account.balance,
        code_hash: proof.account.code_hash,
        nonce: proof.account.nonce,
        storage_hash: proof.account.storage_root,
        storage_proof: proof
            .storage_proof
            .into_iter()
            .map(|p| StorageProof {
                key: p.key.into_uint(),
                value: p.value,
                proof: p.proof,
            })
            .collect(),
    })
}

fn prefix(query: &Eip8304ContentQuery) -> Vec<u8> {
    let mut prefix = query.type_id.to_be_bytes().to_vec();
    prefix.extend_from_slice(&query.content);
    prefix
}

/// Prove the complete smallest posting range, then prove each other exact
/// (filter, event position) key present or absent. Rejected candidates carry
/// absence witnesses too, so the server cannot silently omit a matching log.
fn selective_table(
    table: &IndexTable,
    queries: &[Eip8304ContentQuery],
    remaining: &mut usize,
) -> Result<Value, RpcErr> {
    let entries = table.encoded_entries();
    let prefixes = queries.iter().map(prefix).collect::<Vec<_>>();
    let ranges = prefixes
        .iter()
        .map(|prefix| {
            let first = entries.partition_point(|entry| entry.as_bytes() < prefix.as_slice());
            let end = first
                + entries[first..].partition_point(|entry| entry.as_bytes().starts_with(prefix));
            (first, end)
        })
        .collect::<Vec<_>>();
    let seed = (0..queries.len())
        .min_by_key(|&i| ranges[i].1 - ranges[i].0)
        .ok_or_else(|| bad("empty filters"))?;
    let (first, end) = ranges[seed];
    if end - first > MAX_CANDIDATES {
        return Err(bad("more than 4096 candidates; request smaller tables"));
    }
    let mut selected = BTreeSet::new();
    selected.extend(first..end);
    add_boundaries(&mut selected, first, end, entries.len());
    let mut candidates = Vec::new();
    let mut matches = Vec::new();
    for seed_index in first..end {
        let (block, transaction, log) =
            log_position_key(&entries[seed_index]).ok_or_else(|| bad("invalid log entry"))?;
        let mut checks = Vec::new();
        let mut matched = true;
        for (query_index, prefix) in prefixes.iter().enumerate() {
            if query_index == seed {
                continue;
            }
            let mut key = prefix.clone();
            key.extend_from_slice(&block.to_be_bytes());
            key.extend_from_slice(&transaction.to_be_bytes());
            key.extend_from_slice(&log.to_be_bytes());
            let index = entries.partition_point(|entry| entry.as_bytes() < key.as_slice());
            let present = entries
                .get(index)
                .is_some_and(|entry| entry.as_bytes() == key);
            if present {
                selected.insert(index);
            } else {
                add_boundaries(&mut selected, index, index, entries.len());
            }
            matched &= present;
            checks.push(json!({"queryIndex": query_index, "index": index, "present": present}));
        }
        candidates.push(json!({"seedIndex": seed_index, "checks": checks}));
        if matched {
            // Include all available fields and transaction hash only for matches.
            let tx = table
                .transaction_entry_index(block, transaction)
                .ok_or_else(|| {
                    RpcErr::Internal("matching log is missing its transaction entry".to_owned())
                })?;
            selected.insert(tx);
            let fields = (2..=6)
                .filter_map(|kind| table.log_entry_index(block, transaction, log, kind))
                .collect::<Vec<_>>();
            selected.extend(fields.iter().copied());
            matches.push(json!({"seedIndex": seed_index, "transaction": tx, "fields": fields}));
        }
        if selected.len() > *remaining {
            return Err(bad(
                "batch exceeds 32768 selected entries; split the request",
            ));
        }
    }
    if selected.len() > *remaining {
        return Err(bad(
            "batch exceeds 32768 selected entries; split the request",
        ));
    }
    *remaining -= selected.len();
    let indices = selected.into_iter().collect::<Vec<_>>();
    let proof = table
        .multiproof(&indices)
        .ok_or_else(|| RpcErr::Internal("cannot build table proof".to_owned()))?;
    Ok(json!({
        "firstBlock": format!("0x{:x}", table.first_block()),
        "tableSize": format!("0x{:x}", table.table_size()),
        "entryCount": entries.len(), "tableRoot": format!("{:#x}", table.table_root()),
        "seedQuery": seed, "firstIndex": first, "endIndexExclusive": end,
        "candidates": candidates, "matches": matches,
        "entries": indices.iter().map(|&index| json!({"index": index, "encoded": format!("0x{}", hex::encode(entries[index].as_bytes()))})).collect::<Vec<_>>(),
        "proofNodes": proof.into_iter().map(|node| json!({"level": node.level, "nodeIndex": node.node_index, "hash": format!("{:#x}", node.hash)})).collect::<Vec<_>>()
    }))
}

fn add_boundaries(selected: &mut BTreeSet<usize>, first: usize, end: usize, count: usize) {
    if first > 0 {
        selected.insert(first - 1);
    }
    if end < count {
        selected.insert(end);
    }
}

#[derive(Debug)]
pub(crate) struct AuthenticatedUtxoRequest {
    reference: H256,
    positions: Vec<UtxoEventPosition>,
}

impl RpcHandler for AuthenticatedUtxoRequest {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let object = object(params)?;
        let reference = reference_hash(object)?;
        let positions =
            GetUtxoProofsRequest::parse(&Some(vec![field(object, "positions")?.clone()]))?
                .positions;
        if positions.is_empty() {
            return Err(bad("positions must not be empty"));
        }
        if positions
            .iter()
            .map(|p| p.block_number)
            .collect::<HashSet<_>>()
            .len()
            > MAX_TABLES
        {
            return Err(bad("positions may span at most 32 blocks"));
        }
        Ok(Self {
            reference,
            positions,
        })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let header = reference_header(&context.storage, self.reference)?;
        let mut requested = BTreeMap::<u64, BTreeSet<(u32, u32)>>::new();
        for position in &self.positions {
            ensure_recent(header.number, position.block_number)?;
            requested
                .entry(position.block_number)
                .or_default()
                .insert((position.transaction_index, position.log_index));
        }
        let oldest = *requested
            .keys()
            .next()
            .ok_or_else(|| bad("empty positions"))?;
        let hashes = branch_hashes(&context.storage, self.reference, oldest)?;
        let chain_id = context.storage.get_chain_config().chain_id;
        let mut roots = BTreeMap::new();
        let mut blocks = Vec::new();
        for (number, positions) in requested {
            let hash = *hashes.get(&number).ok_or_else(|| bad("missing ancestor"))?;
            let table = match context.storage.get_utxo_proof_table(hash)? {
                Some(table) => table,
                None => {
                    let receipts = context.storage.get_receipts_for_block(&hash).await?;
                    let table = UtxoProofTable::from_receipts(chain_id, number, hash, &receipts)
                        .map_err(|e| RpcErr::Internal(e.to_string()))?;
                    context.storage.store_utxo_proof_table(&table)?;
                    table
                }
            };
            if table.chain_id() != chain_id
                || table.block_number() != number
                || table.vault() != utxo_vault()
            {
                return Err(RpcErr::Internal("UPT metadata mismatch".to_owned()));
            }
            roots.insert(H256::from_uint(&ring_slot(number)), table.openings_root());
            let (records, nodes) = table
                .select_by_event_positions(&positions)
                .map_err(|e| bad(&e.to_string()))?;
            blocks.push(UtxoBlockProofResult {
                format_version: UTXO_PROOF_TABLE_FORMAT_VERSION,
                chain_id: format!("0x{chain_id:x}"),
                vault: format!("{:#x}", table.vault()),
                block_number: format!("0x{number:x}"),
                block_hash: format!("{hash:#x}"),
                openings_root: format!("{:#x}", table.openings_root()),
                root_storage_slot: format!("{:#x}", ring_slot(number)),
                table_hash: format!("{:#x}", table.table_hash()),
                record_count: format!("0x{:x}", table.records().len()),
                records: records
                    .into_iter()
                    .map(|(i, r)| utxo_record_to_result(i, r))
                    .collect(),
                proof_nodes: nodes.into_iter().map(utxo_node_to_result).collect(),
            });
        }
        let proof = commitment_proof(&context.storage, &header, utxo_vault(), &roots).await?;
        bounded_response(json!({
            "format": "ethrex-authenticated-upt-v1",
            "referenceHeader": format!("0x{}", hex::encode(header.encode_to_vec())),
            "vaultProof": proof, "blocks": blocks
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TEST_GENESIS, default_context_with_storage};
    use ethrex_common::{
        Bytes,
        types::{
            Genesis, GenesisAccount, Log, Receipt, TxType, UTXO_CREATED_TOPIC, eip8304::IndexEntry,
        },
    };
    use ethrex_storage::EngineType;

    fn query_params() -> Value {
        json!({"referenceBlockHash": format!("{:#x}", H256::zero()),
            "tables": [{"firstBlock": 0, "tableSize": 1}],
            "queries": [{"typeId": 2, "content": format!("{:#x}", utxo_vault())}]})
    }

    #[test]
    fn validates_batch_bounds_and_reference_window() {
        let mut value = query_params();
        assert!(QueryTablesRequest::parse(&Some(vec![value.clone()])).is_ok());
        value["tables"] = json!([{"firstBlock": 1, "tableSize": 4}]);
        assert!(QueryTablesRequest::parse(&Some(vec![value.clone()])).is_err());
        value["tables"] =
            json!([{"firstBlock": 0, "tableSize": 4}, {"firstBlock": 1, "tableSize": 1}]);
        assert!(QueryTablesRequest::parse(&Some(vec![value.clone()])).is_err());
        value["tables"] = json!([{"firstBlock": u64::MAX, "tableSize": 1}]);
        assert!(QueryTablesRequest::parse(&Some(vec![value.clone()])).is_err());
        value = query_params();
        value["referenceBlockHash"] = json!("latest");
        assert!(QueryTablesRequest::parse(&Some(vec![value])).is_err());
        assert!(ensure_recent(8192, 0).is_err());
        assert!(ensure_recent(8191, 0).is_ok());
        assert!(ensure_recent(10, 11).is_err());
        assert_eq!(commitment_block(0, 256).unwrap(), 319);
        assert_eq!(commitment_block(4, 1).unwrap(), 4);
        assert!(
            AuthenticatedUtxoRequest::parse(&Some(vec![json!({
                "referenceBlockHash": format!("{:#x}", H256::zero()), "positions": []
            })]))
            .is_err()
        );
    }

    // Real storage trie proofs and RPC wire output are shared with the Node
    // verifier tests. Synthetic genesis commitments make the fixture stable.
    #[tokio::test]
    async fn authenticated_rpc_fixture_and_root_mismatch() {
        let source = Address::from_low_u64_be(0x24);
        let recipient = Address::from_low_u64_be(0x42);
        let topic =
            |address: Address| H256::from_slice(&[&[0u8; 12][..], address.as_bytes()].concat());
        let mut logs = Vec::new();
        for index in 0..4 {
            logs.push(Log {
                address: if index < 2 {
                    utxo_vault()
                } else {
                    Address::repeat_byte(0xff)
                },
                topics: vec![
                    if index == 1 {
                        H256::repeat_byte(0xee)
                    } else {
                        UTXO_CREATED_TOPIC
                    },
                    topic(source),
                    topic(if index == 3 { source } else { recipient }),
                    H256::from_low_u64_be(7 + index),
                ],
                data: Bytes::copy_from_slice(&U256::from(99).to_big_endian()),
            });
        }
        let receipts = vec![Receipt::new(TxType::Legacy, true, 0, logs.clone())];
        let mut entries = vec![IndexEntry::Transaction {
            transaction_hash: H256::repeat_byte(0x22),
            block_number: 0,
            transaction_index: 0,
            cumulative_log_count: 4,
        }];
        for (index, log) in logs.iter().enumerate() {
            let log_index = index as u32;
            entries.push(IndexEntry::LogAddress {
                address: log.address,
                block_number: 0,
                transaction_index: 0,
                log_index,
            });
            entries.push(IndexEntry::LogTopic0 {
                topic: log.topics[0],
                block_number: 0,
                transaction_index: 0,
                log_index,
            });
            entries.push(IndexEntry::LogTopic1 {
                topic: log.topics[1],
                block_number: 0,
                transaction_index: 0,
                log_index,
            });
            entries.push(IndexEntry::LogTopic2 {
                topic: log.topics[2],
                block_number: 0,
                transaction_index: 0,
                log_index,
            });
            entries.push(IndexEntry::LogTopic3 {
                topic: log.topics[3],
                block_number: 0,
                transaction_index: 0,
                log_index,
            });
        }
        let table = IndexTable::new(0, 1, entries).unwrap();
        let mut genesis: Genesis = serde_json::from_str(TEST_GENESIS).unwrap();
        let chain_id = genesis.config.chain_id;
        let upt = UtxoProofTable::from_receipts(chain_id, 0, H256::zero(), &receipts).unwrap();
        for (address, slot, root) in [
            (
                INDEX_CONTRACT_ADDRESS.unwrap(),
                H256::from_low_u64_be(1024),
                table.table_root(),
            ),
            (utxo_vault(), H256::from_low_u64_be(1), upt.openings_root()),
        ] {
            genesis.alloc.insert(
                address,
                GenesisAccount {
                    code: Default::default(),
                    nonce: 1,
                    balance: U256::zero(),
                    storage: [(slot.into_uint(), root.into_uint())].into_iter().collect(),
                },
            );
        }
        let mut store = Store::new("", EngineType::InMemory).unwrap();
        store.add_initial_state(genesis).await.unwrap();
        let header = store.get_block_header(0).unwrap().unwrap();
        let reference = header.hash();
        store.store_index_table(reference, &table).unwrap();
        store
            .store_utxo_proof_table(
                &UtxoProofTable::from_receipts(chain_id, 0, reference, &receipts).unwrap(),
            )
            .unwrap();
        let context = default_context_with_storage(store.clone()).await;
        let mut request = query_params();
        request["referenceBlockHash"] = json!(format!("{reference:#x}"));
        request["queries"] = json!([
            {"typeId": 2, "content": format!("{:#x}", utxo_vault())},
            {"typeId": 3, "content": format!("{UTXO_CREATED_TOPIC:#x}")},
            {"typeId": 5, "content": format!("{:#x}", topic(recipient))}
        ]);
        let parsed = QueryTablesRequest::parse(&Some(vec![request.clone()])).unwrap();
        let tli = parsed.handle(context.clone()).await.unwrap();
        assert_eq!(tli["tables"][0]["seedQuery"], 0);
        assert_eq!(tli["tables"][0]["candidates"].as_array().unwrap().len(), 2);
        assert_eq!(tli["tables"][0]["matches"].as_array().unwrap().len(), 1);
        assert_eq!(
            tli["tables"][0]["candidates"][1]["checks"][0]["present"],
            false
        );
        let upt_request = json!({"referenceBlockHash": format!("{reference:#x}"),
            "positions": [{"blockNumber": 0, "transactionIndex": 0, "logIndex": 0}]});
        let upt = AuthenticatedUtxoRequest::parse(&Some(vec![upt_request.clone()]))
            .unwrap()
            .handle(context.clone())
            .await
            .unwrap();
        let fixture = json!({"request": request, "uptRequest": upt_request, "tli": tli, "upt": upt,
            "wallet": {"address": format!("{recipient:#x}"), "referenceBlockHash": format!("{reference:#x}"), "referenceBlockNumber": 0,
                "chainId": format!("0x{chain_id:x}"), "fromBlock": 0, "toBlock": 0}});
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../scripts/hegota-devnet/utxo-wallet/test/authenticated-fixture.json");
        if std::env::var_os("ETHREX_UPDATE_AUTH_FIXTURE").is_some() {
            std::fs::write(
                &path,
                serde_json::to_string_pretty(&fixture).unwrap() + "\n",
            )
            .unwrap();
        }
        let expected: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(
            fixture, expected,
            "Rust RPC wire format changed; update the shared fixture intentionally"
        );
        // A same-height side branch must not resolve to the canonical table.
        let mut sibling = header.clone();
        sibling.extra_data = Bytes::from_static(b"side branch");
        let _ = sibling.hash.take();
        let sibling_hash = sibling.hash();
        assert_ne!(sibling_hash, reference);
        store.add_block_header(sibling_hash, sibling).await.unwrap();
        store
            .store_index_table(sibling_hash, &IndexTable::new(0, 1, vec![]).unwrap())
            .unwrap();
        let mut sibling_request = fixture["request"].clone();
        sibling_request["referenceBlockHash"] = json!(format!("{sibling_hash:#x}"));
        assert!(
            QueryTablesRequest::parse(&Some(vec![sibling_request]))
                .unwrap()
                .handle(context.clone())
                .await
                .is_err()
        );
        assert!(parsed.handle(context.clone()).await.is_ok());
        // Local cached tables are not trusted over the reference state.
        store
            .store_index_table(reference, &IndexTable::new(0, 1, vec![]).unwrap())
            .unwrap();
        assert!(parsed.handle(context).await.is_err());
        assert!(selective_table(&table, &parsed.queries, &mut 0).is_err());
        let empty = IndexTable::new(0, 1, vec![]).unwrap();
        let proof = selective_table(&empty, &parsed.queries, &mut 10).unwrap();
        assert!(proof["matches"].as_array().unwrap().is_empty());
    }
}
