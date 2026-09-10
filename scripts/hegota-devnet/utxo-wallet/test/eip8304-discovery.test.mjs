import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import http from 'node:http';
import test from 'node:test';

const VAULT = '0x0000000000000000000000000000000000008312';
const INDEX = '0x0000000000000000000000000000000000008304';
const TOPIC = '0x3b19241465a47bc187f1d9c7db70834855a907183742a4b63aa824c576296f5e';
const RECIPIENT = '0x0000000000000000000000000000000000000042';
const SOURCE = '0x0000000000000000000000000000000000000024';
const TX_HASH = `0x${'22'.repeat(32)}`;
const BLOCK_HASH = `0x${'33'.repeat(32)}`;
const VALUE = 20_000_000_000_000_000n;
const padded = (address) => `0x${address.slice(2).padStart(64, '0')}`;
const quantity = (value, bytes) => BigInt(value).toString(16).padStart(bytes * 2, '0');
const sha256 = (value) => createHash('sha256').update(value).digest();

const log = {
  address: VAULT,
  topics: [TOPIC, padded(SOURCE), padded(RECIPIENT), `0x${quantity(7, 32)}`],
  data: `0x${quantity(VALUE, 32)}`,
  blockNumber: '0x5',
  blockHash: BLOCK_HASH,
  transactionHash: TX_HASH,
  transactionIndex: '0x0',
  logIndex: '0x0',
};

function proofTable() {
  const definitions = [
    { entryType: 'transaction', typeId: 1, content: TX_HASH, positionIndex: '0x0' },
    { entryType: 'log.address', typeId: 2, content: VAULT, positionIndex: '0x0' },
    { entryType: 'log.topics[0]', typeId: 3, content: TOPIC, positionIndex: '0x0' },
    { entryType: 'log.topics[1]', typeId: 4, content: padded(SOURCE), positionIndex: '0x0' },
    { entryType: 'log.topics[2]', typeId: 5, content: padded(RECIPIENT), positionIndex: '0x0' },
    { entryType: 'log.topics[3]', typeId: 6, content: `0x${quantity(7, 32)}`, positionIndex: '0x0' },
  ];
  const entries = definitions.map((definition) => ({
    ...definition,
    blockNumber: '0x5',
    transactionIndex: '0x0',
    encoded: `0x${quantity(definition.typeId, 2)}${definition.content.slice(2)}${quantity(5, 8)}${quantity(0, 4)}${quantity(definition.positionIndex, 4)}`,
  }));
  const leafLayer = entries.map((entry) => sha256(Buffer.from(entry.encoded.slice(2), 'hex')));
  let width = 1;
  while (width < leafLayer.length) width *= 2;
  while (leafLayer.length < width) leafLayer.push(Buffer.alloc(32));
  const layers = [leafLayer];
  while (layers.at(-1).length > 1) {
    const previous = layers.at(-1);
    layers.push(Array.from({ length: previous.length / 2 }, (_, index) => sha256(Buffer.concat([
      previous[index * 2], previous[index * 2 + 1],
    ]))));
  }
  const length = Buffer.alloc(32);
  length.writeBigUInt64LE(BigInt(entries.length));
  const root = `0x${sha256(Buffer.concat([layers.at(-1)[0], length])).toString('hex')}`;
  const proven = (index) => ({ ...entries[index], leafIndex: `0x${index.toString(16)}` });
  return {
    firstBlock: '0x5', endBlock: '0x5', endBlockHash: BLOCK_HASH,
    tableSize: '0x1', level: 0, commitmentBlock: '0x5', storageSlot: '0x405',
    entryCount: '0x6', tableRoot: root, loadMicros: 12, queryMicros: 4,
    queries: [{
      typeId: 5,
      content: padded(RECIPIENT),
      firstIndex: '0x4',
      endIndexExclusive: '0x5',
      entries: [proven(4)],
      lowerBoundary: proven(3),
      upperBoundary: proven(5),
    }],
    transactions: [proven(0)],
    candidateEntries: [proven(1), proven(2), proven(3), proven(5)],
    proofFormat: 'shared-per-table-v1',
    // Leaves 0..5 are returned. Only the padded 6..7 subtree is needed.
    proofNodes: [{ level: 1, nodeIndex: '0x3', hash: `0x${layers[1][3].toString('hex')}` }],
  };
}

test('receipt logs and EIP-8304 plus batched UPT proofs discover the same UTXO', async (context) => {
  const calls = new Map();
  let queriedTable = proofTable();
  let uptBlock;
  const rpc = http.createServer((request, response) => {
    let raw = '';
    request.on('data', (chunk) => { raw += chunk; });
    request.on('end', () => {
      const call = JSON.parse(raw);
      calls.set(call.method, (calls.get(call.method) || 0) + 1);
      let result;
      switch (call.method) {
        case 'eth_blockNumber': result = '0x6'; break;
        case 'eth_chainId': result = '0x7a69'; break;
        case 'eth_getLogs': result = [log]; break;
        case 'eth_getBlockByNumber': result = { number: call.params[0], hash: BLOCK_HASH }; break;
        case 'ethrex_queryEip8304Table': result = queriedTable; break;
        case 'ethrex_getUtxoProofs': result = { blocks: [uptBlock] }; break;
        case 'eth_getProof': result = { storageProof: [{ key: '0x6', value: uptBlock.openingsRoot }] }; break;
        case 'eth_gasPrice': result = '0x3b9aca00'; break;
        case 'eth_getStorageAt': result = call.params[0].toLowerCase() === INDEX ? queriedTable.tableRoot : `0x${'00'.repeat(32)}`; break;
        default: throw new Error(`unexpected method ${call.method}`);
      }
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ jsonrpc: '2.0', id: call.id, result }));
    });
  });
  await new Promise((resolve) => rpc.listen(0, '127.0.0.1', resolve));
  context.after(() => new Promise((resolve) => rpc.close(resolve)));
  const address = rpc.address();
  process.env.UTXO_RPC = `http://127.0.0.1:${address.port}`;

  const {
    benchmarkDiscovery, clearDiscoveryCaches, compareDiscovery, keccak256, openingLeafFromRecord,
  } = await import('../server.mjs');
  assert.equal(keccak256(Buffer.alloc(0)).toString('hex'), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
  assert.equal(keccak256(Buffer.from('abc')).toString('hex'), '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45');
  const record = {
    position: '0x0',
    index: '0x7',
    source: SOURCE,
    recipient: RECIPIENT,
    value: `0x${VALUE.toString(16)}`,
    transactionIndex: '0x0',
    transactionLogIndex: '0x0',
  };
  const openingsRoot = `0x${openingLeafFromRecord(record).toString('hex')}`;
  uptBlock = {
    formatVersion: 2,
    chainId: '0x7a69',
    vault: VAULT,
    blockNumber: '0x5',
    blockHash: BLOCK_HASH,
    openingsRoot,
    rootStorageSlot: '0x6',
    tableHash: `0x${'44'.repeat(32)}`,
    recordCount: '0x1',
    records: [record],
    proofNodes: [],
  };

  const result = await compareDiscovery({ address: RECIPIENT, fromBlock: 5, toBlock: 5, enrich: false });
  assert.equal(result.sameResults, true);
  assert.equal(result.receiptLogs.utxos.length, 1);
  assert.equal(result.eip8304Tables.utxos.length, 1);
  assert.equal(result.receiptLogs.utxos[0].index, 7);
  assert.equal(result.receiptLogs.utxos[0].valueWei, VALUE.toString());
  assert.equal(result.eip8304Tables.complete, true);
  assert.equal(result.eip8304Tables.metrics.rootChecks, 2);
  assert.equal(result.eip8304Tables.metrics.receiptsFetched, 0);
  assert.equal(result.eip8304Tables.metrics.uptRecordsReturned, 1);
  assert.equal(result.eip8304Tables.metrics.uptRpcCalls, 1);
  assert.equal(result.eip8304Tables.metrics.proofsVerified, 6);
  assert.equal(result.eip8304Tables.metrics.fullTableEntries, 6);
  assert.equal(result.receiptLogs.metrics.walletRpcCalls, 1);
  assert.equal(result.eip8304Tables.metrics.walletRpcCalls, 4);
  assert.equal(result.receiptLogResultHash, result.eip8304ResultHash);
  assert.equal(calls.get('eth_getBlockReceipts'), undefined);
  assert.equal(calls.get('ethrex_getEip8304Logs'), undefined);

  const warm = await compareDiscovery({ address: RECIPIENT, fromBlock: 5, toBlock: 5, enrich: false, order: 'tablesFirst' });
  assert.equal(warm.sameResults, true);
  assert.equal(warm.eip8304Tables.metrics.queryCacheHits, 1);
  assert.equal(warm.eip8304Tables.metrics.rootCacheHits, 1);
  assert.equal(warm.eip8304Tables.metrics.uptCacheHits, 1);
  assert.equal(warm.eip8304Tables.metrics.cacheValidationRpcCalls, 1);
  assert.equal(warm.eip8304Tables.metrics.rpcCalls, 1);
  assert.equal(calls.get('ethrex_queryEip8304Table'), 1);
  assert.equal(calls.get('ethrex_getUtxoProofs'), 1);
  assert.equal(calls.get('eth_getProof'), 1);

  const measured = await benchmarkDiscovery({
    address: RECIPIENT, fromBlock: 5, toBlock: 5, enrich: false, warmups: 0, repetitions: 3,
  });
  assert.equal(measured.samples.length, 3);
  assert.equal(measured.statistics.receiptLogs.discoveryMs.maximum >= measured.statistics.receiptLogs.discoveryMs.median, true);
  assert.equal(measured.statistics.eip8304Tables.discoveryMs.p95 >= measured.statistics.eip8304Tables.discoveryMs.median, true);

  clearDiscoveryCaches();
  uptBlock.records[0].value = `0x${(VALUE + 1n).toString(16)}`;
  await assert.rejects(
    compareDiscovery({ address: RECIPIENT, fromBlock: 5, toBlock: 5, enrich: false }),
    /invalid UPT opening multiproof/,
  );
  uptBlock.records[0].value = `0x${VALUE.toString(16)}`;

  queriedTable = proofTable();
  queriedTable.queries[0].entries[0].blockNumber = '0x6';
  clearDiscoveryCaches();
  await assert.rejects(
    compareDiscovery({ address: RECIPIENT, fromBlock: 5, toBlock: 5, enrich: false }),
    /decoded EIP-8304 entry fields do not match proven leaf/,
  );
});
