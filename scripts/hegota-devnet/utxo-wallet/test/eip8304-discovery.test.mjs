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
const padded = (address) => `0x${address.slice(2).padStart(64, '0')}`;
const word = (value) => BigInt(value).toString(16).padStart(64, '0');
const quantity = (value, bytes) => BigInt(value).toString(16).padStart(bytes * 2, '0');
const hash = (value) => createHash('sha256').update(value).digest();
const logCommitment = (value) => {
  const data = Buffer.from(value.data.slice(2), 'hex');
  const dataLength = Buffer.alloc(8);
  dataLength.writeBigUInt64BE(BigInt(data.length));
  return `0x${hash(Buffer.concat([
    Buffer.from('EIP8304_LOG_V1'),
    Buffer.from(value.address.slice(2), 'hex'),
    Buffer.from([value.topics.length]),
    ...value.topics.map((topic) => Buffer.from(topic.slice(2), 'hex')),
    dataLength,
    data,
  ])).toString('hex')}`;
};

const log = {
  address: VAULT,
  topics: [TOPIC, padded(SOURCE), padded(RECIPIENT)],
  data: `0x${word(7)}${word(20_000_000_000_000_000n)}`,
  blockNumber: '0x5',
  blockHash: BLOCK_HASH,
  transactionHash: TX_HASH,
  transactionIndex: '0x0',
  logIndex: '0x0',
};

function proofTable() {
  const definitions = [
    { entryType: 'transaction', typeId: 1, content: TX_HASH, positionIndex: '0x1' },
    { entryType: 'log.address', typeId: 2, content: VAULT, positionIndex: '0x0' },
    { entryType: 'log.topics[0]', typeId: 3, content: TOPIC, positionIndex: '0x0' },
    { entryType: 'log.topics[2]', typeId: 5, content: padded(RECIPIENT), positionIndex: '0x0' },
    { entryType: 'log.commitment', typeId: 7, content: logCommitment(log), positionIndex: '0x0' },
  ];
  const entries = definitions.map((definition) => ({
    ...definition,
    blockNumber: '0x5',
    transactionIndex: '0x0',
    encoded: `0x${quantity(definition.typeId, 2)}${definition.content.slice(2)}${quantity(5, 8)}${quantity(0, 4)}${quantity(definition.positionIndex, 4)}`,
  }));
  const leafLayer = entries.map((entry) => hash(Buffer.from(entry.encoded.slice(2), 'hex')));
  let width = 1;
  while (width < leafLayer.length) width *= 2;
  while (leafLayer.length < width) leafLayer.push(Buffer.alloc(32));
  const layers = [leafLayer];
  while (layers.at(-1).length > 1) {
    const previous = layers.at(-1);
    layers.push(Array.from({ length: previous.length / 2 }, (_, index) => hash(Buffer.concat([
      previous[index * 2], previous[index * 2 + 1],
    ]))));
  }
  const length = Buffer.alloc(32);
  length.writeBigUInt64LE(BigInt(entries.length));
  const root = `0x${hash(Buffer.concat([layers.at(-1)[0], length])).toString('hex')}`;
  const proven = (index) => ({ ...entries[index], leafIndex: `0x${index.toString(16)}` });
  const range = (index) => ({
    typeId: entries[index].typeId,
    content: entries[index].content,
    firstIndex: `0x${index.toString(16)}`,
    endIndexExclusive: `0x${(index + 1).toString(16)}`,
    entries: [proven(index)],
    lowerBoundary: index > 0 ? proven(index - 1) : null,
    upperBoundary: index + 1 < entries.length ? proven(index + 1) : null,
  });
  return {
    firstBlock: '0x5', endBlock: '0x5', endBlockHash: BLOCK_HASH,
    tableSize: '0x1', level: 0, commitmentBlock: '0x5', storageSlot: '0x405',
    entryCount: '0x5', tableRoot: root, loadMicros: 12, queryMicros: 4,
    queries: [range(1), range(2), range(3)],
    transactions: [proven(0)],
    logCommitments: [proven(4)],
    proofNodes: layers.slice(0, -1).flatMap((layer, level) => layer.map((node, nodeIndex) => ({
      level, nodeIndex: `0x${nodeIndex.toString(16)}`, hash: `0x${node.toString('hex')}`,
    }))),
  };
}

test('receipt logs and proof-carrying EIP-8304 queries discover the same UTXO', async (context) => {
  const queriedTable = proofTable();
  const selectedLog = { ...log, logRoot: logCommitment(log) };
  const calls = new Map();
  const rpc = http.createServer((request, response) => {
    let raw = '';
    request.on('data', (chunk) => { raw += chunk; });
    request.on('end', () => {
      const call = JSON.parse(raw);
      calls.set(call.method, (calls.get(call.method) || 0) + 1);
      let result;
      switch (call.method) {
        case 'eth_blockNumber': result = '0x6'; break;
        case 'eth_getLogs': result = [log]; break;
        case 'ethrex_queryEip8304Table': result = queriedTable; break;
        case 'ethrex_getEip8304Logs': result = [selectedLog]; break;
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

  const { benchmarkDiscovery, clearDiscoveryCaches, compareDiscovery } = await import('../server.mjs');
  const result = await compareDiscovery({ address: RECIPIENT, fromBlock: 5, toBlock: 5, enrich: false });

  assert.equal(result.sameResults, true);
  assert.equal(result.receiptLogs.utxos.length, 1);
  assert.equal(result.eip8304Tables.utxos.length, 1);
  assert.equal(result.receiptLogs.utxos[0].index, 7);
  assert.equal(result.receiptLogs.utxos[0].valueWei, '20000000000000000');
  assert.equal(result.eip8304Tables.complete, true);
  assert.equal(result.eip8304Tables.metrics.rootChecks, 1);
  assert.equal(result.eip8304Tables.metrics.receiptsFetched, 0);
  assert.equal(result.eip8304Tables.metrics.selectedLogsReturned, 1);
  assert.equal(result.eip8304Tables.metrics.logPayloadRpcCalls, 1);
  assert.equal(result.eip8304Tables.metrics.proofsVerified, 11);
  assert.equal(result.eip8304Tables.metrics.fullTableEntries, 5);
  assert.equal(result.receiptLogs.metrics.walletRpcCalls, 1);
  assert.equal(result.eip8304Tables.metrics.walletRpcCalls, 3);
  assert.equal(result.receiptLogs.metrics.spentCheckMs, 0);
  assert.equal(result.eip8304Tables.metrics.metadataMs, 0);
  assert.match(result.receiptLogResultHash, /^0x[0-9a-f]{64}$/);
  assert.equal(result.receiptLogResultHash, result.eip8304ResultHash);
  assert.equal(calls.get('eth_getBlockReceipts'), undefined);

  const warm = await compareDiscovery({ address: RECIPIENT, fromBlock: 5, toBlock: 5, enrich: false, order: 'tablesFirst' });
  assert.equal(warm.sameResults, true);
  assert.equal(warm.eip8304Tables.metrics.queryCacheHits, 1);
  assert.equal(warm.eip8304Tables.metrics.rootCacheHits, 1);
  assert.equal(warm.eip8304Tables.metrics.rpcCalls, 1);
  assert.equal(calls.get('ethrex_queryEip8304Table'), 1);
  assert.equal(calls.get('eth_getStorageAt'), 1);
  assert.equal(calls.get('ethrex_getEip8304Logs'), 2);
  assert.equal(calls.get('eth_getTransactionReceipt'), undefined);

  const measured = await benchmarkDiscovery({
    address: RECIPIENT, fromBlock: 5, toBlock: 5, enrich: false, warmups: 0, repetitions: 3,
  });
  assert.equal(measured.samples.length, 3);
  assert.equal(measured.statistics.receiptLogs.discoveryMs.maximum >= measured.statistics.receiptLogs.discoveryMs.median, true);
  assert.equal(measured.statistics.eip8304Tables.discoveryMs.p95 >= measured.statistics.eip8304Tables.discoveryMs.median, true);

  selectedLog.data = `0x${word(7)}${word(30_000_000_000_000_000n)}`;
  await assert.rejects(
    compareDiscovery({ address: RECIPIENT, fromBlock: 5, toBlock: 5, enrich: false }),
    /selected EIP-8304 log does not match its proven commitment/,
  );
  selectedLog.data = log.data;

  queriedTable.queries[2].entries[0].blockNumber = '0x6';
  clearDiscoveryCaches();
  await assert.rejects(
    compareDiscovery({ address: RECIPIENT, fromBlock: 5, toBlock: 5, enrich: false }),
    /decoded EIP-8304 entry fields do not match proven leaf/,
  );
});
