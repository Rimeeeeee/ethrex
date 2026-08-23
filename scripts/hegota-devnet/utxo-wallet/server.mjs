#!/usr/bin/env node
// Standalone EIP-8312 UTXO wallet. No npm dependencies.
// The browser is watch-only by default. Sending is enabled only when the
// operator explicitly imports a key into this local process or supplies
// UTXO_WALLET_KEY at startup.

import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { extname, join, normalize, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(fileURLToPath(import.meta.url));
const PUBLIC = join(ROOT, 'public');
const DEFAULT_RPC = 'https://rpc1.hegota.ethrex.xyz';
let rpcUrl = process.env.UTXO_RPC || DEFAULT_RPC;
const VAULT = '0x0000000000000000000000000000000000008312';
const INDEX = '0x0000000000000000000000000000000000008304';
const TOPIC = '0x3b19241465a47bc187f1d9c7db70834855a907183742a4b63aa824c576296f5e';
let walletKey = process.env.UTXO_WALLET_KEY || null;
const TXFORGE = process.env.UTXO_TXFORGE || join(ROOT, '..', 'utxo-demo', 'devnet', 'txforge.py');
const DEFAULT_PYTHON = join(ROOT, '..', 'utxo-demo', '.venv', 'bin', 'python');
const USE_WSL = process.platform === 'win32' && !process.env.UTXO_PYTHON;
const PYTHON = process.env.UTXO_PYTHON || (USE_WSL ? 'wsl.exe' : DEFAULT_PYTHON);
const PORT = Number(process.env.PORT || 8090);
const HOST = process.env.UTXO_HOST || '127.0.0.1';
const API_TOKEN = process.env.UTXO_API_TOKEN || null;

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const UINT_RE = /^(0|[1-9][0-9]*)$/;
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

function isAddress(value) { return typeof value === 'string' && ADDRESS_RE.test(value); }

function blockNumber(value, name) {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value === 'string' && /^(0x[0-9a-f]+|[0-9]+)$/i.test(value)) {
    const n = Number(value);
    if (Number.isSafeInteger(n) && n >= 0) return n;
  }
  throw new Error(`${name} must be a non-negative block number`);
}

function positiveWei(value, name = 'valueWei') {
  if (typeof value !== 'string' || !UINT_RE.test(value) || BigInt(value) <= 0n) throw new Error(`${name} must be a positive integer string`);
  return BigInt(value);
}

function wslPath(value) {
  const match = value.match(/^([A-Za-z]):[\\/](.*)$/);
  return match ? `/mnt/${match[1].toLowerCase()}/${match[2].replaceAll('\\', '/')}` : value.replaceAll('\\', '/');
}

async function rpcMeasured(method, params) {
  const started = performance.now();
  const response = await fetch(rpcUrl, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: Date.now(), method, params }),
  });
  const text = await response.text();
  const body = JSON.parse(text);
  if (body.error) throw new Error(`${method}: ${body.error.message || JSON.stringify(body.error)}`);
  return {
    result: body.result,
    elapsedMs: Number((performance.now() - started).toFixed(3)),
    responseBytes: Buffer.byteLength(text),
  };
}

async function rpc(method, params) {
  return (await rpcMeasured(method, params)).result;
}

function forge(command) {
  return new Promise((resolveForge, rejectForge) => {
    const forgeArgs = USE_WSL ? [wslPath(DEFAULT_PYTHON), wslPath(TXFORGE)] : [TXFORGE];
    const child = spawn(PYTHON, forgeArgs, { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', (error) => rejectForge(new Error(`could not start txforge: ${error.message}`)));
    child.on('close', (code) => {
      try {
        const result = JSON.parse(stdout);
        if (result.error) return rejectForge(new Error(result.error));
        if (code !== 0) return rejectForge(new Error(stderr || `txforge exited with code ${code}`));
        resolveForge(result);
      } catch { rejectForge(new Error(`txforge returned invalid JSON: ${stderr || stdout}`)); }
    });
    child.stdin.end(JSON.stringify({ rpc: rpcUrl, ...command }));
  });
}

function openingFromLog(log) {
  if (!log?.data || log.data.length < 130 || !log.topics || log.topics.length < 3) return null;
  const data = log.data.slice(2);
  const word = (offset) => BigInt(`0x${data.slice(offset, offset + 64)}`);
  const topicAddress = (topic) => `0x${topic.slice(-40)}`.toLowerCase();
  return {
    index: Number(word(0)),
    valueWei: word(64).toString(),
    source: topicAddress(log.topics[1]),
    recipient: topicAddress(log.topics[2]),
    creationBlock: Number.parseInt(log.blockNumber, 16),
    txHash: log.transactionHash,
    blockHash: log.blockHash,
    logIndex: Number.parseInt(log.logIndex || '0x0', 16),
  };
}

async function spent(index) {
  const slot = (1n << 129n) + BigInt(Math.floor(index / 256));
  const word = BigInt(await rpc('eth_getStorageAt', [VAULT, `0x${slot.toString(16)}`, 'latest']));
  return (word & (1n << BigInt(index & 255))) !== 0n;
}

async function maxSelfFundedFee() {
  const gasPrice = BigInt(await rpc('eth_gasPrice', []));
  const maxFeePerGas = gasPrice * 2n > 2_000_000_000n ? gasPrice * 2n : 2_000_000_000n;
  // txforge signs max_gas_limit=400,000 for spend frames. This is a
  // conservative reserve used only to prevent an underfunded self-funded
  // conversion; settlement refunds unused gas.
  return maxFeePerGas * 400_000n;
}

async function enrichDiscoveredUtxos(utxos, head) {
  const spentStarted = performance.now();
  const limit = createLimiter(discoveryConcurrency());
  const spentValues = await Promise.all(utxos.map((item) => limit(() => spent(item.index))));
  for (let index = 0; index < utxos.length; index += 1) {
    const item = utxos[index];
    item.spent = spentValues[index];
    item.spendable = item.creationBlock < head && !item.spent;
  }
  const spentCheckMs = Number((performance.now() - spentStarted).toFixed(3));
  const metadataStarted = performance.now();
  const feeReserve = await maxSelfFundedFee();
  for (const item of utxos) {
    item.selfFundedFeeReserveWei = feeReserve.toString();
    item.maxSelfFundedOutputWei = BigInt(item.valueWei) > feeReserve ? (BigInt(item.valueWei) - feeReserve).toString() : '0';
  }
  return {
    spentCheckMs,
    metadataMs: Number((performance.now() - metadataStarted).toFixed(3)),
  };
}

async function scanLogs({ address, fromBlock = 0, toBlock, enrich = true } = {}) {
  if (!isAddress(address)) throw new Error('address must be a 20-byte hex address');
  const head = Number.parseInt(await rpc('eth_blockNumber', []), 16);
  const from = blockNumber(fromBlock, 'fromBlock');
  const to = toBlock == null || toBlock === '' ? head : Math.min(blockNumber(toBlock, 'toBlock'), head);
  const utxos = [];
  const discoveryStarted = performance.now();
  let rpcCalls = 0;
  let responseBytes = 0;
  let providerRpcMs = 0;
  let chunks = 0;
  for (let start = from; start <= to; start += 2_000) {
    const end = Math.min(start + 1_999, to);
    const response = await rpcMeasured('eth_getLogs', [{
      address: VAULT,
      topics: [TOPIC, null, `0x${address.slice(2).padStart(64, '0')}`],
      fromBlock: `0x${start.toString(16)}`,
      toBlock: `0x${end.toString(16)}`,
    }]);
    rpcCalls += 1;
    chunks += 1;
    responseBytes += response.responseBytes;
    providerRpcMs += response.elapsedMs;
    for (const log of response.result) {
      const item = openingFromLog(log);
      if (!item || item.recipient !== address.toLowerCase()) continue;
      utxos.push(item);
    }
  }
  const discoveryMs = Number((performance.now() - discoveryStarted).toFixed(3));
  utxos.sort((a, b) => a.index - b.index);
  const enrichment = enrich
    ? await enrichDiscoveredUtxos(utxos, head)
    : { spentCheckMs: 0, metadataMs: 0 };
  const walletTotalMs = Number((discoveryMs + enrichment.spentCheckMs + enrichment.metadataMs).toFixed(3));
  return {
    method: 'receiptLogs', address: address.toLowerCase(), fromBlock: from, toBlock: to, head, utxos,
    metrics: {
      discoveryMs,
      providerRpcMs: Number(providerRpcMs.toFixed(3)),
      responseBytes,
      rpcCalls,
      chunks,
      logsReturned: utxos.length,
      walletTotalMs,
      walletRpcCalls: enrich ? rpcCalls + utxos.length + 1 : rpcCalls,
      ...enrichment,
    },
  };
}

function tablePosition(entry) {
  return `${BigInt(entry.blockNumber)}:${BigInt(entry.transactionIndex)}:${BigInt(entry.positionIndex)}`;
}

let tableQueryCache = new Map();
let tableRootCache = new Map();

function clearDiscoveryCaches() {
  tableQueryCache.clear();
  tableRootCache.clear();
}

function discoveryConcurrency(value) {
  const concurrency = Number(value ?? process.env.UTXO_DISCOVERY_CONCURRENCY ?? 8);
  if (!Number.isSafeInteger(concurrency) || concurrency < 1 || concurrency > 64) {
    throw new Error('concurrency must be an integer between 1 and 64');
  }
  return concurrency;
}

function createLimiter(concurrency) {
  let active = 0;
  const pending = [];
  const drain = () => {
    while (active < concurrency && pending.length) {
      const { task, resolveTask, rejectTask } = pending.shift();
      active += 1;
      Promise.resolve()
        .then(task)
        .then(resolveTask, rejectTask)
        .finally(() => { active -= 1; drain(); });
    }
  };
  return (task) => new Promise((resolveTask, rejectTask) => {
    pending.push({ task, resolveTask, rejectTask });
    drain();
  });
}

async function cachedLoad(cache, key, enabled, loader) {
  if (!enabled) return { value: await loader(), hit: false };
  if (cache.has(key)) return { value: await cache.get(key), hit: true };
  const loading = loader();
  cache.set(key, loading);
  try {
    return { value: await loading, hit: false };
  } catch (error) {
    cache.delete(key);
    throw error;
  }
}

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

const LOG_COMMITMENT_DOMAIN = Buffer.from('EIP8304_LOG_V1');

function logCommitment(log) {
  const address = hexBuffer(log.address, 'log address');
  if (address.length !== 20) throw new Error('log address must contain 20 bytes');
  if (!Array.isArray(log.topics) || log.topics.length > 4) throw new Error('log topics must contain at most four items');
  const topics = log.topics.map((topic) => {
    const encoded = hexBuffer(topic, 'log topic');
    if (encoded.length !== 32) throw new Error('log topic must contain 32 bytes');
    return encoded;
  });
  const data = hexBuffer(log.data, 'log data');
  const dataLength = Buffer.alloc(8);
  dataLength.writeBigUInt64BE(BigInt(data.length));
  return `0x${sha256(Buffer.concat([
    LOG_COMMITMENT_DOMAIN,
    address,
    Buffer.from([topics.length]),
    ...topics,
    dataLength,
    data,
  ])).toString('hex')}`;
}

function hexBuffer(value, name) {
  if (typeof value !== 'string' || !/^0x(?:[0-9a-f]{2})*$/i.test(value)) throw new Error(`${name} is not canonical hex bytes`);
  return Buffer.from(value.slice(2), 'hex');
}

function mixedInRoot(node, entryCount) {
  const length = Buffer.alloc(32);
  length.writeBigUInt64LE(BigInt(entryCount));
  return sha256(Buffer.concat([node, length]));
}

function proofNodeMap(table) {
  return new Map(table.proofNodes.map((node) => [
    `${Number(node.level)}:${BigInt(node.nodeIndex)}`,
    hexBuffer(node.hash, 'proof node hash'),
  ]));
}

function decodeTableEntry(encodedValue) {
  const encoded = hexBuffer(encodedValue, 'encoded EIP-8304 entry');
  if (encoded.length < 2) throw new Error('truncated encoded EIP-8304 entry');
  const typeId = encoded.readUInt16BE(0);
  const shape = typeId === 0 && encoded.length === 42 ? { contentEnd: 34, positionOffset: 34, hasTransaction: false, hasPosition: false }
    : typeId === 1 && encoded.length === 50 ? { contentEnd: 34, positionOffset: 34, hasTransaction: true, hasPosition: true }
      : typeId === 2 && encoded.length === 38 ? { contentEnd: 22, positionOffset: 22, hasTransaction: true, hasPosition: true }
        : typeId >= 3 && typeId <= 7 && encoded.length === 50 ? { contentEnd: 34, positionOffset: 34, hasTransaction: true, hasPosition: true }
          : null;
  if (!shape) throw new Error(`malformed encoded EIP-8304 entry type ${typeId}`);
  return {
    typeId,
    content: `0x${encoded.subarray(2, shape.contentEnd).toString('hex')}`,
    blockNumber: encoded.readBigUInt64BE(shape.positionOffset),
    transactionIndex: shape.hasTransaction ? BigInt(encoded.readUInt32BE(shape.positionOffset + 8)) : null,
    positionIndex: shape.hasPosition ? BigInt(encoded.readUInt32BE(shape.positionOffset + 12)) : null,
  };
}

function verifyEntryProof(table, proven, proofNodes) {
  const entryCount = Number(BigInt(table.entryCount));
  const leafIndex = Number(BigInt(proven.leafIndex));
  if (!Number.isSafeInteger(leafIndex) || leafIndex < 0 || leafIndex >= entryCount) throw new Error(`invalid EIP-8304 proof leaf ${proven.leafIndex}`);
  let width = 1;
  while (width < entryCount) width *= 2;
  const decoded = decodeTableEntry(proven.encoded);
  const transactionIndex = proven.transactionIndex == null ? null : BigInt(proven.transactionIndex);
  const positionIndex = proven.positionIndex == null ? null : BigInt(proven.positionIndex);
  if (decoded.typeId !== proven.typeId || decoded.content !== proven.content.toLowerCase()
      || decoded.blockNumber !== BigInt(proven.blockNumber) || decoded.transactionIndex !== transactionIndex
      || decoded.positionIndex !== positionIndex) {
    throw new Error(`decoded EIP-8304 entry fields do not match proven leaf ${leafIndex}`);
  }
  let node = sha256(hexBuffer(proven.encoded, 'encoded EIP-8304 entry'));
  let nodeIndex = leafIndex;
  for (let level = 0; width > 1; level += 1, width /= 2) {
    const sibling = proofNodes.get(`${level}:${BigInt(nodeIndex ^ 1)}`);
    if (!sibling) throw new Error(`missing EIP-8304 proof node at level ${level} index ${nodeIndex ^ 1}`);
    node = nodeIndex % 2 === 0 ? sha256(Buffer.concat([node, sibling])) : sha256(Buffer.concat([sibling, node]));
    nodeIndex = Math.floor(nodeIndex / 2);
  }
  if (`0x${mixedInRoot(node, entryCount).toString('hex')}` !== table.tableRoot.toLowerCase()) {
    throw new Error(`invalid EIP-8304 entry proof at leaf ${leafIndex}`);
  }
  return leafIndex;
}

function verifyEmptyTableRoot(table) {
  const expected = `0x${mixedInRoot(Buffer.alloc(32), 0).toString('hex')}`;
  if (table.tableRoot.toLowerCase() !== expected) throw new Error('invalid empty EIP-8304 table root');
}

function verifyTableQuery(table, filters) {
  const started = performance.now();
  const entryCount = Number(BigInt(table.entryCount));
  if (!Number.isSafeInteger(entryCount) || entryCount < 0) throw new Error('invalid EIP-8304 entry count');
  if (entryCount === 0) verifyEmptyTableRoot(table);
  const proofNodes = proofNodeMap(table);
  const requested = new Map(filters.map((filter) => [`${filter.typeId}:${filter.content.toLowerCase()}`, filter]));
  const postings = new Map();
  let proofsVerified = 0;
  let entriesReturned = 0;

  if (!Array.isArray(table.queries) || table.queries.length !== filters.length) throw new Error('EIP-8304 query response omitted a requested posting range');
  for (const range of table.queries) {
    const key = `${range.typeId}:${range.content.toLowerCase()}`;
    const filter = requested.get(key);
    if (!filter || postings.has(key)) throw new Error(`unexpected or duplicate EIP-8304 posting range ${key}`);
    const prefix = Buffer.concat([
      Buffer.from([(range.typeId >>> 8) & 0xff, range.typeId & 0xff]),
      hexBuffer(range.content, 'query content'),
    ]);
    const first = Number(BigInt(range.firstIndex));
    const end = Number(BigInt(range.endIndexExclusive));
    if (!Number.isSafeInteger(first) || !Number.isSafeInteger(end) || first < 0 || end < first || end > entryCount) throw new Error(`invalid EIP-8304 posting bounds ${first}..${end}`);
    if (!Array.isArray(range.entries) || range.entries.length !== end - first) throw new Error(`incomplete EIP-8304 posting range ${key}`);
    const positions = new Map();
    for (let offset = 0; offset < range.entries.length; offset += 1) {
      const entry = range.entries[offset];
      const leafIndex = verifyEntryProof(table, entry, proofNodes);
      proofsVerified += 1;
      entriesReturned += 1;
      if (leafIndex !== first + offset || entry.typeId !== range.typeId || entry.content.toLowerCase() !== range.content.toLowerCase()) {
        throw new Error(`non-contiguous EIP-8304 posting range ${key}`);
      }
      const encoded = hexBuffer(entry.encoded, 'encoded EIP-8304 posting');
      if (!encoded.subarray(0, prefix.length).equals(prefix)) throw new Error(`EIP-8304 posting prefix mismatch ${key}`);
      positions.set(tablePosition(entry), entry);
    }
    if (first === 0) {
      if (range.lowerBoundary != null) throw new Error(`unexpected lower EIP-8304 boundary for ${key}`);
    } else {
      if (!range.lowerBoundary || verifyEntryProof(table, range.lowerBoundary, proofNodes) !== first - 1) throw new Error(`invalid lower EIP-8304 boundary for ${key}`);
      proofsVerified += 1;
      entriesReturned += 1;
      if (Buffer.compare(hexBuffer(range.lowerBoundary.encoded, 'lower boundary'), prefix) >= 0) throw new Error(`lower EIP-8304 boundary does not prove completeness for ${key}`);
    }
    if (end === entryCount) {
      if (range.upperBoundary != null) throw new Error(`unexpected upper EIP-8304 boundary for ${key}`);
    } else {
      if (!range.upperBoundary || verifyEntryProof(table, range.upperBoundary, proofNodes) !== end) throw new Error(`invalid upper EIP-8304 boundary for ${key}`);
      proofsVerified += 1;
      entriesReturned += 1;
      const upper = hexBuffer(range.upperBoundary.encoded, 'upper boundary');
      if (Buffer.compare(upper, prefix) < 0 || upper.subarray(0, prefix.length).equals(prefix)) throw new Error(`upper EIP-8304 boundary does not prove completeness for ${key}`);
    }
    postings.set(key, positions);
  }

  let matched = null;
  for (const filter of filters) {
    const positions = postings.get(`${filter.typeId}:${filter.content.toLowerCase()}`);
    matched = matched == null
      ? new Map(positions)
      : new Map([...matched].filter(([position]) => positions.has(position)));
  }
  matched ||= new Map();
  const transactionHashes = new Map();
  for (const transaction of table.transactions || []) {
    verifyEntryProof(table, transaction, proofNodes);
    proofsVerified += 1;
    entriesReturned += 1;
    if (transaction.typeId !== 1) throw new Error('EIP-8304 query returned a non-transaction as transaction evidence');
    const key = `${BigInt(transaction.blockNumber)}:${BigInt(transaction.transactionIndex)}`;
    if (transactionHashes.has(key)) throw new Error(`duplicate EIP-8304 transaction evidence for ${key}`);
    transactionHashes.set(key, transaction.content.toLowerCase());
  }
  for (const position of matched.values()) {
    const key = `${BigInt(position.blockNumber)}:${BigInt(position.transactionIndex)}`;
    if (!transactionHashes.has(key)) throw new Error(`missing EIP-8304 transaction evidence for ${key}`);
  }
  const expectedTransactions = new Set([...matched.values()].map((position) => `${BigInt(position.blockNumber)}:${BigInt(position.transactionIndex)}`));
  if (transactionHashes.size !== expectedTransactions.size || [...transactionHashes].some(([key]) => !expectedTransactions.has(key))) {
    throw new Error('EIP-8304 query returned transaction evidence outside the posting intersection');
  }
  const logCommitments = new Map();
  for (const commitment of table.logCommitments || []) {
    verifyEntryProof(table, commitment, proofNodes);
    proofsVerified += 1;
    entriesReturned += 1;
    if (commitment.typeId !== 7) throw new Error('EIP-8304 query returned a non-commitment as log evidence');
    const key = tablePosition(commitment);
    if (logCommitments.has(key)) throw new Error(`duplicate EIP-8304 log commitment for ${key}`);
    logCommitments.set(key, commitment.content.toLowerCase());
  }
  if (logCommitments.size !== matched.size || [...matched].some(([key]) => !logCommitments.has(key))) {
    throw new Error('EIP-8304 query did not return exactly one log commitment per matched position');
  }
  const proofBytes = (table.proofNodes?.length || 0) * 32;
  const uniqueEntriesReturned = new Set([
    ...table.queries.flatMap((range) => [range.lowerBoundary, ...range.entries, range.upperBoundary]),
    ...(table.transactions || []),
    ...(table.logCommitments || []),
  ].filter(Boolean).map((entry) => String(entry.leafIndex))).size;
  return {
    positions: matched,
    transactionHashes,
    logCommitments,
    proofsVerified,
    entriesReturned: uniqueEntriesReturned,
    serializedEntriesReturned: entriesReturned,
    proofBytes,
    proofVerificationMs: Number((performance.now() - started).toFixed(3)),
  };
}

async function requestTableQuery(firstBlock, tableSize, filters, useCache, limit) {
  const filterKey = filters.map((filter) => `${filter.typeId}:${filter.content.toLowerCase()}`).join('|');
  const queryKey = `${rpcUrl}|${firstBlock}|${tableSize}|${filterKey}`;
  const queryLoad = await cachedLoad(tableQueryCache, queryKey, useCache, async () => ({
    response: await limit(() => rpcMeasured('ethrex_queryEip8304Table', [
      `0x${firstBlock.toString(16)}`,
      `0x${tableSize.toString(16)}`,
      filters,
    ])),
    verified: null,
  }));
  const record = queryLoad.value;
  const table = record.response.result;
  if (!table) return { table: null, record, queryCacheHit: queryLoad.hit, rootResponse: null, rootCacheHit: false };

  const rootKey = `${rpcUrl}|${table.storageSlot}|${table.commitmentBlock}|${table.tableRoot.toLowerCase()}`;
  const rootLoad = await cachedLoad(tableRootCache, rootKey, useCache, () => limit(() => rpcMeasured('eth_getStorageAt', [
    INDEX,
    table.storageSlot,
    table.commitmentBlock,
  ])));
  if (rootLoad.value.result.toLowerCase() !== table.tableRoot.toLowerCase()) {
    tableQueryCache.delete(queryKey);
    tableRootCache.delete(rootKey);
    throw new Error(`EIP-8304 table root mismatch for ${firstBlock}/${tableSize}`);
  }
  if (!record.verified) record.verified = verifyTableQuery(table, filters);
  return {
    table,
    verified: record.verified,
    record,
    queryCacheHit: queryLoad.hit,
    rootResponse: rootLoad.value,
    rootCacheHit: rootLoad.hit,
  };
}

function initialTableRanges(from, to, head) {
  const ranges = [];
  let cursor = from;
  while (cursor <= to) {
    const tableSize = [256, 64, 16, 4, 1].find((size) => {
      const end = cursor + size - 1;
      const commitment = end + (size === 1 ? 0 : Math.floor(size / 4));
      return cursor % size === 0 && end <= to && commitment <= head;
    });
    ranges.push({ firstBlock: cursor, tableSize });
    cursor += tableSize;
  }
  return ranges;
}

async function loadTableRange(range, filters, useCache, limit) {
  const candidate = await requestTableQuery(range.firstBlock, range.tableSize, filters, useCache, limit);
  if (candidate.table) return { attempts: [candidate], tables: [candidate], missingBlocks: [] };
  if (range.tableSize === 1) return { attempts: [candidate], tables: [], missingBlocks: [range.firstBlock] };
  const lowerSize = range.tableSize / 4;
  const children = await Promise.all(Array.from({ length: 4 }, (_, index) => loadTableRange({
    firstBlock: range.firstBlock + index * lowerSize,
    tableSize: lowerSize,
  }, filters, useCache, limit)));
  return {
    attempts: [candidate, ...children.flatMap((child) => child.attempts)],
    tables: children.flatMap((child) => child.tables),
    missingBlocks: children.flatMap((child) => child.missingBlocks),
  };
}

async function scanTables({ address, fromBlock = 0, toBlock, enrich = true, cache = true, concurrency } = {}) {
  if (!isAddress(address)) throw new Error('address must be a 20-byte hex address');
  const head = Number.parseInt(await rpc('eth_blockNumber', []), 16);
  const from = blockNumber(fromBlock, 'fromBlock');
  const to = toBlock == null || toBlock === '' ? head : Math.min(blockNumber(toBlock, 'toBlock'), head);
  const discoveryStarted = performance.now();
  const paddedRecipient = `0x${address.slice(2).padStart(64, '0')}`.toLowerCase();
  const filters = [
    { typeId: 2, content: VAULT },
    { typeId: 3, content: TOPIC },
    { typeId: 5, content: paddedRecipient },
  ];
  const limit = createLimiter(discoveryConcurrency(concurrency));
  const positions = new Map();
  const transactionHashes = new Map();
  const logCommitments = new Map();
  const tables = [];
  let rpcCalls = 0;
  let responseBytes = 0;
  let providerRpcMs = 0;
  let providerTableLoadMicros = 0;
  let providerQueryMicros = 0;
  let entriesExamined = 0;
  let fullTableEntries = 0;
  let rootChecks = 0;
  let queryCacheHits = 0;
  let rootCacheHits = 0;
  let proofsVerified = 0;
  let proofBytes = 0;
  let proofVerificationMs = 0;
  const loaded = await Promise.all(initialTableRanges(from, to, head).map((range) => loadTableRange(range, filters, cache, limit)));
  const missingBlocks = loaded.flatMap((range) => range.missingBlocks);
  for (const candidate of loaded.flatMap((range) => range.attempts)) {
    if (candidate.queryCacheHit) queryCacheHits += 1;
    else {
      rpcCalls += 1;
      responseBytes += candidate.record.response.responseBytes;
      providerRpcMs += candidate.record.response.elapsedMs;
    }
    if (candidate.rootResponse) {
      rootChecks += 1;
      if (candidate.rootCacheHit) rootCacheHits += 1;
      else {
        rpcCalls += 1;
        responseBytes += candidate.rootResponse.responseBytes;
        providerRpcMs += candidate.rootResponse.elapsedMs;
      }
    }
  }
  const selectedTables = loaded.flatMap((range) => range.tables).sort((a, b) => Number(BigInt(a.table.firstBlock) - BigInt(b.table.firstBlock)));
  for (const selected of selectedTables) {
    const table = selected.table;
    tables.push({
      firstBlock: Number.parseInt(table.firstBlock, 16),
      tableSize: Number.parseInt(table.tableSize, 16),
      tableRoot: table.tableRoot,
      entryCount: Number.parseInt(table.entryCount, 16),
      returnedEntries: selected.verified.entriesReturned,
      loadMicros: table.loadMicros,
      queryMicros: table.queryMicros,
    });
    if (!selected.queryCacheHit) {
      providerTableLoadMicros += Number(table.loadMicros || 0);
      providerQueryMicros += Number(table.queryMicros || 0);
    }
    entriesExamined += selected.verified.entriesReturned;
    fullTableEntries += Number.parseInt(table.entryCount, 16);
    proofsVerified += selected.queryCacheHit ? 0 : selected.verified.proofsVerified;
    proofBytes += selected.queryCacheHit ? 0 : selected.verified.proofBytes;
    proofVerificationMs += selected.queryCacheHit ? 0 : selected.verified.proofVerificationMs;
    for (const [key, entry] of selected.verified.positions) positions.set(key, entry);
    for (const [key, hash] of selected.verified.transactionHashes) transactionHashes.set(key, hash);
    for (const [key, root] of selected.verified.logCommitments) logCommitments.set(key, root);
  }

  const utxos = [];
  const positionRequests = [...positions.values()].map((position) => ({
    blockNumber: position.blockNumber,
    transactionIndex: position.transactionIndex,
    logIndex: position.positionIndex,
  }));
  const payloadChunks = [];
  for (let offset = 0; offset < positionRequests.length; offset += 1024) payloadChunks.push(positionRequests.slice(offset, offset + 1024));
  const payloadResults = await Promise.all(payloadChunks.map((chunk) => limit(() => rpcMeasured('ethrex_getEip8304Logs', [chunk]))));
  const selectedLogs = new Map();
  for (const response of payloadResults) {
    rpcCalls += 1;
    responseBytes += response.responseBytes;
    providerRpcMs += response.elapsedMs;
    if (!Array.isArray(response.result)) throw new Error('ethrex_getEip8304Logs did not return an array');
    for (const rawLog of response.result) {
      const key = `${BigInt(rawLog.blockNumber)}:${BigInt(rawLog.transactionIndex)}:${BigInt(rawLog.logIndex)}`;
      if (!positions.has(key) || selectedLogs.has(key)) throw new Error(`unexpected or duplicate selected EIP-8304 log ${key}`);
      const calculatedRoot = logCommitment(rawLog);
      if (calculatedRoot !== logCommitments.get(key) || rawLog.logRoot?.toLowerCase() !== calculatedRoot) {
        throw new Error(`selected EIP-8304 log does not match its proven commitment at ${key}`);
      }
      selectedLogs.set(key, rawLog);
    }
  }
  if (selectedLogs.size !== positions.size) throw new Error('ethrex_getEip8304Logs omitted a proven log position');
  for (const [key, position] of positions) {
    const rawLog = selectedLogs.get(key);
    const transactionKey = `${BigInt(position.blockNumber)}:${BigInt(position.transactionIndex)}`;
    const transactionHash = transactionHashes.get(transactionKey);
    if (!transactionHash) throw new Error(`EIP-8304 transaction hash missing for ${transactionKey}`);
    const log = { ...rawLog, transactionHash };
    const item = openingFromLog(log);
    if (!item || item.recipient !== address.toLowerCase() || log.address.toLowerCase() !== VAULT
        || log.topics[0]?.toLowerCase() !== TOPIC) {
      throw new Error(`EIP-8304 position did not resolve to the requested UtxoCreated log`);
    }
    utxos.push(item);
  }

  const discoveryMs = Number((performance.now() - discoveryStarted).toFixed(3));
  utxos.sort((a, b) => a.index - b.index);
  const enrichment = enrich
    ? await enrichDiscoveredUtxos(utxos, head)
    : { spentCheckMs: 0, metadataMs: 0 };
  const walletTotalMs = Number((discoveryMs + enrichment.spentCheckMs + enrichment.metadataMs).toFixed(3));
  return {
    method: 'eip8304Tables', address: address.toLowerCase(), fromBlock: from, toBlock: to, head, utxos,
    complete: missingBlocks.length === 0,
    missingBlocks,
    tables,
    metrics: {
      discoveryMs,
      providerRpcMs: Number(providerRpcMs.toFixed(3)),
      providerTableLoadMicros,
      providerQueryMicros,
      responseBytes,
      rpcCalls,
      tablesLoaded: tables.length,
      entriesExamined,
      fullTableEntries,
      entriesAvoided: fullTableEntries - entriesExamined,
      matchedPositions: positions.size,
      rootChecks,
      queryCacheHits,
      rootCacheHits,
      proofsVerified,
      proofBytes,
      proofVerificationMs: Number(proofVerificationMs.toFixed(3)),
      receiptsFetched: 0,
      receiptRpcCalls: 0,
      selectedLogsReturned: selectedLogs.size,
      logPayloadRpcCalls: payloadResults.length,
      blocksTouched: new Set([...positions.values()].map((entry) => String(entry.blockNumber))).size,
      walletTotalMs,
      walletRpcCalls: enrich ? rpcCalls + utxos.length + 1 : rpcCalls,
      ...enrichment,
    },
  };
}

function resultIdentity(scanResult) {
  const canonical = scanResult.utxos.map((item) => [
    item.creationBlock, item.txHash, item.logIndex, item.index, item.source, item.recipient, item.valueWei,
  ]).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  return createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
}

async function compareDiscovery(query = {}) {
  const head = Number.parseInt(await rpc('eth_blockNumber', []), 16);
  const frozen = { ...query, toBlock: query.toBlock == null || query.toBlock === '' ? head : Math.min(blockNumber(query.toBlock, 'toBlock'), head) };
  const order = query.order === 'tablesFirst' ? ['tables', 'logs'] : ['logs', 'tables'];
  const results = {};
  for (const method of order) {
    results[method] = method === 'tables' ? await scanTables(frozen) : await scanLogs(frozen);
  }
  const logIdentity = resultIdentity(results.logs);
  const tableIdentity = resultIdentity(results.tables);
  return {
    targetHead: head,
    fromBlock: frozen.fromBlock,
    toBlock: frozen.toBlock,
    sameResults: logIdentity === tableIdentity,
    receiptLogResultHash: `0x${logIdentity}`,
    eip8304ResultHash: `0x${tableIdentity}`,
    receiptLogs: results.logs,
    eip8304Tables: results.tables,
  };
}

function measurementCount(value, name, fallback) {
  const count = Number(value ?? fallback);
  if (!Number.isSafeInteger(count) || count < 0 || count > 100) throw new Error(`${name} must be an integer between 0 and 100`);
  return count;
}

function numericStatistics(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const percentile = (fraction) => sorted[Math.max(0, Math.ceil(sorted.length * fraction) - 1)];
  return {
    minimum: sorted[0],
    median: percentile(0.5),
    p95: percentile(0.95),
    maximum: sorted.at(-1),
    mean: Number((sorted.reduce((sum, value) => sum + value, 0) / sorted.length).toFixed(3)),
  };
}

function discoveryStatistics(samples, resultName) {
  const metricNames = new Set(samples.flatMap((sample) => Object.keys(sample[resultName].metrics)));
  const metrics = {};
  for (const metricName of metricNames) {
    const values = samples.map((sample) => sample[resultName].metrics[metricName]).filter(Number.isFinite);
    if (values.length === samples.length) metrics[metricName] = numericStatistics(values);
  }
  return metrics;
}

async function benchmarkDiscovery(query = {}) {
  const warmups = measurementCount(query.warmups, 'warmups', 2);
  const repetitions = measurementCount(query.repetitions, 'repetitions', 7);
  if (repetitions < 1) throw new Error('repetitions must be at least one');
  const benchmarkQuery = { ...query };
  delete benchmarkQuery.warmups;
  delete benchmarkQuery.repetitions;
  clearDiscoveryCaches();

  const cold = await compareDiscovery({ ...benchmarkQuery, order: 'logsFirst' });
  if (!cold.sameResults || !cold.eip8304Tables.complete) throw new Error('cold discovery methods returned different or incomplete results');
  for (let iteration = 0; iteration < warmups; iteration += 1) {
    const warmup = await compareDiscovery({ ...benchmarkQuery, order: iteration % 2 ? 'logsFirst' : 'tablesFirst' });
    if (!warmup.sameResults || !warmup.eip8304Tables.complete) throw new Error(`warmup ${iteration + 1} returned different or incomplete results`);
  }
  const samples = [];
  for (let iteration = 0; iteration < repetitions; iteration += 1) {
    const order = iteration % 2 ? 'tablesFirst' : 'logsFirst';
    const comparison = await compareDiscovery({ ...benchmarkQuery, order });
    if (!comparison.sameResults || !comparison.eip8304Tables.complete) throw new Error(`measurement ${iteration + 1} returned different or incomplete results`);
    samples.push({ iteration: iteration + 1, order, ...comparison });
  }
  return {
    warmups,
    repetitions,
    cold,
    samples,
    statistics: {
      receiptLogs: discoveryStatistics(samples, 'receiptLogs'),
      eip8304Tables: discoveryStatistics(samples, 'eip8304Tables'),
    },
  };
}

async function scan(query = {}) {
  return query.method === 'tables' ? scanTables(query) : scanLogs(query);
}

async function scanCreated({ address, fromBlock = 0, toBlock } = {}) {
  if (!isAddress(address)) throw new Error('address must be a 20-byte hex address');
  const head = Number.parseInt(await rpc('eth_blockNumber', []), 16);
  const from = blockNumber(fromBlock, 'fromBlock');
  const to = toBlock == null || toBlock === '' ? head : Math.min(blockNumber(toBlock, 'toBlock'), head);
  const utxos = [];
  for (let start = from; start <= to; start += 2_000) {
    const end = Math.min(start + 1_999, to);
    const logs = await rpc('eth_getLogs', [{
      address: VAULT,
      topics: [TOPIC, '0x' + address.slice(2).padStart(64, '0'), null],
      fromBlock: '0x' + start.toString(16),
      toBlock: '0x' + end.toString(16),
    }]);
    for (const log of logs) {
      const item = openingFromLog(log);
      if (!item || item.source !== address.toLowerCase()) continue;
      item.spent = await spent(item.index);
      item.spendable = item.creationBlock < head && !item.spent;
      utxos.push(item);
    }
  }
  utxos.sort((a, b) => a.index - b.index);
  return { address: address.toLowerCase(), fromBlock: from, toBlock: to, head, utxos };
}

async function walletAddress() {
  if (!walletKey) return null;
  return (await forge({ op: 'addressOf', key: walletKey })).address.toLowerCase();
}

function checkInputs(body) {
  const inputs = Array.isArray(body.inputs) ? body.inputs : body.input ? [body.input] : null;
  if (!inputs?.length) throw new Error('inputs are required');
  if (inputs.length > 64) throw new Error('a spend cannot contain more than 64 inputs');
  const seen = new Set();
  for (const input of inputs) {
    if (!input || !Number.isInteger(input.index) || !Number.isInteger(input.creationBlock)) throw new Error('each input must include index and creationBlock');
    if (!isAddress(input.source) || !isAddress(input.recipient)) throw new Error('each input source and recipient must be addresses');
    const key = String(input.index) + ':' + String(input.creationBlock);
    if (seen.has(key)) throw new Error('the same UTXO was selected more than once');
    seen.add(key);
  }
  return inputs;
}

async function verifyInputs(inputs, owner) {
  const verified = [];
  for (const input of inputs) {
    if (input.recipient.toLowerCase() !== owner) throw new Error('selected UTXO belongs to ' + input.recipient + ', not the configured wallet');
    positiveWei(String(input.valueWei), 'input.valueWei');
    const exact = await scan({ address: owner, fromBlock: input.creationBlock, toBlock: input.creationBlock });
    const current = exact.utxos.find((u) => u.index === input.index);
    if (!current) throw new Error('selected UTXO #' + input.index + ' was not found in its creation block');
    if (current.spent) throw new Error('selected UTXO #' + input.index + ' is already spent');
    if (current.source !== input.source.toLowerCase() || current.valueWei !== String(input.valueWei)) throw new Error('selected UTXO #' + input.index + ' metadata does not match the chain');
    verified.push(current);
  }
  return verified.sort((a, b) => a.index - b.index);
}

async function sendUtxo(body) {
  if (!walletKey) throw new Error('sending is disabled; import a wallet or set UTXO_WALLET_KEY before starting the wallet');
  const inputs = checkInputs(body);
  if (!isAddress(body.recipient)) throw new Error('recipient must be a 20-byte hex address');
  const amount = positiveWei(body.valueWei);
  const owner = await walletAddress();
  const current = await verifyInputs(inputs, owner);
  const inputValue = current.reduce((sum, item) => sum + BigInt(item.valueWei), 0n);
  if (amount > inputValue) throw new Error('valueWei cannot exceed the selected UTXO value');
  return forge({
    op: 'spend', actorKeys: [walletKey],
    inputs: current,
    utxoOuts: [{ recipient: body.recipient.toLowerCase(), valueWei: amount.toString() }, { recipient: owner, valueWei: '0' }],
    accountOuts: [], changeIndex: 1,
  });
}

async function createFreshUtxo(body) {
  if (!walletKey) throw new Error('fresh UTXO creation is disabled; import a wallet first');
  if (!isAddress(body.recipient)) throw new Error('recipient must be a 20-byte hex address');
  const value = positiveWei(body.valueWei);
  const owner = await walletAddress();
  const beforeWei = await rpc('eth_getBalance', [owner, 'latest']);
  const result = await forge({ op: 'deposit', key: walletKey, recipient: body.recipient.toLowerCase(), valueWei: value.toString() });
  if (result.status !== '0x1') throw new Error(`fresh UTXO deposit reverted: ${result.txHash}`);
  const afterWei = await rpc('eth_getBalance', [owner, 'latest']);
  return { ...result, source: owner, recipient: body.recipient.toLowerCase(), valueWei: value.toString(), accountBalanceBeforeWei: BigInt(beforeWei).toString(), accountBalanceAfterWei: BigInt(afterWei).toString() };
}

async function redeemUtxo(body) {
  if (!walletKey) throw new Error('redemption is disabled; import a wallet or set UTXO_WALLET_KEY before starting the wallet');
  const inputs = checkInputs(body);
  const owner = await walletAddress();
  const current = await verifyInputs(inputs, owner);
  const inputValue = current.reduce((sum, item) => sum + BigInt(item.valueWei), 0n);
  const feeReserve = await maxSelfFundedFee();
  const defaultRedeem = inputValue > feeReserve ? inputValue - feeReserve : 0n;
  const requested = body.valueWei == null || body.valueWei === '' ? defaultRedeem : positiveWei(body.valueWei);
  if (requested <= 0n) throw new Error('the selected UTXOs are too small to cover the self-funded conversion fee');
  if (requested > inputValue) throw new Error('redemption value cannot exceed the selected UTXO value');
  const beforeWei = await rpc('eth_getBalance', [owner, 'latest']);
  const result = await forge({
    op: 'spend', actorKeys: [walletKey],
    inputs: current,
    // A zero-valued UTXO change output is required even when the value is
    // converted back into the account model.
    utxoOuts: [{ recipient: owner, valueWei: '0' }],
    accountOuts: [{ recipient: owner, valueWei: requested.toString() }],
    changeIndex: 0,
  });
  const afterWei = await rpc('eth_getBalance', [owner, 'latest']);
  return { ...result, account: owner, accountBalanceBeforeWei: BigInt(beforeWei).toString(), accountBalanceAfterWei: BigInt(afterWei).toString() };
}

function send(res, status, body, type = 'application/json; charset=utf-8') {
  res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store' });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}

function body(req) {
  return new Promise((resolveBody, rejectBody) => {
    let text = '';
    req.on('data', (chunk) => { text += chunk; if (text.length > 64 * 1024) rejectBody(new Error('request body too large')); });
    req.on('end', () => { try { resolveBody(text ? JSON.parse(text) : {}); } catch { rejectBody(new Error('invalid JSON body')); } });
    req.on('error', rejectBody);
  });
}

async function staticFile(res, pathname) {
  let relative = normalize(decodeURIComponent(pathname)).replace(/^([/\\])+/, '');
  if (!relative || relative.endsWith('/')) relative = join(relative, 'index.html');
  if (relative.startsWith('..')) return send(res, 403, 'forbidden', 'text/plain; charset=utf-8');
  try { return send(res, 200, await readFile(join(PUBLIC, relative)), MIME[extname(relative)] || 'application/octet-stream'); }
  catch { return send(res, 404, 'not found', 'text/plain; charset=utf-8'); }
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (API_TOKEN && url.pathname.startsWith('/api/') && req.headers['x-utxo-token'] !== API_TOKEN) {
      return send(res, 401, { error: 'unauthorized wallet backend request' });
    }
    if (url.pathname === '/api/status' && req.method === 'GET') {
      const address = await walletAddress();
      const accountBalanceWei = address ? BigInt(await rpc('eth_getBalance', [address, 'latest'])).toString() : '0';
      return send(res, 200, { rpc: rpcUrl, defaultRpc: DEFAULT_RPC, vault: VAULT, head: Number.parseInt(await rpc('eth_blockNumber', []), 16), configured: Boolean(address), address, accountBalanceWei });
    }
    if (url.pathname === '/api/rpc' && req.method === 'POST') {
      const candidate = (await body(req)).url;
      if (typeof candidate !== 'string' || !/^https?:\/\/[^\s]+$/i.test(candidate)) return send(res, 400, { error: 'RPC URL must start with http:// or https://' });
      const previous = rpcUrl;
      rpcUrl = candidate.trim();
      try {
        await rpc('eth_chainId', []);
        clearDiscoveryCaches();
        return send(res, 200, { rpc: rpcUrl });
      } catch (error) {
        rpcUrl = previous;
        return send(res, 400, { error: `RPC URL did not respond: ${error.message}` });
      }
    }
    if (url.pathname === '/api/import' && req.method === 'POST') {
      const candidate = (await body(req)).key;
      if (typeof candidate !== 'string' || !/^(0x)?[0-9a-fA-F]{64}$/.test(candidate)) {
        return send(res, 400, { error: 'private key must be exactly 32 bytes in hex' });
      }
      // Validate and derive before replacing the current in-memory wallet.
      const previous = walletKey;
      walletKey = candidate.startsWith('0x') ? candidate : `0x${candidate}`;
      try {
        const address = await walletAddress();
        return send(res, 200, { configured: true, address });
      } catch (error) {
        walletKey = previous;
        return send(res, 400, { error: `could not import wallet: ${error.message}` });
      }
    }
    if (url.pathname === '/api/lock' && req.method === 'POST') {
      walletKey = null;
      return send(res, 200, { configured: false, address: null });
    }
    if (url.pathname === '/api/scan' && req.method === 'POST') return send(res, 200, await scan(await body(req)));
    if (url.pathname === '/api/compare-discovery' && req.method === 'POST') return send(res, 200, await compareDiscovery(await body(req)));
    if (url.pathname === '/api/table' && req.method === 'POST') {
      const request = await body(req);
      const firstBlock = blockNumber(request.firstBlock, 'firstBlock');
      const tableSize = blockNumber(request.tableSize ?? 1, 'tableSize');
      return send(res, 200, await rpc('ethrex_getEip8304Table', [`0x${firstBlock.toString(16)}`, `0x${tableSize.toString(16)}`]));
    }
    if (url.pathname === '/api/created' && req.method === 'POST') return send(res, 200, await scanCreated(await body(req)));
    if (url.pathname === '/api/send' && req.method === 'POST') return send(res, 200, await sendUtxo(await body(req)));
    if (url.pathname === '/api/deposit' && req.method === 'POST') return send(res, 200, await createFreshUtxo(await body(req)));
    if (url.pathname === '/api/redeem' && req.method === 'POST') return send(res, 200, await redeemUtxo(await body(req)));
    if (url.pathname.startsWith('/api/')) return send(res, 404, { error: 'unknown endpoint' });
    return staticFile(res, url.pathname);
  } catch (error) { return send(res, 400, { error: error.message }); }
});

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (!existsSync(TXFORGE)) console.warn(`txforge not found at ${TXFORGE}; watch-only scanning still works`);
  server.listen(PORT, HOST, () => console.log(`Standalone UTXO wallet â†’ http://${HOST}:${PORT} (${rpcUrl})`));
}

export { benchmarkDiscovery, clearDiscoveryCaches, compareDiscovery, rpc, scan, scanLogs, scanTables };
