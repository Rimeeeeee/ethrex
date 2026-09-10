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
  if (!log?.data || log.data.length !== 66 || !log.topics || log.topics.length !== 4) return null;
  const data = log.data.slice(2);
  const topicAddress = (topic) => `0x${topic.slice(-40)}`.toLowerCase();
  return {
    index: Number(BigInt(log.topics[3])),
    valueWei: BigInt(`0x${data}`).toString(),
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
let tableQueryHeads = new Map();
let tableRootCache = new Map();
let utxoPositionCache = new Map();
let utxoRecordCache = new Map();

function clearDiscoveryCaches() {
  tableQueryCache.clear();
  tableQueryHeads.clear();
  tableRootCache.clear();
  utxoPositionCache.clear();
  utxoRecordCache.clear();
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

const KECCAK_MASK = (1n << 64n) - 1n;
const KECCAK_RATE = 136;
const KECCAK_ROTATIONS = [
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];
const KECCAK_ROUND_CONSTANTS = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

function rotateLane(value, amount) {
  const shift = BigInt(amount);
  return shift === 0n ? value : ((value << shift) | (value >> (64n - shift))) & KECCAK_MASK;
}

function keccakPermutation(state) {
  for (const roundConstant of KECCAK_ROUND_CONSTANTS) {
    const parity = Array(5).fill(0n);
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) parity[x] ^= state[x + 5 * y];
    }
    const delta = parity.map((_, x) => parity[(x + 4) % 5] ^ rotateLane(parity[(x + 1) % 5], 1));
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) state[x + 5 * y] = (state[x + 5 * y] ^ delta[x]) & KECCAK_MASK;
    }
    const rotated = Array(25).fill(0n);
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        rotated[y + 5 * ((2 * x + 3 * y) % 5)] = rotateLane(state[x + 5 * y], KECCAK_ROTATIONS[x + 5 * y]);
      }
    }
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        const row = x + 5 * y;
        state[row] = (rotated[row] ^ ((~rotated[(x + 1) % 5 + 5 * y]) & rotated[(x + 2) % 5 + 5 * y])) & KECCAK_MASK;
      }
    }
    state[0] = (state[0] ^ roundConstant) & KECCAK_MASK;
  }
}

function keccak256(value) {
  const data = Buffer.from(value);
  const paddingLength = KECCAK_RATE - (data.length % KECCAK_RATE);
  const padded = Buffer.concat([data, Buffer.alloc(paddingLength)]);
  padded[data.length] = 0x01;
  padded[padded.length - 1] |= 0x80;
  const state = Array(25).fill(0n);
  for (let offset = 0; offset < padded.length; offset += KECCAK_RATE) {
    for (let lane = 0; lane < KECCAK_RATE / 8; lane += 1) {
      state[lane] ^= padded.readBigUInt64LE(offset + lane * 8);
    }
    keccakPermutation(state);
  }
  const output = Buffer.alloc(32);
  for (let lane = 0; lane < 4; lane += 1) output.writeBigUInt64LE(state[lane], lane * 8);
  return output;
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
  if (!Array.isArray(table.proofNodes)) throw new Error('EIP-8304 multiproof nodes are missing');
  const nodes = new Map();
  for (const node of table.proofNodes) {
    const key = `${Number(node.level)}:${BigInt(node.nodeIndex)}`;
    if (nodes.has(key)) throw new Error(`duplicate EIP-8304 multiproof node ${key}`);
    nodes.set(key, hexBuffer(node.hash, 'proof node hash'));
  }
  return nodes;
}

function decodeTableEntry(encodedValue) {
  const encoded = hexBuffer(encodedValue, 'encoded EIP-8304 entry');
  if (encoded.length < 2) throw new Error('truncated encoded EIP-8304 entry');
  const typeId = encoded.readUInt16BE(0);
  const shape = typeId === 0 && encoded.length === 42 ? { contentEnd: 34, positionOffset: 34, hasTransaction: false, hasPosition: false }
    : typeId === 1 && encoded.length === 50 ? { contentEnd: 34, positionOffset: 34, hasTransaction: true, hasPosition: true }
      : typeId === 2 && encoded.length === 38 ? { contentEnd: 22, positionOffset: 22, hasTransaction: true, hasPosition: true }
        : typeId >= 3 && typeId <= 6 && encoded.length === 50 ? { contentEnd: 34, positionOffset: 34, hasTransaction: true, hasPosition: true }
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

function validateProvenEntry(table, proven) {
  const entryCount = Number(BigInt(table.entryCount));
  const leafIndex = Number(BigInt(proven.leafIndex));
  if (!Number.isSafeInteger(leafIndex) || leafIndex < 0 || leafIndex >= entryCount) throw new Error(`invalid EIP-8304 proof leaf ${proven.leafIndex}`);
  const decoded = decodeTableEntry(proven.encoded);
  const transactionIndex = proven.transactionIndex == null ? null : BigInt(proven.transactionIndex);
  const positionIndex = proven.positionIndex == null ? null : BigInt(proven.positionIndex);
  if (decoded.typeId !== proven.typeId || decoded.content !== proven.content.toLowerCase()
      || decoded.blockNumber !== BigInt(proven.blockNumber) || decoded.transactionIndex !== transactionIndex
      || decoded.positionIndex !== positionIndex) {
    throw new Error(`decoded EIP-8304 entry fields do not match proven leaf ${leafIndex}`);
  }
  return { leafIndex, decoded };
}

function verifyTableMultiproof(table, provenEntries) {
  const entryCount = Number(BigInt(table.entryCount));
  if (!Number.isSafeInteger(entryCount) || entryCount < 0) throw new Error('invalid EIP-8304 entry count');
  if (entryCount === 0) {
    if (provenEntries.length !== 0) throw new Error('empty EIP-8304 table returned entries');
    verifyEmptyTableRoot(table);
    return 0;
  }
  let width = 1;
  while (width < entryCount) width *= 2;
  let known = new Map();
  for (const proven of provenEntries) {
    const { leafIndex } = validateProvenEntry(table, proven);
    const leaf = sha256(hexBuffer(proven.encoded, 'encoded EIP-8304 entry'));
    const previous = known.get(leafIndex);
    if (previous && !previous.equals(leaf)) throw new Error(`conflicting EIP-8304 entry at leaf ${leafIndex}`);
    known.set(leafIndex, leaf);
  }
  const proofNodes = proofNodeMap(table);
  const usedProofNodes = new Set();
  for (let level = 0; width > 1; level += 1, width /= 2) {
    const parents = new Set([...known.keys()].map((index) => Math.floor(index / 2)));
    const next = new Map();
    for (const parent of parents) {
      const children = [parent * 2, parent * 2 + 1].map((index) => {
        const calculated = known.get(index);
        if (calculated) return calculated;
        const key = `${level}:${BigInt(index)}`;
        const supplied = proofNodes.get(key);
        if (!supplied) throw new Error(`missing EIP-8304 multiproof node ${key}`);
        usedProofNodes.add(key);
        return supplied;
      });
      next.set(parent, sha256(Buffer.concat(children)));
    }
    known = next;
  }
  const root = known.get(0);
  if (!root || `0x${mixedInRoot(root, entryCount).toString('hex')}` !== table.tableRoot.toLowerCase()) {
    throw new Error('invalid shared EIP-8304 table multiproof');
  }
  if (usedProofNodes.size !== proofNodes.size) throw new Error('EIP-8304 multiproof contains unused nodes');
  return known.size === 1 ? new Set(provenEntries.map((entry) => String(entry.leafIndex))).size : 0;
}

function verifyEmptyTableRoot(table) {
  const expected = `0x${mixedInRoot(Buffer.alloc(32), 0).toString('hex')}`;
  if (table.tableRoot.toLowerCase() !== expected) throw new Error('invalid empty EIP-8304 table root');
}

function verifyTableQuery(table, filters, candidateTypeIds) {
  const started = performance.now();
  const entryCount = Number(BigInt(table.entryCount));
  if (!Number.isSafeInteger(entryCount) || entryCount < 0) throw new Error('invalid EIP-8304 entry count');
  if (table.proofFormat !== 'shared-per-table-v1') throw new Error('EIP-8304 query did not return the required shared multiproof');
  if (!Array.isArray(table.queries) || table.queries.length !== filters.length) throw new Error('EIP-8304 query response omitted a requested posting range');

  const serializedEntries = [
    ...table.queries.flatMap((range) => [range.lowerBoundary, ...(range.entries || []), range.upperBoundary]),
    ...(table.transactions || []),
    ...(table.candidateEntries || []),
  ].filter(Boolean);
  const uniqueEntries = new Map();
  for (const entry of serializedEntries) {
    const { leafIndex } = validateProvenEntry(table, entry);
    const previous = uniqueEntries.get(leafIndex);
    if (previous && previous.encoded.toLowerCase() !== entry.encoded.toLowerCase()) {
      throw new Error(`conflicting serialized EIP-8304 entry at leaf ${leafIndex}`);
    }
    uniqueEntries.set(leafIndex, entry);
  }
  const proofsVerified = verifyTableMultiproof(table, [...uniqueEntries.values()]);

  const requested = new Map(filters.map((filter) => [`${filter.typeId}:${filter.content.toLowerCase()}`, filter]));
  const postings = new Map();
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
      const { leafIndex } = validateProvenEntry(table, entry);
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
      if (!range.lowerBoundary || validateProvenEntry(table, range.lowerBoundary).leafIndex !== first - 1) throw new Error(`invalid lower EIP-8304 boundary for ${key}`);
      if (Buffer.compare(hexBuffer(range.lowerBoundary.encoded, 'lower boundary'), prefix) >= 0) throw new Error(`lower EIP-8304 boundary does not prove completeness for ${key}`);
    }
    if (end === entryCount) {
      if (range.upperBoundary != null) throw new Error(`unexpected upper EIP-8304 boundary for ${key}`);
    } else {
      if (!range.upperBoundary || validateProvenEntry(table, range.upperBoundary).leafIndex !== end) throw new Error(`invalid upper EIP-8304 boundary for ${key}`);
      const upper = hexBuffer(range.upperBoundary.encoded, 'upper boundary');
      if (Buffer.compare(upper, prefix) < 0 || upper.subarray(0, prefix.length).equals(prefix)) throw new Error(`upper EIP-8304 boundary does not prove completeness for ${key}`);
    }
    postings.set(key, positions);
  }

  let matched = null;
  for (const filter of filters) {
    const positions = postings.get(`${filter.typeId}:${filter.content.toLowerCase()}`);
    matched = matched == null ? new Map(positions) : new Map([...matched].filter(([position]) => positions.has(position)));
  }
  matched ||= new Map();

  const transactionHashes = new Map();
  for (const transaction of table.transactions || []) {
    if (transaction.typeId !== 1) throw new Error('EIP-8304 query returned a non-transaction as transaction evidence');
    const key = `${BigInt(transaction.blockNumber)}:${BigInt(transaction.transactionIndex)}`;
    if (transactionHashes.has(key)) throw new Error(`duplicate EIP-8304 transaction evidence for ${key}`);
    transactionHashes.set(key, transaction.content.toLowerCase());
  }
  const expectedTransactions = new Set([...matched.values()].map((position) => `${BigInt(position.blockNumber)}:${BigInt(position.transactionIndex)}`));
  if (transactionHashes.size !== expectedTransactions.size || [...transactionHashes].some(([key]) => !expectedTransactions.has(key))) {
    throw new Error('EIP-8304 query returned incomplete or extraneous transaction evidence');
  }

  const requestedCandidateTypes = new Set(candidateTypeIds);
  const candidateEntries = new Map();
  for (const entry of table.candidateEntries || []) {
    const key = tablePosition(entry);
    if (!matched.has(key) || !requestedCandidateTypes.has(entry.typeId)) throw new Error(`unexpected EIP-8304 candidate entry at ${key}`);
    const byType = candidateEntries.get(key) || new Map();
    if (byType.has(entry.typeId)) throw new Error(`duplicate EIP-8304 type ${entry.typeId} at ${key}`);
    byType.set(entry.typeId, entry);
    candidateEntries.set(key, byType);
  }

  const nativePositions = new Map();
  for (const [key, recipientEntry] of matched) {
    const byType = candidateEntries.get(key) || new Map();
    const addressEntry = byType.get(2);
    const signatureEntry = byType.get(3);
    if (!addressEntry || !signatureEntry) throw new Error(`unresolved EIP-8304 recipient candidate ${key}`);
    if (addressEntry.content.toLowerCase() !== VAULT || signatureEntry.content.toLowerCase() !== TOPIC) continue;
    const sourceEntry = byType.get(4);
    const indexEntry = byType.get(6);
    if (!sourceEntry || !indexEntry) throw new Error(`native EIP-8304 candidate lacks source or index at ${key}`);
    const sourceWord = hexBuffer(sourceEntry.content, 'UTXO source topic');
    const indexWord = hexBuffer(indexEntry.content, 'UTXO index topic');
    if (sourceWord.length !== 32 || !sourceWord.subarray(0, 12).equals(Buffer.alloc(12))) throw new Error(`non-canonical UTXO source at ${key}`);
    if (indexWord.length !== 32 || !indexWord.subarray(0, 24).equals(Buffer.alloc(24))) throw new Error(`non-canonical UTXO index at ${key}`);
    nativePositions.set(key, {
      ...recipientEntry,
      source: `0x${sourceWord.subarray(12).toString('hex')}`,
      index: Number(indexWord.readBigUInt64BE(24)),
    });
  }

  return {
    positions: nativePositions,
    transactionHashes,
    proofsVerified,
    entriesReturned: uniqueEntries.size,
    serializedEntriesReturned: serializedEntries.length,
    proofBytes: (table.proofNodes?.length || 0) * 32,
    proofVerificationMs: Number((performance.now() - started).toFixed(3)),
  };
}

async function requestTableQuery(firstBlock, tableSize, filters, candidateTypeIds, useCache, limit) {
  const filterKey = filters.map((filter) => `${filter.typeId}:${filter.content.toLowerCase()}`).join('|');
  const queryKey = `${rpcUrl}|${firstBlock}|${tableSize}|${filterKey}|${candidateTypeIds.join(',')}`;
  let record = null;
  let queryCacheHit = false;
  let cacheValidationResponse = null;
  const cachedBlockHash = useCache ? tableQueryHeads.get(queryKey) : null;
  if (cachedBlockHash) {
    record = await tableQueryCache.get(`${queryKey}|${cachedBlockHash}`);
    if (record?.response.result) {
      cacheValidationResponse = await limit(() => rpcMeasured('eth_getBlockByNumber', [
        record.response.result.endBlock,
        false,
      ]));
      if (cacheValidationResponse.result?.hash?.toLowerCase() === cachedBlockHash) {
        queryCacheHit = true;
      } else {
        clearDiscoveryCaches();
        record = null;
      }
    }
  }
  if (!record) {
    record = {
      response: await limit(() => rpcMeasured('ethrex_queryEip8304Table', [
      `0x${firstBlock.toString(16)}`,
      `0x${tableSize.toString(16)}`,
      filters,
      candidateTypeIds,
      ])),
      verified: null,
    };
    const returnedHash = record.response.result?.endBlockHash?.toLowerCase();
    if (useCache && returnedHash) {
      tableQueryHeads.set(queryKey, returnedHash);
      tableQueryCache.set(`${queryKey}|${returnedHash}`, Promise.resolve(record));
    }
  }
  const table = record.response.result;
  if (!table) return { table: null, record, queryCacheHit, cacheValidationResponse, rootResponse: null, rootCacheHit: false };

  const rootKey = `${rpcUrl}|${table.endBlockHash.toLowerCase()}|${table.storageSlot}|${table.commitmentBlock}|${table.tableRoot.toLowerCase()}`;
  const rootLoad = await cachedLoad(tableRootCache, rootKey, useCache, () => limit(() => rpcMeasured('eth_getStorageAt', [
    INDEX,
    table.storageSlot,
    table.commitmentBlock,
  ])));
  if (rootLoad.value.result.toLowerCase() !== table.tableRoot.toLowerCase()) {
    clearDiscoveryCaches();
    throw new Error(`EIP-8304 table root mismatch for ${firstBlock}/${tableSize}`);
  }
  if (!record.verified) record.verified = verifyTableQuery(table, filters, candidateTypeIds);
  return {
    table,
    verified: record.verified,
    record,
    queryCacheHit,
    cacheValidationResponse,
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

async function loadTableRange(range, filters, candidateTypeIds, useCache, limit) {
  const candidate = await requestTableQuery(range.firstBlock, range.tableSize, filters, candidateTypeIds, useCache, limit);
  if (candidate.table) return { attempts: [candidate], tables: [candidate], missingBlocks: [] };
  if (range.tableSize === 1) return { attempts: [candidate], tables: [], missingBlocks: [range.firstBlock] };
  const lowerSize = range.tableSize / 4;
  const children = await Promise.all(Array.from({ length: 4 }, (_, index) => loadTableRange({
    firstBlock: range.firstBlock + index * lowerSize,
    tableSize: lowerSize,
  }, filters, candidateTypeIds, useCache, limit)));
  return {
    attempts: [candidate, ...children.flatMap((child) => child.attempts)],
    tables: children.flatMap((child) => child.tables),
    missingBlocks: children.flatMap((child) => child.missingBlocks),
  };
}

function uintWord(value, bytes, name) {
  const number = BigInt(value);
  if (number < 0n || number >= (1n << BigInt(bytes * 8))) throw new Error(`${name} exceeds uint${bytes * 8}`);
  const encoded = Buffer.alloc(bytes);
  for (let offset = 0, current = number; offset < bytes; offset += 1, current >>= 8n) {
    encoded[bytes - 1 - offset] = Number(current & 0xffn);
  }
  return encoded;
}

function openingLeafFromRecord(record) {
  const source = hexBuffer(record.source, 'UPT source');
  const recipient = hexBuffer(record.recipient, 'UPT recipient');
  if (source.length !== 20 || recipient.length !== 20) throw new Error('UPT record addresses must contain 20 bytes');
  return keccak256(Buffer.concat([
    uintWord(record.index, 8, 'UPT index'),
    source,
    recipient,
    uintWord(record.value, 32, 'UPT value'),
  ]));
}

function verifyUptBlock(block, expectedPositions, transactionHashes, rootValue, chainId) {
  if (Number(block.formatVersion) !== 2) throw new Error('unsupported UPT format version');
  if (BigInt(block.chainId) !== chainId) throw new Error(`UPT chain ID mismatch for block ${block.blockNumber}`);
  if (block.vault?.toLowerCase() !== VAULT) throw new Error(`UPT vault mismatch for block ${block.blockNumber}`);
  if (BigInt(rootValue) !== BigInt(block.openingsRoot)) throw new Error(`UPT root does not match vault storage for block ${block.blockNumber}`);
  const blockNumberValue = BigInt(block.blockNumber);
  const recordCount = Number(BigInt(block.recordCount));
  if (!Number.isSafeInteger(recordCount) || recordCount < 1) throw new Error(`invalid UPT record count for block ${block.blockNumber}`);
  if (!Array.isArray(block.records) || block.records.length !== expectedPositions.size) throw new Error(`UPT omitted selected records for block ${block.blockNumber}`);

  let width = 1;
  while (width < recordCount) width *= 2;
  let known = new Map();
  const items = [];
  const returnedPositions = new Set();
  for (const record of block.records) {
    const position = Number(BigInt(record.position));
    if (!Number.isSafeInteger(position) || position < 0 || position >= recordCount || known.has(position)) throw new Error(`invalid or duplicate UPT opening position ${record.position}`);
    const eventKey = `${blockNumberValue}:${BigInt(record.transactionIndex)}:${BigInt(record.transactionLogIndex)}`;
    const expected = expectedPositions.get(eventKey);
    if (!expected || returnedPositions.has(eventKey)) throw new Error(`unexpected or duplicate UPT event position ${eventKey}`);
    const recordIndex = BigInt(record.index);
    if (recordIndex !== BigInt(expected.index)
        || record.source.toLowerCase() !== expected.source.toLowerCase()
        || record.recipient.toLowerCase() !== `0x${expected.content.slice(-40)}`.toLowerCase()) {
      throw new Error(`UPT record does not match EIP-8304 topics at ${eventKey}`);
    }
    const transactionKey = `${blockNumberValue}:${BigInt(record.transactionIndex)}`;
    const transactionHash = transactionHashes.get(transactionKey);
    if (!transactionHash) throw new Error(`UPT record lacks authenticated transaction hash at ${eventKey}`);
    known.set(position, openingLeafFromRecord(record));
    returnedPositions.add(eventKey);
    const numericIndex = Number(recordIndex);
    if (!Number.isSafeInteger(numericIndex)) throw new Error(`UPT index ${record.index} exceeds wallet integer precision`);
    items.push({
      index: numericIndex,
      valueWei: BigInt(record.value).toString(),
      source: record.source.toLowerCase(),
      recipient: record.recipient.toLowerCase(),
      creationBlock: Number(blockNumberValue),
      txHash: transactionHash,
      blockHash: block.blockHash.toLowerCase(),
      transactionIndex: Number(BigInt(record.transactionIndex)),
      logIndex: Number(BigInt(record.transactionLogIndex)),
      openingPosition: position,
      openingsRoot: block.openingsRoot.toLowerCase(),
      uptTableHash: block.tableHash.toLowerCase(),
    });
  }

  const proofNodes = new Map();
  for (const node of block.proofNodes || []) {
    const key = `${Number(node.level)}:${BigInt(node.nodeIndex)}`;
    if (proofNodes.has(key)) throw new Error(`duplicate UPT multiproof node ${key}`);
    const hash = hexBuffer(node.hash, 'UPT proof node');
    if (hash.length !== 32) throw new Error(`invalid UPT proof node ${key}`);
    proofNodes.set(key, hash);
  }
  const usedProofNodes = new Set();
  for (let level = 0; width > 1; level += 1, width /= 2) {
    const parents = new Set([...known.keys()].map((index) => Math.floor(index / 2)));
    const next = new Map();
    for (const parent of parents) {
      const children = [parent * 2, parent * 2 + 1].map((index) => {
        const calculated = known.get(index);
        if (calculated) return calculated;
        const key = `${level}:${BigInt(index)}`;
        const supplied = proofNodes.get(key);
        if (!supplied) throw new Error(`missing UPT multiproof node ${key}`);
        usedProofNodes.add(key);
        return supplied;
      });
      next.set(parent, keccak256(Buffer.concat(children)));
    }
    known = next;
  }
  const root = known.get(0);
  if (!root || `0x${root.toString('hex')}` !== block.openingsRoot.toLowerCase()) throw new Error(`invalid UPT opening multiproof for block ${block.blockNumber}`);
  if (usedProofNodes.size !== proofNodes.size) throw new Error(`UPT multiproof for block ${block.blockNumber} contains unused nodes`);
  return { items, proofNodes: proofNodes.size };
}

async function scanTables({ address, fromBlock = 0, toBlock, enrich = true, cache = true, concurrency } = {}) {
  if (!isAddress(address)) throw new Error('address must be a 20-byte hex address');
  const head = Number.parseInt(await rpc('eth_blockNumber', []), 16);
  const chainId = BigInt(await rpc('eth_chainId', []));
  const from = blockNumber(fromBlock, 'fromBlock');
  const to = toBlock == null || toBlock === '' ? head : Math.min(blockNumber(toBlock, 'toBlock'), head);
  const discoveryStarted = performance.now();
  const paddedRecipient = `0x${address.slice(2).padStart(64, '0')}`.toLowerCase();
  const filters = [{ typeId: 5, content: paddedRecipient }];
  const candidateTypeIds = [2, 3, 4, 6];
  const limit = createLimiter(discoveryConcurrency(concurrency));
  const positions = new Map();
  const transactionHashes = new Map();
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
  let cacheValidationRpcCalls = 0;
  let proofsVerified = 0;
  let proofBytes = 0;
  let proofVerificationMs = 0;
  const loaded = await Promise.all(initialTableRanges(from, to, head).map((range) => loadTableRange(range, filters, candidateTypeIds, cache, limit)));
  const missingBlocks = loaded.flatMap((range) => range.missingBlocks);
  for (const candidate of loaded.flatMap((range) => range.attempts)) {
    if (candidate.cacheValidationResponse) {
      rpcCalls += 1;
      cacheValidationRpcCalls += 1;
      responseBytes += candidate.cacheValidationResponse.responseBytes;
      providerRpcMs += candidate.cacheValidationResponse.elapsedMs;
    }
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
  }

  const utxos = [];
  const uncachedPositions = new Map();
  let uptCacheHits = 0;
  for (const [key, position] of positions) {
    const positionCacheKey = `${rpcUrl}|${key}`;
    const cachedBlockHash = cache ? utxoPositionCache.get(positionCacheKey) : null;
    const cached = cachedBlockHash ? utxoRecordCache.get(`${rpcUrl}|${cachedBlockHash}|${key}`) : null;
    if (cached) {
      uptCacheHits += 1;
      utxos.push({ ...cached });
    } else {
      uncachedPositions.set(key, position);
    }
  }

  let uptRpcCalls = 0;
  let uptRootProofRpcCalls = 0;
  let uptBlocksReturned = 0;
  let uptRecordsReturned = 0;
  let uptProofNodes = 0;
  if (uncachedPositions.size > 4096) throw new Error('one wallet scan cannot request more than 4096 uncached UPT records');
  if (uncachedPositions.size > 0) {
    const request = [...uncachedPositions.values()].map((position) => ({
      blockNumber: position.blockNumber,
      transactionIndex: position.transactionIndex,
      logIndex: position.positionIndex,
    }));
    const uptResponse = await limit(() => rpcMeasured('ethrex_getUtxoProofs', [request]));
    rpcCalls += 1;
    uptRpcCalls += 1;
    responseBytes += uptResponse.responseBytes;
    providerRpcMs += uptResponse.elapsedMs;
    if (!uptResponse.result || !Array.isArray(uptResponse.result.blocks)) throw new Error('ethrex_getUtxoProofs returned an invalid response');

    const expectedByBlock = new Map();
    for (const [key, position] of uncachedPositions) {
      const blockKey = String(BigInt(position.blockNumber));
      const expected = expectedByBlock.get(blockKey) || new Map();
      expected.set(key, position);
      expectedByBlock.set(blockKey, expected);
    }
    if (uptResponse.result.blocks.length !== expectedByBlock.size) throw new Error('ethrex_getUtxoProofs omitted or duplicated a requested block');
    const rootSlots = [...new Set(uptResponse.result.blocks.map((block) => `0x${BigInt(block.rootStorageSlot).toString(16)}`))];
    const rootResponse = await limit(() => rpcMeasured('eth_getProof', [VAULT, rootSlots, 'latest']));
    rpcCalls += 1;
    uptRootProofRpcCalls += 1;
    rootChecks += rootSlots.length;
    responseBytes += rootResponse.responseBytes;
    providerRpcMs += rootResponse.elapsedMs;
    const rootValues = new Map((rootResponse.result?.storageProof || []).map((proof) => [BigInt(proof.key).toString(), proof.value]));
    if (rootValues.size !== rootSlots.length) throw new Error('eth_getProof omitted a UPT openings-root slot');

    const returnedKeys = new Set();
    for (const block of uptResponse.result.blocks) {
      const blockKey = BigInt(block.blockNumber).toString();
      const expected = expectedByBlock.get(blockKey);
      if (!expected) throw new Error(`ethrex_getUtxoProofs returned unexpected block ${block.blockNumber}`);
      const rootValue = rootValues.get(BigInt(block.rootStorageSlot).toString());
      if (rootValue == null) throw new Error(`missing vault root for block ${block.blockNumber}`);
      const verified = verifyUptBlock(block, expected, transactionHashes, rootValue, chainId);
      uptBlocksReturned += 1;
      uptRecordsReturned += verified.items.length;
      uptProofNodes += verified.proofNodes;
      for (const item of verified.items) {
        const key = `${BigInt(item.creationBlock)}:${BigInt(item.transactionIndex)}:${BigInt(item.logIndex)}`;
        if (returnedKeys.has(key)) throw new Error(`duplicate verified UPT record ${key}`);
        returnedKeys.add(key);
        utxos.push(item);
        if (cache) {
          const blockHash = item.blockHash.toLowerCase();
          utxoPositionCache.set(`${rpcUrl}|${key}`, blockHash);
          utxoRecordCache.set(`${rpcUrl}|${blockHash}|${key}`, { ...item });
        }
      }
    }
    if (returnedKeys.size !== uncachedPositions.size) throw new Error('UPT response omitted a requested opening');
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
      cacheValidationRpcCalls,
      proofsVerified,
      proofBytes,
      proofVerificationMs: Number(proofVerificationMs.toFixed(3)),
      receiptsFetched: 0,
      receiptRpcCalls: 0,
      uptRpcCalls,
      uptRootProofRpcCalls,
      uptBlocksReturned,
      uptRecordsReturned,
      uptProofNodes,
      uptProofBytes: uptProofNodes * 32,
      uptCacheHits,
      blocksTouched: new Set([...positions.values()].map((entry) => String(entry.blockNumber))).size,
      walletTotalMs,
      walletRpcCalls: enrich ? rpcCalls + utxos.length + 1 : rpcCalls,
      ...enrichment,
    },
  };
}

function resultIdentity(scanResult) {
  const canonical = scanResult.utxos.map((item) => [
    item.creationBlock, item.txHash, item.index, item.source, item.recipient, item.valueWei,
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

export {
  benchmarkDiscovery,
  clearDiscoveryCaches,
  compareDiscovery,
  keccak256,
  openingLeafFromRecord,
  rpc,
  scan,
  scanLogs,
  scanTables,
};
