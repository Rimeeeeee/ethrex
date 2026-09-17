// Proof verification for the experimental authenticated RPC profile.
// No provider-reported root or block number is accepted as a trust anchor.
import { keccak256, decodeTableEntry, verifyTableMultiproof, verifyUptBlock, initialTableRanges, rpc } from './server.mjs';

const INDEX = '0x0000000000000000000000000000000000008304';
const VAULT = '0x0000000000000000000000000000000000008312';
const TOPIC = '0x3b19241465a47bc187f1d9c7db70834855a907183742a4b63aa824c576296f5e';
function requireProof(condition, message) { if (!condition) throw new Error(message); }
const hex = (bytes) => `0x${bytes.toString('hex')}`;
function bytes(value, length) {
  requireProof(typeof value === 'string' && /^0x(?:[0-9a-f]{2})*$/i.test(value), 'invalid proof hex');
  const result = Buffer.from(value.slice(2), 'hex');
  requireProof(length == null || result.length === length, 'invalid proof byte length');
  return result;
}
function integer(value, max = Number.MAX_SAFE_INTEGER) {
  requireProof(Number.isSafeInteger(value) && value >= 0 && value <= max, 'invalid proof integer');
  return value;
}
function uint(value) {
  requireProof(Buffer.isBuffer(value) && value.length <= 32 && (value.length === 0 || value[0] !== 0), 'non-canonical RLP integer');
  return value.length ? BigInt(hex(value)) : 0n;
}
function word(value) {
  const n = BigInt(value);
  requireProof(n >= 0n && n < 1n << 256n, 'storage slot exceeds uint256');
  return Buffer.from(n.toString(16).padStart(64, '0'), 'hex');
}

// Strict RLP parsing matters for both hashed and embedded trie nodes.
export function decodeRlp(input) {
  const parse = (offset, limit, depth) => {
    requireProof(depth < 128 && offset < limit, 'truncated or deeply nested RLP');
    const tag = input[offset];
    if (tag < 0x80) return [input.subarray(offset, offset + 1), offset + 1];
    const list = tag >= 0xc0;
    const short = list ? 0xc0 : 0x80;
    const long = list ? 0xf7 : 0xb7;
    let start = offset + 1;
    let length = tag - short;
    if (tag > long) {
      const size = tag - long;
      requireProof(size <= 6 && start + size <= limit && input[start] !== 0, 'invalid RLP length');
      length = 0;
      for (let i = 0; i < size; i += 1) length = length * 256 + input[start + i];
      requireProof(length >= 56, 'non-canonical long RLP');
      start += size;
    }
    const end = start + length;
    requireProof(end <= limit, 'truncated RLP payload');
    if (!list) {
      requireProof(length !== 1 || input[start] >= 0x80, 'non-canonical short RLP');
      return [input.subarray(start, end), end];
    }
    const items = [];
    while (start < end) {
      const [item, next] = parse(start, end, depth + 1);
      items.push(item); start = next;
    }
    return [items, end];
  };
  const [value, end] = parse(0, input.length, 0);
  requireProof(end === input.length, 'trailing RLP data');
  return value;
}

export function encodeRlp(value) {
  const list = Array.isArray(value);
  const payload = list ? Buffer.concat(value.map(encodeRlp)) : value;
  if (!list && payload.length === 1 && payload[0] < 0x80) return payload;
  const base = list ? 0xc0 : 0x80;
  if (payload.length < 56) return Buffer.concat([Buffer.from([base + payload.length]), payload]);
  let length = payload.length.toString(16);
  if (length.length % 2) length = `0${length}`;
  const size = Buffer.from(length, 'hex');
  return Buffer.concat([Buffer.from([base + 55 + size.length]), size, payload]);
}

const nibbles = (value) => [...value].flatMap((byte) => [byte >> 4, byte & 15]);

export function verifyTrie(root, key, proof) {
  requireProof(root.length === 32 && key.length === 32 && Array.isArray(proof) && proof.length <= 128, 'invalid trie proof');
  const nodes = new Map();
  let total = 0;
  for (const item of proof) {
    const raw = bytes(item);
    total += raw.length;
    requireProof(total <= 1024 * 1024, 'trie proof is too large');
    nodes.set(hex(keccak256(raw)), raw);
  }
  if (root.equals(keccak256(Buffer.from([0x80])))) return null;
  const path = nibbles(key);
  let reference = root;
  let offset = 0;
  for (let step = 0; step < 130; step += 1) {
    let node;
    if (Array.isArray(reference)) {
      requireProof(encodeRlp(reference).length < 32, 'oversized embedded trie node');
      node = reference;
    } else {
      requireProof(Buffer.isBuffer(reference) && reference.length === 32, 'invalid trie child reference');
      const raw = nodes.get(hex(reference));
      requireProof(raw != null && (step === 0 || raw.length >= 32), 'missing or non-canonical trie node');
      node = decodeRlp(raw);
    }
    requireProof(Array.isArray(node), 'trie node must be a list');
    if (node.length === 17) {
      if (offset === path.length) {
        requireProof(Buffer.isBuffer(node[16]), 'invalid branch value');
        return node[16].length ? node[16] : null;
      }
      reference = node[path[offset++]];
      if (Buffer.isBuffer(reference) && reference.length === 0) return null;
    } else {
      requireProof(node.length === 2 && Buffer.isBuffer(node[0]) && node[0].length > 0, 'invalid trie short node');
      const encodedPath = nibbles(node[0]);
      const flag = encodedPath[0];
      requireProof(flag <= 3 && (flag % 2 === 1 || encodedPath[1] === 0), 'invalid compact trie path');
      const segment = encodedPath.slice(flag % 2 ? 1 : 2);
      const leaf = flag >= 2;
      requireProof(leaf || segment.length > 0, 'empty extension path');
      if (segment.some((n, i) => path[offset + i] !== n)) return null;
      offset += segment.length;
      if (leaf) {
        requireProof(Buffer.isBuffer(node[1]), 'invalid trie leaf value');
        return offset === path.length ? node[1] : null;
      }
      requireProof(offset < path.length, 'extension exceeds trie key');
      reference = node[1];
    }
  }
  throw new Error('trie proof exceeds path length');
}

export function verifyReference(headerHex, trustedHash) {
  const raw = bytes(headerHex);
  requireProof(keccak256(raw).equals(bytes(trustedHash, 32)), 'reference header does not match trusted hash');
  const header = decodeRlp(raw);
  requireProof(Array.isArray(header) && header.length >= 15 && Buffer.isBuffer(header[3]) && header[3].length === 32, 'invalid reference header');
  const number = uint(header[8]);
  requireProof(number <= BigInt(Number.MAX_SAFE_INTEGER), 'reference block exceeds wallet precision');
  return { number: Number(number), stateRoot: header[3] };
}

export function verifyStorage(header, accountProof, address, expectedSlots) {
  requireProof(accountProof?.address?.toLowerCase() === address.toLowerCase(), 'wrong commitment account');
  const value = verifyTrie(header.stateRoot, keccak256(bytes(address, 20)), accountProof.accountProof);
  requireProof(value != null, 'commitment account is absent');
  const account = decodeRlp(value);
  requireProof(Array.isArray(account) && account.length === 4 && Buffer.isBuffer(account[2]) && account[2].length === 32, 'invalid commitment account');
  const slots = new Map();
  requireProof(Array.isArray(accountProof.storageProof) && accountProof.storageProof.length === expectedSlots.size, 'missing or extra storage proofs');
  for (const item of accountProof.storageProof) {
    const slot = BigInt(item.key).toString();
    requireProof(expectedSlots.has(slot) && !slots.has(slot), 'unexpected or duplicate storage proof');
    const encoded = verifyTrie(account[2], keccak256(word(item.key)), item.proof);
    const actual = encoded == null ? 0n : uint(decodeRlp(encoded));
    requireProof(actual === BigInt(item.value), 'storage proof value mismatch');
    slots.set(slot, actual);
  }
  return slots;
}

const position = (entry) => `${entry.blockNumber}:${entry.transactionIndex}:${entry.positionIndex}`;
const prefix = (query) => Buffer.concat([Buffer.from([0, query.typeId]), bytes(query.content, query.typeId === 2 ? 20 : 32)]);

export function verifySelectiveTable(table, filters, range, authenticatedRoot) {
  requireProof(BigInt(table.firstBlock) === BigInt(range.firstBlock) && BigInt(table.tableSize) === BigInt(range.tableSize), 'wrong table range');
  requireProof(BigInt(table.tableRoot) === authenticatedRoot && bytes(table.tableRoot, 32).length === 32, 'unauthenticated table root');
  const count = integer(table.entryCount);
  requireProof(Array.isArray(table.entries) && table.entries.length <= 32768, 'invalid table entries');
  const entries = new Map();
  for (const item of table.entries) {
    const index = integer(item.index, count - 1);
    requireProof(!entries.has(index), 'duplicate table entry');
    const decoded = decodeTableEntry(item.encoded);
    entries.set(index, { ...decoded, encoded: item.encoded, leafIndex: index });
  }
  const get = (index) => {
    requireProof(entries.has(index), `missing selected entry ${index}`);
    return entries.get(index);
  };
  // Reuse the existing SSZ table multiproof verifier, deriving every decoded
  // field ourselves from the single wire encoding.
  requireProof(Array.isArray(table.proofNodes) && table.proofNodes.length <= 32768, 'invalid table nodes');
  for (const node of table.proofNodes) { integer(node.level, 53); integer(node.nodeIndex); bytes(node.hash, 32); }
  if (count === 0) requireProof(table.proofNodes.length === 0, 'extraneous empty table nodes');
  verifyTableMultiproof(table, [...entries.values()]);
  const seed = integer(table.seedQuery, filters.length - 1);
  const first = integer(table.firstIndex, count);
  const end = integer(table.endIndexExclusive, count);
  requireProof(end >= first && end - first <= 4096 && Array.isArray(table.candidates) && table.candidates.length === end - first, 'incomplete candidate range');
  const seedPrefix = prefix(filters[seed]);
  if (first > 0) requireProof(Buffer.compare(bytes(get(first - 1).encoded), seedPrefix) < 0, 'invalid lower posting boundary');
  if (end < count) {
    const upper = bytes(get(end).encoded);
    requireProof(Buffer.compare(upper, seedPrefix) > 0 && !upper.subarray(0, seedPrefix.length).equals(seedPrefix), 'invalid upper posting boundary');
  }
  const matched = new Map();
  for (let index = first; index < end; index += 1) {
    const entry = get(index);
    const raw = bytes(entry.encoded);
    requireProof(raw.subarray(0, seedPrefix.length).equals(seedPrefix), 'incorrect seed posting');
    requireProof(entry.blockNumber >= BigInt(range.firstBlock) && entry.blockNumber < BigInt(range.firstBlock) + BigInt(range.tableSize), 'event outside table range');
    const candidate = table.candidates[index - first];
    requireProof(candidate.seedIndex === index && Array.isArray(candidate.checks) && candidate.checks.length === filters.length - 1, 'missing candidate checks');
    const seen = new Set([seed]);
    let match = true;
    for (const check of candidate.checks) {
      const queryIndex = integer(check.queryIndex, filters.length - 1);
      requireProof(!seen.has(queryIndex) && typeof check.present === 'boolean', 'duplicate or invalid filter check');
      seen.add(queryIndex);
      const key = Buffer.concat([prefix(filters[queryIndex]), raw.subarray(raw.length - 16)]);
      const offset = integer(check.index, count);
      if (check.present) requireProof(bytes(get(offset).encoded).equals(key), 'incorrect membership proof');
      else {
        if (offset > 0) requireProof(Buffer.compare(bytes(get(offset - 1).encoded), key) < 0, 'invalid lower absence boundary');
        if (offset < count) requireProof(Buffer.compare(bytes(get(offset).encoded), key) > 0, 'invalid upper absence boundary');
        match = false;
      }
    }
    if (match) matched.set(index, entry);
  }
  requireProof(Array.isArray(table.matches) && table.matches.length === matched.size, 'omitted or extra matches');
  const results = [];
  const seen = new Set();
  for (const match of table.matches) {
    const event = matched.get(match.seedIndex);
    requireProof(event != null && !seen.has(match.seedIndex), 'unexpected or duplicate match');
    seen.add(match.seedIndex);
    const tx = get(match.transaction);
    requireProof(tx.typeId === 1 && tx.blockNumber === event.blockNumber && tx.transactionIndex === event.transactionIndex, 'incorrect transaction evidence');
    const fields = new Map();
    requireProof(Array.isArray(match.fields) && match.fields.length <= 5, 'invalid match fields');
    for (const index of match.fields) {
      const field = get(index);
      requireProof(field.typeId >= 2 && field.typeId <= 6 && !fields.has(field.typeId) && position(field) === position(event), 'incorrect related field');
      fields.set(field.typeId, field);
    }
    results.push({ event, fields, transactionHash: tx.content });
  }
  return results;
}

// The caller supplies a trusted hash AND number (the latter only plans the
// request and is checked against the authenticated header before acceptance).
export async function authenticatedScan({ address, referenceBlockHash, referenceBlockNumber, chainId, fromBlock, toBlock } = {}) {
  bytes(address, 20); bytes(referenceBlockHash, 32);
  const head = integer(referenceBlockNumber);
  const from = integer(fromBlock);
  const to = integer(toBlock ?? head);
  requireProof(chainId != null && BigInt(chainId) >= 0n, 'chainId is required');
  requireProof(from <= to && to <= head && head - from < 8192, 'scan is outside the reference window');
  const filters = [{ typeId: 2, content: VAULT }, { typeId: 3, content: TOPIC }, { typeId: 5, content: `0x${address.slice(2).padStart(64, '0')}` }];
  const ranges = initialTableRanges(from, to, head);
  const positions = new Map();
  const transactions = new Map();
  let rpcCalls = 0;
  for (let offset = 0; offset < ranges.length; offset += 32) {
    const batch = ranges.slice(offset, offset + 32);
    const response = await rpc('ethrex_queryEip8304Tables', [{ referenceBlockHash, tables: batch, queries: filters }]);
    rpcCalls += 1;
    requireProof(response.format === 'ethrex-authenticated-tli-v1', 'unsupported authenticated TLI format');
    const header = verifyReference(response.referenceHeader, referenceBlockHash);
    requireProof(header.number === head, 'reference block number mismatch');
    const slotFor = ({ firstBlock, tableSize }) => BigInt(tableSize) * 1024n + BigInt(firstBlock / tableSize) % 1024n;
    for (const range of batch) {
      const commitment = range.firstBlock + range.tableSize - 1 + (range.tableSize === 1 ? 0 : range.tableSize / 4);
      requireProof(commitment <= head && head - commitment < range.tableSize * 1024, 'table commitment has expired');
    }
    const roots = verifyStorage(header, response.indexProof, INDEX, new Set(batch.map((range) => slotFor(range).toString())));
    requireProof(Array.isArray(response.tables) && response.tables.length === batch.length, 'missing tables');
    for (let i = 0; i < batch.length; i += 1) {
      for (const result of verifySelectiveTable(response.tables[i], filters, batch[i], roots.get(slotFor(batch[i]).toString()))) {
        const recipient = result.fields.get(5);
        const source = result.fields.get(4);
        const index = result.fields.get(6);
        requireProof(recipient && source && index && recipient.content.toLowerCase() === filters[2].content.toLowerCase(), 'missing native UTXO fields');
        const sourceWord = bytes(source.content, 32);
        const indexWord = bytes(index.content, 32);
        requireProof(sourceWord.subarray(0, 12).equals(Buffer.alloc(12)) && indexWord.subarray(0, 24).equals(Buffer.alloc(24)), 'non-canonical UTXO topics');
        const key = position(recipient);
        requireProof(!positions.has(key), 'duplicate discovered position');
        positions.set(key, { ...recipient, source: hex(sourceWord.subarray(12)), index: indexWord.readBigUInt64BE(24) });
        transactions.set(`${recipient.blockNumber}:${recipient.transactionIndex}`, result.transactionHash);
      }
    }
  }
  const byBlock = new Map();
  for (const [key, entry] of positions) {
    const block = entry.blockNumber.toString();
    if (!byBlock.has(block)) byBlock.set(block, new Map());
    byBlock.get(block).set(key, entry);
  }
  const items = [];
  // Batches obey both server bounds: 32 blocks and 4096 positions.
  const pending = [...byBlock.entries()].flatMap(([block, entries]) => [...entries].map(([key, entry]) => ({ block, key, entry })));
  while (pending.length) {
    const requested = new Map();
    const batch = [];
    while (pending.length && batch.length < 4096) {
      const next = pending[0];
      if (!requested.has(next.block) && requested.size === 32) break;
      pending.shift();
      if (!requested.has(next.block)) requested.set(next.block, new Map());
      requested.get(next.block).set(next.key, next.entry);
      batch.push({ blockNumber: `0x${next.entry.blockNumber.toString(16)}`, transactionIndex: `0x${next.entry.transactionIndex.toString(16)}`, logIndex: `0x${next.entry.positionIndex.toString(16)}` });
    }
    const response = await rpc('ethrex_getAuthenticatedUtxoProofs', [{ referenceBlockHash, positions: batch }]);
    rpcCalls += 1;
    requireProof(response.format === 'ethrex-authenticated-upt-v1', 'unsupported authenticated UPT format');
    const header = verifyReference(response.referenceHeader, referenceBlockHash);
    const roots = verifyStorage(header, response.vaultProof, VAULT, new Set([...requested.keys()].map((block) => (1n + BigInt(block) % 8192n).toString())));
    requireProof(Array.isArray(response.blocks) && response.blocks.length === requested.size, 'missing UPT blocks');
    const seen = new Set();
    for (const block of response.blocks) {
      const number = BigInt(block.blockNumber).toString();
      requireProof(requested.has(number) && !seen.has(number), 'unexpected UPT block');
      seen.add(number);
      const slot = 1n + BigInt(number) % 8192n;
      requireProof(BigInt(block.rootStorageSlot) === slot, 'incorrect UPT ring slot');
      const verified = verifyUptBlock(block, requested.get(number), transactions, roots.get(slot.toString()), BigInt(chainId));
      for (const item of verified.items) {
        // Opening proofs do not authenticate these availability-object hashes.
        delete item.blockHash; delete item.uptTableHash;
        items.push(item);
      }
    }
  }
  return { address: address.toLowerCase(), referenceBlockHash: referenceBlockHash.toLowerCase(), referenceBlockNumber: head, fromBlock: from, toBlock: to, authenticated: true, spentStatusVerified: false, rpcCalls, items };
}
