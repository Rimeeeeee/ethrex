import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { authenticatedScan, decodeRlp, encodeRlp, verifyReference, verifySelectiveTable, verifyStorage, verifyTrie } from '../authenticated.mjs';
import { keccak256 } from '../server.mjs';

const fixture = JSON.parse(await readFile(new URL('./authenticated-fixture.json', import.meta.url), 'utf8'));
const hex = (value) => `0x${value.toString('hex')}`;
const bytes = (value) => Buffer.from(value.slice(2), 'hex');
const clone = (value) => structuredClone(value);

test('Rust RPC fixture verifies end to end in two proof calls', async (context) => {
  const original = globalThis.fetch;
  context.after(() => { globalThis.fetch = original; });
  const methods = [];
  globalThis.fetch = async (_, options) => {
    const request = JSON.parse(options.body);
    methods.push(request.method);
    assert.equal(request.params[0].referenceBlockHash, fixture.wallet.referenceBlockHash);
    const result = request.method === 'ethrex_queryEip8304Tables' ? fixture.tli
      : request.method === 'ethrex_getAuthenticatedUtxoProofs' ? fixture.upt : null;
    assert.ok(result, `unexpected RPC ${request.method}`);
    return { text: async () => JSON.stringify({ result }) };
  };
  const result = await authenticatedScan(fixture.wallet);
  assert.equal(result.authenticated, true);
  assert.equal(result.spentStatusVerified, false);
  assert.equal(result.rpcCalls, 2);
  assert.deepEqual(methods, ['ethrex_queryEip8304Tables', 'ethrex_getAuthenticatedUtxoProofs']);
  assert.equal(result.items.length, 1);
  assert.equal(result.items[0].index, 7);
  assert.equal(result.items[0].valueWei, '99');
  assert.equal(result.items[0].recipient, fixture.wallet.address);
  assert.ok(!('blockHash' in result.items[0]));
  assert.ok(!('uptTableHash' in result.items[0]));
});

test('reference and storage verification reject untrusted roots and altered paths', () => {
  const header = verifyReference(fixture.tli.referenceHeader, fixture.wallet.referenceBlockHash);
  const slots = new Set(['1024']);
  const address = fixture.tli.indexProof.address;
  const roots = verifyStorage(header, fixture.tli.indexProof, address, slots);
  assert.equal(roots.get('1024'), BigInt(fixture.tli.tables[0].tableRoot));
  assert.throws(() => verifyReference(fixture.tli.referenceHeader, `0x${'ff'.repeat(32)}`), /trusted hash/);
  for (const mutate of [
    (proof) => { proof.storageProof[0].value = '0x1234'; },
    (proof) => { proof.storageProof[0].key = '0x401'; },
    (proof) => { proof.storageProof[0].proof = []; },
    (proof) => { proof.accountProof = []; },
    (proof) => { proof.address = `0x${'11'.repeat(20)}`; },
    (proof) => { proof.storageProof.push(proof.storageProof[0]); },
    (proof) => { proof.accountProof[0] = `${proof.accountProof[0].slice(0, -2)}00`; },
  ]) {
    const proof = clone(fixture.tli.indexProof); mutate(proof);
    assert.throws(() => verifyStorage(header, proof, address, slots));
  }
});

test('selective proof accounts for accepted and rejected candidates', () => {
  const table = fixture.tli.tables[0];
  const verify = (candidate) => verifySelectiveTable(candidate, fixture.request.queries, fixture.request.tables[0], BigInt(table.tableRoot));
  assert.equal(table.candidates.length, 2);
  assert.equal(verify(table).length, 1);
  for (const mutate of [
    (proof) => { proof.matches = []; },
    (proof) => { proof.candidates.pop(); },
    (proof) => { proof.candidates[0].checks = []; },
    (proof) => { proof.candidates[1].checks[0].present = true; },
    (proof) => { proof.candidates[0].checks[0].present = false; },
    (proof) => { proof.candidates[1].checks[0].index = 0; },
    (proof) => { proof.firstIndex += 1; proof.candidates.shift(); },
    (proof) => { proof.entries.pop(); },
    (proof) => { proof.entries.push(proof.entries[0]); },
    (proof) => { proof.entries[0].encoded = `${proof.entries[0].encoded.slice(0, -2)}ff`; },
    (proof) => { proof.tableRoot = `0x${'ff'.repeat(32)}`; },
    (proof) => { proof.firstBlock = '0x1'; },
    (proof) => { proof.proofNodes.push({ level: 0, nodeIndex: 999, hash: `0x${'00'.repeat(32)}` }); },
  ]) {
    const proof = clone(table); mutate(proof);
    assert.throws(() => verify(proof));
  }
});

test('wallet rejects altered openings and extra blocks without returning partial results', async (context) => {
  const original = globalThis.fetch;
  context.after(() => { globalThis.fetch = original; });
  for (const mutate of [
    (proof) => { proof.blocks[0].records[0].value = '0x1234'; },
    (proof) => { proof.blocks[0].records[0].recipient = `0x${'ff'.repeat(20)}`; },
    (proof) => { proof.blocks[0].rootStorageSlot = '0x2'; },
    (proof) => { proof.blocks[0].chainId = '0xffff'; },
    (proof) => { proof.blocks = []; },
    (proof) => { proof.blocks.push(proof.blocks[0]); },
    (proof) => { proof.vaultProof.storageProof[0].proof = []; },
  ]) {
    const proof = clone(fixture.upt); mutate(proof);
    globalThis.fetch = async (_, options) => ({ text: async () => JSON.stringify({ result:
      JSON.parse(options.body).method === 'ethrex_queryEip8304Tables' ? fixture.tli : proof }) });
    await assert.rejects(authenticatedScan(fixture.wallet));
  }
  await assert.rejects(authenticatedScan({ ...fixture.wallet, referenceBlockNumber: 8192 }));
});

test('strict RLP handles canonical encodings and rejects malleable lengths', () => {
  for (const value of [Buffer.alloc(0), Buffer.from([0x12]), Buffer.alloc(60, 1), [Buffer.from([0]), Buffer.alloc(0)]]) {
    assert.deepEqual(decodeRlp(encodeRlp(value)), value);
  }
  for (const malformed of ['8101', 'b80100', 'b9003800', 'c201', '8080', 'f80180']) {
    assert.throws(() => decodeRlp(Buffer.from(malformed, 'hex')));
  }
});

test('MPT verifies embedded nodes, hashed children, and authenticated absence', () => {
  const key = Buffer.alloc(32); key[31] = 1;
  const compact = Buffer.alloc(32); compact[0] = 0x10; // extension: 63 zero nibbles
  for (const large of [false, true]) {
    const value = Buffer.alloc(large ? 40 : 1, 0x42);
    const leaf = [Buffer.from([0x20]), value];
    const rawLeaf = encodeRlp(leaf);
    const branch = Array.from({ length: 17 }, () => Buffer.alloc(0));
    branch[1] = large ? keccak256(rawLeaf) : leaf;
    branch[2] = large ? keccak256(rawLeaf) : leaf;
    const rawBranch = encodeRlp(branch);
    const rootNode = encodeRlp([compact, large ? keccak256(rawBranch) : branch]);
    const root = keccak256(rootNode);
    const proof = [hex(rootNode), ...(large ? [hex(rawBranch), hex(rawLeaf)] : [])];
    assert.deepEqual(verifyTrie(root, key, proof), value);
    const absent = Buffer.from(key); absent[31] = 3;
    assert.equal(verifyTrie(root, absent, proof), null);
    const divergent = Buffer.from(key); divergent[0] = 1;
    assert.equal(verifyTrie(root, divergent, proof), null);
    assert.throws(() => verifyTrie(root, key, []));
    if (large) assert.throws(() => verifyTrie(root, key, proof.slice(0, 2)));
  }
  assert.equal(verifyTrie(keccak256(Buffer.from([0x80])), key, []), null);
});
