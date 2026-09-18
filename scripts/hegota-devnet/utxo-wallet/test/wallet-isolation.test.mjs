import assert from 'node:assert/strict';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { WalletSession } from '../public/wallet-session.js';

const KEY_A = `0x${'11'.repeat(32)}`;
const KEY_B = `0x${'22'.repeat(32)}`;
const ADDRESS_A = `0x${'11'.repeat(20)}`;
const ADDRESS_B = `0x${'22'.repeat(20)}`;
const post = (body) => ({ method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
const listen = (server) => new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${server.address().port}`)));
const close = (server) => new Promise((resolve) => server.close(resolve));

test('two browsers independently import, read, sign, change RPC, and disconnect', async (t) => {
  const rpcServers = [1, 2].map((head) => http.createServer(async (req, res) => {
    let input = '';
    for await (const chunk of req) input += chunk;
    const { method } = JSON.parse(input);
    setTimeout(() => res.end(JSON.stringify({ result: method === 'eth_blockNumber' ? `0x${head}` : '0x1' })), 5);
  }));
  const [rpcA, rpcB] = await Promise.all(rpcServers.map(listen));
  t.after(() => Promise.all(rpcServers.map(close)));
  process.env.UTXO_RPC = rpcA;
  process.env.UTXO_PYTHON = process.execPath;
  process.env.UTXO_TXFORGE = fileURLToPath(new URL('./fixtures/wallet-forge.cjs', import.meta.url));
  // An old deployment setting must never expose a shared signer.
  process.env.UTXO_WALLET_KEY = KEY_A;
  const { server } = await import('../server.mjs');
  const base = await listen(server);
  t.after(() => close(server));
  const requests = [];
  const fetcher = (path, options) => {
    requests.push({ path, options });
    return fetch(base + path, options);
  };
  const alice = new WalletSession(fetcher);
  const bob = new WalletSession(fetcher);
  const anonymous = new WalletSession(fetcher);
  await Promise.all([alice.connect(KEY_A), bob.connect(KEY_B)]);
  await bob.setRpc(rpcB);
  const [a, b, visitor] = await Promise.all([alice, bob, anonymous].map((wallet) => wallet.request('/api/status')));
  assert.equal(a.address, ADDRESS_A);
  assert.equal(a.head, 1);
  assert.equal(b.address, ADDRESS_B);
  assert.equal(b.head, 2);
  assert.equal(visitor.address, null);
  assert.equal(visitor.configured, false);
  const deposits = await Promise.all([alice, bob].map((wallet) => wallet.request('/api/deposit', post({ recipient: ADDRESS_A, valueWei: '1' }))));
  assert.deepEqual(deposits.map((r) => [r.source, r.signer, r.rpc]), [[ADDRESS_A, ADDRESS_A, rpcA], [ADDRESS_B, ADDRESS_B, rpcB]]);
  alice.disconnect();
  assert.equal((await alice.request('/api/status')).configured, false);
  assert.equal((await bob.request('/api/status')).address, ADDRESS_B);
  await assert.rejects(alice.request('/api/deposit', post({})), /Connect a wallet first/);
  const reloaded = new WalletSession(fetcher);
  assert.equal((await reloaded.request('/api/status')).configured, false);
  for (const path of ['/api/deposit', '/api/send', '/api/redeem']) {
    const response = await fetch(base + path, { ...post({}), headers: { 'content-type': 'application/json', 'x-wallet-address': ADDRESS_B } });
    assert.equal(response.status, 400);
  }
  for (const { path, options } of requests) {
    assert.ok(!JSON.stringify([...options.headers]).includes(KEY_A));
    assert.ok(!JSON.stringify([...options.headers]).includes(KEY_B));
    if (!['/api/import', '/api/deposit'].includes(path)) assert.ok(!options.body?.includes('"key"'));
  }
});

test('disconnect discards a delayed connection response', async () => {
  let finish;
  const wallet = new WalletSession(() => new Promise((resolve) => { finish = resolve; }));
  const connecting = wallet.connect(KEY_A);
  wallet.disconnect();
  finish({ ok: true, json: async () => ({ configured: true, address: ADDRESS_A }) });
  await assert.rejects(connecting, /connection changed/);
  await assert.rejects(wallet.request('/api/send', post({})), /Connect a wallet first/);
});

test('failed import leaves the current connection usable', async () => {
  const wallet = new WalletSession(async (path, options) => {
    if (path === '/api/import') {
      const valid = JSON.parse(options.body).key === KEY_A;
      return { ok: valid, json: async () => valid ? { address: ADDRESS_A } : { error: 'invalid key' } };
    }
    return { ok: true, json: async () => ({ address: options.headers.get('x-wallet-address') }) };
  });
  await wallet.connect(KEY_A);
  await assert.rejects(wallet.connect('invalid'), /invalid key/);
  assert.equal((await wallet.request('/api/status')).address, ADDRESS_A);
});
