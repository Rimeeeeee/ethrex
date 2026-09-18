// One connection per tab. Keys never go into storage, cookies, URLs or headers.
export class WalletSession {
  #key = null;
  #address = null;
  #rpc = null;
  #revision = 0;
  #fetch;

  constructor(fetcher = globalThis.fetch.bind(globalThis)) {
    this.#fetch = fetcher;
  }

  async request(path, options = {}) {
    const revision = this.#revision;
    const headers = new Headers(options.headers);
    if (this.#rpc) headers.set('x-utxo-rpc', this.#rpc);
    if (path === '/api/status' && this.#address) headers.set('x-wallet-address', this.#address);
    let body = options.body;
    if (['/api/deposit', '/api/send', '/api/redeem'].includes(path)) {
      if (!this.#key) throw new Error('Connect a wallet first.');
      body = JSON.stringify({ ...JSON.parse(body || '{}'), key: this.#key });
      headers.set('content-type', 'application/json');
    }
    const response = await this.#fetch(path, { ...options, headers, body, cache: 'no-store' });
    const result = await response.json();
    if (revision !== this.#revision) throw new Error('Wallet connection changed; refresh and try again.');
    if (!response.ok || result.error) throw new Error(result.error || 'Request failed.');
    return result;
  }

  async connect(key) {
    const result = await this.request('/api/import', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key }),
    });
    this.#key = key;
    this.#address = result.address;
    this.#revision += 1;
    return result;
  }

  disconnect() {
    this.#key = null;
    this.#address = null;
    this.#revision += 1;
  }

  async setRpc(url) {
    const result = await this.request('/api/rpc', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    this.#rpc = result.rpc;
    this.#revision += 1;
    return result;
  }
}
