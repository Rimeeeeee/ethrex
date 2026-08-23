// Wallet Lab: dependency-free watch/receive/send UI for the live devnet.

const VAULT = '0x0000000000000000000000000000000000008312';
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));

const short = (value) => value ? `${value.slice(0, 8)}…${value.slice(-6)}` : '—';
const weiToEth = (value) => {
  const n = BigInt(value || '0');
  const whole = n / 1_000_000_000_000_000_000n;
  const fraction = (n % 1_000_000_000_000_000_000n).toString().padStart(18, '0').slice(0, 6).replace(/0+$/, '');
  return fraction ? `${whole}.${fraction}` : `${whole}`;
};

function ethToWei(value) {
  const raw = String(value || '').trim();
  if (!/^\d+(\.\d{1,18})?$/.test(raw) || Number(raw) <= 0) throw new Error('Enter a positive ETH amount with up to 18 decimals');
  const [whole, fraction = ''] = raw.split('.');
  return (BigInt(whole) * 1_000_000_000_000_000_000n + BigInt(fraction.padEnd(18, '0') || '0')).toString();
}

async function json(url, options) {
  const r = await fetch(url, options);
  const body = await r.json();
  if (!r.ok || body.error) throw new Error(body.error || `request failed (${r.status})`);
  return body;
}

function button(label, className = 'btn primary') {
  const b = document.createElement('button');
  b.className = className;
  b.textContent = label;
  return b;
}

export function mountWalletLab(root) {
  root.innerHTML = `
    <div class="wallet-lab">
      <div class="wallet-hero">
        <div>
          <div class="eyebrow">EIP-8312 · LIVE WALLET LAB</div>
          <h2>Own the history, spend the claim.</h2>
          <p>Scan the vault for UTXOs addressed to you. Select one, send a fresh UTXO, and keep the opening metadata visible.</p>
        </div>
        <div class="hero-orbit"><span class="orbit-dot"></span><span class="orbit-ring"></span><span class="orbit-ring orbit-ring-2"></span></div>
      </div>
      <div class="wallet-banner" id="wallet-lab-banner"></div>
      <div class="wallet-metrics" id="wallet-lab-metrics"></div>
      <div class="wallet-layout">
        <section class="card wallet-panel">
          <div class="panel-heading"><div><div class="eyebrow">RECEIVE / WATCH</div><h3>Find my UTXOs</h3></div><span class="live-dot"></span></div>
          <p class="dim">A receiver does not need ETH. It only needs its address and a starting block to scan.</p>
          <label class="field-label" for="wallet-watch-address">Recipient address</label>
          <input id="wallet-watch-address" class="wallet-input mono" spellcheck="false" placeholder="0x…20-byte address" />
          <div class="field-row">
            <div><label class="field-label" for="wallet-from-block">Scan from block</label><input id="wallet-from-block" class="wallet-input mono" inputmode="numeric" placeholder="auto: head − 2,000" /></div>
            <div><label class="field-label" for="wallet-to-block">To block</label><input id="wallet-to-block" class="wallet-input mono" placeholder="latest" inputmode="numeric" /></div>
          </div>
          <div class="action-row"><button id="wallet-scan" class="btn primary">Scan vault <span>↗</span></button><span id="wallet-scan-note" class="dim"></span></div>
          <div class="scan-note"><span>◎</span><span>Scanner uses <span class="mono">eth_getLogs</span> on <span class="mono">${VAULT}</span> and checks spent bits before showing a claim as available.</span></div>
        </section>
        <section class="card wallet-panel send-panel">
          <div class="panel-heading"><div><div class="eyebrow">SEND</div><h3>Make a UTXO payment</h3></div><span class="send-lock">⌁</span></div>
          <p class="dim">The local server signs only when <span class="mono">EIP8312_WALLET_KEY</span> is explicitly configured.</p>
          <label class="field-label" for="wallet-input-select">Input UTXO</label>
          <select id="wallet-input-select" class="wallet-input mono"><option value="">Scan first</option></select>
          <label class="field-label" for="wallet-send-recipient">Send to</label>
          <input id="wallet-send-recipient" class="wallet-input mono" spellcheck="false" placeholder="0x…20-byte address" />
          <div class="field-row">
            <div><label class="field-label" for="wallet-send-amount">Amount (ETH)</label><input id="wallet-send-amount" class="wallet-input" inputmode="decimal" placeholder="0.001" /></div>
            <div class="amount-preview"><span>valueWei</span><strong id="wallet-send-wei">—</strong></div>
          </div>
          <div class="action-row"><button id="wallet-send" class="btn accent">Send UTXO <span>→</span></button><span id="wallet-send-note" class="dim"></span></div>
          <div class="security-note"><span>⚿</span><span>No private key field exists in this page. Sending is disabled unless the server operator opted in.</span></div>
        </section>
      </div>
      <section class="card wallet-panel holdings-panel">
        <div class="panel-heading"><div><div class="eyebrow">HOLDINGS</div><h3>UTXO inventory</h3></div><span id="wallet-holdings-count" class="tag">0 claims</span></div>
        <div id="wallet-utxo-table" class="utxo-table empty-state">Scan a recipient address to inspect its claims.</div>
      </section>
      <details class="wallet-details"><summary>What this wallet stores and what it does not</summary><div class="detail-grid"><div><b>Stores locally in memory</b><span>Address, scan range, UTXO index, creation block, source, value, transaction hash.</span></div><div><b>Never stored in the page</b><span>Private keys, seed phrases, or raw signed transactions.</span></div><div><b>Protocol rule</b><span>A UTXO becomes spendable from the block after creation, once its spent bit is still clear.</span></div></div></details>
    </div>`;

  const banner = root.querySelector('#wallet-lab-banner');
  const metrics = root.querySelector('#wallet-lab-metrics');
  const address = root.querySelector('#wallet-watch-address');
  const fromBlock = root.querySelector('#wallet-from-block');
  const toBlock = root.querySelector('#wallet-to-block');
  const scanButton = root.querySelector('#wallet-scan');
  const scanNote = root.querySelector('#wallet-scan-note');
  const select = root.querySelector('#wallet-input-select');
  const recipient = root.querySelector('#wallet-send-recipient');
  const amount = root.querySelector('#wallet-send-amount');
  const weiPreview = root.querySelector('#wallet-send-wei');
  const sendButton = root.querySelector('#wallet-send');
  const sendNote = root.querySelector('#wallet-send-note');
  const table = root.querySelector('#wallet-utxo-table');
  const count = root.querySelector('#wallet-holdings-count');
  let state = { info: null, scan: null };

  function renderMetrics() {
    const utxos = state.scan?.utxos || [];
    const available = utxos.filter((u) => u.spendable);
    const total = available.reduce((sum, u) => sum + BigInt(u.valueWei), 0n);
    metrics.innerHTML = [
      ['CHAIN HEAD', state.info?.head ?? state.scan?.head ?? '—', 'blocks observed'],
      ['AVAILABLE', available.length, `${weiToEth(total.toString())} ETH claimable`],
      ['WATCHING', state.scan ? short(state.scan.address) : '—', state.scan ? `blocks ${state.scan.fromBlock} → ${state.scan.toBlock}` : 'not scanned'],
    ].map(([label, value, note]) => `<div class="metric"><span>${label}</span><strong>${esc(value)}</strong><small>${esc(note)}</small></div>`).join('');
  }

  function renderTable() {
    const utxos = state.scan?.utxos || [];
    count.textContent = `${utxos.length} claim${utxos.length === 1 ? '' : 's'}`;
    if (!utxos.length) {
      table.className = 'utxo-table empty-state';
      table.textContent = state.scan ? 'No UtxoCreated event for this address in the selected range.' : 'Scan a recipient address to inspect its claims.';
      return;
    }
    table.className = 'utxo-table';
    table.innerHTML = `<div class="utxo-row utxo-head"><span>STATUS</span><span>INDEX / BLOCK</span><span>VALUE</span><span>CREATED BY</span><span>TX</span></div>` + utxos.map((u) => `
      <div class="utxo-row ${u.spendable ? 'is-live' : u.spent ? 'is-spent' : 'is-young'}">
        <span><b class="status-chip ${u.spendable ? 'ready' : u.spent ? 'spent' : 'young'}">${u.spendable ? 'AVAILABLE' : u.spent ? 'SPENT' : 'WAITING'}</b></span>
        <span class="mono">#${esc(u.index)} <small>block ${esc(u.creationBlock)}</small></span>
        <span class="value-cell"><b>${esc(weiToEth(u.valueWei))}</b> <small>ETH</small></span>
        <span class="mono dim">${esc(short(u.source))}</span>
        <a class="mono tx-link" href="#" data-tx="${esc(u.txHash)}">${esc(short(u.txHash))}</a>
      </div>`).join('');
    table.querySelectorAll('[data-tx]').forEach((link) => link.onclick = (event) => { event.preventDefault(); navigator.clipboard?.writeText(link.dataset.tx); link.textContent = 'copied'; });
  }

  function renderSelect() {
    const available = state.scan?.utxos?.filter((u) => u.spendable) || [];
    select.innerHTML = available.length ? available.map((u) => `<option value="${esc(u.index)}">#${esc(u.index)} · ${esc(weiToEth(u.valueWei))} ETH · block ${esc(u.creationBlock)}</option>`).join('') : '<option value="">No available UTXOs</option>';
  }

  function selected() {
    const index = Number(select.value);
    return state.scan?.utxos?.find((u) => u.index === index && u.spendable) || null;
  }

  function setBanner() {
    const configured = state.info?.configured;
    banner.className = `wallet-banner ${configured ? 'ready-banner' : 'watch-banner'}`;
    banner.innerHTML = configured
      ? `<span class="banner-icon">✓</span><span><b>Send-enabled local wallet.</b> ${esc(short(state.info.address))} can sign UTXO frames. The page remains key-blind.</span>`
      : `<span class="banner-icon">◌</span><span><b>Watch-only mode.</b> Scanning and receiving inspection are available. Set <span class="mono">EIP8312_WALLET_KEY</span> before starting the server to enable sends.</span>`;
  }

  async function refreshStatus() {
    try {
      state.info = await json('/api/wallet/status');
      setBanner();
      if (!fromBlock.value && state.info.head != null) fromBlock.value = String(Math.max(0, state.info.head - 2_000));
      renderMetrics();
    } catch (error) {
      banner.className = 'wallet-banner error-banner';
      banner.textContent = error.message;
    }
  }

  scanButton.onclick = async () => {
    const target = address.value.trim();
    if (!ADDRESS_RE.test(target)) { scanNote.textContent = 'Enter a valid 20-byte address.'; return; }
    scanButton.disabled = true; scanNote.textContent = 'reading vault logs…';
    try {
      state.scan = await json('/api/wallet/scan', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ address: target, fromBlock: fromBlock.value || 0, toBlock: toBlock.value || undefined }) });
      scanNote.textContent = `${state.scan.utxos.length} event${state.scan.utxos.length === 1 ? '' : 's'} found`;
      renderMetrics(); renderTable(); renderSelect();
    } catch (error) { scanNote.textContent = error.message; }
    scanButton.disabled = false;
  };

  amount.oninput = () => { try { weiPreview.textContent = ethToWei(amount.value); } catch { weiPreview.textContent = '—'; } };
  select.onchange = () => { const u = selected(); if (u && !amount.value) amount.value = weiToEth(u.valueWei); amount.dispatchEvent(new Event('input')); };

  sendButton.onclick = async () => {
    const u = selected();
    if (!u) { sendNote.textContent = 'Select an available UTXO first.'; return; }
    if (!ADDRESS_RE.test(recipient.value.trim())) { sendNote.textContent = 'Enter a valid recipient address.'; return; }
    let valueWei; try { valueWei = ethToWei(amount.value); } catch (error) { sendNote.textContent = error.message; return; }
    if (BigInt(valueWei) > BigInt(u.valueWei)) { sendNote.textContent = 'Amount exceeds this UTXO.'; return; }
    sendButton.disabled = true; sendNote.textContent = 'signing and waiting for inclusion…';
    try {
      const result = await json('/api/wallet/send', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ input: u, recipient: recipient.value.trim(), valueWei }) });
      sendNote.textContent = `sent ${short(result.txHash)} in block ${result.block}`;
      // Refresh the same range so the spent bit and new recipient claim are visible.
      scanButton.click();
    } catch (error) { sendNote.textContent = error.message; }
    sendButton.disabled = false;
  };

  if (state.info?.address) address.value = state.info.address;
  refreshStatus().then(() => { if (state.info?.address) address.value = state.info.address; });
  renderMetrics(); renderTable(); renderSelect();
}
