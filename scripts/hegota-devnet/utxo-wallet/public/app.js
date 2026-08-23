const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const KEY_RE = /^(0x)?[0-9a-fA-F]{64}$/;
const WEI = 1000000000000000000n;
const $ = (id) => document.getElementById(id);
const state = {
  status: null,
  scan: null,
  created: null,
  comparison: null,
  compareTablesFirst: false,
  discoveryMethod: "logs",
  section: "holdings",
  holdingFilter: "available"
};

const short = (value) => value ? value.slice(0, 8) + "..." + value.slice(-6) : "";
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
}[c]));

function weiToEth(value) {
  const amount = BigInt(String(value || "0"));
  const whole = amount / WEI;
  const fraction = (amount % WEI).toString().padStart(18, "0").replace(/0+$/, "");
  return fraction ? whole + "." + fraction : String(whole);
}

function compactEth(value, decimals = 6) {
  const amount = BigInt(String(value || "0"));
  if (amount === 0n) return "0";
  const scale = 10n ** BigInt(18 - decimals);
  const rounded = (amount + scale / 2n) / scale;
  const base = 10n ** BigInt(decimals);
  const whole = rounded / base;
  const fraction = rounded % base;
  if (rounded === 0n) return "<0." + "0".repeat(decimals - 1) + "1";
  if (fraction === 0n) return String(whole);
  const fractionText = fraction.toString().padStart(decimals, "0").replace(/0+$/, "");
  return whole + "." + fractionText;
}

function setEthDisplay(id, value) {
  const element = $(id);
  const exact = weiToEth(value);
  element.textContent = compactEth(value);
  element.title = exact + " ETH";
  element.setAttribute("aria-label", exact + " ETH");
}

function ethMarkup(value) {
  const exact = weiToEth(value);
  return '<span class="value-tooltip" title="' + esc(exact) + ' ETH">' +
    esc(compactEth(value)) + ' ETH</span>';
}

function ethToWei(value) {
  const raw = String(value || "").trim();
  if (!/^\d+(\.\d{1,18})?$/.test(raw)) throw new Error("Enter an amount with up to 18 decimals.");
  const [whole, fraction = ""] = raw.split(".");
  const result = BigInt(whole) * WEI + BigInt(fraction.padEnd(18, "0"));
  if (result <= 0n) throw new Error("Enter an amount greater than zero.");
  return result.toString();
}

async function request(path, options) {
  const response = await fetch(path, options);
  const result = await response.json();
  if (!response.ok || result.error) throw new Error(result.error || "Request failed.");
  return result;
}

function available() {
  return state.scan?.utxos?.filter((item) => item.spendable) || [];
}

function aggregateUtxoWei() {
  return available().reduce((sum, item) => sum + BigInt(item.valueWei), 0n);
}

function renderStatus() {
  const connected = Boolean(state.status?.configured);
  $("state-label").textContent = connected ? "CONNECTED" : "WATCH ONLY";
  $("state-label").className = "state-label " + (connected ? "connected" : "");
  $("welcome").hidden = connected;
  $("actions").hidden = !connected;
  $("lock-wallet").hidden = !connected;
  $("lock-wallet").textContent = "Disconnect";
  $("lock-wallet").title = "Disconnect wallet";
  $("lock-wallet").setAttribute("aria-label", "Disconnect wallet");
  $("wallet-address").hidden = !connected;
  if (connected) {
    $("wallet-address").textContent = short(state.status.address);
    $("wallet-address").dataset.address = state.status.address;
  } else {
    $("wallet-address").textContent = "";
  }
  renderBalance();
}

function renderBalance() {
  const account = BigInt(state.status?.accountBalanceWei || "0");
  const utxos = aggregateUtxoWei();
  setEthDisplay("account-balance", account);
  setEthDisplay("utxo-balance", utxos);
  setEthDisplay("total-balance", account + utxos);
}

function renderHoldings() {
  if (state.section === "created") {
    renderCreated();
    return;
  }
  const items = state.scan?.utxos || [];
  const spent = items.filter((item) => item.spent);
  const shown = state.holdingFilter === "spent" ? spent : items.filter((item) => !item.spent);
  $("claim-count").textContent = shown.length ? shown.length + " shown" : "";
  const list = $("holdings-list");
  if (!state.status?.configured) {
    list.innerHTML = '<div class="empty">Connect a wallet to view holdings.</div>';
    renderBalance();
    return;
  }
  if (!shown.length) {
    list.innerHTML = state.holdingFilter === "spent"
      ? '<div class="empty">No spent UTXOs.</div>'
      : '<div class="empty">No available UTXOs.</div>';
    renderBalance();
    return;
  }
  list.innerHTML = shown.map((item) => {
    const status = item.spendable ? "AVAILABLE" : item.spent ? "SPENT" : "WAITING";
    return '<div class="holding-row"><span class="holding-status ' + status.toLowerCase() + '">' +
      status + '</span><span class="holding-value">' + ethMarkup(item.valueWei) +
      '</span><span class="holding-meta">#' + esc(item.index) + ' / block ' +
      esc(item.creationBlock) + '</span></div>';
  }).join("");
  renderBalance();
}

function renderHoldingTabs() {
  $("holding-filters").hidden = state.section === "created";
  const spent = state.holdingFilter === "spent";
  $("available-tab").classList.toggle("active", !spent);
  $("spent-tab").classList.toggle("active", spent);
  $("available-tab").setAttribute("aria-selected", String(!spent));
  $("spent-tab").setAttribute("aria-selected", String(spent));
}

function renderSectionTabs() {
  const created = state.section === "created";
  $("holdings-tab").classList.toggle("active", !created);
  $("created-tab").classList.toggle("active", created);
  $("holdings-tab").setAttribute("aria-selected", String(!created));
  $("created-tab").setAttribute("aria-selected", String(created));
  renderHoldingTabs();
}

function renderCreated() {
  const items = state.created?.utxos || [];
  const list = $("holdings-list");
  $("holding-filters").hidden = true;
  $("claim-count").textContent = items.length ? items.length + " created" : "";
  if (!state.status?.configured) {
    list.innerHTML = '<div class="empty">Connect a wallet to view created UTXOs.</div>';
    return;
  }
  if (!items.length) {
    list.innerHTML = '<div class="empty">No UTXOs created by this wallet yet.</div>';
    return;
  }
  list.innerHTML = items.map((item) => {
    const status = item.spent ? "SPENT" : "LIVE";
    return '<div class="created-row"><span class="holding-status ' + status.toLowerCase() + '">' +
      status + '</span><span class="holding-value">' + ethMarkup(item.valueWei) +
      '</span><span class="holding-meta">to ' + esc(short(item.recipient)) +
      '<small>#' + esc(item.index) + ' / block ' + esc(item.creationBlock) + '</small></span></div>';
  }).join("");
}

function setActivity(message, error = false) {
  $("activity-note").textContent = message || "";
  $("activity-note").className = "activity-note" + (error ? " error" : "");
}

const metric = (label, value) => '<span><b>' + esc(value ?? "â€”") + '</b><small>' + esc(label) + '</small></span>';

function renderDiscovery() {
  const tables = state.discoveryMethod === "tables";
  $("discovery-logs").classList.toggle("active", !tables);
  $("discovery-tables").classList.toggle("active", tables);
  const metrics = state.scan?.metrics;
  $("discovery-status").textContent = state.scan
    ? (tables ? (state.scan.complete ? "TABLES VERIFIED" : "TABLES PARTIAL") : "LOG FILTER")
    : "â€”";
  $("compare-discovery").disabled = !state.status?.address;
  if (!metrics) {
    $("discovery-metrics").innerHTML = '<div class="empty">Connect a wallet to benchmark discovery.</div>';
  } else {
    $("discovery-metrics").innerHTML = [
      metric("wallet total ms", Number(metrics.walletTotalMs || metrics.discoveryMs || 0).toFixed(2)),
      metric("provider RPC ms", Number(metrics.providerRpcMs || 0).toFixed(2)),
      metric("wallet RPC calls", metrics.walletRpcCalls || metrics.rpcCalls),
      metric("response bytes", Number(metrics.responseBytes || 0).toLocaleString()),
      metric(tables ? "tables loaded" : "logs returned", tables ? metrics.tablesLoaded : metrics.logsReturned),
      metric(tables ? "receipts fetched" : "range chunks", tables ? metrics.receiptsFetched : metrics.chunks)
    ].join("");
  }

  if (!state.comparison) {
    $("comparison-result").textContent = "";
    return;
  }
  const logs = state.comparison.receiptLogs.metrics;
  const indexed = state.comparison.eip8304Tables.metrics;
  const logsTotal = logs.walletTotalMs || logs.discoveryMs;
  const indexedTotal = indexed.walletTotalMs || indexed.discoveryMs;
  const ratio = indexedTotal > 0 ? logsTotal / indexedTotal : 0;
  $("comparison-result").innerHTML = '<b>' + (state.comparison.sameResults ? "Same UTXO set" : "RESULT MISMATCH") +
    '</b><span>logs ' + esc(Number(logsTotal).toFixed(2)) + ' ms Â· tables ' +
    esc(Number(indexedTotal).toFixed(2)) + ' ms Â· ' + esc(ratio.toFixed(2)) + 'Ã— logs/table</span>';
}

async function refreshScan() {
  if (!state.status?.address) {
    state.scan = null;
    renderHoldings();
    return;
  }
  const head = Number(state.status.head || 0);
  state.scan = await request("/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      method: state.discoveryMethod,
      address: state.status.address,
      fromBlock: Math.max(0, head - 2000),
      toBlock: head
    })
  });
  renderHoldings();
  renderDiscovery();
}

async function refreshCreated() {
  if (!state.status?.address) {
    state.created = null;
    if (state.section === "created") renderCreated();
    return;
  }
  const head = Number(state.status.head || 0);
  state.created = await request("/api/created", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ address: state.status.address, fromBlock: Math.max(0, head - 2000), toBlock: head })
  });
  if (state.section === "created") renderCreated();
}

async function refresh() {
  state.status = await request("/api/status");
  renderStatus();
  if (!$("table-block").value) $("table-block").placeholder = String(state.status.head || "latest");
  await refreshScan();
  await refreshCreated();
}

function openModal(id) { $(id).hidden = false; }
function closeModal(id) { $(id).hidden = true; }

function selectedInputsFor(amountWei, mode) {
  const requested = BigInt(amountWei || "0");
  const feeReserve = BigInt(available()[0]?.selfFundedFeeReserveWei || "0");
  const required = mode === "withdraw" ? requested + feeReserve : requested;
  const selected = [];
  let total = 0n;
  const candidates = available().slice().sort((a, b) =>
    BigInt(a.valueWei) < BigInt(b.valueWei) ? 1 : -1
  );
  for (const item of candidates) {
    selected.push(item);
    total += BigInt(item.valueWei);
    if (total >= required) break;
  }
  return total >= required
    ? selected.sort((a, b) => a.index - b.index)
    : [];
}

function largestFor(mode) {
  return available().slice().sort((a, b) => {
    const av = BigInt(mode === "withdraw" ? (a.maxSelfFundedOutputWei || "0") : a.valueWei);
    const bv = BigInt(mode === "withdraw" ? (b.maxSelfFundedOutputWei || "0") : b.valueWei);
    return av < bv ? 1 : -1;
  })[0] || null;
}

function createMode() {
  return document.querySelector('input[name="create-mode"]:checked')?.value || "send";
}

function updateSendForm() {
  const mode = createMode();
  $("destination-field").hidden = false;
  $("confirm-send").textContent = mode === "fresh" ? "Create" : "Send";
  if (mode === "fresh") {
    $("send-hint").textContent = "Funded from your account balance.";
    return;
  }
  const item = largestFor(mode);
  if (!item) {
    $("send-hint").textContent = "No available UTXO.";
    return;
  }
  if (!$("send-amount").value) {
    $("send-amount").value = weiToEth(item.valueWei);
  }
  try {
    const amountWei = ethToWei($("send-amount").value);
    const selected = selectedInputsFor(amountWei, mode);
    const selectedTotal = selected.reduce((sum, item) => sum + BigInt(item.valueWei), 0n);
    $("send-hint").textContent = selected.length
      ? selected.length + " UTXO" + (selected.length === 1 ? "" : "s") +
        " selected (" + weiToEth(selectedTotal.toString()) + " ETH)"
      : "Not enough UTXO value.";
  } catch {
    $("send-hint").textContent = weiToEth(item.valueWei) + " ETH available";
  }
}

function openCreate() {
  $("send-error").textContent = "";
  document.querySelector('input[name="create-mode"][value="send"]').checked = true;
  $("send-to").value = "";
  $("send-amount").value = "";
  updateSendForm();
  openModal("send-modal");
  $("send-to").focus();
}

function openWithdraw() {
  $("receive-error").textContent = "";
  const items = available();
  const total = items.reduce((sum, item) => sum + BigInt(item.valueWei), 0n);
  const feeReserve = BigInt(items[0]?.selfFundedFeeReserveWei || "0");
  const max = total > feeReserve ? total - feeReserve : 0n;
  $("receive-amount").value = max ? weiToEth(max.toString()) : "";
  $("withdraw-hint").textContent = items.length
    ? items.length + " UTXO" + (items.length === 1 ? "" : "s") + " selected automatically."
    : "No available UTXO.";
  openModal("receive-modal");
  $("receive-amount").focus();
}

async function connect() {
  const key = $("private-key").value.trim();
  if (!KEY_RE.test(key)) {
    $("connect-error").textContent = "Enter a 32-byte hex key.";
    return;
  }
  $("confirm-connect").disabled = true;
  $("connect-error").textContent = "";
  try {
    const result = await request("/api/import", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ key })
    });
    state.status = { ...state.status, ...result, configured: true };
    $("private-key").value = "";
    closeModal("connect-modal");
    await refresh();
    setActivity("Wallet connected.");
  } catch (error) {
    $("connect-error").textContent = error.message;
  } finally {
    $("confirm-connect").disabled = false;
  }
}

async function createValue() {
  $("send-error").textContent = "";
  const mode = createMode();
  let amountWei;
  try {
    amountWei = ethToWei($("send-amount").value);
  } catch (error) {
    $("send-error").textContent = error.message;
    return;
  }
  const recipient = $("send-to").value.trim();
  if (!ADDRESS_RE.test(recipient)) {
    $("send-error").textContent = "Enter a valid recipient address.";
    return;
  }
  $("confirm-send").disabled = true;
  try {
    const inputs = mode === "fresh" ? [] : selectedInputsFor(amountWei, mode);
    if (mode === "send" && !inputs.length) throw new Error("Not enough available UTXO value.");
    const result = await request(mode === "fresh" ? "/api/deposit" : "/api/send", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(mode === "fresh"
        ? { recipient, valueWei: amountWei }
        : { inputs, recipient, valueWei: amountWei })
    });
    closeModal("send-modal");
    await refresh();
    setActivity(mode === "fresh"
      ? "Created UTXO #" + result.index + "."
      : "Sent " + weiToEth(amountWei) + " ETH as a UTXO.");
  } catch (error) {
    $("send-error").textContent = error.message;
  } finally {
    $("confirm-send").disabled = false;
  }
}

async function withdrawValue() {
  $("receive-error").textContent = "";
  let valueWei;
  try {
    valueWei = ethToWei($("receive-amount").value);
  } catch (error) {
    $("receive-error").textContent = error.message;
    return;
  }
  const inputs = selectedInputsFor(valueWei, "withdraw");
  if (!inputs.length) {
    $("receive-error").textContent = "Not enough available UTXO value.";
    return;
  }
  $("confirm-receive").disabled = true;
  try {
    const result = await request("/api/redeem", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ inputs, valueWei })
    });
    closeModal("receive-modal");
    await refresh();
    setActivity("Withdrew " + weiToEth(valueWei) + " ETH.");
  } catch (error) {
    $("receive-error").textContent = error.message;
  } finally {
    $("confirm-receive").disabled = false;
  }
}

function wireModal(id, closeId, cancelId) {
  $(closeId).onclick = () => closeModal(id);
  $(cancelId).onclick = () => closeModal(id);
  $(id).onclick = (event) => { if (event.target === $(id)) closeModal(id); };
}

$("connect-wallet").onclick = () => openModal("connect-modal");
$("close-connect").onclick = () => closeModal("connect-modal");
$("cancel-connect").onclick = () => closeModal("connect-modal");
$("confirm-connect").onclick = connect;
$("private-key").onkeydown = (event) => { if (event.key === "Enter") connect(); };
$("create-open").onclick = openCreate;
$("withdraw-open").onclick = openWithdraw;
$("confirm-send").onclick = createValue;
$("confirm-receive").onclick = withdrawValue;
$("send-amount").oninput = updateSendForm;
document.querySelectorAll('input[name="create-mode"]').forEach((input) => input.onchange = updateSendForm);
wireModal("send-modal", "close-send", "cancel-send");
wireModal("receive-modal", "close-receive", "cancel-receive");
$("holdings-tab").onclick = () => { state.section = "holdings"; renderSectionTabs(); renderHoldings(); };
$("created-tab").onclick = () => { state.section = "created"; renderSectionTabs(); renderCreated(); };
$("available-tab").onclick = () => { state.holdingFilter = "available"; renderHoldingTabs(); renderHoldings(); };
$("spent-tab").onclick = () => { state.holdingFilter = "spent"; renderHoldingTabs(); renderHoldings(); };

async function selectDiscovery(method) {
  state.discoveryMethod = method;
  state.comparison = null;
  renderDiscovery();
  try {
    await refreshScan();
  } catch (error) {
    setActivity(error.message, true);
  }
}

$("discovery-logs").onclick = () => selectDiscovery("logs");
$("discovery-tables").onclick = () => selectDiscovery("tables");
$("compare-discovery").onclick = async () => {
  const button = $("compare-discovery");
  button.disabled = true;
  button.textContent = "Comparingâ€¦";
  try {
    const head = Number(state.status.head || 0);
    state.comparison = await request("/api/compare-discovery", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        address: state.status.address,
        fromBlock: Math.max(0, head - 2000),
        toBlock: head,
        order: state.compareTablesFirst ? "tablesFirst" : "logsFirst"
      })
    });
    state.compareTablesFirst = !state.compareTablesFirst;
    renderDiscovery();
  } catch (error) {
    setActivity(error.message, true);
  } finally {
    button.disabled = !state.status?.address;
    button.textContent = "Compare both";
  }
};

$("load-table").onclick = async () => {
  const button = $("load-table");
  const rawBlock = $("table-block").value.trim();
  const firstBlock = rawBlock || Number(state.status?.head || 0);
  button.disabled = true;
  $("table-error").textContent = "";
  try {
    const table = await request("/api/table", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ firstBlock, tableSize: Number($("table-size").value) })
    });
    $("table-result").textContent = JSON.stringify(table, null, 2);
  } catch (error) {
    $("table-error").textContent = error.message;
  } finally {
    button.disabled = false;
  }
};

$("wallet-address").onclick = async () => {
  const address = $("wallet-address").dataset.address;
  if (address && navigator.clipboard) {
    await navigator.clipboard.writeText(address);
    setActivity("Address copied.");
  }
};

$("lock-wallet").onclick = async () => {
  await request("/api/lock", { method: "POST" });
  state.status = { ...state.status, configured: false, address: null, accountBalanceWei: "0" };
  state.scan = null;
  state.comparison = null;
  renderStatus();
  renderHoldings();
  renderDiscovery();
  setActivity("Wallet locked.");
};

$("rpc-settings").onclick = () => {
  $("rpc-url").value = state.status?.rpc || "https://rpc1.hegota.ethrex.xyz";
  $("rpc-error").textContent = "";
  openModal("rpc-modal");
};

$("confirm-rpc").onclick = async () => {
  const url = $("rpc-url").value.trim();
  if (!/^https?:\/\/[^\s]+$/i.test(url)) {
    $("rpc-error").textContent = "Use an HTTP(S) endpoint.";
    return;
  }
  $("confirm-rpc").disabled = true;
  try {
    const result = await request("/api/rpc", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url })
    });
    state.status.rpc = result.rpc;
    closeModal("rpc-modal");
    await refresh();
  } catch (error) {
    $("rpc-error").textContent = error.message;
  } finally {
    $("confirm-rpc").disabled = false;
  }
};
wireModal("rpc-modal", "close-rpc", "cancel-rpc");

(async () => {
  try {
    await refresh();
  } catch (error) {
    $("mode-banner").textContent = error.message;
    setActivity(error.message, true);
  }
})();
