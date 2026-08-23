#!/usr/bin/env node
/**
 * Five paired EIP-8312 UTXO wallet scenarios. Each measured block receives at
 * least 100 UTXOs and is discovered once through receipt-log filtering and
 * once through EIP-8304 index tables. Run this from WSL after the combined
 * Kurtosis devnet is healthy.
 */
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(SCRIPT_DIR, '..', '..');
const DEFAULT_ENV = resolve(SCRIPT_DIR, 'benchmark.env');
const TXFORGE = resolve(REPO, 'scripts', 'hegota-devnet', 'utxo-wallet', 'api', 'txforge.py');
const DEFAULT_PYTHON = resolve(REPO, 'scripts', 'hegota-devnet', '.venv', 'bin', 'python');
const VAULT = '0x0000000000000000000000000000000000008312';
const INDEX = '0x0000000000000000000000000000000000008304';
const UTXO_CREATED_TOPIC = '0x3b19241465a47bc187f1d9c7db70834855a907183742a4b63aa824c576296f5e';
const WEI = 1_000_000_000_000_000_000n;

function argument(name, fallback) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : fallback;
}

async function loadEnv(path) {
  if (!existsSync(path)) throw new Error(`configuration not found: ${path}`);
  const text = await readFile(path, 'utf8');
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const separator = line.indexOf('=');
    if (separator < 1) throw new Error(`invalid environment line: ${raw}`);
    const key = line.slice(0, separator).trim();
    let value = line.slice(separator + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (process.env[key] == null) process.env[key] = value;
  }
}

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function parseEth(value, name) {
  if (!/^\d+(\.\d{1,18})?$/.test(value)) throw new Error(`${name} must be an ETH amount with at most 18 decimals`);
  const [whole, fraction = ''] = value.split('.');
  return BigInt(whole) * WEI + BigInt(fraction.padEnd(18, '0'));
}

function asNumber(name, fallback, minimum = 0) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isSafeInteger(value) || value < minimum) throw new Error(`${name} must be an integer >= ${minimum}`);
  return value;
}

function mulberry32(seed) {
  let state = seed >>> 0;
  return () => {
    state += 0x6D2B79F5;
    let value = state;
    value = Math.imul(value ^ value >>> 15, value | 1);
    value ^= value + Math.imul(value ^ value >>> 7, value | 61);
    return ((value ^ value >>> 14) >>> 0) / 4_294_967_296;
  };
}

const sleep = (milliseconds) => new Promise((resolveSleep) => setTimeout(resolveSleep, milliseconds));

function forge(python, command) {
  return new Promise((resolveForge, rejectForge) => {
    const started = performance.now();
    const child = spawn(python, [TXFORGE], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', (error) => rejectForge(new Error(`could not start txforge: ${error.message}`)));
    child.on('close', (code) => {
      let result;
      try { result = JSON.parse(stdout); }
      catch { return rejectForge(new Error(`txforge returned invalid JSON: ${stderr || stdout}`)); }
      if (result.error) return rejectForge(new Error(result.error));
      if (code !== 0) return rejectForge(new Error(stderr || `txforge exited with code ${code}`));
      resolveForge({ ...result, inclusionMs: Number((performance.now() - started).toFixed(3)) });
    });
    child.stdin.end(JSON.stringify({ rpc: process.env.UTXO_RPC, ...command }));
  });
}

function quantity(value) { return Number(BigInt(value)); }

async function waitPastBlock(rpc, block, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const head = quantity(await rpc('eth_blockNumber', []));
    if (head > block) return head;
    await sleep(1_000);
  }
  throw new Error(`chain did not advance past block ${block} within ${timeoutMs} ms`);
}

async function transactionMetrics(rpc, hash) {
  const receipt = await rpc('eth_getTransactionReceipt', [hash]);
  return {
    block: quantity(receipt.blockNumber),
    status: receipt.status,
    gasUsed: quantity(receipt.gasUsed),
    effectiveGasPriceWei: BigInt(receipt.effectiveGasPrice || '0x0').toString(),
  };
}

async function createdUtxosInBlock(rpc, block) {
  const blockTag = `0x${block.toString(16)}`;
  const logs = await rpc('eth_getLogs', [{
    address: VAULT,
    topics: [UTXO_CREATED_TOPIC],
    fromBlock: blockTag,
    toBlock: blockTag,
  }]);
  return logs.length;
}

function csvEscape(value) {
  const text = String(value ?? '');
  return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function htmlEscape(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

function renderReport(results, seed, rpcUrl) {
  const rows = results.flatMap((item) => [
    { scenario: item.scenario, method: 'Receipt logs', className: 'logs', fanoutUtxos: item.correctness.discoveredFanoutUtxos, ...item.receiptLogs.totals },
    { scenario: item.scenario, method: 'Extended EIP-8304', className: 'tables', fanoutUtxos: item.correctness.discoveredFanoutUtxos, ...item.eip8304Tables.totals },
  ]);
  const maximum = Math.max(...rows.map((row) => row.discoveryMs), 1);
  const averages = (method) => {
    const selected = rows.filter((row) => row.className === method);
    return selected.reduce((sum, row) => sum + row.discoveryMs, 0) / selected.length;
  };
  const logsAverage = averages('logs');
  const tablesAverage = averages('tables');
  const allCorrect = results.every((item) => (
    item.correctness.depositSameResults
    && item.correctness.spendSameResults
    && item.correctness.workloadBlockMinimumMet
    && item.correctness.createdFanoutUtxos >= item.correctness.requiredUtxosPerBlock
    && item.correctness.discoveredFanoutUtxos >= item.correctness.requiredUtxosPerBlock
  ));
  const bars = results.map((item) => {
    const logs = item.receiptLogs.totals;
    const tables = item.eip8304Tables.totals;
    return `<section class="case"><h3>Scenario ${item.scenario}: ${htmlEscape(item.route.funder)} â†’ ${htmlEscape(item.route.receiver)} â†’ ${htmlEscape(item.route.destination)}</h3>
      <div class="bar-row"><span>Receipt logs</span><i class="logs" style="width:${Math.max(1, logs.discoveryMs / maximum * 100)}%"></i><b>${logs.discoveryMs.toFixed(2)} ms</b></div>
      <div class="bar-row"><span>EIP-8304</span><i class="tables" style="width:${Math.max(1, tables.discoveryMs / maximum * 100)}%"></i><b>${tables.discoveryMs.toFixed(2)} ms</b></div></section>`;
  }).join('');
  const tableRows = rows.map((row) => `<tr><td>${row.scenario}</td><td>${row.method}</td><td>${row.discoveryMs.toFixed(3)}</td><td>${row.walletTotalMs.toFixed(3)}</td><td>${row.providerRpcMs.toFixed(3)}</td><td>${row.walletRpcCalls}</td><td>${row.responseBytes}</td><td>${row.tablesLoaded || 0}</td><td>${row.entriesExamined || 0}</td><td>${row.logPayloadRpcCalls || 0}</td><td>${row.fanoutUtxos}</td></tr>`).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>EIP-8304 wallet discovery benchmark</title><style>
    :root{color-scheme:dark;font-family:Inter,system-ui,sans-serif;background:#0b0e14;color:#edf2f7}body{max-width:1050px;margin:auto;padding:32px}h1{margin-bottom:4px}.meta{color:#98a6b8}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:24px 0}.card,.case{border:1px solid #273244;border-radius:12px;background:#121824;padding:16px}.card b{display:block;font-size:24px}.card small{color:#98a6b8}.pass{color:#72e2c0}.fail{color:#ff817b}.bar-row{display:grid;grid-template-columns:110px 1fr 100px;align-items:center;gap:10px;margin:9px 0}.bar-row i{display:block;height:13px;border-radius:8px}.logs{background:#9580ff}.tables{background:#72e2c0}.bar-row b{text-align:right;font:12px ui-monospace,monospace}table{width:100%;border-collapse:collapse;margin-top:26px;font-size:12px}th,td{padding:9px;border-bottom:1px solid #273244;text-align:right}th:first-child,td:first-child,th:nth-child(2),td:nth-child(2){text-align:left}@media(max-width:700px){.cards{grid-template-columns:1fr}.bar-row{grid-template-columns:90px 1fr}.bar-row b{grid-column:2}}</style></head><body>
    <h1>EIP-8304 wallet discovery</h1><div class="meta">Seed ${seed} Â· ${htmlEscape(rpcUrl)} Â· five paired scenarios</div>
    <div class="cards"><div class="card"><b>${logsAverage.toFixed(2)} ms</b><small>mean receipt-log discovery</small></div><div class="card"><b>${tablesAverage.toFixed(2)} ms</b><small>mean EIP-8304 discovery</small></div><div class="card"><b class="${allCorrect ? 'pass' : 'fail'}">${allCorrect ? 'MATCH' : 'MISMATCH'}</b><small>result-set correctness</small></div></div>
    ${bars}<table><thead><tr><th>Case</th><th>Method</th><th>Source ms</th><th>Wallet ms</th><th>Provider ms</th><th>Wallet calls</th><th>Bytes</th><th>Tables</th><th>Entries</th><th>Payload RPCs</th><th>Fan-out UTXOs</th></tr></thead><tbody>${tableRows}</tbody></table>
    <p class="meta">Transaction inclusion time and gas are recorded separately in summary.json and comparison.csv; they are chain-change costs, not discovery costs.</p></body></html>`;
}

async function main() {
  const envPath = resolve(argument('--env', DEFAULT_ENV));
  await loadEnv(envPath);
  process.env.UTXO_RPC = process.env.UTXO_RPC || process.env.RPC;
  if (!process.env.UTXO_RPC) throw new Error('UTXO_RPC (or RPC) is required');

  const python = process.env.UTXO_PYTHON || DEFAULT_PYTHON;
  if (!existsSync(python)) throw new Error(`Python environment not found: ${python}; set UTXO_PYTHON`);
  if (!existsSync(TXFORGE)) throw new Error(`txforge not found: ${TXFORGE}`);

  const cases = asNumber('BENCHMARK_CASES', 5, 1);
  if (cases !== 5) throw new Error('BENCHMARK_CASES must be 5 for this experiment');
  const minDelayMs = asNumber('MIN_DELAY_MS', 1_000);
  const maxDelayMs = asNumber('MAX_DELAY_MS', 4_000);
  if (maxDelayMs < minDelayMs) throw new Error('MAX_DELAY_MS must be >= MIN_DELAY_MS');
  const minDeposit = parseEth(process.env.MIN_DEPOSIT_ETH || '0.020', 'MIN_DEPOSIT_ETH');
  const maxDeposit = parseEth(process.env.MAX_DEPOSIT_ETH || '0.030', 'MAX_DEPOSIT_ETH');
  if (maxDeposit < minDeposit) throw new Error('MAX_DEPOSIT_ETH must be >= MIN_DEPOSIT_ETH');
  const utxosPerBlock = asNumber('UTXOS_PER_BLOCK', 100, 100);
  const seed = asNumber('BENCHMARK_SEED', Date.now() & 0xffffffff);
  const random = mulberry32(seed);
  const randomInteger = (minimum, maximum) => minimum + Math.floor(random() * (maximum - minimum + 1));
  const randomBigInt = (minimum, maximum) => {
    const sample = BigInt(Math.floor(random() * 4_294_967_296));
    return minimum + ((maximum - minimum + 1n) * sample) / 4_294_967_296n;
  };
  const blockTimeoutMs = asNumber('BLOCK_TIMEOUT_MS', 180_000, 1);

  const funders = [1, 2].map((number) => ({
    name: `funded-${number}`,
    address: required(`FUNDED_${number}_ADDRESS`).toLowerCase(),
    key: required(`FUNDED_${number}_PRIVATE_KEY`),
  }));
  const receivingInspectors = [1, 2].map((number) => ({
    name: `inspect-${number}`,
    address: required(`INSPECT_${number}_ADDRESS`).toLowerCase(),
    key: required(`INSPECT_${number}_PRIVATE_KEY`),
  }));
  const destinationInspectors = [3, 4].map((number) => ({
    name: `inspect-${number}`,
    address: required(`INSPECT_${number}_ADDRESS`).toLowerCase(),
    key: required(`INSPECT_${number}_PRIVATE_KEY`),
  }));
  const allWallets = [...funders, ...receivingInspectors, ...destinationInspectors];
  for (const wallet of allWallets) {
    const derived = (await forge(python, { op: 'addressOf', key: wallet.key })).address.toLowerCase();
    if (derived !== wallet.address) throw new Error(`${wallet.name}: configured address ${wallet.address} does not match private key (${derived})`);
  }

  const { compareDiscovery, rpc } = await import('../hegota-devnet/utxo-wallet/server.mjs');
  const [vaultCode, indexCode, headHex, gasPriceHex] = await Promise.all([
    rpc('eth_getCode', [VAULT, 'latest']),
    rpc('eth_getCode', [INDEX, 'latest']),
    rpc('eth_blockNumber', []),
    rpc('eth_gasPrice', []),
  ]);
  if (vaultCode === '0x') throw new Error(`EIP-8312 vault has no code at ${VAULT}`);
  if (indexCode === '0x') throw new Error(`EIP-8304 index contract has no code at ${INDEX}`);
  const initialHead = quantity(headHex);
  const tableProbe = await rpc('ethrex_getEip8304Table', [`0x${initialHead.toString(16)}`, '0x1']);
  if (!tableProbe) throw new Error(`EIP-8304 table is unavailable at current head ${initialHead}; wait for activation`);
  const committedRoot = await rpc('eth_getStorageAt', [INDEX, tableProbe.storageSlot, `0x${initialHead.toString(16)}`]);
  if (committedRoot.toLowerCase() !== tableProbe.tableRoot.toLowerCase()) throw new Error('EIP-8304 preflight root verification failed');

  const gasPrice = BigInt(gasPriceHex);
  const balancesBefore = {};
  for (const wallet of allWallets) balancesBefore[wallet.name] = BigInt(await rpc('eth_getBalance', [wallet.address, 'latest'])).toString();
  if ((process.env.REQUIRE_ZERO_INSPECTOR_BALANCE || '1') !== '0') {
    for (const inspector of [...receivingInspectors, ...destinationInspectors]) {
      if (BigInt(balancesBefore[inspector.name]) !== 0n) {
        throw new Error(`${inspector.name} must start with zero normal-account ETH; set REQUIRE_ZERO_INSPECTOR_BALANCE=0 to override`);
      }
    }
  }
  for (let index = 0; index < funders.length; index += 1) {
    const assignedCases = Math.floor((cases + (funders.length - 1 - index)) / funders.length);
    const gasCushion = gasPrice * 500_000n * BigInt(assignedCases);
    const requiredBalance = maxDeposit * BigInt(assignedCases) + (gasCushion > WEI / 100n ? gasCushion : WEI / 100n);
    const actual = BigInt(balancesBefore[funders[index].name]);
    if (actual < requiredBalance) {
      throw new Error(`${funders[index].name} has ${actual} wei; at least ${requiredBalance} wei is required for ${assignedCases} cases`);
    }
  }

  const watchStartBlock = initialHead + 1;
  const outputRoot = resolve(process.env.BENCHMARK_OUTPUT_DIR || resolve(SCRIPT_DIR, 'results'));
  const runId = new Date().toISOString().replaceAll(':', '-').replaceAll('.', '-');
  const runStartedEpoch = Date.now();
  const runStartedAt = new Date(runStartedEpoch).toISOString();
  const outputDir = resolve(outputRoot, runId);
  await mkdir(outputDir, { recursive: true });
  const caseResults = [];

  console.log(`RPC: ${process.env.UTXO_RPC}`);
  console.log(`Seed: ${seed}; discovery starts at block ${watchStartBlock}; writing ${outputDir}`);
  for (let caseIndex = 0; caseIndex < cases; caseIndex += 1) {
    const caseStartedAt = new Date();
    const number = caseIndex + 1;
    const funder = funders[caseIndex % funders.length];
    const receiver = receivingInspectors[randomInteger(0, receivingInspectors.length - 1)];
    const destination = destinationInspectors[randomInteger(0, destinationInspectors.length - 1)];
    const delayMs = randomInteger(minDelayMs, maxDelayMs);
    const valueWei = randomBigInt(minDeposit, maxDeposit);
    const forwardBasisPoints = randomInteger(5_500, 7_500);
    const forwardValueWei = valueWei * BigInt(forwardBasisPoints) / 10_000n;
    const fanoutValueWei = forwardValueWei / BigInt(utxosPerBlock);
    const fanoutRemainder = forwardValueWei % BigInt(utxosPerBlock);
    if (fanoutValueWei === 0n) {
      throw new Error(`case ${number}: deposit is too small to create ${utxosPerBlock} positive-value UTXOs`);
    }
    const fanoutOutputs = Array.from({ length: utxosPerBlock }, (_, outputIndex) => ({
      recipient: destination.address,
      valueWei: (fanoutValueWei + (BigInt(outputIndex) < fanoutRemainder ? 1n : 0n)).toString(),
    }));

    console.log(`[${number}/5] waiting ${delayMs} ms; ${funder.name} -> ${receiver.name} -> ${utxosPerBlock} outputs for ${destination.name}`);
    await sleep(delayMs);
    const deposit = await forge(python, {
      op: 'deposit', key: funder.key, recipient: receiver.address, valueWei: valueWei.toString(),
    });
    if (deposit.status !== '0x1' || deposit.index == null) {
      throw new Error(`case ${number}: deposit failed (${deposit.txHash}, gasUsed=${deposit.gasUsed ?? 'unknown'})`);
    }
    const depositHead = await waitPastBlock(rpc, deposit.block, blockTimeoutMs);
    const depositComparison = await compareDiscovery({
      address: receiver.address,
      fromBlock: watchStartBlock,
      toBlock: depositHead,
      order: caseIndex % 2 ? 'tablesFirst' : 'logsFirst',
    });
    if (!depositComparison.sameResults || !depositComparison.eip8304Tables.complete) {
      throw new Error(`case ${number}: deposit discovery was incomplete or methods returned different UTXO sets`);
    }
    const opening = depositComparison.receiptLogs.utxos.find((item) => item.index === deposit.index && item.txHash.toLowerCase() === deposit.txHash.toLowerCase());
    if (!opening || !opening.spendable) throw new Error(`case ${number}: deposited UTXO #${deposit.index} was not discovered as spendable`);

    const spend = await forge(python, {
      op: 'spend',
      actorKeys: [receiver.key],
      inputs: [opening],
      utxoOuts: [
        ...fanoutOutputs,
        { recipient: receiver.address, valueWei: '0' },
      ],
      accountOuts: [],
      changeIndex: fanoutOutputs.length,
    });
    if (spend.status !== '0x1') throw new Error(`case ${number}: inspector spend failed (${spend.txHash})`);
    const forwarded = spend.created.filter((item) => item.recipient.toLowerCase() === destination.address);
    if (forwarded.length < utxosPerBlock) {
      throw new Error(`case ${number}: fan-out created ${forwarded.length} destination UTXOs; expected at least ${utxosPerBlock}`);
    }
    const forwardedTotal = forwarded.reduce((sum, item) => sum + BigInt(item.valueWei), 0n);
    if (forwardedTotal !== forwardValueWei) {
      throw new Error(`case ${number}: fan-out value ${forwardedTotal} does not match expected ${forwardValueWei}`);
    }
    const blockUtxosCreated = await createdUtxosInBlock(rpc, spend.block);
    if (blockUtxosCreated < utxosPerBlock) {
      throw new Error(`case ${number}: workload block ${spend.block} created only ${blockUtxosCreated} UTXOs; expected at least ${utxosPerBlock}`);
    }
    const spendHead = await waitPastBlock(rpc, spend.block, blockTimeoutMs);
    const spendComparison = await compareDiscovery({
      address: destination.address,
      fromBlock: spend.block,
      toBlock: spend.block,
      order: caseIndex % 2 ? 'logsFirst' : 'tablesFirst',
    });
    if (!spendComparison.sameResults || !spendComparison.eip8304Tables.complete) {
      throw new Error(`case ${number}: forwarded discovery was incomplete or methods returned different UTXO sets`);
    }
    const forwardedIndexes = new Set(forwarded.map((item) => item.index));
    const discoveredForward = spendComparison.receiptLogs.utxos.filter((item) => (
      item.txHash.toLowerCase() === spend.txHash.toLowerCase() && forwardedIndexes.has(item.index)
    ));
    if (discoveredForward.length < utxosPerBlock) {
      throw new Error(`case ${number}: wallet discovered ${discoveredForward.length} fan-out UTXOs; expected at least ${utxosPerBlock}`);
    }

    // Only the exact fan-out block contributes to benchmark totals. The
    // one-output deposit is bootstrap state needed to construct the spend.
    const receiptLogMetrics = spendComparison.receiptLogs.metrics;
    const tableMetrics = spendComparison.eip8304Tables.metrics;
    const result = {
      scenario: number,
      timing: {
        startedAt: caseStartedAt.toISOString(),
        completedAt: new Date().toISOString(),
        elapsedMs: Date.now() - caseStartedAt.getTime(),
      },
      random: { delayMs, forwardBasisPoints },
      route: { funder: funder.name, receiver: receiver.name, destination: destination.name },
      values: {
        depositWei: valueWei.toString(),
        forwardedWei: forwardValueWei.toString(),
        fanoutBaseValueWei: fanoutValueWei.toString(),
      },
      blocks: { watchStartBlock, depositHead, spendHead, workloadBlock: spend.block, workloadUtxosCreated: blockUtxosCreated },
      transactions: {
        deposit: { ...deposit, ...(await transactionMetrics(rpc, deposit.txHash)) },
        spend: { ...spend, ...(await transactionMetrics(rpc, spend.txHash)) },
      },
      correctness: {
        depositSameResults: depositComparison.sameResults,
        spendSameResults: spendComparison.sameResults,
        depositReceiptLogHash: depositComparison.receiptLogResultHash,
        depositTableHash: depositComparison.eip8304ResultHash,
        spendReceiptLogHash: spendComparison.receiptLogResultHash,
        spendTableHash: spendComparison.eip8304ResultHash,
        requiredUtxosPerBlock: utxosPerBlock,
        createdFanoutUtxos: forwarded.length,
        discoveredFanoutUtxos: discoveredForward.length,
        workloadBlockMinimumMet: blockUtxosCreated >= utxosPerBlock,
      },
      receiptLogs: {
        depositDiscovery: depositComparison.receiptLogs.metrics,
        spendDiscovery: spendComparison.receiptLogs.metrics,
        totals: receiptLogMetrics,
      },
      eip8304Tables: {
        depositDiscovery: depositComparison.eip8304Tables.metrics,
        spendDiscovery: spendComparison.eip8304Tables.metrics,
        totals: tableMetrics,
      },
    };
    caseResults.push(result);
    await writeFile(resolve(outputDir, 'cases.jsonl'), caseResults.map((item) => JSON.stringify(item)).join('\n') + '\n');
    console.log(`  block=${spend.block} created=${blockUtxosCreated} fan-out=${forwarded.length} discovered=${discoveredForward.length}`);
    console.log(`  logs=${receiptLogMetrics.discoveryMs.toFixed(2)}ms tables=${tableMetrics.discoveryMs.toFixed(2)}ms calls=${receiptLogMetrics.rpcCalls}/${tableMetrics.rpcCalls}`);
  }

  const balancesAfter = {};
  for (const wallet of allWallets) balancesAfter[wallet.name] = BigInt(await rpc('eth_getBalance', [wallet.address, 'latest'])).toString();
  const rows = [['scenario', 'method', 'source_discovery_ms', 'wallet_total_ms', 'provider_rpc_ms', 'table_load_us', 'source_rpc_calls', 'wallet_rpc_calls', 'response_bytes', 'tables_loaded', 'entries_examined', 'matched_positions', 'root_checks', 'receipts_fetched', 'selected_logs_returned', 'log_payload_rpc_calls', 'logs_returned', 'range_blocks', 'utxos_required_per_block', 'utxos_created_in_workload_block', 'fanout_utxos_created', 'fanout_utxos_discovered', 'scenario_elapsed_ms', 'deposit_inclusion_ms', 'spend_inclusion_ms', 'deposit_gas', 'spend_gas', 'same_results']];
  for (const item of caseResults) {
    for (const [method, value] of [['receiptLogs', item.receiptLogs], ['eip8304Tables', item.eip8304Tables]]) {
      const metrics = value.totals;
      rows.push([
        item.scenario, method, metrics.discoveryMs, metrics.walletTotalMs, metrics.providerRpcMs,
        metrics.providerTableLoadMicros, metrics.rpcCalls, metrics.walletRpcCalls,
        metrics.responseBytes, metrics.tablesLoaded, metrics.entriesExamined,
        metrics.matchedPositions, metrics.rootChecks, metrics.receiptsFetched,
        metrics.selectedLogsReturned, metrics.logPayloadRpcCalls, metrics.logsReturned,
        1,
        item.correctness.requiredUtxosPerBlock, item.blocks.workloadUtxosCreated,
        item.correctness.createdFanoutUtxos, item.correctness.discoveredFanoutUtxos,
        item.timing.elapsedMs,
        item.transactions.deposit.inclusionMs, item.transactions.spend.inclusionMs,
        item.transactions.deposit.gasUsed, item.transactions.spend.gasUsed,
        item.correctness.depositSameResults && item.correctness.spendSameResults,
      ]);
    }
  }
  const summary = {
    runId,
    startedAt: runStartedAt,
    completedAt: new Date().toISOString(),
    elapsedMs: Date.now() - runStartedEpoch,
    rpc: process.env.UTXO_RPC,
    seed,
    cases,
    utxosPerBlock,
    initialHead,
    watchStartBlock,
    range: { minDelayMs, maxDelayMs, minDepositWei: minDeposit.toString(), maxDepositWei: maxDeposit.toString() },
    contracts: { vault: VAULT, index: INDEX },
    balancesBefore,
    balancesAfter,
    scenarios: caseResults,
  };
  await Promise.all([
    writeFile(resolve(outputDir, 'summary.json'), JSON.stringify(summary, null, 2) + '\n'),
    writeFile(resolve(outputDir, 'comparison.csv'), rows.map((row) => row.map(csvEscape).join(',')).join('\n') + '\n'),
    writeFile(resolve(outputDir, 'report.html'), renderReport(caseResults, seed, process.env.UTXO_RPC)),
  ]);
  console.table(caseResults.flatMap((item) => [
    { scenario: item.scenario, method: 'receiptLogs', milliseconds: item.receiptLogs.totals.discoveryMs, rpcCalls: item.receiptLogs.totals.rpcCalls, bytes: item.receiptLogs.totals.responseBytes },
    { scenario: item.scenario, method: 'eip8304Tables', milliseconds: item.eip8304Tables.totals.discoveryMs, rpcCalls: item.eip8304Tables.totals.rpcCalls, bytes: item.eip8304Tables.totals.responseBytes },
  ]));
  console.log(`Results: ${outputDir}`);
}

main().catch((error) => {
  console.error(`benchmark failed: ${error.stack || error.message}`);
  process.exitCode = 1;
});
