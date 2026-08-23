#!/usr/bin/env node
/**
 * Sparse EIP-8312 wallet history for comparing receipt-log discovery with
 * EIP-8304 aggregated tables over a range of at least 100 blocks.
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
const WEI = 1_000_000_000_000_000_000n;

function argument(name, fallback) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : fallback;
}

async function loadEnv(path) {
  if (!existsSync(path)) throw new Error(`configuration not found: ${path}`);
  const contents = await readFile(path, 'utf8');
  for (const raw of contents.split(/\r?\n/)) {
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

function integer(name, fallback, minimum = 0) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isSafeInteger(value) || value < minimum) throw new Error(`${name} must be an integer >= ${minimum}`);
  return value;
}

function parseEth(value, name) {
  if (!/^\d+(\.\d{1,18})?$/.test(value)) throw new Error(`${name} must be an ETH amount with at most 18 decimals`);
  const [whole, fraction = ''] = value.split('.');
  return BigInt(whole) * WEI + BigInt(fraction.padEnd(18, '0'));
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
const quantity = (value) => Number(BigInt(value));
const alignUp = (value, alignment) => Math.ceil(value / alignment) * alignment;

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

async function waitForBlock(rpc, target, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const head = quantity(await rpc('eth_blockNumber', []));
    if (head >= target) return head;
    await sleep(1_000);
  }
  throw new Error(`chain did not reach block ${target} within ${timeoutMs} ms`);
}

async function openingFor(scanLogs, wallet, block, index) {
  const scan = await scanLogs({ address: wallet.address, fromBlock: block, toBlock: block });
  const opening = scan.utxos.find((item) => item.index === index);
  if (!opening) throw new Error(`${wallet.name}: UTXO #${index} was not found in block ${block}`);
  return opening;
}

function csvEscape(value) {
  const text = String(value ?? '');
  return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function htmlEscape(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

function renderReport(summary) {
  const eventRows = summary.events.map((event) => `<tr><td>${event.number}</td><td>${event.block}</td><td>${event.actualGapBlocks ?? '-'}</td><td>${htmlEscape(event.source)}</td><td>${htmlEscape(event.destination)}</td><td>${event.selfTransfer ? 'yes' : 'no'}</td><td>${event.outputIndex}</td><td>${event.gasUsed}</td></tr>`).join('');
  const comparisonRows = summary.comparisons.flatMap((comparison) => [
    ['Receipt logs', 'receiptLogs', comparison.receiptLogs],
    ['Proof query + selected logs', 'eip8304Tables', comparison.eip8304Tables],
  ].map(([method, key, result]) => `<tr><td>${htmlEscape(comparison.wallet)}</td><td>${method}</td><td>${result.metrics.discoveryMs.toFixed(3)}</td><td>${comparison.statistics[key].discoveryMs.median.toFixed(3)}</td><td>${comparison.statistics[key].discoveryMs.p95.toFixed(3)}</td><td>${comparison.statistics[key].rpcCalls.median}</td><td>${comparison.statistics[key].responseBytes.median}</td><td>${result.metrics.tablesLoaded || 0}</td><td>${result.metrics.logPayloadRpcCalls || 0}</td><td>${result.utxoCount}</td><td>${comparison.sameResults ? 'match' : 'mismatch'}</td></tr>`)).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sparse EIP-8304 wallet benchmark</title><style>:root{color-scheme:dark;font-family:Inter,system-ui,sans-serif;background:#0b0e14;color:#edf2f7}body{max-width:1100px;margin:auto;padding:32px}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.card{background:#121824;border:1px solid #273244;border-radius:12px;padding:16px}.card b{display:block;font-size:25px}.card small,.meta{color:#98a6b8}table{width:100%;border-collapse:collapse;margin:24px 0;font-size:12px}th,td{padding:9px;border-bottom:1px solid #273244;text-align:right}th:first-child,td:first-child{text-align:left}.pass{color:#72e2c0}@media(max-width:700px){.cards{grid-template-columns:1fr}}</style></head><body><h1>Sparse EIP-8304 wallet discovery</h1><p class="meta">Seed ${summary.seed} · blocks ${summary.scan.firstBlock}–${summary.scan.endBlock} · ${summary.configuration.discoveryRepetitions} measured runs after ${summary.configuration.discoveryWarmups} warmups</p><div class="cards"><div class="card"><b>${summary.scan.blockCount}</b><small>blocks scanned</small></div><div class="card"><b>${summary.events.length}</b><small>sparse UTXO changes</small></div><div class="card"><b class="pass">MATCH</b><small>all cold and measured result hashes</small></div></div><h2>Random UTXO route</h2><table><thead><tr><th>Event</th><th>Block</th><th>Gap</th><th>Source</th><th>Destination</th><th>Self</th><th>UTXO</th><th>Gas</th></tr></thead><tbody>${eventRows}</tbody></table><h2>Sparse wallet scans</h2><table><thead><tr><th>Wallet</th><th>Method</th><th>Cold ms</th><th>Median ms</th><th>p95 ms</th><th>Median calls</th><th>Median bytes</th><th>Tables</th><th>Payload RPCs</th><th>UTXOs</th><th>Correctness</th></tr></thead><tbody>${comparisonRows}</tbody></table></body></html>`;
}

async function main() {
  const envPath = resolve(argument('--env', DEFAULT_ENV));
  await loadEnv(envPath);
  process.env.UTXO_RPC = process.env.UTXO_RPC || process.env.RPC;
  if (!process.env.UTXO_RPC) throw new Error('UTXO_RPC (or RPC) is required');

  const python = process.env.UTXO_PYTHON || DEFAULT_PYTHON;
  if (!existsSync(python)) throw new Error(`Python environment not found: ${python}; set UTXO_PYTHON`);
  if (!existsSync(TXFORGE)) throw new Error(`txforge not found: ${TXFORGE}`);

  const seed = integer('BENCHMARK_SEED', Date.now() & 0xffffffff);
  const random = mulberry32(seed);
  const randomInteger = (minimum, maximum) => minimum + Math.floor(random() * (maximum - minimum + 1));
  const eventCount = integer('SPARSE_EVENTS', 5, 2);
  const minGapBlocks = integer('SPARSE_MIN_GAP_BLOCKS', 25, 1);
  const maxGapBlocks = integer('SPARSE_MAX_GAP_BLOCKS', 30, minGapBlocks);
  const scanBlocks = integer('SPARSE_SCAN_BLOCKS', 144, 100);
  const tableSettlementBlocks = integer('SPARSE_TABLE_SETTLEMENT_BLOCKS', 16, 16);
  const waitTimeoutMs = integer('SPARSE_WAIT_TIMEOUT_MS', 900_000, 1);
  const discoveryWarmups = integer('DISCOVERY_WARMUPS', 2, 0);
  const discoveryRepetitions = integer('DISCOVERY_REPETITIONS', 7, 1);
  const discoveryConcurrency = integer('UTXO_DISCOVERY_CONCURRENCY', 8, 1);
  const seedValueWei = parseEth(process.env.SPARSE_SEED_ETH || '0.050', 'SPARSE_SEED_ETH');
  if (scanBlocks % 16 !== 0) throw new Error('SPARSE_SCAN_BLOCKS must be a multiple of 16 so aggregated EIP-8304 tables can be used');
  if ((eventCount - 1) * minGapBlocks < 100) throw new Error('event count and minimum gap must span at least 100 blocks');
  if ((eventCount - 1) * maxGapBlocks + 8 > scanBlocks) throw new Error('SPARSE_SCAN_BLOCKS is too short for the configured event count and maximum gap');

  const funders = [1, 2].map((number) => ({
    name: `funded-${number}`,
    address: required(`FUNDED_${number}_ADDRESS`).toLowerCase(),
    key: required(`FUNDED_${number}_PRIVATE_KEY`),
  }));
  const inspectors = [1, 2, 3, 4].map((number) => ({
    name: `inspect-${number}`,
    address: required(`INSPECT_${number}_ADDRESS`).toLowerCase(),
    key: required(`INSPECT_${number}_PRIVATE_KEY`),
  }));
  const inspectorsByAddress = new Map(inspectors.map((wallet) => [wallet.address, wallet]));

  for (const wallet of [...funders, ...inspectors]) {
    const derived = (await forge(python, { op: 'addressOf', key: wallet.key })).address.toLowerCase();
    if (derived !== wallet.address) throw new Error(`${wallet.name}: address does not match its configured private key`);
  }

  const { benchmarkDiscovery, rpc, scanLogs } = await import('../hegota-devnet/utxo-wallet/server.mjs');
  const [vaultCode, indexCode, preflightHeadHex, gasPriceHex] = await Promise.all([
    rpc('eth_getCode', [VAULT, 'latest']),
    rpc('eth_getCode', [INDEX, 'latest']),
    rpc('eth_blockNumber', []),
    rpc('eth_gasPrice', []),
  ]);
  if (vaultCode === '0x') throw new Error(`EIP-8312 vault has no code at ${VAULT}`);
  if (indexCode === '0x') throw new Error(`EIP-8304 index contract has no code at ${INDEX}`);
  const preflightHead = quantity(preflightHeadHex);
  const tableProbe = await rpc('ethrex_getEip8304Table', [`0x${preflightHead.toString(16)}`, '0x1']);
  if (!tableProbe) throw new Error(`EIP-8304 table is unavailable at current head ${preflightHead}`);
  const committedRoot = await rpc('eth_getStorageAt', [INDEX, tableProbe.storageSlot, preflightHeadHex]);
  if (committedRoot.toLowerCase() !== tableProbe.tableRoot.toLowerCase()) throw new Error('EIP-8304 preflight root verification failed');

  const maxFeePerGas = BigInt(gasPriceHex) * 2n > 2_000_000_000n ? BigInt(gasPriceHex) * 2n : 2_000_000_000n;
  const worstCaseSpendReserve = maxFeePerGas * 400_000n * BigInt(eventCount);
  if (seedValueWei <= worstCaseSpendReserve) {
    throw new Error(`SPARSE_SEED_ETH must exceed the conservative ${worstCaseSpendReserve} wei spend-fee reserve`);
  }
  for (const funder of funders) {
    const balance = BigInt(await rpc('eth_getBalance', [funder.address, 'latest']));
    const requiredBalance = seedValueWei + maxFeePerGas * 250_000n;
    if (balance < requiredBalance) throw new Error(`${funder.name} has ${balance} wei; at least ${requiredBalance} wei is required`);
  }

  const runId = `sparse-${new Date().toISOString().replaceAll(':', '-').replaceAll('.', '-')}`;
  const outputDir = resolve(process.env.BENCHMARK_OUTPUT_DIR || resolve(SCRIPT_DIR, 'results'), runId);
  await mkdir(outputDir, { recursive: true });

  console.log('Creating two bootstrap UTXOs outside the measured range');
  const tokens = [];
  for (let index = 0; index < funders.length; index += 1) {
    const owner = inspectors[index];
    const deposit = await forge(python, {
      op: 'deposit', key: funders[index].key, recipient: owner.address, valueWei: seedValueWei.toString(),
    });
    if (deposit.status !== '0x1' || deposit.index == null) throw new Error(`${funders[index].name}: bootstrap deposit failed`);
    tokens.push({
      id: index + 1,
      owner,
      opening: await openingFor(scanLogs, owner, deposit.block, deposit.index),
      bootstrap: { ...deposit, funder: funders[index].name },
    });
  }

  const headAfterBootstrap = quantity(await rpc('eth_blockNumber', []));
  const scanStartBlock = alignUp(headAfterBootstrap + 2, 16);
  const scanEndBlock = scanStartBlock + scanBlocks - 1;
  const tablesReadyBlock = scanEndBlock + tableSettlementBlocks;
  console.log(`Measured range: ${scanStartBlock}-${scanEndBlock} (${scanBlocks} blocks)`);
  console.log(`Waiting for first event window at block ${scanStartBlock}`);
  await waitForBlock(rpc, scanStartBlock - 1, waitTimeoutMs);

  const events = [];
  for (let eventIndex = 0; eventIndex < eventCount; eventIndex += 1) {
    let requestedGapBlocks = null;
    if (eventIndex > 0) {
      requestedGapBlocks = randomInteger(minGapBlocks, maxGapBlocks);
      const targetBlock = events.at(-1).block + requestedGapBlocks;
      console.log(`Waiting for event ${eventIndex + 1}/${eventCount} near block ${targetBlock}`);
      await waitForBlock(rpc, targetBlock - 1, waitTimeoutMs);
    }

    // Exercise both bootstrap UTXOs at least once, then select a live token at random.
    const tokenIndex = eventIndex < tokens.length ? eventIndex : randomInteger(0, tokens.length - 1);
    const token = tokens[tokenIndex];
    const source = token.owner;
    const destination = inspectors[randomInteger(0, inspectors.length - 1)];
    const spend = await forge(python, {
      op: 'spend',
      actorKeys: [source.key],
      inputs: [token.opening],
      utxoOuts: [{ recipient: destination.address, valueWei: '0' }],
      accountOuts: [],
      changeIndex: 0,
    });
    if (spend.status !== '0x1' || spend.created.length !== 1) {
      throw new Error(`event ${eventIndex + 1}: expected one successful replacement UTXO (${spend.txHash})`);
    }
    if (spend.block > scanEndBlock) throw new Error(`event ${eventIndex + 1} landed after measured range at block ${spend.block}`);
    const created = spend.created[0];
    const opening = await openingFor(scanLogs, destination, spend.block, created.index);
    const previousEvent = events.at(-1);
    const event = {
      number: eventIndex + 1,
      token: token.id,
      block: spend.block,
      requestedGapBlocks,
      actualGapBlocks: previousEvent ? spend.block - previousEvent.block : null,
      source: source.name,
      sourceAddress: source.address,
      destination: destination.name,
      destinationAddress: destination.address,
      selfTransfer: source.address === destination.address,
      inputIndex: token.opening.index,
      outputIndex: created.index,
      outputValueWei: created.valueWei,
      txHash: spend.txHash,
      gasUsed: spend.gasUsed,
      inclusionMs: spend.inclusionMs,
    };
    if (previousEvent && event.actualGapBlocks < requestedGapBlocks) {
      throw new Error(`event ${event.number}: actual gap ${event.actualGapBlocks} is below requested gap ${requestedGapBlocks}`);
    }
    events.push(event);
    token.owner = inspectorsByAddress.get(destination.address);
    token.opening = opening;
    await writeFile(resolve(outputDir, 'events.jsonl'), events.map((item) => JSON.stringify(item)).join('\n') + '\n');
    console.log(`  block=${event.block} token=${event.token} ${event.source} -> ${event.destination}${event.selfTransfer ? ' (self)' : ''}`);
  }

  if (events.at(-1).block - events[0].block < 100) throw new Error('generated event history spans fewer than 100 blocks');
  console.log(`Waiting until block ${tablesReadyBlock} so aggregated EIP-8304 commitments are available`);
  await waitForBlock(rpc, tablesReadyBlock, waitTimeoutMs);

  const comparisons = [];
  for (let index = 0; index < inspectors.length; index += 1) {
    const wallet = inspectors[index];
    const benchmark = await benchmarkDiscovery({
      address: wallet.address,
      fromBlock: scanStartBlock,
      toBlock: scanEndBlock,
      enrich: false,
      warmups: discoveryWarmups,
      repetitions: discoveryRepetitions,
      concurrency: discoveryConcurrency,
    });
    const comparison = benchmark.cold;
    const expectedIndexes = events.filter((event) => event.destinationAddress === wallet.address).map((event) => event.outputIndex);
    const discoveredIndexes = new Set(comparison.receiptLogs.utxos.map((item) => item.index));
    if (!expectedIndexes.every((utxoIndex) => discoveredIndexes.has(utxoIndex))) {
      throw new Error(`${wallet.name}: at least one generated sparse UTXO was not discovered`);
    }
    comparisons.push({
      wallet: wallet.name,
      address: wallet.address,
      expectedGeneratedIndexes: expectedIndexes,
      sameResults: comparison.sameResults,
      receiptLogResultHash: comparison.receiptLogResultHash,
      eip8304ResultHash: comparison.eip8304ResultHash,
      receiptLogs: { metrics: comparison.receiptLogs.metrics, utxoCount: comparison.receiptLogs.utxos.length },
      eip8304Tables: { metrics: comparison.eip8304Tables.metrics, utxoCount: comparison.eip8304Tables.utxos.length, tables: comparison.eip8304Tables.tables },
      warmups: benchmark.warmups,
      repetitions: benchmark.repetitions,
      statistics: benchmark.statistics,
      samples: benchmark.samples.map((sample) => ({
        iteration: sample.iteration,
        order: sample.order,
        receiptLogs: { metrics: sample.receiptLogs.metrics, utxoCount: sample.receiptLogs.utxos.length },
        eip8304Tables: { metrics: sample.eip8304Tables.metrics, utxoCount: sample.eip8304Tables.utxos.length },
      })),
    });
    console.log(`  ${wallet.name}: cold logs=${comparison.receiptLogs.metrics.discoveryMs}ms query=${comparison.eip8304Tables.metrics.discoveryMs}ms; median logs=${benchmark.statistics.receiptLogs.discoveryMs.median}ms query=${benchmark.statistics.eip8304Tables.discoveryMs.median}ms UTXOs=${comparison.receiptLogs.utxos.length}`);
  }

  const summary = {
    runId,
    completedAt: new Date().toISOString(),
    rpc: process.env.UTXO_RPC,
    seed,
    configuration: { eventCount, minGapBlocks, maxGapBlocks, scanBlocks, tableSettlementBlocks, seedValueWei: seedValueWei.toString(), discoveryWarmups, discoveryRepetitions, discoveryConcurrency },
    scan: { firstBlock: scanStartBlock, endBlock: scanEndBlock, blockCount: scanBlocks, tablesReadyBlock },
    bootstrap: tokens.map((token) => token.bootstrap),
    events,
    comparisons,
  };
  const csvRows = [['wallet', 'phase', 'iteration', 'order', 'method', 'discovery_ms', 'wallet_total_ms', 'provider_rpc_ms', 'table_load_us', 'query_us', 'source_rpc_calls', 'wallet_rpc_calls', 'response_bytes', 'tables_loaded', 'entries_returned', 'full_table_entries', 'matched_positions', 'root_checks', 'query_cache_hits', 'root_cache_hits', 'proofs_verified', 'proof_bytes', 'proof_verification_ms', 'receipts_fetched', 'logs_returned', 'utxos_found', 'scan_blocks', 'same_results']];
  for (const comparison of comparisons) {
    const runs = [
      { phase: 'cold', iteration: 0, order: 'logsFirst', receiptLogs: comparison.receiptLogs, eip8304Tables: comparison.eip8304Tables },
      ...comparison.samples.map((sample) => ({ phase: 'measured', ...sample })),
    ];
    for (const run of runs) {
      for (const [method, result] of [['receiptLogs', run.receiptLogs], ['eip8304Tables', run.eip8304Tables]]) {
        const metrics = result.metrics;
        csvRows.push([
          comparison.wallet, run.phase, run.iteration, run.order, method, metrics.discoveryMs,
          metrics.walletTotalMs, metrics.providerRpcMs, metrics.providerTableLoadMicros,
          metrics.providerQueryMicros, metrics.rpcCalls, metrics.walletRpcCalls, metrics.responseBytes,
          metrics.tablesLoaded, metrics.entriesExamined, metrics.fullTableEntries, metrics.matchedPositions,
          metrics.rootChecks, metrics.queryCacheHits, metrics.rootCacheHits, metrics.proofsVerified,
          metrics.proofBytes, metrics.proofVerificationMs, metrics.receiptsFetched, metrics.logsReturned,
          result.utxoCount, scanBlocks, comparison.sameResults,
        ]);
      }
    }
  }
  await Promise.all([
    writeFile(resolve(outputDir, 'summary.json'), JSON.stringify(summary, null, 2) + '\n'),
    writeFile(resolve(outputDir, 'comparison.csv'), csvRows.map((row) => row.map(csvEscape).join(',')).join('\n') + '\n'),
    writeFile(resolve(outputDir, 'report.html'), renderReport(summary)),
  ]);
  console.log(`Results: ${outputDir}`);
}

main().catch((error) => {
  console.error(`sparse benchmark failed: ${error.stack || error.message}`);
  process.exitCode = 1;
});
