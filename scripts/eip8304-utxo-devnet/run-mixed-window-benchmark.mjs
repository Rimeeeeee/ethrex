#!/usr/bin/env node
/**
 * Continuous mixed-address EIP-8312 workload. Every activity transaction has
 * four independently signed routes and creates 70-100 UTXOs in one block.
 * The same early UTXO is located through receipt logs and root-verified
 * extended EIP-8304 tables with selected log payloads over 100- and 150-block
 * windows.
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
    await sleep(500);
  }
  throw new Error(`chain did not reach block ${target} within ${timeoutMs} ms`);
}

async function countBlockUtxos(rpc, block) {
  const tag = `0x${block.toString(16)}`;
  const logs = await rpc('eth_getLogs', [{
    address: VAULT,
    topics: [UTXO_CREATED_TOPIC],
    fromBlock: tag,
    toBlock: tag,
  }]);
  return logs.length;
}

function allocateDestinationOutputs(totalUtxos, routeCount, randomInteger) {
  const destinationTotal = totalUtxos - routeCount;
  if (destinationTotal < routeCount) throw new Error('total UTXOs cannot provide a destination and change output for every route');
  const counts = Array(routeCount).fill(1);
  for (let remaining = destinationTotal - routeCount; remaining > 0; remaining -= 1) {
    counts[randomInteger(0, routeCount - 1)] += 1;
  }
  return counts;
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
  const checkpointRows = summary.checkpoints.flatMap((checkpoint) => [
    ['Receipt logs', 'receiptLogs', checkpoint.receiptLogs],
    ['Proof query + selected logs', 'eip8304Tables', checkpoint.eip8304Tables],
  ].map(([method, key, result]) => {
    const statistics = checkpoint.statistics[key];
    return `<tr><td>${checkpoint.windowBlocks}</td><td>${method}</td><td>${result.discoveryMs.toFixed(3)}</td><td>${statistics.discoveryMs.median.toFixed(3)}</td><td>${statistics.discoveryMs.p95.toFixed(3)}</td><td>${statistics.rpcCalls.median}</td><td>${statistics.responseBytes.median}</td><td>${result.tablesLoaded || 0}</td><td>${result.logPayloadRpcCalls || 0}</td><td>${result.candidates}</td><td>${result.found ? 'found' : 'missing'}</td></tr>`;
  })).join('');
  const recentBlocks = summary.activity.slice(-12).map((activity) => `<tr><td>${activity.block}</td><td>${activity.targetUtxos}</td><td>${activity.actualUtxos}</td><td>${activity.gapFromPrevious ?? '-'}</td><td>${activity.routes.map((route) => `${htmlEscape(route.source)}→${htmlEscape(route.destination)} (${route.destinationUtxos})`).join('<br>')}</td><td>${activity.gasUsed}</td><td>${activity.confirmation?.reorgs || 0}</td><td>${activity.confirmation?.resubmissions || 0}</td></tr>`).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Mixed-address EIP-8304 benchmark</title><style>:root{color-scheme:dark;font-family:Inter,system-ui,sans-serif;background:#0b0e14;color:#edf2f7}body{max-width:1100px;margin:auto;padding:32px}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.card{background:#121824;border:1px solid #273244;border-radius:12px;padding:16px}.card b{display:block;font-size:24px}.card small,.meta{color:#98a6b8}.pass{color:#72e2c0}table{width:100%;border-collapse:collapse;margin:24px 0;font-size:12px}th,td{padding:9px;border-bottom:1px solid #273244;text-align:right;vertical-align:top}th:first-child,td:first-child,th:nth-child(2),td:nth-child(2){text-align:left}@media(max-width:700px){.cards{grid-template-columns:1fr}}</style></head><body><h1>Mixed-address extended EIP-8304 lookup</h1><p class="meta">Seed ${summary.seed} · tracked UTXO #${summary.tracked.index} · ${htmlEscape(summary.tracked.recipient)} · ${summary.configuration.discoveryRepetitions} measured runs after ${summary.configuration.discoveryWarmups} warmups</p><div class="cards"><div class="card"><b>${summary.activity.length}</b><small>activity blocks</small></div><div class="card"><b>${summary.totalCreatedUtxos}</b><small>UTXOs created</small></div><div class="card"><b class="pass">MATCH</b><small>all cold and measured result hashes</small></div></div><h2>Specific-item lookup</h2><table><thead><tr><th>Window</th><th>Method</th><th>Cold ms</th><th>Median ms</th><th>p95 ms</th><th>Median calls</th><th>Median bytes</th><th>Tables</th><th>Payload RPCs</th><th>Candidates</th><th>Item</th></tr></thead><tbody>${checkpointRows}</tbody></table><h2>Latest mixed-route blocks</h2><table><thead><tr><th>Block</th><th>Target</th><th>Created</th><th>Gap</th><th>Routes</th><th>Gas</th><th>Reorgs</th><th>Resubmits</th></tr></thead><tbody>${recentBlocks}</tbody></table></body></html>`;
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
  const minimumUtxos = integer('MIXED_MIN_UTXOS', 70, 1);
  const maximumUtxos = integer('MIXED_MAX_UTXOS', 100, minimumUtxos);
  const firstWindow = integer('MIXED_FIRST_WINDOW_BLOCKS', 100, 1);
  const secondWindow = integer('MIXED_SECOND_WINDOW_BLOCKS', 150, firstWindow + 1);
  const outputValueWei = BigInt(process.env.MIXED_OUTPUT_VALUE_WEI || '1000000000000');
  const carrierValueWei = parseEth(process.env.MIXED_CARRIER_ETH || '1.0', 'MIXED_CARRIER_ETH');
  const waitTimeoutMs = integer('MIXED_WAIT_TIMEOUT_MS', 600_000, 1);
  const confirmations = integer('MIXED_CONFIRMATIONS', 3, 1);
  const discoveryWarmups = integer('DISCOVERY_WARMUPS', 2, 0);
  const discoveryRepetitions = integer('DISCOVERY_REPETITIONS', 7, 1);
  const discoveryConcurrency = integer('UTXO_DISCOVERY_CONCURRENCY', 8, 1);
  if (minimumUtxos < 70 || maximumUtxos > 100) {
    throw new Error('the mixed workload must stay within 70-100 UTXOs per activity block');
  }
  if (outputValueWei <= 0n) throw new Error('MIXED_OUTPUT_VALUE_WEI must be positive');
  if (firstWindow !== 100 || secondWindow !== 150) throw new Error('this experiment requires 100- and 150-block windows');

  const funders = [1, 2].map((number) => ({
    name: `funded-${number}`,
    address: required(`FUNDED_${number}_ADDRESS`).toLowerCase(),
    key: required(`FUNDED_${number}_PRIVATE_KEY`),
  }));
  const inspectors = [1, 2, 3, 4].map((number) => ({
    name: `A${number}`,
    address: required(`INSPECT_${number}_ADDRESS`).toLowerCase(),
    key: required(`INSPECT_${number}_PRIVATE_KEY`),
  }));
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
  const probe = await rpc('ethrex_getEip8304Table', [`0x${preflightHead.toString(16)}`, '0x1']);
  if (!probe) throw new Error(`EIP-8304 table is unavailable at current head ${preflightHead}`);
  const root = await rpc('eth_getStorageAt', [INDEX, probe.storageSlot, preflightHeadHex]);
  if (root.toLowerCase() !== probe.tableRoot.toLowerCase()) throw new Error('EIP-8304 preflight root mismatch');

  const maxFeePerGas = BigInt(gasPriceHex) * 2n > 2_000_000_000n ? BigInt(gasPriceHex) * 2n : 2_000_000_000n;
  const estimatedOutputsPerRoute = BigInt(Math.ceil(maximumUtxos / inspectors.length));
  const requiredCarrier = outputValueWei * estimatedOutputsPerRoute * BigInt(secondWindow) + WEI / 100n;
  if (carrierValueWei < requiredCarrier) throw new Error(`MIXED_CARRIER_ETH is too small; use at least ${requiredCarrier} wei`);
  for (const funder of funders) {
    const balance = BigInt(await rpc('eth_getBalance', [funder.address, 'latest']));
    // txforge binds a 750k maximum-gas cap in every multi-spend signature. The
    // actual charged gas is lower, but reserve against the cap for preflight.
    const required = carrierValueWei * 4n + maxFeePerGas * 750_000n * BigInt(secondWindow / 2 + 8);
    if (balance < required) throw new Error(`${funder.name} has ${balance} wei; at least ${required} wei is required`);
  }

  const runId = `mixed-${new Date().toISOString().replaceAll(':', '-').replaceAll('.', '-')}`;
  const outputDir = resolve(process.env.BENCHMARK_OUTPUT_DIR || resolve(SCRIPT_DIR, 'results'), runId);
  await mkdir(outputDir, { recursive: true });
  const runStartedAt = new Date().toISOString();

  console.log('Creating two alternating carrier UTXOs per wallet outside the measured range');
  const carriers = inspectors.map(() => []);
  for (let index = 0; index < inspectors.length; index += 1) {
    const owner = inspectors[index];
    const funder = funders[index % funders.length];
    for (let bank = 0; bank < 2; bank += 1) {
      const deposit = await forge(python, {
        op: 'deposit', key: funder.key, recipient: owner.address, valueWei: carrierValueWei.toString(),
        confirmations,
      });
      if (deposit.status !== '0x1' || deposit.index == null) throw new Error(`${owner.name}: carrier ${bank} deposit failed`);
      const scan = await scanLogs({ address: owner.address, fromBlock: deposit.block, toBlock: deposit.block, enrich: false });
      const opening = scan.utxos.find((item) => item.index === deposit.index);
      if (!opening) throw new Error(`${owner.name}: carrier UTXO #${deposit.index} was not found`);
      carriers[index].push(opening);
    }
  }

  const headAfterBootstrap = quantity(await rpc('eth_blockNumber', []));
  const scanStartBlock = alignUp(headAfterBootstrap + 2, 64);
  const firstEndBlock = scanStartBlock + firstWindow - 1;
  const secondEndBlock = scanStartBlock + secondWindow - 1;
  console.log(`Waiting for aligned range ${scanStartBlock}-${secondEndBlock}`);
  await waitForBlock(rpc, scanStartBlock - 1, waitTimeoutMs);

  const activity = [];
  const checkpoints = [];
  let tracked = null;

  async function measureCheckpoint(windowBlocks, endBlock) {
    const started = performance.now();
    const benchmark = await benchmarkDiscovery({
      address: tracked.recipient,
      fromBlock: scanStartBlock,
      toBlock: endBlock,
      enrich: false,
      warmups: discoveryWarmups,
      repetitions: discoveryRepetitions,
      concurrency: discoveryConcurrency,
    });
    const comparison = benchmark.cold;
    const matches = (result) => result.utxos.filter((item) => (
      item.index === tracked.index && item.txHash.toLowerCase() === tracked.txHash.toLowerCase()
    ));
    const logMatches = matches(comparison.receiptLogs);
    const tableMatches = matches(comparison.eip8304Tables);
    if (logMatches.length !== 1 || tableMatches.length !== 1) {
      throw new Error(`${windowBlocks}-block checkpoint did not locate the tracked UTXO exactly once through both methods`);
    }
    for (const sample of benchmark.samples) {
      if (matches(sample.receiptLogs).length !== 1 || matches(sample.eip8304Tables).length !== 1) {
        throw new Error(`${windowBlocks}-block measurement ${sample.iteration} did not locate the tracked UTXO exactly once`);
      }
    }
    const simplify = (result, found) => ({
      ...result.metrics,
      candidates: result.utxos.length,
      found,
    });
    const checkpoint = {
      windowBlocks,
      firstBlock: scanStartBlock,
      endBlock,
      measuredAtHead: comparison.targetHead,
      elapsedMs: Number((performance.now() - started).toFixed(3)),
      sameResults: comparison.sameResults,
      receiptLogResultHash: comparison.receiptLogResultHash,
      eip8304ResultHash: comparison.eip8304ResultHash,
      receiptLogs: simplify(comparison.receiptLogs, true),
      eip8304Tables: {
        ...simplify(comparison.eip8304Tables, true),
        tableSizes: comparison.eip8304Tables.tables.map((table) => table.tableSize),
      },
      warmups: benchmark.warmups,
      repetitions: benchmark.repetitions,
      statistics: benchmark.statistics,
      samples: benchmark.samples.map((sample) => ({
        iteration: sample.iteration,
        order: sample.order,
        receiptLogs: simplify(sample.receiptLogs, true),
        eip8304Tables: simplify(sample.eip8304Tables, true),
      })),
    };
    checkpoints.push(checkpoint);
    await writeFile(resolve(outputDir, 'checkpoints.json'), JSON.stringify(checkpoints, null, 2) + '\n');
    console.log(`${windowBlocks} blocks: cold logs=${checkpoint.receiptLogs.discoveryMs}ms query=${checkpoint.eip8304Tables.discoveryMs}ms; median logs=${checkpoint.statistics.receiptLogs.discoveryMs.median}ms query=${checkpoint.statistics.eip8304Tables.discoveryMs.median}ms item=#${tracked.index}`);
  }

  let activityNumber = 0;
  while (quantity(await rpc('eth_blockNumber', [])) < secondEndBlock) {
    // Alternating banks allow consecutive activity blocks: a carrier created
    // in block N is not reused until at least block N+2.
    const carrierBank = activityNumber % 2;
    const targetUtxos = randomInteger(minimumUtxos, maximumUtxos);
    const destinationCounts = allocateDestinationOutputs(targetUtxos, inspectors.length, randomInteger);
    const firstBlockDestinations = [1, 2, 0, 1]; // A1→A2, A2→A3, A3→A1, A4→A2.
    const destinations = inspectors.map((source, sourceIndex) => {
      if (activityNumber === 0) return inspectors[firstBlockDestinations[sourceIndex]];
      let destinationIndex;
      do { destinationIndex = randomInteger(0, inspectors.length - 1); }
      while (destinationIndex === sourceIndex);
      return inspectors[destinationIndex];
    });
    const routes = inspectors.map((source, sourceIndex) => {
      const destination = destinations[sourceIndex];
      const destinationOuts = Array.from({ length: destinationCounts[sourceIndex] }, () => ({
        recipient: destination.address,
        valueWei: outputValueWei.toString(),
      }));
      return {
        actorKeys: [source.key],
        inputs: [carriers[sourceIndex][carrierBank]],
        utxoOuts: [...destinationOuts, { recipient: source.address, valueWei: '0' }],
        accountOuts: [],
        changeIndex: destinationOuts.length,
      };
    });
    const sponsor = funders[activityNumber % funders.length];
    const result = await forge(python, {
      op: 'multiSponsoredSpend', sponsorKey: sponsor.key, routes, confirmations,
    });
    if (result.status !== '0x1' || result.created.length !== targetUtxos) {
      throw new Error(`activity ${activityNumber + 1}: created ${result.created.length} UTXOs; expected ${targetUtxos}`);
    }
    const actualUtxos = await countBlockUtxos(rpc, result.block);
    if (actualUtxos < minimumUtxos) throw new Error(`activity block ${result.block} contains only ${actualUtxos} UTXOs`);

    const routeRecords = [];
    for (let sourceIndex = 0; sourceIndex < inspectors.length; sourceIndex += 1) {
      const created = result.routes[sourceIndex].created;
      const destinationCreated = created.slice(0, -1);
      const change = created.at(-1);
      if (destinationCreated.length !== destinationCounts[sourceIndex]) throw new Error(`activity ${activityNumber + 1}: route ${sourceIndex} output mismatch`);
      if (change.recipient.toLowerCase() !== inspectors[sourceIndex].address) throw new Error(`activity ${activityNumber + 1}: route ${sourceIndex} change recipient mismatch`);
      carriers[sourceIndex][carrierBank] = change;
      routeRecords.push({
        source: inspectors[sourceIndex].name,
        sourceAddress: inspectors[sourceIndex].address,
        destination: destinations[sourceIndex].name,
        destinationAddress: destinations[sourceIndex].address,
        destinationUtxos: destinationCreated.length,
        changeIndex: change.index,
      });
      if (!tracked && sourceIndex === 0) {
        const item = destinationCreated[0];
        tracked = {
          index: item.index,
          block: result.block,
          txHash: result.txHash,
          source: item.source,
          recipient: item.recipient,
          valueWei: item.valueWei,
          route: `${inspectors[sourceIndex].name}->${destinations[sourceIndex].name}`,
        };
      }
    }

    const previous = activity.at(-1);
    const record = {
      number: activityNumber + 1,
      block: result.block,
      gapFromPrevious: previous ? result.block - previous.block : null,
      targetUtxos,
      actualUtxos,
      txHash: result.txHash,
      sponsor: sponsor.name,
      carrierBank,
      gasUsed: result.gasUsed,
      forgeTotalMs: result.inclusionMs,
      firstCanonicalReceiptMs: result.confirmation?.firstCanonicalReceiptMs,
      confirmationWaitMs: result.confirmation?.waitMs,
      confirmation: result.confirmation,
      routes: routeRecords,
    };
    activity.push(record);
    activityNumber += 1;
    await writeFile(resolve(outputDir, 'activity.jsonl'), activity.map((item) => JSON.stringify(item)).join('\n') + '\n');
    console.log(`block=${record.block} UTXOs=${record.actualUtxos} reorgs=${record.confirmation?.reorgs || 0} routes=${routeRecords.map((route) => `${route.source}->${route.destination}:${route.destinationUtxos}`).join(' ')}`);

    if (!checkpoints.some((checkpoint) => checkpoint.windowBlocks === firstWindow)
        && quantity(await rpc('eth_blockNumber', [])) >= firstEndBlock) {
      await measureCheckpoint(firstWindow, firstEndBlock);
    }
  }

  await waitForBlock(rpc, secondEndBlock, waitTimeoutMs);
  if (!checkpoints.some((checkpoint) => checkpoint.windowBlocks === firstWindow)) {
    await measureCheckpoint(firstWindow, firstEndBlock);
  }
  await measureCheckpoint(secondWindow, secondEndBlock);

  const summary = {
    runId,
    startedAt: runStartedAt,
    completedAt: new Date().toISOString(),
    rpc: process.env.UTXO_RPC,
    seed,
    configuration: {
      minimumUtxos,
      maximumUtxos,
      firstWindow,
      secondWindow,
      outputValueWei: outputValueWei.toString(),
      carrierValueWei: carrierValueWei.toString(),
      confirmations,
      discoveryWarmups,
      discoveryRepetitions,
      discoveryConcurrency,
    },
    scan: { firstBlock: scanStartBlock, firstEndBlock, secondEndBlock },
    tracked,
    totalCreatedUtxos: activity.reduce((sum, item) => sum + item.actualUtxos, 0),
    chainStability: {
      reorgs: activity.reduce((sum, item) => sum + (item.confirmation?.reorgs || 0), 0),
      resubmissions: activity.reduce((sum, item) => sum + (item.confirmation?.resubmissions || 0), 0),
    },
    activity,
    checkpoints,
  };
  const csvRows = [['window_blocks', 'phase', 'iteration', 'order', 'method', 'specific_index', 'found', 'discovery_ms', 'provider_rpc_ms', 'rpc_calls', 'response_bytes', 'candidates', 'tables_loaded', 'table_sizes', 'table_load_us', 'query_us', 'entries_returned', 'full_table_entries', 'matched_positions', 'root_checks', 'query_cache_hits', 'root_cache_hits', 'proofs_verified', 'proof_bytes', 'proof_verification_ms', 'receipts_fetched', 'selected_logs_returned', 'log_payload_rpc_calls', 'same_results']];
  for (const checkpoint of checkpoints) {
    const runs = [
      { phase: 'cold', iteration: 0, order: 'logsFirst', receiptLogs: checkpoint.receiptLogs, eip8304Tables: checkpoint.eip8304Tables },
      ...checkpoint.samples.map((sample) => ({ phase: 'measured', ...sample })),
    ];
    for (const run of runs) {
      for (const [method, result] of [['receiptLogs', run.receiptLogs], ['eip8304Tables', run.eip8304Tables]]) {
        csvRows.push([
          checkpoint.windowBlocks, run.phase, run.iteration, run.order, method, tracked.index, result.found,
          result.discoveryMs, result.providerRpcMs, result.rpcCalls, result.responseBytes, result.candidates,
          result.tablesLoaded, result.tableSizes?.join('|'), result.providerTableLoadMicros,
          result.providerQueryMicros, result.entriesExamined, result.fullTableEntries, result.matchedPositions,
          result.rootChecks, result.queryCacheHits, result.rootCacheHits, result.proofsVerified,
          result.proofBytes, result.proofVerificationMs, result.receiptsFetched,
          result.selectedLogsReturned, result.logPayloadRpcCalls, checkpoint.sameResults,
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
  console.error(`mixed-window benchmark failed: ${error.stack || error.message}`);
  process.exitCode = 1;
});
