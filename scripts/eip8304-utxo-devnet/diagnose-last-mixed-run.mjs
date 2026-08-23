#!/usr/bin/env node
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(SCRIPT_DIR, '../..');
const TXFORGE = resolve(ROOT, 'scripts/hegota-devnet/utxo-wallet/api/txforge.py');
const DEFAULT_ENV = resolve(ROOT, 'scripts/hegota-devnet/utxo-demo/wallets.env');
const DEFAULT_PYTHON = resolve(ROOT, 'scripts/hegota-devnet/.venv/bin/python');

function argument(name, fallback = null) {
  const index = process.argv.indexOf(name);
  return index === -1 ? fallback : process.argv[index + 1];
}

async function loadEnv(path) {
  const text = await readFile(path, 'utf8');
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const separator = line.indexOf('=');
    if (separator === -1) continue;
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

function forge(python, command) {
  return new Promise((resolveForge, rejectForge) => {
    const child = spawn(python, [TXFORGE], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', rejectForge);
    child.on('close', (code) => {
      let result;
      try { result = JSON.parse(stdout); }
      catch { return rejectForge(new Error(stderr || stdout || `txforge exited with code ${code}`)); }
      if (result.error) return rejectForge(new Error(result.error));
      resolveForge(result);
    });
    child.stdin.end(JSON.stringify(command));
  });
}

async function main() {
  const resultDir = argument('--results');
  if (!resultDir) throw new Error('usage: diagnose-last-mixed-run.mjs --results <mixed-result-dir> [--env <wallets.env>]');
  const envPath = resolve(argument('--env', DEFAULT_ENV));
  await loadEnv(envPath);
  process.env.UTXO_RPC = process.env.UTXO_RPC || process.env.RPC;
  const python = process.env.UTXO_PYTHON || DEFAULT_PYTHON;
  if (!process.env.UTXO_RPC) throw new Error('UTXO_RPC (or RPC) is required');
  if (!existsSync(python)) throw new Error(`Python environment not found: ${python}`);

  const activityText = await readFile(resolve(resultDir, 'activity.jsonl'), 'utf8');
  const activity = activityText.trim().split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
  if (!activity.length) throw new Error('the partial run contains no completed activity');

  const inspectors = [1, 2, 3, 4].map((number) => ({
    name: `A${number}`,
    address: required(`INSPECT_${number}_ADDRESS`).toLowerCase(),
    key: required(`INSPECT_${number}_PRIVATE_KEY`),
  }));
  const funders = [1, 2].map((number) => ({ key: required(`FUNDED_${number}_PRIVATE_KEY`) }));
  const seed = Number(process.env.BENCHMARK_SEED || 8304);
  const minimum = Number(process.env.MIXED_MIN_UTXOS || 70);
  const maximum = Number(process.env.MIXED_MAX_UTXOS || 100);
  const outputValueWei = process.env.MIXED_OUTPUT_VALUE_WEI || '1000000000000';
  const random = mulberry32(seed);
  const randomInteger = (low, high) => low + Math.floor(random() * (high - low + 1));

  let targetUtxos;
  let destinationCounts;
  let destinations;
  for (let number = 0; number <= activity.length; number += 1) {
    targetUtxos = randomInteger(minimum, maximum);
    destinationCounts = [1, 1, 1, 1];
    for (let remaining = targetUtxos - 8; remaining > 0; remaining -= 1) {
      destinationCounts[randomInteger(0, 3)] += 1;
    }
    destinations = inspectors.map((_, sourceIndex) => {
      if (number === 0) return [1, 2, 0, 1][sourceIndex];
      let destination;
      do { destination = randomInteger(0, 3); } while (destination === sourceIndex);
      return destination;
    });
  }

  const { rpc, scanLogs } = await import('../hegota-devnet/utxo-wallet/server.mjs');
  const carrierBank = activity.length % 2;
  const carrierActivity = [...activity].reverse().find((item) => item.carrierBank === carrierBank);
  if (!carrierActivity) throw new Error(`no prior carrier state found for bank ${carrierBank}`);
  const carriers = [];
  for (let sourceIndex = 0; sourceIndex < inspectors.length; sourceIndex += 1) {
    const index = carrierActivity.routes[sourceIndex].changeIndex;
    const scan = await scanLogs({
      address: inspectors[sourceIndex].address,
      fromBlock: carrierActivity.block,
      toBlock: carrierActivity.block,
      enrich: false,
    });
    const carrier = scan.utxos.find((item) => item.index === index);
    if (!carrier) throw new Error(`carrier UTXO #${index} was not found`);
    carriers.push(carrier);
  }

  const routes = inspectors.map((source, sourceIndex) => {
    const destination = inspectors[destinations[sourceIndex]];
    const destinationOuts = Array.from({ length: destinationCounts[sourceIndex] }, () => ({
      recipient: destination.address,
      valueWei: outputValueWei,
    }));
    return {
      actorKeys: [source.key],
      inputs: [carriers[sourceIndex]],
      utxoOuts: [...destinationOuts, { recipient: source.address, valueWei: '0' }],
      accountOuts: [],
      changeIndex: destinationOuts.length,
    };
  });
  const built = await forge(python, {
    rpc: process.env.UTXO_RPC,
    op: 'multiSponsoredSpend',
    sponsorKey: funders[activity.length % funders.length].key,
    routes,
    buildOnly: true,
  });
  const simulation = await rpc('ethrex_simulateFrameTransaction', [built.rawTransaction, 'latest']);
  console.log(JSON.stringify({
    nextActivity: activity.length + 1,
    targetUtxos,
    destinationCounts,
    destinations: destinations.map((destination, source) => `A${source + 1}->A${destination + 1}`),
    carrierBank,
    carrierBlock: carrierActivity.block,
    txHash: built.txHash,
    nonceSeq: built.nonceSeq,
    frameGasLimits: built.frameGasLimits,
    signedMaxGasLimit: built.signedMaxGasLimit,
    simulation,
  }, null, 2));
}

main().catch((error) => {
  console.error(`diagnosis failed: ${error.stack || error.message}`);
  process.exitCode = 1;
});
