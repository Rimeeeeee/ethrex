// Read-only-first wallet service for the live EIP-8312 devnet.
//
// The browser never receives a private key. Sending is available only when the
// operator explicitly provides EIP8312_WALLET_KEY to the local server.

export const VAULT = '0x0000000000000000000000000000000000008312';
export const UTXO_CREATED_TOPIC = '0x3b19241465a47bc187f1d9c7db70834855a907183742a4b63aa824c576296f5e';

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const UINT_RE = /^(0|[1-9][0-9]*)$/;

export function isAddress(value) {
  return typeof value === 'string' && ADDRESS_RE.test(value);
}

function asBlock(value, name) {
  if (typeof value === 'number' && Number.isInteger(value) && value >= 0) return value;
  if (typeof value === 'string' && /^(0x[0-9a-f]+|[0-9]+)$/i.test(value)) {
    const parsed = Number(value);
    if (Number.isSafeInteger(parsed) && parsed >= 0) return parsed;
  }
  throw new Error(`${name} must be a non-negative block number`);
}

function parseOpening(log) {
  const data = String(log.data || '0x').slice(2);
  if (data.length < 128 || !Array.isArray(log.topics) || log.topics.length < 3) return null;
  const word = (offset) => BigInt(`0x${data.slice(offset, offset + 64)}`);
  const topicAddress = (topic) => `0x${String(topic).slice(-40)}`.toLowerCase();
  return {
    index: Number(word(0)),
    valueWei: word(64).toString(),
    source: topicAddress(log.topics[1]),
    recipient: topicAddress(log.topics[2]),
    creationBlock: Number.parseInt(log.blockNumber, 16),
    txHash: log.transactionHash,
    logIndex: Number.parseInt(log.logIndex || '0x0', 16),
    blockHash: log.blockHash,
  };
}

async function spentAt(chain, index) {
  // The EIP-8312 PoC stores one spent bit per UTXO in the vault's bitfield.
  const slot = (1n << 129n) + BigInt(Math.floor(index / 256));
  const word = BigInt(await chain.rpcCall('eth_getStorageAt', [VAULT, `0x${slot.toString(16)}`, 'latest']));
  return (word & (1n << BigInt(index & 255))) !== 0n;
}

export async function scanWallet(chain, { address, fromBlock = 0, toBlock } = {}) {
  if (!isAddress(address)) throw new Error('address must be a 20-byte hex address');
  const head = Number.parseInt(await chain.rpcCall('eth_blockNumber', []), 16);
  const start = asBlock(fromBlock, 'fromBlock');
  const end = toBlock == null ? head : Math.min(asBlock(toBlock, 'toBlock'), head);
  if (start > end) return { address, fromBlock: start, toBlock: end, head, utxos: [] };

  const utxos = [];
  const chunkSize = 2_000;
  for (let from = start; from <= end; from += chunkSize) {
    const to = Math.min(from + chunkSize - 1, end);
    const logs = await chain.rpcCall('eth_getLogs', [{
      address: VAULT,
      topics: [UTXO_CREATED_TOPIC, null, `0x${address.slice(2).padStart(64, '0')}`],
      fromBlock: `0x${from.toString(16)}`,
      toBlock: `0x${to.toString(16)}`,
    }]);
    for (const log of logs) {
      const opening = parseOpening(log);
      if (!opening || opening.recipient !== address.toLowerCase()) continue;
      opening.spent = await spentAt(chain, opening.index);
      opening.spendable = opening.creationBlock < head && !opening.spent;
      utxos.push(opening);
    }
  }
  utxos.sort((a, b) => a.index - b.index);
  return { address: address.toLowerCase(), fromBlock: start, toBlock: end, head, utxos };
}

function validateAmount(valueWei) {
  if (typeof valueWei !== 'string' || !UINT_RE.test(valueWei) || BigInt(valueWei) <= 0n) {
    throw new Error('valueWei must be a positive integer string');
  }
  return BigInt(valueWei);
}

export async function walletInfo(chain, walletKey) {
  if (!walletKey) return { configured: false, address: null };
  const { address } = await chain.forge({ op: 'addressOf', key: walletKey });
  return { configured: true, address: address.toLowerCase() };
}

export async function sendUtxo(chain, walletKey, { input, recipient, valueWei }) {
  if (!walletKey) throw new Error('sending is disabled: start the server with EIP8312_WALLET_KEY');
  if (!input || !Number.isInteger(input.index) || !Number.isInteger(input.creationBlock)) {
    throw new Error('input must include index and creationBlock');
  }
  if (!isAddress(input.recipient) || !isAddress(input.source)) {
    throw new Error('input must include source and recipient addresses');
  }
  if (!isAddress(recipient)) throw new Error('recipient must be a 20-byte hex address');
  const amount = validateAmount(valueWei);
  const inputValue = validateAmount(String(input.valueWei));
  if (amount > inputValue) throw new Error('valueWei cannot exceed the selected UTXO value');

  const info = await walletInfo(chain, walletKey);
  if (input.recipient.toLowerCase() !== info.address) {
    throw new Error(`selected UTXO belongs to ${input.recipient}, not the configured wallet`);
  }

  // Re-read the exact opening and spent bit immediately before signing. The
  // client is allowed to suggest an input, but the server does not trust it.
  const fresh = await scanWallet(chain, { address: info.address, fromBlock: input.creationBlock, toBlock: input.creationBlock });
  const onChain = fresh.utxos.find((u) => u.index === input.index);
  if (!onChain) throw new Error('selected UTXO was not found in the requested creation block');
  if (onChain.spent) throw new Error('selected UTXO is already spent');
  if (onChain.source !== input.source.toLowerCase() || onChain.valueWei !== String(input.valueWei)) {
    throw new Error('selected UTXO metadata does not match the chain');
  }

  return chain.forge({
    op: 'spend',
    actorKeys: [walletKey],
    inputs: [{
      index: onChain.index,
      creationBlock: onChain.creationBlock,
      source: onChain.source,
      recipient: onChain.recipient,
      valueWei: onChain.valueWei,
    }],
    utxoOuts: [
      { recipient: recipient.toLowerCase(), valueWei: amount.toString() },
      // Protocol-required zero-signed change output. The remainder after gas
      // is assigned by settlement; it is not an ordinary zero-value payment.
      { recipient: info.address, valueWei: '0' },
    ],
    accountOuts: [],
    changeIndex: 1,
  });
}
