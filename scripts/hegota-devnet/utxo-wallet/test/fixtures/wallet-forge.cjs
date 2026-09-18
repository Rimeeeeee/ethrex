// Test double: derives recognizable fake addresses and never contacts a chain.
let input = '';
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', () => {
  const command = JSON.parse(input);
  const key = command.key || command.actorKeys?.[0];
  const address = `0x${key.slice(-40)}`;
  setTimeout(() => process.stdout.write(JSON.stringify(command.op === 'addressOf'
    ? { address }
    : { status: '0x1', txHash: `0x${'aa'.repeat(32)}`, signer: address, rpc: command.rpc }
  )), 10);
});
