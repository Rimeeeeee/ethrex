# Orbit — EIP-8312 wallet with EIP-8304 discovery

This is a complete Vercel project for the ethrex/Hegota UTXO devnet:

- static wallet UI in `public/`
- one Vercel Python Function in `api/[...path].py`
- the transaction forge bundled as `api/txforge.py`
- no separate backend process
- no `package.json` and no npm runtime dependencies

On the combined local devnet, the Discovery Lab supports both recipient-filtered
receipt-log scanning and EIP-8304 table scanning. The latter verifies committed
table roots and a complete recipient range plus vault/signature/source/index
candidate entries under one shared multiproof per table. The local Node backend
then fetches all selected UPT records in one RPC and verifies one shared opening
multiproof per touched block against the vault roots. It does not download
transaction receipts. The UI can compare latency, RPC calls, response bytes,
UPT records, and result-set equality at a frozen head, or decode the table for a
selected block.

The Vercel Python function remains a compatibility deployment for the public
Hegota endpoint. Its table mode still reads full EIP-8304 table bodies and block
receipts; use `server.mjs` and the combined devnet when measuring the new
proof-query + UPT path.

The default RPC is:

```
https://rpc1.hegota.ethrex.xyz
```

This is a devnet wallet. Do not import a mainnet or production private key.

## Deploy to Vercel

1. Create a new GitHub repository and copy the contents of this folder into the repository root.
2. Push the repository to GitHub.
3. In Vercel, choose **Add New Project**, import that GitHub repository, and deploy it.
4. Keep the framework preset as **Other**. Do not add a build command. The checked-in `vercel.json` serves `public/` and routes `/api/*` to the Python function.
5. In Vercel project settings, add this environment variable:

   ```
   UTXO_RPC=https://rpc1.hegota.ethrex.xyz
   ```

6. Redeploy after saving the variable.
7. Open the deployment URL and use **Connect wallet**. The private key is kept in that tab's memory and sent over HTTPS to the same-origin Vercel function for validation and each requested devnet transaction. Every visitor connects independently.

No separate server, VPS, Docker container, tunnel, or ethrex checkout is needed at runtime.

Vercel installs only the exact Python packages pinned in `requirements.txt`. There are no npm dependencies to install or audit.

## Use the wallet

1. Open **RPC settings** if you want to use another HTTP(S) JSON-RPC endpoint.
2. Click **Connect wallet** and enter a 32-byte hex private key. Use a disposable, funded Hegota devnet key.
3. The address is filled into the watch field after import.
4. Click **Scan chain** to find UTXOs whose recipient is that address.
5. Use **Create** and choose **Fresh UTXO** to create a new claim directly from the imported account balance.
6. Use **Create** and choose **Existing UTXO** to send an available claim to another recipient.
7. Use **Withdraw ETH** to redeem an available UTXO back into the imported wallet's normal ETH account balance.

Existing-UTXO sends and withdrawals can combine multiple available UTXOs in one spend. The wallet automatically selects enough claims to cover the requested amount.

**Holdings** shows UTXOs received by the connected address. **Created** shows UTXOs emitted by the connected account, including claims created for other recipients.
8. **Disconnect** clears the imported key and wallet data from this tab. Other visitors stay connected.

Amounts are entered in ETH and converted exactly to wei in the browser. The API also validates integer wei strings before signing.

## Independent wallet connections

Each browser tab owns its connection and RPC settings. The backend does not retain a wallet key or a visitor's RPC selection between requests. Multiple people can import different wallets and transact concurrently, including when Vercel uses different function instances. To use two wallets yourself, open two tabs and connect one wallet in each.

Keys are not written to local storage, session storage, cookies, or URLs. Reloading or closing the page disconnects that tab; reconnect to continue. Disconnecting cannot cancel a transaction already submitted.

The browser sends its public address in `X-Wallet-Address` for `/api/status`, and its selected RPC in `X-UTXO-RPC`. The address header only selects public balance information; it does not authorize signing. `/api/import` validates the supplied key without saving it. `/api/deposit`, `/api/send`, and `/api/redeem` require a `key` in each JSON request body and derive the signer from that key. `/api/lock` is a compatibility no-op; callers clear their own connection locally. `UTXO_WALLET_KEY` is no longer used by either backend and should be removed from deployment settings.

This design is suitable for a devnet demonstration, not for custody or production funds. For production, signing should happen client-side with a wallet provider or hardware wallet, so a server never receives private keys.

A request that submits a transaction must finish within the configured function duration. The current function is configured for 60 seconds. If the devnet takes longer to mine a receipt, retry after checking the transaction hash in Dora.

## Local run

For local development from the ethrex checkout, the existing Node server remains available:

```bash
cd /mnt/d/bogota/ethrex
export UTXO_RPC=http://127.0.0.1:<kurtosis-rpc-port>
export UTXO_PYTHON=/mnt/d/bogota/ethrex/scripts/hegota-devnet/.venv/bin/python
node scripts/hegota-devnet/utxo-wallet/server.mjs
```

Open http://127.0.0.1:8090.

The local server uses the ethrex devnet Python environment and the original checkout's forge path. Vercel does not use `server.mjs`; it uses the bundled Python function and `api/txforge.py`.

## Ethrex requirements

Optimized table discovery requires the combined devnet branch and its
`ethrex_queryEip8304Table` and `ethrex_getUtxoProofs` RPCs. The current public
Hegota endpoint may support receipt-log discovery only until it is upgraded.
The project bundles the
transaction-building helper from:

```
scripts/hegota-devnet/utxo-demo/devnet/txforge.py
```

If that helper changes in ethrex, copy the reviewed change into `api/txforge.py` and redeploy.

## Files to keep out of Git

Never commit:

- private keys
- `.env` files
- wallet export files
- logs containing sensitive operational data
- local Python virtual environments

The included `.gitignore` and `.vercelignore` cover the common cases.
