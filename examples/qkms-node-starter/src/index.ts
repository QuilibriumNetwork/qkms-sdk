// qkms-node-starter — demonstrates @quilibrium/qkms-sdk-node.
//
// Demonstrates @quilibrium/qkms-sdk-node by exposing a small Express API:
//   POST /key_quorums/create_wallet            — DKG via the in-process sidecar
//   POST /transactions/send_usdc               — sign+broadcast an ERC-20 transfer
//   POST /internal/policies/create_allowlist_usdc — record a policy
//
// Setup:
//   cp .env.example .env   # then edit
//   pnpm install
//   pnpm dev               # tsx src/index.ts

import express from 'express';
import { qkms } from './lib/qkms.js';
import { createWallet } from './handlers/key_quorums/create_wallet.js';
import { sendUSDC } from './handlers/transactions/send_usdc.js';
import { createAllowlistUsdc } from './handlers/internal/policies/create_allowlist_usdc.js';

async function main() {
  const app = express();
  const port = process.env.PORT ?? '3300';
  app.use(express.json());

  // Boot the sidecar early so the first request doesn't wait on DKG init.
  await qkms.ensureStarted();
  // eslint-disable-next-line no-console
  console.log('[qkms-node-starter] sidecar started, sidecarId =', await qkms.sidecar.getSidecarId());

  app.get('/health', (_req, res) => {
    res.json({ ok: true });
  });

  app.post('/key_quorums/create_wallet', createWallet);
  app.post('/transactions/send_usdc', sendUSDC);
  app.post('/internal/policies/create_allowlist_usdc', createAllowlistUsdc);

  app.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`[qkms-node-starter] listening on port ${port}`);
  });
}

void main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('[qkms-node-starter] fatal:', err);
  process.exit(1);
});
