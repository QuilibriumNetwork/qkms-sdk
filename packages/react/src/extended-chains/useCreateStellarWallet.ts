// useCreateStellarWallet — DKG flow that produces a Stellar wallet record.
//
// Uses FROST (Ed25519) via QKMS CreateKey(ECC_ED25519), then derives
// a Stellar address using StrKey encoding (G...).

import { useCallback, useContext } from 'react';
import {
  stellarAddressFromPublicKey,
  type ConnectedWallet,
  type QkmsRpcClient,
} from '@quilibrium/qkms-sdk-core';
import { QkmsContext } from '../context.js';

export interface StellarCreateWalletOptions {
  createAdditional?: boolean;
}

export interface StellarCreateWalletResult {
  wallet: ConnectedWallet;
}

function base64ToBytes(b64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(b64, 'base64'));
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function useCreateStellarWallet(callbacks?: {
  onSuccess?: (args: { wallet: ConnectedWallet }) => void;
  onError?: (err: unknown) => void;
}): { createWallet: (opts?: StellarCreateWalletOptions) => Promise<StellarCreateWalletResult> } {
  const ctx = useContext(QkmsContext);
  if (!ctx) throw new Error('useCreateStellarWallet must be used inside <QkmsProvider>');

  const createWallet = useCallback(
    async (_opts?: StellarCreateWalletOptions): Promise<StellarCreateWalletResult> => {
      if (!ctx.client || !ctx.sidecar) throw new Error('useCreateStellarWallet: provider not ready');

      try {
        // Stellar uses Ed25519 — driven by FROST session.
        const createRes = await ctx.client.createKey({
          KeySpec: 'ECC_ED25519',
          KeyUsage: 'SIGN_VERIFY',
          Origin: 'AWS_KMS',
        });
        const keyId = createRes.KeyMetadata.KeyId;
        const publicKeyBytes = await waitForPublicKey(ctx.client, keyId, 120_000);
        const address = stellarAddressFromPublicKey(publicKeyBytes);

        const wallet: ConnectedWallet = {
          keyId,
          address,
          walletClientType: 'privy',
          connectorType: 'embedded',
          chainId: 0,
          chainType: 'stellar',
          createdAt: Date.now(),
          getProvider: async () => ({ keyId, address, chainType: 'stellar' }),
        };

        ctx.registerWallet(wallet);
        callbacks?.onSuccess?.({ wallet });
        return { wallet };
      } catch (err) {
        callbacks?.onError?.(err);
        throw err;
      }
    },
    [ctx, callbacks],
  );

  return { createWallet };
}

async function waitForPublicKey(
  client: QkmsRpcClient,
  keyId: string,
  timeoutMs = 120_000,
  intervalMs = 500,
): Promise<Uint8Array> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown = null;
  while (Date.now() < deadline) {
    try {
      const res = await client.getPublicKey({ KeyId: keyId });
      if (res.PublicKey) return base64ToBytes(res.PublicKey);
    } catch (err) {
      lastError = err;
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(`useCreateStellarWallet: timed out waiting for DKG${lastError ? `: ${lastError}` : ''}`);
}
