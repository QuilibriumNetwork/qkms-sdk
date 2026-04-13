// useCreateCosmosWallet — DKG flow that produces a Cosmos wallet record.
//
// Uses DKLs23 (secp256k1) via QKMS CreateKey(ECC_SECG_P256K1), then
// derives a bech32 Cosmos address from the compressed public key.

import { useCallback, useContext } from 'react';
import {
  cosmosAddressFromPublicKey,
  type ConnectedWallet,
  type QkmsRpcClient,
} from '@quilibrium/qkms-sdk-core';
import { QkmsContext } from '../context.js';

export interface CosmosCreateWalletOptions {
  createAdditional?: boolean;
  /** Bech32 prefix: "cosmos", "osmo", "juno", etc. Defaults to "cosmos". */
  prefix?: string;
}

export interface CosmosCreateWalletResult {
  wallet: ConnectedWallet;
}

function base64ToBytes(b64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(b64, 'base64'));
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function useCreateCosmosWallet(callbacks?: {
  onSuccess?: (args: { wallet: ConnectedWallet }) => void;
  onError?: (err: unknown) => void;
}): { createWallet: (opts?: CosmosCreateWalletOptions) => Promise<CosmosCreateWalletResult> } {
  const ctx = useContext(QkmsContext);
  if (!ctx) throw new Error('useCreateCosmosWallet must be used inside <QkmsProvider>');

  const createWallet = useCallback(
    async (opts?: CosmosCreateWalletOptions): Promise<CosmosCreateWalletResult> => {
      if (!ctx.client || !ctx.sidecar) throw new Error('useCreateCosmosWallet: provider not ready');

      try {
        // Cosmos uses secp256k1 — same as Ethereum, driven by DKLs23.
        const createRes = await ctx.client.createKey({
          KeySpec: 'ECC_SECG_P256K1',
          KeyUsage: 'SIGN_VERIFY',
          Origin: 'AWS_KMS',
        });
        const keyId = createRes.KeyMetadata.KeyId;
        const publicKeyBytes = await waitForPublicKey(ctx.client, keyId);
        const prefix = opts?.prefix ?? 'cosmos';
        const address = cosmosAddressFromPublicKey(publicKeyBytes, prefix);

        const wallet: ConnectedWallet = {
          keyId,
          address,
          walletClientType: 'privy',
          connectorType: 'embedded',
          chainId: 0,
          chainType: 'cosmos',
          createdAt: Date.now(),
          getProvider: async () => ({ keyId, address, chainType: 'cosmos' }),
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
  timeoutMs = 60_000,
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
  throw new Error(`useCreateCosmosWallet: timed out waiting for DKG${lastError ? `: ${lastError}` : ''}`);
}
