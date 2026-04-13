// useCreateWallet (solana) — DKG flow that produces a Solana wallet record.
//
// Triggers FROST-Ed25519 DKG via QKMS CreateKey (KeySpec=ECC_ED25519),
// waits for the public key, and derives the Solana address (base58 of the
// 32-byte Ed25519 public key). The sidecar's FROSTSession handles the MPC
// protocol rounds automatically.

import { useCallback, useContext } from 'react';
import {
  SolanaProvider,
  solanaAddressFromPublicKey,
  type ConnectedWallet,
  type QkmsRpcClient,
} from '@quilibrium/qkms-sdk-core';
import { QkmsContext } from '../context.js';

export interface SolanaCreateWalletOptions {
  createAdditional?: boolean;
}

export interface SolanaCreateWalletResult {
  wallet: ConnectedWallet;
}

export interface UseSolanaCreateWalletResult {
  createWallet: (opts?: SolanaCreateWalletOptions) => Promise<SolanaCreateWalletResult>;
}

function base64ToBytes(b64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(b64, 'base64'));
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function useCreateWallet(callbacks?: {
  onSuccess?: (args: { wallet: ConnectedWallet }) => void;
  onError?: (err: unknown) => void;
}): UseSolanaCreateWalletResult {
  const ctx = useContext(QkmsContext);
  if (!ctx) {
    throw new Error('useCreateWallet (solana) must be used inside <QkmsProvider>');
  }

  const createWallet = useCallback(
    async (_opts?: SolanaCreateWalletOptions): Promise<SolanaCreateWalletResult> => {
      if (!ctx.client || !ctx.sidecar) {
        throw new Error('useCreateWallet (solana): provider not ready');
      }

      try {
        // 1. Issue CreateKey with Ed25519. The sidecar's FROSTSession picks
        //    up the AWAITING_CLIENT task and drives FROST DKG to completion.
        const ownerTag = ctx.user?.id
          ? [{ TagKey: 'owner_id', TagValue: ctx.user.id }]
          : [];
        const createRes = await ctx.client.createKey({
          KeySpec: 'ECC_ED25519',
          KeyUsage: 'SIGN_VERIFY',
          Origin: 'AWS_KMS',
          Participants: ctx.participants,
          Threshold: ctx.threshold,
          Tags: [
            { TagKey: 'chain_type', TagValue: 'solana' },
            ...ownerTag,
          ],
        });
        const keyId = createRes.KeyMetadata.KeyId;

        // 2. Wait for GetPublicKey to succeed — DKG finalized server-side.
        const publicKeyBytes = await waitForPublicKey(ctx.client, keyId);

        // 3. Derive Solana address (base58 of 32-byte Ed25519 public key).
        const address = solanaAddressFromPublicKey(publicKeyBytes);

        const wallet: ConnectedWallet = {
          keyId,
          address,
          walletClientType: 'privy',
          connectorType: 'embedded',
          chainId: 0, // Solana doesn't use EVM chain ids
          chainType: 'solana',
          createdAt: Date.now(),
          getProvider: async () =>
            new SolanaProvider({
              client: ctx.client!,
              keyId,
              address,
            }),
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
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error(
    `useCreateWallet (solana): timed out waiting for FROST DKG completion${lastError ? `: ${lastError}` : ''}`,
  );
}
