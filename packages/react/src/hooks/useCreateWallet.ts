// useCreateWallet — DKG flow that produces a ConnectedWallet record.
//
// On call:
//   1. CreateKey on QKMS (KeySpec=ECC_SECG_P256K1, threshold mode).
//   2. The DKLs23Session in the sidecar picks up the resulting AWAITING_CLIENT
//      task, runs DKG rounds 1-3 + finalize, persists the key share, and
//      submits completion.
//   3. We poll DescribeKey/GetPublicKey until the key is ACTIVE, then derive
//      the EVM address from the public key.
//   4. The wallet is registered in the React context so useWallets sees it.

import { useCallback, useContext } from 'react';
import {
  EthereumProvider,
  SolanaProvider,
  evmChecksumAddressFromPublicKey,
  solanaAddressFromPublicKey,
  type ConnectedWallet,
  type QkmsRpcClient,
} from '@quilibrium/qkms-sdk-core';
import { QkmsContext } from '../context.js';

export interface CreateWalletOptions {
  createAdditional?: boolean;
  chainType?: 'ethereum' | 'solana';
}

export interface CreateWalletResult {
  wallet: ConnectedWallet;
}

export interface UseCreateWalletResult {
  createWallet: (opts?: CreateWalletOptions) => Promise<CreateWalletResult>;
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
}): UseCreateWalletResult {
  const ctx = useContext(QkmsContext);
  if (!ctx) {
    throw new Error('useCreateWallet must be used inside <QkmsProvider>');
  }

  const createWallet = useCallback(
    async (opts?: CreateWalletOptions): Promise<CreateWalletResult> => {
      if (!ctx.client || !ctx.sidecar) {
        throw new Error('useCreateWallet: provider not ready');
      }

      const chainType = opts?.chainType ?? 'ethereum';

      try {
        // Pick KeySpec based on chain type.
        const keySpec = chainType === 'solana' ? 'ECC_ED25519' : 'ECC_SECG_P256K1';

        // 1. Issue CreateKey. The sidecar picks up the AWAITING_CLIENT task
        //    and drives DKG to completion (DKLs23 for secp256k1, FROST for Ed25519).
        // Auto-tag with owner_id for per-user policy scoping.
        // The userName comes from the JWT claims set during login().
        const ownerTag = ctx.user?.id
          ? [{ TagKey: 'owner_id', TagValue: ctx.user.id }]
          : [];

        const createRes = await ctx.client.createKey({
          KeySpec: keySpec,
          KeyUsage: 'SIGN_VERIFY',
          Origin: 'AWS_KMS',
          Participants: ctx.participants,
          Threshold: ctx.threshold,
          Tags: [
            { TagKey: 'chain_type', TagValue: chainType },
            ...ownerTag,
          ],
        });
        const keyId = createRes.KeyMetadata.KeyId;

        // 2. Wait for GetPublicKey to succeed — DKG finalized server-side.
        const timeoutMs = chainType === 'solana' ? 120_000 : 60_000;
        const publicKeyBytes = await waitForPublicKey(ctx.client, keyId, timeoutMs);

        // 3. Derive chain-specific address.
        let wallet: ConnectedWallet;
        if (chainType === 'solana') {
          const address = solanaAddressFromPublicKey(publicKeyBytes);
          wallet = {
            keyId,
            address,
            walletClientType: 'privy',
            connectorType: 'embedded',
            chainId: 0,
            chainType: 'solana',
            createdAt: Date.now(),
            getProvider: async () =>
              new SolanaProvider({
                client: ctx.client!,
                keyId,
                address,
              }),
          };
        } else {
          const address = evmChecksumAddressFromPublicKey(publicKeyBytes);
          wallet = {
            keyId,
            address,
            walletClientType: 'privy',
            connectorType: 'embedded',
            chainId: ctx.defaultChainId,
            chainType: 'ethereum',
            createdAt: Date.now(),
            getProvider: async () =>
              new EthereumProvider({
                client: ctx.client!,
                keyId,
                address,
                chainId: ctx.defaultChainId,
                rpcUrl: ctx.evmRpcUrl,
              }),
          };
        }

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
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error(`useCreateWallet: timed out waiting for DKG completion${lastError ? `: ${lastError}` : ''}`);
}
