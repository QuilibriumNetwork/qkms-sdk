// useSignTransaction / useSignAndSendTransaction (solana).
//
// Both methods route through `SolanaProvider` from core; the underlying QKMS
// Sign calls use the FROST-Ed25519 session.

import { useCallback, useContext } from 'react';
import { SolanaProvider, type ConnectedWallet } from '@quilibrium/qkms-sdk-core';
import { QkmsContext } from '../context.js';

export interface SolanaSignTransactionInput {
  /** Serialized Solana transaction bytes (the signable message portion). */
  transaction: Uint8Array;
  wallet: ConnectedWallet;
}

export interface UseSolanaSignTransactionResult {
  signTransaction: (input: SolanaSignTransactionInput) => Promise<{ signature: Uint8Array }>;
}

export function useSignTransaction(): UseSolanaSignTransactionResult {
  const ctx = useContext(QkmsContext);
  if (!ctx) throw new Error('useSignTransaction (solana) must be used inside <QkmsProvider>');

  const signTransaction = useCallback(
    async (input: SolanaSignTransactionInput) => {
      if (!ctx.client) throw new Error('signTransaction: provider not ready');
      const provider = new SolanaProvider({
        client: ctx.client,
        keyId: input.wallet.keyId,
        address: input.wallet.address,
      });
      const signature = await provider.signTransaction(input.transaction);
      return { signature };
    },
    [ctx],
  );
  return { signTransaction };
}

export interface UseSolanaSignAndSendTransactionResult {
  signAndSendTransaction: (input: SolanaSignTransactionInput) => Promise<{ signature: string }>;
}

export function useSignAndSendTransaction(): UseSolanaSignAndSendTransactionResult {
  const ctx = useContext(QkmsContext);
  if (!ctx) throw new Error('useSignAndSendTransaction (solana) must be used inside <QkmsProvider>');

  const signAndSendTransaction = useCallback(
    async (input: SolanaSignTransactionInput) => {
      if (!ctx.client) throw new Error('signAndSendTransaction: provider not ready');
      const provider = new SolanaProvider({
        client: ctx.client,
        keyId: input.wallet.keyId,
        address: input.wallet.address,
      });
      return await provider.signAndSendTransaction(input.transaction);
    },
    [ctx],
  );
  return { signAndSendTransaction };
}
