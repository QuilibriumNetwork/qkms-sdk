// useSignMessage (solana) — sign a raw message with a QKMS-backed Ed25519 wallet.

import { useCallback, useContext } from 'react';
import { SolanaProvider, type ConnectedWallet } from '@quilibrium/qkms-sdk-core';
import { QkmsContext } from '../context.js';

export interface SolanaSignMessageInput {
  message: Uint8Array;
  wallet: ConnectedWallet;
  options?: { uiOptions?: { title?: string } };
}

export interface UseSolanaSignMessageResult {
  signMessage: (input: SolanaSignMessageInput) => Promise<{ signature: Uint8Array }>;
}

export function useSignMessage(): UseSolanaSignMessageResult {
  const ctx = useContext(QkmsContext);
  if (!ctx) {
    throw new Error('useSignMessage (solana) must be used inside <QkmsProvider>');
  }
  const signMessage = useCallback(
    async (input: SolanaSignMessageInput) => {
      if (!ctx.client) throw new Error('signMessage: provider not ready');
      const provider = new SolanaProvider({
        client: ctx.client,
        keyId: input.wallet.keyId,
        address: input.wallet.address,
      });
      const signature = await provider.signMessage(input.message);
      return { signature };
    },
    [ctx],
  );
  return { signMessage };
}
