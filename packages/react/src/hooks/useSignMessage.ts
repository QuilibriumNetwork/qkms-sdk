// useSignMessage — EIP-191 personal sign over a QKMS-backed embedded wallet.

import { useCallback, useContext } from 'react';
import type { Hex } from '@quilibrium/qkms-sdk-core';
import { QkmsContext } from '../context.js';

export interface SignMessageInput {
  message: string;
}

export interface SignMessageOptions {
  address: string;
}

export interface UseSignMessageResult {
  signMessage: (input: SignMessageInput, opts: SignMessageOptions) => Promise<{ signature: Hex }>;
}

export function useSignMessage(): UseSignMessageResult {
  const ctx = useContext(QkmsContext);
  if (!ctx) throw new Error('useSignMessage must be used inside <QkmsProvider>');

  const signMessage = useCallback(
    async (input: SignMessageInput, opts: SignMessageOptions) => {
      const wallet = ctx.wallets.find(
        (w) => w.address.toLowerCase() === opts.address.toLowerCase(),
      );
      if (!wallet) throw new Error(`useSignMessage: no wallet for address ${opts.address}`);
      const provider = await wallet.getProvider();
      const signature = (await provider.request({
        method: 'personal_sign',
        params: [input.message, opts.address],
      })) as Hex;
      return { signature };
    },
    [ctx],
  );

  return { signMessage };
}
