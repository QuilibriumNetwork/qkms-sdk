import { useContext } from 'react';
import type { ConnectedWallet } from '@quilibrium/qkms-sdk-core';
import { QkmsContext } from '../context.js';

export interface UseWalletsResult {
  wallets: ConnectedWallet[];
  ready: boolean;
}

export function useWallets(): UseWalletsResult {
  const ctx = useContext(QkmsContext);
  if (!ctx) {
    throw new Error('useWallets must be used inside <QkmsProvider>');
  }
  return {
    wallets: ctx.wallets,
    ready: ctx.ready,
  };
}
