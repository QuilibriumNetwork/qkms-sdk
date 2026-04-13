import { useContext } from 'react';
import type { ConnectedWallet } from '@quilibrium/qkms-sdk-core';
import { QkmsContext } from '../context.js';

export interface UseSolanaWalletsResult {
  wallets: ConnectedWallet[];
  ready: boolean;
}

/** Returns only Solana wallets from the global wallet list. */
export function useWallets(): UseSolanaWalletsResult {
  const ctx = useContext(QkmsContext);
  if (!ctx) {
    throw new Error('useWallets (solana) must be used inside <QkmsProvider>');
  }
  return {
    wallets: ctx.wallets.filter((w) => w.chainType === 'solana'),
    ready: ctx.ready,
  };
}
