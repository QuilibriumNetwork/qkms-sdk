// Helper functions for the vanilla SDK. We derive wallets from QKMS threshold
// DKG and synthesize reasonable values for entropy-related fields.

import type { ConnectedWallet, User } from '@quilibrium/qkms-sdk-core';

/**
 * Returns the first embedded Ethereum wallet on the user record, or null if
 * none.
 */
export function getUserEmbeddedEthereumWallet(user: User | null): ConnectedWallet | null {
  if (!user) return null;
  const linked = (user as User & { wallets?: ConnectedWallet[] }).wallets ?? [];
  return linked.find((w) => w.chainType === 'ethereum' && w.walletClientType === 'privy') ?? null;
}

/**
 * Returns the first embedded Solana wallet on the user record, or null if
 * none. Same contract as the Ethereum variant above.
 */
export function getUserEmbeddedSolanaWallet(user: User | null): ConnectedWallet | null {
  if (!user) return null;
  const linked = (user as User & { wallets?: ConnectedWallet[] }).wallets ?? [];
  return linked.find((w) => w.chainType === 'solana' && w.walletClientType === 'privy') ?? null;
}

/**
 * Returns the `entropyId` and `entropyIdVerifier` for embedded-wallet
 * provider construction.
 *
 * We synthesize stable values from the user id so apps that pass these
 * through verbatim still work.
 */
export function getEntropyDetailsFromUser(
  user: User | null,
): { entropyId: string; entropyIdVerifier: string } | null {
  if (!user) return null;
  return {
    entropyId: user.entropyId ?? user.id,
    entropyIdVerifier: user.entropyIdVerifier ?? user.id,
  };
}

/**
 * Session-signer helpers. The QKMS analogue is the wallets resource's
 * `update` method in `@quilibrium/qkms-sdk-node`, which requires the DKLs23
 * key refresh protocol.
 *
 * These functions throw with a clear error so apps fail fast instead of
 * silently no-op'ing.
 */
export async function addSessionSigners(_args: {
  client: unknown;
  wallet: ConnectedWallet;
  signers: Array<{ signerId: string; policyIds?: string[] }>;
}): Promise<never> {
  throw new Error(
    'addSessionSigners is not supported in qkms-sdk (requires DKLs23 refresh/resize protocol)',
  );
}

export async function removeSessionSigners(_args: {
  client: unknown;
  wallet: ConnectedWallet;
}): Promise<never> {
  throw new Error(
    'removeSessionSigners is not supported in qkms-sdk (requires DKLs23 refresh/resize protocol)',
  );
}
