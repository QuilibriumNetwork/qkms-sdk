// @quilibrium/qkms-sdk-react/solana — Solana hooks subpath.
//
// All hooks are functional: `useCreateWallet` drives FROST-Ed25519 DKG,
// signing hooks route through `SolanaProvider` → QKMS Sign (EDDSA_ED25519),
// and `useWallets` filters the global wallet list by `chainType === 'solana'`.

export { useWallets } from './useWallets.js';
export { useCreateWallet, type SolanaCreateWalletOptions } from './useCreateWallet.js';
export { useSignMessage, type SolanaSignMessageInput } from './useSignMessage.js';
export {
  useSignTransaction,
  useSignAndSendTransaction,
  type SolanaSignTransactionInput,
} from './useSignTransaction.js';

/**
 * Solana wallet connectors helper. Returns empty array (embedded wallets only).
 */
export function toSolanaWalletConnectors(): never[] {
  return [];
}
