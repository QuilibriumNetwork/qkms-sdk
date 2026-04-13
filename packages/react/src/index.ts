// Public surface of @quilibrium/qkms-sdk-react.

export { QkmsProvider, PrivyProvider, type QkmsClientConfig, type QkmsProviderProps } from './provider.js';
export { QkmsContext, type QkmsContextValue } from './context.js';
export { useQkms, usePrivy, type UsePrivyResult } from './hooks/usePrivy.js';
export { useWallets, type UseWalletsResult } from './hooks/useWallets.js';
export {
  useCreateWallet,
  type CreateWalletOptions,
  type CreateWalletResult,
  type UseCreateWalletResult,
} from './hooks/useCreateWallet.js';
export {
  useSignMessage,
  type SignMessageInput,
  type SignMessageOptions,
  type UseSignMessageResult,
} from './hooks/useSignMessage.js';
export {
  useFundWallet,
  useLinkAccount,
  useMfaEnrollment,
  useCrossAppAccounts,
  useImportWallet,
  useExportWallet,
  useSigners,
} from './hooks/stubs.js';

// Re-export the core types most apps will need.
export type {
  ConnectedWallet,
  Wallet,
  User,
  EIP1193Provider,
  Hex,
} from '@quilibrium/qkms-sdk-core';
