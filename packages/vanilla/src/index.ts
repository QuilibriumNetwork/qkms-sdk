// Public surface of @quilibrium/qkms-sdk.

export { Qkms, Privy, type QkmsOptions } from './qkms.js';
export {
  LocalStorage,
  VanillaStorageAdapter,
  type QkmsVanillaStorage,
} from './storage.js';
export {
  getUserEmbeddedEthereumWallet,
  getUserEmbeddedSolanaWallet,
  getEntropyDetailsFromUser,
  addSessionSigners,
  removeSessionSigners,
} from './helpers.js';
// Re-export core types so vanilla consumers don't need a second dependency.
export type {
  ConnectedWallet,
  EIP1193Provider,
  User,
  Wallet,
} from '@quilibrium/qkms-sdk-core';
