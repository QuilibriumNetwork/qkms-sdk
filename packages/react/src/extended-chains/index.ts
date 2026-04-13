// @quilibrium/qkms-sdk-react/extended-chains — hooks for non-EVM, non-Solana chains.
//
// Currently supports Cosmos (secp256k1 + bech32), Sui (Ed25519 + Blake2b),
// and Stellar (Ed25519 + StrKey).
//
// Each chain's useCreateWallet triggers the appropriate MPC DKG session:
//   - Cosmos: DKLs23 (secp256k1) — same key type as Ethereum
//   - Sui:    FROST (Ed25519) — same key type as Solana
//   - Stellar: FROST (Ed25519)

export {
  useCreateCosmosWallet,
  type CosmosCreateWalletOptions,
} from './useCreateCosmosWallet.js';

export {
  useCreateSuiWallet,
  type SuiCreateWalletOptions,
} from './useCreateSuiWallet.js';

export {
  useCreateStellarWallet,
  type StellarCreateWalletOptions,
} from './useCreateStellarWallet.js';
