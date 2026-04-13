// Core types for QKMS-backed wallets and QNZM-issued credentials.

export type Hex = `0x${string}`;

/** EIP-712 typed-data envelope. Loosely mirrors viem's TypedDataDefinition. */
export interface EIP712TypedData {
  domain: {
    name?: string;
    version?: string;
    chainId?: number;
    verifyingContract?: Hex;
    salt?: Hex;
  };
  types: Record<string, Array<{ name: string; type: string }>>;
  primaryType: string;
  message: Record<string, unknown>;
}

/** Supported QKMS key specs. */
export type KeySpec =
  | 'ECC_SECG_P256K1'
  | 'ECC_NIST_P256'
  | 'ECC_BLS12_381'
  | 'ECC_BLS48_581'
  | 'ECC_DECAF_448'
  | 'ECC_ED25519'
  | 'ECC_ED448'
  | 'EDDSA_ED25519'
  | 'EDDSA_ED448'
  | 'RSA_2048'
  | 'RSA_3072'
  | 'RSA_4096';

/** Chain identifier for wallet creation. */
export type ChainType =
  | 'ethereum'
  | 'solana'
  | 'cosmos'
  | 'stellar'
  | 'sui'
  | 'tron'
  | 'bitcoin-segwit'
  | 'near'
  | 'ton'
  | 'starknet'
  | 'spark';

/** A wallet record stored client-side after createWallet. */
export interface Wallet {
  /** Wallet's chain-specific address (0x... for EVM, base58 for Solana, etc.). */
  address: string;
  /** QKMS key ARN — the underlying KMS key id. */
  keyId: string;
  /** Wallet client type — distinguishes embedded wallets from external. */
  walletClientType: 'privy' | string;
  /** Connector type. */
  connectorType: 'embedded' | string;
  /** EIP-155 chain id for EVM wallets, undefined for non-EVM. */
  chainId?: number;
  /** What chain this wallet belongs to. */
  chainType: ChainType;
  /** When the wallet was created (unix ms). */
  createdAt: number;
}

/** EIP-1193 provider for EVM wallets — what `wallet.getProvider()` returns. */
export interface EIP1193Provider {
  request(args: { method: string; params?: unknown[] | object }): Promise<unknown>;
  on?(event: string, listener: (...args: unknown[]) => void): void;
  removeListener?(event: string, listener: (...args: unknown[]) => void): void;
}

/** Solana wallet provider — returned by `wallet.getProvider()` for Solana wallets. */
export interface SolanaWalletProvider {
  signMessage(message: Uint8Array): Promise<Uint8Array>;
  signTransaction(serializedMessage: Uint8Array): Promise<Uint8Array>;
  signAndSendTransaction?(serializedTx: Uint8Array): Promise<{ signature: string }>;
}

/** A connected wallet with provider access — what useWallets returns. */
export interface ConnectedWallet extends Wallet {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  getProvider(): Promise<EIP1193Provider | SolanaWalletProvider | any>;
}

/** A linked account on the user record. */
export interface LinkedAccount {
  type: 'wallet' | 'email' | 'phone' | 'oauth' | string;
  address?: string;
  chainId?: string;
  walletClientType?: string;
  connectorType?: string;
  // We carry only what the wallet-ops surface needs.
}

/** User object. */
export interface User {
  id: string;
  createdAt: Date;
  linkedAccounts: LinkedAccount[];
  /** Synthesized entropy id — apps that pass these to providers will work. */
  entropyId?: string;
  entropyIdVerifier?: string;
  /** Convenience accessor for the embedded wallet. */
  wallet?: {
    address: string;
    chainId?: string;
    walletClientType: string;
    connectorType: string;
  };
}

/** Configuration for the underlying QKMS RPC client. */
export interface QkmsClientConfig {
  /** QKMS server base URL — e.g. "https://qkms.quilibrium.com". */
  server: string;
  /** QNZM access key id. */
  accessKey: string;
  /** QNZM secret key. */
  secretKey: string;
  /** AWS region for SigV4 (defaults to "us-east-1"). */
  region?: string;
}

/** Sidecar configuration. */
export interface SidecarConfig {
  /** Polling interval in milliseconds (default: 250ms). */
  pollIntervalMs?: number;
  /** Optional sidecar id; if absent one is derived from the X448 identity key. */
  sidecarId?: string;
  /** Whether to register the sidecar with the server on start (default: true). */
  autoRegister?: boolean;
}

/** Result of a CreateKey RPC call. */
export interface CreateKeyResponse {
  KeyMetadata: {
    KeyId: string;
    Arn?: string;
    KeySpec?: KeySpec;
    KeyState?: string;
    CreationDate?: number;
  };
}

/** A QKMS task as surfaced by ListTasks. */
export interface QkmsTask {
  TaskId: string;
  Operation: string;
  Status: 'AWAITING_CLIENT' | 'IN_PROGRESS' | 'COMPLETED' | 'FAILED' | string;
  Round: number;
  TotalRounds: number;
  KeyId?: string;
  KeySpec?: KeySpec;
  Protocol?: string;
  Participants?: string[];
  PartyIdMap?: Record<string, number>;
  ServerData?: string; // raw JSON
  PartyContributions?: Record<string, string>;
  CreatedAt?: number;
  UpdatedAt?: number;
}

/** Sidecar identity persisted across restarts. */
export interface SidecarIdentity {
  /** SHA256 prefix of the X448 identity public key, hex (16 bytes = 32 chars). */
  sidecarId: string;
  /** Hex-encoded private keys. */
  identityPrivateX448: string;
  identityPublicX448: string;
  signedPreKeyPrivateX448: string;
  signedPreKeyPublicX448: string;
  signingPrivateEd448: string;
  signingPublicEd448: string;
  /** Ed448 signature over the signed pre-key public bytes. */
  preKeySignature: string;
}
