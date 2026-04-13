// Public surface of @quilibrium/qkms-sdk-core.

export * from './types.js';
export { SigV4Signer, type SigV4SignerConfig } from './sigv4.js';
export {
  QnzmAuthClient,
  type QnzmAuthConfig,
  type AuthChallenge,
  type WalletLoginRequest,
  type WalletLoginResponse,
  type JWTClaims,
  type JsonWebKeySet,
} from './auth/index.js';
export {
  Sidecar,
  TaskDispatcher,
  PollLoop,
  loadOrCreateIdentity,
  generateIdentity,
  identityKeysAsBytes,
  type SidecarOptions,
  type ProtocolSession,
  type SessionContext,
  type PollLoopConfig,
} from './sidecar/index.js';
export { DKLs23Session } from './sidecar/sessions/dkls23.js';
export { Decaf448Session } from './sidecar/sessions/decaf448.js';
export { BLSSession, BLS_CONSTANTS } from './sidecar/sessions/bls.js';
export { RSASession } from './sidecar/sessions/rsa.js';
export { RSA2PCSession } from './sidecar/sessions/rsa2pc.js';
export {
  WorkerSidecar,
  createSidecarWorker,
  canUseSidecarWorker,
  type WorkerSidecarOptions,
  type SidecarLike,
} from './worker/sidecar-proxy.js';
export type {
  RpcEndpoint,
  RpcMessage,
  RpcRequest,
  RpcResponse,
  RpcEvent,
} from './worker/rpc.js';
export {
  type StorageAdapter,
  MemoryStorage,
  IndexedDbStorage,
  FilesystemStorage,
} from './storage/index.js';
export {
  evmAddressFromPublicKey,
  evmChecksumAddressFromPublicKey,
  solanaAddressFromPublicKey,
  cosmosAddressFromPublicKey,
  suiAddressFromPublicKey,
  stellarAddressFromPublicKey,
  toChecksumAddress,
  EthereumProvider,
  SolanaProvider,
  type EthereumProviderOptions,
  type SolanaProviderOptions,
  type Hex0x,
} from './wallets/index.js';
export { FROSTSession } from './sidecar/sessions/frost.js';
export {
  QkmsRpcClient,
  QkmsRpcError,
  type TrentServiceMethod,
  type RegisterSidecarRequest,
  type RegisterSidecarResponse,
  type ListTasksRequest,
  type ListTasksResponse,
  type ListTasksForSidecarRequest,
  type ClaimTaskRequest,
  type ClaimTaskResponse,
  type UpdateTaskRequest,
  type UpdateTaskResponse,
  type SendPartyMessageRequest,
  type GetPartyMessagesRequest,
  type GetPartyMessagesResponse,
  type CreateKeyRequest,
  type CreateKeyResponse,
  type SignRequest,
  type SignResponse,
  type GetPublicKeyRequest,
  type GetPublicKeyResponse,
} from './client.js';
