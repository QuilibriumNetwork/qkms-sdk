import { createContext } from 'react';
import type {
  ConnectedWallet,
  QkmsRpcClient,
  QnzmAuthClient,
  SidecarLike,
  StorageAdapter,
  User,
} from '@quilibrium/qkms-sdk-core';

export interface QkmsContextValue {
  ready: boolean;
  authenticated: boolean;
  user: User | null;
  /** Developer's appId (QNZM account ID). */
  appId: string;
  /** Client API key for auth bridge requests. */
  clientKey: string;
  /** This browser sidecar's identity ID (hex). */
  sidecarId: string;
  /** MPC participants for key creation (resolved from config + this sidecar). */
  participants: string[];
  /** MPC threshold (default 2). */
  threshold: number;
  client: QkmsRpcClient | null;
  /**
   * Either an in-process `Sidecar` (Node / SSR) or a `WorkerSidecar` proxy
   * (browser). Consumers only ever need the lifecycle methods, so both
   * satisfy the common `SidecarLike` interface.
   */
  sidecar: SidecarLike | null;
  storage: StorageAdapter | null;
  wallets: ConnectedWallet[];
  /** Default chain id used when creating EVM wallets and signing transactions. */
  defaultChainId: number;
  /** Optional upstream RPC URL passed to created EthereumProviders. */
  evmRpcUrl?: string;
  /**
   * Internal state-mutation hook used by hooks like useCreateWallet to
   * register a freshly created wallet without going through the polling loop.
   */
  registerWallet: (wallet: ConnectedWallet) => void;

  /** Auth bridge client (available when qnzmServer is configured). */
  authClient: QnzmAuthClient | null;
  /** Current JWT token (set after login()). */
  jwt: string | null;
  /** Update credentials dynamically (used by login()). */
  setCredentials: (accessKey: string, secretKey: string) => void;
  /** Update JWT dynamically (used by login()). */
  setJwt: (jwt: string) => void;
  /** Update user dynamically (used by login()). */
  setUser: (user: User) => void;
}

export const QkmsContext = createContext<QkmsContextValue | null>(null);
