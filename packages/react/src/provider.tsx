// QkmsProvider — the React context root.
//
// Apps construct it with an `appId` (mapped to QNZM access key id) and a
// `config` object. Wires up the QKMS RPC client, the sidecar (runs in a
// Web Worker when available, falls back to main thread), and the EVM wallet
// hooks.

import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import {
  BLSSession,
  DKLs23Session,
  Decaf448Session,
  FROSTSession,
  IndexedDbStorage,
  QkmsRpcClient,
  QnzmAuthClient,
  RSASession,
  RSA2PCSession,
  Sidecar,
  WorkerSidecar,
  canUseSidecarWorker,
  createSidecarWorker,
  EthereumProvider,
  SolanaProvider,
  evmChecksumAddressFromPublicKey,
  solanaAddressFromPublicKey,
  type ConnectedWallet,
  type SidecarLike,
  type StorageAdapter,
  type User,
} from '@quilibrium/qkms-sdk-core';
import { QkmsContext, type QkmsContextValue } from './context.js';

function base64ToBytes(b64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(b64, 'base64'));
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Resolve the MPC participants list. If the dev specified participants,
 * ensure this browser's sidecar is included. Otherwise default to
 * ['service', thisSidecarId].
 */
function resolveParticipants(configured: string[] | undefined, mySidecarId: string): string[] {
  if (!mySidecarId) return [];
  if (!configured || configured.length === 0) {
    return ['service', mySidecarId];
  }
  // Ensure this sidecar is in the list
  if (!configured.includes(mySidecarId)) {
    return [...configured, mySidecarId];
  }
  return configured;
}

/** Per-chain embedded-wallet creation policy. */
export type CreateOnLoginPolicy = 'users-without-wallets' | 'all-users' | 'off';

export interface QkmsClientConfig {
  embeddedWallets?: {
    ethereum?: { createOnLogin?: CreateOnLoginPolicy };
    solana?: { createOnLogin?: CreateOnLoginPolicy };
  };
  appearance?: {
    walletChainType?: 'ethereum-and-solana' | 'ethereum-only' | 'solana-only';
  };
  defaultChain?: { id: number };
  /**
   * Public Ethereum RPC URL passed to wallet providers for read-only methods,
   * so the EthereumProvider can serve `eth_chainId`/`eth_call` without an
   * extra wrapper.
   */
  evmRpcUrl?: string;
  /**
   * QNZM credentials. Apps must mint these from a QNZM-aware service
   * (e.g. the `qnzm-auth` bridge) and inject them here.
   */
  credentials?: {
    accessKey: string;
    secretKey: string;
    region?: string;
  };
  /** QKMS server URL — defaults to https://qkms.quilibrium.com. */
  qkmsServer?: string;
  /** QNZM server URL for auth operations. If provided, login() becomes functional. */
  qnzmServer?: string;
  /** Client API key for auth bridge (non-secret, safe to embed in browser JS). */
  clientKey?: string;
  /**
   * MPC participants for key creation. Each entry is a sidecar ID.
   * Use `'service'` for the QKMS server sidecar.
   *
   * If not specified, defaults to `['service', <this browser's sidecar ID>]`
   * (standard 2-of-2 with the QKMS server sidecar).
   *
   * For browser-only 2-of-2, pass two browser sidecar IDs (no 'service').
   * For 2-of-3, pass three IDs (e.g. `['service', browser1, browser2]`).
   *
   * The current browser's sidecar ID is automatically appended if not
   * already in the list.
   */
  participants?: string[];
  /**
   * MPC threshold — minimum number of parties required to sign.
   * Defaults to 2. Must be <= number of participants.
   */
  threshold?: number;
  /**
   * If true, the sidecar polls QKMS via `ListTasksForSidecar` (filtered by
   * its own sidecar id). Required for any threshold scheme beyond 2-of-2,
   * since multi-party DKG generates a per-sidecar task and each sidecar
   * must only process its own.
   *
   * Auto-enabled when `participants.length > 2` or `threshold > 2`. Set
   * explicitly to override the heuristic.
   */
  useTofN?: boolean;
}

export interface QkmsProviderProps {
  /** Opaque app id. Treated as the access key id if no `credentials` are provided. */
  appId: string;
  config?: QkmsClientConfig;
  /** Optional storage adapter override; defaults to IndexedDbStorage. */
  storage?: StorageAdapter;
  /**
   * If set to false, runs the MPC sidecar on the main thread instead of
   * inside a Web Worker. Defaults to auto (worker when available, direct
   * Sidecar otherwise).
   *
   * Set this to `false` for SSR, tests without a jsdom Worker polyfill,
   * or debugging.
   */
  useWorker?: boolean;
  children: ReactNode;
}

const DEFAULT_QKMS_SERVER = 'https://qkms.quilibrium.com';

export function QkmsProvider({
  appId,
  config,
  storage,
  useWorker,
  children,
}: QkmsProviderProps): ReactNode {
  const sessionKey = `qkms-session-${appId}`;

  // Load persisted session from localStorage on mount
  const loadSession = () => {
    if (typeof localStorage === 'undefined') return null;
    try {
      const raw = localStorage.getItem(sessionKey);
      return raw ? JSON.parse(raw) as { creds: { accessKey: string; secretKey: string }; user: User; jwt: string } : null;
    } catch { return null; }
  };

  const savedSession = loadSession();
  const [ready, setReady] = useState(false);
  const [user, setUser] = useState<User | null>(savedSession?.user ?? null);
  const [wallets, setWallets] = useState<ConnectedWallet[]>([]);
  const [jwt, setJwt] = useState<string | null>(savedSession?.jwt ?? null);
  const [sidecarId, setSidecarId] = useState('');
  const [dynamicCreds, setDynamicCreds] = useState<{ accessKey: string; secretKey: string } | null>(savedSession?.creds ?? null);
  const sidecarRef = useRef<SidecarLike | null>(null);
  const storageRef = useRef<StorageAdapter | null>(null);

  const accessKey = dynamicCreds?.accessKey ?? config?.credentials?.accessKey ?? appId;
  const secretKey = dynamicCreds?.secretKey ?? config?.credentials?.secretKey ?? '';
  const region = config?.credentials?.region;
  const server = config?.qkmsServer ?? DEFAULT_QKMS_SERVER;

  // Persist session to localStorage when credentials/user/jwt change
  useEffect(() => {
    if (typeof localStorage === 'undefined') return;
    if (dynamicCreds && user && jwt) {
      localStorage.setItem(sessionKey, JSON.stringify({ creds: dynamicCreds, user, jwt }));
    }
  }, [dynamicCreds, user, jwt, sessionKey]);

  // RPC client — created eagerly so it's available immediately after login.
  const client = useMemo(
    () => secretKey ? new QkmsRpcClient({ server, accessKey, secretKey, region }) : null,
    [server, accessKey, secretKey, region],
  );

  // Auth bridge client (only when qnzmServer is configured)
  const authClient = useMemo(
    () => config?.qnzmServer ? new QnzmAuthClient({ qnzmServer: config.qnzmServer }) : null,
    [config?.qnzmServer],
  );
  const defaultChainId = config?.defaultChain?.id ?? 1;
  const evmRpcUrl = config?.evmRpcUrl;

  // Initialize client + sidecar once on mount.
  useEffect(() => {
    // Don't initialize until we have credentials (either from config or login)
    if (!secretKey) {
      setReady(false);
      return;
    }

    let cancelled = false;

    // Decide t-of-n polling mode. Anything beyond plain 2-of-2 needs
    // ListTasksForSidecar so each sidecar only processes its own task.
    const cfgParticipants = config?.participants ?? [];
    const cfgThreshold = config?.threshold ?? 2;
    const useTofN = config?.useTofN ?? (cfgParticipants.length > 2 || cfgThreshold > 2);

    async function init(): Promise<void> {
      // DB name must be stable across logins for the same user so key shares
      // persist. Use the user's stable identifier (from JWT claims) when
      // available, fall back to appId for pre-login (manual creds) mode.
      const userId = user?.id ?? '';
      const dbName = userId ? `qkms-sdk-${appId}-${userId}` : `qkms-sdk-${appId}`;
      const adapter = storage ?? new IndexedDbStorage(dbName);
      storageRef.current = adapter;

      // Decide whether to run the sidecar in a Worker or on the main thread.
      // Default: worker when available (browser), direct Sidecar otherwise.
      const shouldUseWorker = useWorker ?? canUseSidecarWorker();
      let sidecar: SidecarLike;

      if (shouldUseWorker) {
        // Worker backend — all MPC state + wasm lives inside the worker.
        // The storage adapter on the main thread is still used by wallet
        // list hooks; the worker has its own IndexedDbStorage instance
        // pointing at the same database (IndexedDB supports concurrent
        // access across workers).
        sidecar = new WorkerSidecar(createSidecarWorker(), {
          client: { server, accessKey, secretKey, region },
          dbName,
          useTofN,
        });
      } else {
        // Direct Sidecar — runs on this thread. Used in Node / SSR /
        // environments without Worker support. All sessions are constructed
        // inline with callbacks bound to the main-thread storage adapter.
        const dklsSession = new DKLs23Session();
        dklsSession.loadKeyShare = async (keyId) => {
          const stored = await adapter.get(`keyshare/${keyId}`);
          if (!stored) return null;
          return new TextDecoder().decode(stored);
        };
        dklsSession.onKeyShareReady = async (keyId, keyShareHex, publicKeyHex) => {
          await adapter.put(`keyshare/${keyId}`, new TextEncoder().encode(keyShareHex));
          if (publicKeyHex) {
            await adapter.put(`pubkey/${keyId}`, new TextEncoder().encode(publicKeyHex));
          }
        };

        const frostSession = new FROSTSession();
        frostSession.loadKeyShare = async (keyId) => {
          const stored = await adapter.get(`frost-keyshare/${keyId}`);
          if (!stored) return null;
          return new TextDecoder().decode(stored);
        };
        frostSession.onKeyShareReady = async (keyId, keyShareJson) => {
          await adapter.put(`frost-keyshare/${keyId}`, new TextEncoder().encode(keyShareJson));
        };

        const decaf448Session = new Decaf448Session();
        decaf448Session.loadKeyShare = async (keyId) => {
          const stored = await adapter.get(`decaf448-keyshare/${keyId}`);
          if (!stored) return null;
          return new TextDecoder().decode(stored);
        };
        decaf448Session.onKeyShareReady = async (keyId, keyShareJson) => {
          await adapter.put(`decaf448-keyshare/${keyId}`, new TextEncoder().encode(keyShareJson));
        };

        const blsSession = new BLSSession();
        blsSession.loadKeyShare = async (keyId) => {
          const stored = await adapter.get(`bls-keyshare/${keyId}`);
          if (!stored) return null;
          return new TextDecoder().decode(stored);
        };
        blsSession.onKeyShareReady = async (keyId, keyShareJson) => {
          await adapter.put(`bls-keyshare/${keyId}`, new TextEncoder().encode(keyShareJson));
        };

        const rsaSession = new RSASession();
        rsaSession.loadKeyShare = async (keyId) => {
          const stored = await adapter.get(`rsa-keyshare/${keyId}`);
          if (!stored) return null;
          return new TextDecoder().decode(stored);
        };
        rsaSession.onKeyShareReady = async (keyId, keyShareJson) => {
          await adapter.put(`rsa-keyshare/${keyId}`, new TextEncoder().encode(keyShareJson));
        };

        const rsa2pcSession = new RSA2PCSession();
        rsa2pcSession.onKeyShareReady = async (keyId, keyShareJson) => {
          await adapter.put(`rsa2pc-keyshare/${keyId}`, new TextEncoder().encode(keyShareJson));
        };

        sidecar = new Sidecar({
          client: client!,
          storage: adapter,
          sessions: [frostSession, decaf448Session, blsSession, rsaSession, rsa2pcSession, dklsSession],
          useTofN,
        });
      }

      sidecarRef.current = sidecar;

      try {
        await sidecar.start();
      } catch (err) {
        // Surface but don't block UI; consumers can read the error from the
        // RPC client on subsequent calls.
        console.error('[qkms-sdk] sidecar start failed', err);
      }

      // Construct a synthetic user record from the sidecar identity.
      const id = await sidecar.getSidecarId().catch(() => 'unknown');
      setSidecarId(id);
      const synthesized: User = {
        id: `did:qkms:${id}`,
        createdAt: new Date(),
        linkedAccounts: [],
        entropyId: id,
        entropyIdVerifier: accessKey,
      };

      if (cancelled) return;
      // Only set the synthetic user if login() hasn't already set a real one.
      setUser((prev) => prev ?? synthesized);
      setReady(true);

      // Load existing wallets from QKMS
      if (client) {
        try {
          const listResult = await client.call<Record<string, unknown>, { Keys?: Array<{ KeyId: string; KeyArn: string }> }>('ListKeys', {});
          const Keys = listResult.Keys;
          const loaded: ConnectedWallet[] = [];
          for (const key of Keys ?? []) {
            try {
              const pkRes = await client.getPublicKey({ KeyId: key.KeyId });
              const pkBytes = base64ToBytes(pkRes.PublicKey);
              const keySpec = pkRes.KeySpec ?? '';
              let address: string;
              let chainType: string;
              if (keySpec.includes('P256K1') || keySpec.includes('NIST')) {
                address = evmChecksumAddressFromPublicKey(pkBytes);
                chainType = 'ethereum';
              } else if (keySpec.includes('ED25519')) {
                address = solanaAddressFromPublicKey(pkBytes);
                chainType = 'solana';
              } else {
                // Unknown key type — show hex of public key
                let hex = '';
                for (let i = 0; i < pkBytes.length; i++) hex += pkBytes[i]!.toString(16).padStart(2, '0');
                address = '0x' + hex;
                chainType = keySpec || 'unknown';
              }
              loaded.push({
                keyId: key.KeyId,
                address,
                walletClientType: 'privy',
                connectorType: 'embedded',
                chainId: chainType === 'ethereum' ? defaultChainId : 0,
                chainType: chainType as 'ethereum' | 'solana',
                createdAt: 0,
                getProvider: async () => {
                  if (chainType === 'ethereum') {
                    return new EthereumProvider({
                      client: client!,
                      keyId: key.KeyId,
                      address,
                      chainId: defaultChainId,
                      rpcUrl: evmRpcUrl,
                    });
                  }
                  return new SolanaProvider({
                    client: client!,
                    keyId: key.KeyId,
                    address,
                  });
                },
              });
            } catch {
              // Skip keys that can't be loaded (e.g. non-wallet keys)
            }
          }
          if (loaded.length > 0 && !cancelled) {
            setWallets(loaded);
          }
        } catch {
          // Wallet listing failed; will retry on next mount
        }
      }
    }

    void init();
    return () => {
      cancelled = true;
      sidecarRef.current?.stop();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [accessKey, secretKey, server, user?.id]);

  const value: QkmsContextValue = useMemo(
    () => ({
      ready,
      authenticated: !!user || (ready && !!secretKey),
      user,
      appId,
      clientKey: config?.clientKey ?? '',
      sidecarId,
      participants: resolveParticipants(config?.participants, sidecarId),
      threshold: config?.threshold ?? 2,
      client,
      sidecar: sidecarRef.current,
      storage: storageRef.current,
      wallets,
      defaultChainId,
      evmRpcUrl,
      registerWallet: (wallet) => {
        setWallets((prev) => {
          if (prev.some((w) => w.address.toLowerCase() === wallet.address.toLowerCase())) {
            return prev;
          }
          return [...prev, wallet];
        });
      },
      authClient,
      jwt,
      setCredentials: (ak: string, sk: string) => setDynamicCreds({ accessKey: ak, secretKey: sk }),
      setJwt,
      setUser,
    }),
    [ready, user, wallets, client, secretKey, defaultChainId, evmRpcUrl, authClient, jwt],
  );

  return <QkmsContext.Provider value={value}>{children}</QkmsContext.Provider>;
}

export { QkmsProvider as PrivyProvider };
