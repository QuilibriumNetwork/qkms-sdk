// Qkms — the framework-agnostic vanilla SDK class.
//
// Under the hood this is the same underlying sidecar that qkms-sdk-react
// uses; the difference is the API shape (class methods vs hooks) and how
// the embedded wallet records are stored. Apps that only need wallet ops
// can use this package directly without pulling in React.

import {
  BLSSession,
  DKLs23Session,
  Decaf448Session,
  EthereumProvider,
  FROSTSession,
  QkmsRpcClient,
  RSASession,
  RSA2PCSession,
  Sidecar,
  SolanaProvider,
  WorkerSidecar,
  canUseSidecarWorker,
  createSidecarWorker,
  evmChecksumAddressFromPublicKey,
  type ConnectedWallet,
  type EIP1193Provider,
  type SidecarLike,
  type SolanaProvider as SolanaProviderType,
  type StorageAdapter,
  type User,
  type Wallet,
} from '@quilibrium/qkms-sdk-core';
import {
  LocalStorage,
  VanillaStorageAdapter,
  type QkmsVanillaStorage,
} from './storage.js';

export interface QkmsOptions {
  /** QNZM access key id. */
  appId: string;
  /** Unused by qkms-sdk, kept for API symmetry. */
  clientId?: string;
  /**
   * Storage backend used for the sidecar identity + key shares + wallet list.
   * Must implement the `getItem`/`setItem`/`removeItem` interface —
   * `LocalStorage` from this package is the default.
   */
  storage: QkmsVanillaStorage;
  /** QNZM secret key. Required for real QKMS calls. */
  appSecret?: string;
  /** QKMS server URL. Defaults to https://qkms.quilibrium.com. */
  server?: string;
  /** AWS SigV4 region. Defaults to us-east-1. */
  region?: string;
  /** Default EVM chain id for wallet providers. Defaults to 1 (mainnet). */
  defaultChainId?: number;
  /** Optional upstream RPC URL for EIP-1193 read methods. */
  evmRpcUrl?: string;
  /** Optional Solana RPC URL for signAndSendTransaction. */
  solanaRpcUrl?: string;
  /**
   * If set to `false`, runs the MPC sidecar on the main thread instead of
   * inside a Web Worker. Default: auto (worker when available, direct
   * Sidecar otherwise). Disable for SSR, tests, or debugging.
   */
  useWorker?: boolean;
}

/** Tag kept on wallet records so listWallets can filter on chain type. */
const WALLET_STORAGE_PREFIX = 'wallet/';

interface StoredWalletRecord {
  address: string;
  keyId: string;
  chainType: 'ethereum' | 'solana';
  chainId?: number;
  createdAt: number;
}

const DEFAULT_QKMS_SERVER = 'https://qkms.quilibrium.com';

/** Framework-agnostic QKMS SDK class. */
export class Qkms {
  /** Public access to the underlying storage. */
  readonly storage: QkmsVanillaStorage;
  readonly appId: string;

  /** Core RPC client. */
  readonly client: QkmsRpcClient;
  /**
   * Either an in-process `Sidecar` (Node / SSR) or a `WorkerSidecar` proxy
   * (browser). Consumers only need the lifecycle methods, so both satisfy
   * the common `SidecarLike` interface.
   */
  readonly sidecar: SidecarLike;

  private readonly storageAdapter: VanillaStorageAdapter;
  private readonly defaultChainId: number;
  private readonly evmRpcUrl?: string;
  private readonly solanaRpcUrl?: string;
  private userCache: User | null = null;
  private sidecarStarted = false;
  private sidecarStartPromise: Promise<void> | null = null;

  // -------------------------------------------------------------------------
  // Sub-namespaces (auth, user, embeddedWallet, mfa, etc.)
  // -------------------------------------------------------------------------

  readonly user = {
    /** Fetch the current user record. Synthesized from the sidecar identity. */
    get: async (): Promise<{ user: User }> => {
      await this.ensureSidecarStarted();
      if (!this.userCache) {
        const id = await this.sidecar.getSidecarId().catch(() => 'unknown');
        this.userCache = {
          id: `did:qkms:${id}`,
          createdAt: new Date(),
          linkedAccounts: [],
          entropyId: id,
          entropyIdVerifier: this.appId,
        };
      }
      return { user: this.userCache };
    },
  };

  readonly auth = {
    logout: async (): Promise<void> => {
      this.sidecar.stop();
      this.sidecarStarted = false;
      this.sidecarStartPromise = null;
      this.userCache = null;
    },
    /**
     * Email-code login. qkms-sdk has no IdP — apps must mint QNZM
     * credentials via the `qnzm-auth` bridge and pass them into
     * `new Qkms({ appSecret })`.
     */
    email: {
      sendCode: this.unsupportedMethod('auth.email.sendCode'),
      loginWithCode: this.unsupportedMethod('auth.email.loginWithCode'),
    },
    phone: {
      sendCode: this.unsupportedMethod('auth.phone.sendCode'),
      loginWithCode: this.unsupportedMethod('auth.phone.loginWithCode'),
    },
    siwe: {
      init: this.unsupportedMethod('auth.siwe.init'),
      loginWithSiwe: this.unsupportedMethod('auth.siwe.loginWithSiwe'),
    },
    siws: {
      fetchNonce: this.unsupportedMethod('auth.siws.fetchNonce'),
      login: this.unsupportedMethod('auth.siws.login'),
    },
    oauth: {
      generateURL: this.unsupportedMethod('auth.oauth.generateURL'),
      loginWithCode: this.unsupportedMethod('auth.oauth.loginWithCode'),
      linkWithCode: this.unsupportedMethod('auth.oauth.linkWithCode'),
    },
  };

  readonly mfa = {
    initEnrollMfa: this.unsupportedMethod('mfa.initEnrollMfa'),
    submitEnrollMfa: this.unsupportedMethod('mfa.submitEnrollMfa'),
  };

  /**
   * MFA event emitter. No-op in qkms-sdk (no MFA support).
   */
  readonly mfaPromises = {
    on(_event: 'mfaRequired', _handler: (...args: unknown[]) => void): void {
      /* no-op */
    },
    off(_event: 'mfaRequired', _handler: (...args: unknown[]) => void): void {
      /* no-op */
    },
  };

  readonly embeddedWallet = {
    /** Create an embedded Ethereum wallet via QKMS threshold DKG. */
    create: async (_opts: { chainType?: 'ethereum' } = {}): Promise<Wallet> => {
      return this.createWalletInternal('ethereum');
    },
    /** Create an embedded Solana wallet (Ed25519 via FROST). */
    createSolana: async (): Promise<Wallet> => {
      return this.createWalletInternal('solana');
    },
    /** Construct an EIP-1193 provider bound to an existing embedded wallet. */
    getEthereumProvider: (args: {
      wallet: Wallet;
      entropyId?: string;
      entropyIdVerifier?: string;
    }): EIP1193Provider => {
      return new EthereumProvider({
        client: this.client,
        keyId: args.wallet.keyId,
        address: args.wallet.address,
        chainId: args.wallet.chainId ?? this.defaultChainId,
        rpcUrl: this.evmRpcUrl,
      });
    },
    /** Construct a Solana provider bound to an existing embedded wallet. */
    getSolanaProvider: (
      account: Wallet,
      _entropyId?: string,
      _entropyIdVerifier?: string,
    ): SolanaProviderType => {
      return new SolanaProvider({
        client: this.client,
        keyId: account.keyId,
        address: account.address,
        rpcUrl: this.solanaRpcUrl,
      });
    },
    /**
     * Iframe URL — not applicable. QKMS runs in-page via wasm, so this
     * returns an empty string.
     */
    getURL: (): string => '',
    /**
     * Message handler for iframe communication. No-op in qkms-sdk because
     * there's no iframe.
     */
    onMessage: (_data: unknown): void => {
      /* no-op */
    },
  };

  // -------------------------------------------------------------------------
  // Construction
  // -------------------------------------------------------------------------

  constructor(opts: QkmsOptions) {
    if (!opts.appId) throw new Error('Qkms: appId is required');
    if (!opts.storage) throw new Error('Qkms: storage is required (pass new LocalStorage())');

    this.appId = opts.appId;
    this.storage = opts.storage;
    this.storageAdapter = new VanillaStorageAdapter(opts.storage);
    this.defaultChainId = opts.defaultChainId ?? 1;
    this.evmRpcUrl = opts.evmRpcUrl;
    this.solanaRpcUrl = opts.solanaRpcUrl;

    const server = opts.server ?? DEFAULT_QKMS_SERVER;
    const secretKey = opts.appSecret ?? '';
    this.client = new QkmsRpcClient({
      server,
      accessKey: opts.appId,
      secretKey,
      region: opts.region,
    });

    // Decide whether to run the sidecar in a Worker or on this thread.
    // The WorkerSidecar path is ~250ms faster to first-DKG (no main-thread
    // wasm boot cost) and — more importantly — doesn't block rendering
    // during MPC rounds.
    const shouldUseWorker = opts.useWorker ?? canUseSidecarWorker();

    if (shouldUseWorker) {
      // Worker backend. The worker constructs its own storage adapter
      // against the same IndexedDB database (IDB supports concurrent
      // worker access). The worker also builds its own client + all
      // protocol sessions — we just hand it the config.
      //
      // Vanilla storage is usually `LocalStorage` (sync wrapper around
      // window.localStorage); the worker can't reach localStorage, so we
      // key the worker's IndexedDbStorage off the appId. Apps that inject
      // a non-default vanilla storage should pass `useWorker: false` and
      // the vanilla path will still use it.
      this.sidecar = new WorkerSidecar(createSidecarWorker(), {
        client: { server, accessKey: opts.appId, secretKey, region: opts.region },
        dbName: `qkms-sdk-${opts.appId}`,
        useTofN: false,
      });
    } else {
      // Direct in-process Sidecar. Used in Node / SSR / tests. All
      // sessions are constructed inline with callbacks bound to the
      // vanilla storage adapter.
      const dklsSession = new DKLs23Session();
      dklsSession.loadKeyShare = async (keyId) => {
        const stored = await this.storageAdapter.get(`keyshare/${keyId}`);
        if (!stored) return null;
        return new TextDecoder().decode(stored);
      };
      dklsSession.onKeyShareReady = async (keyId, keyShareHex) => {
        await this.storageAdapter.put(
          `keyshare/${keyId}`,
          new TextEncoder().encode(keyShareHex),
        );
      };

      const frostSession = new FROSTSession();
      frostSession.loadKeyShare = async (keyId) => {
        const stored = await this.storageAdapter.get(`frost-keyshare/${keyId}`);
        if (!stored) return null;
        return new TextDecoder().decode(stored);
      };
      frostSession.onKeyShareReady = async (keyId, keyShareJson) => {
        await this.storageAdapter.put(
          `frost-keyshare/${keyId}`,
          new TextEncoder().encode(keyShareJson),
        );
      };

      const decaf448Session = new Decaf448Session();
      decaf448Session.loadKeyShare = async (keyId) => {
        const stored = await this.storageAdapter.get(`decaf448-keyshare/${keyId}`);
        if (!stored) return null;
        return new TextDecoder().decode(stored);
      };
      decaf448Session.onKeyShareReady = async (keyId, keyShareJson) => {
        await this.storageAdapter.put(
          `decaf448-keyshare/${keyId}`,
          new TextEncoder().encode(keyShareJson),
        );
      };

      const blsSession = new BLSSession();
      blsSession.loadKeyShare = async (keyId) => {
        const stored = await this.storageAdapter.get(`bls-keyshare/${keyId}`);
        if (!stored) return null;
        return new TextDecoder().decode(stored);
      };
      blsSession.onKeyShareReady = async (keyId, keyShareJson) => {
        await this.storageAdapter.put(
          `bls-keyshare/${keyId}`,
          new TextEncoder().encode(keyShareJson),
        );
      };

      const rsaSession = new RSASession();
      rsaSession.loadKeyShare = async (keyId) => {
        const stored = await this.storageAdapter.get(`rsa-keyshare/${keyId}`);
        if (!stored) return null;
        return new TextDecoder().decode(stored);
      };
      rsaSession.onKeyShareReady = async (keyId, keyShareJson) => {
        await this.storageAdapter.put(
          `rsa-keyshare/${keyId}`,
          new TextEncoder().encode(keyShareJson),
        );
      };

      const rsa2pcSession = new RSA2PCSession();
      rsa2pcSession.onKeyShareReady = async (keyId, keyShareJson) => {
        await this.storageAdapter.put(
          `rsa2pc-keyshare/${keyId}`,
          new TextEncoder().encode(keyShareJson),
        );
      };

      this.sidecar = new Sidecar({
        client: this.client,
        storage: this.storageAdapter,
        sessions: [dklsSession, frostSession, decaf448Session, blsSession, rsaSession, rsa2pcSession],
        useTofN: false,
      });
    }
  }

  // -------------------------------------------------------------------------
  // Surface methods for compatibility that qkms-sdk either implements
  // differently or doesn't support.
  // -------------------------------------------------------------------------

  /** Set the iframe message poster — no-op in qkms-sdk (no iframe). */
  setMessagePoster(_poster: unknown): void {
    /* no-op */
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  private async ensureSidecarStarted(): Promise<void> {
    if (this.sidecarStarted) return;
    if (!this.sidecarStartPromise) {
      this.sidecarStartPromise = this.sidecar.start().then(
        () => {
          this.sidecarStarted = true;
        },
        (err) => {
          this.sidecarStartPromise = null;
          throw err;
        },
      );
    }
    return this.sidecarStartPromise;
  }

  private async createWalletInternal(chainType: 'ethereum' | 'solana'): Promise<Wallet> {
    await this.ensureSidecarStarted();

    if (chainType === 'solana') {
      throw new Error(
        'Qkms.embeddedWallet.createSolana: gated on a working FROST-Ed25519 session. ' +
          'Current mpc-wasm supports Ed448 + Decaf448; Solana-flavored FROST-Ed25519 ' +
          'needs a nekryptology keyspec tweak. See packages/core/src/sidecar/sessions/frost.ts.',
      );
    }

    // Create an ECDSA key via QKMS (DKLs23 DKG drives via the sidecar).
    const res = await this.client.createKey({
      KeySpec: 'ECC_SECG_P256K1',
      KeyUsage: 'SIGN_VERIFY',
      Origin: 'AWS_KMS',
    });
    const keyId = res.KeyMetadata.KeyId;

    // Wait for DKG to complete (GetPublicKey succeeds only after finalize).
    const publicKey = await this.waitForPublicKey(keyId);
    const address = evmChecksumAddressFromPublicKey(publicKey);

    const record: StoredWalletRecord = {
      address,
      keyId,
      chainType: 'ethereum',
      chainId: this.defaultChainId,
      createdAt: Date.now(),
    };
    await this.storageAdapter.put(
      `${WALLET_STORAGE_PREFIX}${address.toLowerCase()}`,
      new TextEncoder().encode(JSON.stringify(record)),
    );

    return {
      address,
      keyId,
      walletClientType: 'privy',
      connectorType: 'embedded',
      chainId: this.defaultChainId,
      chainType: 'ethereum',
      createdAt: record.createdAt,
    };
  }

  private async waitForPublicKey(
    keyId: string,
    timeoutMs = 60_000,
    intervalMs = 500,
  ): Promise<Uint8Array> {
    const deadline = Date.now() + timeoutMs;
    let lastError: unknown = null;
    while (Date.now() < deadline) {
      try {
        const res = await this.client.getPublicKey({ KeyId: keyId });
        if (res.PublicKey) return base64ToBytes(res.PublicKey);
      } catch (err) {
        lastError = err;
      }
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
    throw new Error(
      `Qkms.createWallet: timed out waiting for DKG completion${lastError ? `: ${String(lastError)}` : ''}`,
    );
  }

  /** Factory for stub methods that qkms-sdk doesn't support. */
  private unsupportedMethod(name: string): (...args: unknown[]) => Promise<never> {
    return async () => {
      throw new Error(
        `${name} is not supported in qkms-sdk. Identity flows (OAuth, email/SMS, MFA, SIWE) ` +
          `are out of scope for this SDK — apps must mint QNZM credentials via a separate ` +
          `service and pass them into new Qkms({ appSecret }).`,
      );
    };
  }
}

// Keep the type exports at module scope so consumers can import them.
export type { ConnectedWallet, User, Wallet, EIP1193Provider } from '@quilibrium/qkms-sdk-core';

function base64ToBytes(b64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(b64, 'base64'));
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export { Qkms as Privy };
