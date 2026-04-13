// QkmsClient — Node-side resource API.
//
// Pass `{appId, appSecret}` (QNZM accessKey/secretKey) plus an optional QKMS
// server URL. Internally we boot an in-process Sidecar with FilesystemStorage
// so all DKG rounds happen in-process and key shares persist across restarts.

import {
  BLSSession,
  DKLs23Session,
  Decaf448Session,
  FROSTSession,
  FilesystemStorage,
  QkmsRpcClient,
  RSASession,
  Sidecar,
  type StorageAdapter,
} from '@quilibrium/qkms-sdk-core';
import { WalletsResource } from './resources/wallets.js';
import { KeyQuorumsResource } from './resources/keyQuorums.js';
import { PoliciesResource } from './resources/policies.js';
import { AuthResource } from './resources/auth.js';
import { UsersResource } from './resources/users.js';

export interface QkmsClientOptions {
  /** QNZM access key id. */
  appId: string;
  /** QNZM secret key. */
  appSecret: string;
  /** QKMS server URL. Defaults to https://qkms.quilibrium.com. */
  server?: string;
  /** AWS region for SigV4. Defaults to us-east-1. */
  region?: string;
  /** Filesystem directory for sidecar state (key shares, identity). Defaults to ./qkms-sdk-data. */
  dataDir?: string;
  /** Storage adapter override — useful for tests. */
  storage?: StorageAdapter;
  /** Default chain id used by ethereum().sendTransaction when CAIP2 is not provided. */
  defaultChainId?: number;
  /**
   * Optional map of CAIP2 chain id → JSON-RPC URL. Used by sendTransaction
   * to broadcast signed transactions. Apps that don't broadcast (just sign)
   * can leave this empty.
   */
  rpcUrls?: Record<string, string>;
  /** QNZM server URL for auth/user/policy operations. */
  qnzmServer?: string;
}

const DEFAULT_SERVER = 'https://qkms.quilibrium.com';
const DEFAULT_DATA_DIR = './qkms-sdk-data';

/**
 * Node-side QKMS client. Use this from server-side Node code to issue wallet
 * operations against QKMS without the React provider boilerplate.
 *
 * The sidecar starts lazily on the first resource access. Call `sidecar.start()`
 * directly if you need to register the sidecar identity early.
 */
export class QkmsClient {
  readonly opts: QkmsClientOptions;
  readonly rpcClient: QkmsRpcClient;
  readonly sidecar: Sidecar;
  readonly storage: StorageAdapter;
  readonly defaultChainId: number;
  readonly rpcUrls: Record<string, string>;
  private started = false;
  private startPromise: Promise<void> | null = null;
  private dklsSession: DKLs23Session;
  private frostSession: FROSTSession;
  private decaf448Session: Decaf448Session;
  private blsSession: BLSSession;
  private rsaSession: RSASession;

  // Resource caches
  private _wallets?: WalletsResource;
  private _keyQuorums?: KeyQuorumsResource;
  private _policies?: PoliciesResource;
  private _auth?: AuthResource;
  private _users?: UsersResource;

  constructor(opts: QkmsClientOptions) {
    if (!opts.appId) throw new Error('QkmsClient: appId is required');
    if (!opts.appSecret) throw new Error('QkmsClient: appSecret is required');
    this.opts = opts;
    this.defaultChainId = opts.defaultChainId ?? 1;
    this.rpcUrls = opts.rpcUrls ?? {};

    this.rpcClient = new QkmsRpcClient({
      server: opts.server ?? DEFAULT_SERVER,
      accessKey: opts.appId,
      secretKey: opts.appSecret,
      region: opts.region,
    });

    this.storage = opts.storage ?? new FilesystemStorage(opts.dataDir ?? DEFAULT_DATA_DIR);

    this.dklsSession = new DKLs23Session();
    this.dklsSession.loadKeyShare = async (keyId) => {
      const stored = await this.storage.get(`keyshare/${keyId}`);
      if (!stored) return null;
      return new TextDecoder().decode(stored);
    };
    this.dklsSession.onKeyShareReady = async (keyId, keyShareHex) => {
      await this.storage.put(`keyshare/${keyId}`, new TextEncoder().encode(keyShareHex));
    };

    this.frostSession = new FROSTSession();
    this.frostSession.loadKeyShare = async (keyId) => {
      const stored = await this.storage.get(`frost-keyshare/${keyId}`);
      if (!stored) return null;
      return new TextDecoder().decode(stored);
    };
    this.frostSession.onKeyShareReady = async (keyId, keyShareJson) => {
      await this.storage.put(`frost-keyshare/${keyId}`, new TextEncoder().encode(keyShareJson));
    };

    this.decaf448Session = new Decaf448Session();
    this.decaf448Session.loadKeyShare = async (keyId) => {
      const stored = await this.storage.get(`decaf448-keyshare/${keyId}`);
      if (!stored) return null;
      return new TextDecoder().decode(stored);
    };
    this.decaf448Session.onKeyShareReady = async (keyId, keyShareJson) => {
      await this.storage.put(`decaf448-keyshare/${keyId}`, new TextEncoder().encode(keyShareJson));
    };

    this.blsSession = new BLSSession();
    this.blsSession.loadKeyShare = async (keyId) => {
      const stored = await this.storage.get(`bls-keyshare/${keyId}`);
      if (!stored) return null;
      return new TextDecoder().decode(stored);
    };
    this.blsSession.onKeyShareReady = async (keyId, keyShareJson) => {
      await this.storage.put(`bls-keyshare/${keyId}`, new TextEncoder().encode(keyShareJson));
    };

    this.rsaSession = new RSASession();
    this.rsaSession.loadKeyShare = async (keyId) => {
      const stored = await this.storage.get(`rsa-keyshare/${keyId}`);
      if (!stored) return null;
      return new TextDecoder().decode(stored);
    };
    this.rsaSession.onKeyShareReady = async (keyId, keyShareJson) => {
      await this.storage.put(`rsa-keyshare/${keyId}`, new TextEncoder().encode(keyShareJson));
    };

    this.sidecar = new Sidecar({
      client: this.rpcClient,
      storage: this.storage,
      sessions: [
        this.dklsSession,
        this.frostSession,
        this.decaf448Session,
        this.blsSession,
        this.rsaSession,
      ],
      useTofN: false,
    });
  }

  /**
   * Start the in-process sidecar so DKG and signing tasks are processed.
   * Idempotent — safe to call from multiple resource methods. Resources call
   * this internally on first use.
   */
  async ensureStarted(): Promise<void> {
    if (this.started) return;
    if (!this.startPromise) {
      this.startPromise = this.sidecar.start().then(() => {
        this.started = true;
      });
    }
    return this.startPromise;
  }

  /** Stop the sidecar polling loop and release resources. */
  stop(): void {
    this.sidecar.stop();
    this.started = false;
    this.startPromise = null;
  }

  // ---------------------------------------------------------------------------
  // Resource API
  // ---------------------------------------------------------------------------

  wallets(): WalletsResource {
    if (!this._wallets) {
      this._wallets = new WalletsResource(this);
    }
    return this._wallets;
  }

  keyQuorums(): KeyQuorumsResource {
    if (!this._keyQuorums) {
      this._keyQuorums = new KeyQuorumsResource(this);
    }
    return this._keyQuorums;
  }

  policies(): PoliciesResource {
    if (!this._policies) {
      this._policies = new PoliciesResource(this);
    }
    return this._policies;
  }

  auth(): AuthResource {
    if (!this._auth) {
      this._auth = new AuthResource(this);
    }
    return this._auth;
  }

  users(): UsersResource {
    if (!this._users) {
      this._users = new UsersResource(this);
    }
    return this._users;
  }
}

export { QkmsClient as PrivyClient };
export type PrivyClientOptions = QkmsClientOptions;
