// Sidecar orchestrator. Glues together identity, polling, and protocol
// dispatch. Construct once per credential pair, call start() to begin
// processing tasks, stop() to drain.

import type { QkmsRpcClient } from '../client.js';
import type { StorageAdapter } from '../storage/adapter.js';
import type { SidecarConfig, SidecarIdentity } from '../types.js';
import { TaskDispatcher, type ProtocolSession } from './dispatch.js';
import { loadOrCreateIdentity } from './identity.js';
import { PeerChannel } from './peer-channel.js';
import { PollLoop } from './poll.js';
import { initAllWasm } from './wasm-init.js';

/** Convert a hex string to base64 (Go []byte JSON encoding). */
function hexToBase64(hex: string): string {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64');
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s);
}

export interface SidecarOptions extends SidecarConfig {
  client: QkmsRpcClient;
  storage: StorageAdapter;
  /** Protocol sessions to register on startup. */
  sessions?: ProtocolSession[];
  /** If true, use ListTasksForSidecar (t-of-n). Default: false (2-of-2). */
  useTofN?: boolean;
}

const DEFAULT_POLL_INTERVAL_MS = 250;

export class Sidecar {
  readonly client: QkmsRpcClient;
  readonly storage: StorageAdapter;
  readonly dispatcher: TaskDispatcher;
  peerChannel: PeerChannel | null = null;
  private readonly opts: SidecarOptions;
  private identity: SidecarIdentity | null = null;
  private pollLoop: PollLoop | null = null;
  private started = false;

  constructor(opts: SidecarOptions) {
    this.client = opts.client;
    this.storage = opts.storage;
    this.opts = opts;
    this.dispatcher = new TaskDispatcher();
    for (const s of opts.sessions ?? []) {
      this.dispatcher.register(s);
    }
  }

  /** Add a protocol session after construction. */
  registerSession(session: ProtocolSession): void {
    this.dispatcher.register(session);
  }

  /** Returns the identity, loading or generating it on first call. */
  async getIdentity(): Promise<SidecarIdentity> {
    if (!this.identity) {
      this.identity = await loadOrCreateIdentity(this.storage);
    }
    return this.identity;
  }

  /** Sidecar id (X448 public key SHA-256 prefix, hex). */
  async getSidecarId(): Promise<string> {
    const id = await this.getIdentity();
    return id.sidecarId;
  }

  /** Register the sidecar identity with the QKMS server. */
  async register(): Promise<void> {
    const id = await this.getIdentity();
    // QKMS expects []byte fields as base64 (Go JSON convention), not hex.
    await this.client.registerSidecar({
      SidecarId: id.sidecarId,
      IdentityKey: hexToBase64(id.identityPublicX448),
      SignedPreKey: hexToBase64(id.signedPreKeyPublicX448),
      PreKeySignature: hexToBase64(id.preKeySignature),
      SigningKey: hexToBase64(id.signingPublicEd448),
    });
  }

  /** Start polling. Loads identity, optionally registers, then begins poll loop. */
  async start(): Promise<void> {
    if (this.started) return;
    // Initialize all wasm-bindgen modules before any session or identity code runs.
    await initAllWasm();
    const id = await this.getIdentity();
    this.peerChannel = new PeerChannel(id);
    if (this.opts.autoRegister !== false) {
      try {
        await this.register();
      } catch (err) {
        // Treat already-registered as success; bubble anything else.
        const msg = err instanceof Error ? err.message : String(err);
        if (!/already registered|exists/i.test(msg)) {
          throw err;
        }
      }
    }
    this.pollLoop = new PollLoop({
      client: this.client,
      dispatcher: this.dispatcher,
      identity: id,
      peerChannel: this.peerChannel ?? undefined,
      pollIntervalMs: this.opts.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS,
      useTofN: this.opts.useTofN ?? false,
    });
    this.pollLoop.start();
    this.started = true;
  }

  stop(): void {
    if (!this.started) return;
    this.pollLoop?.stop();
    this.pollLoop = null;
    this.started = false;
  }
}

export { TaskDispatcher } from './dispatch.js';
export type { ProtocolSession, SessionContext } from './dispatch.js';
export { PollLoop } from './poll.js';
export type { PollLoopConfig } from './poll.js';
export { loadOrCreateIdentity, generateIdentity, identityKeysAsBytes } from './identity.js';
