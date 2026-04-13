// WorkerSidecar — main-thread proxy that looks like a regular Sidecar but
// runs all the MPC work inside a Web Worker.
//
// Usage (browser / Vite):
//
//   import { createSidecarWorker, WorkerSidecar } from '@quilibrium/qkms-sdk-core';
//
//   const worker = createSidecarWorker();
//   const sidecar = new WorkerSidecar(worker, {
//     client: { server, accessKey, secretKey },
//     dbName: 'qkms-sdk',
//   });
//   await sidecar.start();
//
// In Node or non-browser environments, `typeof Worker === 'undefined'` and
// apps should fall back to the regular in-process `Sidecar`. The React
// provider and the vanilla `Qkms` class both do this automatically.

import type { QkmsClientConfig } from '../types.js';
import { RpcClient } from './rpc.js';

/**
 * Common surface of `Sidecar` and `WorkerSidecar`. Consumers that only need
 * lifecycle methods (start/stop/getSidecarId/register) can accept this
 * interface and work with either backend.
 */
export interface SidecarLike {
  start(): Promise<void>;
  stop(): void;
  getSidecarId(): Promise<string>;
  register(): Promise<void>;
}

export interface WorkerSidecarOptions {
  /** Configuration to pass to the worker's QkmsRpcClient. */
  client: QkmsClientConfig;
  /** IndexedDB database name. Defaults to `qkms-sdk`. */
  dbName?: string;
  /** Polling interval override. */
  pollIntervalMs?: number;
  /** If true, use ListTasksForSidecar (t-of-n). */
  useTofN?: boolean;
  /** Whether to auto-register on start. Default true. */
  autoRegister?: boolean;
}

/**
 * Factory for the Sidecar Worker. Uses the `new URL(..., import.meta.url)`
 * pattern that Vite / webpack / esbuild pick up at build time to bundle the
 * worker entry point as a separate chunk.
 *
 * Apps that want to supply their own Worker instance (for testing, or to
 * use a SharedWorker) can pass one directly to `new WorkerSidecar(worker, ...)`
 * instead of calling this factory.
 */
export function createSidecarWorker(): Worker {
  if (typeof Worker === 'undefined') {
    throw new Error(
      'createSidecarWorker: Web Workers are not available in this environment. ' +
        'Use the direct Sidecar class in Node contexts.',
    );
  }
  return new Worker(new URL('./sidecar-worker.js', import.meta.url), {
    type: 'module',
  });
}

/**
 * Main-thread proxy for a Sidecar running in a Web Worker. Surface matches
 * the non-worker Sidecar's public methods: `start`, `stop`, `getSidecarId`,
 * `register`. Internal methods like `dispatch` live inside the worker only.
 */
export class WorkerSidecar implements SidecarLike {
  private readonly rpc: RpcClient;
  private started = false;
  private readyPromise: Promise<void>;
  private cachedSidecarId: string | null = null;

  constructor(
    private readonly worker: Worker,
    private readonly opts: WorkerSidecarOptions,
  ) {
    this.rpc = new RpcClient(worker);

    // The worker emits a `ready` event once its module body has executed
    // (RpcServer handlers registered, etc.). We race start() against that
    // signal so callers don't hit "worker not started" errors when calling
    // too early.
    this.readyPromise = new Promise<void>((resolve) => {
      const off = this.rpc.on('ready', () => {
        off();
        resolve();
      });
      // Fallback: if the worker is already running by the time we subscribe,
      // just resolve after a microtask.
      queueMicrotask(() => {
        // No-op: if the 'ready' event already fired, subsequent emits will
        // still be delivered to our handler. Workers typically post the
        // event after we attach, so this is just defensive.
      });
    });
  }

  /** Block until the worker module has finished booting. */
  private async waitForWorkerReady(): Promise<void> {
    // Give the worker up to 2s to emit its `ready` event. After that, we
    // optimistically proceed — `start()` will still succeed if the worker
    // just hasn't emitted yet.
    let resolved = false;
    await Promise.race([
      this.readyPromise.then(() => {
        resolved = true;
      }),
      new Promise<void>((resolve) => setTimeout(resolve, 2000)),
    ]);
    void resolved;
  }

  async start(): Promise<void> {
    if (this.started) return;
    await this.waitForWorkerReady();
    const res = (await this.rpc.call<{ sidecarId: string }>('start', {
      client: this.opts.client,
      dbName: this.opts.dbName ?? 'qkms-sdk',
      pollIntervalMs: this.opts.pollIntervalMs,
      useTofN: this.opts.useTofN,
      autoRegister: this.opts.autoRegister,
    })) ?? { sidecarId: '' };
    this.cachedSidecarId = res.sidecarId;
    this.started = true;
  }

  /** Terminate the worker. After `stop()` the proxy is no longer usable. */
  stop(): void {
    if (!this.started) return;
    try {
      this.worker.terminate();
    } catch {
      // ignore
    }
    this.started = false;
    this.cachedSidecarId = null;
  }

  /**
   * Returns the sidecar id. Cached from the `start` response so the common
   * case doesn't incur an RPC round trip.
   */
  async getSidecarId(): Promise<string> {
    if (this.cachedSidecarId) return this.cachedSidecarId;
    const id = await this.rpc.call<string>('getSidecarId');
    this.cachedSidecarId = id;
    return id;
  }

  async register(): Promise<void> {
    await this.rpc.call('register');
  }
}

/**
 * Returns true if Web Workers are available in the current environment.
 * Use this to decide whether to construct a `WorkerSidecar` or fall back to
 * the direct in-process `Sidecar`.
 */
export function canUseSidecarWorker(): boolean {
  return typeof Worker !== 'undefined' && typeof window !== 'undefined';
}
