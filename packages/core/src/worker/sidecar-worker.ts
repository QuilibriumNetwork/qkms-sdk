// Sidecar Worker entrypoint — runs the entire MPC sidecar stack (polling
// loop, dispatcher, all protocol sessions, all wasm modules) off the main
// thread so DKG and threshold signing don't jank the UI.
//
// This file is loaded as a Web Worker via:
//
//   const worker = new Worker(new URL('./sidecar-worker.js', import.meta.url),
//                             { type: 'module' });
//
// Bundlers with worker support (Vite, webpack 5+, esbuild 0.19+) see the
// `new URL(..., import.meta.url)` pattern and bundle this file as a separate
// chunk, pulling in all its transitive deps (core + wasm modules).
//
// The worker boots lazily — it waits for a `start` RPC from the main thread
// which supplies the configuration (server URL, credentials, storage db
// name). Before that, all other RPCs fail with "worker not started".

import { QkmsRpcClient } from '../client.js';
import { IndexedDbStorage } from '../storage/indexeddb.js';
import { Sidecar, type SidecarOptions } from '../sidecar/index.js';
import { DKLs23Session } from '../sidecar/sessions/dkls23.js';
import { FROSTSession } from '../sidecar/sessions/frost.js';
import { Decaf448Session } from '../sidecar/sessions/decaf448.js';
import { BLSSession } from '../sidecar/sessions/bls.js';
import { RSASession } from '../sidecar/sessions/rsa.js';
import { RSA2PCSession } from '../sidecar/sessions/rsa2pc.js';
import type { QkmsClientConfig } from '../types.js';
import { RpcServer, type RpcEndpoint } from './rpc.js';

// `self` in a DedicatedWorkerGlobalScope matches our RpcEndpoint interface
// closely enough to use directly.
const endpoint: RpcEndpoint = self as unknown as RpcEndpoint;
const server = new RpcServer(endpoint);

let sidecar: Sidecar | null = null;

interface StartArgs {
  /** QkmsRpcClient config. */
  client: QkmsClientConfig;
  /** IndexedDB database name used by this sidecar instance. */
  dbName: string;
  /** Optional polling interval override. */
  pollIntervalMs?: number;
  /** If true, use ListTasksForSidecar (t-of-n). Default false (2-of-2). */
  useTofN?: boolean;
  /** Whether to auto-register on start. Default true. */
  autoRegister?: boolean;
}

function requireStarted(): Sidecar {
  if (!sidecar) {
    throw new Error('worker: sidecar not started — call start() first');
  }
  return sidecar;
}

function buildSidecar(args: StartArgs): Sidecar {
  const client = new QkmsRpcClient(args.client);
  const storage = new IndexedDbStorage(args.dbName);

  // Construct every protocol session with its own storage namespace.
  const dklsSession = new DKLs23Session();
  dklsSession.loadKeyShare = async (keyId) => {
    const stored = await storage.get(`keyshare/${keyId}`);
    return stored ? new TextDecoder().decode(stored) : null;
  };
  dklsSession.onKeyShareReady = async (keyId, keyShareHex) => {
    await storage.put(`keyshare/${keyId}`, new TextEncoder().encode(keyShareHex));
  };

  const frostSession = new FROSTSession();
  frostSession.loadKeyShare = async (keyId) => {
    const stored = await storage.get(`frost-keyshare/${keyId}`);
    return stored ? new TextDecoder().decode(stored) : null;
  };
  frostSession.onKeyShareReady = async (keyId, keyShareJson) => {
    await storage.put(`frost-keyshare/${keyId}`, new TextEncoder().encode(keyShareJson));
  };

  const decaf448Session = new Decaf448Session();
  decaf448Session.loadKeyShare = async (keyId) => {
    const stored = await storage.get(`decaf448-keyshare/${keyId}`);
    return stored ? new TextDecoder().decode(stored) : null;
  };
  decaf448Session.onKeyShareReady = async (keyId, keyShareJson) => {
    await storage.put(`decaf448-keyshare/${keyId}`, new TextEncoder().encode(keyShareJson));
  };

  const blsSession = new BLSSession();
  blsSession.loadKeyShare = async (keyId) => {
    const stored = await storage.get(`bls-keyshare/${keyId}`);
    return stored ? new TextDecoder().decode(stored) : null;
  };
  blsSession.onKeyShareReady = async (keyId, keyShareJson) => {
    await storage.put(`bls-keyshare/${keyId}`, new TextEncoder().encode(keyShareJson));
  };

  const rsaSession = new RSASession();
  rsaSession.loadKeyShare = async (keyId) => {
    const stored = await storage.get(`rsa-keyshare/${keyId}`);
    return stored ? new TextDecoder().decode(stored) : null;
  };
  rsaSession.onKeyShareReady = async (keyId, keyShareJson) => {
    await storage.put(`rsa-keyshare/${keyId}`, new TextEncoder().encode(keyShareJson));
  };

  const rsa2pcSession = new RSA2PCSession();
  rsa2pcSession.onKeyShareReady = async (keyId, keyShareJson) => {
    await storage.put(`rsa2pc-keyshare/${keyId}`, new TextEncoder().encode(keyShareJson));
  };

  const options: SidecarOptions = {
    client,
    storage,
    sessions: [frostSession, decaf448Session, blsSession, rsaSession, rsa2pcSession, dklsSession],
    useTofN: args.useTofN ?? false,
    pollIntervalMs: args.pollIntervalMs,
    autoRegister: args.autoRegister,
  };
  return new Sidecar(options);
}

server.on('start', async (rawArgs) => {
  if (sidecar) {
    // Idempotent: calling start() twice is fine.
    return { sidecarId: await sidecar.getSidecarId() };
  }
  const args = rawArgs as StartArgs;
  if (!args?.client?.server) {
    throw new Error('worker: start requires client config with server URL');
  }
  try {
    sidecar = buildSidecar(args);
    await sidecar.start();
    const sidecarId = await sidecar.getSidecarId();
    return { sidecarId };
  } catch (err) {
    sidecar = null;
    throw err;
  }
});

server.on('stop', async () => {
  if (sidecar) {
    sidecar.stop();
    sidecar = null;
  }
  return null;
});

server.on('getSidecarId', async () => {
  return requireStarted().getSidecarId();
});

server.on('register', async () => {
  await requireStarted().register();
  return null;
});

// The worker script runs at import time. Signal readiness so the main
// thread knows the worker has loaded without waiting for a full start().
server.emit('ready', {});
