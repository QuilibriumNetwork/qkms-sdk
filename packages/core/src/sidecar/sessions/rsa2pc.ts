// RSA 2PC session — 2-party RSA key generation backed by mpc-wasm.
//
// Protocol overview (client/sidecar perspective):
//   Round 0: Receive server's prime commitment → send client's prime commitment
//   Round 1: Receive server's prime reveal → verify commitment → send client prime reveal
//   Round 2: Receive key share (dShare, n, e) → verify n = p*q → send confirmation
//
// Sign/decrypt after DKG uses the RSA-N Shoup threshold path (RSASession)
// since the additive d-shares from 2PC are directly usable by Shoup.
//
// References:
//   wasm/mpc-wasm/mpcrsa/rsa_keygen.go — RSA2PCClientSession
//   qkms/src/mpc/rsa_keygen.go — server-side RSA2PCSession

import { loadMpcWasm, type MpcWasmApi } from '@quilibrium/mpc-wasm';
import type { QkmsTask } from '../../types.js';
import type { ProtocolSession, SessionContext } from '../dispatch.js';

// ============================================================
// Wire types
// ============================================================

interface ServerData {
  protocol?: string;
  keySpec?: string;
  keySize?: number;
  partyIDMap?: Record<string, number>;
  /** The server's RSA keygen message (RSAKeyGenMessage). */
  serverMessage?: ServerKeyGenMessage;
  /** Alternatively, wrapped in partyContributions. */
  partyContributions?: Record<string, unknown>;
}

interface ServerKeyGenMessage {
  round?: number;
  protocol?: string;
  primeCommitment?: string; // base64
  prime?: string; // base64
  primeCommitKey?: string; // base64
  dShare?: string; // base64
  n?: string; // base64
  e?: string; // base64
  publicKey?: string; // base64
  instructions?: string;
}

interface KeyShare {
  dShare: string; // base64
  n: string; // base64
  q?: string; // base64 — client's prime
}

// ============================================================
// Encoding helpers
// ============================================================

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64');
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s);
}

function base64ToBytes(b64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(b64, 'base64'));
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function parseServerData(task: QkmsTask): ServerData {
  if (!task.ServerData) return {};
  if (typeof task.ServerData === 'string') {
    try {
      return JSON.parse(task.ServerData) as ServerData;
    } catch {
      return {};
    }
  }
  return task.ServerData as unknown as ServerData;
}

// ============================================================
// Session
// ============================================================

export class RSA2PCSession implements ProtocolSession {
  private apiPromise: Promise<MpcWasmApi> | null = null;
  /** Cache of completed key shares keyed by taskId. */
  private readonly completedKeyShares = new Map<string, string>();

  /**
   * Persistence callback. Wired to StorageAdapter to save the RSA key share
   * when 2PC DKG completes.
   */
  onKeyShareReady?: (keyId: string, keyShareJson: string, publicKeyB64: string) => Promise<void>;

  private getApi(): Promise<MpcWasmApi> {
    if (!this.apiPromise) this.apiPromise = loadMpcWasm();
    return this.apiPromise;
  }

  canHandle(task: QkmsTask): boolean {
    const proto = (task.Protocol ?? '').toLowerCase();
    // Only handle 2-of-2 RSA keygen. RSA-N DKG and sign/decrypt use RSASession.
    return proto === 'rsa-2pc' || proto === 'rsa-2of2' || proto === 'rsa_2pc';
  }

  async process(task: QkmsTask, ctx: SessionContext): Promise<void> {
    const operation = (task.Operation ?? '').toLowerCase();
    if (operation === 'createkey') {
      await this.processDKG(task, ctx);
    } else {
      throw new Error(`RSA2PCSession: unsupported operation ${task.Operation}. Use RSASession for sign/decrypt.`);
    }
  }

  private async processDKG(task: QkmsTask, ctx: SessionContext): Promise<void> {
    const api = await this.getApi();
    const serverData = parseServerData(task);

    // Re-poll after completion: re-emit confirmation.
    const cachedKeyShareJson = this.completedKeyShares.get(task.TaskId);
    if (cachedKeyShareJson) {
      await ctx.client.updateTask({
        TaskId: task.TaskId,
        ClientData: { round: 3, confirmed: true },
      });
      return;
    }

    if (task.Round === 0) {
      // Init: generate client prime, create commitment.
      const keySize = serverData.keySize ?? 2048;

      const initResult = JSON.parse(
        api.rsa_2pc_init(JSON.stringify({ taskId: task.TaskId, keySize })),
      ) as { primeCommitment?: string; error?: string };

      if (initResult.error) throw new Error(`RSA 2PC init: ${initResult.error}`);

      // Send the client's prime commitment as round 1 response.
      await ctx.client.updateTask({
        TaskId: task.TaskId,
        ClientData: { round: 1, primeCommitment: initResult.primeCommitment },
      });
      return;
    }

    // Rounds 1+: extract the server's message and advance the client session.
    const serverMsg = this.extractServerMessage(serverData, ctx.sidecarId);
    if (!serverMsg) {
      throw new Error(`RSA 2PC: no server message at round ${task.Round}`);
    }

    const serverMsgB64 = bytesToBase64(
      new TextEncoder().encode(JSON.stringify(serverMsg)),
    );

    const roundResult = JSON.parse(
      api.rsa_2pc_round(JSON.stringify({ taskId: task.TaskId, serverMsg: serverMsgB64 })),
    ) as { response?: string; complete?: boolean; keyShare?: string; error?: string };

    if (roundResult.error) throw new Error(`RSA 2PC round: ${roundResult.error}`);

    // Decode client response.
    const responseBytes = roundResult.response
      ? base64ToBytes(roundResult.response)
      : new Uint8Array();
    const clientResponse = responseBytes.length > 0
      ? JSON.parse(new TextDecoder().decode(responseBytes))
      : {};

    if (roundResult.complete && roundResult.keyShare) {
      const keyShareBytes = base64ToBytes(roundResult.keyShare);
      const keyShareJson = new TextDecoder().decode(keyShareBytes);

      this.completedKeyShares.set(task.TaskId, keyShareJson);

      if (this.onKeyShareReady && task.KeyId) {
        // Parse to extract n for a "public key" identifier.
        const ks = JSON.parse(keyShareJson) as KeyShare;
        await this.onKeyShareReady(task.KeyId, keyShareJson, ks.n);
      }
    }

    // Submit client's response.
    await ctx.client.updateTask({
      TaskId: task.TaskId,
      ClientData: clientResponse,
    });
  }

  /**
   * Extract the server's RSAKeyGenMessage from serverData. The server may
   * put it directly in `serverMessage` or wrap it in `partyContributions`
   * under the server's sidecar key.
   */
  private extractServerMessage(
    serverData: ServerData,
    _mySidecarId: string,
  ): ServerKeyGenMessage | null {
    if (serverData.serverMessage) return serverData.serverMessage;

    // Fall back to looking in partyContributions for a non-us entry.
    if (serverData.partyContributions) {
      for (const [, value] of Object.entries(serverData.partyContributions)) {
        if (value && typeof value === 'object') {
          const msg = value as Record<string, unknown>;
          if (msg.protocol === 'rsa-2pc' || msg.round != null) {
            return msg as unknown as ServerKeyGenMessage;
          }
        }
      }
    }
    return null;
  }
}
