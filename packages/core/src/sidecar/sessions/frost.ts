// FROST EdDSA session — backed by mpc-wasm (nekryptology compiled via
// GOOS=js GOARCH=wasm). Because the wasm binary is the *same Go code path*
// the server-side sidecar runs, the wire format and challenge derivation
// match byte-for-byte without any TS reimplementation.
//
// References:
//   wasm/mpc-wasm/main.go — the Go entry point we call into
//   qkms/cmd/mpc-sidecar/main.go processFROSTNKeyGen ~line 2180
//   qkms/cmd/mpc-sidecar/main.go computeFROSTNSignContribution ~line 3696

import { loadMpcWasm, type MpcWasmApi } from '@quilibrium/mpc-wasm';
import type { QkmsRpcClient } from '../../client.js';
import type { QkmsTask } from '../../types.js';
import type { ProtocolSession, SessionContext } from '../dispatch.js';

// ---------------------------------------------------------------------------
// Wire types — what the QKMS server <-> sidecar protocol carries
// ---------------------------------------------------------------------------

interface ContributionPayload {
  sidecarId?: string;
  partyId: number;
  round: number;
  // DKG round 0 fields:
  round1Bcast?: { commitments: string[]; wi: string; ci: string };
  p2pShares?: Record<string, string>;
  // DKG completion + sign init:
  complete?: boolean;
  publicKey?: string | number[];
  signature?: string | number[];
  // Sign round broadcasts:
  round2Bcast?: { zi: string | number[]; vki: string | number[] };
}

interface ServerData {
  thresholdConfig?: { threshold?: number; totalParties?: number };
  partyIDMap?: Record<string, number>;
  dkgPartyIDMap?: Record<string, number>;
  keySpec?: string;
  participants?: string[];
  message?: string | number[];
  partyContributions?: Record<string, ContributionPayload>;
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

/** Decode a server-data binary field that may be base64 string or byte array. */
function decodeServerBinary(value: unknown): Uint8Array {
  if (value == null) return new Uint8Array();
  if (typeof value === 'string') return base64ToBytes(value);
  if (Array.isArray(value)) return Uint8Array.from(value as number[]);
  throw new Error(`unexpected binary field type: ${typeof value}`);
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

export class FROSTSession implements ProtocolSession {
  /** Lazy handle to the loaded wasm API. */
  private apiPromise: Promise<MpcWasmApi> | null = null;
  /** Cache of completed key shares (JSON) keyed by `task:<taskId>`. */
  private readonly completedKeyShares = new Map<string, string>();
  /** Tracks task ids whose sign rounds we've initialized. */
  private readonly initializedSignTasks = new Set<string>();

  /**
   * Persistence callback. Apps wire this to their StorageAdapter to save
   * the FROST key share JSON when DKG completes.
   */
  onKeyShareReady?: (keyId: string, keyShareJson: string, publicKeyHex: string) => Promise<void>;

  /**
   * Resolver to fetch a stored key share for signing. Returns the
   * FROSTNClientKeyShare JSON or null if absent.
   */
  loadKeyShare?: (keyId: string) => Promise<string | null>;

  private async getApi(): Promise<MpcWasmApi> {
    if (!this.apiPromise) {
      this.apiPromise = loadMpcWasm();
    }
    return this.apiPromise;
  }

  canHandle(task: QkmsTask): boolean {
    const keySpec = task.KeySpec ?? this.extractServerDataField(task, 'keySpec') ?? '';
    const proto = (task.Protocol ?? this.extractServerDataField(task, 'protocol') ?? '').toLowerCase();
    if (keySpec === 'EDDSA_ED25519' || keySpec === 'EDDSA_ED448') return true;
    if (keySpec === 'ECC_ED25519' || keySpec === 'ECC_ED448') return true;
    if (keySpec === 'Ed25519' || keySpec === 'Ed448') return true;
    return proto === 'frost' || proto === 'frost-n';
  }

  private extractServerDataField(task: QkmsTask, field: string): string | undefined {
    const sd = parseServerData(task);
    const val = (sd as Record<string, unknown>)[field];
    return typeof val === 'string' ? val : undefined;
  }

  async process(task: QkmsTask, ctx: SessionContext): Promise<void> {
    const operation = (task.Operation ?? '').toLowerCase();
    if (operation === 'createkey') {
      await this.processDKG(task, ctx);
    } else if (operation === 'sign') {
      await this.processSign(task, ctx);
    } else {
      throw new Error(`FROSTSession: unsupported operation ${task.Operation}`);
    }
  }

  // -------------------------------------------------------------------------
  // DKG
  // -------------------------------------------------------------------------

  private async processDKG(task: QkmsTask, ctx: SessionContext): Promise<void> {
    const serverData = parseServerData(task);
    const partyIdMap = serverData.partyIDMap ?? {};
    const myPartyId = partyIdMap[ctx.sidecarId];
    if (myPartyId == null) {
      throw new Error(`FROST DKG: sidecar id ${ctx.sidecarId} not in partyIDMap`);
    }

    const cachedShareKey = `task:${task.TaskId}`;
    if (this.completedKeyShares.has(cachedShareKey)) {
      // Re-poll after completion: re-emit completion contribution.
      await this.submitContribution(task, ctx, {
        partyId: myPartyId,
        round: task.Round,
        complete: true,
      });
      return;
    }

    const threshold = serverData.thresholdConfig?.threshold ?? 2;
    const totalParties = serverData.thresholdConfig?.totalParties ?? 3;
    const keySpec = serverData.keySpec ?? 'ECC_ED25519';

    const api = await this.getApi();
    const sessionId = task.TaskId;

    if (task.Round === 0) {
      // Build the otherPartyIDs list from partyIDMap (everything that isn't us).
      const otherPartyIds: number[] = [];
      for (const [, pid] of Object.entries(partyIdMap)) {
        if (pid !== myPartyId) otherPartyIds.push(pid);
      }

      const initJson = api.dkg_init(
        JSON.stringify({
          sessionId,
          keySpec,
          partyId: myPartyId,
          threshold,
          totalParties,
          otherPartyIds,
        }),
      );
      const initRes = parseWasmResponse(initJson, 'dkg_init');
      if (!initRes.contribution) throw new Error('dkg_init returned no contribution');
      await this.submitContribution(task, ctx, initRes.contribution);
      return;
    }

    // Round > 0: drive round 2 and finalize.
    const partyContribs = serverData.partyContributions ?? {};
    if (Object.keys(partyContribs).length === 0) {
      await this.submitContribution(task, ctx, {
        partyId: myPartyId,
        round: task.Round,
      });
      return;
    }

    const roundJson = api.dkg_round(
      JSON.stringify({
        sessionId,
        mySidecarId: ctx.sidecarId,
        partyContributions: partyContribs,
      }),
    );
    const roundRes = parseWasmResponse(roundJson, 'dkg_round');
    if (!roundRes.contribution) throw new Error('dkg_round returned no contribution');
    const contribution = roundRes.contribution;

    if (roundRes.keyShare) {
      // DKG complete — persist the key share and cache.
      const keyShareJson = JSON.stringify(roundRes.keyShare);
      this.completedKeyShares.set(cachedShareKey, keyShareJson);
      api.clear(sessionId);
      if (this.onKeyShareReady && task.KeyId) {
        const publicKeyHex = bytesToHex(decodeServerBinary(contribution.publicKey));
        await this.onKeyShareReady(task.KeyId, keyShareJson, publicKeyHex);
      }
    }

    await this.submitContribution(task, ctx, contribution);
  }

  // -------------------------------------------------------------------------
  // Sign
  // -------------------------------------------------------------------------

  private async processSign(task: QkmsTask, ctx: SessionContext): Promise<void> {
    const serverData = parseServerData(task);
    const partyIdMap = serverData.partyIDMap ?? {};
    const myPartyId = partyIdMap[ctx.sidecarId];
    if (myPartyId == null) {
      throw new Error(`FROST sign: sidecar id ${ctx.sidecarId} not in partyIDMap`);
    }

    // Build cosigner ID list from dkgPartyIDMap restricted to participants.
    const dkgPartyIdMap = serverData.dkgPartyIDMap ?? {};
    const signingParticipants = serverData.participants ?? [];
    let cosignerIds: number[];
    if (signingParticipants.length > 0) {
      cosignerIds = signingParticipants
        .map((p) => dkgPartyIdMap[p])
        .filter((id): id is number => id != null);
    } else {
      cosignerIds = Object.values(dkgPartyIdMap);
    }
    if (cosignerIds.length === 0) {
      cosignerIds = Object.values(partyIdMap);
    }
    cosignerIds.sort((a, b) => a - b);

    const api = await this.getApi();
    const sessionId = `frost-sign-${task.TaskId}`;

    if (task.Round === 0) {
      if (this.initializedSignTasks.has(task.TaskId)) {
        await this.submitContribution(task, ctx, {
          partyId: myPartyId,
          round: task.Round,
        });
        return;
      }

      const message = decodeServerBinary(serverData.message);
      if (message.length === 0) {
        throw new Error('FROST sign: missing message in serverData');
      }
      if (!task.KeyId) throw new Error('FROST sign: task missing KeyId');
      if (!this.loadKeyShare) {
        throw new Error('FROST sign: loadKeyShare resolver not set on session');
      }
      const keyShareJson = await this.loadKeyShare(task.KeyId);
      if (!keyShareJson) {
        throw new Error(`FROST sign: no key share found for key ${task.KeyId}`);
      }

      // Use the DKG-time party id from dkgPartyIDMap if present.
      const dkgPartyId = dkgPartyIdMap[ctx.sidecarId] ?? myPartyId;

      const initJson = api.sign_init(
        JSON.stringify({
          sessionId,
          keyShareJson,
          message: bytesToBase64(message),
          myPartyId: dkgPartyId,
          cosignerIds,
        }),
      );
      const initRes = parseWasmResponse(initJson, 'sign_init');
      if (!initRes.contribution) throw new Error('sign_init returned no contribution');
      this.initializedSignTasks.add(task.TaskId);
      await this.submitContribution(task, ctx, initRes.contribution);
      return;
    }

    const partyContribs = serverData.partyContributions ?? {};
    if (Object.keys(partyContribs).length === 0) {
      await this.submitContribution(task, ctx, {
        partyId: myPartyId,
        round: task.Round,
      });
      return;
    }

    // task.Round 1 → run round1to2; task.Round 2 → run round2to3 (finalize).
    const handler = task.Round === 1 ? 'sign_round1to2' : 'sign_round2to3';
    const fn = task.Round === 1 ? api.sign_round1to2 : api.sign_round2to3;

    const roundJson = fn(
      JSON.stringify({
        sessionId,
        taskRound: task.Round,
        mySidecarId: ctx.sidecarId,
        partyContributions: partyContribs,
      }),
    );
    const roundRes = parseWasmResponse(roundJson, handler);
    if (!roundRes.contribution) throw new Error(`${handler} returned no contribution`);
    const contribution = roundRes.contribution;

    if (contribution.complete) {
      api.clear(sessionId);
      this.initializedSignTasks.delete(task.TaskId);
    }

    await this.submitContribution(task, ctx, contribution);
  }

  // -------------------------------------------------------------------------
  // Common
  // -------------------------------------------------------------------------

  private async submitContribution(
    task: QkmsTask,
    ctx: SessionContext,
    payload: Omit<ContributionPayload, 'sidecarId'>,
  ): Promise<void> {
    await ctx.client.updateTask({
      TaskId: task.TaskId,
      ClientData: { sidecarId: ctx.sidecarId, ...payload },
    });
  }
}

/**
 * The Go side serializes responses as `{contribution: <object>, keyShare: <object>?}`.
 * `contribution` and `keyShare` come through as embedded JSON objects (Go's
 * `json.RawMessage` is inlined verbatim by the marshaler) — NOT as strings.
 * Don't double-parse them.
 */
interface WasmResponseShape {
  contribution?: ContributionPayload;
  keyShare?: Record<string, unknown>;
  error?: string;
}

function parseWasmResponse(json: string, fnName: string): WasmResponseShape {
  let parsed: WasmResponseShape;
  try {
    parsed = JSON.parse(json) as WasmResponseShape;
  } catch {
    throw new Error(`mpc-wasm ${fnName}: invalid JSON response: ${json}`);
  }
  if (parsed.error) {
    throw new Error(`mpc-wasm ${fnName}: ${parsed.error}`);
  }
  return parsed;
}

function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i]!.toString(16).padStart(2, '0');
  return s;
}

// Avoid an unused-import warning if QkmsRpcClient ends up needed by future
// helpers; keep the type re-export so callers can match this session against
// other ProtocolSession implementations.
export type _ = QkmsRpcClient;
