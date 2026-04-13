// DKLs23 protocol session — drives DKG and signing on top of dkls23-wasm.
//
// References:
//   qkms/cmd/mpc-sidecar/main.go processDKLs23KeyGen      ~lines 1896-2169
//   qkms/cmd/mpc-sidecar/main.go computeDKLs23SignContribution ~lines 3152+
//
// Wire format note: the Go sidecar serializes PartyMessage with the default
// Go json convention (capitalized FromParty/ToParty/Data, with Data as
// base64). dkls23-wasm uses snake_case + hex. We translate at the session
// boundary so the on-wire ClientData/partyContributions stay compatible
// with the existing Go server sidecar.

import * as dkls23wasm from 'dkls23wasm';
import type { QkmsRpcClient } from '../../client.js';
import type { QkmsTask } from '../../types.js';
import type { ProtocolSession, SessionContext } from '../dispatch.js';

// ---------------------------------------------------------------------------
// Wire types — what the QKMS server <-> sidecar protocol carries
// ---------------------------------------------------------------------------

/** Go-style message envelope as it appears on the QKMS wire. */
interface WirePartyMessage {
  FromParty: number;
  ToParty: number;
  /** Base64-encoded payload bytes. */
  Data: string;
}

/** Sidecar contribution payload submitted via UpdateTask.ClientData. */
interface ContributionPayload {
  sidecarId: string;
  partyId: number;
  round: number;
  messages?: WirePartyMessage[];
  complete?: boolean;
  publicKey?: string; // base64
  dkgResult?: string; // base64
  signature?: string; // base64
}

/** Local cached session state — held in memory for the duration of one task. */
interface DklsSessionState {
  internalRound: number;
  /** hex-encoded session state per dkls23-wasm convention. */
  sessionStateHex: string;
}

// ---------------------------------------------------------------------------
// dkls23-wasm result types
// ---------------------------------------------------------------------------

interface WasmPartyMessage {
  from_party: number;
  to_party: number;
  /** Hex-encoded data. */
  data: string;
}

interface WasmRoundResult {
  session_state: string;
  messages_to_send: WasmPartyMessage[];
  is_complete: boolean;
  success: boolean;
  error_message?: string;
}

interface WasmDkgInitResult {
  session_state: string;
  success: boolean;
  error_message?: string;
}

interface WasmDkgFinalResult {
  key_share: string;
  public_key: string;
  party_id: number;
  threshold: number;
  total_parties: number;
  success: boolean;
  error_message?: string;
}

interface WasmSignFinalResult {
  signature: string;
  success: boolean;
  error_message?: string;
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

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

function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i]!.toString(16).padStart(2, '0');
  return s;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function wireToWasmMessage(m: WirePartyMessage): WasmPartyMessage {
  return {
    from_party: m.FromParty,
    to_party: m.ToParty,
    data: bytesToHex(base64ToBytes(m.Data)),
  };
}

function wasmToWireMessage(m: WasmPartyMessage): WirePartyMessage {
  return {
    FromParty: m.from_party,
    ToParty: m.to_party,
    Data: bytesToBase64(hexToBytes(m.data)),
  };
}

/** Decode a server-data binary field that may be string-base64, byte array, or omitted. */
function decodeServerBinary(value: unknown): Uint8Array {
  if (value == null) return new Uint8Array();
  if (typeof value === 'string') return base64ToBytes(value);
  if (Array.isArray(value)) return Uint8Array.from(value as number[]);
  throw new Error(`unexpected binary field type: ${typeof value}`);
}

interface ServerData {
  thresholdConfig?: { threshold?: number; totalParties?: number };
  partyIDMap?: Record<string, number>;
  dkgPartyIDMap?: Record<string, number>;
  dkgSessionId?: string | number[];
  signSessionId?: string | number[];
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

/** Extract a string field from the task's ServerData JSON (like the Go sidecar does). */
function extractFromServerData(task: QkmsTask, field: string): string | undefined {
  const sd = parseServerData(task);
  const val = (sd as Record<string, unknown>)[field];
  return typeof val === 'string' ? val : undefined;
}

// ---------------------------------------------------------------------------
// DKLs23 session
// ---------------------------------------------------------------------------

/**
 * Tracks DKLs23 DKG and Sign sessions across rounds. Implements the
 * ProtocolSession interface so it can be registered on a Sidecar's dispatcher.
 */
export class DKLs23Session implements ProtocolSession {
  /** Per-task DKG state. Key: task.TaskId. */
  private readonly dkgStates = new Map<string, DklsSessionState>();
  /** Per-task Sign state. Key: `dkls23-sign-${task.TaskId}`. */
  private readonly signStates = new Map<string, DklsSessionState>();
  /** Cache of completed key shares to handle re-polls. Key: `task:${task.TaskId}` -> hex key share. */
  private readonly completedKeyShares = new Map<string, string>();

  /**
   * Optional callback fired when a key share is finalized via DKG. Apps wire
   * this to their persistence layer (e.g. StorageAdapter) to record the share.
   */
  onKeyShareReady?: (keyId: string, keyShareHex: string, publicKeyHex: string) => Promise<void>;

  /**
   * Resolver to fetch a stored key share for signing. Apps must wire this if
   * they want to support sign tasks. Returns the hex-encoded key share or
   * null if absent.
   */
  loadKeyShare?: (keyId: string) => Promise<string | null>;

  canHandle(task: QkmsTask): boolean {
    const proto = (task.Protocol ?? '').toLowerCase();
    const op = (task.Operation ?? '').toLowerCase();
    const keySpec = task.KeySpec ?? extractFromServerData(task, 'keySpec') ?? '';
    const serverProto = extractFromServerData(task, 'protocol') ?? '';
    if (proto === 'dkls23' || proto === 'dkls' || serverProto === 'dkls23') return true;
    if (op === 'createkey' && (keySpec === 'ECC_SECG_P256K1' || keySpec === 'ECC_NIST_P256')) {
      return true;
    }
    if (op === 'sign' && (keySpec === 'ECC_SECG_P256K1' || keySpec === 'ECC_NIST_P256')) {
      return true;
    }
    // Fallback: if no KeySpec/Protocol anywhere, DKLs23 is the default for
    // CreateKey/Sign (secp256k1 ECDSA is the most common case).
    if ((op === 'createkey' || op === 'sign') && !keySpec && !proto && !serverProto) {
      return true;
    }
    return false;
  }

  async process(task: QkmsTask, ctx: SessionContext): Promise<void> {
    const operation = (task.Operation ?? '').toLowerCase();
    if (operation === 'createkey') {
      await this.processDKG(task, ctx);
    } else if (operation === 'sign') {
      await this.processSign(task, ctx);
    } else {
      throw new Error(`DKLs23Session: unsupported operation ${task.Operation}`);
    }
  }

  // -------------------------------------------------------------------------
  // DKG
  // -------------------------------------------------------------------------

  private async processDKG(task: QkmsTask, ctx: SessionContext): Promise<void> {
    const serverData = parseServerData(task);
    const partyIdMap = serverData.partyIDMap ?? {};
    const myPartyId = partyIdMap[ctx.sidecarId] ?? 2;

    const cachedShareKey = `task:${task.TaskId}`;
    const cachedShare = this.completedKeyShares.get(cachedShareKey);
    if (cachedShare) {
      // Re-poll after completion: re-emit the completion contribution.
      await this.submitContribution(task, ctx, {
        sidecarId: ctx.sidecarId,
        partyId: myPartyId,
        round: task.Round,
        complete: true,
      });
      return;
    }

    const threshold = serverData.thresholdConfig?.threshold ?? 2;
    const totalParties = serverData.thresholdConfig?.totalParties ?? 3;
    const dkgSessionId = decodeServerBinary(serverData.dkgSessionId);
    if (dkgSessionId.length === 0) {
      throw new Error('DKLs23 DKG: missing dkgSessionId in serverData');
    }

    const curve = serverData.keySpec === 'ECC_NIST_P256' ? 'P256' : 'Secp256k1';

    if (task.Round === 0) {
      if (this.dkgStates.has(task.TaskId)) {
        // Already initialized for this task — re-emit the cached round 1 messages
        // by re-running round1 from the cached state. The Go sidecar just sends
        // an empty contribution in this case; we mirror that.
        await this.submitContribution(task, ctx, {
          sidecarId: ctx.sidecarId,
          partyId: myPartyId,
          round: task.Round,
        });
        return;
      }

      dkls23wasm.js_dkls23_init();
      const initJson = dkls23wasm.js_dkls23_dkg_init(
        myPartyId,
        threshold,
        totalParties,
        bytesToHex(dkgSessionId),
        curve,
      );
      const initResult = JSON.parse(initJson) as WasmDkgInitResult;
      if (!initResult.success) {
        throw new Error(`DKLs23 DKG init failed: ${initResult.error_message}`);
      }

      const round1Json = dkls23wasm.js_dkls23_dkg_round1(initResult.session_state);
      const round1 = JSON.parse(round1Json) as WasmRoundResult;
      if (!round1.success) {
        throw new Error(`DKLs23 DKG round 1 failed: ${round1.error_message}`);
      }

      this.dkgStates.set(task.TaskId, {
        internalRound: 1,
        sessionStateHex: round1.session_state,
      });

      await this.submitContribution(task, ctx, {
        sidecarId: ctx.sidecarId,
        partyId: myPartyId,
        round: task.Round,
        messages: round1.messages_to_send.map(wasmToWireMessage),
      });
      return;
    }

    // Round > 0: process incoming contributions, advance internal round.
    const partyContribs = serverData.partyContributions ?? {};
    if (Object.keys(partyContribs).length === 0) {
      await this.submitContribution(task, ctx, {
        sidecarId: ctx.sidecarId,
        partyId: myPartyId,
        round: task.Round,
      });
      return;
    }

    const session = this.dkgStates.get(task.TaskId);
    if (!session) {
      throw new Error(`DKLs23 DKG: no session for task ${task.TaskId} at round ${task.Round}`);
    }

    const incoming = collectIncomingMessages(partyContribs, ctx.sidecarId, myPartyId);
    const wasmMessages = JSON.stringify(incoming);
    const nextInternalRound = session.internalRound + 1;

    if (nextInternalRound === 2) {
      const result = JSON.parse(
        dkls23wasm.js_dkls23_dkg_round2(session.sessionStateHex, wasmMessages),
      ) as WasmRoundResult;
      if (!result.success) throw new Error(`DKLs23 DKG round 2 failed: ${result.error_message}`);
      session.internalRound = 2;
      session.sessionStateHex = result.session_state;
      await this.submitContribution(task, ctx, {
        sidecarId: ctx.sidecarId,
        partyId: myPartyId,
        round: task.Round,
        messages: result.messages_to_send.map(wasmToWireMessage),
      });
      return;
    }
    if (nextInternalRound === 3) {
      const result = JSON.parse(
        dkls23wasm.js_dkls23_dkg_round3(session.sessionStateHex, wasmMessages),
      ) as WasmRoundResult;
      if (!result.success) throw new Error(`DKLs23 DKG round 3 failed: ${result.error_message}`);
      session.internalRound = 3;
      session.sessionStateHex = result.session_state;
      await this.submitContribution(task, ctx, {
        sidecarId: ctx.sidecarId,
        partyId: myPartyId,
        round: task.Round,
        messages: result.messages_to_send.map(wasmToWireMessage),
      });
      return;
    }
    if (nextInternalRound === 4) {
      const result = JSON.parse(
        dkls23wasm.js_dkls23_dkg_finalize(session.sessionStateHex, wasmMessages),
      ) as WasmDkgFinalResult;
      if (!result.success) throw new Error(`DKLs23 DKG finalize failed: ${result.error_message}`);

      this.completedKeyShares.set(cachedShareKey, result.key_share);
      this.dkgStates.delete(task.TaskId);

      if (this.onKeyShareReady && task.KeyId) {
        await this.onKeyShareReady(task.KeyId, result.key_share, result.public_key);
      }

      await this.submitContribution(task, ctx, {
        sidecarId: ctx.sidecarId,
        partyId: myPartyId,
        round: task.Round,
        complete: true,
        publicKey: bytesToBase64(hexToBytes(result.public_key)),
        dkgResult: bytesToBase64(hexToBytes(result.key_share)),
      });
      return;
    }

    throw new Error(`DKLs23 DKG: unexpected internal round ${nextInternalRound}`);
  }

  // -------------------------------------------------------------------------
  // Sign
  // -------------------------------------------------------------------------

  private async processSign(task: QkmsTask, ctx: SessionContext): Promise<void> {
    const serverData = parseServerData(task);
    const partyIdMap = serverData.partyIDMap ?? {};
    const myPartyId = partyIdMap[ctx.sidecarId] ?? 2;

    const dkgPartyIdMap = serverData.dkgPartyIDMap ?? {};
    const signingParticipants = serverData.participants ?? [];
    let signerIds: number[];
    if (signingParticipants.length > 0) {
      signerIds = signingParticipants
        .map((p) => dkgPartyIdMap[p])
        .filter((id): id is number => id != null);
    } else {
      signerIds = Object.values(dkgPartyIdMap);
    }
    if (signerIds.length === 0) {
      signerIds = Object.values(partyIdMap);
    }
    signerIds.sort((a, b) => a - b);

    const signSessionKey = `dkls23-sign-${task.TaskId}`;
    const signSessionId = decodeServerBinary(serverData.signSessionId);
    if (signSessionId.length === 0) {
      throw new Error('DKLs23 sign: missing signSessionId in serverData');
    }

    if (task.Round === 0) {
      if (this.signStates.has(signSessionKey)) {
        await this.submitContribution(task, ctx, {
          sidecarId: ctx.sidecarId,
          partyId: myPartyId,
          round: task.Round,
        });
        return;
      }

      const message = decodeServerBinary(serverData.message);
      if (message.length !== 32) {
        throw new Error(`DKLs23 sign: expected 32-byte message hash, got ${message.length}`);
      }
      if (!task.KeyId) throw new Error('DKLs23 sign: task missing KeyId');
      if (!this.loadKeyShare) {
        throw new Error('DKLs23 sign: loadKeyShare resolver not set on session');
      }
      const keyShareHex = await this.loadKeyShare(task.KeyId);
      if (!keyShareHex) {
        throw new Error(`DKLs23 sign: no key share found for key ${task.KeyId}`);
      }

      dkls23wasm.js_dkls23_init();
      const initJson = dkls23wasm.js_dkls23_sign_init(
        keyShareHex,
        bytesToHex(message),
        JSON.stringify(signerIds),
        bytesToHex(signSessionId),
      );
      const initResult = JSON.parse(initJson) as WasmDkgInitResult;
      if (!initResult.success) throw new Error(`DKLs23 sign init failed: ${initResult.error_message}`);

      const round1Json = dkls23wasm.js_dkls23_sign_round1(initResult.session_state);
      const round1 = JSON.parse(round1Json) as WasmRoundResult;
      if (!round1.success) throw new Error(`DKLs23 sign round 1 failed: ${round1.error_message}`);

      this.signStates.set(signSessionKey, {
        internalRound: 1,
        sessionStateHex: round1.session_state,
      });

      await this.submitContribution(task, ctx, {
        sidecarId: ctx.sidecarId,
        partyId: myPartyId,
        round: task.Round,
        messages: round1.messages_to_send.map(wasmToWireMessage),
      });
      return;
    }

    const partyContribs = serverData.partyContributions ?? {};
    if (Object.keys(partyContribs).length === 0) {
      await this.submitContribution(task, ctx, {
        sidecarId: ctx.sidecarId,
        partyId: myPartyId,
        round: task.Round,
      });
      return;
    }

    const session = this.signStates.get(signSessionKey);
    if (!session) {
      throw new Error(`DKLs23 sign: no session for task ${task.TaskId} at round ${task.Round}`);
    }

    const incoming = collectIncomingMessages(partyContribs, ctx.sidecarId, myPartyId);
    const wasmMessages = JSON.stringify(incoming);
    const nextInternalRound = session.internalRound + 1;

    if (nextInternalRound === 2) {
      const result = JSON.parse(
        dkls23wasm.js_dkls23_sign_round2(session.sessionStateHex, wasmMessages),
      ) as WasmRoundResult;
      if (!result.success) throw new Error(`DKLs23 sign round 2 failed: ${result.error_message}`);
      session.internalRound = 2;
      session.sessionStateHex = result.session_state;
      await this.submitContribution(task, ctx, {
        sidecarId: ctx.sidecarId,
        partyId: myPartyId,
        round: task.Round,
        messages: result.messages_to_send.map(wasmToWireMessage),
      });
      return;
    }
    if (nextInternalRound === 3) {
      const result = JSON.parse(
        dkls23wasm.js_dkls23_sign_round3(session.sessionStateHex, wasmMessages),
      ) as WasmRoundResult;
      if (!result.success) throw new Error(`DKLs23 sign round 3 failed: ${result.error_message}`);
      session.internalRound = 3;
      session.sessionStateHex = result.session_state;
      await this.submitContribution(task, ctx, {
        sidecarId: ctx.sidecarId,
        partyId: myPartyId,
        round: task.Round,
        messages: result.messages_to_send.map(wasmToWireMessage),
      });
      return;
    }
    if (nextInternalRound === 4) {
      const result = JSON.parse(
        dkls23wasm.js_dkls23_sign_finalize(session.sessionStateHex, wasmMessages),
      ) as WasmSignFinalResult;
      if (!result.success) throw new Error(`DKLs23 sign finalize failed: ${result.error_message}`);
      this.signStates.delete(signSessionKey);

      await this.submitContribution(task, ctx, {
        sidecarId: ctx.sidecarId,
        partyId: myPartyId,
        round: task.Round,
        complete: true,
        signature: bytesToBase64(hexToBytes(result.signature)),
      });
      return;
    }

    throw new Error(`DKLs23 sign: unexpected internal round ${nextInternalRound}`);
  }

  // -------------------------------------------------------------------------
  // Common
  // -------------------------------------------------------------------------

  private async submitContribution(
    task: QkmsTask,
    ctx: SessionContext,
    payload: ContributionPayload,
  ): Promise<void> {
    // If we have a peer channel and the task is multi-party, broadcast
    // our messages to peer sidecars via E2EE.
    if (ctx.peerChannel && payload.messages && payload.messages.length > 0) {
      const partyIdMap = this.getPartyIdMap(task);
      for (const [peerId, peerPartyId] of Object.entries(partyIdMap)) {
        if (peerId === ctx.sidecarId) continue;
        if (peerId === 'service') continue;
        // Send the full contribution as JSON via E2EE
        const data = new TextEncoder().encode(JSON.stringify(payload));
        try {
          await ctx.peerChannel.sendMessage(
            ctx.client, task.TaskId, ctx.sidecarId,
            payload.partyId, peerId, peerPartyId, task.Round, data,
          );
        } catch (err) {
          console.warn('[dkls23] E2EE send to', peerId, 'failed:', err);
        }
      }
    }

    // Always submit via UpdateTask (coordinator relay) so QKMS tracks progress
    await ctx.client.updateTask({
      TaskId: task.TaskId,
      ClientData: payload,
    });
  }

  /** Extract partyIdMap from task's ServerData. */
  private getPartyIdMap(task: QkmsTask): Record<string, number> {
    const sd = parseServerData(task);
    return sd.partyIDMap ?? {};
  }
}

/**
 * Filters partyContributions for messages addressed to us (or broadcast),
 * translates from the Go wire format to the wasm wire format, and sorts by
 * sender. Mirrors the message-collection loop in main.go:2055-2091.
 */
function collectIncomingMessages(
  partyContribs: Record<string, ContributionPayload>,
  ourSidecarId: string,
  myPartyId: number,
): WasmPartyMessage[] {
  const out: WasmPartyMessage[] = [];
  for (const [sidecarKey, contrib] of Object.entries(partyContribs)) {
    if (sidecarKey === ourSidecarId) continue;
    const msgs = contrib.messages ?? [];
    for (const msg of msgs) {
      if (msg.ToParty === myPartyId || msg.ToParty === 0) {
        out.push(wireToWasmMessage(msg));
      }
    }
  }
  out.sort((a, b) => a.from_party - b.from_party);
  return out;
}
