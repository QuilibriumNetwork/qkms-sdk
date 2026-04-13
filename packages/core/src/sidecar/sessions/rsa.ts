// RSA-N threshold session — backed by mpc-wasm (nekryptology compiled via
// GOOS=js GOARCH=wasm).
//
// Two code paths exposed by the wasm module:
//
//   1. Sign / Decrypt (Shoup 2000 threshold RSA)
//      - `rsa_shoup_partial`: compute m^{2*Δ*d_i} mod N
//      - `rsa_shoup_combine`: combine partials into the final signature
//        (or plaintext, when `unpadOaep` is supplied)
//      These match the sidecar flow in
//      qkms/cmd/mpc-sidecar/main.go `computeRSANContribution` (~line 2925).
//
//   2. DKG (8-phase Paillier-based n-party key generation)
//      - `rsa_dkg_init`: initialize session, return round 1 broadcast
//      - `rsa_dkg_round`: process one incoming DKG message, drive protocol
//      These match `processRSANKeyGen` (~line 2357) in the Go sidecar.
//      Note: DKG can take a long time (biprimality test iterates until
//      it hits a prime candidate) — 5-120 seconds is not unusual for
//      RSA-2048.
//
// The wasm binary is the same Go/nekryptology code the Go server-side
// sidecar runs, so the wire format matches byte-for-byte.

import { loadMpcWasm, type MpcWasmApi } from '@quilibrium/mpc-wasm';
import type { QkmsTask } from '../../types.js';
import type { ProtocolSession, SessionContext } from '../dispatch.js';

// ============================================================
// Wire types — match Go's wire format exactly
// ============================================================

type Uint8ArrayLike = string | number[];

interface SignContributionPayload {
  sidecarId?: string;
  protocol?: string;
  partyId: number;
  partialResult?: Uint8ArrayLike;
  complete?: boolean;
  signature?: Uint8ArrayLike;
  plaintext?: Uint8ArrayLike;
}

interface DkgContributionPayload {
  sidecarId?: string;
  partyId: number;
  round: number;
  /** DKG message blob (NPartyRSADKGMessage JSON) wrapped in `data`. */
  data?: unknown;
  complete?: boolean;
}

interface ServerData {
  protocol?: string;
  keySpec?: string;
  keySize?: number;
  thresholdConfig?: { threshold?: number; totalParties?: number };
  partyIDMap?: Record<string, number>;
  dkgPartyIDMap?: Record<string, number>;
  message?: Uint8ArrayLike;
  ciphertext?: Uint8ArrayLike;
  encryptionAlgorithm?: string;
  rsaPublicKey?: { n?: Uint8ArrayLike; e?: Uint8ArrayLike };
  partyContributions?: Record<string, unknown>;
}

interface KeyShare {
  /** Base64-encoded RSA modulus N. */
  n: string;
  /** Base64-encoded public exponent e. */
  e: string;
  /** Base64-encoded private exponent share d_i. */
  dShare: string;
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

function decodeWireBytes(value: Uint8ArrayLike | undefined): Uint8Array {
  if (value == null) return new Uint8Array();
  if (typeof value === 'string') return base64ToBytes(value);
  if (Array.isArray(value)) return Uint8Array.from(value);
  throw new Error(`unexpected wire bytes: ${typeof value}`);
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

function extractPubKeyFromServerData(sd: ServerData): { nB64: string; eB64: string } | null {
  if (!sd.rsaPublicKey) return null;
  const n = sd.rsaPublicKey.n;
  const e = sd.rsaPublicKey.e;
  if (n == null || e == null) return null;
  return {
    nB64: bytesToBase64(decodeWireBytes(n)),
    eB64: bytesToBase64(decodeWireBytes(e)),
  };
}

// ============================================================
// Session
// ============================================================

export class RSASession implements ProtocolSession {
  private apiPromise: Promise<MpcWasmApi> | null = null;
  /** Cache completed DKG key shares so re-poll after completion is idempotent. */
  private readonly completedKeyShares = new Map<string, KeyShare>();
  /** Track which tasks we've initialized so DKG init isn't re-run on re-poll. */
  private readonly initializedDkgTasks = new Set<string>();
  /** Track sign tasks that have already emitted their partial (for idempotent re-poll). */
  private readonly initializedSignTasks = new Set<string>();

  onKeyShareReady?: (keyId: string, keyShareJson: string, publicKeyHex: string) => Promise<void>;
  loadKeyShare?: (keyId: string) => Promise<string | null>;

  private async getApi(): Promise<MpcWasmApi> {
    if (!this.apiPromise) {
      this.apiPromise = loadMpcWasm();
    }
    return this.apiPromise;
  }

  canHandle(task: QkmsTask): boolean {
    if (
      task.KeySpec === 'RSA_2048' ||
      task.KeySpec === 'RSA_3072' ||
      task.KeySpec === 'RSA_4096'
    ) {
      return true;
    }
    const proto = (task.Protocol ?? '').toLowerCase();
    return proto === 'rsa-n' || proto === 'rsa-n-sign' || proto === 'rsa-n-decrypt';
  }

  async process(task: QkmsTask, ctx: SessionContext): Promise<void> {
    const operation = (task.Operation ?? '').toLowerCase();
    if (operation === 'createkey') {
      await this.processDKG(task, ctx);
    } else if (operation === 'sign' || operation === 'decrypt') {
      await this.processSignOrDecrypt(task, ctx, operation === 'decrypt');
    } else {
      throw new Error(`RSASession: unsupported operation ${task.Operation}`);
    }
  }

  // ----- Sign / Decrypt ---------------------------------------------------

  private async processSignOrDecrypt(
    task: QkmsTask,
    ctx: SessionContext,
    isDecrypt: boolean,
  ): Promise<void> {
    const api = await this.getApi();
    const serverData = parseServerData(task);

    // Load our key share.
    if (!task.KeyId) throw new Error('RSA sign: task missing KeyId');
    if (!this.loadKeyShare) {
      throw new Error('RSA sign: loadKeyShare resolver not set on session');
    }
    const keyShareJson = await this.loadKeyShare(task.KeyId);
    if (!keyShareJson) {
      throw new Error(`RSA sign: no key share for key ${task.KeyId}`);
    }
    const keyShare = JSON.parse(keyShareJson) as KeyShare;

    // Fallback: if the key share JSON doesn't carry N/E, read it from
    // serverData.rsaPublicKey — matches the Go sidecar's "old format"
    // compat path.
    let nB64 = keyShare.n;
    let eB64 = keyShare.e;
    if (!nB64 || !eB64) {
      const pub = extractPubKeyFromServerData(serverData);
      if (!pub) {
        throw new Error('RSA sign: key share missing N/E and serverData has no rsaPublicKey');
      }
      nB64 = pub.nB64;
      eB64 = pub.eB64;
    }

    // Determine party id (prefer DKG-time id for Shoup Lagrange).
    const partyIdMap = serverData.partyIDMap ?? {};
    const dkgPartyIdMap = serverData.dkgPartyIDMap ?? {};
    let myPartyId = dkgPartyIdMap[ctx.sidecarId];
    if (myPartyId == null) {
      myPartyId = partyIdMap[ctx.sidecarId] ?? 1;
    }

    // totalParties used for Δ = n!
    const totalParties = serverData.thresholdConfig?.totalParties ?? 1;

    // Input: message for sign, ciphertext for decrypt.
    const inputBytes = decodeWireBytes(isDecrypt ? serverData.ciphertext : serverData.message);
    if (inputBytes.length === 0) {
      throw new Error(`RSA ${isDecrypt ? 'decrypt' : 'sign'}: missing input in serverData`);
    }

    // Collect other parties' partials (available from round 1+).
    const otherPartials: Record<string, string> = {};
    for (const [sidecarKey, rawContrib] of Object.entries(serverData.partyContributions ?? {})) {
      if (sidecarKey === ctx.sidecarId) continue;
      // Contribution might be wrapped in a { data: {...} } envelope OR inlined.
      const contrib = this.unwrapContribution(rawContrib);
      if (contrib?.partyId != null && contrib.partialResult != null) {
        otherPartials[String(contrib.partyId)] = bytesToBase64(
          decodeWireBytes(contrib.partialResult),
        );
      }
    }

    // Compute our own partial via the wasm helper.
    const partialJson = api.rsa_shoup_partial(
      JSON.stringify({
        input: bytesToBase64(inputBytes),
        n: nB64,
        dShare: keyShare.dShare,
        totalParties,
      }),
    );
    const partialRes = parseWasmResponse<{ partial: string }>(partialJson, 'rsa_shoup_partial');

    if (Object.keys(otherPartials).length === 0) {
      // Round 0: emit our partial and wait for others.
      this.initializedSignTasks.add(task.TaskId);
      await ctx.client.updateTask({
        TaskId: task.TaskId,
        ClientData: {
          sidecarId: ctx.sidecarId,
          protocol: isDecrypt ? 'rsa-n-decrypt' : 'rsa-n-sign',
          partyId: myPartyId,
          partialResult: partialRes.partial,
        } satisfies SignContributionPayload,
      });
      return;
    }

    // Round 1+: combine all partials and emit the final result.
    const allPartials: Record<string, string> = {
      ...otherPartials,
      [String(myPartyId)]: partialRes.partial,
    };

    const combineArgs: Record<string, unknown> = {
      input: bytesToBase64(inputBytes),
      n: nB64,
      e: eB64,
      totalParties,
      partials: allPartials,
    };
    if (isDecrypt) {
      combineArgs.unpadOaep = serverData.encryptionAlgorithm ?? 'RSAES_OAEP_SHA_256';
    }

    const combineJson = api.rsa_shoup_combine(JSON.stringify(combineArgs));
    const combineRes = parseWasmResponse<{ result: string }>(combineJson, 'rsa_shoup_combine');

    this.initializedSignTasks.delete(task.TaskId);
    await ctx.client.updateTask({
      TaskId: task.TaskId,
      ClientData: {
        sidecarId: ctx.sidecarId,
        protocol: isDecrypt ? 'rsa-n-decrypt' : 'rsa-n-sign',
        partyId: myPartyId,
        complete: true,
        ...(isDecrypt
          ? { plaintext: combineRes.result }
          : { signature: combineRes.result }),
      } satisfies SignContributionPayload,
    });
  }

  // ----- DKG --------------------------------------------------------------

  private async processDKG(task: QkmsTask, ctx: SessionContext): Promise<void> {
    const api = await this.getApi();
    const serverData = parseServerData(task);

    const partyIdMap = serverData.partyIDMap ?? {};
    const myPartyId = partyIdMap[ctx.sidecarId];
    if (myPartyId == null) {
      throw new Error(`RSA DKG: sidecar id ${ctx.sidecarId} not in partyIDMap`);
    }

    // Re-poll after completion: re-emit completion.
    const completed = this.completedKeyShares.get(task.TaskId);
    if (completed) {
      await ctx.client.updateTask({
        TaskId: task.TaskId,
        ClientData: {
          sidecarId: ctx.sidecarId,
          partyId: myPartyId,
          round: task.Round,
          complete: true,
        } satisfies DkgContributionPayload,
      });
      return;
    }

    const threshold = serverData.thresholdConfig?.threshold ?? 2;
    const totalParties = serverData.thresholdConfig?.totalParties ?? 2;
    const keySize = this.keySizeFromSpec(task.KeySpec, serverData.keySize);

    if (task.Round === 0) {
      if (this.initializedDkgTasks.has(task.TaskId)) {
        await ctx.client.updateTask({
          TaskId: task.TaskId,
          ClientData: {
            sidecarId: ctx.sidecarId,
            partyId: myPartyId,
            round: task.Round,
          } satisfies DkgContributionPayload,
        });
        return;
      }

      const initJson = api.rsa_dkg_init(
        JSON.stringify({
          taskId: task.TaskId,
          keySize,
          threshold,
          totalParties,
          partyId: myPartyId,
        }),
      );
      const initRes = parseWasmResponse<{ data: string }>(initJson, 'rsa_dkg_init');
      this.initializedDkgTasks.add(task.TaskId);

      await ctx.client.updateTask({
        TaskId: task.TaskId,
        ClientData: {
          sidecarId: ctx.sidecarId,
          partyId: myPartyId,
          round: task.Round,
          // The Go sidecar wraps the DKG message in a `data` field — preserve
          // that shape so server-side relay code can unwrap it the same way.
          data: JSON.parse(new TextDecoder().decode(base64ToBytes(initRes.data))),
        } satisfies DkgContributionPayload,
      });
      return;
    }

    // Round > 0: drive the protocol with every incoming contribution we see.
    let lastOutput: string | null = null;
    let completedKeyShare: KeyShare | null = null;

    for (const [sidecarKey, rawContrib] of Object.entries(serverData.partyContributions ?? {})) {
      if (sidecarKey === ctx.sidecarId) continue;
      const contrib = this.unwrapContribution(rawContrib);
      if (!contrib || contrib.data == null) continue;

      // The contribution's `data` may be a single NPartyRSADKGMessage object
      // or an array of directed messages (see Go sidecar's processRSANKeyGen).
      // Normalize to an array of single messages we can feed through one at a time.
      const messages = Array.isArray(contrib.data) ? contrib.data : [contrib.data];

      for (const msg of messages) {
        // Only process broadcasts (toParty == 0) or messages addressed to us.
        const toParty = (msg as { toParty?: number }).toParty ?? 0;
        if (toParty !== 0 && toParty !== myPartyId) continue;

        const incomingB64 = bytesToBase64(new TextEncoder().encode(JSON.stringify(msg)));
        const roundJson = api.rsa_dkg_round(
          JSON.stringify({ taskId: task.TaskId, incoming: incomingB64 }),
        );
        const roundRes = parseWasmResponse<{
          output?: string;
          complete: boolean;
          publicKeyN?: string;
          publicKeyE?: string;
          privShare?: string;
        }>(roundJson, 'rsa_dkg_round');

        if (roundRes.output) {
          lastOutput = roundRes.output;
        }
        if (roundRes.complete && roundRes.publicKeyN && roundRes.privShare) {
          completedKeyShare = {
            n: roundRes.publicKeyN,
            e: roundRes.publicKeyE ?? bytesToBase64(new Uint8Array([1, 0, 1])), // 65537 default
            dShare: roundRes.privShare,
          };
        }
      }
    }

    if (completedKeyShare) {
      this.completedKeyShares.set(task.TaskId, completedKeyShare);
      this.initializedDkgTasks.delete(task.TaskId);
      if (this.onKeyShareReady && task.KeyId) {
        await this.onKeyShareReady(
          task.KeyId,
          JSON.stringify(completedKeyShare),
          completedKeyShare.n, // publicKeyHex placeholder — RSA pk is N+E, not a hex point
        );
      }
      await ctx.client.updateTask({
        TaskId: task.TaskId,
        ClientData: {
          sidecarId: ctx.sidecarId,
          partyId: myPartyId,
          round: task.Round,
          complete: true,
        } satisfies DkgContributionPayload,
      });
      return;
    }

    if (lastOutput == null) {
      // No incoming messages yet — send an empty round ack so the server
      // knows we're alive.
      await ctx.client.updateTask({
        TaskId: task.TaskId,
        ClientData: {
          sidecarId: ctx.sidecarId,
          partyId: myPartyId,
          round: task.Round,
        } satisfies DkgContributionPayload,
      });
      return;
    }

    // Emit the output from the last DKG step as our round contribution.
    await ctx.client.updateTask({
      TaskId: task.TaskId,
      ClientData: {
        sidecarId: ctx.sidecarId,
        partyId: myPartyId,
        round: task.Round,
        data: JSON.parse(new TextDecoder().decode(base64ToBytes(lastOutput))),
      } satisfies DkgContributionPayload,
    });
  }

  // ----- Helpers ----------------------------------------------------------

  private keySizeFromSpec(keySpec?: string, explicit?: number): number {
    if (explicit && explicit > 0) return explicit;
    switch (keySpec) {
      case 'RSA_2048':
        return 2048;
      case 'RSA_3072':
        return 3072;
      case 'RSA_4096':
        return 4096;
      default:
        return 2048;
    }
  }

  /**
   * Unwrap a raw `partyContributions[id]` value. The Go server relays
   * contributions as-is, so we may see either the inner payload directly
   * or wrapped in `{ data: {...} }` depending on who submitted it.
   */
  private unwrapContribution(raw: unknown): (SignContributionPayload & DkgContributionPayload) | null {
    if (!raw || typeof raw !== 'object') return null;
    return raw as unknown as SignContributionPayload & DkgContributionPayload;
  }
}

function parseWasmResponse<T>(json: string, fnName: string): T {
  let parsed: { error?: string } & T;
  try {
    parsed = JSON.parse(json) as { error?: string } & T;
  } catch {
    throw new Error(`mpc-wasm ${fnName}: invalid JSON: ${json}`);
  }
  if (parsed.error) {
    throw new Error(`mpc-wasm ${fnName}: ${parsed.error}`);
  }
  return parsed;
}
