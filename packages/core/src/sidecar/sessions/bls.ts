// BLS t-of-n threshold session — dual-curve:
//
//   BLS48-581: uses bls48581-wasm (Rust crate) for scalar + G1/G8 ops
//   BLS12-381: uses mpc-wasm (Go wasm) via mpcbls12381 sub-package
//
// Protocol mirrors qkms/src/mpc/bls_threshold_n_client.go (~510 lines):
//
//   DKG (Feldman VSS, 2 internal rounds):
//     Round 0: random poly coefficients → Feldman commitments → send
//     Round 1: collect commitments → send shares targeted at each party
//     Finalize: collect shares for us → combine sk_share, sum constant-term
//               commitments into master verification key
//
//   Sign (2 rounds):
//     Round 0: compute partial sig H(m)^{sk_i * L_i(0)} (Lagrange-weighted)
//     Round 1: collect partial sigs, aggregate via point addition, emit complete
//
// **BLS48-581 group convention:**  PK on G8/ECP8 (585-byte compressed),
//   sigs on G1 (74-byte compressed).
//
// **BLS12-381 group convention:**  PK on G1 (48-byte compressed), sigs on
//   G2 (96-byte compressed). DKG uses nekryptology BLS12381G1 curve.
//   Signing uses gnark-crypto HashToCurveG2Svdw with
//   DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_".

import * as bls48581 from 'bls48581wasm';
import { loadMpcWasm, type MpcWasmApi } from '@quilibrium/mpc-wasm';
import type { QkmsTask } from '../../types.js';
import type { ProtocolSession, SessionContext } from '../dispatch.js';

// ============================================================
// Constants
// ============================================================

const BLS_SCALAR_BYTES = 73;
const BLS_G1_COMPRESSED_BYTES = 74;
const BLS_G8_COMPRESSED_BYTES = 585;

// ============================================================
// Wire types — match Go's BLSNClientDKGContribution exactly
// ============================================================

type Uint8ArrayLike = string | number[];

interface ContributionPayload {
  sidecarId?: string;
  partyId: number;
  round: number;
  // DKG round 0:
  commitments?: Uint8ArrayLike[];
  // DKG round 1:
  shares?: Record<string, Uint8ArrayLike>;
  // Sign round 0:
  partialSig?: Uint8ArrayLike;
  // Completion (DKG and sign):
  complete?: boolean;
  publicKey?: Uint8ArrayLike;
  signature?: Uint8ArrayLike;
}

interface ServerData {
  thresholdConfig?: { threshold?: number; totalParties?: number };
  partyIDMap?: Record<string, number>;
  dkgPartyIDMap?: Record<string, number>;
  participants?: string[];
  message?: Uint8ArrayLike;
  partyContributions?: Record<string, ContributionPayload>;
  keySpec?: string;
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

function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i]!.toString(16).padStart(2, '0');
  return s;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error(`hex string has odd length: ${hex.length}`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function decodeWireBytes(value: Uint8ArrayLike | undefined): Uint8Array {
  if (value == null) return new Uint8Array();
  if (typeof value === 'string') return base64ToBytes(value);
  if (Array.isArray(value)) return Uint8Array.from(value);
  throw new Error(`unexpected wire bytes: ${typeof value}`);
}

// ============================================================
// bls48581-wasm wrappers — typed and JSON-aware
// ============================================================

/** Parse a JSON-encoded hex string return from bls48581-wasm. */
function parseWasmHex(jsonResult: string, fnName: string): Uint8Array {
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonResult);
  } catch {
    throw new Error(`bls48581-wasm ${fnName}: invalid JSON: ${jsonResult}`);
  }
  if (typeof parsed === 'object' && parsed !== null && 'error' in parsed) {
    throw new Error(`bls48581-wasm ${fnName}: ${(parsed as { error: string }).error}`);
  }
  if (typeof parsed !== 'string') {
    throw new Error(`bls48581-wasm ${fnName}: expected hex string, got ${typeof parsed}`);
  }
  return hexToBytes(parsed);
}

let initialized = false;
function ensureInit(): void {
  if (initialized) return;
  bls48581.js_init();
  initialized = true;
}

function scalarRandom(): Uint8Array {
  return parseWasmHex(bls48581.js_bls_scalar_random(), 'scalar_random');
}

function scalarMul(a: Uint8Array, b: Uint8Array): Uint8Array {
  return parseWasmHex(bls48581.js_bls_scalar_mul(bytesToHex(a), bytesToHex(b)), 'scalar_mul');
}

function scalarAdd(a: Uint8Array, b: Uint8Array): Uint8Array {
  return parseWasmHex(bls48581.js_bls_scalar_add(bytesToHex(a), bytesToHex(b)), 'scalar_add');
}

function scalarSub(a: Uint8Array, b: Uint8Array): Uint8Array {
  return parseWasmHex(bls48581.js_bls_scalar_sub(bytesToHex(a), bytesToHex(b)), 'scalar_sub');
}

function scalarNeg(a: Uint8Array): Uint8Array {
  return parseWasmHex(bls48581.js_bls_scalar_neg(bytesToHex(a)), 'scalar_neg');
}

function scalarInv(a: Uint8Array): Uint8Array {
  return parseWasmHex(bls48581.js_bls_scalar_inv(bytesToHex(a)), 'scalar_inv');
}

function scalarFromU64(v: bigint | number): Uint8Array {
  // wasm-bindgen serializes u64 from JS as bigint.
  return parseWasmHex(bls48581.js_bls_scalar_from_u64(BigInt(v)), 'scalar_from_u64');
}

function scalarToG1(s: Uint8Array): Uint8Array {
  return parseWasmHex(bls48581.js_bls_scalar_to_g1(bytesToHex(s)), 'scalar_to_g1');
}

function g1Add(a: Uint8Array, b: Uint8Array): Uint8Array {
  return parseWasmHex(bls48581.js_bls_g1_add(bytesToHex(a), bytesToHex(b)), 'g1_add');
}

/** g8^scalar — the BLS48-581 public-key group (585-byte compressed). */
function scalarToG8(s: Uint8Array): Uint8Array {
  return parseWasmHex(bls48581.js_bls_scalar_to_g8(bytesToHex(s)), 'scalar_to_g8');
}

function g8Add(a: Uint8Array, b: Uint8Array): Uint8Array {
  return parseWasmHex(bls48581.js_bls_g8_add(bytesToHex(a), bytesToHex(b)), 'g8_add');
}

function blsSign(sk: Uint8Array, message: Uint8Array, domain: Uint8Array): Uint8Array {
  return parseWasmHex(
    bls48581.js_bls_sign(bytesToHex(sk), bytesToHex(message), bytesToHex(domain)),
    'bls_sign',
  );
}

// ============================================================
// Protocol helpers
// ============================================================

/**
 * Evaluate the polynomial f(x) = sum(coefficients[i] * x^i) over the
 * BLS48-581 scalar field. Mirrors evaluatePolynomial-style logic from
 * qkms/src/mpc/bls_threshold_n.go but stays inside the wasm scalar field
 * via the new helpers (no need to hard-code the curve order in JS).
 */
function evaluatePolynomial(coefficients: Uint8Array[], x: number): Uint8Array {
  if (coefficients.length === 0) {
    throw new Error('evaluatePolynomial: empty coefficients');
  }
  let result = scalarFromU64(0);
  let xPow = scalarFromU64(1);
  const xScalar = scalarFromU64(x);
  for (const coeff of coefficients) {
    const term = scalarMul(coeff, xPow);
    result = scalarAdd(result, term);
    xPow = scalarMul(xPow, xScalar);
  }
  return result;
}

/**
 * Compute Lagrange coefficient L_i(0) for party `partyId` in the cosigner
 * set. Mirrors `computeBLS12381LagrangeCoeff` / `computeBLSLagrangeCoeffs` in
 * the Go reference, but uses the wasm scalar field directly so we don't
 * need a hard-coded curve order constant.
 *
 *   L_i(0) = prod_{j != i} (-j / (i - j)) mod q
 */
function computeLagrangeCoeff(partyId: number, cosignerIds: number[]): Uint8Array {
  let num = scalarFromU64(1);
  let den = scalarFromU64(1);
  const i = scalarFromU64(partyId);
  for (const j of cosignerIds) {
    if (j === partyId) continue;
    const jScalar = scalarFromU64(j);
    // num *= -j
    num = scalarMul(num, scalarNeg(jScalar));
    // den *= (i - j)
    den = scalarMul(den, scalarSub(i, jScalar));
  }
  return scalarMul(num, scalarInv(den));
}

// ============================================================
// Per-task in-memory state
// ============================================================

interface DkgState {
  internalRound: 0 | 1 | 2;
  partyId: number;
  threshold: number;
  totalParties: number;
  /** Polynomial coefficients (73-byte BE scalars). */
  coefficients: Uint8Array[];
  /** Feldman commitments g8^{a_i} — 585-byte compressed G8 points. */
  commitments: Uint8Array[];
  /** Map partyId → 73-byte BE scalar — share we send to each party. */
  shares: Map<number, Uint8Array>;
  collectedCommitments: Map<number, Uint8Array[]>;
  collectedShares: Map<number, Uint8Array>;
}

interface SignState {
  internalRound: 0 | 1 | 2;
  partyId: number;
  /** Our partial signature (74-byte G1 compressed). */
  partialSig: Uint8Array;
}

interface KeyShare {
  curve: string;
  partyId: number;
  /** Hex-encoded 73-byte BE scalar. */
  skShareHex: string;
  /** Hex-encoded 585-byte compressed G8 point — the master verification key. */
  verificationKeyHex: string;
}

// ============================================================
// Session
// ============================================================

export class BLSSession implements ProtocolSession {
  private readonly dkgStates = new Map<string, DkgState>();
  private readonly signStates = new Map<string, SignState>();
  private readonly completedKeyShares = new Map<string, KeyShare>();

  /** Persist a finalized key share. Wired to StorageAdapter by the consumer. */
  onKeyShareReady?: (keyId: string, keyShareJson: string, publicKeyHex: string) => Promise<void>;

  /** Resolver for stored key shares used by signing. JSON string or null. */
  loadKeyShare?: (keyId: string) => Promise<string | null>;

  /** Lazy handle to the loaded mpc-wasm API (used for BLS12-381 path). */
  private mpcApiPromise: Promise<MpcWasmApi> | null = null;

  private getMpcApi(): Promise<MpcWasmApi> {
    if (!this.mpcApiPromise) this.mpcApiPromise = loadMpcWasm();
    return this.mpcApiPromise;
  }

  canHandle(task: QkmsTask): boolean {
    const sd = parseServerData(task);
    const keySpec = task.KeySpec ?? (sd as Record<string, unknown>).keySpec as string ?? '';
    const proto = (task.Protocol ?? (sd as Record<string, unknown>).protocol as string ?? '').toLowerCase();
    if (keySpec === 'ECC_BLS48_581' || keySpec === 'ECC_BLS12_381') return true;
    return proto === 'bls48581' || proto === 'bls48581-n' || proto === 'bls-n'
      || proto === 'bls12381' || proto === 'bls12381-n';
  }

  async process(task: QkmsTask, ctx: SessionContext): Promise<void> {
    const operation = (task.Operation ?? '').toLowerCase();
    const sd = parseServerData(task);
    const keySpec = task.KeySpec ?? (sd as Record<string, unknown>).keySpec as string ?? '';
    const proto = (task.Protocol ?? (sd as Record<string, unknown>).protocol as string ?? '').toLowerCase();
    const isBls12381 = keySpec === 'ECC_BLS12_381' || proto.includes('bls12381');

    if (isBls12381) {
      if (operation === 'createkey') {
        await this.processDKG12381(task, ctx);
      } else if (operation === 'sign') {
        await this.processSign12381(task, ctx);
      } else {
        throw new Error(`BLSSession: unsupported operation ${task.Operation} for BLS12-381`);
      }
      return;
    }

    if (operation === 'createkey') {
      await this.processDKG(task, ctx);
    } else if (operation === 'sign') {
      await this.processSign(task, ctx);
    } else {
      throw new Error(`BLSSession: unsupported operation ${task.Operation}`);
    }
  }

  // ----- DKG --------------------------------------------------------------

  private async processDKG(task: QkmsTask, ctx: SessionContext): Promise<void> {
    ensureInit();
    const serverData = parseServerData(task);

    const partyIdMap = serverData.partyIDMap ?? {};
    const myPartyId = partyIdMap[ctx.sidecarId];
    if (myPartyId == null) {
      throw new Error(`BLS DKG: sidecar id ${ctx.sidecarId} not in partyIDMap`);
    }

    // Re-poll after completion: re-emit completion contribution.
    const completed = this.completedKeyShares.get(task.TaskId);
    if (completed) {
      await this.submitContribution(task, ctx, {
        partyId: myPartyId,
        round: task.Round,
        complete: true,
        publicKey: bytesToBase64(hexToBytes(completed.verificationKeyHex)),
      });
      return;
    }

    if (task.Round === 0) {
      if (this.dkgStates.has(task.TaskId)) {
        await this.submitContribution(task, ctx, { partyId: myPartyId, round: task.Round });
        return;
      }

      const threshold = serverData.thresholdConfig?.threshold ?? 2;
      const totalParties = serverData.thresholdConfig?.totalParties ?? 3;

      // Generate random coefficients (one per threshold) and Feldman commits.
      // Commitments are on G8 (BLS48-581 public-key group).
      const coefficients: Uint8Array[] = [];
      const commitments: Uint8Array[] = [];
      for (let i = 0; i < threshold; i++) {
        const coeff = scalarRandom();
        coefficients.push(coeff);
        commitments.push(scalarToG8(coeff));
      }

      // Evaluate the polynomial at every party id 1..totalParties.
      const shares = new Map<number, Uint8Array>();
      for (let j = 1; j <= totalParties; j++) {
        shares.set(j, evaluatePolynomial(coefficients, j));
      }

      this.dkgStates.set(task.TaskId, {
        internalRound: 0,
        partyId: myPartyId,
        threshold,
        totalParties,
        coefficients,
        commitments,
        shares,
        collectedCommitments: new Map(),
        collectedShares: new Map(),
      });

      await this.submitContribution(task, ctx, {
        partyId: myPartyId,
        round: 0,
        commitments: commitments.map(bytesToBase64),
      });
      return;
    }

    const state = this.dkgStates.get(task.TaskId);
    if (!state) {
      throw new Error(`BLS DKG: no session for task ${task.TaskId} at round ${task.Round}`);
    }
    const partyContribs = serverData.partyContributions ?? {};

    if (state.internalRound === 0) {
      // Round 0 → 1: store others' commitments, send our shares.
      for (const [sidecarKey, contrib] of Object.entries(partyContribs)) {
        if (sidecarKey === ctx.sidecarId) continue;
        if (!contrib.commitments) continue;
        const coms = (contrib.commitments as unknown[]).map((c) =>
          decodeWireBytes(c as Uint8ArrayLike),
        );
        state.collectedCommitments.set(contrib.partyId, coms);
      }
      const expected = state.totalParties - 1;
      if (state.collectedCommitments.size < expected) {
        throw new Error(
          `BLS DKG: expected ${expected} other commitments, got ${state.collectedCommitments.size}`,
        );
      }
      state.internalRound = 1;

      const sharesPayload: Record<string, string> = {};
      for (const [pid, share] of state.shares.entries()) {
        sharesPayload[String(pid)] = bytesToBase64(share);
      }
      await this.submitContribution(task, ctx, {
        partyId: state.partyId,
        round: task.Round,
        shares: sharesPayload,
      });
      return;
    }

    if (state.internalRound === 1) {
      // Round 1 → complete.
      for (const [sidecarKey, contrib] of Object.entries(partyContribs)) {
        if (sidecarKey === ctx.sidecarId) continue;
        if (!contrib.shares) continue;
        const myShare = contrib.shares[String(state.partyId)];
        if (myShare == null) continue;
        state.collectedShares.set(contrib.partyId, decodeWireBytes(myShare));
      }
      const expected = state.totalParties - 1;
      if (state.collectedShares.size < expected) {
        throw new Error(
          `BLS DKG: expected ${expected} shares for us, got ${state.collectedShares.size}`,
        );
      }

      // Master verification key = sum of every party's commitment[0] on G8.
      let publicKey = state.commitments[0]!;
      for (const coms of state.collectedCommitments.values()) {
        if (coms.length === 0) continue;
        publicKey = g8Add(publicKey, coms[0]!);
      }

      // Combined sk_share = sum of every share targeted at us (including ours).
      let combinedShare = state.shares.get(state.partyId)!;
      for (const share of state.collectedShares.values()) {
        combinedShare = scalarAdd(combinedShare, share);
      }

      const keyShare: KeyShare = {
        curve: 'BLS48-581',
        partyId: state.partyId,
        skShareHex: bytesToHex(combinedShare),
        verificationKeyHex: bytesToHex(publicKey),
      };
      this.completedKeyShares.set(task.TaskId, keyShare);
      this.dkgStates.delete(task.TaskId);

      if (this.onKeyShareReady && task.KeyId) {
        await this.onKeyShareReady(
          task.KeyId,
          JSON.stringify(keyShare),
          keyShare.verificationKeyHex,
        );
      }

      await this.submitContribution(task, ctx, {
        partyId: state.partyId,
        round: 2,
        complete: true,
        publicKey: bytesToBase64(publicKey),
      });
      return;
    }

    throw new Error(`BLS DKG: unexpected internal round ${state.internalRound}`);
  }

  // ----- Sign -------------------------------------------------------------

  private async processSign(task: QkmsTask, ctx: SessionContext): Promise<void> {
    ensureInit();
    const serverData = parseServerData(task);

    const partyIdMap = serverData.partyIDMap ?? {};
    const myPartyId = partyIdMap[ctx.sidecarId];
    if (myPartyId == null) {
      throw new Error(`BLS sign: sidecar id ${ctx.sidecarId} not in partyIDMap`);
    }

    const dkgPartyIdMap = serverData.dkgPartyIDMap ?? {};
    const dkgPartyId = dkgPartyIdMap[ctx.sidecarId] ?? myPartyId;

    // cosignerIDs = DKG party ids of all SIGNING participants.
    let cosignerIds: number[] = [];
    if (Object.keys(dkgPartyIdMap).length > 0) {
      for (const sidecarKey of Object.keys(partyIdMap)) {
        const id = dkgPartyIdMap[sidecarKey];
        if (id != null) cosignerIds.push(id);
      }
    }
    if (cosignerIds.length === 0) {
      cosignerIds = Object.values(partyIdMap);
    }
    cosignerIds.sort((a, b) => a - b);

    if (task.Round === 0) {
      if (this.signStates.has(task.TaskId)) {
        await this.submitContribution(task, ctx, { partyId: dkgPartyId, round: task.Round });
        return;
      }

      const message = decodeWireBytes(serverData.message);
      if (message.length === 0) {
        throw new Error('BLS sign: missing message in serverData');
      }
      if (!task.KeyId) throw new Error('BLS sign: task missing KeyId');
      if (!this.loadKeyShare) {
        throw new Error('BLS sign: loadKeyShare resolver not set on session');
      }
      const keyShareJson = await this.loadKeyShare(task.KeyId);
      if (!keyShareJson) {
        throw new Error(`BLS sign: no key share for key ${task.KeyId}`);
      }
      const keyShare = JSON.parse(keyShareJson) as KeyShare;
      const skShare = hexToBytes(keyShare.skShareHex);

      // partial_sig = bls_sign(sk_i * L_i(0), message, domain="")
      const lagrange = computeLagrangeCoeff(dkgPartyId, cosignerIds);
      const scaledShare = scalarMul(skShare, lagrange);
      const partialSig = blsSign(scaledShare, message, new Uint8Array());

      this.signStates.set(task.TaskId, {
        internalRound: 0,
        partyId: dkgPartyId,
        partialSig,
      });

      await this.submitContribution(task, ctx, {
        partyId: dkgPartyId,
        round: 0,
        partialSig: bytesToBase64(partialSig),
      });
      return;
    }

    const state = this.signStates.get(task.TaskId);
    if (!state) {
      throw new Error(`BLS sign: no session for task ${task.TaskId} at round ${task.Round}`);
    }
    const partyContribs = serverData.partyContributions ?? {};

    // Round 1: aggregate every party's partial sig (including ours), emit complete.
    let aggregated: Uint8Array | null = state.partialSig;
    for (const [sidecarKey, contrib] of Object.entries(partyContribs)) {
      if (sidecarKey === ctx.sidecarId) continue;
      if (!contrib.partialSig) continue;
      const partial = decodeWireBytes(contrib.partialSig);
      if (partial.length !== BLS_G1_COMPRESSED_BYTES) continue;
      aggregated = aggregated == null ? partial : g1Add(aggregated, partial);
    }
    if (aggregated == null) {
      throw new Error('BLS sign: nothing to aggregate');
    }

    state.internalRound = 2;
    this.signStates.delete(task.TaskId);

    await this.submitContribution(task, ctx, {
      partyId: state.partyId,
      round: task.Round,
      complete: true,
      signature: bytesToBase64(aggregated),
    });
  }

  // ----- BLS12-381 DKG (via mpc-wasm) --------------------------------------

  /** Per-task cache of BLS12-381 key share JSON for re-poll idempotency. */
  private readonly completed12381KeyShares = new Map<string, { publicKeyB64: string }>();

  private async processDKG12381(task: QkmsTask, ctx: SessionContext): Promise<void> {
    const api = await this.getMpcApi();
    const serverData = parseServerData(task);

    const partyIdMap = serverData.partyIDMap ?? {};
    const myPartyId = partyIdMap[ctx.sidecarId];
    if (myPartyId == null) {
      throw new Error(`BLS12-381 DKG: sidecar id ${ctx.sidecarId} not in partyIDMap`);
    }

    // Re-poll after completion: re-emit completion contribution.
    const cached = this.completed12381KeyShares.get(task.TaskId);
    if (cached) {
      await this.submitContribution(task, ctx, {
        partyId: myPartyId,
        round: task.Round,
        complete: true,
        publicKey: cached.publicKeyB64,
      });
      return;
    }

    if (task.Round === 0) {
      // Init DKG if not already done.
      const threshold = serverData.thresholdConfig?.threshold ?? 2;
      const totalParties = serverData.thresholdConfig?.totalParties ?? 3;

      const initResult = JSON.parse(
        api.bls12381_dkg_init(
          JSON.stringify({
            sessionId: task.TaskId,
            partyId: myPartyId,
            threshold,
            totalParties,
          }),
        ),
      ) as { contribution?: unknown; error?: string };

      if (initResult.error) throw new Error(`BLS12-381 DKG init: ${initResult.error}`);

      await ctx.client.updateTask({
        TaskId: task.TaskId,
        ClientData: { sidecarId: ctx.sidecarId, ...(initResult.contribution as Record<string, unknown>) },
      });
      return;
    }

    // Round 1+: advance the DKG session with party contributions from server.
    const roundResult = JSON.parse(
      api.bls12381_dkg_round(
        JSON.stringify({
          sessionId: task.TaskId,
          taskRound: task.Round,
          mySidecarId: ctx.sidecarId,
          partyContributions: serverData.partyContributions ?? {},
        }),
      ),
    ) as {
      contribution?: unknown;
      complete?: boolean;
      keyShare?: { curve: string; partyId: number; skShare: number[]; verificationKey: number[] };
      error?: string;
    };

    if (roundResult.error) throw new Error(`BLS12-381 DKG round: ${roundResult.error}`);

    if (roundResult.complete && roundResult.keyShare) {
      // Persist the key share.
      const ks = roundResult.keyShare;
      const skShareB64 = bytesToBase64(Uint8Array.from(ks.skShare));
      const vkB64 = bytesToBase64(Uint8Array.from(ks.verificationKey));
      const keyShareJson = JSON.stringify({
        curve: ks.curve,
        partyId: ks.partyId,
        skShareB64,
        verificationKeyB64: vkB64,
      });

      this.completed12381KeyShares.set(task.TaskId, { publicKeyB64: vkB64 });
      api.clear(task.TaskId);

      if (this.onKeyShareReady && task.KeyId) {
        await this.onKeyShareReady(task.KeyId, keyShareJson, vkB64);
      }
    }

    await ctx.client.updateTask({
      TaskId: task.TaskId,
      ClientData: { sidecarId: ctx.sidecarId, ...(roundResult.contribution as Record<string, unknown>) },
    });
  }

  // ----- BLS12-381 Sign (via mpc-wasm) -------------------------------------

  /** Cache of submitted BLS12-381 sign contributions for re-poll. */
  private readonly submitted12381Sigs = new Map<string, unknown>();

  private async processSign12381(task: QkmsTask, ctx: SessionContext): Promise<void> {
    const api = await this.getMpcApi();
    const serverData = parseServerData(task);

    const partyIdMap = serverData.partyIDMap ?? {};
    const myPartyId = partyIdMap[ctx.sidecarId];
    if (myPartyId == null) {
      throw new Error(`BLS12-381 sign: sidecar id ${ctx.sidecarId} not in partyIDMap`);
    }

    const dkgPartyIdMap = serverData.dkgPartyIDMap ?? {};
    const dkgPartyId = dkgPartyIdMap[ctx.sidecarId] ?? myPartyId;

    // cosignerIDs = DKG party ids of all SIGNING participants.
    let cosignerIds: number[] = [];
    if (Object.keys(dkgPartyIdMap).length > 0) {
      for (const sidecarKey of Object.keys(partyIdMap)) {
        const id = dkgPartyIdMap[sidecarKey];
        if (id != null) cosignerIds.push(id);
      }
    }
    if (cosignerIds.length === 0) {
      cosignerIds = Object.values(partyIdMap);
    }
    cosignerIds.sort((a, b) => a - b);

    if (task.Round === 0) {
      // Re-poll: return cached contribution.
      const cached = this.submitted12381Sigs.get(task.TaskId);
      if (cached) {
        await ctx.client.updateTask({ TaskId: task.TaskId, ClientData: { sidecarId: ctx.sidecarId, ...(cached as Record<string, unknown>) } });
        return;
      }

      const message = decodeWireBytes(serverData.message);
      if (message.length === 0) throw new Error('BLS12-381 sign: missing message');
      if (!task.KeyId) throw new Error('BLS12-381 sign: task missing KeyId');
      if (!this.loadKeyShare) throw new Error('BLS12-381 sign: loadKeyShare not set');

      const keyShareJson = await this.loadKeyShare(task.KeyId);
      if (!keyShareJson) throw new Error(`BLS12-381 sign: no key share for key ${task.KeyId}`);

      const ks = JSON.parse(keyShareJson) as { skShareB64?: string; skShareHex?: string };
      let skShareB64: string;
      if (ks.skShareB64) {
        skShareB64 = ks.skShareB64;
      } else if (ks.skShareHex) {
        skShareB64 = bytesToBase64(hexToBytes(ks.skShareHex));
      } else {
        throw new Error('BLS12-381 sign: key share missing skShareB64 and skShareHex');
      }

      const result = JSON.parse(
        api.bls12381_partial_sig(
          JSON.stringify({
            keyShare: skShareB64,
            message: bytesToBase64(message),
            partyId: dkgPartyId,
            cosignerIds,
          }),
        ),
      ) as { partialSig?: string; error?: string };

      if (result.error) throw new Error(`BLS12-381 partial sig: ${result.error}`);

      const contrib = { partyId: dkgPartyId, round: 0, partialSig: result.partialSig };
      this.submitted12381Sigs.set(task.TaskId, contrib);

      await ctx.client.updateTask({ TaskId: task.TaskId, ClientData: { sidecarId: ctx.sidecarId, ...contrib } });
      return;
    }

    // Round 1: aggregate all partial signatures.
    const partyContribs = serverData.partyContributions ?? {};
    const partials: Record<string, string> = {};

    // Include our own cached partial.
    const myContrib = this.submitted12381Sigs.get(task.TaskId) as
      | { partialSig?: string; partyId?: number }
      | undefined;
    if (myContrib?.partialSig) {
      partials[String(dkgPartyId)] = myContrib.partialSig;
    }

    for (const [sidecarKey, contrib] of Object.entries(partyContribs)) {
      if (sidecarKey === ctx.sidecarId) continue;
      if (!contrib.partialSig) continue;
      const partialB64 = typeof contrib.partialSig === 'string'
        ? contrib.partialSig
        : bytesToBase64(decodeWireBytes(contrib.partialSig));
      const pid = dkgPartyIdMap[sidecarKey] ?? contrib.partyId;
      partials[String(pid)] = partialB64;
    }

    const aggResult = JSON.parse(
      api.bls12381_aggregate_sigs(JSON.stringify({ partials })),
    ) as { signature?: string; error?: string };

    if (aggResult.error) throw new Error(`BLS12-381 aggregate: ${aggResult.error}`);

    this.submitted12381Sigs.delete(task.TaskId);

    await this.submitContribution(task, ctx, {
      partyId: dkgPartyId,
      round: task.Round,
      complete: true,
      signature: aggResult.signature,
    });
  }

  // ----- Common -----------------------------------------------------------

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

// Reference the constants so they appear in the dist file's imports — also
// helps catch any future drift in the wasm wire format if these change.
export const BLS_CONSTANTS = {
  SCALAR_BYTES: BLS_SCALAR_BYTES,
  G1_COMPRESSED_BYTES: BLS_G1_COMPRESSED_BYTES,
  G8_COMPRESSED_BYTES: BLS_G8_COMPRESSED_BYTES,
} as const;
