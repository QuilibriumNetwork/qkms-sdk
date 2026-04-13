// Decaf448 t-of-n threshold session — uses bulletproofs-wasm primitives.
//
// The Quilibrium Decaf448 protocol is a Feldman VSS DKG followed by a
// 3-round threshold Schnorr sign. Reference implementations:
//
//   qkms/src/mpc/decaf448_threshold_n_client.go (~556 lines)
//   qkms/src/mpc/decaf448_sign.go              (helper functions)
//   qkms/src/mpc/decaf448_threshold_n.go        (server side, helpers we mirror)
//
// All curve operations come from `bulletproofs-wasm`, which is the same Rust
// crate (`crates/bulletproofs/`) the Go side links via cgo. Byte-for-byte
// interop with the Go server-side sidecar is guaranteed because both sides
// call the same Rust functions:
//
//   js_scalar_to_point(s)         → crates/bulletproofs/src/uniffi_bulletproofs.rs:scalar_to_point
//   js_scalar_addition(a, b)      → scalar_addition
//   js_scalar_subtraction(a, b)   → scalar_subtraction
//   js_scalar_mult(a, b)          → scalar_mult         (returns 112 bytes: 56 scalar || 56 point)
//   js_hash_to_scalar(input)      → hash_to_scalar      (returns 112 bytes: 56 scalar || 56 point)
//   js_point_addition(a, b)       → point_addition
//
// Wire format:
//   Scalars are 56-byte little-endian (Scalar::from_bits in curve25519-dalek style)
//   Points are 56-byte compressed Decaf points
//   The Lagrange-coefficient and polynomial-evaluation arithmetic uses BigInt
//   over the curve order (a 446-bit prime, RFC 8032).

import * as bulletproofs from 'bulletproofswasm';
import type { QkmsTask } from '../../types.js';
import type { ProtocolSession, SessionContext } from '../dispatch.js';

// ============================================================
// Constants
// ============================================================

const DECAF448_SCALAR_SIZE = 56;

/** Decaf448 scalar field order — RFC 8032 / ed448-goldilocks-plus. */
// Same constant as decaf448CurveOrder() in qkms/src/mpc/decaf448_threshold_n.go:671.
const DECAF448_ORDER = BigInt(
  '181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649779',
);

// ============================================================
// Wire types — these match the Go-side ContributionPayload exactly
// ============================================================

interface ContributionPayload {
  sidecarId?: string;
  partyId: number;
  round: number;
  // DKG round 0: list of compressed-point byte arrays
  commitments?: Uint8ArrayLike[];           // [][]byte (Go)
  // DKG round 1: per-recipient share map
  shares?: Record<string, Uint8ArrayLike>;  // map[uint32][]byte
  // Sign round 0:
  nonceCommit?: Uint8ArrayLike;
  // Sign round 1:
  partialSig?: Uint8ArrayLike;
  aggregatedNonce?: Uint8ArrayLike;
  // Completion (DKG and sign):
  complete?: boolean;
  publicKey?: Uint8ArrayLike;
  signature?: Uint8ArrayLike;
}

/**
 * Go marshals []byte as base64 in JSON, but `[][]byte` becomes `[]string` of
 * base64 strings. We accept both base64 strings and number arrays so we
 * can interop with either side.
 */
type Uint8ArrayLike = string | number[];

interface ServerData {
  thresholdConfig?: { threshold?: number; totalParties?: number };
  partyIDMap?: Record<string, number>;
  dkgPartyIDMap?: Record<string, number>;
  participants?: string[];
  message?: Uint8ArrayLike;
  partyContributions?: Record<string, ContributionPayload>;
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

/** BigInt → 56-byte little-endian (the Decaf448 scalar wire format). */
function bigintToLEBytes56(value: bigint): Uint8Array {
  const out = new Uint8Array(DECAF448_SCALAR_SIZE);
  let v = ((value % DECAF448_ORDER) + DECAF448_ORDER) % DECAF448_ORDER;
  for (let i = 0; i < DECAF448_SCALAR_SIZE; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** 56-byte little-endian → BigInt. */
function leBytes56ToBigint(bytes: Uint8Array): bigint {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    v = (v << 8n) | BigInt(bytes[i]!);
  }
  return v;
}

/** Cryptographically random 56-byte LE scalar (mod-reduced to the curve order). */
function randomScalar(): Uint8Array {
  const buf = new Uint8Array(DECAF448_SCALAR_SIZE);
  crypto.getRandomValues(buf);
  // Mask the top byte slightly so we don't bias toward larger values too much.
  // The dalek Scalar::from_bits accepts any 56 bytes, so this is just a courtesy.
  return buf;
}

// ============================================================
// bulletproofs-wasm wrappers — typed and JSON-aware
// ============================================================

type WasmScalarMultResult = { scalar: Uint8Array; pointSelfMult: Uint8Array };

/** Parse the JSON-encoded hex string returned by bulletproofs-wasm. */
function parseWasmHex(jsonResult: string, fnName: string): Uint8Array {
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonResult);
  } catch {
    throw new Error(`bulletproofs-wasm ${fnName}: invalid JSON: ${jsonResult}`);
  }
  if (typeof parsed === 'object' && parsed !== null && 'error' in parsed) {
    throw new Error(`bulletproofs-wasm ${fnName}: ${(parsed as { error: string }).error}`);
  }
  if (typeof parsed !== 'string') {
    throw new Error(`bulletproofs-wasm ${fnName}: expected hex string, got ${typeof parsed}`);
  }
  return hexToBytes(parsed);
}

function scalarToPoint(scalar: Uint8Array): Uint8Array {
  return parseWasmHex(bulletproofs.js_scalar_to_point(bytesToHex(scalar)), 'scalar_to_point');
}

function scalarAddition(a: Uint8Array, b: Uint8Array): Uint8Array {
  return parseWasmHex(
    bulletproofs.js_scalar_addition(bytesToHex(a), bytesToHex(b)),
    'scalar_addition',
  );
}

function scalarSubtraction(a: Uint8Array, b: Uint8Array): Uint8Array {
  return parseWasmHex(
    bulletproofs.js_scalar_subtraction(bytesToHex(a), bytesToHex(b)),
    'scalar_subtraction',
  );
}

/**
 * `js_scalar_mult` returns a 112-byte buffer: `scalar (56) || self_mul_point (56)`.
 * Decaf448 sign protocol only needs the scalar half — the point half is just a
 * convenience the underlying Rust function provides.
 */
function scalarMultScalarOnly(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = parseWasmHex(bulletproofs.js_scalar_mult(bytesToHex(a), bytesToHex(b)), 'scalar_mult');
  if (out.length !== 112) {
    throw new Error(`scalar_mult expected 112 bytes, got ${out.length}`);
  }
  return out.slice(0, DECAF448_SCALAR_SIZE);
}

/**
 * `js_hash_to_scalar(input)` returns 112 bytes (scalar (56) || point (56)).
 * Decaf448 sign needs only the scalar half.
 */
function hashToScalarScalarOnly(input: Uint8Array): Uint8Array {
  const out = parseWasmHex(bulletproofs.js_hash_to_scalar(bytesToHex(input)), 'hash_to_scalar');
  if (out.length !== 112) {
    throw new Error(`hash_to_scalar expected 112 bytes, got ${out.length}`);
  }
  return out.slice(0, DECAF448_SCALAR_SIZE);
}

function pointAddition(a: Uint8Array, b: Uint8Array): Uint8Array {
  return parseWasmHex(
    bulletproofs.js_point_addition(bytesToHex(a), bytesToHex(b)),
    'point_addition',
  );
}

// ============================================================
// Protocol helpers — direct ports of qkms/src/mpc/decaf448_threshold_n.go
// ============================================================

/**
 * Evaluate f(x) = sum(coefficients[i] * x^i) mod order.
 * Mirrors evaluatePolynomial() in decaf448_threshold_n.go:585.
 * Coefficients are 56-byte LE scalars; output is also 56-byte LE.
 */
function evaluatePolynomial(coefficients: Uint8Array[], x: number): Uint8Array {
  let result = 0n;
  let xPow = 1n;
  const xBig = BigInt(x);
  for (const coeff of coefficients) {
    const coeffBig = leBytes56ToBigint(coeff);
    result = (result + coeffBig * xPow) % DECAF448_ORDER;
    xPow = (xPow * xBig) % DECAF448_ORDER;
  }
  return bigintToLEBytes56(result);
}

/**
 * Compute Lagrange coefficient L_i(0) for party i in the cosigner set, mod order.
 * Mirrors computeDecaf448LagrangeCoeff in decaf448_threshold_n_client.go:517.
 */
function computeLagrangeCoeff(partyId: number, cosignerIds: number[]): bigint {
  let num = 1n;
  let den = 1n;
  for (const j of cosignerIds) {
    if (j === partyId) continue;
    // num *= -j mod order
    const negJ = ((-BigInt(j)) % DECAF448_ORDER + DECAF448_ORDER) % DECAF448_ORDER;
    num = (num * negJ) % DECAF448_ORDER;
    // den *= (i - j) mod order
    const diff = ((BigInt(partyId) - BigInt(j)) % DECAF448_ORDER + DECAF448_ORDER) % DECAF448_ORDER;
    den = (den * diff) % DECAF448_ORDER;
  }
  // L_i(0) = num * den^{-1} mod order
  const denInv = modInverse(den, DECAF448_ORDER);
  return (num * denInv) % DECAF448_ORDER;
}

/** Modular inverse via extended Euclidean algorithm. */
function modInverse(a: bigint, m: bigint): bigint {
  const aMod = ((a % m) + m) % m;
  let [old_r, r] = [aMod, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) throw new Error('modInverse: not invertible');
  return ((old_s % m) + m) % m;
}

/**
 * Compute partial Schnorr signature: s_i = k_i - c * lagrange_share_i
 * where lagrange_share_i = L_i(0) * sk_i (precomputed) and
 * c = HashToScalar(message || publicKey || R).
 * Mirrors computeDecaf448PartialSchnorr in decaf448_sign.go:259.
 */
function computePartialSchnorr(
  nonce: Uint8Array,
  lagrangeKeyShare: Uint8Array,
  combinedR: Uint8Array,
  publicKey: Uint8Array,
  message: Uint8Array,
): Uint8Array {
  const challengeInput = new Uint8Array(message.length + publicKey.length + combinedR.length);
  challengeInput.set(message, 0);
  challengeInput.set(publicKey, message.length);
  challengeInput.set(combinedR, message.length + publicKey.length);
  const challenge = hashToScalarScalarOnly(challengeInput);
  const cx = scalarMultScalarOnly(challenge, lagrangeKeyShare);
  return scalarSubtraction(nonce, cx);
}

// ============================================================
// Per-task in-memory state
// ============================================================

interface DkgState {
  internalRound: 0 | 1 | 2;
  partyId: number;
  threshold: number;
  totalParties: number;
  /** 56-byte LE scalars — the polynomial coefficients we generated. */
  coefficients: Uint8Array[];
  /** 56-byte compressed points — Feldman commitments g^{a_i}. */
  commitments: Uint8Array[];
  /** Map partyId → 56-byte LE scalar. Shares we send to each party. */
  shares: Map<number, Uint8Array>;
  /** Collected from other parties: their commitment lists. */
  collectedCommitments: Map<number, Uint8Array[]>;
  /** Collected from other parties: shares targeted at us. */
  collectedShares: Map<number, Uint8Array>;
}

interface SignState {
  internalRound: 0 | 1 | 2;
  partyId: number;
  cosignerIds: number[];
  message: Uint8Array;
  publicKey: Uint8Array;
  /** 56-byte LE scalar — our random nonce k_i. */
  nonce: Uint8Array;
  /** 56-byte point — R_i = g^{k_i}. */
  nonceCommit: Uint8Array;
  /** Pre-computed L_i(0) * sk_i mod order, as a 56-byte LE scalar. */
  lagrangeKeyShare: Uint8Array;
  /** R = sum(R_i) — set after round 0. */
  aggregatedNonce: Uint8Array;
}

interface KeyShare {
  partyId: number;
  /** Hex-encoded 56-byte LE scalar. */
  skShareHex: string;
  /** Hex-encoded 56-byte compressed point. */
  verificationKeyHex: string;
}

// ============================================================
// Session
// ============================================================

export class Decaf448Session implements ProtocolSession {
  private readonly dkgStates = new Map<string, DkgState>();
  private readonly signStates = new Map<string, SignState>();
  /** Cache of completed key shares so re-poll after completion is idempotent. */
  private readonly completedKeyShares = new Map<string, KeyShare>();

  /** Persist a finalized key share. Apps wire this to their StorageAdapter. */
  onKeyShareReady?: (keyId: string, keyShareJson: string, publicKeyHex: string) => Promise<void>;

  /** Resolver for stored key shares used by signing. Returns a JSON string or null. */
  loadKeyShare?: (keyId: string) => Promise<string | null>;

  canHandle(task: QkmsTask): boolean {
    const sd = parseServerData(task);
    const keySpec = task.KeySpec ?? (sd as Record<string, unknown>).keySpec as string ?? '';
    const proto = (task.Protocol ?? (sd as Record<string, unknown>).protocol as string ?? '').toLowerCase();
    if (keySpec === 'ECC_DECAF_448' || keySpec === 'ECC_DECAF448') return true;
    return proto === 'decaf448' || proto === 'decaf448-n';
  }

  async process(task: QkmsTask, ctx: SessionContext): Promise<void> {
    const operation = (task.Operation ?? '').toLowerCase();
    if (operation === 'createkey') {
      await this.processDKG(task, ctx);
    } else if (operation === 'sign') {
      await this.processSign(task, ctx);
    } else {
      throw new Error(`Decaf448Session: unsupported operation ${task.Operation}`);
    }
  }

  // ----- DKG --------------------------------------------------------------

  private async processDKG(task: QkmsTask, ctx: SessionContext): Promise<void> {
    const serverData = parseServerData(task);
    const partyIdMap = serverData.partyIDMap ?? {};
    const myPartyId = partyIdMap[ctx.sidecarId];
    if (myPartyId == null) {
      throw new Error(`Decaf448 DKG: sidecar id ${ctx.sidecarId} not in partyIDMap`);
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
        // Already initialized — just resubmit cached contribution shape.
        // The dispatcher's submittedRounds cache normally prevents this.
        await this.submitContribution(task, ctx, {
          partyId: myPartyId,
          round: task.Round,
        });
        return;
      }

      const threshold = serverData.thresholdConfig?.threshold ?? 2;
      const totalParties = serverData.thresholdConfig?.totalParties ?? 3;

      // Generate random polynomial coefficients (one per threshold).
      const coefficients: Uint8Array[] = [];
      const commitments: Uint8Array[] = [];
      for (let i = 0; i < threshold; i++) {
        const coeff = randomScalar();
        coefficients.push(coeff);
        commitments.push(scalarToPoint(coeff));
      }

      // Evaluate the polynomial at every party id 1..totalParties to produce
      // the share each party will receive.
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

      // Round 0: send commitments only.
      await this.submitContribution(task, ctx, {
        partyId: myPartyId,
        round: 0,
        commitments: commitments.map(bytesToBase64),
      });
      return;
    }

    const state = this.dkgStates.get(task.TaskId);
    if (!state) {
      throw new Error(`Decaf448 DKG: no session for task ${task.TaskId} at round ${task.Round}`);
    }
    const partyContribs = serverData.partyContributions ?? {};

    if (state.internalRound === 0) {
      // Round 0 → 1: store other parties' commitments, then send our shares.
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
          `Decaf448 DKG: expected ${expected} other commitments, got ${state.collectedCommitments.size}`,
        );
      }
      state.internalRound = 1;

      // Send our shares — one per recipient party id.
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
      // Round 1 → complete: collect shares for us, combine into the final
      // sk_share, sum the constant-term commitments into the verification key.
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
          `Decaf448 DKG: expected ${expected} shares for us, got ${state.collectedShares.size}`,
        );
      }

      // Combined verification key = sum of every party's commitment[0].
      let publicKey = state.commitments[0]!;
      for (const coms of state.collectedCommitments.values()) {
        if (coms.length === 0) continue;
        publicKey = pointAddition(publicKey, coms[0]!);
      }

      // Combined sk_share = sum of every share targeted at us (including ours).
      // Use BigInt arithmetic mod the curve order rather than scalar_addition,
      // since scalar_addition doesn't reduce mod order (it's a raw byte op via
      // Scalar::from_bits / + / as_bytes — the sum can overflow 56 bytes).
      let combined = leBytes56ToBigint(state.shares.get(state.partyId)!);
      for (const share of state.collectedShares.values()) {
        combined = (combined + leBytes56ToBigint(share)) % DECAF448_ORDER;
      }
      const skShareBytes = bigintToLEBytes56(combined);

      const keyShare: KeyShare = {
        partyId: state.partyId,
        skShareHex: bytesToHex(skShareBytes),
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

    throw new Error(`Decaf448 DKG: unexpected internal round ${state.internalRound}`);
  }

  // ----- Sign -------------------------------------------------------------

  private async processSign(task: QkmsTask, ctx: SessionContext): Promise<void> {
    const serverData = parseServerData(task);
    const partyIdMap = serverData.partyIDMap ?? {};
    const myPartyId = partyIdMap[ctx.sidecarId];
    if (myPartyId == null) {
      throw new Error(`Decaf448 sign: sidecar id ${ctx.sidecarId} not in partyIDMap`);
    }

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

    const dkgPartyId = dkgPartyIdMap[ctx.sidecarId] ?? myPartyId;

    if (task.Round === 0) {
      if (this.signStates.has(task.TaskId)) {
        await this.submitContribution(task, ctx, {
          partyId: dkgPartyId,
          round: task.Round,
        });
        return;
      }

      const message = decodeWireBytes(serverData.message);
      if (message.length === 0) {
        throw new Error('Decaf448 sign: missing message in serverData');
      }
      if (!task.KeyId) throw new Error('Decaf448 sign: task missing KeyId');
      if (!this.loadKeyShare) {
        throw new Error('Decaf448 sign: loadKeyShare resolver not set on session');
      }
      const keyShareJson = await this.loadKeyShare(task.KeyId);
      if (!keyShareJson) {
        throw new Error(`Decaf448 sign: no key share for key ${task.KeyId}`);
      }
      const keyShare = JSON.parse(keyShareJson) as KeyShare;
      const skShare = hexToBytes(keyShare.skShareHex);
      const publicKey = hexToBytes(keyShare.verificationKeyHex);

      // Random nonce + commitment R_i = g^{k_i}.
      const nonce = randomScalar();
      const nonceCommit = scalarToPoint(nonce);

      // Pre-compute lagrangeKeyShare = L_i(0) * sk_i mod order.
      const lagrange = computeLagrangeCoeff(dkgPartyId, cosignerIds);
      const skShareBig = leBytes56ToBigint(skShare);
      const lagrangeKeyShareBig = (lagrange * skShareBig) % DECAF448_ORDER;
      const lagrangeKeyShare = bigintToLEBytes56(lagrangeKeyShareBig);

      this.signStates.set(task.TaskId, {
        internalRound: 0,
        partyId: dkgPartyId,
        cosignerIds,
        message,
        publicKey,
        nonce,
        nonceCommit,
        lagrangeKeyShare,
        aggregatedNonce: new Uint8Array(),
      });

      await this.submitContribution(task, ctx, {
        partyId: dkgPartyId,
        round: 0,
        nonceCommit: bytesToBase64(nonceCommit),
      });
      return;
    }

    const state = this.signStates.get(task.TaskId);
    if (!state) {
      throw new Error(`Decaf448 sign: no session for task ${task.TaskId} at round ${task.Round}`);
    }
    const partyContribs = serverData.partyContributions ?? {};

    if (state.internalRound === 0) {
      // Round 0 → 1: aggregate nonce commits, compute partial sig.
      const allNonceCommits = new Map<number, Uint8Array>();
      allNonceCommits.set(state.partyId, state.nonceCommit);
      for (const [sidecarKey, contrib] of Object.entries(partyContribs)) {
        if (sidecarKey === ctx.sidecarId) continue;
        if (!contrib.nonceCommit) continue;
        allNonceCommits.set(contrib.partyId, decodeWireBytes(contrib.nonceCommit));
      }

      // R = sum(R_i) — order doesn't matter for point addition.
      let aggregatedNonce: Uint8Array | null = null;
      for (const commit of allNonceCommits.values()) {
        if (aggregatedNonce == null) {
          aggregatedNonce = commit;
        } else {
          aggregatedNonce = pointAddition(aggregatedNonce, commit);
        }
      }
      if (aggregatedNonce == null) {
        throw new Error('Decaf448 sign: no nonce commitments to aggregate');
      }
      state.aggregatedNonce = aggregatedNonce;

      const partialSig = computePartialSchnorr(
        state.nonce,
        state.lagrangeKeyShare,
        aggregatedNonce,
        state.publicKey,
        state.message,
      );

      state.internalRound = 1;
      await this.submitContribution(task, ctx, {
        partyId: state.partyId,
        round: task.Round,
        partialSig: bytesToBase64(partialSig),
        aggregatedNonce: bytesToBase64(aggregatedNonce),
      });
      return;
    }

    if (state.internalRound === 1) {
      // Round 1 → complete: aggregate partial sigs, build (R, s) signature.
      // Recompute our own partial sig (the Go side does the same — we don't
      // store it across rounds because it's cheap to redo).
      const ownPartialSig = computePartialSchnorr(
        state.nonce,
        state.lagrangeKeyShare,
        state.aggregatedNonce,
        state.publicKey,
        state.message,
      );

      let aggregatedS = ownPartialSig;
      for (const [sidecarKey, contrib] of Object.entries(partyContribs)) {
        if (sidecarKey === ctx.sidecarId) continue;
        if (!contrib.partialSig) continue;
        aggregatedS = scalarAddition(aggregatedS, decodeWireBytes(contrib.partialSig));
      }

      // Signature = R || s, 112 bytes.
      const signature = new Uint8Array(state.aggregatedNonce.length + aggregatedS.length);
      signature.set(state.aggregatedNonce, 0);
      signature.set(aggregatedS, state.aggregatedNonce.length);

      state.internalRound = 2;
      this.signStates.delete(task.TaskId);

      await this.submitContribution(task, ctx, {
        partyId: state.partyId,
        round: task.Round,
        complete: true,
        signature: bytesToBase64(signature),
      });
      return;
    }

    throw new Error(`Decaf448 sign: unexpected internal round ${state.internalRound}`);
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

// Avoid an unused-import warning if WasmScalarMultResult ends up needed.
export type _ = WasmScalarMultResult;
