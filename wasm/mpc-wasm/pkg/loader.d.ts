/**
 * The set of MPC protocol functions registered on `globalThis.mpcWasm` once
 * the Go wasm runtime has booted. Each function takes a single JSON-encoded
 * string argument and returns a JSON-encoded string result.
 *
 * Errors are returned in-band as `{"error": "..."}`.
 *
 * Protocols currently exposed:
 *   - FROST EdDSA (dkg_*, sign_*)
 *   - RSA-N threshold sign/decrypt (rsa_shoup_partial, rsa_shoup_combine)
 *   - RSA-N distributed key generation (rsa_dkg_init, rsa_dkg_round)
 *   - RSA 2PC key generation (rsa_2pc_init, rsa_2pc_round)
 *   - BLS12-381 threshold DKG + sign (bls12381_dkg_*, bls12381_partial_sig, bls12381_aggregate_sigs, bls12381_verify)
 */
export interface MpcWasmApi {
  // ----- FROST EdDSA -----
  /** dkgInitRequest -> dkgInitResponse JSON */
  dkg_init(requestJson: string): string;
  /** dkgRoundRequest -> dkgRoundResponse JSON */
  dkg_round(requestJson: string): string;
  /** signInitRequest -> signInitResponse JSON */
  sign_init(requestJson: string): string;
  /** signRoundRequest -> signRoundResponse JSON */
  sign_round1to2(requestJson: string): string;
  /** signRoundRequest -> signRoundResponse JSON */
  sign_round2to3(requestJson: string): string;

  // ----- RSA-N threshold (Shoup 2000) -----
  /** Compute Shoup partial: m^{2*Δ*d_i} mod N. */
  rsa_shoup_partial(requestJson: string): string;
  /** Combine partials via Lagrange interpolation + extended GCD. */
  rsa_shoup_combine(requestJson: string): string;

  // ----- RSA-N distributed key generation (Paillier-based, 8-phase) -----
  /** Initialize DKG session and return Phase 1 broadcast. */
  rsa_dkg_init(requestJson: string): string;
  /** Process one incoming DKG message. */
  rsa_dkg_round(requestJson: string): string;

  // ----- RSA 2PC key generation -----
  /** Initialize RSA 2PC client session: generate prime q and return commitment. */
  rsa_2pc_init(requestJson: string): string;
  /** Process one round of RSA 2PC from the client side. */
  rsa_2pc_round(requestJson: string): string;

  // ----- BLS12-381 threshold DKG + signing -----
  /** Initialize BLS12-381 DKG session, return round 0 contribution. */
  bls12381_dkg_init(requestJson: string): string;
  /** Advance BLS12-381 DKG one round. */
  bls12381_dkg_round(requestJson: string): string;
  /** Compute Lagrange-weighted partial BLS12-381 signature. */
  bls12381_partial_sig(requestJson: string): string;
  /** Aggregate partial BLS12-381 signatures into final signature. */
  bls12381_aggregate_sigs(requestJson: string): string;
  /** Verify a BLS12-381 signature against a public key. */
  bls12381_verify(requestJson: string): string;

  /** Free per-task state for any protocol. */
  clear(sessionId: string): void;
  /** Always true once the runtime is up. */
  ready: boolean;
}

/** Legacy alias retained for callers still referring to the FROST-only API shape. */
export type FrostWasmApi = MpcWasmApi;

/**
 * Loads mpc.wasm and starts the Go runtime. Resolves to the registered API.
 * Idempotent: subsequent calls return the cached instance.
 *
 * Browser: pass `wasmUrl` to override the location of mpc.wasm
 * (defaults to a URL relative to this loader). Node: pass `wasmPath`
 * (absolute filesystem path).
 */
export function loadMpcWasm(opts?: {
  wasmUrl?: string;
  wasmPath?: string;
}): Promise<MpcWasmApi>;

/** Backwards-compat alias for `loadMpcWasm`. */
export const loadFrostWasm: typeof loadMpcWasm;
