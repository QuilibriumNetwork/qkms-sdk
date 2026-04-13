// Full BLS48-581 t-of-n protocol smoke test.
//
// Drives a 2-of-3 Feldman VSS DKG and a 2-party Lagrange-weighted
// threshold sign through the new bls48581-wasm helpers, then verifies
// the aggregated signature against the master public key with the
// existing js_bls_verify. This is the same protocol the qkms-sdk
// BLSSession runs, just stripped of the dispatcher / wire format
// plumbing so we can exercise the math directly.
//
// Run from this directory:  node bls-protocol-smoke-test.mjs

import * as bls from '../../../ceremonyclient/crates/bls48581-wasm/pkg/bls48581wasm.js';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const wasmPath = join(here, '../../../ceremonyclient/crates/bls48581-wasm/pkg/bls48581wasm_bg.wasm');
await bls.default({ module_or_path: await readFile(wasmPath) });
bls.js_init();

function unwrap(json, label) {
  const v = JSON.parse(json);
  if (v && typeof v === 'object' && 'error' in v) {
    throw new Error(`${label}: ${v.error}`);
  }
  if (typeof v !== 'string' && typeof v !== 'boolean') {
    throw new Error(`${label}: unexpected return type ${typeof v}`);
  }
  return v;
}

function hex(s) { return s; } // already hex

function scalarRandom() { return unwrap(bls.js_bls_scalar_random(), 'scalar_random'); }
function scalarMul(a, b) { return unwrap(bls.js_bls_scalar_mul(a, b), 'scalar_mul'); }
function scalarAdd(a, b) { return unwrap(bls.js_bls_scalar_add(a, b), 'scalar_add'); }
function scalarSub(a, b) { return unwrap(bls.js_bls_scalar_sub(a, b), 'scalar_sub'); }
function scalarNeg(a) { return unwrap(bls.js_bls_scalar_neg(a), 'scalar_neg'); }
function scalarInv(a) { return unwrap(bls.js_bls_scalar_inv(a), 'scalar_inv'); }
function scalarFromU64(v) { return unwrap(bls.js_bls_scalar_from_u64(BigInt(v)), 'scalar_from_u64'); }
function scalarToG1(s) { return unwrap(bls.js_bls_scalar_to_g1(s), 'scalar_to_g1'); }
function g1Add(a, b) { return unwrap(bls.js_bls_g1_add(a, b), 'g1_add'); }
function scalarToG8(s) { return unwrap(bls.js_bls_scalar_to_g8(s), 'scalar_to_g8'); }
function g8Add(a, b) { return unwrap(bls.js_bls_g8_add(a, b), 'g8_add'); }
function blsSign(sk, msg, dom) { return unwrap(bls.js_bls_sign(sk, msg, dom), 'bls_sign'); }
function blsVerify(pk, sig, msg, dom) {
  // js_bls_verify returns a JSON-encoded boolean, not a hex string.
  const v = JSON.parse(bls.js_bls_verify(pk, sig, msg, dom));
  return v === true;
}

function evaluatePolynomial(coefficients, x) {
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

function lagrangeCoeff(partyId, cosignerIds) {
  let num = scalarFromU64(1);
  let den = scalarFromU64(1);
  const i = scalarFromU64(partyId);
  for (const j of cosignerIds) {
    if (j === partyId) continue;
    const jS = scalarFromU64(j);
    num = scalarMul(num, scalarNeg(jS));
    den = scalarMul(den, scalarSub(i, jS));
  }
  return scalarMul(num, scalarInv(den));
}

console.log('[bls-proto] Running 2-of-3 BLS48-581 DKG + threshold sign…');

const N = 3;          // total parties
const T = 2;          // threshold

// ----- DKG ---------------------------------------------------------------

// Each party generates polynomial coefficients and Feldman commitments.
const partyCoefficients = new Map();   // partyId → [scalar]
const partyCommitments = new Map();    // partyId → [g1 point]
const partyShares = new Map();         // partyId → Map(recipientId → scalar)

for (let p = 1; p <= N; p++) {
  const coefficients = [];
  const commitments = [];
  for (let i = 0; i < T; i++) {
    const coeff = scalarRandom();
    coefficients.push(coeff);
    // BLS48-581 puts public keys on G8/ECP8 (the larger pairing-friendly group),
    // so Feldman commitments + master verification key live on G8 too.
    commitments.push(scalarToG8(coeff));
  }
  partyCoefficients.set(p, coefficients);
  partyCommitments.set(p, commitments);

  // Evaluate at every party id 1..N.
  const shares = new Map();
  for (let j = 1; j <= N; j++) {
    shares.set(j, evaluatePolynomial(coefficients, j));
  }
  partyShares.set(p, shares);
}
console.log('[bls-proto] DKG round 0: 3 parties produced commitments + shares');

// Each party combines (their own share + shares for them from others).
const finalSkShares = new Map();
for (let p = 1; p <= N; p++) {
  let combined = partyShares.get(p).get(p); // own share
  for (let q = 1; q <= N; q++) {
    if (q === p) continue;
    const shareForP = partyShares.get(q).get(p);
    combined = scalarAdd(combined, shareForP);
  }
  finalSkShares.set(p, combined);
}
console.log('[bls-proto] DKG round 1: each party combined their final sk_share');

// Verification key = sum of every party's commitment[0] (g8^{a_0_p}).
let masterPk = partyCommitments.get(1)[0];
for (let p = 2; p <= N; p++) {
  masterPk = g8Add(masterPk, partyCommitments.get(p)[0]);
}
console.log('[bls-proto] master verification key derived (', masterPk.length / 2, 'bytes G8)');

// Sanity check: master pubkey should equal g8^(sum of constant terms).
let sumOfConstantTerms = scalarFromU64(0);
for (let p = 1; p <= N; p++) {
  sumOfConstantTerms = scalarAdd(sumOfConstantTerms, partyCoefficients.get(p)[0]);
}
const masterPkAlt = scalarToG8(sumOfConstantTerms);
if (masterPk !== masterPkAlt) {
  throw new Error('master pk mismatch: g8^(sum of a_0_p) != sum of g8^a_0_p');
}
console.log('[bls-proto] ✓ master pk consistency check (additive homomorphism on G8)');

// ----- Threshold sign with parties {1, 2} --------------------------------

const message = Buffer.from('hello qkms-sdk bls-n', 'utf-8').toString('hex');
const signers = [1, 2];

// Each signer computes a Lagrange-weighted partial sig.
const partialSigs = signers.map((p) => {
  const lagrange = lagrangeCoeff(p, signers);
  const scaled = scalarMul(finalSkShares.get(p), lagrange);
  return blsSign(scaled, message, '');
});
console.log('[bls-proto] threshold sign: 2 partial sigs computed');

// Aggregate partial sigs via G1 point addition.
let aggregated = partialSigs[0];
for (let i = 1; i < partialSigs.length; i++) {
  aggregated = g1Add(aggregated, partialSigs[i]);
}

// Verify the aggregated signature against the master public key.
const ok = blsVerify(masterPk, aggregated, message, '');
if (!ok) {
  console.error('[bls-proto] FAILED: aggregated threshold signature did not verify');
  console.error('  master pk: ', masterPk.slice(0, 32) + '…');
  console.error('  signature: ', aggregated.slice(0, 32) + '…');
  process.exit(1);
}
console.log('[bls-proto] ✅ aggregated threshold signature VERIFIES against master pk');

// Also try with signers {1, 3} to make sure other subsets work.
const signers2 = [1, 3];
const partialSigs2 = signers2.map((p) => {
  const lagrange = lagrangeCoeff(p, signers2);
  const scaled = scalarMul(finalSkShares.get(p), lagrange);
  return blsSign(scaled, message, '');
});
let aggregated2 = partialSigs2[0];
for (let i = 1; i < partialSigs2.length; i++) {
  aggregated2 = g1Add(aggregated2, partialSigs2[i]);
}
const ok2 = blsVerify(masterPk, aggregated2, message, '');
if (!ok2) {
  console.error('[bls-proto] FAILED: signature from subset {1,3} did not verify');
  process.exit(1);
}
console.log('[bls-proto] ✅ subset {1, 3} also produces a valid signature');

// And signers {2, 3}.
const signers3 = [2, 3];
const partialSigs3 = signers3.map((p) => {
  const lagrange = lagrangeCoeff(p, signers3);
  const scaled = scalarMul(finalSkShares.get(p), lagrange);
  return blsSign(scaled, message, '');
});
let aggregated3 = partialSigs3[0];
for (let i = 1; i < partialSigs3.length; i++) {
  aggregated3 = g1Add(aggregated3, partialSigs3[i]);
}
const ok3 = blsVerify(masterPk, aggregated3, message, '');
if (!ok3) {
  console.error('[bls-proto] FAILED: signature from subset {2,3} did not verify');
  process.exit(1);
}
console.log('[bls-proto] ✅ subset {2, 3} also produces a valid signature');

console.log('[bls-proto] all checks passed ✅');
