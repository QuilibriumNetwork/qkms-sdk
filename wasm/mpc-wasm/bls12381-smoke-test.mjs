// Full BLS12-381 t-of-n protocol smoke test.
//
// Drives a 2-of-3 Feldman VSS DKG and a threshold sign through the new
// bls12381_* handlers in mpc-wasm, then verifies the aggregated signature
// using bls12381_verify. This mirrors the BLSSession.processDKG12381 +
// processSign12381 flow in the TS SDK.
//
// Run from this directory:  node bls12381-smoke-test.mjs

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

// ---- Load Go wasm runtime ----
const go = await import(join(here, 'pkg/wasm_exec.js'));
const Go = globalThis.Go;
const goInst = new Go();
const wasmPath = join(here, 'pkg/mpc.wasm');
const wasmBytes = await readFile(wasmPath);
const { instance } = await WebAssembly.instantiate(wasmBytes, goInst.importObject);
goInst.run(instance); // starts the Go main goroutine

// Wait for globalThis.mpcWasm.ready
while (!globalThis.mpcWasm?.ready) {
  await new Promise((r) => setTimeout(r, 50));
}
const api = globalThis.mpcWasm;
console.log('[bls12381] mpc-wasm loaded, BLS12-381 handlers available');

function call(method, req) {
  const raw = api[method](JSON.stringify(req));
  const resp = JSON.parse(raw);
  if (resp.error) throw new Error(`${method}: ${resp.error}`);
  return resp;
}

// ---- Config ----
const N = 3; // total parties
const T = 2; // threshold

// ---- DKG ----
console.log(`[bls12381] Running ${T}-of-${N} DKG...`);

const sessionIds = {};
const contributions = {}; // round 0 contributions indexed by sidecarId
const keyShares = {};
const sidecarIds = ['sidecar-1', 'sidecar-2', 'sidecar-3'];

// Round 0: each party inits DKG, gets commitments contribution
for (let p = 0; p < N; p++) {
  const sessionId = `dkg-test-${p + 1}`;
  sessionIds[p] = sessionId;

  const result = call('bls12381_dkg_init', {
    sessionId,
    partyId: p + 1,
    threshold: T,
    totalParties: N,
  });
  contributions[sidecarIds[p]] = result.contribution;
  console.log(`  Party ${p + 1}: DKG init OK (commitments: ${contributions[sidecarIds[p]].commitments.length})`);
}

// Verify all parties emitted round 0 with commitments
for (const [sid, contrib] of Object.entries(contributions)) {
  if (!contrib.commitments || contrib.commitments.length !== T) {
    throw new Error(`Party ${sid} missing commitments`);
  }
}

// Round 1: each party processes others' commitments, sends shares
const round1Contribs = {};
for (let p = 0; p < N; p++) {
  const result = call('bls12381_dkg_round', {
    sessionId: sessionIds[p],
    taskRound: 1,
    mySidecarId: sidecarIds[p],
    partyContributions: contributions,
  });
  if (result.complete) throw new Error(`Party ${p + 1} completed too early`);
  round1Contribs[sidecarIds[p]] = result.contribution;
  console.log(`  Party ${p + 1}: round 1 OK (shares keys: ${Object.keys(round1Contribs[sidecarIds[p]].shares ?? {}).length})`);
}

// Round 2 (finalize): each party processes others' shares, combines
for (let p = 0; p < N; p++) {
  const result = call('bls12381_dkg_round', {
    sessionId: sessionIds[p],
    taskRound: 2,
    mySidecarId: sidecarIds[p],
    partyContributions: round1Contribs,
  });
  if (!result.complete) throw new Error(`Party ${p + 1} did not complete`);
  if (!result.keyShare) throw new Error(`Party ${p + 1} missing keyShare`);
  keyShares[p + 1] = result.keyShare;
  console.log(`  Party ${p + 1}: DKG COMPLETE (vk: ${result.keyShare.verificationKey?.length} bytes)`);
}

// Verify all parties agree on the verification key
const vk0 = JSON.stringify(keyShares[1].verificationKey);
for (let p = 2; p <= N; p++) {
  if (JSON.stringify(keyShares[p].verificationKey) !== vk0) {
    throw new Error(`Party ${p} verification key mismatch!`);
  }
}
console.log('[bls12381] All parties agree on verification key');

// ---- Sign ----
const message = Buffer.from('Hello from BLS12-381 threshold!').toString('base64');
// verificationKey is already base64 from Go's JSON marshaling of []byte
const vkB64 = keyShares[1].verificationKey;

// Try three different 2-of-3 subsets to prove threshold works
const subsets = [
  [1, 2],
  [1, 3],
  [2, 3],
];

for (const signers of subsets) {
  console.log(`[bls12381] Signing with subset {${signers.join(', ')}}...`);

  // Each signer computes a Lagrange-weighted partial sig
  const partials = {};
  for (const pid of signers) {
    const ks = keyShares[pid];
    // skShare is already base64 from Go's JSON marshaling of []byte
    const skShareB64 = ks.skShare;

    const result = call('bls12381_partial_sig', {
      keyShare: skShareB64,
      message,
      partyId: pid,
      cosignerIds: signers,
    });
    partials[String(pid)] = result.partialSig;
    console.log(`  Party ${pid}: partial sig OK`);
  }

  // Aggregate
  const aggResult = call('bls12381_aggregate_sigs', { partials });
  console.log(`  Aggregated signature: ${aggResult.signature.slice(0, 20)}...`);

  // Verify against master public key
  const verifyResult = call('bls12381_verify', {
    publicKey: vkB64,
    message,
    signature: aggResult.signature,
  });

  if (!verifyResult.valid) {
    throw new Error(`Signature verification FAILED for subset {${signers.join(', ')}}`);
  }
  console.log(`  Verification: PASS`);
}

console.log('\n[bls12381] All tests passed!');
process.exit(0);
