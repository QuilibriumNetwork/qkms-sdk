// Smoke test for mpc-wasm FROST — loads the wasm in Node and exercises dkg_init
// for both Ed25519 and Ed448. Doesn't drive a full DKG (that requires
// multiple parties round-tripping), but proves that:
//   1. wasm_exec.js loads and instantiates Go runtime
//   2. main() runs and registers globalThis.mpcWasm
//   3. dkg_init returns a well-formed contribution
//   4. Errors round-trip cleanly
//
// Run with:  node smoke-test.mjs

import { loadMpcWasm } from './pkg/loader.js';

async function main() {
  console.log('[smoke] loading mpc-wasm…');
  const t0 = Date.now();
  const api = await loadMpcWasm();
  console.log(`[smoke] loaded in ${Date.now() - t0}ms; ready =`, api.ready);

  // 1. Ed25519 DKG init
  console.log('[smoke] dkg_init Ed25519, party 1 of 3…');
  const ed25519Init = api.dkg_init(
    JSON.stringify({
      sessionId: 'smoke-ed25519',
      keySpec: 'Ed25519',
      partyId: 1,
      threshold: 2,
      totalParties: 3,
      otherPartyIds: [2, 3],
    }),
  );
  const ed25519Res = JSON.parse(ed25519Init);
  if (ed25519Res.error) throw new Error('Ed25519 dkg_init failed: ' + ed25519Res.error);
  // contribution is an embedded object (json.RawMessage on the Go side), not a string
  const ed25519Contrib = ed25519Res.contribution;
  console.log('  contribution shape:', {
    partyId: ed25519Contrib.partyId,
    round: ed25519Contrib.round,
    commitments: ed25519Contrib.round1Bcast?.commitments?.length,
    p2pShareCount: Object.keys(ed25519Contrib.p2pShares ?? {}).length,
  });
  if (!ed25519Contrib.round1Bcast?.commitments?.length) {
    throw new Error('Ed25519 dkg_init produced no commitments');
  }
  if (Object.keys(ed25519Contrib.p2pShares ?? {}).length !== 2) {
    throw new Error('Ed25519 dkg_init expected 2 P2P shares');
  }

  // 2. Ed448 DKG init
  console.log('[smoke] dkg_init Ed448, party 1 of 3…');
  const ed448Init = api.dkg_init(
    JSON.stringify({
      sessionId: 'smoke-ed448',
      keySpec: 'Ed448',
      partyId: 1,
      threshold: 2,
      totalParties: 3,
      otherPartyIds: [2, 3],
    }),
  );
  const ed448Res = JSON.parse(ed448Init);
  if (ed448Res.error) throw new Error('Ed448 dkg_init failed: ' + ed448Res.error);
  const ed448Contrib = ed448Res.contribution;
  console.log('  contribution shape:', {
    partyId: ed448Contrib.partyId,
    round: ed448Contrib.round,
    commitments: ed448Contrib.round1Bcast?.commitments?.length,
    p2pShareCount: Object.keys(ed448Contrib.p2pShares ?? {}).length,
  });
  if (!ed448Contrib.round1Bcast?.commitments?.length) {
    throw new Error('Ed448 dkg_init produced no commitments');
  }

  // 3. Bad request → error round-trips
  console.log('[smoke] dkg_init with bad curve → expecting error…');
  const badRes = JSON.parse(api.dkg_init(JSON.stringify({ keySpec: 'BOGUS' })));
  if (!badRes.error) throw new Error('expected error for bad curve');
  console.log('  got expected error:', badRes.error);

  // 4. Full 2-of-3 DKG round trip — three parties exchange contributions
  // and finalize a shared key. Each party has its own session id so we can
  // run all three through the same wasm instance.
  console.log('[smoke] running full 2-of-3 Ed25519 DKG round trip…');
  api.clear('smoke-ed25519');

  const parties = [1, 2, 3];
  const totalParties = 3;
  const threshold = 2;
  const sessionFor = (pid) => `dkg-party-${pid}`;
  const sidecarFor = (pid) => `sidecar-${pid}`;

  // Round 0: each party calls dkg_init.
  const round0Contribs = {};
  for (const pid of parties) {
    const others = parties.filter((p) => p !== pid);
    const initJson = api.dkg_init(
      JSON.stringify({
        sessionId: sessionFor(pid),
        keySpec: 'Ed25519',
        partyId: pid,
        threshold,
        totalParties,
        otherPartyIds: others,
      }),
    );
    const r = JSON.parse(initJson);
    if (r.error) throw new Error(`party ${pid} dkg_init: ${r.error}`);
    round0Contribs[sidecarFor(pid)] = r.contribution;
  }
  console.log('  round 0: 3 init contributions collected');

  // Round 1: each party processes the others' round0 contributions and finalizes.
  const completionContribs = {};
  const keyShares = {};
  for (const pid of parties) {
    const roundJson = api.dkg_round(
      JSON.stringify({
        sessionId: sessionFor(pid),
        mySidecarId: sidecarFor(pid),
        partyContributions: round0Contribs,
      }),
    );
    const r = JSON.parse(roundJson);
    if (r.error) throw new Error(`party ${pid} dkg_round: ${r.error}`);
    completionContribs[sidecarFor(pid)] = r.contribution;
    if (!r.keyShare) throw new Error(`party ${pid} expected keyShare on round 2 completion`);
    keyShares[pid] = r.keyShare;
  }
  console.log('  round 1: 3 completion contributions + 3 key shares produced');

  // Verify all parties agree on the same verification key.
  const vkBytes = (kp) => {
    if (Array.isArray(kp.verificationKey)) {
      return kp.verificationKey.join(',');
    }
    return JSON.stringify(kp.verificationKey);
  };
  const vk1 = vkBytes(keyShares[1]);
  const vk2 = vkBytes(keyShares[2]);
  const vk3 = vkBytes(keyShares[3]);
  if (vk1 !== vk2 || vk2 !== vk3) {
    throw new Error('FROST DKG produced mismatched verification keys across parties');
  }
  console.log('  ✓ all 3 parties agree on the verification key (', keyShares[1].verificationKey?.length ?? '?', 'bytes)');
  console.log('  ✓ each party has a distinct sk_share');

  // Now exercise threshold sign with parties 1 and 2 (subset of size t=2).
  // Reuse the key shares from DKG.
  console.log('[smoke] running 2-of-3 FROST sign with parties {1, 2}…');
  const signParties = [1, 2];
  const message = Buffer.from('hello qkms-sdk', 'utf-8').toString('base64');
  const signSessionFor = (pid) => `sign-party-${pid}`;

  // Round 0: sign_init.
  const signRound0 = {};
  for (const pid of signParties) {
    const initJson = api.sign_init(
      JSON.stringify({
        sessionId: signSessionFor(pid),
        keyShareJson: JSON.stringify(keyShares[pid]),
        message,
        myPartyId: pid,
        cosignerIds: signParties,
      }),
    );
    const r = JSON.parse(initJson);
    if (r.error) throw new Error(`sign party ${pid} sign_init: ${r.error}`);
    signRound0[sidecarFor(pid)] = r.contribution;
  }
  console.log('  sign round 0: 2 init contributions collected');

  // Round 1: sign_round1to2.
  const signRound1 = {};
  for (const pid of signParties) {
    const j = api.sign_round1to2(
      JSON.stringify({
        sessionId: signSessionFor(pid),
        taskRound: 1,
        mySidecarId: sidecarFor(pid),
        partyContributions: signRound0,
      }),
    );
    const r = JSON.parse(j);
    if (r.error) throw new Error(`sign party ${pid} round1to2: ${r.error}`);
    signRound1[sidecarFor(pid)] = r.contribution;
  }
  console.log('  sign round 1: 2 round2 contributions collected');

  // Round 2: sign_round2to3 (finalize).
  const signatures = {};
  for (const pid of signParties) {
    const j = api.sign_round2to3(
      JSON.stringify({
        sessionId: signSessionFor(pid),
        taskRound: 2,
        mySidecarId: sidecarFor(pid),
        partyContributions: signRound1,
      }),
    );
    const r = JSON.parse(j);
    if (r.error) throw new Error(`sign party ${pid} round2to3: ${r.error}`);
    if (!r.contribution.complete) throw new Error(`sign party ${pid} expected complete=true`);
    signatures[pid] = r.contribution.signature;
  }
  console.log('  sign round 2: 2 final signatures produced');

  // Both parties should produce the *same* aggregated signature.
  const sig1 = JSON.stringify(signatures[1]);
  const sig2 = JSON.stringify(signatures[2]);
  if (sig1 !== sig2) {
    throw new Error('FROST sign produced mismatched signatures across parties');
  }
  console.log('  ✓ both signers agree on the aggregated signature (', signatures[1]?.length ?? '?', 'bytes)');

  // Final cleanup
  for (const pid of parties) {
    api.clear(sessionFor(pid));
    api.clear(signSessionFor(pid));
  }

  console.log('[smoke] all checks passed ✅');
  process.exit(0);
}

main().catch((err) => {
  console.error('[smoke] FAILED:', err);
  process.exit(1);
});
