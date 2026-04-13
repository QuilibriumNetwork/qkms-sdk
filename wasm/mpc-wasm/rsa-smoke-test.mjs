// Smoke test for the new RSA-N Shoup handlers in mpc-wasm.
//
// Exercises the sign path end-to-end:
//   1. Generate a real RSA-2048 keypair in node:crypto
//   2. Extract (n, e, d) from the PKCS#8 DER
//   3. Call rsa_shoup_partial with the full d as a 1-party "share"
//   4. Call rsa_shoup_combine with that single partial
//   5. Verify sig^e mod N == message (the Shoup algorithm extracted m^d)
//
// For n=1, delta = 1, partial = m^(2d) mod N, and CombineShoup runs the
// extended-GCD extraction exactly as it does for multi-party. So this
// test catches any wire-format bugs in the JS → Go bridge.
//
// Multi-party (true threshold) is tested by the Go side's unit suite; the
// only thing this smoke test has to prove is that (a) the wasm bridge
// transmits N, e, d, m correctly, and (b) our new exports hook into
// CombineShoup and factorial without any subtle byte-order mistakes.
//
// Run with:  node rsa-smoke-test.mjs

import { loadMpcWasm } from './pkg/loader.js';
import { generateKeyPairSync, createHash, constants, privateDecrypt } from 'node:crypto';

function bnFromBytes(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

function bytesFromBn(n, length) {
  const out = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function modPow(base, exp, mod) {
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

async function main() {
  console.log('[rsa-smoke] loading mpc-wasm…');
  const api = await loadMpcWasm();

  // 1. Generate RSA-2048 keypair + extract n, e, d via JWK export.
  console.log('[rsa-smoke] generating RSA-2048 keypair…');
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = privateKey.export({ format: 'jwk' });

  function b64urlToBytes(s) {
    const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
    return Buffer.from((s + pad).replaceAll('-', '+').replaceAll('_', '/'), 'base64');
  }
  const nBytes = b64urlToBytes(jwk.n);
  const eBytes = b64urlToBytes(jwk.e);
  const dBytes = b64urlToBytes(jwk.d);
  console.log(`[rsa-smoke]   n: ${nBytes.length} bytes, e: ${eBytes.length} bytes, d: ${dBytes.length} bytes`);

  // Convert to BigInt for reference math.
  const nBig = bnFromBytes(nBytes);
  const eBig = bnFromBytes(eBytes);

  // 2. Build a 32-byte "digest" to sign.
  const digest = createHash('sha256').update('hello qkms-sdk rsa-n').digest();

  // 3. Call rsa_shoup_partial with totalParties=1.
  console.log('[rsa-smoke] rsa_shoup_partial (1-party)…');
  const partialJson = api.rsa_shoup_partial(
    JSON.stringify({
      input: digest.toString('base64'),
      n: nBytes.toString('base64'),
      dShare: dBytes.toString('base64'),
      totalParties: 1,
    }),
  );
  const partialRes = JSON.parse(partialJson);
  if (partialRes.error) throw new Error('rsa_shoup_partial: ' + partialRes.error);
  console.log(`[rsa-smoke]   partial: ${Buffer.from(partialRes.partial, 'base64').length} bytes`);

  // Sanity: partial should equal m^(2*delta*d) mod N = m^(2d) mod N for n=1.
  const mBig = bnFromBytes(digest);
  const dBig = bnFromBytes(dBytes);
  const expectedPartial = modPow(mBig, 2n * dBig, nBig);
  const actualPartial = bnFromBytes(Buffer.from(partialRes.partial, 'base64'));
  if (actualPartial !== expectedPartial) {
    throw new Error(
      `rsa_shoup_partial result mismatch!\n  expected: ${expectedPartial.toString(16).slice(0, 32)}…\n  got:      ${actualPartial.toString(16).slice(0, 32)}…`,
    );
  }
  console.log('[rsa-smoke] ✓ partial matches pure-BigInt reference (m^(2d) mod N)');

  // 4. Call rsa_shoup_combine with the single partial.
  console.log('[rsa-smoke] rsa_shoup_combine (1-party)…');
  const combineJson = api.rsa_shoup_combine(
    JSON.stringify({
      input: digest.toString('base64'),
      n: nBytes.toString('base64'),
      e: eBytes.toString('base64'),
      totalParties: 1,
      partials: { '1': partialRes.partial },
    }),
  );
  const combineRes = JSON.parse(combineJson);
  if (combineRes.error) throw new Error('rsa_shoup_combine: ' + combineRes.error);
  const sigBytes = Buffer.from(combineRes.result, 'base64');
  console.log(`[rsa-smoke]   signature: ${sigBytes.length} bytes`);

  // 5. Verify: sig^e mod N should equal the message (digest).
  const sigBig = bnFromBytes(sigBytes);
  const recovered = modPow(sigBig, eBig, nBig);
  if (recovered !== mBig) {
    throw new Error(
      `rsa_shoup_combine: sig^e mod N does not recover the message\n  expected: ${mBig.toString(16).slice(0, 32)}…\n  got:      ${recovered.toString(16).slice(0, 32)}…`,
    );
  }
  console.log('[rsa-smoke] ✅ sig^e mod N == message (Shoup extraction correct)');

  console.log('[rsa-smoke] all checks passed ✅');
  // Explicit exit: the Go wasm runtime's `select {}` holds the Node event
  // loop open, so we'd otherwise hang forever after the test finishes.
  process.exit(0);
}

main().catch((err) => {
  console.error('[rsa-smoke] FAILED:', err);
  process.exit(1);
});
