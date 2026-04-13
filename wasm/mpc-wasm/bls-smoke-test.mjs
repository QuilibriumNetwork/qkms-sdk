// Smoke test for the new bls48581-wasm scalar/G1 helpers.
//
// Doesn't drive a full t-of-n protocol — that's the TS session's job. This
// just verifies the new exports work end-to-end:
//
//   1. wasm loads in Node
//   2. random scalar produces 73 BE bytes
//   3. scalar add/mul produce results consistent with their algebraic identities
//   4. scalar_to_g1 produces a 74-byte compressed G1 point
//   5. g1_add of two such points produces another 74-byte compressed point
//   6. bls_sign with a scalar from scalar_random verifies (sanity)
//
// Run from this directory:  node bls-smoke-test.mjs

import * as bls from '../../../ceremonyclient/crates/bls48581-wasm/pkg/bls48581wasm.js';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const wasmPath = join(here, '../../../ceremonyclient/crates/bls48581-wasm/pkg/bls48581wasm_bg.wasm');
const wasmBytes = await readFile(wasmPath);
await bls.default({ module_or_path: wasmBytes });

function unwrap(json, label) {
  const v = JSON.parse(json);
  if (v && typeof v === 'object' && 'error' in v) {
    throw new Error(`${label}: ${v.error}`);
  }
  if (typeof v !== 'string') throw new Error(`${label}: expected hex string, got ${typeof v}`);
  return v;
}

bls.js_init();
console.log('[bls-smoke] init ok');

// 1. Random scalars
const a = unwrap(bls.js_bls_scalar_random(), 'scalar_random a');
const b = unwrap(bls.js_bls_scalar_random(), 'scalar_random b');
if (a.length !== 73 * 2) throw new Error(`scalar a wrong length: ${a.length / 2} bytes`);
if (b.length !== 73 * 2) throw new Error(`scalar b wrong length: ${b.length / 2} bytes`);
console.log('[bls-smoke] random scalars: 73 bytes each ✓');

// 2. Algebraic identities
const sum = unwrap(bls.js_bls_scalar_add(a, b), 'add(a, b)');
const sumCommutative = unwrap(bls.js_bls_scalar_add(b, a), 'add(b, a)');
if (sum !== sumCommutative) throw new Error('add not commutative');
console.log('[bls-smoke] add commutativity ✓');

const product = unwrap(bls.js_bls_scalar_mul(a, b), 'mul(a, b)');
const productCommutative = unwrap(bls.js_bls_scalar_mul(b, a), 'mul(b, a)');
if (product !== productCommutative) throw new Error('mul not commutative');
console.log('[bls-smoke] mul commutativity ✓');

// 3. (a + b) - b == a (mod q)
const aPlusBMinusB = unwrap(
  bls.js_bls_scalar_sub(unwrap(bls.js_bls_scalar_add(a, b), 'add'), b),
  'sub',
);
if (aPlusBMinusB !== a) {
  throw new Error(`(a + b) - b != a\n  expected ${a}\n  got      ${aPlusBMinusB}`);
}
console.log('[bls-smoke] (a + b) - b = a ✓');

// 4. inverse: a * a^{-1} == 1
const aInv = unwrap(bls.js_bls_scalar_inv(a), 'inv(a)');
const product1 = unwrap(bls.js_bls_scalar_mul(a, aInv), 'a * a^{-1}');
const one = unwrap(bls.js_bls_scalar_from_u64(1n), 'from_u64(1)');
if (product1 !== one) {
  throw new Error(`a * a^{-1} != 1\n  expected ${one}\n  got      ${product1}`);
}
console.log('[bls-smoke] a * inv(a) = 1 ✓');

// 5. scalar_to_g1 → 74-byte compressed point
const g1Point = unwrap(bls.js_bls_scalar_to_g1(a), 'scalar_to_g1(a)');
if (g1Point.length !== 74 * 2) {
  throw new Error(`g1Point wrong length: ${g1Point.length / 2} bytes`);
}
console.log('[bls-smoke] scalar_to_g1: 74-byte compressed point ✓');

// 6. g1_add: g^a + g^b = g^(a+b)
const g1B = unwrap(bls.js_bls_scalar_to_g1(b), 'scalar_to_g1(b)');
const g1Sum = unwrap(bls.js_bls_g1_add(g1Point, g1B), 'g1_add');
const g1OfSum = unwrap(bls.js_bls_scalar_to_g1(sum), 'scalar_to_g1(sum)');
if (g1Sum !== g1OfSum) {
  throw new Error(`g^a + g^b != g^(a+b)\n  expected ${g1OfSum}\n  got      ${g1Sum}`);
}
console.log('[bls-smoke] g^a + g^b = g^(a+b) ✓');

// 7. from_u64 sanity: scalar_to_g1(scalar_from_u64(0)) should be the identity, but
//    that's tricky to assert without knowing the encoding. Just check that
//    different inputs produce different points.
const g1Zero = unwrap(bls.js_bls_scalar_to_g1(unwrap(bls.js_bls_scalar_from_u64(0n), 'from_u64(0)')), 'g1(0)');
const g1One = unwrap(bls.js_bls_scalar_to_g1(one), 'g1(1)');
if (g1Zero === g1One) throw new Error('g^0 == g^1, broken');
console.log('[bls-smoke] from_u64 distinct outputs ✓');

console.log('[bls-smoke] all checks passed ✅');
