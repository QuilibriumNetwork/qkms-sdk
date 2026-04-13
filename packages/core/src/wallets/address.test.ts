// Address derivation unit tests.
//
// Uses well-known test vectors from the Ethereum and Solana ecosystems
// to verify that public keys produce the correct chain addresses.
//
// Run:  npx tsx --test packages/core/src/wallets/address.test.ts

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  evmAddressFromPublicKey,
  evmChecksumAddressFromPublicKey,
  toChecksumAddress,
  solanaAddressFromPublicKey,
  cosmosAddressFromPublicKey,
  suiAddressFromPublicKey,
  stellarAddressFromPublicKey,
} from './address.js';

// ---- Helpers ----

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// ---- EVM address derivation ----

describe('evmAddressFromPublicKey', () => {
  // Well-known: private key 1 (secp256k1 generator point)
  // Address: 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf
  const privKey1 = hexToBytes(
    '0000000000000000000000000000000000000000000000000000000000000001',
  );
  const pubKey1Uncompressed = secp256k1.getPublicKey(privKey1, false);
  const pubKey1Compressed = secp256k1.getPublicKey(privKey1, true);
  const expectedAddr1 = '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf';

  // Well-known: private key 2
  // Address: 0x2b5ad5c4795c026514f8317c7a215e218dccd6cf
  const privKey2 = hexToBytes(
    '0000000000000000000000000000000000000000000000000000000000000002',
  );
  const pubKey2Uncompressed = secp256k1.getPublicKey(privKey2, false);
  const expectedAddr2 = '0x2b5ad5c4795c026514f8317c7a215e218dccd6cf';

  it('derives correct address from 65-byte uncompressed key (privkey 1)', () => {
    assert.equal(pubKey1Uncompressed.length, 65);
    assert.equal(pubKey1Uncompressed[0], 0x04);
    const addr = evmAddressFromPublicKey(pubKey1Uncompressed);
    assert.equal(addr, expectedAddr1);
  });

  it('derives correct address from 64-byte uncompressed key (no prefix)', () => {
    const addr = evmAddressFromPublicKey(pubKey1Uncompressed.subarray(1));
    assert.equal(addr, expectedAddr1);
  });

  it('derives correct address from 33-byte compressed key', () => {
    assert.equal(pubKey1Compressed.length, 33);
    const addr = evmAddressFromPublicKey(pubKey1Compressed);
    assert.equal(addr, expectedAddr1);
  });

  it('derives correct address for private key 2', () => {
    const addr = evmAddressFromPublicKey(pubKey2Uncompressed);
    assert.equal(addr, expectedAddr2);
  });

  it('compressed and uncompressed produce the same address', () => {
    const addrU = evmAddressFromPublicKey(pubKey1Uncompressed);
    const addrC = evmAddressFromPublicKey(pubKey1Compressed);
    assert.equal(addrU, addrC);
  });

  it('throws on invalid key length', () => {
    assert.throws(
      () => evmAddressFromPublicKey(new Uint8Array(32)),
      /unexpected public key length 32/,
    );
  });

  it('throws on 33-byte key with wrong prefix', () => {
    const bad = new Uint8Array(33);
    bad[0] = 0x05; // not 02 or 03
    assert.throws(
      () => evmAddressFromPublicKey(bad),
      /unexpected public key length 33/,
    );
  });
});

// ---- EIP-55 checksum ----

describe('toChecksumAddress', () => {
  // Test vectors from EIP-55: https://eips.ethereum.org/EIPS/eip-55
  const eip55Vectors = [
    // All caps
    '0x52908400098527886E0F7030069857D2E4169EE7',
    '0x8617E340B3D01FA5F11F306F4090FD50E238070D',
    // All lower
    '0xde709f2102306220921060314715629080e2fb77',
    '0x27b1fdb04752bbc536007a920d24acb045561c26',
    // Normal
    '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
    '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
    '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
    '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
  ];

  for (const expected of eip55Vectors) {
    it(`produces correct checksum for ${expected}`, () => {
      const result = toChecksumAddress(expected.toLowerCase() as `0x${string}`);
      assert.equal(result, expected);
    });
  }

  it('throws on invalid input', () => {
    assert.throws(() => toChecksumAddress('not-an-address'), /invalid input/);
    assert.throws(() => toChecksumAddress('0xABCD'), /invalid input/);
  });
});

describe('evmChecksumAddressFromPublicKey', () => {
  it('produces checksummed address from public key', () => {
    const privKey1 = hexToBytes(
      '0000000000000000000000000000000000000000000000000000000000000001',
    );
    const pubKey = secp256k1.getPublicKey(privKey1, false);
    const addr = evmChecksumAddressFromPublicKey(pubKey);
    // EIP-55 checksum of 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf
    assert.equal(addr, '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf');
  });
});

// ---- Solana address derivation ----

describe('solanaAddressFromPublicKey', () => {
  it('encodes a 32-byte Ed25519 key as base58', () => {
    // System program: all zeros
    const pubKey = new Uint8Array(32);
    const addr = solanaAddressFromPublicKey(pubKey);
    assert.equal(addr, '11111111111111111111111111111111');
  });

  it('encodes a known public key correctly', () => {
    // Token program: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
    const tokenProgramBytes = hexToBytes(
      '06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9',
    );
    const addr = solanaAddressFromPublicKey(tokenProgramBytes);
    assert.equal(addr, 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
  });

  it('throws on invalid key length', () => {
    assert.throws(
      () => solanaAddressFromPublicKey(new Uint8Array(33)),
      /expected 32-byte/,
    );
    assert.throws(
      () => solanaAddressFromPublicKey(new Uint8Array(20)),
      /expected 32-byte/,
    );
  });
});

// ---- Cosmos address derivation ----

describe('cosmosAddressFromPublicKey', () => {
  it('derives correct bech32 address from compressed secp256k1 key', () => {
    // Well-known: private key 1 → cosmos address
    const compressed = secp256k1.getPublicKey(
      hexToBytes('0000000000000000000000000000000000000000000000000000000000000001'),
      true,
    );
    const addr = cosmosAddressFromPublicKey(compressed);
    // cosmos prefix + RIPEMD160(SHA256(compressed_pubkey))
    assert.ok(addr.startsWith('cosmos1'), `Expected cosmos1 prefix, got ${addr}`);
    assert.equal(addr.length, 45); // bech32 cosmos address is 45 chars
  });

  it('accepts uncompressed 65-byte key', () => {
    const uncompressed = secp256k1.getPublicKey(
      hexToBytes('0000000000000000000000000000000000000000000000000000000000000001'),
      false,
    );
    const compressed = secp256k1.getPublicKey(
      hexToBytes('0000000000000000000000000000000000000000000000000000000000000001'),
      true,
    );
    // Both forms should produce the same address
    assert.equal(
      cosmosAddressFromPublicKey(uncompressed),
      cosmosAddressFromPublicKey(compressed),
    );
  });

  it('uses custom prefix', () => {
    const compressed = secp256k1.getPublicKey(
      hexToBytes('0000000000000000000000000000000000000000000000000000000000000001'),
      true,
    );
    const osmoAddr = cosmosAddressFromPublicKey(compressed, 'osmo');
    assert.ok(osmoAddr.startsWith('osmo1'));
    const junoAddr = cosmosAddressFromPublicKey(compressed, 'juno');
    assert.ok(junoAddr.startsWith('juno1'));
  });

  it('throws on invalid key length', () => {
    assert.throws(
      () => cosmosAddressFromPublicKey(new Uint8Array(32)),
      /unexpected public key length/,
    );
  });
});

// ---- Sui address derivation ----

describe('suiAddressFromPublicKey', () => {
  it('derives a 0x-prefixed 64-char hex address', () => {
    const pubKey = new Uint8Array(32); // all zeros
    const addr = suiAddressFromPublicKey(pubKey);
    assert.ok(addr.startsWith('0x'));
    assert.equal(addr.length, 66); // 0x + 64 hex chars
  });

  it('produces deterministic output', () => {
    const pubKey = hexToBytes(
      '06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9',
    );
    const addr1 = suiAddressFromPublicKey(pubKey);
    const addr2 = suiAddressFromPublicKey(pubKey);
    assert.equal(addr1, addr2);
  });

  it('throws on invalid key length', () => {
    assert.throws(
      () => suiAddressFromPublicKey(new Uint8Array(33)),
      /expected 32-byte/,
    );
  });
});

// ---- Stellar address derivation ----

describe('stellarAddressFromPublicKey', () => {
  it('produces a G-prefixed address of length 56', () => {
    const pubKey = new Uint8Array(32); // all zeros
    const addr = stellarAddressFromPublicKey(pubKey);
    assert.ok(addr.startsWith('G'), `Expected G prefix, got ${addr[0]}`);
    assert.equal(addr.length, 56);
  });

  it('produces deterministic output', () => {
    const pubKey = hexToBytes(
      '06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9',
    );
    const addr1 = stellarAddressFromPublicKey(pubKey);
    const addr2 = stellarAddressFromPublicKey(pubKey);
    assert.equal(addr1, addr2);
  });

  it('throws on invalid key length', () => {
    assert.throws(
      () => stellarAddressFromPublicKey(new Uint8Array(33)),
      /expected 32-byte/,
    );
  });
});
