// Chain-specific address derivation. QKMS GetPublicKey returns the raw
// secp256k1/ed25519/etc. public key bytes; this module turns those bytes
// into the canonical address format for each supported chain.
//
// We deliberately keep this in the SDK (not QKMS) so adding chain support
// doesn't require server changes.

import { base58, bech32 } from '@scure/base';
import { keccak_256 } from '@noble/hashes/sha3';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 } from '@noble/hashes/sha256';
import { secp256k1 } from '@noble/curves/secp256k1';
import { blake2b } from '@noble/hashes/blake2b';

/** Lowercase hex string with `0x` prefix. */
export type Hex0x = `0x${string}`;

/**
 * Check if bytes look like DER-encoded SubjectPublicKeyInfo.
 * Validates: starts with 0x30 (SEQUENCE), contains inner 0x30 (algorithm
 * SEQUENCE), and total length is consistent. This avoids false positives
 * where a raw key happens to start with 0x30.
 */
function isDEREncoded(data: Uint8Array): boolean {
  if (data.length < 10 || data[0] !== 0x30) return false;
  // Read outer SEQUENCE length
  let offset = 1;
  let outerLen: number;
  if (data[offset]! & 0x80) {
    const lenBytes = data[offset]! & 0x7f;
    if (lenBytes > 2 || offset + lenBytes >= data.length) return false;
    outerLen = 0;
    for (let i = 0; i < lenBytes; i++) outerLen = (outerLen << 8) | data[offset + 1 + i]!;
    offset += 1 + lenBytes;
  } else {
    outerLen = data[offset]!;
    offset += 1;
  }
  // Total length should match
  if (offset + outerLen !== data.length) return false;
  // Must have inner SEQUENCE at this position
  return data[offset] === 0x30;
}

/**
 * Extract the raw public key bytes from a DER-encoded SubjectPublicKeyInfo.
 * DER structure: SEQUENCE { SEQUENCE { OID, ... }, BIT STRING { 0x00, raw_key } }
 */
function extractRawKeyFromDER(der: Uint8Array): Uint8Array {
  let offset = 0;
  // Outer SEQUENCE
  offset += 1;
  offset += der[offset]! & 0x80 ? (der[offset]! & 0x7f) + 1 : 1;

  // Inner SEQUENCE (algorithm identifier) — skip entirely
  offset += 1;
  const innerLen = der[offset]!;
  offset += 1 + innerLen;

  // BIT STRING
  if (der[offset] !== 0x03) throw new Error('DER: expected BIT STRING');
  offset += 1;
  const bitStringLen = der[offset]!;
  offset += 1;
  // Skip the "unused bits" byte (always 0x00 for EC keys)
  if (der[offset] !== 0x00) throw new Error('DER: expected 0x00 unused bits');
  offset += 1;

  return der.subarray(offset, offset + bitStringLen - 1);
}

function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i]!.toString(16).padStart(2, '0');
  return s;
}

/**
 * Derive an EVM (Ethereum) address from a secp256k1 public key.
 *
 * Accepts:
 *   - 33-byte compressed (`02|03 || x`)
 *   - 64-byte uncompressed without prefix (`x || y`)
 *   - 65-byte uncompressed with prefix (`04 || x || y`)
 *
 * Returns the lowercase hex EIP-55 representation (without checksum casing).
 */
export function evmAddressFromPublicKey(publicKey: Uint8Array): Hex0x {
  // Strip DER envelope if present (starts with 0x30 = SEQUENCE)
  if (publicKey[0] === 0x30) {
    publicKey = extractRawKeyFromDER(publicKey);
  }

  let uncompressed: Uint8Array;
  if (publicKey.length === 65 && publicKey[0] === 0x04) {
    uncompressed = publicKey;
  } else if (publicKey.length === 64) {
    uncompressed = new Uint8Array(65);
    uncompressed[0] = 0x04;
    uncompressed.set(publicKey, 1);
  } else if (publicKey.length === 33 && (publicKey[0] === 0x02 || publicKey[0] === 0x03)) {
    // Decompress
    const point = secp256k1.ProjectivePoint.fromHex(publicKey);
    uncompressed = point.toRawBytes(false);
  } else {
    throw new Error(
      `evmAddressFromPublicKey: unexpected public key length ${publicKey.length} (prefix ${publicKey[0]?.toString(16)})`,
    );
  }

  // Drop the 0x04 prefix, keccak256 the (x || y) bytes, take last 20.
  const xy = uncompressed.subarray(1);
  const hash = keccak_256(xy);
  const addr = hash.subarray(hash.length - 20);
  return ('0x' + bytesToHex(addr)) as Hex0x;
}

/**
 * Apply EIP-55 checksum casing to a 20-byte hex EVM address.
 * Input must be lowercase `0x` + 40 hex chars; output is the same string
 * with mixed-case representing the checksum.
 */
export function toChecksumAddress(address: string): Hex0x {
  if (!/^0x[0-9a-f]{40}$/.test(address)) {
    throw new Error(`toChecksumAddress: invalid input ${address}`);
  }
  const lower = address.slice(2);
  const hashHex = bytesToHex(keccak_256(new TextEncoder().encode(lower)));
  let out = '0x';
  for (let i = 0; i < lower.length; i++) {
    const ch = lower[i]!;
    if (/[0-9]/.test(ch)) {
      out += ch;
    } else {
      out += parseInt(hashHex[i]!, 16) >= 8 ? ch.toUpperCase() : ch;
    }
  }
  return out as Hex0x;
}

/** Derive an EVM address from a public key, returning the EIP-55 checksum form. */
export function evmChecksumAddressFromPublicKey(publicKey: Uint8Array): Hex0x {
  return toChecksumAddress(evmAddressFromPublicKey(publicKey));
}

/**
 * Derive a Solana address from an Ed25519 public key. Solana addresses are
 * just the 32-byte public key encoded as base58 — there's no checksum or
 * prefix.
 */
export function solanaAddressFromPublicKey(publicKey: Uint8Array): string {
  if (isDEREncoded(publicKey)) publicKey = extractRawKeyFromDER(publicKey);
  if (publicKey.length !== 32) {
    throw new Error(
      `solanaAddressFromPublicKey: expected 32-byte Ed25519 public key, got ${publicKey.length}`,
    );
  }
  return base58.encode(publicKey);
}

/**
 * Derive a Cosmos address from a compressed secp256k1 public key.
 *
 * Cosmos address = bech32(prefix, RIPEMD160(SHA256(compressed_pubkey)))
 *
 * The prefix is chain-specific: "cosmos" for Cosmos Hub, "osmo" for
 * Osmosis, "juno" for Juno, etc.
 */
export function cosmosAddressFromPublicKey(
  publicKey: Uint8Array,
  prefix = 'cosmos',
): string {
  if (isDEREncoded(publicKey)) publicKey = extractRawKeyFromDER(publicKey);
  let compressed: Uint8Array;
  if (publicKey.length === 33 && (publicKey[0] === 0x02 || publicKey[0] === 0x03)) {
    compressed = publicKey;
  } else if (publicKey.length === 65 && publicKey[0] === 0x04) {
    const point = secp256k1.ProjectivePoint.fromHex(publicKey);
    compressed = point.toRawBytes(true);
  } else if (publicKey.length === 64) {
    const full = new Uint8Array(65);
    full[0] = 0x04;
    full.set(publicKey, 1);
    const point = secp256k1.ProjectivePoint.fromHex(full);
    compressed = point.toRawBytes(true);
  } else {
    throw new Error(
      `cosmosAddressFromPublicKey: unexpected public key length ${publicKey.length}`,
    );
  }

  // Cosmos address = RIPEMD160(SHA256(compressed_pubkey))
  const hash = ripemd160(sha256(compressed));
  // bech32 encoding with 5-bit words
  const words = bech32.toWords(hash);
  return bech32.encode(prefix, words);
}

/**
 * Derive a Sui address from an Ed25519 public key.
 *
 * Sui address = 0x + first 32 bytes of Blake2b-256(flag || pubkey)
 * where flag = 0x00 for Ed25519.
 */
export function suiAddressFromPublicKey(publicKey: Uint8Array): Hex0x {
  if (isDEREncoded(publicKey)) publicKey = extractRawKeyFromDER(publicKey);
  if (publicKey.length !== 32) {
    throw new Error(
      `suiAddressFromPublicKey: expected 32-byte Ed25519 public key, got ${publicKey.length}`,
    );
  }
  // Sui scheme: flag byte (0x00 = Ed25519) prepended before hashing
  const flaggedKey = new Uint8Array(33);
  flaggedKey[0] = 0x00; // Ed25519 flag
  flaggedKey.set(publicKey, 1);
  const hash = blake2b(flaggedKey, { dkLen: 32 });
  return ('0x' + bytesToHex(hash)) as Hex0x;
}

/**
 * Derive a Stellar address from an Ed25519 public key.
 *
 * Stellar uses a custom base32 encoding (StrKey) with a version byte
 * and CRC16 checksum. Public key addresses start with "G".
 */
export function stellarAddressFromPublicKey(publicKey: Uint8Array): string {
  if (isDEREncoded(publicKey)) publicKey = extractRawKeyFromDER(publicKey);
  if (publicKey.length !== 32) {
    throw new Error(
      `stellarAddressFromPublicKey: expected 32-byte Ed25519 public key, got ${publicKey.length}`,
    );
  }
  // Version byte for public key = 6 << 3 = 48 (0x30), which maps to 'G'
  const payload = new Uint8Array(35);
  payload[0] = 6 << 3; // version byte
  payload.set(publicKey, 1);
  // CRC16-XModem checksum over version + key
  const checksum = crc16xmodem(payload.subarray(0, 33));
  payload[33] = checksum & 0xff; // little-endian
  payload[34] = (checksum >> 8) & 0xff;
  return base32Encode(payload);
}

/** CRC16-XModem used by Stellar StrKey encoding. */
function crc16xmodem(data: Uint8Array): number {
  let crc = 0x0000;
  for (let i = 0; i < data.length; i++) {
    let code = (crc >>> 8) & 0xff;
    code ^= data[i]! & 0xff;
    code ^= code >>> 4;
    crc = ((crc << 8) & 0xffff) ^ (code << 12) ^ (code << 5) ^ code;
    crc &= 0xffff;
  }
  return crc;
}

/** RFC 4648 base32 encoding (no padding, uppercase). */
function base32Encode(data: Uint8Array): string {
  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let result = '';
  for (let i = 0; i < data.length; i++) {
    value = (value << 8) | data[i]!;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += ALPHABET[(value >>> bits) & 0x1f];
    }
  }
  if (bits > 0) {
    result += ALPHABET[(value << (5 - bits)) & 0x1f];
  }
  return result;
}
