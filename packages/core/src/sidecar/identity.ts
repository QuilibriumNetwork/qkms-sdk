// Sidecar identity: X448 (encryption) + Ed448 (signing) + signed pre-key.
//
// This mirrors the identity setup in qkms/cmd/mpc-sidecar/main.go
// LoadOrCreateIdentity (~lines 323-448) but uses the channel-wasm primitives
// instead of the Go FFI bindings. We persist all keys via the StorageAdapter
// so the same identity is used across browser/Node restarts.
//
// channel-wasm convention: js_generate_x448 / js_generate_ed448 return a JSON
// object {"public_key":[u8...], "private_key":[u8...]}. Other functions
// (js_sign_ed448, js_get_pubkey_*) take base64-encoded byte strings and
// return either bare base64 strings or base64-quoted JSON-style strings.

import * as channelwasm from 'channelwasm';
import type { SidecarIdentity } from '../types.js';
import type { StorageAdapter } from '../storage/adapter.js';

const IDENTITY_KEY = 'identity';

/** Convert a JSON byte-array (`[1,2,3,...]`) to a Uint8Array. */
function jsonBytesToUint8(arr: number[]): Uint8Array {
  return Uint8Array.from(arr);
}

/** Convert a Uint8Array to lowercase hex. */
function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i]!.toString(16).padStart(2, '0');
  return s;
}

/** Convert lowercase hex to a Uint8Array. */
function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error(`hex string has odd length: ${hex.length}`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Convert a Uint8Array to base64. */
function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s);
}

/** Decode a base64 string into bytes. */
function base64ToBytes(b64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(b64, 'base64'));
  }
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Strip a JSON-quoted string the channel-wasm helpers sometimes return,
 * e.g. `"\"base64data\""` → `base64data`. The crate sometimes returns a
 * raw base64 wrapped in JSON quotes (so callers can parse it as JSON).
 */
function unwrapJsonString(s: string): string {
  const t = s.trim();
  if (t.startsWith('"') && t.endsWith('"')) {
    return t.slice(1, -1);
  }
  return t;
}

interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

function parseKeyPair(json: string): KeyPair {
  const obj = JSON.parse(json) as { public_key?: number[]; private_key?: number[] };
  if (!obj.public_key || !obj.private_key) {
    throw new Error(`channel-wasm returned unexpected key pair shape: ${json}`);
  }
  return {
    publicKey: jsonBytesToUint8(obj.public_key),
    privateKey: jsonBytesToUint8(obj.private_key),
  };
}

/**
 * Sign `message` with an Ed448 private key.
 * channel-wasm convention: both args are base64-encoded; returned signature
 * is a JSON-quoted base64 string. The wasm crate is forgiving about quoting.
 */
function signEd448(privateKey: Uint8Array, message: Uint8Array): Uint8Array {
  const result = channelwasm.js_sign_ed448(bytesToBase64(privateKey), bytesToBase64(message));
  // Some channel-wasm builds return the bare base64; others return a JSON
  // quoted string. We tolerate both. If the result starts with `{` it's an
  // error object — surface that.
  const trimmed = result.trim();
  if (trimmed.startsWith('{')) {
    throw new Error(`channel-wasm js_sign_ed448 error: ${trimmed}`);
  }
  return base64ToBytes(unwrapJsonString(trimmed));
}

/** Compute SHA-256 of `data` and return the first 16 bytes as lowercase hex. */
async function sidecarIdFromX448PublicKey(pub: Uint8Array): Promise<string> {
  const subtle = (globalThis as { crypto?: Crypto }).crypto?.subtle;
  if (!subtle) {
    throw new Error('Web Crypto API (crypto.subtle) is not available');
  }
  const digest = await subtle.digest('SHA-256', pub as BufferSource);
  return bytesToHex(new Uint8Array(digest).slice(0, 16));
}

/** Generates a fresh sidecar identity. Use loadOrCreate to persist across restarts. */
export async function generateIdentity(): Promise<SidecarIdentity> {
  const x448Identity = parseKeyPair(channelwasm.js_generate_x448());
  const x448SignedPreKey = parseKeyPair(channelwasm.js_generate_x448());
  const ed448Signing = parseKeyPair(channelwasm.js_generate_ed448());

  const preKeySignature = signEd448(ed448Signing.privateKey, x448SignedPreKey.publicKey);
  const sidecarId = await sidecarIdFromX448PublicKey(x448Identity.publicKey);

  return {
    sidecarId,
    identityPrivateX448: bytesToHex(x448Identity.privateKey),
    identityPublicX448: bytesToHex(x448Identity.publicKey),
    signedPreKeyPrivateX448: bytesToHex(x448SignedPreKey.privateKey),
    signedPreKeyPublicX448: bytesToHex(x448SignedPreKey.publicKey),
    signingPrivateEd448: bytesToHex(ed448Signing.privateKey),
    signingPublicEd448: bytesToHex(ed448Signing.publicKey),
    preKeySignature: bytesToHex(preKeySignature),
  };
}

/**
 * Loads an existing identity from storage, or generates and persists one
 * if none exists. Mirrors LoadOrCreateIdentity in main.go.
 */
export async function loadOrCreateIdentity(storage: StorageAdapter): Promise<SidecarIdentity> {
  const existing = await storage.get(IDENTITY_KEY);
  if (existing) {
    const text = new TextDecoder().decode(existing);
    return JSON.parse(text) as SidecarIdentity;
  }
  const identity = await generateIdentity();
  await storage.put(IDENTITY_KEY, new TextEncoder().encode(JSON.stringify(identity)));
  return identity;
}

/** Helper for callers that need the raw byte arrays for the channel-wasm primitives. */
export function identityKeysAsBytes(id: SidecarIdentity): {
  identityPrivateX448: Uint8Array;
  identityPublicX448: Uint8Array;
  signedPreKeyPrivateX448: Uint8Array;
  signedPreKeyPublicX448: Uint8Array;
  signingPrivateEd448: Uint8Array;
  signingPublicEd448: Uint8Array;
  preKeySignature: Uint8Array;
} {
  return {
    identityPrivateX448: hexToBytes(id.identityPrivateX448),
    identityPublicX448: hexToBytes(id.identityPublicX448),
    signedPreKeyPrivateX448: hexToBytes(id.signedPreKeyPrivateX448),
    signedPreKeyPublicX448: hexToBytes(id.signedPreKeyPublicX448),
    signingPrivateEd448: hexToBytes(id.signingPrivateEd448),
    signingPublicEd448: hexToBytes(id.signingPublicEd448),
    preKeySignature: hexToBytes(id.preKeySignature),
  };
}
