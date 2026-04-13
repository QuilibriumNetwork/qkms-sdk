// LocalStorage class — wraps window.localStorage with a key prefix.
//
// Under the hood we also provide an internal bridge so the underlying
// Sidecar (which wants a `StorageAdapter` with get/put/delete/list) can use
// whatever backend the app passes here.

import type { StorageAdapter } from '@quilibrium/qkms-sdk-core';

/** Sync storage interface over string values. */
export interface QkmsVanillaStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
  /** Optional: list all keys. Used by the underlying sidecar adapter. */
  keys?(): string[];
}

/** Wrapper around window.localStorage with key-prefix support. */
export class LocalStorage implements QkmsVanillaStorage {
  private readonly prefix: string;

  constructor(opts: { prefix?: string } = {}) {
    this.prefix = opts.prefix ?? 'qkms:';
  }

  private fullKey(key: string): string {
    return this.prefix + key;
  }

  getItem(key: string): string | null {
    if (typeof localStorage === 'undefined') return null;
    return localStorage.getItem(this.fullKey(key));
  }

  setItem(key: string, value: string): void {
    if (typeof localStorage === 'undefined') return;
    localStorage.setItem(this.fullKey(key), value);
  }

  removeItem(key: string): void {
    if (typeof localStorage === 'undefined') return;
    localStorage.removeItem(this.fullKey(key));
  }

  keys(): string[] {
    if (typeof localStorage === 'undefined') return [];
    const out: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith(this.prefix)) {
        out.push(k.slice(this.prefix.length));
      }
    }
    return out;
  }
}

/**
 * Adapts a QkmsVanillaStorage (sync string API) to the `StorageAdapter`
 * interface the core Sidecar expects (async Uint8Array). Bytes are
 * base64-encoded so they round-trip through localStorage cleanly.
 */
export class VanillaStorageAdapter implements StorageAdapter {
  constructor(private readonly inner: QkmsVanillaStorage) {}

  async get(key: string): Promise<Uint8Array | null> {
    const s = this.inner.getItem(key);
    if (s == null) return null;
    return base64ToBytes(s);
  }

  async put(key: string, value: Uint8Array): Promise<void> {
    this.inner.setItem(key, bytesToBase64(value));
  }

  async delete(key: string): Promise<void> {
    this.inner.removeItem(key);
  }

  async list(prefix: string): Promise<string[]> {
    const keys = this.inner.keys?.() ?? [];
    return keys.filter((k) => k.startsWith(prefix));
  }
}

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
