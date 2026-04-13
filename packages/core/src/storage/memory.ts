import type { StorageAdapter } from './adapter.js';

/** In-memory storage adapter. Resets on every construction — for tests only. */
export class MemoryStorage implements StorageAdapter {
  private readonly store = new Map<string, Uint8Array>();

  async get(key: string): Promise<Uint8Array | null> {
    const v = this.store.get(key);
    return v ? new Uint8Array(v) : null;
  }

  async put(key: string, value: Uint8Array): Promise<void> {
    this.store.set(key, new Uint8Array(value));
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async list(prefix: string): Promise<string[]> {
    const out: string[] = [];
    for (const k of this.store.keys()) {
      if (k.startsWith(prefix)) out.push(k);
    }
    return out;
  }
}
