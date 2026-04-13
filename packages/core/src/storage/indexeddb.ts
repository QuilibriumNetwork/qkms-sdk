import { openDB, type IDBPDatabase } from 'idb';
import type { StorageAdapter } from './adapter.js';

const DB_VERSION = 1;
const STORE_NAME = 'qkms-sidecar';

/**
 * IndexedDB-backed storage for the browser. Uses a single object store
 * keyed by string with Uint8Array values. Persists across page reloads
 * and tab restarts (subject to browser storage eviction policy).
 */
export class IndexedDbStorage implements StorageAdapter {
  private readonly dbName: string;
  private dbPromise: Promise<IDBPDatabase> | null = null;

  constructor(dbName = 'qkms-sdk') {
    this.dbName = dbName;
  }

  private getDb(): Promise<IDBPDatabase> {
    if (!this.dbPromise) {
      this.dbPromise = openDB(this.dbName, DB_VERSION, {
        upgrade(db) {
          if (!db.objectStoreNames.contains(STORE_NAME)) {
            db.createObjectStore(STORE_NAME);
          }
        },
      });
    }
    return this.dbPromise;
  }

  async get(key: string): Promise<Uint8Array | null> {
    const db = await this.getDb();
    const value = await db.get(STORE_NAME, key);
    if (value == null) return null;
    if (value instanceof Uint8Array) return value;
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    throw new Error(`Unexpected stored type for key ${key}: ${typeof value}`);
  }

  async put(key: string, value: Uint8Array): Promise<void> {
    const db = await this.getDb();
    await db.put(STORE_NAME, value, key);
  }

  async delete(key: string): Promise<void> {
    const db = await this.getDb();
    await db.delete(STORE_NAME, key);
  }

  async list(prefix: string): Promise<string[]> {
    const db = await this.getDb();
    const keys = await db.getAllKeys(STORE_NAME);
    return keys
      .filter((k): k is string => typeof k === 'string')
      .filter((k) => k.startsWith(prefix));
  }
}
