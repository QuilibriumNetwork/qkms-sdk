import type { StorageAdapter } from './adapter.js';

/**
 * Filesystem-backed storage for Node. Mirrors the layout of
 * qkms/cmd/mpc-sidecar: each key becomes a file under the configured
 * directory, with `/` in the key path translated to subdirectory boundaries.
 *
 * This file uses dynamic imports for `node:fs/promises` and `node:path` so
 * it can be type-checked in environments where the @types/node bundler
 * resolution is shaky. The runtime require is gated — calling any method
 * in a browser environment will throw immediately.
 */
export class FilesystemStorage implements StorageAdapter {
  private readonly dir: string;
  private fsModule: typeof import('node:fs/promises') | null = null;
  private pathModule: typeof import('node:path') | null = null;

  constructor(dir: string) {
    this.dir = dir;
  }

  private async getFs(): Promise<typeof import('node:fs/promises')> {
    if (!this.fsModule) {
      this.fsModule = await import('node:fs/promises');
    }
    return this.fsModule;
  }

  private async getPath(): Promise<typeof import('node:path')> {
    if (!this.pathModule) {
      this.pathModule = await import('node:path');
    }
    return this.pathModule;
  }

  private async resolvePath(key: string): Promise<string> {
    const path = await this.getPath();
    // Sanitize: keys can contain `/` (e.g. "keyshare/abc-123"); these become
    // subdirectories. Reject `..` segments to keep things contained.
    if (key.includes('..')) {
      throw new Error(`Invalid storage key: ${key}`);
    }
    return path.join(this.dir, key);
  }

  async get(key: string): Promise<Uint8Array | null> {
    const fs = await this.getFs();
    const fullPath = await this.resolvePath(key);
    try {
      const buf = await fs.readFile(fullPath);
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw e;
    }
  }

  async put(key: string, value: Uint8Array): Promise<void> {
    const fs = await this.getFs();
    const path = await this.getPath();
    const fullPath = await this.resolvePath(key);
    await fs.mkdir(path.dirname(fullPath), { recursive: true });
    await fs.writeFile(fullPath, value);
  }

  async delete(key: string): Promise<void> {
    const fs = await this.getFs();
    const fullPath = await this.resolvePath(key);
    try {
      await fs.unlink(fullPath);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
    }
  }

  async list(prefix: string): Promise<string[]> {
    const fs = await this.getFs();
    const path = await this.getPath();
    const out: string[] = [];

    // Walk the entire dir, return entries whose relative key starts with prefix.
    type DirEntry = { name: string; isDirectory(): boolean; isFile(): boolean };
    const walk = async (cur: string, relBase: string): Promise<void> => {
      let entries: DirEntry[];
      try {
        entries = (await fs.readdir(cur, { withFileTypes: true })) as unknown as DirEntry[];
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === 'ENOENT') return;
        throw e;
      }
      for (const entry of entries) {
        const childPath = path.join(cur, entry.name);
        const childKey = relBase ? `${relBase}/${entry.name}` : entry.name;
        if (entry.isDirectory()) {
          await walk(childPath, childKey);
        } else if (entry.isFile() && childKey.startsWith(prefix)) {
          out.push(childKey);
        }
      }
    };

    await walk(this.dir, '');
    return out;
  }
}
