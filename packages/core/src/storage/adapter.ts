// StorageAdapter — pluggable persistence for the sidecar.
//
// The qkms-sdk sidecar needs to persist three categories of state:
//
//   1. The sidecar identity (X448 + Ed448 keypairs + signed pre-key signature)
//      under the key `identity`. Generated once on first run, then reused.
//
//   2. Key shares produced by DKG, one per key id, under the key
//      `keyshare/{keyId}`. These are the sensitive bytes — losing them means
//      losing access to the wallet.
//
//   3. Wallet records (chain type, address, key id, created-at) under the
//      key `wallet/{address}`, so the SDK can list wallets without an extra
//      QKMS round-trip.
//
// All values are byte buffers so the adapter is encoding-agnostic. JSON or
// hex serialization happens at the call site.
//
// Implementations:
//   - `IndexedDbStorage`  — browser, persists across page loads
//   - `FilesystemStorage` — Node, mirrors qkms/cmd/mpc-sidecar layout
//   - `MemoryStorage`     — in-memory, for tests

export interface StorageAdapter {
  /** Returns the value for `key`, or `null` if not present. */
  get(key: string): Promise<Uint8Array | null>;
  /** Stores `value` under `key`, overwriting any prior value. */
  put(key: string, value: Uint8Array): Promise<void>;
  /** Removes `key`. No-op if absent. */
  delete(key: string): Promise<void>;
  /** Lists all keys with the given prefix. */
  list(prefix: string): Promise<string[]>;
}
