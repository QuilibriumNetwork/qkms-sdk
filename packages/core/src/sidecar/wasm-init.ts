// Initializes all wasm-bindgen modules before they're used.
//
// wasm-bindgen (--target web) outputs modules that require an explicit
// init() call with the .wasm binary before any exports work. In Node,
// this sometimes auto-resolves, but in browsers (especially Vite dev
// mode) it never does — the `wasm` internal variable stays undefined
// until init() is called.
//
// This module provides a single `initAllWasm()` that initializes every
// wasm-bindgen crate the sidecar depends on. It's idempotent — safe
// to call multiple times.

let initialized = false;

export async function initAllWasm(): Promise<void> {
  if (initialized) return;

  // Dynamic imports so we can call the default export (init function)
  // without triggering top-level wasm access.
  try {
    const channelwasm = await import('channelwasm');
    if (typeof channelwasm.default === 'function') {
      await channelwasm.default();
    }
  } catch {
    // Already initialized or not available in this environment
  }

  try {
    const dkls23wasm = await import('dkls23wasm');
    if (typeof dkls23wasm.default === 'function') {
      await dkls23wasm.default();
    }
  } catch {
    // Already initialized or not available in this environment
  }

  try {
    const bls48581wasm = await import('bls48581wasm');
    if (typeof bls48581wasm.default === 'function') {
      await bls48581wasm.default();
    }
  } catch {
    // Already initialized or not available in this environment
  }

  try {
    const bulletproofswasm = await import('bulletproofswasm');
    if (typeof bulletproofswasm.default === 'function') {
      await bulletproofswasm.default();
    }
  } catch {
    // Already initialized or not available in this environment
  }

  initialized = true;
}
