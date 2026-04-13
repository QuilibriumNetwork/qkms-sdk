// Loader for mpc.wasm. Handles both browser and Node environments.
//
// Browser: imports wasm_exec.js as a side-effect script (it sets `Go` on
// globalThis). Then `WebAssembly.instantiateStreaming(fetch(wasmUrl), ...)`
// instantiates the Go runtime, which calls `js.Global().Set("mpcWasm", ...)`
// during main(). We resolve once that global is present.
//
// Node: same flow, but we read the .wasm file from disk and use
// `WebAssembly.instantiate` (no fetch).
//
// The loader is idempotent — repeat calls return the cached instance.

let cachedApi = null;
let inflight = null;

function findApi() {
  // Go's syscall/js writes to whatever globalThis points at. In ESM modules
  // and Web Workers, `globalThis` is the right reference; in CJS Node it's
  // `global`. Both are aliases under modern runtimes.
  return globalThis.mpcWasm;
}

async function ensureGoClass() {
  if (typeof globalThis.Go === 'function') return;

  if (typeof window !== 'undefined' || typeof self !== 'undefined') {
    // Browser / Web Worker — load via dynamic import of the script URL.
    const wasmExecUrl = new URL('./wasm_exec.js', import.meta.url).href;
    await import(/* @vite-ignore */ wasmExecUrl);
    if (typeof globalThis.Go !== 'function') {
      throw new Error('mpc-wasm: failed to load wasm_exec.js — globalThis.Go is undefined');
    }
    return;
  }

  // Node — read the file and eval it. wasm_exec.js is written as a global
  // script (not an ES module), so we can't dynamic-import it directly.
  const fs = await import('node:fs/promises');
  const url = await import('node:url');
  const here = url.fileURLToPath(new URL('.', import.meta.url));
  const path = await import('node:path');
  const wasmExecPath = path.join(here, 'wasm_exec.js');
  const wasmExecSrc = await fs.readFile(wasmExecPath, 'utf-8');
  // eslint-disable-next-line no-new-func
  new Function(wasmExecSrc).call(globalThis);
  if (typeof globalThis.Go !== 'function') {
    throw new Error('mpc-wasm: failed to evaluate wasm_exec.js in Node — globalThis.Go is undefined');
  }
}

async function loadWasmBytes(opts) {
  if (typeof window !== 'undefined' || typeof self !== 'undefined') {
    const url = opts?.wasmUrl ?? new URL('./mpc.wasm', import.meta.url).href;
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`mpc-wasm: failed to fetch ${url}: ${res.status}`);
    }
    return await res.arrayBuffer();
  }
  const fs = await import('node:fs/promises');
  const urlMod = await import('node:url');
  const path = await import('node:path');
  const here = urlMod.fileURLToPath(new URL('.', import.meta.url));
  const wasmPath = opts?.wasmPath ?? path.join(here, 'mpc.wasm');
  const buf = await fs.readFile(wasmPath);
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

export async function loadMpcWasm(opts) {
  if (cachedApi) return cachedApi;
  if (inflight) return inflight;

  inflight = (async () => {
    await ensureGoClass();

    const wasmBytes = await loadWasmBytes(opts);
    const go = new globalThis.Go();
    const result = await WebAssembly.instantiate(wasmBytes, go.importObject);

    // go.run() returns a Promise that resolves when main() returns. Our main
    // blocks on `select {}` so this never resolves — we don't await it.
    // Registered Funcs become valid synchronously after `js.Global().Set(...)`
    // executes during main, so we yield to the microtask queue once and
    // then check.
    //
    // We deliberately don't `await` go.run() — it would hang forever.
    void go.run(result.instance);

    // Wait for `globalThis.mpcWasm` to appear. Yield repeatedly until it
    // does or we time out.
    const deadline = Date.now() + 2000;
    while (Date.now() < deadline) {
      const api = findApi();
      if (api && api.ready) {
        cachedApi = api;
        inflight = null;
        return api;
      }
      await new Promise((r) => setTimeout(r, 1));
    }
    inflight = null;
    throw new Error('mpc-wasm: globalThis.mpcWasm did not appear within 2s after go.run()');
  })();

  return inflight;
}

// Backwards-compat alias so callers using the old name keep working.
export const loadFrostWasm = loadMpcWasm;
