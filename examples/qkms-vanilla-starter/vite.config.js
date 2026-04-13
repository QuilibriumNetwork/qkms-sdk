import { defineConfig } from 'vite';

export default defineConfig({
  optimizeDeps: {
    // wasm-pack outputs need to be excluded so the .wasm files are loaded
    // via fetch at runtime instead of pre-bundled.
    exclude: ['dkls23wasm', 'channelwasm', 'bls48581wasm', 'bulletproofswasm', '@quilibrium/mpc-wasm'],
  },
  worker: {
    // The Sidecar Worker from @quilibrium/qkms-sdk-core is spawned with
    // `{ type: 'module' }` and imports the core package + all wasm modules.
    // A multi-chunk worker requires ES-format output; the default IIFE
    // doesn't support code splitting.
    format: 'es',
  },
});
