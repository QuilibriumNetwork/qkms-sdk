import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  optimizeDeps: {
    // wasm-pack outputs need to be excluded from optimization so the .wasm
    // files are loaded via fetch at runtime instead of pre-bundled.
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
