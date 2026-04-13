// Empty stub used by next.config.ts to replace `node:*` imports in the
// client bundle. The qkms-sdk code that would reach for these modules
// (FilesystemStorage, mpc-wasm Node loader path) runs a `typeof window`
// check before calling them, so in the browser they're never invoked —
// webpack just needs a module to point at.
module.exports = {};
