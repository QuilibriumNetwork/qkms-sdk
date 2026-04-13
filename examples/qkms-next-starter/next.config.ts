import type { NextConfig } from 'next';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const nextConfig: NextConfig = {
  // The qkms-sdk packages live in the pnpm workspace and ship compiled
  // dist/ output; we need Next to transpile them into its module graph so
  // we can also patch the `node:*` imports in their dynamic loaders.
  transpilePackages: [
    '@quilibrium/qkms-sdk-core',
    '@quilibrium/qkms-sdk-react',
  ],

  webpack: (config, { isServer, webpack }) => {
    // qkms-sdk-core's FilesystemStorage and @quilibrium/mpc-wasm/loader.js
    // both have runtime-gated dynamic imports to `node:fs/promises`,
    // `node:path`, and `node:url` that only execute under Node. Webpack 5
    // follows them statically and errors with "UnhandledSchemeError" on
    // the client bundle because it doesn't know how to resolve the `node:`
    // URI scheme outside of `target: 'node'` builds.
    //
    // `resolve.fallback` only handles bare module names, not URI-prefixed
    // imports. The right tool is `NormalModuleReplacementPlugin`, which
    // lets us intercept any request matching `/^node:/` and redirect it
    // at bundle time to an empty stub. Since the code paths that would
    // reach these imports are gated behind `typeof window` checks and
    // never execute in the browser, pointing at an empty module is safe.
    if (!isServer) {
      config.plugins = config.plugins ?? [];
      config.plugins.push(
        new webpack.NormalModuleReplacementPlugin(/^node:/, (resource: { request: string }) => {
          resource.request = path.resolve(__dirname, 'empty-module.js');
        }),
      );
    }
    return config;
  },
};

export default nextConfig;
