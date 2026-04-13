# QKMS SDK

Embedded wallet SDK backed by [QKMS](https://quilibrium.com) threshold MPC key management. Create and manage wallets across multiple chains using distributed key generation — no single party ever holds the full private key.

## Packages

| Package | Description |
|---|---|
| `@quilibrium/qkms-sdk-core` | Core engine: SigV4 RPC client, MPC sidecar, storage adapters, wallet providers |
| `@quilibrium/qkms-sdk-react` | React provider and hooks for browser apps |
| `@quilibrium/qkms-sdk-react/solana` | Solana-specific hooks |
| `@quilibrium/qkms-sdk-react/extended-chains` | Cosmos, Sui, Stellar wallet creation |
| `@quilibrium/qkms-sdk-node` | Server-side SDK for Node.js backends |
| `@quilibrium/qkms-sdk` | Vanilla JS SDK (no framework dependency) |

## Supported Key Types

| Key Type | Protocol | Chain | Address Format |
|---|---|---|---|
| secp256k1 (ECDSA) | DKLs23 | Ethereum, Cosmos | EIP-55 checksum, bech32 |
| Ed25519 (EdDSA) | FROST | Solana, Sui, Stellar | base58, Blake2b hex, StrKey |
| BLS12-381 | Feldman VSS | — | Raw public key |
| BLS48-581 | Feldman VSS | — | Raw public key |
| Decaf448 | Threshold Schnorr | — | Raw public key |
| Ed448 | FROST | — | Raw public key |
| RSA (2048/3072/4096) | Shoup threshold / Paillier DKG | — | DER-encoded |

## Quick Start (React)

```bash
npm install @quilibrium/qkms-sdk-react
```

```tsx
import {
  QkmsProvider,
  useQkms,
  useWallets,
  useCreateWallet,
  useSignMessage,
} from '@quilibrium/qkms-sdk-react';

function App() {
  return (
    <QkmsProvider
      appId="your-qnzm-account-id"
      config={{
        qkmsServer: 'https://qkms.quilibrium.com',
        qnzmServer: 'https://qnzm.quilibrium.com',
        clientKey: 'qnzm_ck_...',
      }}
    >
      <WalletDemo />
    </QkmsProvider>
  );
}

function WalletDemo() {
  const { login, logout, authenticated, user } = useQkms();
  const { wallets } = useWallets();
  const { createWallet } = useCreateWallet();
  const { signMessage } = useSignMessage();

  if (!authenticated) {
    return (
      <button onClick={() => login({ email: 'user@example.com' })}>
        Login
      </button>
    );
  }

  return (
    <div>
      <p>Logged in as {user?.id}</p>
      <button onClick={() => createWallet({ chainType: 'ethereum' })}>
        Create Ethereum Wallet
      </button>
      {wallets.map((w) => (
        <div key={w.keyId}>
          <code>{w.address}</code>
          <button
            onClick={async () => {
              const { signature } = await signMessage(
                { message: 'Hello' },
                { address: w.address },
              );
            }}
          >
            Sign
          </button>
        </div>
      ))}
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

## MPC Participant Configuration

The SDK supports flexible threshold MPC schemes. By default, keys are created as 2-of-2 between the QKMS server sidecar and the browser. You can configure different schemes via the `participants` and `threshold` config options.

### 2-of-2 with QKMS server sidecar (default)

```tsx
<QkmsProvider appId="..." config={{ qkmsServer: '...' }} />
```

No additional configuration needed. The server sidecar (`'service'`) holds one share, the browser holds the other.

### 2-of-2 between two browsers (no server sidecar)

```tsx
<QkmsProvider
  appId="..."
  config={{
    qkmsServer: '...',
    participants: [browserSidecarId1, browserSidecarId2],
  }}
/>
```

Both shares are held by browser clients. QKMS acts as a pure coordinator — it never sees the key material.

### 2-of-3 with server + two browsers

```tsx
<QkmsProvider
  appId="..."
  config={{
    qkmsServer: '...',
    participants: ['service', browserSidecarId1, browserSidecarId2],
    threshold: 2,
  }}
/>
```

Any 2 of the 3 participants can sign. The server sidecar provides availability; either browser can co-sign.

### 3-of-5

```tsx
<QkmsProvider
  appId="..."
  config={{
    qkmsServer: '...',
    participants: ['service', sidecar1, sidecar2, sidecar3, sidecar4],
    threshold: 3,
  }}
/>
```

The current browser's sidecar ID is automatically added to the participants list if not already present. Use `'service'` to include the QKMS server sidecar.

## Authentication

The SDK supports end-user authentication via the QNZM auth bridge.

### Email OTP

```tsx
const { login } = useQkms();

// Step 1: Send OTP
await login({ email: 'user@example.com' });

// Step 2: Verify (after user receives code)
await login({ email: 'user@example.com', otp: '123456' });
```

### Wallet Signature

```tsx
const { login } = useQkms();

// Connect MetaMask and sign a challenge
await login(); // uses window.ethereum

// Or pass a specific provider
await login({ walletProvider: myProvider });
```

### Developer Setup

1. Create a QNZM account (via wallet signature or CLI)
2. Generate a Client API Key (QNZM IAM Settings)
3. Pass `appId` (account ID) and `clientKey` to the provider

End users authenticate under the developer's account. Each user gets scoped access — they can only interact with keys they created.

## React Hooks

### Core Hooks

| Hook | Description |
|---|---|
| `useQkms()` | Auth state: `ready`, `authenticated`, `user`, `login()`, `logout()` |
| `useWallets()` | List all wallets: `{ wallets: ConnectedWallet[] }` |
| `useCreateWallet()` | Create a wallet: `createWallet({ chainType: 'ethereum' \| 'solana' })` |
| `useSignMessage()` | Sign a message: `signMessage({ message }, { address })` |

### Solana Hooks (`/solana`)

| Hook | Description |
|---|---|
| `useCreateWallet()` | Create a Solana wallet (FROST Ed25519 DKG) |
| `useSignMessage()` | Sign with Ed25519 |
| `useSignTransaction()` | Sign a serialized Solana transaction |
| `useSignAndSendTransaction()` | Sign and broadcast |

### Extended Chains (`/extended-chains`)

| Hook | Description |
|---|---|
| `useCreateCosmosWallet()` | Create a Cosmos wallet (bech32 address, configurable prefix) |
| `useCreateSuiWallet()` | Create a Sui wallet (Blake2b address) |
| `useCreateStellarWallet()` | Create a Stellar wallet (StrKey G-address) |

## Node.js SDK

```bash
npm install @quilibrium/qkms-sdk-node
```

```typescript
import { QkmsClient } from '@quilibrium/qkms-sdk-node';

const client = new QkmsClient({
  appId: process.env.QKMS_APP_ID,
  appSecret: process.env.QKMS_APP_SECRET,
  server: 'https://qkms.quilibrium.com',
  qnzmServer: 'https://qnzm.quilibrium.com',
});

// Create an Ethereum wallet
const wallet = await client.wallets().create({ chain_type: 'ethereum' });

// Create a Solana wallet
const solWallet = await client.wallets().create({ chain_type: 'solana' });

// Sign and broadcast an Ethereum transaction
const { hash } = await client.wallets().ethereum().sendTransaction(wallet.id, {
  caip2: 'eip155:1',
  params: {
    transaction: { to: '0x...', value: '1000000000000000' },
  },
});

// Verify a JWT from the auth bridge
const claims = await client.auth().verifyAuthToken(jwt);

// Manage IAM policies
await client.policies().create({ name: 'sign-only', ... });
```

## Vanilla JS SDK

```bash
npm install @quilibrium/qkms-sdk
```

```javascript
import { Qkms, LocalStorage } from '@quilibrium/qkms-sdk';

const qkms = new Qkms({
  appId: 'your-app-id',
  clientId: 'your-client-id',
  storage: new LocalStorage(),
  server: 'https://qkms.quilibrium.com',
});

const wallet = await qkms.embeddedWallet.create({ chainType: 'ethereum' });
const provider = qkms.embeddedWallet.getEthereumProvider({
  wallet,
  entropyId: wallet.keyId,
  entropyIdVerifier: 'your-app-id',
});

const signature = await provider.request({
  method: 'personal_sign',
  params: ['Hello, World!', wallet.address],
});
```

## Security Model

- **Threshold MPC**: Private keys are never assembled in a single location. Key shares are generated via distributed key generation (DKG) and signing uses threshold protocols (DKLs23, FROST, Feldman VSS).
- **E2EE between sidecars**: Multi-party communication uses X3DH key agreement + double ratchet encryption (the same protocol used by Signal).
- **Per-user key scoping**: End users can only access keys they created. Enforced server-side via IAM policies with resource tag conditions.
- **Client API keys**: Browser-side auth bridge calls are validated against a non-secret client key tied to the developer's account, with optional origin restrictions.
- **JWT authentication**: Login produces Ed25519-signed JWTs with issuer validation, expiration enforcement, and required claims checking.

## Current Limitations

| Feature | Status |
|---|---|
| Social login (OAuth) | Use email OTP or wallet signature instead |
| SMS OTP | Scaffolded, not enabled |
| Key export | Threshold keys cannot be exported without all shares |
| Key refresh/resize | Requires DKLs23 refresh protocol |
| Fund wallet | Use your chain's native faucet/bridge |
| MFA enrollment | Not available |
| Cross-app accounts | Not available |
| Solana `signAndSendTransaction` | Use `signTransaction` + your own broadcast |

## Development

```bash
# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run tests
pnpm test

# Run protocol smoke tests
cd wasm/mpc-wasm && node smoke-test.mjs

# Start local dev environment
./start-local.sh
```

## Architecture

```
Browser                          QKMS Server              QNZM (IAM)
  |                                |                         |
  |-- QkmsProvider -------> QkmsRpcClient (SigV4) -----> TrentService.*
  |   |                            |                         |
  |   |-- Sidecar (wasm)           |-- Server Sidecar        |-- Users/Policies
  |   |   |-- DKLs23 Session       |   |-- DKLs23 (Go FFI)   |-- Access Keys
  |   |   |-- FROST Session        |   |-- FROST (Go FFI)    |-- Client API Keys
  |   |   |-- BLS Session          |   |-- BLS (Go FFI)      |-- Auth Bridge
  |   |   |-- Decaf448 Session     |   |-- Decaf448          |   |-- Email OTP
  |   |   |-- RSA Session          |   |-- RSA               |   |-- Wallet Login
  |   |   |-- PeerChannel (E2EE)   |   |-- PeerChannel       |
  |   |                            |                         |
  |   |-- IndexedDB (key shares,   |-- Pebble DB (keys,      |-- Pebble DB
  |       identity, wallets)       |   tasks, shares)        |
```

## License

Copyright Quilibrium, Inc. All rights reserved.
