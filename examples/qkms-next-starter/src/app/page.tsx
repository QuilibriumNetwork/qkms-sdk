'use client';

// Home page — client component because it uses the qkms-sdk-react hooks.
// The flow mirrors qkms-react-starter: credentials form → QkmsProvider
// context becomes available → createWallet → signMessage → verify recovery.

import { useState } from 'react';
import { recoverMessageAddress } from 'viem';
import {
  useQkms,
  useWallets,
  useCreateWallet,
  useSignMessage,
} from '@quilibrium/qkms-sdk-react';
import { saveCreds, clearStoredCreds } from '@/providers/providers';

/**
 * Entry component: shows the credentials form if no creds are stored,
 * otherwise shows the signed-in wallet UI.
 */
export default function HomePage() {
  // Provider-ready state: `useQkms` throws outside <QkmsProvider>, so we
  // catch that and fall back to the credentials form.
  try {
    useQkms();
  } catch {
    return <CredentialsForm />;
  }
  return <SignedInView />;
}

function CredentialsForm() {
  const [accessKey, setAccessKey] = useState('');
  const [secretKey, setSecretKey] = useState('');
  const [qkmsServer, setQkmsServer] = useState('https://qkms.quilibrium.com');

  return (
    <main style={styles.page}>
      <h1 style={styles.title}>qkms-sdk Next.js starter</h1>
      <p style={styles.hint}>
        Provide QNZM credentials to boot the sidecar. These come from a
        QNZM-aware service (e.g. the planned <code>qnzm-auth</code> bridge).
      </p>
      <form
        style={styles.form}
        onSubmit={(e) => {
          e.preventDefault();
          if (!accessKey || !secretKey) return;
          saveCreds({ accessKey, secretKey, qkmsServer });
          window.location.reload();
        }}
      >
        <label style={styles.label}>
          Access key
          <input
            style={styles.input}
            type="text"
            value={accessKey}
            onChange={(e) => setAccessKey(e.target.value)}
            placeholder="AKIA..."
            required
          />
        </label>
        <label style={styles.label}>
          Secret key
          <input
            style={styles.input}
            type="password"
            value={secretKey}
            onChange={(e) => setSecretKey(e.target.value)}
            required
          />
        </label>
        <label style={styles.label}>
          QKMS server
          <input
            style={styles.input}
            type="text"
            value={qkmsServer}
            onChange={(e) => setQkmsServer(e.target.value)}
          />
        </label>
        <button style={styles.button} type="submit">
          Save & connect
        </button>
      </form>
    </main>
  );
}

function SignedInView() {
  const { ready, authenticated, user, logout } = useQkms();
  const { wallets } = useWallets();
  const { createWallet } = useCreateWallet();
  const { signMessage } = useSignMessage();

  const [creating, setCreating] = useState(false);
  const [signing, setSigning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [signature, setSignature] = useState<string | null>(null);
  const [recovered, setRecovered] = useState<string | null>(null);
  const [message, setMessage] = useState('Hello from qkms-sdk Next.js!');

  const wallet = wallets[0];

  const handleCreate = async () => {
    setError(null);
    setCreating(true);
    try {
      await createWallet({ chainType: 'ethereum' });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setCreating(false);
    }
  };

  const handleSign = async () => {
    if (!wallet) return;
    setError(null);
    setSignature(null);
    setRecovered(null);
    setSigning(true);
    try {
      const { signature: sig } = await signMessage({ message }, { address: wallet.address });
      setSignature(sig);
      const addr = await recoverMessageAddress({ message, signature: sig });
      setRecovered(addr);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSigning(false);
    }
  };

  if (!ready) {
    return (
      <main style={styles.page}>
        <p>Loading sidecar…</p>
      </main>
    );
  }

  return (
    <main style={styles.page}>
      <h1 style={styles.title}>qkms-sdk Next.js starter</h1>
      <p style={styles.hint}>
        ready: {String(ready)} · authenticated: {String(authenticated)} · user.id:{' '}
        <code>{user?.id ?? '—'}</code>
      </p>

      <section style={styles.section}>
        <h2 style={styles.sectionTitle}>Wallet</h2>
        {wallet ? (
          <div>
            <div>
              <strong>Address:</strong> <code>{wallet.address}</code>
            </div>
            <div>
              <strong>Key id:</strong> <code>{wallet.keyId}</code>
            </div>
            <div>
              <strong>Chain:</strong> {wallet.chainType} (chainId {wallet.chainId})
            </div>
          </div>
        ) : (
          <button style={styles.button} onClick={handleCreate} disabled={creating}>
            {creating ? 'Running DKG…' : 'Create wallet'}
          </button>
        )}
      </section>

      {wallet && (
        <section style={styles.section}>
          <h2 style={styles.sectionTitle}>Sign message</h2>
          <input
            style={{ ...styles.input, marginBottom: 8 }}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
          />
          <button style={styles.button} onClick={handleSign} disabled={signing}>
            {signing ? 'Running threshold sign…' : 'Sign'}
          </button>
          {signature && (
            <div style={{ marginTop: 12 }}>
              <div>
                <strong>Signature:</strong>{' '}
                <code style={{ wordBreak: 'break-all' }}>{signature}</code>
              </div>
              <div>
                <strong>Recovered address:</strong> <code>{recovered}</code>{' '}
                {recovered &&
                  (recovered.toLowerCase() === wallet.address.toLowerCase()
                    ? '✅ matches'
                    : '❌ MISMATCH')}
              </div>
            </div>
          )}
        </section>
      )}

      {error && <pre style={styles.error}>{error}</pre>}

      <section style={{ marginTop: 32 }}>
        <button
          style={styles.button}
          onClick={() => {
            clearStoredCreds();
            void logout();
            window.location.reload();
          }}
        >
          Reset & log out
        </button>
      </section>
    </main>
  );
}

const styles = {
  page: {
    fontFamily: 'system-ui, -apple-system, sans-serif',
    padding: 24,
    maxWidth: 720,
    margin: '0 auto',
  },
  title: { fontSize: '1.5rem' },
  hint: { color: '#666', fontSize: '0.875rem' },
  section: {
    margin: '1.5rem 0',
    padding: '1rem',
    border: '1px solid #ccc',
    borderRadius: 8,
    background: '#fff',
  },
  sectionTitle: { fontSize: '1.125rem', marginTop: 0 },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: 12,
    maxWidth: 480,
  },
  label: { display: 'flex', flexDirection: 'column', fontSize: '0.875rem' },
  input: {
    padding: '0.5rem',
    fontFamily: 'monospace',
    fontSize: '0.875rem',
    border: '1px solid #ccc',
    borderRadius: 4,
    width: '100%',
    boxSizing: 'border-box',
  },
  button: {
    padding: '0.5rem 1rem',
    cursor: 'pointer',
    background: '#111',
    color: '#fff',
    border: 'none',
    borderRadius: 4,
    fontSize: '0.875rem',
  },
  error: {
    color: '#c00',
    whiteSpace: 'pre-wrap',
    marginTop: 16,
    padding: 12,
    background: '#fee',
    borderRadius: 4,
    fontSize: '0.75rem',
  },
} as const;
