// QKMS SDK React demo — end-user login + embedded wallet.
//
// Auth flows:
//   1. Email OTP: enter email → receive code → submit → authenticated
//   2. Wallet: connect MetaMask → sign challenge → authenticated
//
// Once authenticated:
//   - Create wallet (DKG via WASM sidecar → EVM address, auto-tagged with owner_id)
//   - Sign message (ECDSA threshold sign → signature)
//   - Verify (viem recoverMessageAddress)

import { useState } from 'react';
import { recoverMessageAddress } from 'viem';
import { useContext } from 'react';
import {
  QkmsProvider,
  useQkms,
  useWallets,
  useCreateWallet,
  useSignMessage,
  QkmsContext,
} from '@quilibrium/qkms-sdk-react';
import { useSignMessage as useSolanaSignMessage } from '@quilibrium/qkms-sdk-react/solana';

// ---- Config (defaults for local dev) ----
const DEFAULT_QKMS = 'https://localhost:8082';
const DEFAULT_QNZM = 'https://localhost:4566';
const STORAGE_KEY = 'qkms-react-starter-config';

interface AppConfig {
  qkmsServer: string;
  qnzmServer: string;
  appId: string;
  clientKey: string;
}

function loadConfig(): AppConfig | null {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) ?? 'null');
  } catch { return null; }
}

// ---- Login screen ----

function LoginScreen() {
  const { login } = useQkms();
  const [mode, setMode] = useState<'email' | 'wallet'>('email');
  const [email, setEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [otpSent, setOtpSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSendOTP = async () => {
    setError(null);
    setLoading(true);
    try {
      await login({ email });
      setOtpSent(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOTP = async () => {
    setError(null);
    setLoading(true);
    try {
      await login({ email, otp });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  const handleWalletLogin = async () => {
    setError(null);
    setLoading(true);
    try {
      await login({});
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.page}>
      <h1 style={styles.title}>QKMS SDK React Starter</h1>
      <p style={styles.hint}>Sign in to create an embedded wallet backed by threshold MPC.</p>

      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <button style={{ ...styles.tab, ...(mode === 'email' ? styles.tabActive : {}) }} onClick={() => setMode('email')}>
          Email
        </button>
        <button style={{ ...styles.tab, ...(mode === 'wallet' ? styles.tabActive : {}) }} onClick={() => setMode('wallet')}>
          Wallet
        </button>
      </div>

      {mode === 'email' ? (
        <div style={styles.section}>
          {!otpSent ? (
            <>
              <label style={styles.label}>
                Email address
                <input style={styles.input} type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" />
              </label>
              <button style={{ ...styles.button, marginTop: 12 }} onClick={handleSendOTP} disabled={loading || !email}>
                {loading ? 'Sending...' : 'Send code'}
              </button>
            </>
          ) : (
            <>
              <p style={styles.hint}>Code sent to <strong>{email}</strong>. Check the QNZM server console (dev mode).</p>
              <label style={styles.label}>
                Verification code
                <input style={styles.input} type="text" value={otp} onChange={(e) => setOtp(e.target.value)} placeholder="123456" maxLength={6} />
              </label>
              <button style={{ ...styles.button, marginTop: 12 }} onClick={handleVerifyOTP} disabled={loading || otp.length < 6}>
                {loading ? 'Verifying...' : 'Verify & sign in'}
              </button>
              <button style={{ ...styles.linkBtn, marginTop: 8 }} onClick={() => { setOtpSent(false); setOtp(''); }}>
                Use a different email
              </button>
            </>
          )}
        </div>
      ) : (
        <div style={styles.section}>
          <p style={styles.hint}>Connect MetaMask (or another injected wallet) to sign in.</p>
          <button style={{ ...styles.button, background: '#4f46e5' }} onClick={handleWalletLogin} disabled={loading}>
            {loading ? 'Connecting...' : 'Connect Wallet'}
          </button>
        </div>
      )}

      {error && <pre style={styles.error}>{error}</pre>}
    </div>
  );
}

// ---- Authenticated view ----

const WALLET_TYPES = [
  { label: 'Ethereum (secp256k1)', chainType: 'ethereum' as const },
  { label: 'Solana (Ed25519)', chainType: 'solana' as const },
] as const;

const RAW_KEY_TYPES = [
  { label: 'BLS12-381', keySpec: 'ECC_BLS12_381' },
  { label: 'BLS48-581', keySpec: 'ECC_BLS48_581' },
  { label: 'Decaf448', keySpec: 'ECC_DECAF448' },
  { label: 'Ed448', keySpec: 'ECC_ED448' },
] as const;

function Dashboard() {
  const { ready, authenticated, user, logout } = useQkms();
  const qkmsCtx = useContext(QkmsContext);
  const { wallets } = useWallets();
  const { createWallet } = useCreateWallet();
  const { signMessage } = useSignMessage();
  const { signMessage: signSolanaMessage } = useSolanaSignMessage();

  const [creating, setCreating] = useState<string | null>(null);
  const [signing, setSigning] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [signature, setSignature] = useState<string | null>(null);
  const [recovered, setRecovered] = useState<string | null>(null);
  const [message, setMessage] = useState('Hello from qkms-sdk!');

  if (!ready) return <p style={styles.page}>Loading sidecar...</p>;

  const handleCreate = async (chainType: 'ethereum' | 'solana') => {
    setCreating(chainType);
    setError(null);
    try {
      await createWallet({ chainType });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setCreating(null);
    }
  };

  const handleCreateRawKey = async (keySpec: string) => {
    setCreating(keySpec);
    setError(null);
    try {
      if (!qkmsCtx?.client || !qkmsCtx?.sidecarId) throw new Error('Not ready');
      await qkmsCtx.client.createKey({
        KeySpec: keySpec,
        KeyUsage: 'SIGN_VERIFY',
        Origin: 'AWS_KMS',
        Participants: qkmsCtx.participants,
        Threshold: qkmsCtx.threshold,
        Tags: user?.id ? [
          { TagKey: 'owner_id', TagValue: user.id },
          { TagKey: 'chain_type', TagValue: keySpec },
        ] : [],
      });
      // Reload page to pick up the new key
      window.location.reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setCreating(null);
    }
  };

  const handleSign = async (wallet: typeof wallets[number]) => {
    setSigning(wallet.address);
    setError(null);
    setSignature(null);
    setRecovered(null);
    try {
      if (wallet.chainType === 'ethereum') {
        // EVM: personal_sign via EthereumProvider
        const { signature: sig } = await signMessage({ message }, { address: wallet.address });
        setSignature(sig);
        try {
          const addr = await recoverMessageAddress({ message, signature: sig });
          setRecovered(addr);
        } catch {
          setRecovered('(recovery not available)');
        }
      } else if (wallet.chainType === 'solana') {
        // Solana: Ed25519 via SolanaProvider
        const msgBytes = new TextEncoder().encode(message);
        const { signature: sigBytes } = await signSolanaMessage({ message: msgBytes, wallet });
        let hex = '';
        for (let i = 0; i < sigBytes.length; i++) hex += sigBytes[i]!.toString(16).padStart(2, '0');
        setSignature('0x' + hex);
        setRecovered(`(Ed25519 signature, ${sigBytes.length} bytes)`);
      } else {
        // Generic: call QKMS Sign directly for BLS/Decaf/Ed448/etc.
        if (!qkmsCtx?.client) throw new Error('Not ready');
        const msgB64 = btoa(message);
        // Map chainType (keySpec) to signing algorithm
        const algMap: Record<string, string> = {
          'ECC_BLS12_381': 'BLS12_381',
          'ECC_BLS48_581': 'BLS48_581',
          'ECC_DECAF448': 'ECDSA_DECAF448',
          'ECC_DECAF_448': 'ECDSA_DECAF448',
          'ECC_ED448': 'EDDSA_ED448',
        };
        const sigAlg = algMap[wallet.chainType] ?? wallet.chainType;
        const res = await qkmsCtx.client.sign({
          KeyId: wallet.keyId,
          Message: msgB64,
          MessageType: 'RAW',
          SigningAlgorithm: sigAlg,
        });
        setSignature(res.Signature);
        setRecovered(`(${wallet.chainType} signature via QKMS Sign)`);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSigning(null);
    }
  };

  return (
    <div style={styles.page}>
      <h1 style={styles.title}>QKMS SDK React Starter</h1>
      <p style={styles.hint}>
        authenticated: {String(authenticated)} | user: <code>{user?.id ?? '-'}</code>
      </p>

      {/* Create key buttons */}
      <section style={styles.section}>
        <h2 style={styles.sectionTitle}>Create Key</h2>
        <p style={styles.hint}>Chain wallets (address derived):</p>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 8 }}>
          {WALLET_TYPES.map(({ label, chainType }) => (
            <button
              key={chainType}
              style={styles.button}
              onClick={() => handleCreate(chainType)}
              disabled={creating !== null}
            >
              {creating === chainType ? 'Running DKG...' : label}
            </button>
          ))}
        </div>
        <p style={styles.hint}>Raw MPC keys (threshold signing):</p>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {RAW_KEY_TYPES.map(({ label, keySpec }) => (
            <button
              key={keySpec}
              style={{ ...styles.button, background: '#555' }}
              onClick={() => handleCreateRawKey(keySpec)}
              disabled={creating !== null}
            >
              {creating === keySpec ? 'Running DKG...' : label}
            </button>
          ))}
        </div>
      </section>

      {/* All wallets */}
      {wallets.length > 0 && (
        <section style={styles.section}>
          <h2 style={styles.sectionTitle}>Wallets ({wallets.length})</h2>
          {wallets.map((w, i) => (
            <div key={w.keyId ?? i} style={{ padding: '8px 0', borderBottom: i < wallets.length - 1 ? '1px solid #eee' : 'none' }}>
              <div><strong>Address:</strong> <code style={{ fontSize: '0.75rem', wordBreak: 'break-all' }}>{w.address}</code></div>
              <div><strong>KeyId:</strong> <code style={{ fontSize: '0.75rem' }}>{w.keyId}</code></div>
              <div><strong>Chain:</strong> {w.chainType}</div>
              <button
                style={{ ...styles.button, marginTop: 4, fontSize: '0.75rem', padding: '4px 8px' }}
                onClick={() => handleSign(w)}
                disabled={signing !== null}
              >
                {signing === w.address ? 'Signing...' : 'Sign message'}
              </button>
            </div>
          ))}
        </section>
      )}

      {/* Sign message */}
      {wallets.length > 0 && (
        <section style={styles.section}>
          <h2 style={styles.sectionTitle}>Message to sign</h2>
          <input style={styles.input} value={message} onChange={(e) => setMessage(e.target.value)} />
          {signature && (
            <div style={{ marginTop: 12 }}>
              <div><strong>Signature:</strong> <code style={{ wordBreak: 'break-all', fontSize: '0.75rem' }}>{signature}</code></div>
              <div><strong>Recovered:</strong> <code>{recovered}</code></div>
            </div>
          )}
        </section>
      )}

      {error && <pre style={styles.error}>{error}</pre>}

      <button style={{ ...styles.button, marginTop: 24, background: '#666' }} onClick={() => { void logout(); localStorage.removeItem(STORAGE_KEY); window.location.reload(); }}>
        Log out
      </button>
    </div>
  );
}

// ---- Root ----

export function App() {
  const [config, setConfig] = useState<AppConfig | null>(() => loadConfig());
  const [appId, setAppId] = useState('');
  const [clientKey, setClientKey] = useState('');
  const [qkmsServer, setQkmsServer] = useState(DEFAULT_QKMS);
  const [qnzmServer, setQnzmServer] = useState(DEFAULT_QNZM);

  if (!config) {
    return (
      <div style={styles.page}>
        <h1 style={styles.title}>QKMS SDK React Starter</h1>
        <p style={styles.hint}>Configure your developer account to get started.</p>
        <div style={styles.section}>
          <label style={styles.label}>App ID (QNZM account ID)<input style={styles.input} value={appId} onChange={(e) => setAppId(e.target.value)} /></label>
          <label style={styles.label}>Client API Key<input style={styles.input} value={clientKey} onChange={(e) => setClientKey(e.target.value)} placeholder="qnzm_ck_..." /></label>
          <label style={styles.label}>QKMS server<input style={styles.input} value={qkmsServer} onChange={(e) => setQkmsServer(e.target.value)} /></label>
          <label style={styles.label}>QNZM server<input style={styles.input} value={qnzmServer} onChange={(e) => setQnzmServer(e.target.value)} /></label>
          <button style={{ ...styles.button, marginTop: 12 }} onClick={() => { const c = { appId, clientKey, qkmsServer, qnzmServer }; localStorage.setItem(STORAGE_KEY, JSON.stringify(c)); setConfig(c); }}>
            Continue
          </button>
        </div>
      </div>
    );
  }

  const resetConfig = () => { localStorage.removeItem(STORAGE_KEY); setConfig(null); };

  return (
    <QkmsProvider
      appId={config.appId}
      useWorker={false}
      config={{
        qkmsServer: config.qkmsServer,
        qnzmServer: config.qnzmServer,
        clientKey: config.clientKey,
        embeddedWallets: { ethereum: { createOnLogin: 'off' } },
        defaultChain: { id: 1 },
      }}
    >
      <AuthGate />
      <div style={{ ...styles.page, marginTop: 0 }}>
        <button style={styles.linkBtn} onClick={resetConfig}>Reset config</button>
      </div>
    </QkmsProvider>
  );
}

/** Shows login or dashboard depending on auth state. */
function AuthGate() {
  const { authenticated } = useQkms();
  return authenticated ? <Dashboard /> : <LoginScreen />;
}

// ---- Styles ----
const styles = {
  page: { fontFamily: 'system-ui, -apple-system, sans-serif', padding: 24, maxWidth: 720, margin: '0 auto' } as const,
  title: { fontSize: '1.5rem', marginBottom: 4 } as const,
  hint: { color: '#666', fontSize: '0.875rem' } as const,
  section: { margin: '1.5rem 0', padding: '1rem', border: '1px solid #ccc', borderRadius: 8, background: '#fff', display: 'flex', flexDirection: 'column' as const, gap: 8 } as const,
  sectionTitle: { fontSize: '1.125rem', marginTop: 0 } as const,
  label: { display: 'flex', flexDirection: 'column' as const, fontSize: '0.875rem', gap: 2 } as const,
  input: { padding: '0.5rem', fontFamily: 'monospace', fontSize: '0.875rem', border: '1px solid #ccc', borderRadius: 4, width: '100%', boxSizing: 'border-box' as const } as const,
  button: { padding: '0.5rem 1rem', cursor: 'pointer', background: '#111', color: '#fff', border: 'none', borderRadius: 4, fontSize: '0.875rem' } as const,
  tab: { padding: '0.5rem 1rem', cursor: 'pointer', background: '#eee', color: '#333', border: '1px solid #ccc', borderRadius: 4, fontSize: '0.875rem' } as const,
  tabActive: { background: '#111', color: '#fff', borderColor: '#111' } as const,
  linkBtn: { background: 'none', border: 'none', color: '#4f46e5', cursor: 'pointer', fontSize: '0.875rem', padding: 0 } as const,
  error: { color: '#c00', whiteSpace: 'pre-wrap' as const, marginTop: 16, padding: 12, background: '#fee', borderRadius: 4, fontSize: '0.75rem' } as const,
};
