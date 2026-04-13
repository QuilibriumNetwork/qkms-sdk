// qkms-sdk vanilla starter — demonstrates the class-based SDK surface.
//
// Flow:
//   1. User provides QNZM access key + secret
//   2. Construct a Qkms instance with LocalStorage backing
//   3. Fetch the user record (synthesized from the sidecar identity)
//   4. Create an embedded Ethereum wallet (runs 3-round DKLs23 DKG)
//   5. Sign a message via the EIP-1193 provider (personal_sign)
//   6. Recover the address from the signature via viem.recoverMessageAddress
//
// A backward-compatible class alias is also exported.

import { Qkms, LocalStorage } from '@quilibrium/qkms-sdk';
import { recoverMessageAddress } from 'viem';

const CREDS_STORAGE_KEY = 'qkms-vanilla-creds';

function loadCreds() {
  try {
    const raw = localStorage.getItem(CREDS_STORAGE_KEY);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}
function saveCreds(c) {
  localStorage.setItem(CREDS_STORAGE_KEY, JSON.stringify(c));
}
function clearCreds() {
  localStorage.removeItem(CREDS_STORAGE_KEY);
}

// -----------------------------------------------------------------------------
// DOM helpers
// -----------------------------------------------------------------------------

const el = (id) => document.getElementById(id);

function show(id) { el(id).classList.remove('hidden'); }
function hide(id) { el(id).classList.add('hidden'); }

function setError(id, msg) {
  const target = el(id);
  target.textContent = msg;
  target.classList.remove('hidden');
}
function clearError(id) {
  const target = el(id);
  target.textContent = '';
  target.classList.add('hidden');
}

// -----------------------------------------------------------------------------
// App state
// -----------------------------------------------------------------------------

let qkms = null;
let wallet = null;
let user = null;

// -----------------------------------------------------------------------------
// Initialization
// -----------------------------------------------------------------------------

async function initQkms(creds) {
  qkms = new Qkms({
    appId: creds.accessKey,
    appSecret: creds.secretKey,
    server: creds.qkmsServer,
    storage: new LocalStorage({ prefix: 'qkms-vanilla:' }),
    defaultChainId: 1,
  });

  // Get the user record. This lazily starts the sidecar.
  const { user: u } = await qkms.user.get();
  user = u;
  el('user-info').textContent = `ready · user.id = ${user.id}`;

  // Show wallet section.
  show('wallet-section');
  show('logout-section');
  hide('creds-section');
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

el('connect-btn').addEventListener('click', async () => {
  const creds = {
    accessKey: el('access-key').value.trim(),
    secretKey: el('secret-key').value,
    qkmsServer: el('qkms-server').value.trim() || 'https://qkms.quilibrium.com',
  };
  if (!creds.accessKey || !creds.secretKey) {
    el('creds-status').textContent = 'access key and secret key are required';
    return;
  }
  saveCreds(creds);
  el('creds-status').textContent = 'initializing sidecar…';
  try {
    await initQkms(creds);
  } catch (err) {
    el('creds-status').textContent = 'init failed: ' + (err?.message ?? String(err));
  }
});

el('create-wallet-btn').addEventListener('click', async () => {
  clearError('wallet-error');
  el('create-wallet-btn').disabled = true;
  el('create-wallet-btn').textContent = 'Running DKG…';
  try {
    wallet = await qkms.embeddedWallet.create({ chainType: 'ethereum' });
    el('wallet-address').textContent = wallet.address;
    el('wallet-keyid').textContent = wallet.keyId;
    hide('no-wallet');
    show('wallet-info');
    show('sign-section');
  } catch (err) {
    setError('wallet-error', err?.message ?? String(err));
  } finally {
    el('create-wallet-btn').disabled = false;
    el('create-wallet-btn').textContent = 'Create wallet (runs DKG)';
  }
});

el('sign-btn').addEventListener('click', async () => {
  clearError('sign-error');
  hide('sig-output');
  if (!wallet) return;

  el('sign-btn').disabled = true;
  el('sign-btn').textContent = 'Running threshold sign…';
  try {
    const provider = qkms.embeddedWallet.getEthereumProvider({ wallet });
    const message = el('message').value;
    const signature = await provider.request({
      method: 'personal_sign',
      params: [message, wallet.address],
    });
    el('signature').textContent = signature;
    show('sig-output');

    // Verify signature recovery matches the wallet address.
    const recovered = await recoverMessageAddress({ message, signature });
    const match = recovered.toLowerCase() === wallet.address.toLowerCase();
    el('recovery-result').innerHTML = `<strong>Recovered address:</strong> <code>${recovered}</code> ${
      match ? '<span class="success">✅ matches</span>' : '<span class="error">❌ MISMATCH</span>'
    }`;
  } catch (err) {
    setError('sign-error', err?.message ?? String(err));
  } finally {
    el('sign-btn').disabled = false;
    el('sign-btn').textContent = 'Sign';
  }
});

el('logout-btn').addEventListener('click', async () => {
  if (qkms) await qkms.auth.logout();
  clearCreds();
  window.location.reload();
});

// -----------------------------------------------------------------------------
// Auto-reconnect if we have saved creds
// -----------------------------------------------------------------------------

const savedCreds = loadCreds();
if (savedCreds) {
  el('access-key').value = savedCreds.accessKey;
  el('secret-key').value = savedCreds.secretKey;
  el('qkms-server').value = savedCreds.qkmsServer;
  initQkms(savedCreds).catch((err) => {
    el('creds-status').textContent = 'auto-reconnect failed: ' + (err?.message ?? String(err));
  });
}
