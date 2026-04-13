'use client';

// Providers component — runs on the client (qkms-sdk uses wasm + Web Workers
// which have no Node equivalent during Next's SSR pass). Wraps children in
// the QkmsProvider.

import { useEffect, useState, type ReactNode } from 'react';
import { QkmsProvider } from '@quilibrium/qkms-sdk-react';

const STORAGE_KEY = 'qkms-next-starter-creds';

interface StoredCreds {
  accessKey: string;
  secretKey: string;
  qkmsServer: string;
}

function loadCreds(): StoredCreds | null {
  if (typeof localStorage === 'undefined') return null;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as StoredCreds;
  } catch {
    return null;
  }
}

export function saveCreds(c: StoredCreds): void {
  if (typeof localStorage === 'undefined') return;
  localStorage.setItem(STORAGE_KEY, JSON.stringify(c));
}

export function clearStoredCreds(): void {
  if (typeof localStorage === 'undefined') return;
  localStorage.removeItem(STORAGE_KEY);
}

/**
 * Provider wrapper that pulls QNZM credentials from localStorage. Apps that
 * mint creds server-side via a real identity flow (qnzm-auth bridge, OAuth
 * redirect handler, etc.) would instead fetch them in a server component
 * and pass them down as props — the `config.credentials` shape is stable
 * and accepts any source.
 */
export function Providers({ children }: { children: ReactNode }): ReactNode {
  // SSR-safe: useState initializer runs on both server and client, but the
  // server always produces `null` because `localStorage` is undefined.
  const [creds, setCreds] = useState<StoredCreds | null>(() => loadCreds());

  // On first mount, re-check localStorage. Next hydration sometimes misses
  // the initial read if the component renders before localStorage is ready.
  useEffect(() => {
    const fromStorage = loadCreds();
    if (fromStorage && !creds) setCreds(fromStorage);
    const onStorage = (e: StorageEvent) => {
      if (e.key === STORAGE_KEY) setCreds(loadCreds());
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Before the user has entered credentials, render children without a
  // provider context — the home page detects this and shows the credentials
  // form instead of the signed-in view.
  if (!creds) {
    return <>{children}</>;
  }

  return (
    <QkmsProvider
      appId={creds.accessKey}
      config={{
        credentials: {
          accessKey: creds.accessKey,
          secretKey: creds.secretKey,
        },
        qkmsServer: creds.qkmsServer,
        embeddedWallets: { ethereum: { createOnLogin: 'off' } },
        defaultChain: { id: 1 },
      }}
    >
      {children}
    </QkmsProvider>
  );
}
