// Stub hooks for methods qkms-sdk does not support. We export the surface so
// apps that import them don't fail at module-load time; the hook returns
// functions that throw when called. Only the unsupported features will fail at
// runtime, and only when actually invoked.

const unsupported =
  (name: string) =>
  () => {
    throw new Error(`${name} is not supported in qkms-sdk-react (wallet operations only)`);
  };

export function useFundWallet(): { fundWallet: (...args: unknown[]) => void } {
  return { fundWallet: unsupported('fundWallet') };
}

export function useLinkAccount(): {
  linkEmail: (...args: unknown[]) => Promise<void>;
  linkPhone: (...args: unknown[]) => Promise<void>;
  linkWallet: (...args: unknown[]) => Promise<void>;
  linkPasskey: (...args: unknown[]) => Promise<void>;
  linkGoogle: (...args: unknown[]) => Promise<void>;
  linkApple: (...args: unknown[]) => Promise<void>;
  linkTwitter: (...args: unknown[]) => Promise<void>;
  linkDiscord: (...args: unknown[]) => Promise<void>;
  linkGithub: (...args: unknown[]) => Promise<void>;
  linkLinkedIn: (...args: unknown[]) => Promise<void>;
  linkTiktok: (...args: unknown[]) => Promise<void>;
  linkFarcaster: (...args: unknown[]) => Promise<void>;
  linkTelegram: (...args: unknown[]) => Promise<void>;
} {
  const stub = unsupported('useLinkAccount.*') as () => Promise<void>;
  return {
    linkEmail: stub,
    linkPhone: stub,
    linkWallet: stub,
    linkPasskey: stub,
    linkGoogle: stub,
    linkApple: stub,
    linkTwitter: stub,
    linkDiscord: stub,
    linkGithub: stub,
    linkLinkedIn: stub,
    linkTiktok: stub,
    linkFarcaster: stub,
    linkTelegram: stub,
  };
}

export function useMfaEnrollment(): { showMfaEnrollmentModal: () => void } {
  return { showMfaEnrollmentModal: unsupported('showMfaEnrollmentModal') };
}

export function useCrossAppAccounts(): {
  linkCrossAppAccount: (...args: unknown[]) => Promise<void>;
  loginWithCrossAppAccount: (...args: unknown[]) => Promise<void>;
  unlinkCrossAppAccount: (...args: unknown[]) => Promise<void>;
} {
  const stub = unsupported('useCrossAppAccounts.*') as () => Promise<void>;
  return {
    linkCrossAppAccount: stub,
    loginWithCrossAppAccount: stub,
    unlinkCrossAppAccount: stub,
  };
}

export function useImportWallet(): { importWallet: (...args: unknown[]) => Promise<unknown> } {
  return {
    importWallet: unsupported('importWallet') as () => Promise<unknown>,
  };
}

export function useExportWallet(): { exportWallet: (...args: unknown[]) => Promise<void> } {
  return {
    exportWallet: unsupported('exportWallet') as () => Promise<void>,
  };
}

export function useSigners(): {
  addSigners: (...args: unknown[]) => Promise<void>;
  removeSigners: (...args: unknown[]) => Promise<void>;
} {
  return {
    addSigners: unsupported('addSigners') as () => Promise<void>,
    removeSigners: unsupported('removeSigners') as () => Promise<void>,
  };
}
