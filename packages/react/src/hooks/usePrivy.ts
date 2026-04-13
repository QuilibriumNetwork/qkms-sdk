// usePrivy / useQkms hook — top-level state + auth methods.
//
// The login() method supports two flows:
//   1. Email OTP: login({ email }) → sends OTP → login({ email, otp }) → authenticated
//   2. Wallet: login({ walletProvider }) → signs challenge → authenticated
//
// Both flows create a USER under the DEVELOPER's QNZM account (appId),
// scoped by an auto-attached policy that restricts key access to keys
// the user created.

import { useCallback, useContext } from 'react';
import type { EIP1193Provider } from '@quilibrium/qkms-sdk-core';
import { QkmsContext, type QkmsContextValue } from '../context.js';

export interface LoginOptions {
  /** Email OTP flow — step 1: send code. Step 2: verify with `otp`. */
  email?: string;
  /** Email OTP flow — step 2: verify the code received via email. */
  otp?: string;
  /** Wallet flow: sign challenge with this provider (or window.ethereum). */
  walletProvider?: EIP1193Provider;
}

export interface UsePrivyResult {
  ready: boolean;
  authenticated: boolean;
  user: QkmsContextValue['user'];
  /**
   * Multi-step login for end users:
   *   login({ email }) → sends OTP, returns (UI should show OTP input)
   *   login({ email, otp }) → verifies OTP, authenticates
   *   login({ walletProvider }) → wallet signature, authenticates
   */
  login: (opts?: LoginOptions) => Promise<void>;
  logout: () => Promise<void>;
  exportWallet: (opts: { address?: string }) => Promise<void>;
  unlinkEmail: (address: string) => Promise<void>;
  unlinkPhone: (number: string) => Promise<void>;
  unlinkWallet: (address: string) => Promise<void>;
  unlinkGoogle: (subject: string) => Promise<void>;
  unlinkApple: (subject: string) => Promise<void>;
  unlinkTwitter: (subject: string) => Promise<void>;
  unlinkDiscord: (subject: string) => Promise<void>;
  unlinkGithub: (subject: string) => Promise<void>;
  unlinkLinkedIn: (subject: string) => Promise<void>;
  unlinkTiktok: (subject: string) => Promise<void>;
  unlinkFarcaster: (fid: number) => Promise<void>;
  unlinkTelegram: (telegramUserId: string) => Promise<void>;
  unlinkPasskey: (credentialId: string) => Promise<void>;
}

const UNSUPPORTED = (name: string) => async (): Promise<never> => {
  throw new Error(`${name} is not supported in qkms-sdk-react`);
};

export function useQkms(): UsePrivyResult {
  const ctx = useContext(QkmsContext);
  if (!ctx) {
    throw new Error('useQkms must be used inside <QkmsProvider>');
  }

  const login = useCallback(
    async (opts?: LoginOptions) => {
      if (!ctx.authClient) {
        throw new Error(
          'login() requires config.qnzmServer on QkmsProvider.',
        );
      }

      const appId = ctx.appId;
      const clientKey = ctx.clientKey;
      if (!clientKey) {
        throw new Error('login() requires config.clientKey on QkmsProvider.');
      }

      // ---- Email OTP flow ----
      if (opts?.email) {
        if (!opts.otp) {
          // Step 1: send OTP
          await ctx.authClient.sendEmailOTP(appId, clientKey, opts.email);
          return; // UI should now show OTP input
        }

        // Step 2: verify OTP
        const result = await ctx.authClient.verifyEmailOTP(appId, clientKey, opts.email, opts.otp);
        ctx.setCredentials(result.access_key_id, result.secret_access_key);
        ctx.setJwt(result.jwt);
        ctx.setUser({
          id: result.user_name, // stable IAM userName (e.g. email_abc123) — used for DB name + owner_id tagging
          createdAt: new Date(),
          linkedAccounts: [{ type: 'email', address: opts.email }],
        });
        return;
      }

      // ---- Wallet flow ----
      const provider =
        opts?.walletProvider ??
        ((globalThis as Record<string, unknown>).ethereum as EIP1193Provider | undefined);
      if (!provider) {
        throw new Error('No wallet provider available. Pass walletProvider or install MetaMask.');
      }

      const accounts = (await provider.request({
        method: 'eth_requestAccounts',
      })) as string[];
      const address = accounts[0];
      if (!address) throw new Error('No accounts returned from wallet');

      // Get challenge
      const { challenge, nonce } = await ctx.authClient.getChallenge(address, 'ethereum');

      // Sign challenge
      const signature = (await provider.request({
        method: 'personal_sign',
        params: [challenge, address],
      })) as string;

      // Exchange for credentials via bridge (creates user under developer account)
      const result = await ctx.authClient.authBridgeWalletLogin(
        appId,
        clientKey,
        address,
        signature,
        nonce,
        Math.floor(Date.now() / 1000),
      );

      ctx.setCredentials(result.access_key_id, result.secret_access_key);
      ctx.setJwt(result.jwt);
      ctx.setUser({
        id: result.user_name, // stable IAM userName — used for DB name + owner_id tagging
        createdAt: new Date(),
        linkedAccounts: [{ type: 'wallet', address }],
        wallet: {
          address,
          walletClientType: 'external',
          connectorType: 'injected',
        },
      });
    },
    [ctx],
  );

  return {
    ready: ctx.ready,
    authenticated: ctx.authenticated,
    user: ctx.user,
    login,
    logout: async () => {
      ctx.sidecar?.stop();
      ctx.setJwt('');
      ctx.setUser(null as unknown as NonNullable<QkmsContextValue['user']>);
      // Clear persisted session
      if (typeof localStorage !== 'undefined') {
        localStorage.removeItem(`qkms-session-${ctx.appId}`);
      }
    },
    exportWallet: UNSUPPORTED('exportWallet'),
    unlinkEmail: UNSUPPORTED('unlinkEmail'),
    unlinkPhone: UNSUPPORTED('unlinkPhone'),
    unlinkWallet: UNSUPPORTED('unlinkWallet'),
    unlinkGoogle: UNSUPPORTED('unlinkGoogle'),
    unlinkApple: UNSUPPORTED('unlinkApple'),
    unlinkTwitter: UNSUPPORTED('unlinkTwitter'),
    unlinkDiscord: UNSUPPORTED('unlinkDiscord'),
    unlinkGithub: UNSUPPORTED('unlinkGithub'),
    unlinkLinkedIn: UNSUPPORTED('unlinkLinkedIn'),
    unlinkTiktok: UNSUPPORTED('unlinkTiktok'),
    unlinkFarcaster: UNSUPPORTED('unlinkFarcaster'),
    unlinkTelegram: UNSUPPORTED('unlinkTelegram'),
    unlinkPasskey: UNSUPPORTED('unlinkPasskey'),
  };
}

export { useQkms as usePrivy };
