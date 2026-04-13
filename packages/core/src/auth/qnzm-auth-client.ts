// QNZM auth bridge client — wallet login + JWT verification.
//
// Talks to the QNZM server's /auth/* and /.well-known/jwks.json endpoints.
// These are public JSON endpoints (no SigV4 required).

import type {
  AuthChallenge,
  JWTClaims,
  JsonWebKeySet,
  QnzmAuthConfig,
  WalletLoginRequest,
  WalletLoginResponse,
} from './types.js';

export class QnzmAuthClient {
  private readonly server: string;
  private cachedJWKS: { keys: CryptoKey[]; fetchedAt: number } | null = null;
  private readonly jwksCacheTTL = 3600_000; // 1 hour

  constructor(config: QnzmAuthConfig) {
    this.server = config.qnzmServer.replace(/\/+$/, '');
  }

  /** Request a login challenge for the given wallet address. */
  async getChallenge(
    address: string,
    signatureType: 'ethereum' | 'quilibrium' = 'ethereum',
  ): Promise<AuthChallenge> {
    const res = await fetch(`${this.server}/auth/challenge`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ address, signature_type: signatureType }),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`QNZM auth challenge failed: ${res.status} ${text}`);
    }
    return (await res.json()) as AuthChallenge;
  }

  /** Exchange a signed challenge for JWT + QNZM credentials. */
  async walletLogin(req: WalletLoginRequest): Promise<WalletLoginResponse> {
    const res = await fetch(`${this.server}/auth/wallet-login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(req),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`QNZM wallet login failed: ${res.status} ${text}`);
    }
    return (await res.json()) as WalletLoginResponse;
  }

  // ---- Auth bridge methods (end-user login under developer account) ----

  /** Send email OTP to an end user. Requires the developer's appId + clientKey. */
  async sendEmailOTP(appId: string, clientKey: string, email: string): Promise<{ sent: boolean }> {
    const res = await fetch(`${this.server}/auth/email-otp/send`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ app_id: appId, client_key: clientKey, email }),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`Email OTP send failed: ${res.status} ${text}`);
    }
    return (await res.json()) as { sent: boolean };
  }

  /** Verify email OTP and get user credentials. */
  async verifyEmailOTP(
    appId: string,
    clientKey: string,
    email: string,
    otp: string,
  ): Promise<WalletLoginResponse> {
    const res = await fetch(`${this.server}/auth/email-otp/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ app_id: appId, client_key: clientKey, email, otp }),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`Email OTP verify failed: ${res.status} ${text}`);
    }
    return (await res.json()) as WalletLoginResponse;
  }

  /**
   * Wallet login bridge — creates a user under the developer's account
   * (NOT a new account). For end-user wallet login.
   */
  async authBridgeWalletLogin(
    appId: string,
    clientKey: string,
    address: string,
    signature: string,
    nonce: string,
    timestamp: number,
    signatureType: 'ethereum' | 'quilibrium' = 'ethereum',
  ): Promise<WalletLoginResponse> {
    const res = await fetch(`${this.server}/auth/wallet-login-bridge`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        app_id: appId,
        client_key: clientKey,
        address,
        signature,
        nonce,
        timestamp,
        signature_type: signatureType,
      }),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`Wallet login bridge failed: ${res.status} ${text}`);
    }
    return (await res.json()) as WalletLoginResponse;
  }

  /** Fetch the JWKS (public keys) for JWT verification. */
  async getJWKS(): Promise<JsonWebKeySet> {
    const res = await fetch(`${this.server}/.well-known/jwks.json`);
    if (!res.ok) {
      throw new Error(`QNZM JWKS fetch failed: ${res.status}`);
    }
    return (await res.json()) as JsonWebKeySet;
  }

  /**
   * Verify a JWT locally using the JWKS public key. Returns decoded claims.
   * Caches the JWKS for 1 hour to avoid repeated fetches.
   */
  async verifyToken(token: string): Promise<JWTClaims> {
    const keys = await this.getCachedKeys();
    if (keys.length === 0) {
      throw new Error('No signing keys available from QNZM JWKS');
    }

    // JWT structure: header.payload.signature (base64url encoded)
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }

    const headerJson = base64UrlDecode(parts[0]!);
    const header = JSON.parse(headerJson) as { alg: string; typ?: string };
    if (header.alg !== 'EdDSA') {
      throw new Error(`Unsupported JWT algorithm: ${header.alg}`);
    }

    // Verify signature
    const data = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
    const signature = base64UrlToBytes(parts[2]!);

    let verified = false;
    for (const key of keys) {
      try {
        verified = await crypto.subtle.verify('Ed25519', key, signature as BufferSource, data as BufferSource);
        if (verified) break;
      } catch {
        continue;
      }
    }

    if (!verified) {
      throw new Error('JWT signature verification failed');
    }

    // Decode and validate claims
    const payloadJson = base64UrlDecode(parts[1]!);
    const claims = JSON.parse(payloadJson) as JWTClaims;

    // SECURITY: Validate expiration
    const now = Math.floor(Date.now() / 1000);
    if (claims.exp && claims.exp < now) {
      throw new Error('JWT has expired');
    }

    // SECURITY: Validate issuer matches QNZM
    if (claims.iss && claims.iss !== 'qnzm') {
      throw new Error(`JWT issuer mismatch: expected "qnzm", got "${claims.iss}"`);
    }

    // SECURITY: Validate required claims are present
    if (!claims.uid || !claims.aid) {
      throw new Error('JWT missing required claims (uid, aid)');
    }

    return claims;
  }

  private async getCachedKeys(): Promise<CryptoKey[]> {
    if (this.cachedJWKS && Date.now() - this.cachedJWKS.fetchedAt < this.jwksCacheTTL) {
      return this.cachedJWKS.keys;
    }

    const jwks = await this.getJWKS();
    const keys: CryptoKey[] = [];

    for (const jwk of jwks.keys) {
      if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && jwk.x) {
        const publicKeyBytes = base64UrlToBytes(jwk.x);
        const key = await crypto.subtle.importKey(
          'raw',
          publicKeyBytes as BufferSource,
          'Ed25519',
          true,
          ['verify'],
        );
        keys.push(key);
      }
    }

    this.cachedJWKS = { keys, fetchedAt: Date.now() };
    return keys;
  }
}

function base64UrlDecode(s: string): string {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = padded.length % 4;
  const full = pad ? padded + '='.repeat(4 - pad) : padded;
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(full, 'base64').toString('utf-8');
  }
  return atob(full);
}

function base64UrlToBytes(s: string): Uint8Array {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = padded.length % 4;
  const full = pad ? padded + '='.repeat(4 - pad) : padded;
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(full, 'base64'));
  }
  const bin = atob(full);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
