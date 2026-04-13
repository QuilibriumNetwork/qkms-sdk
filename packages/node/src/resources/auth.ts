// auth() resource — JWT verification.
//
// Verifies QNZM-issued JWTs using the Ed25519 public key from the QNZM
// JWKS endpoint. Requires `qnzmServer` to be configured on QkmsClient.

import { QnzmAuthClient } from '@quilibrium/qkms-sdk-core';
import type { QkmsClient } from '../client.js';

export interface VerifyAuthTokenResult {
  userId: string;
  appId: string;
  issuer: string;
  expiration: number;
}

export class AuthResource {
  private authClient: QnzmAuthClient | null = null;

  constructor(private readonly client: QkmsClient) {
    if (client.opts.qnzmServer) {
      this.authClient = new QnzmAuthClient({ qnzmServer: client.opts.qnzmServer });
    }
  }

  async verifyAuthToken(token: string): Promise<VerifyAuthTokenResult> {
    if (!this.authClient) {
      throw new Error(
        'auth().verifyAuthToken requires qnzmServer in QkmsClient options.',
      );
    }

    const claims = await this.authClient.verifyToken(token);
    return {
      userId: claims.uid,
      appId: claims.app ?? this.client.opts.appId,
      issuer: claims.iss,
      expiration: claims.exp,
    };
  }
}
