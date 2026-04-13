// keyQuorums() resource — n-of-m key quorum management.
//
// A key quorum is an n-of-m public-key authorization construct: a wallet
// owned by a quorum requires `authorization_threshold` signatures from the
// quorum's `public_keys` to authorize any operation.
//
// QKMS's native equivalent is a threshold key created via `CreateKey` with
// an explicit participants list — exactly the t-of-n DKG flow that
// DKLs23Session drives. We map keyQuorums().create() onto a CreateKey call
// with the participants set, and treat the returned QKMS KeyId as the quorum id.

import type { QkmsClient } from '../client.js';

export interface CreateKeyQuorumRequest {
  /** Sidecar identity public keys (or QNZM access keys) that participate in the quorum. */
  public_keys: string[];
  /** Threshold — minimum number of signers required to authorize. */
  authorization_threshold: number;
  /** Display name stored as a tag on the underlying QKMS key. */
  display_name: string;
}

export interface CreateKeyQuorumResponse {
  id: string;
  public_keys: string[];
  authorization_threshold: number;
  display_name: string;
}

export class KeyQuorumsResource {
  constructor(private readonly client: QkmsClient) {}

  async create(req: CreateKeyQuorumRequest): Promise<CreateKeyQuorumResponse> {
    if (!req.public_keys || req.public_keys.length === 0) {
      throw new Error('keyQuorums().create: public_keys must be non-empty');
    }
    if (req.authorization_threshold < 1 || req.authorization_threshold > req.public_keys.length) {
      throw new Error(
        `keyQuorums().create: authorization_threshold ${req.authorization_threshold} out of range`,
      );
    }

    await this.client.ensureStarted();

    // Map the quorum onto a threshold ECDSA key. The participants list tells
    // QKMS which sidecars must hold a share — the t-of-n DKG runs across all
    // of them. Currently supports threshold ECDSA; other signing schemes
    // (BLS, FROST, RSA) require additional key spec support.
    const createRes = await this.client.rpcClient.createKey({
      KeySpec: 'ECC_SECG_P256K1',
      KeyUsage: 'SIGN_VERIFY',
      Origin: 'AWS_KMS',
      Description: req.display_name,
      Tags: [
        { TagKey: 'kind', TagValue: 'key_quorum' },
        { TagKey: 'display_name', TagValue: req.display_name },
        { TagKey: 'authorization_threshold', TagValue: String(req.authorization_threshold) },
      ],
      Participants: req.public_keys,
      Threshold: req.authorization_threshold,
    });

    return {
      id: createRes.KeyMetadata.KeyId,
      public_keys: req.public_keys,
      authorization_threshold: req.authorization_threshold,
      display_name: req.display_name,
    };
  }
}
