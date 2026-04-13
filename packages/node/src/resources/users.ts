// users() resource — user management.
//
// Fetches user info from QNZM via the SigV4-authenticated IAM API.
// Requires `qnzmServer` to be configured on QkmsClient.

import { SigV4Signer } from '@quilibrium/qkms-sdk-core';
import type { QkmsClient } from '../client.js';

export interface UserRecord {
  id: string;
  userName: string;
  accountId: string;
  createdAt: number;
  linkedAccounts: Array<Record<string, unknown>>;
}

export class UsersResource {
  constructor(private readonly client: QkmsClient) {}

  async get(did: string): Promise<UserRecord> {
    if (!this.client.opts.qnzmServer) {
      throw new Error('users().get requires qnzmServer in QkmsClient options.');
    }

    // Parse DID: "did:qnzm:<userId>" or just the userName
    const userName = did.startsWith('did:qnzm:') ? did.slice(9) : did;

    // Call QNZM GetUser action via SigV4-authenticated form-encoded POST
    const body = new URLSearchParams({
      Action: 'GetUser',
      UserName: userName,
    }).toString();

    const signer = new SigV4Signer({
      accessKeyId: this.client.opts.appId,
      secretAccessKey: this.client.opts.appSecret,
      region: this.client.opts.region,
    });

    const url = this.client.opts.qnzmServer!;
    const headers = new Headers({
      'content-type': 'application/x-www-form-urlencoded',
    });
    const bodyBytes = new TextEncoder().encode(body);
    await signer.signRequest('POST', url, headers, bodyBytes);

    const res = await fetch(url, {
      method: 'POST',
      headers,
      body: bodyBytes,
    });

    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`QNZM GetUser failed: ${res.status} ${text}`);
    }

    // Parse XML response (simplified — extract key fields)
    const xml = await res.text();
    const userId = extractXmlField(xml, 'UserId') ?? userName;
    const createDate = extractXmlField(xml, 'CreateDate');

    return {
      id: userId,
      userName,
      accountId: this.client.opts.appId,
      createdAt: createDate ? new Date(createDate).getTime() : 0,
      linkedAccounts: [],
    };
  }

  async list(): Promise<{ users: UserRecord[] }> {
    if (!this.client.opts.qnzmServer) {
      return { users: [] };
    }

    const body = new URLSearchParams({ Action: 'ListUsers' }).toString();
    const signer = new SigV4Signer({
      accessKeyId: this.client.opts.appId,
      secretAccessKey: this.client.opts.appSecret,
      region: this.client.opts.region,
    });

    const url = this.client.opts.qnzmServer!;
    const headers = new Headers({
      'content-type': 'application/x-www-form-urlencoded',
    });
    const bodyBytes = new TextEncoder().encode(body);
    await signer.signRequest('POST', url, headers, bodyBytes);

    const res = await fetch(url, { method: 'POST', headers, body: bodyBytes });
    if (!res.ok) return { users: [] };

    const xml = await res.text();
    // Extract user names from <UserName> tags
    const userNames = extractAllXmlFields(xml, 'UserName');
    const users: UserRecord[] = userNames.map((name) => ({
      id: name,
      userName: name,
      accountId: this.client.opts.appId,
      createdAt: 0,
      linkedAccounts: [],
    }));

    return { users };
  }
}

function extractXmlField(xml: string, tag: string): string | null {
  const re = new RegExp(`<${tag}>([^<]*)</${tag}>`);
  const match = re.exec(xml);
  return match?.[1] ?? null;
}

function extractAllXmlFields(xml: string, tag: string): string[] {
  const re = new RegExp(`<${tag}>([^<]*)</${tag}>`, 'g');
  const results: string[] = [];
  let match;
  while ((match = re.exec(xml)) !== null) {
    results.push(match[1]!);
  }
  return results;
}
