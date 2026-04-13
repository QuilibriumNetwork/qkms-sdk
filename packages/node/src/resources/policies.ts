// policies() resource — policy management.
//
// When qnzmServer is configured, policies are managed via the QNZM IAM
// API (CreatePolicy, AttachUserPolicy, DetachUserPolicy). Enforcement
// happens server-side in the QNZM middleware — the SDK is a management
// surface, not an enforcement point.
//
// When qnzmServer is NOT configured, falls back to local storage (no
// server-side enforcement).

import { SigV4Signer } from '@quilibrium/qkms-sdk-core';
import type { QkmsClient } from '../client.js';

export interface PolicyRule {
  name: string;
  method: string;
  action: 'ALLOW' | 'DENY';
  conditions: Array<{
    field_source: string;
    field: string;
    operator: string;
    value: string | number | boolean;
  }>;
}

export interface CreatePolicyRequest {
  name: string;
  version: string;
  chain_type: string;
  rules: PolicyRule[];
  owner_id?: string;
}

export interface CreatePolicyResponse {
  id: string;
  name: string;
  version: string;
}

/** AWS IAM-style policy document for QNZM. */
export interface PolicyDocument {
  Version: string;
  Statement: Array<{
    Effect: 'Allow' | 'Deny';
    Action: string | string[];
    Resource: string | string[];
    Condition?: Record<string, Record<string, string>>;
  }>;
}

export interface CreateIAMPolicyRequest {
  policyName: string;
  policyDocument: PolicyDocument;
  description?: string;
}

export interface AttachPolicyRequest {
  policyArn: string;
  userName: string;
}

export class PoliciesResource {
  constructor(private readonly client: QkmsClient) {}

  /**
   * Create a policy. If qnzmServer is configured, creates it via QNZM's
   * CreatePolicy action. Otherwise falls back to local storage.
   */
  async create(req: CreatePolicyRequest): Promise<CreatePolicyResponse> {
    await this.client.ensureStarted();

    if (this.client.opts.qnzmServer) {
      // Convert policy rules to IAM policy document
      const policyDoc = rulesToPolicyDocument(req.rules, req.chain_type);
      const body = new URLSearchParams({
        Action: 'CreatePolicy',
        PolicyName: req.name,
        PolicyDocument: JSON.stringify(policyDoc),
        Description: `chain_type=${req.chain_type}, version=${req.version}`,
      }).toString();

      const xml = await this.callQnzm(body);
      const policyId = extractXmlField(xml, 'PolicyId') ?? req.name;
      return { id: policyId, name: req.name, version: req.version };
    }

    // Fallback: local storage
    const id = `policy-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
    const blob = new TextEncoder().encode(JSON.stringify({ id, ...req }));
    await this.client.storage.put(`policy/${id}`, blob);
    return { id, name: req.name, version: req.version };
  }

  /**
   * Create an IAM-style policy directly on QNZM.
   * This is the lower-level API — use `create()` for higher-level policy rules.
   */
  async createIAMPolicy(req: CreateIAMPolicyRequest): Promise<{ policyArn: string }> {
    if (!this.client.opts.qnzmServer) {
      throw new Error('createIAMPolicy requires qnzmServer in QkmsClient options.');
    }

    const body = new URLSearchParams({
      Action: 'CreatePolicy',
      PolicyName: req.policyName,
      PolicyDocument: JSON.stringify(req.policyDocument),
      ...(req.description ? { Description: req.description } : {}),
    }).toString();

    const xml = await this.callQnzm(body);
    const arn = extractXmlField(xml, 'Arn') ?? '';
    return { policyArn: arn };
  }

  /** Attach a managed policy to a user. */
  async attach(req: AttachPolicyRequest): Promise<void> {
    if (!this.client.opts.qnzmServer) {
      throw new Error('attach requires qnzmServer in QkmsClient options.');
    }

    const body = new URLSearchParams({
      Action: 'AttachUserPolicy',
      UserName: req.userName,
      PolicyArn: req.policyArn,
    }).toString();

    await this.callQnzm(body);
  }

  /** Detach a managed policy from a user. */
  async detach(req: AttachPolicyRequest): Promise<void> {
    if (!this.client.opts.qnzmServer) {
      throw new Error('detach requires qnzmServer in QkmsClient options.');
    }

    const body = new URLSearchParams({
      Action: 'DetachUserPolicy',
      UserName: req.userName,
      PolicyArn: req.policyArn,
    }).toString();

    await this.callQnzm(body);
  }

  private async callQnzm(body: string): Promise<string> {
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
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`QNZM policy operation failed: ${res.status} ${text}`);
    }
    return res.text();
  }
}

/** Convert policy rules to an IAM policy document. */
function rulesToPolicyDocument(rules: PolicyRule[], chainType: string): PolicyDocument {
  const statements = rules.map((rule) => ({
    Effect: (rule.action === 'ALLOW' ? 'Allow' : 'Deny') as 'Allow' | 'Deny',
    Action: mapMethodToKmsAction(rule.method),
    Resource: `arn:aws:kms:*:*:key/*`,
    ...(chainType !== '*' ? {
      Condition: { StringEquals: { 'kms:KeySpec': chainTypeToKeySpec(chainType) } },
    } : {}),
  }));

  return { Version: '2012-10-17', Statement: statements };
}

function mapMethodToKmsAction(method: string): string {
  switch (method.toLowerCase()) {
    case 'sign': return 'kms:Sign';
    case 'create': case 'createkey': return 'kms:CreateKey';
    case 'encrypt': return 'kms:Encrypt';
    case 'decrypt': return 'kms:Decrypt';
    case 'delete': return 'kms:ScheduleKeyDeletion';
    default: return `kms:${method}`;
  }
}

function chainTypeToKeySpec(chainType: string): string {
  switch (chainType.toLowerCase()) {
    case 'ethereum': return 'ECC_SECG_P256K1';
    case 'solana': return 'ECC_ED25519';
    default: return '*';
  }
}

function extractXmlField(xml: string, tag: string): string | null {
  const re = new RegExp(`<${tag}>([^<]*)</${tag}>`);
  const match = re.exec(xml);
  return match?.[1] ?? null;
}
