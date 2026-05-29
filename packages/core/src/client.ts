// Typed wrappers around QKMS's AWS-KMS-style RPC surface.
//
// Each public method corresponds to a `TrentService.<Method>` call. The wire
// format is:
//   POST {server}/
//   X-Amz-Target: TrentService.<Method>
//   Authorization: AWS4-HMAC-SHA256 ...
//   Content-Type: application/json
//   <JSON body>
//
// QKMS server delegates SigV4 validation to QNZM (see
// qkms/src/handler/request_handler.go:90-220). Validation failures surface as
// HTTP 400 with body `{"__type":"NotAuthorizedException","message":"..."}`.

import { SigV4Signer } from './sigv4.js';
import type { QkmsClientConfig, QkmsTask } from './types.js';

/** Subset of TrentService method names we use. */
export type TrentServiceMethod =
  // Identity
  | 'RegisterSidecar'
  | 'GetSidecar'
  // Tasks
  | 'ListTasks'
  | 'ListTasksForSidecar'
  | 'ClaimTask'
  | 'UpdateTask'
  | 'SendPartyMessage'
  | 'GetPartyMessages'
  // Keys
  | 'CreateKey'
  | 'Sign'
  | 'Verify'
  | 'Encrypt'
  | 'Decrypt'
  | 'GetPublicKey'
  | 'DescribeKey'
  | 'ListKeys'
  | 'GenerateRandom'
  | 'ImportKeyMaterial'
  | 'ScheduleKeyDeletion';

export interface RegisterSidecarRequest {
  SidecarId: string;
  IdentityKey: string; // hex
  SignedPreKey: string; // hex
  PreKeySignature: string; // hex
  SigningKey: string; // hex (Ed448 public)
}

export interface RegisterSidecarResponse {
  SidecarId: string;
  Status: string;
}

export interface ListTasksRequest {
  Limit?: number;
  IncludeTerminal?: boolean;
}

export interface ListTasksResponse {
  Tasks: QkmsTask[];
}

export interface ListTasksForSidecarRequest {
  SidecarId: string;
  Limit?: number;
  IncludeTerminal?: boolean;
}

export interface ClaimTaskRequest {
  TaskId: string;
  SidecarId: string;
}

export interface ClaimTaskResponse {
  TaskId: string;
  SidecarId: string;
  Claimed: boolean;
  Message?: string;
}

export interface UpdateTaskRequest {
  TaskId: string;
  /** Opaque client contribution as a JSON object — matches the Go sidecar wire format. */
  ClientData: unknown;
}

export interface UpdateTaskResponse {
  Status?: string;
}

export interface SendPartyMessageRequest {
  TaskId: string;
  Round: number;
  FromParty: number;
  ToParty: number;
  Ciphertext: string; // base64
  FromSidecarId: string;
  ToSidecarId: string;
}

export interface GetPartyMessagesRequest {
  TaskId: string;
  Round: number;
  PartyId: number;
}

export interface GetPartyMessagesResponse {
  Messages: Array<{
    FromParty: number;
    ToParty: number;
    Ciphertext: string;
    FromSidecarId: string;
  }>;
}

export interface CreateKeyRequest {
  KeySpec: string;
  KeyUsage?: string;
  Origin?: string;
  Description?: string;
  Tags?: Array<{ TagKey: string; TagValue: string }>;
  Participants?: string[];
  Threshold?: number;
  /**
   * Total party count (n in t-of-n). If omitted, the server infers it from
   * `Participants.length`, but always sending it avoids the
   * "Participants count doesn't match TotalParties, adjusting" warning.
   */
  TotalParties?: number;
}

export interface CreateKeyResponse {
  KeyMetadata: {
    KeyId: string;
    Arn?: string;
    KeySpec?: string;
    KeyState?: string;
    CreationDate?: number;
  };
}

export interface SignRequest {
  KeyId: string;
  Message: string; // base64
  MessageType?: 'RAW' | 'DIGEST';
  SigningAlgorithm?: string;
}

export interface SignResponse {
  KeyId: string;
  Signature: string; // base64
  SigningAlgorithm: string;
}

export interface GetPublicKeyRequest {
  KeyId: string;
}

export interface GetPublicKeyResponse {
  KeyId: string;
  PublicKey: string; // base64
  KeySpec: string;
  KeyUsage?: string;
  SigningAlgorithms?: string[];
}

/** QKMS RPC client. Construct once per credential pair. */
export class QkmsRpcClient {
  private readonly server: string;
  private readonly signer: SigV4Signer;
  private readonly endpoint: string;

  constructor(config: QkmsClientConfig) {
    if (!config.server) throw new Error('server is required');
    // Trim trailing slashes — Cloudflare canonicalizes "//" with a 301 which
    // breaks SigV4 because Go's http.Client downgrades POST to GET on redirect.
    this.server = config.server.replace(/\/+$/, '');
    this.endpoint = `${this.server}/`;
    this.signer = new SigV4Signer({
      accessKeyId: config.accessKey,
      secretAccessKey: config.secretKey,
      region: config.region,
    });
  }

  /**
   * Generic typed RPC dispatch. Most callers should use the typed wrappers below.
   * `query` lets callers append signed query parameters (e.g. `?async=1` for
   * non-blocking CreateKey). The signer includes the canonical query string
   * in the SigV4 hash so they're authenticated.
   */
  async call<TReq extends object, TRes>(
    method: TrentServiceMethod,
    request: TReq,
    query?: Record<string, string>,
  ): Promise<TRes> {
    const body = new TextEncoder().encode(JSON.stringify(request));
    const headers = new Headers({
      // Match the Go sidecar exactly (qkms/cmd/mpc-sidecar/main.go:4794) so
      // canonical request hashes line up with the QNZM validator.
      'content-type': 'application/json',
      'x-amz-target': `TrentService.${method}`,
    });

    let url = this.endpoint;
    if (query && Object.keys(query).length > 0) {
      const sp = new URLSearchParams(query);
      url = `${this.endpoint}?${sp.toString()}`;
    }

    await this.signer.signRequest('POST', url, headers, body);

    const res = await fetch(url, {
      method: 'POST',
      headers,
      body,
    });

    if (!res.ok) {
      let errBody: string;
      try {
        errBody = await res.text();
      } catch {
        errBody = '<unreadable>';
      }
      throw new QkmsRpcError(method, res.status, errBody);
    }

    // Empty 200 responses (rare) — return empty object cast.
    const text = await res.text();
    if (!text) return {} as TRes;
    return JSON.parse(text) as TRes;
  }

  // ---------------------------------------------------------------------------
  // Identity
  // ---------------------------------------------------------------------------

  registerSidecar(req: RegisterSidecarRequest): Promise<RegisterSidecarResponse> {
    return this.call('RegisterSidecar', req);
  }

  getSidecar(sidecarId: string): Promise<{ SidecarIdentity: RegisterSidecarRequest }> {
    return this.call('GetSidecar', { SidecarId: sidecarId });
  }

  // ---------------------------------------------------------------------------
  // Tasks
  // ---------------------------------------------------------------------------

  listTasks(req: ListTasksRequest = {}): Promise<ListTasksResponse> {
    return this.call('ListTasks', req);
  }

  listTasksForSidecar(req: ListTasksForSidecarRequest): Promise<ListTasksResponse> {
    return this.call('ListTasksForSidecar', req);
  }

  claimTask(req: ClaimTaskRequest): Promise<ClaimTaskResponse> {
    return this.call('ClaimTask', req);
  }

  updateTask(req: UpdateTaskRequest): Promise<UpdateTaskResponse> {
    return this.call('UpdateTask', req);
  }

  sendPartyMessage(req: SendPartyMessageRequest): Promise<Record<string, never>> {
    return this.call('SendPartyMessage', req);
  }

  getPartyMessages(req: GetPartyMessagesRequest): Promise<GetPartyMessagesResponse> {
    return this.call('GetPartyMessages', req);
  }

  // ---------------------------------------------------------------------------
  // Keys
  // ---------------------------------------------------------------------------

  /**
   * Create an MPC-backed key. By default this blocks until DKG completes.
   * Pass `async: true` to make the server return immediately after the task
   * is created — the response carries the new `KeyId` and the caller polls
   * `getPublicKey` (or watches local storage) to detect completion.
   *
   * Async mode is the right shape for browser callers behind CDNs/WAFs
   * whose proxy timeouts would otherwise kill the long-held HTTP socket.
   */
  createKey(req: CreateKeyRequest, opts?: { async?: boolean }): Promise<CreateKeyResponse> {
    const query = opts?.async ? { async: '1' } : undefined;
    return this.call('CreateKey', req, query);
  }

  sign(req: SignRequest): Promise<SignResponse> {
    return this.call('Sign', req);
  }

  getPublicKey(req: GetPublicKeyRequest): Promise<GetPublicKeyResponse> {
    return this.call('GetPublicKey', req);
  }
}

/** Error thrown when a QKMS RPC call returns a non-2xx response. */
export class QkmsRpcError extends Error {
  constructor(
    public readonly method: TrentServiceMethod,
    public readonly status: number,
    public readonly body: string,
  ) {
    super(`QKMS RPC ${method} failed: ${status} ${body}`);
    this.name = 'QkmsRpcError';
  }
}
