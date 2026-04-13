// QkmsRpcClient unit tests.
//
// These tests validate request construction and error handling without
// hitting a real QKMS server. We mock `globalThis.fetch` to capture
// the outgoing requests and return canned responses.
//
// Run:  npx tsx --test packages/core/src/client.test.ts

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { QkmsRpcClient, QkmsRpcError } from './client.js';

// ---- Fetch mock infrastructure ----

interface CapturedRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
}

let captured: CapturedRequest[] = [];
let mockResponse: { status: number; body: string } = { status: 200, body: '{}' };
const originalFetch = globalThis.fetch;

function installFetchMock(): void {
  captured = [];
  // @ts-ignore — mock fetch
  globalThis.fetch = async (url: string | URL | Request, init?: RequestInit) => {
    const headers: Record<string, string> = {};
    if (init?.headers instanceof Headers) {
      init.headers.forEach((v, k) => {
        headers[k] = v;
      });
    }
    const body = init?.body
      ? new TextDecoder().decode(init.body as Uint8Array)
      : '';

    captured.push({
      url: typeof url === 'string' ? url : url.toString(),
      method: init?.method ?? 'GET',
      headers,
      body,
    });

    return new Response(mockResponse.body, {
      status: mockResponse.status,
      headers: { 'content-type': 'application/json' },
    });
  };
}

function restoreFetch(): void {
  globalThis.fetch = originalFetch;
}

// ---- Tests ----

describe('QkmsRpcClient', () => {
  beforeEach(() => {
    mockResponse = { status: 200, body: '{}' };
    installFetchMock();
  });

  afterEach(() => {
    restoreFetch();
  });

  it('constructs with valid config', () => {
    const client = new QkmsRpcClient({
      server: 'https://kms.example.com',
      accessKey: 'AKID',
      secretKey: 'SK',
    });
    assert.ok(client);
  });

  it('rejects missing server', () => {
    assert.throws(
      () => new QkmsRpcClient({ server: '', accessKey: 'AK', secretKey: 'SK' }),
      /server/,
    );
  });

  it('strips trailing slashes from server URL', async () => {
    const client = new QkmsRpcClient({
      server: 'https://kms.example.com///',
      accessKey: 'AKID',
      secretKey: 'SK',
    });

    await client.listTasks();
    assert.equal(captured[0]!.url, 'https://kms.example.com/');
  });

  it('sets correct X-Amz-Target header for each method', async () => {
    const client = new QkmsRpcClient({
      server: 'https://kms.example.com',
      accessKey: 'AKID',
      secretKey: 'SK',
    });

    await client.listTasks();
    assert.equal(captured[0]!.headers['x-amz-target'], 'TrentService.ListTasks');

    await client.createKey({ KeySpec: 'ECC_NIST_P256' });
    assert.equal(captured[1]!.headers['x-amz-target'], 'TrentService.CreateKey');

    await client.sign({ KeyId: 'k1', Message: 'bXNn' });
    assert.equal(captured[2]!.headers['x-amz-target'], 'TrentService.Sign');

    await client.getPublicKey({ KeyId: 'k1' });
    assert.equal(captured[3]!.headers['x-amz-target'], 'TrentService.GetPublicKey');
  });

  it('sends POST with JSON content-type', async () => {
    const client = new QkmsRpcClient({
      server: 'https://kms.example.com',
      accessKey: 'AKID',
      secretKey: 'SK',
    });

    await client.listTasks();
    assert.equal(captured[0]!.method, 'POST');
    assert.equal(captured[0]!.headers['content-type'], 'application/json');
  });

  it('includes SigV4 Authorization header', async () => {
    const client = new QkmsRpcClient({
      server: 'https://kms.example.com',
      accessKey: 'AKID',
      secretKey: 'SK',
    });

    await client.listTasks();
    const auth = captured[0]!.headers['authorization'];
    assert.ok(auth, 'Authorization header should be present');
    assert.ok(auth.startsWith('AWS4-HMAC-SHA256'), 'Should use AWS4-HMAC-SHA256');
    assert.ok(auth.includes('Credential=AKID/'), 'Should include access key in credential');
    assert.ok(auth.includes('/kms/'), 'Service should be kms');
  });

  it('includes x-amz-date header', async () => {
    const client = new QkmsRpcClient({
      server: 'https://kms.example.com',
      accessKey: 'AKID',
      secretKey: 'SK',
    });

    await client.listTasks();
    const amzDate = captured[0]!.headers['x-amz-date'];
    assert.ok(amzDate, 'x-amz-date should be present');
    assert.match(amzDate, /^\d{8}T\d{6}Z$/, 'Should match YYYYMMDDTHHMMSSZ format');
  });

  it('serializes request body as JSON', async () => {
    const client = new QkmsRpcClient({
      server: 'https://kms.example.com',
      accessKey: 'AKID',
      secretKey: 'SK',
    });

    await client.createKey({ KeySpec: 'ECC_NIST_P256', Description: 'test' });
    const body = JSON.parse(captured[0]!.body);
    assert.equal(body.KeySpec, 'ECC_NIST_P256');
    assert.equal(body.Description, 'test');
  });

  it('parses successful JSON responses', async () => {
    mockResponse = {
      status: 200,
      body: JSON.stringify({
        Tasks: [{ TaskId: 't1', Operation: 'Sign', Round: 0 }],
      }),
    };

    const client = new QkmsRpcClient({
      server: 'https://kms.example.com',
      accessKey: 'AKID',
      secretKey: 'SK',
    });

    const result = await client.listTasks();
    assert.equal(result.Tasks.length, 1);
    assert.equal(result.Tasks[0]!.TaskId, 't1');
  });

  it('handles empty 200 responses', async () => {
    mockResponse = { status: 200, body: '' };

    const client = new QkmsRpcClient({
      server: 'https://kms.example.com',
      accessKey: 'AKID',
      secretKey: 'SK',
    });

    const result = await client.listTasks();
    assert.deepEqual(result, {});
  });

  it('throws QkmsRpcError on non-2xx response', async () => {
    mockResponse = {
      status: 400,
      body: JSON.stringify({
        __type: 'NotAuthorizedException',
        message: 'Invalid credentials',
      }),
    };

    const client = new QkmsRpcClient({
      server: 'https://kms.example.com',
      accessKey: 'AKID',
      secretKey: 'SK',
    });

    await assert.rejects(
      () => client.listTasks(),
      (err: unknown) => {
        assert.ok(err instanceof QkmsRpcError);
        assert.equal(err.method, 'ListTasks');
        assert.equal(err.status, 400);
        assert.ok(err.body.includes('NotAuthorizedException'));
        assert.equal(err.name, 'QkmsRpcError');
        return true;
      },
    );
  });

  it('throws QkmsRpcError on 500', async () => {
    mockResponse = { status: 500, body: 'Internal Server Error' };

    const client = new QkmsRpcClient({
      server: 'https://kms.example.com',
      accessKey: 'AKID',
      secretKey: 'SK',
    });

    await assert.rejects(
      () => client.sign({ KeyId: 'k1', Message: 'dGVzdA==' }),
      (err: unknown) => {
        assert.ok(err instanceof QkmsRpcError);
        assert.equal(err.method, 'Sign');
        assert.equal(err.status, 500);
        return true;
      },
    );
  });

  it('uses custom region in credential scope', async () => {
    const client = new QkmsRpcClient({
      server: 'https://kms.eu-west-1.example.com',
      accessKey: 'AKID',
      secretKey: 'SK',
      region: 'eu-west-1',
    });

    await client.listTasks();
    const auth = captured[0]!.headers['authorization'];
    assert.ok(auth.includes('/eu-west-1/kms/'));
  });
});

describe('QkmsRpcError', () => {
  it('has correct name and message format', () => {
    const err = new QkmsRpcError('CreateKey', 403, 'Forbidden');
    assert.equal(err.name, 'QkmsRpcError');
    assert.equal(err.method, 'CreateKey');
    assert.equal(err.status, 403);
    assert.equal(err.body, 'Forbidden');
    assert.ok(err.message.includes('CreateKey'));
    assert.ok(err.message.includes('403'));
  });

  it('is an instance of Error', () => {
    const err = new QkmsRpcError('Sign', 400, 'bad');
    assert.ok(err instanceof Error);
    assert.ok(err instanceof QkmsRpcError);
  });
});
