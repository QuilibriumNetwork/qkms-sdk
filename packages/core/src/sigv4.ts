// AWS Signature Version 4 signer for QKMS RPC requests.
//
// Direct port of qkms/cmd/mpc-sidecar/sigv4.go (Go reference, lines 1-223).
// The wire format must match byte-for-byte: QKMS server hands the canonical
// request to QNZM (qnzm/internal/api/internal_handlers.go) which rebuilds and
// compares signatures. Any divergence here produces "Request is missing
// required authentication parameters" 400 responses.
//
// Service constants:
//   algorithm     = "AWS4-HMAC-SHA256"
//   serviceName   = "kms"
//   signedHeaders = "content-type;host;x-amz-date;x-amz-target"
// These match qkms/cmd/mpc-sidecar/sigv4.go:17-23.

const ALGORITHM = 'AWS4-HMAC-SHA256';
const SERVICE_NAME = 'kms';
const SIGNED_HEADERS = 'content-type;host;x-amz-date;x-amz-target';
const TERMINATION_KEY = 'aws4_request';

/** Cross-platform crypto subtle access (browser + Node 16+). */
function getSubtle(): SubtleCrypto {
  // Node 20+ exposes globalThis.crypto.subtle. Browser exposes window.crypto.subtle.
  // We avoid `node:crypto` so this file is bundle-able for the browser.
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c?.subtle) {
    throw new Error('Web Crypto API (crypto.subtle) is not available in this environment');
  }
  return c.subtle;
}

const textEncoder = new TextEncoder();

function toHex(bytes: Uint8Array | ArrayBuffer): string {
  const view = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes;
  let s = '';
  for (let i = 0; i < view.length; i++) {
    s += view[i]!.toString(16).padStart(2, '0');
  }
  return s;
}

// `as BufferSource` casts are needed because TS 5.7+ types Uint8Array as
// `Uint8Array<ArrayBufferLike>` (covering SharedArrayBuffer) while Web Crypto
// signatures still require `ArrayBufferView<ArrayBuffer>`. The runtime values
// are always plain ArrayBuffer-backed, so the cast is sound.

async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const subtle = getSubtle();
  const buf = typeof data === 'string' ? textEncoder.encode(data) : data;
  const digest = await subtle.digest('SHA-256', buf as BufferSource);
  return toHex(digest);
}

async function hmacSha256(key: Uint8Array, data: Uint8Array | string): Promise<Uint8Array> {
  const subtle = getSubtle();
  const cryptoKey = await subtle.importKey(
    'raw',
    key as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const buf = typeof data === 'string' ? textEncoder.encode(data) : data;
  const sig = await subtle.sign('HMAC', cryptoKey, buf as BufferSource);
  return new Uint8Array(sig);
}

/** Format a Date as `YYYYMMDDTHHMMSSZ` (Go's "20060102T150405Z"). */
function formatAmzDate(d: Date): string {
  const yyyy = d.getUTCFullYear().toString().padStart(4, '0');
  const mm = (d.getUTCMonth() + 1).toString().padStart(2, '0');
  const dd = d.getUTCDate().toString().padStart(2, '0');
  const hh = d.getUTCHours().toString().padStart(2, '0');
  const mi = d.getUTCMinutes().toString().padStart(2, '0');
  const ss = d.getUTCSeconds().toString().padStart(2, '0');
  return `${yyyy}${mm}${dd}T${hh}${mi}${ss}Z`;
}

/** Format a Date as `YYYYMMDD`. */
function formatDateStamp(d: Date): string {
  const yyyy = d.getUTCFullYear().toString().padStart(4, '0');
  const mm = (d.getUTCMonth() + 1).toString().padStart(2, '0');
  const dd = d.getUTCDate().toString().padStart(2, '0');
  return `${yyyy}${mm}${dd}`;
}

/**
 * RFC 3986 percent-encoding matching AWS SigV4. JS's `encodeURIComponent`
 * leaves a few characters un-encoded that AWS encodes (`!`, `'`, `(`, `)`, `*`)
 * and encodes a space as `+`; AWS uses `%20`.
 */
function awsUrlEncode(s: string): string {
  return encodeURIComponent(s)
    .replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase())
    .replace(/\+/g, '%20');
}

/** Build canonical query string per AWS spec. Mirrors getCanonicalQueryString in qkms/src/handler/sigv4.go. */
function buildCanonicalQueryString(searchParams: URLSearchParams): string {
  const names: string[] = [];
  searchParams.forEach((_v, name) => {
    if (!names.includes(name)) names.push(name);
  });
  names.sort();
  const parts: string[] = [];
  for (const name of names) {
    const values = searchParams.getAll(name).slice().sort();
    for (const v of values) {
      parts.push(`${awsUrlEncode(name)}=${awsUrlEncode(v)}`);
    }
  }
  return parts.join('&');
}

/** Internal: build the canonical request string. Mirrors createCanonicalRequest in sigv4.go. */
async function createCanonicalRequest(
  method: string,
  path: string,
  searchParams: URLSearchParams,
  headers: Headers,
  body: Uint8Array,
): Promise<string> {
  const canonicalUri = path === '' ? '/' : path;
  const canonicalQueryString = buildCanonicalQueryString(searchParams);

  // Canonical headers — exact order from SIGNED_HEADERS.
  const headerOrder = SIGNED_HEADERS.split(';');
  let canonicalHeaders = '';
  for (const h of headerOrder) {
    const value = (headers.get(h) ?? '').trim();
    canonicalHeaders += `${h}:${value}\n`;
  }

  const payloadHash = await sha256Hex(body);

  return [
    method,
    canonicalUri,
    canonicalQueryString,
    canonicalHeaders,
    SIGNED_HEADERS,
    payloadHash,
  ].join('\n');
}

async function createStringToSign(
  amzDate: string,
  credentialScope: string,
  canonicalRequest: string,
): Promise<string> {
  const hashedRequest = await sha256Hex(canonicalRequest);
  return [ALGORITHM, amzDate, credentialScope, hashedRequest].join('\n');
}

async function calculateSignature(
  secretAccessKey: string,
  dateStamp: string,
  region: string,
  stringToSign: string,
): Promise<string> {
  const kDate = await hmacSha256(textEncoder.encode(`AWS4${secretAccessKey}`), dateStamp);
  const kRegion = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, SERVICE_NAME);
  const kSigning = await hmacSha256(kService, TERMINATION_KEY);
  const sig = await hmacSha256(kSigning, stringToSign);
  return toHex(sig);
}

export interface SigV4SignerConfig {
  accessKeyId: string;
  secretAccessKey: string;
  region?: string;
}

/** Signs HTTP requests for the QKMS server. */
export class SigV4Signer {
  private readonly accessKeyId: string;
  private readonly secretAccessKey: string;
  private readonly region: string;

  constructor(cfg: SigV4SignerConfig) {
    if (!cfg.accessKeyId) throw new Error('accessKeyId is required');
    if (!cfg.secretAccessKey) throw new Error('secretAccessKey is required');
    this.accessKeyId = cfg.accessKeyId;
    this.secretAccessKey = cfg.secretAccessKey;
    this.region = cfg.region ?? 'us-east-1';
  }

  /**
   * Adds AWS Signature Version 4 authentication headers to the given request.
   * Mutates the supplied Headers object in place. Mirrors SignRequest in sigv4.go:45.
   *
   * The caller must ensure that:
   * - `headers` already has `x-amz-target` set to e.g. `TrentService.Sign`
   * - `body` is the exact byte sequence that will be sent on the wire
   * - `url` is the absolute request URL
   */
  async signRequest(
    method: string,
    url: string,
    headers: Headers,
    body: Uint8Array,
  ): Promise<void> {
    const t = new Date();
    const amzDate = formatAmzDate(t);
    const dateStamp = formatDateStamp(t);

    const parsed = new URL(url);

    headers.set('x-amz-date', amzDate);
    if (!headers.has('content-type')) {
      headers.set('content-type', 'application/json');
    }
    if (!headers.has('host')) {
      headers.set('host', parsed.host);
    }

    const canonicalRequest = await createCanonicalRequest(
      method.toUpperCase(),
      parsed.pathname || '/',
      parsed.searchParams,
      headers,
      body,
    );

    const credentialScope = `${dateStamp}/${this.region}/${SERVICE_NAME}/${TERMINATION_KEY}`;
    const stringToSign = await createStringToSign(amzDate, credentialScope, canonicalRequest);
    const signature = await calculateSignature(
      this.secretAccessKey,
      dateStamp,
      this.region,
      stringToSign,
    );

    const authHeader = `${ALGORITHM} Credential=${this.accessKeyId}/${credentialScope}, SignedHeaders=${SIGNED_HEADERS}, Signature=${signature}`;
    headers.set('authorization', authHeader);
  }
}
