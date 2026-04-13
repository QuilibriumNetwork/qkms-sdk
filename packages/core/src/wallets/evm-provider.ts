// EIP-1193 provider for QKMS-backed embedded wallets.
//
// This is the integration point for wagmi, viem, ethers, rainbowkit, etc. The
// provider implements the standard `request({method, params})` JSON-RPC
// interface. Signing methods (`personal_sign`, `eth_signTypedData_v4`,
// `eth_signTransaction`, `eth_sendTransaction`, `secp256k1_sign`) are routed
// through QKMS's threshold ECDSA. Read-only RPC (`eth_chainId`, `eth_call`,
// `eth_getBalance`, etc.) falls through to a user-configured upstream RPC.
//
// The `secp256k1_sign` method supports raw 32-byte hash signing (used by smart
// account userops), mapped onto QKMS Sign with MessageType=DIGEST.

import { keccak_256 } from '@noble/hashes/sha3';
import {
  hashTypedData,
  recoverAddress,
  serializeTransaction,
  type Hex as ViemHex,
  type Signature,
  type TransactionSerializable,
  type TypedDataDefinition,
} from 'viem';
import type { QkmsRpcClient } from '../client.js';
import type { EIP1193Provider, Hex } from '../types.js';

export interface EthereumProviderOptions {
  /** QKMS client used to issue Sign/GetPublicKey calls. */
  client: QkmsRpcClient;
  /** QKMS key id (ARN) backing this wallet. */
  keyId: string;
  /** EVM address (with EIP-55 checksum). */
  address: string;
  /** Default chain id for transactions when none is specified. */
  chainId: number;
  /**
   * Upstream RPC URL for read-only methods. If unset, all read methods
   * throw. Most apps inject a public RPC like Alchemy/Infura.
   */
  rpcUrl?: string;
}

const READ_METHODS = new Set([
  'eth_chainId',
  'eth_blockNumber',
  'eth_getBalance',
  'eth_call',
  'eth_estimateGas',
  'eth_gasPrice',
  'eth_maxPriorityFeePerGas',
  'eth_feeHistory',
  'eth_getCode',
  'eth_getStorageAt',
  'eth_getTransactionCount',
  'eth_getBlockByNumber',
  'eth_getBlockByHash',
  'eth_getTransactionByHash',
  'eth_getTransactionReceipt',
  'eth_getLogs',
  'net_version',
]);

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64');
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s);
}

function base64ToBytes(b64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(b64, 'base64'));
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  let h = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (h.length % 2 !== 0) h = '0' + h;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex0x(bytes: Uint8Array): Hex {
  let s = '0x';
  for (let i = 0; i < bytes.length; i++) s += bytes[i]!.toString(16).padStart(2, '0');
  return s as Hex;
}

/**
 * Hash a message according to the EIP-191 personal-sign convention:
 *   keccak256("\x19Ethereum Signed Message:\n" + length(msg) + msg)
 */
function eip191Digest(message: Uint8Array): Uint8Array {
  const prefix = `\x19Ethereum Signed Message:\n${message.length}`;
  const prefixBytes = new TextEncoder().encode(prefix);
  const concat = new Uint8Array(prefixBytes.length + message.length);
  concat.set(prefixBytes, 0);
  concat.set(message, prefixBytes.length);
  return keccak_256(concat);
}

/** Decode a `personal_sign` message argument. Accepts hex (with `0x`) or utf-8 string. */
function decodeMessageArg(raw: unknown): Uint8Array {
  if (typeof raw !== 'string') {
    throw new Error(`personal_sign: expected string message, got ${typeof raw}`);
  }
  if (raw.startsWith('0x')) {
    return hexToBytes(raw);
  }
  return new TextEncoder().encode(raw);
}

/**
 * Coerce viem-style transaction request fields (BigInt, hex strings, etc.)
 * into a `TransactionSerializable` viem can serialize. Mirrors the loose
 * shape that wagmi / web3.js / ethers all hand to wallets via
 * `eth_sendTransaction`.
 */
interface RawTxRequest {
  from?: string;
  to?: string;
  data?: string;
  value?: string | bigint;
  gas?: string | bigint;
  gasLimit?: string | bigint;
  gasPrice?: string | bigint;
  maxFeePerGas?: string | bigint;
  maxPriorityFeePerGas?: string | bigint;
  nonce?: string | number;
  chainId?: string | number;
  type?: string;
  accessList?: unknown[];
}

/**
 * Decode a DER-encoded ECDSA signature into raw 64-byte (r || s).
 * DER format: 30 <len> 02 <rlen> <r-bytes> 02 <slen> <s-bytes>
 * r and s may have a leading 0x00 padding byte if the high bit is set.
 */
function decodeDERSignature(der: Uint8Array): Uint8Array {
  let offset = 0;
  if (der[offset++] !== 0x30) throw new Error('DER sig: expected SEQUENCE');
  offset++; // skip sequence length

  // Read r
  if (der[offset++] !== 0x02) throw new Error('DER sig: expected INTEGER for r');
  const rLen = der[offset++]!;
  let rBytes = der.subarray(offset, offset + rLen);
  offset += rLen;
  // Strip leading zero padding
  if (rBytes.length === 33 && rBytes[0] === 0x00) rBytes = rBytes.subarray(1);

  // Read s
  if (der[offset++] !== 0x02) throw new Error('DER sig: expected INTEGER for s');
  const sLen = der[offset++]!;
  let sBytes = der.subarray(offset, offset + sLen);
  // Strip leading zero padding
  if (sBytes.length === 33 && sBytes[0] === 0x00) sBytes = sBytes.subarray(1);

  // Pad to 32 bytes each (in case they're shorter)
  const raw = new Uint8Array(64);
  raw.set(rBytes, 32 - rBytes.length);
  raw.set(sBytes, 64 - sBytes.length);
  return raw;
}

function coerceBigInt(v: string | bigint | number | undefined): bigint | undefined {
  if (v == null) return undefined;
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number') return BigInt(v);
  if (typeof v === 'string') return BigInt(v);
  return undefined;
}

function coerceNumber(v: string | number | undefined): number | undefined {
  if (v == null) return undefined;
  if (typeof v === 'number') return v;
  if (typeof v === 'string') return v.startsWith('0x') ? parseInt(v, 16) : parseInt(v, 10);
  return undefined;
}

function buildTransactionSerializable(
  raw: RawTxRequest,
  defaultChainId: number,
): TransactionSerializable {
  const chainId = coerceNumber(raw.chainId) ?? defaultChainId;
  const nonce = coerceNumber(raw.nonce);
  const value = coerceBigInt(raw.value);
  const gasField = raw.gas ?? raw.gasLimit;
  const gas = coerceBigInt(gasField);
  const data = (raw.data ?? '0x') as ViemHex;
  const to = raw.to as ViemHex | undefined;

  // Distinguish 1559 vs legacy by presence of fee fields.
  const maxFeePerGas = coerceBigInt(raw.maxFeePerGas);
  const maxPriorityFeePerGas = coerceBigInt(raw.maxPriorityFeePerGas);
  const gasPrice = coerceBigInt(raw.gasPrice);

  if (maxFeePerGas != null || maxPriorityFeePerGas != null || raw.type === '0x2' || raw.type === 'eip1559') {
    return {
      type: 'eip1559',
      chainId,
      nonce: nonce ?? 0,
      to,
      value,
      data,
      gas,
      maxFeePerGas,
      maxPriorityFeePerGas,
      accessList: (raw.accessList as TransactionSerializable extends { accessList?: infer A } ? A : never) ?? undefined,
    } as TransactionSerializable;
  }

  return {
    type: 'legacy',
    chainId,
    nonce: nonce ?? 0,
    to,
    value,
    data,
    gas,
    gasPrice,
  } as TransactionSerializable;
}

export class EthereumProvider implements EIP1193Provider {
  private readonly client: QkmsRpcClient;
  private readonly keyId: string;
  private readonly address: string;
  private readonly chainId: number;
  private readonly rpcUrl?: string;

  constructor(opts: EthereumProviderOptions) {
    this.client = opts.client;
    this.keyId = opts.keyId;
    this.address = opts.address;
    this.chainId = opts.chainId;
    this.rpcUrl = opts.rpcUrl;
  }

  async request(args: { method: string; params?: unknown[] | object }): Promise<unknown> {
    const params = (Array.isArray(args.params) ? args.params : []) as unknown[];

    switch (args.method) {
      case 'eth_chainId':
        return `0x${this.chainId.toString(16)}`;

      case 'eth_accounts':
      case 'eth_requestAccounts':
        return [this.address];

      case 'personal_sign': {
        // params: [message, address]
        const message = decodeMessageArg(params[0]);
        const digest = eip191Digest(message);
        return await this.signDigestWithRecovery(digest);
      }

      case 'eth_sign': {
        // params: [address, message]
        const message = decodeMessageArg(params[1]);
        const digest = eip191Digest(message);
        return await this.signDigestWithRecovery(digest);
      }

      case 'secp256k1_sign': {
        // Raw hash signing. params: [hash]
        const hash = decodeMessageArg(params[0]);
        if (hash.length !== 32) {
          throw new Error(`secp256k1_sign: expected 32-byte hash, got ${hash.length}`);
        }
        return await this.signDigestWithRecovery(hash);
      }

      case 'eth_signTypedData_v4': {
        // params: [address, typedDataJsonOrObject]
        const arg = params[1];
        let typedData: TypedDataDefinition;
        if (typeof arg === 'string') {
          typedData = JSON.parse(arg) as TypedDataDefinition;
        } else if (arg && typeof arg === 'object') {
          typedData = arg as TypedDataDefinition;
        } else {
          throw new Error('eth_signTypedData_v4: expected typed-data object or JSON string');
        }
        const digestHex = hashTypedData(typedData);
        return await this.signDigestWithRecovery(hexToBytes(digestHex));
      }

      case 'eth_signTransaction': {
        const rawTx = (params[0] ?? {}) as RawTxRequest;
        const serialized = await this.signTransaction(rawTx);
        return serialized;
      }

      case 'eth_sendTransaction': {
        const rawTx = (params[0] ?? {}) as RawTxRequest;
        const serialized = await this.signTransaction(rawTx);
        return await this.passthroughRpc('eth_sendRawTransaction', [serialized]);
      }
    }

    if (READ_METHODS.has(args.method)) {
      return await this.passthroughRpc(args.method, params);
    }

    throw new Error(`EthereumProvider: unsupported method ${args.method}`);
  }

  /**
   * Calls QKMS Sign over a 32-byte digest. Returns the raw signature bytes
   * exactly as the server emitted them — caller is responsible for splitting
   * into r/s and computing the recovery byte if needed.
   */
  private async rawSignDigest(digest: Uint8Array): Promise<Uint8Array> {
    if (digest.length !== 32) {
      throw new Error(`signDigest: expected 32-byte digest, got ${digest.length}`);
    }
    const res = await this.client.sign({
      KeyId: this.keyId,
      Message: bytesToBase64(digest),
      MessageType: 'DIGEST',
      SigningAlgorithm: 'ECDSA_SHA_256',
    });
    return base64ToBytes(res.Signature);
  }

  /**
   * Sign a 32-byte digest and return a 65-byte EVM-compatible signature
   * (`r || s || v`) as a `0x`-prefixed hex string.
   *
   * QKMS sometimes returns the raw 64-byte (r || s) form (the dkls23 native
   * shape) and sometimes the full 65-byte form. We tolerate both: when the
   * recovery byte is missing we recompute it by trial recovery against this
   * provider's known address.
   */
  private async signDigestWithRecovery(digest: Uint8Array): Promise<Hex> {
    let sig = await this.rawSignDigest(digest);

    // DER-encoded ECDSA signature: 30 <len> 02 <rlen> <r> 02 <slen> <s>
    // Decode to raw 64-byte (r || s) format.
    if (sig[0] === 0x30 && sig.length > 64) {
      sig = decodeDERSignature(sig);
    }

    if (sig.length === 65) {
      return bytesToHex0x(sig);
    }
    if (sig.length !== 64) {
      throw new Error(`signDigestWithRecovery: unexpected sig length ${sig.length}`);
    }
    const r = sig.subarray(0, 32);
    const s = sig.subarray(32, 64);
    const digestHex = bytesToHex0x(digest);
    for (const yParity of [0, 1] as const) {
      try {
        const recovered = await recoverAddress({
          hash: digestHex as ViemHex,
          signature: {
            r: bytesToHex0x(r) as ViemHex,
            s: bytesToHex0x(s) as ViemHex,
            yParity,
          } satisfies Signature,
        });
        if (recovered.toLowerCase() === this.address.toLowerCase()) {
          const out = new Uint8Array(65);
          out.set(sig, 0);
          out[64] = yParity + 27;
          return bytesToHex0x(out);
        }
      } catch {
        // try the other parity
      }
    }
    throw new Error('signDigestWithRecovery: could not recover v byte from signature');
  }

  /**
   * Build, hash, sign, and serialize an EVM transaction. Returns the
   * fully-signed RLP-encoded transaction as a `0x`-prefixed hex string —
   * suitable for `eth_sendRawTransaction`.
   */
  private async signTransaction(raw: RawTxRequest): Promise<Hex> {
    const tx = buildTransactionSerializable(raw, this.chainId);
    // viem's serializeTransaction without a signature returns the
    // pre-image bytes that get keccak'd to produce the signing digest.
    const unsignedHex = serializeTransaction(tx);
    const digest = keccak_256(hexToBytes(unsignedHex));

    const sig = await this.rawSignDigest(digest);
    let r: Uint8Array;
    let s: Uint8Array;
    let yParity: 0 | 1;

    if (sig.length === 65) {
      r = sig.subarray(0, 32);
      s = sig.subarray(32, 64);
      const v = sig[64]!;
      yParity = (v % 2 === 0 ? 1 : 0) as 0 | 1;
    } else if (sig.length === 64) {
      r = sig.subarray(0, 32);
      s = sig.subarray(32, 64);
      // Compute yParity by trial recovery against our address.
      const digestHex = bytesToHex0x(digest);
      let found: 0 | 1 | null = null;
      for (const candidate of [0, 1] as const) {
        try {
          const recovered = await recoverAddress({
            hash: digestHex as ViemHex,
            signature: {
              r: bytesToHex0x(r) as ViemHex,
              s: bytesToHex0x(s) as ViemHex,
              yParity: candidate,
            } satisfies Signature,
          });
          if (recovered.toLowerCase() === this.address.toLowerCase()) {
            found = candidate;
            break;
          }
        } catch {
          // try other
        }
      }
      if (found == null) {
        throw new Error('signTransaction: could not recover v byte from signature');
      }
      yParity = found;
    } else {
      throw new Error(`signTransaction: unexpected sig length ${sig.length}`);
    }

    const signedHex = serializeTransaction(tx, {
      r: bytesToHex0x(r) as ViemHex,
      s: bytesToHex0x(s) as ViemHex,
      yParity,
    } satisfies Signature);
    return signedHex as Hex;
  }

  private async passthroughRpc(method: string, params: unknown[]): Promise<unknown> {
    if (!this.rpcUrl) {
      throw new Error(`EthereumProvider: ${method} requires an upstream rpcUrl in provider options`);
    }
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
    const res = await fetch(this.rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body,
    });
    if (!res.ok) {
      throw new Error(`upstream RPC ${method} failed: ${res.status} ${await res.text()}`);
    }
    const json = (await res.json()) as { result?: unknown; error?: { message: string } };
    if (json.error) throw new Error(`upstream RPC ${method} error: ${json.error.message}`);
    return json.result;
  }
}
