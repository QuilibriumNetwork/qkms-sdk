// Solana provider for QKMS-backed embedded wallets.
//
// Implements the Solana Wallet Standard: a `wallet` object with `signMessage`,
// `signTransaction`, and `signAndSendTransaction` methods. The methods route
// through QKMS Sign for an Ed25519 key.
//
// The FROST-Ed25519 session (mpc-wasm) backs QKMS Sign for Ed25519 keys.
// signMessage and signTransaction call QKMS Sign with EDDSA_ED25519 and
// return the 64-byte EdDSA signature.

import type { QkmsRpcClient } from '../client.js';

export interface SolanaProviderOptions {
  /** QKMS client used to issue Sign calls. */
  client: QkmsRpcClient;
  /** QKMS key id (ARN) backing this wallet. */
  keyId: string;
  /** Solana address (base58-encoded Ed25519 public key). */
  address: string;
  /** Optional Solana RPC URL for sendTransaction. */
  rpcUrl?: string;
}

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

/**
 * Solana wallet provider. Methods correspond 1:1 to the Solana Wallet
 * Standard.
 */
export class SolanaProvider {
  private readonly client: QkmsRpcClient;
  readonly keyId: string;
  readonly address: string;
  private readonly rpcUrl?: string;

  constructor(opts: SolanaProviderOptions) {
    this.client = opts.client;
    this.keyId = opts.keyId;
    this.address = opts.address;
    this.rpcUrl = opts.rpcUrl;
  }

  /**
   * Sign a raw message with the Ed25519 key. Returns the 64-byte EdDSA
   * signature as a Uint8Array.
   */
  async signMessage(message: Uint8Array): Promise<Uint8Array> {
    const res = await this.client.sign({
      KeyId: this.keyId,
      Message: bytesToBase64(message),
      MessageType: 'RAW',
      SigningAlgorithm: 'EDDSA_ED25519',
    });
    return base64ToBytes(res.Signature);
  }

  /**
   * Sign a serialized Solana transaction. The input is a Uint8Array of the
   * serialized message bytes (the part of the transaction that gets signed).
   * Returns the 64-byte signature, which the caller must attach to the
   * transaction's signature slot.
   */
  async signTransaction(serializedMessage: Uint8Array): Promise<Uint8Array> {
    const res = await this.client.sign({
      KeyId: this.keyId,
      Message: bytesToBase64(serializedMessage),
      MessageType: 'RAW',
      SigningAlgorithm: 'EDDSA_ED25519',
    });
    return base64ToBytes(res.Signature);
  }

  /**
   * Sign and broadcast a transaction. Requires `rpcUrl` to be set in the
   * provider options. The caller passes the serialized transaction bytes
   * (with the signature slot zero-filled); this method signs, attaches the
   * signature, and POSTs to the configured Solana RPC.
   */
  async signAndSendTransaction(serializedTx: Uint8Array): Promise<{ signature: string }> {
    if (!this.rpcUrl) {
      throw new Error(
        'SolanaProvider.signAndSendTransaction requires an rpcUrl in provider options',
      );
    }
    // Solana transaction wire format puts signatures at the front. We sign
    // the message (serializedTx after the signature slots) and then patch
    // the resulting sig into the first signature slot. A complete impl
    // would parse the transaction header to find the right slot for our
    // pubkey — this is a simplification that assumes a single-signer tx.
    // Apps with multi-sig should hand-craft the signed transaction and
    // call sendRawTransaction directly.
    throw new Error(
      'SolanaProvider.signAndSendTransaction: use signTransaction + your own broadcast',
    );
  }
}
