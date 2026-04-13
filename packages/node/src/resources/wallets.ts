// wallets() resource — wallet management.
//
// create() returns a `wallet_id` (mapped 1:1 onto a QKMS key id / ARN) which
// is later used as the first argument to ethereum().sendTransaction(walletId, ...).
// The owner_id field becomes a tag on the QKMS key for ACL bookkeeping.

import {
  EthereumProvider,
  evmChecksumAddressFromPublicKey,
  solanaAddressFromPublicKey,
} from '@quilibrium/qkms-sdk-core';
import type { QkmsClient } from '../client.js';

export interface CreateWalletRequest {
  chain_type: 'ethereum' | 'solana' | string;
  /** Owner identifier — typically a key quorum id from keyQuorums().create. Stored as a QKMS tag. */
  owner_id?: string;
}

export interface WalletRecord {
  id: string;
  address: string;
  chain_type: string;
  owner_id?: string;
}

export type CreateWalletResponse = WalletRecord;

export interface AuthorizationContext {
  user_jwts?: string[];
  authorization_private_keys?: string[];
}

/**
 * CAIP2 + nested-params shape for ethereum().sendTransaction. The inner
 * `transaction` object follows EIP-1559 / legacy field naming with
 * snake_case (`chain_id`).
 */
export interface EthereumTransactionParams {
  chain_id?: number;
  to?: string;
  data?: string;
  value?: string | number | bigint;
  gas?: string | number | bigint;
  gas_limit?: string | number | bigint;
  gas_price?: string | number | bigint;
  max_fee_per_gas?: string | number | bigint;
  max_priority_fee_per_gas?: string | number | bigint;
  nonce?: string | number;
}

export interface SendEthereumTransactionRequest {
  /** CAIP-2 chain reference, e.g. "eip155:84532" for Base Sepolia. */
  caip2: string;
  params: {
    transaction: EthereumTransactionParams;
  };
  authorization_context?: AuthorizationContext;
}

export interface SendEthereumTransactionResponse {
  hash: string;
}

export interface UpdateWalletRequest {
  additional_signers?: Array<{ signer_id: string; override_policy_ids?: string[] }>;
  authorization_context?: AuthorizationContext;
}

function base64ToBytes(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

function caip2ToChainId(caip2: string): number {
  // Format: "eip155:<chainId>"
  const m = /^eip155:(\d+)$/.exec(caip2);
  if (!m) throw new Error(`unsupported CAIP2: ${caip2}`);
  return parseInt(m[1]!, 10);
}

/**
 * Wait until the QKMS key has a public key available. Used after CreateKey
 * to give the in-process sidecar time to drive DKG to completion.
 */
async function waitForPublicKey(
  client: QkmsClient,
  keyId: string,
  timeoutMs = 60_000,
  intervalMs = 500,
): Promise<Uint8Array> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown = null;
  while (Date.now() < deadline) {
    try {
      const res = await client.rpcClient.getPublicKey({ KeyId: keyId });
      if (res.PublicKey) return base64ToBytes(res.PublicKey);
    } catch (e) {
      lastError = e;
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(
    `wallets().create: timed out waiting for DKG completion${lastError ? `: ${String(lastError)}` : ''}`,
  );
}

export class WalletsResource {
  constructor(private readonly client: QkmsClient) {}

  async create(req: CreateWalletRequest): Promise<CreateWalletResponse> {
    const chainType = req.chain_type;
    if (chainType !== 'ethereum' && chainType !== 'solana') {
      throw new Error(
        `wallets().create: chain_type "${chainType}" not supported (use "ethereum" or "solana")`,
      );
    }
    await this.client.ensureStarted();

    const keySpec = chainType === 'solana' ? 'ECC_ED25519' : 'ECC_SECG_P256K1';
    const tags: Array<{ TagKey: string; TagValue: string }> = [];
    if (req.owner_id) {
      tags.push({ TagKey: 'owner_id', TagValue: req.owner_id });
    }
    tags.push({ TagKey: 'chain_type', TagValue: chainType });

    const createRes = await this.client.rpcClient.createKey({
      KeySpec: keySpec,
      KeyUsage: 'SIGN_VERIFY',
      Origin: 'AWS_KMS',
      Tags: tags,
    });
    const keyId = createRes.KeyMetadata.KeyId;

    const timeoutMs = chainType === 'solana' ? 120_000 : 60_000;
    const publicKey = await waitForPublicKey(this.client, keyId, timeoutMs);
    const address = chainType === 'solana'
      ? solanaAddressFromPublicKey(publicKey)
      : evmChecksumAddressFromPublicKey(publicKey);

    return {
      id: keyId,
      address,
      chain_type: chainType,
      owner_id: req.owner_id,
    };
  }

  async get(walletId: string): Promise<WalletRecord> {
    await this.client.ensureStarted();
    const desc = (await this.client.rpcClient.call('DescribeKey', {
      KeyId: walletId,
    })) as { KeyMetadata?: { KeyId: string; Tags?: Array<{ TagKey: string; TagValue: string }> } };
    const tags = desc.KeyMetadata?.Tags ?? [];
    const owner = tags.find((t) => t.TagKey === 'owner_id')?.TagValue;
    const chain = tags.find((t) => t.TagKey === 'chain_type')?.TagValue ?? 'ethereum';

    const pkRes = await this.client.rpcClient.getPublicKey({ KeyId: walletId });
    const pkBytes = base64ToBytes(pkRes.PublicKey);
    const address = chain === 'solana'
      ? solanaAddressFromPublicKey(pkBytes)
      : evmChecksumAddressFromPublicKey(pkBytes);

    return { id: walletId, address, chain_type: chain, owner_id: owner };
  }

  async list(): Promise<{ wallets: WalletRecord[] }> {
    await this.client.ensureStarted();
    const res = (await this.client.rpcClient.call('ListKeys', {})) as {
      Keys?: Array<{ KeyId: string }>;
    };
    const wallets = await Promise.all(
      (res.Keys ?? []).map(async (k) => {
        try {
          return await this.get(k.KeyId);
        } catch {
          return null;
        }
      }),
    );
    return { wallets: wallets.filter((w): w is WalletRecord => w != null) };
  }

  async update(walletId: string, _req: UpdateWalletRequest): Promise<WalletRecord> {
    // Updating the participants list on a threshold key requires the DKLs23
    // refresh/resize protocol.
    // We surface a clear error so app code fails fast instead of silently
    // no-op'ing.
    throw new Error(
      `wallets().update is not supported in qkms-sdk-node (wallet=${walletId}); requires DKLs23 refresh/resize protocol`,
    );
  }

  ethereum(): EthereumWalletsResource {
    return new EthereumWalletsResource(this.client);
  }

  solana(): SolanaWalletsResource {
    return new SolanaWalletsResource(this.client);
  }
}

/**
 * wallets().ethereum() namespace — Ethereum-specific transaction methods.
 */
export class EthereumWalletsResource {
  constructor(private readonly client: QkmsClient) {}

  /**
   * Sign and broadcast an Ethereum transaction.
   *
   * The `authorization_context` field is currently ignored — sign authority
   * is derived directly from the QNZM credentials passed to QkmsClient.
   */
  async sendTransaction(
    walletId: string,
    req: SendEthereumTransactionRequest,
  ): Promise<SendEthereumTransactionResponse> {
    await this.client.ensureStarted();

    const chainId = caip2ToChainId(req.caip2);
    const wallet = await new WalletsResource(this.client).get(walletId);

    const rpcUrl = this.client.rpcUrls[req.caip2];
    if (!rpcUrl) {
      throw new Error(
        `sendTransaction: no rpcUrl configured for ${req.caip2}; pass rpcUrls in QkmsClient options`,
      );
    }

    const provider = new EthereumProvider({
      client: this.client.rpcClient,
      keyId: wallet.id,
      address: wallet.address,
      chainId,
      rpcUrl,
    });

    const tx = req.params.transaction;
    const txParams = {
      to: tx.to,
      data: tx.data,
      value: tx.value,
      gas: tx.gas ?? tx.gas_limit,
      gasPrice: tx.gas_price,
      maxFeePerGas: tx.max_fee_per_gas,
      maxPriorityFeePerGas: tx.max_priority_fee_per_gas,
      nonce: tx.nonce,
      chainId: tx.chain_id ?? chainId,
    };

    // If nonce/gas/fees aren't provided, fetch sensible defaults from the RPC.
    const populated = await populateTransaction(provider, wallet.address, txParams);

    const hash = (await provider.request({
      method: 'eth_sendTransaction',
      params: [populated],
    })) as string;

    return { hash };
  }

  /** Sign without broadcasting. Returns the serialized signed transaction. */
  async signTransaction(
    walletId: string,
    req: SendEthereumTransactionRequest,
  ): Promise<{ signed_transaction: string }> {
    await this.client.ensureStarted();
    const chainId = caip2ToChainId(req.caip2);
    const wallet = await new WalletsResource(this.client).get(walletId);
    const rpcUrl = this.client.rpcUrls[req.caip2];

    const provider = new EthereumProvider({
      client: this.client.rpcClient,
      keyId: wallet.id,
      address: wallet.address,
      chainId,
      rpcUrl,
    });

    const tx = req.params.transaction;
    const txParams = {
      to: tx.to,
      data: tx.data,
      value: tx.value,
      gas: tx.gas ?? tx.gas_limit,
      gasPrice: tx.gas_price,
      maxFeePerGas: tx.max_fee_per_gas,
      maxPriorityFeePerGas: tx.max_priority_fee_per_gas,
      nonce: tx.nonce,
      chainId: tx.chain_id ?? chainId,
    };

    const populated = rpcUrl
      ? await populateTransaction(provider, wallet.address, txParams)
      : txParams;

    const signed = (await provider.request({
      method: 'eth_signTransaction',
      params: [populated],
    })) as string;

    return { signed_transaction: signed };
  }
}

/**
 * Fill in nonce, gas, and fee fields by querying the upstream RPC if any
 * field is unset. Mirrors what wagmi/viem does for users.
 */
async function populateTransaction(
  provider: EthereumProvider,
  fromAddress: string,
  tx: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const out: Record<string, unknown> = { ...tx };

  if (out.nonce == null) {
    const nonceHex = (await provider.request({
      method: 'eth_getTransactionCount',
      params: [fromAddress, 'pending'],
    })) as string;
    out.nonce = parseInt(nonceHex, 16);
  }

  if (out.gas == null) {
    try {
      const gasHex = (await provider.request({
        method: 'eth_estimateGas',
        params: [{ from: fromAddress, to: out.to, data: out.data, value: out.value }],
      })) as string;
      out.gas = BigInt(gasHex);
    } catch {
      // Some RPCs reject contracts with no value; fall back to a safe default.
      out.gas = 200_000n;
    }
  }

  if (out.maxFeePerGas == null && out.gasPrice == null) {
    try {
      const feeHex = (await provider.request({
        method: 'eth_gasPrice',
        params: [],
      })) as string;
      // Use legacy gasPrice path — simpler and more compatible than 1559 fee oracles.
      out.gasPrice = BigInt(feeHex);
    } catch {
      // leave undefined; viem will throw a clearer error during serialization
    }
  }

  return out;
}

// ---- Solana transaction methods ----

import { SolanaProvider } from '@quilibrium/qkms-sdk-core';

export interface SignSolanaMessageRequest {
  message: Uint8Array;
  encoding?: 'utf-8' | 'base64';
}

export interface SignSolanaMessageResponse {
  signature: Uint8Array;
}

export interface SendSolanaTransactionRequest {
  transaction: Uint8Array;
  rpc_url?: string;
}

export interface SendSolanaTransactionResponse {
  signature: string;
}

/**
 * wallets().solana() namespace — Solana-specific methods.
 */
export class SolanaWalletsResource {
  constructor(private readonly client: QkmsClient) {}

  /**
   * Sign a raw message with a Solana wallet's Ed25519 key.
   * Returns the 64-byte EdDSA signature.
   */
  async signMessage(
    walletId: string,
    req: SignSolanaMessageRequest,
  ): Promise<SignSolanaMessageResponse> {
    await this.client.ensureStarted();
    const wallet = await new WalletsResource(this.client).get(walletId);
    const provider = new SolanaProvider({
      client: this.client.rpcClient,
      keyId: wallet.id,
      address: wallet.address,
    });
    const signature = await provider.signMessage(req.message);
    return { signature };
  }

  /**
   * Sign a serialized Solana transaction message. Returns the 64-byte
   * signature which the caller attaches to the transaction's signature slot.
   */
  async signTransaction(
    walletId: string,
    req: { transaction: Uint8Array },
  ): Promise<{ signature: Uint8Array }> {
    await this.client.ensureStarted();
    const wallet = await new WalletsResource(this.client).get(walletId);
    const provider = new SolanaProvider({
      client: this.client.rpcClient,
      keyId: wallet.id,
      address: wallet.address,
    });
    const signature = await provider.signTransaction(req.transaction);
    return { signature };
  }
}
