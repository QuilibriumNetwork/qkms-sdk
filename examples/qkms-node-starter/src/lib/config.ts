// Configuration sourced from environment, using QNZM credential names.

import 'dotenv/config';

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}

/** QNZM access key id. */
export const QKMS_APP_ID = required('QKMS_APP_ID');

/** QNZM secret key. */
export const QKMS_APP_SECRET = required('QKMS_APP_SECRET');

/** Optional QKMS server URL override. */
export const QKMS_SERVER = process.env.QKMS_SERVER ?? 'https://qkms.quilibrium.com';

/** Filesystem dir for sidecar key shares + identity. */
export const QKMS_DATA_DIR = process.env.QKMS_DATA_DIR ?? './qkms-sdk-data';

/** Treasury wallet id used by send_usdc handler. */
export const TREASURY_WALLET_ID = process.env.TREASURY_WALLET_ID ?? '';

/** Treasury wallet address (for pay_with_usdc handler). */
export const TREASURY_WALLET_ADDRESS = process.env.TREASURY_WALLET_ADDRESS ?? '';

/** Owner identifier used as a tag on treasury wallet. */
export const TREASURY_OWNER_ID = process.env.TREASURY_OWNER_ID ?? '';

/** Policy ID for the USDC allowlist. */
export const ALLOWLIST_USDC_POLICY_ID = process.env.ALLOWLIST_USDC_POLICY_ID ?? '';

/** Public key (sidecar id) used as the second member of the 2-of-2 quorum. */
export const TREASURY_QUORUM_PUBLIC_KEY = process.env.TREASURY_QUORUM_PUBLIC_KEY ?? '';

/** Optional Base Sepolia RPC URL. */
export const BASE_SEPOLIA_RPC = process.env.BASE_SEPOLIA_RPC ?? 'https://sepolia.base.org';
