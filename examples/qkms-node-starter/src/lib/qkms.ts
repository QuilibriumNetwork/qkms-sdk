// Construct the shared QkmsClient.

import { QkmsClient } from '@quilibrium/qkms-sdk-node';
import { baseSepolia } from 'viem/chains';
import {
  QKMS_APP_ID,
  QKMS_APP_SECRET,
  QKMS_DATA_DIR,
  QKMS_SERVER,
  BASE_SEPOLIA_RPC,
} from './config.js';

export const qkms = new QkmsClient({
  appId: QKMS_APP_ID,
  appSecret: QKMS_APP_SECRET,
  server: QKMS_SERVER,
  dataDir: QKMS_DATA_DIR,
  defaultChainId: baseSepolia.id,
  rpcUrls: {
    [`eip155:${baseSepolia.id}`]: BASE_SEPOLIA_RPC,
  },
});
