// Creates a policy that allows only transactions to the USDC contract.
// When qnzmServer is configured, policies are enforced server-side via QNZM.
// Without it, the policy is stored as JSON for reference.
//
// curl -X POST http://localhost:3300/internal/policies/create_allowlist_usdc

import type { RequestHandler } from 'express';
import { qkms } from '../../../lib/qkms.js';
import { BASE_USDC_ADDRESS } from '../../../lib/constants.js';
import { TREASURY_OWNER_ID } from '../../../lib/config.js';

export const createAllowlistUsdc: RequestHandler = async (_req, res) => {
  try {
    const policy = await qkms.policies().create({
      name: 'Allow list certain smart contracts',
      version: '1.0',
      chain_type: 'ethereum',
      rules: [
        {
          name: 'Allow list USDC',
          method: 'eth_sendTransaction',
          action: 'ALLOW',
          conditions: [
            {
              field_source: 'ethereum_transaction',
              field: 'to',
              operator: 'eq',
              value: BASE_USDC_ADDRESS,
            },
          ],
        },
      ],
      owner_id: TREASURY_OWNER_ID,
    });
    res.status(200).json({ policy_id: policy.id, policy_name: policy.name });
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : String(err) });
  }
};
