// Sends 1 USDC from the configured TREASURY_WALLET_ID to the recipient.
//
// curl -X POST http://localhost:3300/transactions/send_usdc \
//   -H "Content-Type: application/json" \
//   -d '{"recipient": "0xFE7EB87dddD8300F0bc52f23bEf41684123E313F"}'

import type { RequestHandler } from 'express';
import { encodeFunctionData, erc20Abi, type Hex } from 'viem';
import { baseSepolia } from 'viem/chains';
import { qkms } from '../../lib/qkms.js';
import { BASE_USDC_ADDRESS } from '../../lib/constants.js';
import { TREASURY_WALLET_ID } from '../../lib/config.js';

export const sendUSDC: RequestHandler = async (req, res) => {
  const { recipient } = req.body as { recipient?: string };
  if (!recipient) {
    res.status(400).json({ error: 'recipient is required' });
    return;
  }
  if (!TREASURY_WALLET_ID) {
    res.status(500).json({ error: 'TREASURY_WALLET_ID not configured' });
    return;
  }

  const encodedData = encodeFunctionData({
    abi: erc20Abi,
    functionName: 'transfer',
    args: [recipient as Hex, 1_000_000n], // 1 USDC (6 decimals)
  });

  try {
    const sentTransaction = await qkms
      .wallets()
      .ethereum()
      .sendTransaction(TREASURY_WALLET_ID, {
        caip2: `eip155:${baseSepolia.id}`,
        params: {
          transaction: {
            chain_id: baseSepolia.id,
            to: BASE_USDC_ADDRESS,
            data: encodedData,
          },
        },
      });
    res.status(200).json({ hash: sentTransaction.hash });
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : String(err) });
  }
};
