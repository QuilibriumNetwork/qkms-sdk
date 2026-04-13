// Creates a wallet owned by a 2-of-2 key quorum, composed of the public key
// provided by the caller and the treasury public key. This translates to a
// CreateKey with two participants.
//
// curl -X POST http://localhost:3300/key_quorums/create_wallet \
//   -H "Content-Type: application/json" \
//   -d '{"public_key": "0x036CbD..."}'

import type { RequestHandler } from 'express';
import { qkms } from '../../lib/qkms.js';
import { TREASURY_QUORUM_PUBLIC_KEY } from '../../lib/config.js';

export const createWallet: RequestHandler = async (req, res) => {
  const { public_key, alias } = req.body as { public_key?: string; alias?: string };
  if (!public_key) {
    res.status(400).json({ error: 'public_key is required' });
    return;
  }
  if (!TREASURY_QUORUM_PUBLIC_KEY) {
    res.status(500).json({ error: 'TREASURY_QUORUM_PUBLIC_KEY not configured' });
    return;
  }

  try {
    const keyQuorum = await qkms.keyQuorums().create({
      public_keys: [public_key, TREASURY_QUORUM_PUBLIC_KEY],
      authorization_threshold: 2,
      display_name: `Treasury 2-of-2 Key Quorum${alias ? ' with ' + alias : ''}`,
    });

    const wallet = await qkms.wallets().create({
      chain_type: 'ethereum',
      owner_id: keyQuorum.id,
    });

    res.status(200).json({ wallet_id: wallet.id, address: wallet.address });
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : String(err) });
  }
};
