// Auth bridge types for QNZM wallet login and JWT verification.

export interface JWTClaims {
  uid: string;    // userId
  aid: string;    // accountId
  unm: string;    // userName
  app?: string;   // appId (optional)
  iss: string;    // issuer
  exp: number;    // expiration (unix seconds)
  iat: number;    // issued at (unix seconds)
}

export interface AuthChallenge {
  challenge: string;
  nonce: string;
  expires_at: number;
}

export interface WalletLoginRequest {
  address: string;
  signature: string;
  nonce: string;
  timestamp: number;
  signature_type: 'ethereum' | 'quilibrium';
}

export interface WalletLoginResponse {
  jwt: string;
  access_key_id: string;
  secret_access_key: string;
  account_id: string;
  user_id: string;
  user_name: string;
  is_new_account: boolean;
}

export interface JsonWebKeySet {
  keys: JsonWebKey[];
}

export interface QnzmAuthConfig {
  /** QNZM server base URL, e.g. "https://qnzm.quilibrium.com" */
  qnzmServer: string;
}
