export interface Metadata {
  version: string;
  createdAt: string;
  lastAccessed?: string;
  addressCount: number;
}

export interface Wallet {
  iv: string;
  content: string;
  tag: string;
  salt: string; // unique salt per wallet
}

export interface Addresses {
  bitcoin: {
    p2pkh: string; // legacy
    p2wpkh: string; // native segwit (bech32)
    p2sh: string; // segwit wrapped
  };
  ethereum: string;
  solana: string;
}
