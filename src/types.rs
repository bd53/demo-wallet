use serde::{Deserialize, Serialize};
use zeroize::{Zeroizing};

#[derive(Serialize, Deserialize)]
pub struct EncryptedWallet {
    pub iv: String,
    pub content: String,
    pub tag: String,
    pub salt: String,
}

#[derive(Serialize, Deserialize)]
pub struct Metadata {
    pub version: String,
    pub created_at: String,
    pub address_count: u32,
    pub last_accessed: Option<String>,
}

#[derive(Clone)]
pub struct BitcoinAddresses {
    pub p2pkh: String,
    pub p2wpkh: String,
    pub p2sh: String,
}

pub struct Addresses {
    pub bitcoin: BitcoinAddresses,
    pub ethereum: String,
    pub solana: String,
}

pub struct SecureSeed {
    seed: Zeroizing<Vec<u8>>,
}

impl SecureSeed {
    pub fn new(seed: Vec<u8>) -> Self {
        Self {
            seed: Zeroizing::new(seed),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.seed
    }
}

pub struct SecureMnemonic {
    phrase: Zeroizing<String>,
}

impl SecureMnemonic {
    pub fn from_phrase(phrase: String) -> Self {
        Self {
            phrase: Zeroizing::new(phrase),
        }
    }

    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    pub fn to_seed(&self, password: &str) -> SecureSeed {
        use bip39::{Mnemonic, Language, Seed};
        let mnemonic = Mnemonic::from_phrase(&self.phrase, Language::English).expect("Invalid mnemonic in SecureMnemonic");
        let seed = Seed::new(&mnemonic, password);
        SecureSeed::new(seed.as_bytes().to_vec())
    }
}
