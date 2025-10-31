use bip39::Mnemonic;
use serde::{Deserialize, Serialize};

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

pub struct SecureMnemonic {
    pub mnemonic: Mnemonic,
}

impl Drop for SecureMnemonic {
    fn drop(&mut self) {
        // mnemonic zeroization handled internally by bip39
    }
}

impl SecureMnemonic {
    pub fn new(mnemonic: Mnemonic) -> Self {
        Self { mnemonic }
    }

    pub fn phrase(&self) -> String {
        self.mnemonic.phrase().to_string()
    }

    pub fn to_seed(&self, password: &str) -> Vec<u8> {
        use bip39::Seed;
        Seed::new(&self.mnemonic, password).as_bytes().to_vec()
    }
}
