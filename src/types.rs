use bip39::{Language, Mnemonic};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize)]
pub struct EncryptedWallet {
    pub iv: String,
    pub content: String,
    pub tag: String,
    pub salt: String,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedData {
    pub iv: String,
    pub content: String,
    pub tag: String,
    pub salt: String,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedShare {
    pub number: u8,
    pub iv: String,
    pub content: String,
    pub tag: String,
    pub salt: String,
}

#[derive(Serialize, Deserialize)]
pub struct SeedlessMarker {
    pub wallet_type: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum WalletType {
    Mnemonic,
    Seedless,
}

#[derive(Serialize, Deserialize)]
pub struct ShamirConfig {
    pub threshold: u8,
    pub total_shares: u8,
}

#[derive(Serialize, Deserialize)]
pub struct Metadata {
    pub version: String,
    pub created_at: String,
    pub address_count: u32,
    pub last_accessed: Option<String>,
    pub wallet_type: WalletType,
    pub shamir_config: Option<ShamirConfig>,
}

#[derive(Serialize, Deserialize)]
pub struct BitcoinAddresses {
    pub p2pkh: String,
    pub p2wpkh: String,
    pub p2sh: String,
}

#[derive(Serialize, Deserialize)]
pub struct Addresses {
    pub bitcoin: BitcoinAddresses,
    pub ethereum: String,
    pub solana: String,
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

    pub fn phrase_zeroizing(&self) -> Zeroizing<String> {
        Zeroizing::new(self.phrase.to_string())
    }

    pub fn to_seed(&self, passphrase: &str) -> SecureSeed {
        let mnemonic = Mnemonic::from_phrase(&self.phrase, Language::English).expect("Invalid mnemonic");
        use k256::sha2::Sha512;
        use pbkdf2::pbkdf2_hmac;
        let entropy = mnemonic.entropy();
        let salt = format!("mnemonic{}", passphrase);
        let mut seed = [0u8; 64];
        pbkdf2_hmac::<Sha512>(entropy, salt.as_bytes(), 2048, &mut seed);
        SecureSeed::new(seed)
    }
}

impl Drop for SecureMnemonic {
    fn drop(&mut self) {
        // zeroizing handles cleanup automatically
    }
}

pub struct SecureSeed {
    seed: Zeroizing<[u8; 64]>,
}

impl SecureSeed {
    pub fn new(seed: [u8; 64]) -> Self {
        Self {
            seed: Zeroizing::new(seed),
        }
    }

    pub fn from_entropy(entropy: &[u8]) -> Self {
        // for seedless wallets, derive a 64-byte seed from 32-byte entropy
        // we'll use the entropy directly as first 32 bytes and HKDF for the rest
        use k256::sha2::{Digest, Sha256};
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&entropy[..32.min(entropy.len())]);
        let mut hasher = Sha256::new();
        hasher.update(entropy);
        hasher.update(b"seedless-wallet-expansion");
        let hash = hasher.finalize();
        seed[32..].copy_from_slice(&hash);
        Self::new(seed)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.seed[..]
    }
}

impl Drop for SecureSeed {
    fn drop(&mut self) {
        // zeroizing handles cleanup automatically
    }
}

impl Zeroize for SecureSeed {
    fn zeroize(&mut self) {
        self.seed.zeroize();
    }
}
