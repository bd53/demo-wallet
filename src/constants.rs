pub const WALLET_DIR: &str = ".cws";
pub const WALLET_FILE: &str = "wallet.json";
pub const METADATA_FILE: &str = "metadata.json";
pub const SHARES_DIR: &str = ".shares";

pub const PASSWORD_LENGTH: usize = 8;
pub const ACCOUNT_MAX: u32 = 20;

pub const SCRYPT_LOG_N: u8 = 14;
pub const SCRYPT_R: u32 = 8;
pub const SCRYPT_P: u32 = 1;
pub const CIPHERTEXT_MIN: usize = 17;
pub const ENTROPY_SIZE: usize = 32;

pub const MIN_THRESHOLD: u8 = 2;
pub const MAX_THRESHOLD: u8 = 10;
