use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm};
use bip39::{Language, Mnemonic, MnemonicType};
use clap::{Parser};
use qrcode::{QrCode, render::unicode};
use scrypt::{password_hash::{SaltString, rand_core::{OsRng, RngCore}}, Params};
use solana_sdk::signature::{Keypair as SolanaKeypair, SeedDerivable, Signer};
use std::{fs::{self, OpenOptions}, io::{Write, Seek, SeekFrom}, path::PathBuf};
use tiny_keccak::{Hasher, Keccak};
use zeroize::{Zeroize, Zeroizing};

mod commands;
mod convert;
mod types;

use commands::Commands;
use types::*;

const WALLET_DIR: &str = ".demo-wallet";
const WALLET_FILE: &str = "wallet.json";
const METADATA_FILE: &str = "metadata.json";
const PASSWORD_LENGTH: usize = 8;
const ACCOUNT_MAX: u32 = 20;
const SCRYPT_LOG_N: u8 = 14;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

#[derive(Parser)]
#[command(name = env!("CARGO_PKG_NAME"), about = env!("CARGO_PKG_DESCRIPTION"), author = env!("CARGO_PKG_AUTHORS"), version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

fn get_wallet_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let home = dirs::home_dir().ok_or("Could not find home directory")?;
    let wallet_dir = home.join(WALLET_DIR);
    if !wallet_dir.exists() {
        fs::create_dir_all(&wallet_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&wallet_dir, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(wallet_dir)
}

fn get_wallet_file() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(get_wallet_dir()?.join(WALLET_FILE))
}

fn get_metadata_file() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(get_wallet_dir()?.join(METADATA_FILE))
}

fn validate_password(password: &str) -> bool {
    if password.is_empty() {
        println!("Password cannot be empty.");
        return false;
    }
    if password.len() < PASSWORD_LENGTH {
        println!("Password must be at least {} characters long.", PASSWORD_LENGTH);
        return false;
    }
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_number = password.chars().any(|c| c.is_numeric());
    let has_symbol = password.chars().any(|c| "!@#$%^&*(),.?\":{}|<>_-\\[]/~`+=;".contains(c));
    if !(has_upper && has_lower && has_number && has_symbol) {
        println!("Password must contain at least one uppercase letter, one lowercase letter, one number, and one special symbol.");
        return false;
    }
    true
}

fn validate_account_index(index: u32) -> bool {
    if index >= ACCOUNT_MAX {
        println!("Account index must be between 0 and {}.", ACCOUNT_MAX - 1);
        return false;
    }
    true
}

fn wallet_exists() -> Result<bool, Box<dyn std::error::Error>> {
    Ok(get_wallet_file()?.exists())
}

fn check_wallet_exists() -> Result<bool, Box<dyn std::error::Error>> {
    if !wallet_exists()? {
        println!("No wallet found. Run `generate` first.");
        return Ok(false);
    }
    Ok(true)
}

fn check_wallet_not_found() -> Result<bool, Box<dyn std::error::Error>> {
    if wallet_exists()? {
        println!("Wallet already exists. Use `delete` first if you want to create a new one.");
        return Ok(false);
    }
    Ok(true)
}

fn encrypt_mnemonic(mnemonic: &str, password: &str) -> Result<EncryptedWallet, Box<dyn std::error::Error>> {
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, 32)?;
    let mut key = Zeroizing::new(vec![0u8; 32]);
    scrypt::scrypt(password.as_bytes(), salt.as_str().as_bytes(), &params, &mut key)?;
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let nonce = &iv.into();
    let ciphertext = cipher.encrypt(nonce, mnemonic.as_bytes()).map_err(|e| format!("Encryption failed: {:?}", e))?;
    let tag_start = ciphertext.len() - 16;
    let content = hex::encode(&ciphertext[..tag_start]);
    let tag = hex::encode(&ciphertext[tag_start..]);
    Ok(EncryptedWallet { iv: hex::encode(iv), content, tag, salt: salt.as_str().to_string() })
}

fn decrypt_mnemonic(wallet: &EncryptedWallet, password: &str) -> Result<SecureMnemonic, Box<dyn std::error::Error>> {
    let params = Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, 32)?;
    let mut key = Zeroizing::new(vec![0u8; 32]);
    scrypt::scrypt(password.as_bytes(), wallet.salt.as_bytes(), &params, &mut key)?;
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let iv = hex::decode(&wallet.iv)?;
    let iv_array: [u8; 12] = iv.as_slice().try_into().map_err(|_| "Invalid IV length")?;
    let nonce = &iv_array.into();
    let content = hex::decode(&wallet.content)?;
    let tag = hex::decode(&wallet.tag)?;
    let mut ciphertext = content;
    ciphertext.extend_from_slice(&tag);
    let plaintext = Zeroizing::new(cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| "Decryption failed. Invalid password or corrupted wallet file.")?);
    let mnemonic_str = std::str::from_utf8(&plaintext)?;
    let _ = Mnemonic::from_phrase(mnemonic_str, Language::English).map_err(|_| "Invalid mnemonic in wallet file")?;
    let secure = SecureMnemonic::from_phrase(mnemonic_str.to_string());
    Ok(secure)
}

fn derive_bitcoin_addresses(seed: &[u8], index: u32) -> Result<BitcoinAddresses, Box<dyn std::error::Error>> {
    use bitcoin::{ Address, Network, NetworkKind, PublicKey, PrivateKey, CompressedPublicKey, bip32::{DerivationPath, Xpriv, ChildNumber}, secp256k1::Secp256k1 };
    let secp = Secp256k1::new();
    let xprv = Xpriv::new_master(Network::Bitcoin, seed)?;
    let path = DerivationPath::from(vec![ChildNumber::from_hardened_idx(44)?, ChildNumber::from_hardened_idx(0)?, ChildNumber::from_hardened_idx(0)?, ChildNumber::from_normal_idx(0)?, ChildNumber::from_normal_idx(index)?]);
    let derived = xprv.derive_priv(&secp, &path)?;
    let network_kind: NetworkKind = Network::Bitcoin.into();
    let private_key = PrivateKey::new(derived.private_key, network_kind);
    let public_key = PublicKey::from_private_key(&secp, &private_key);
    let p2pkh = Address::p2pkh(public_key, Network::Bitcoin).to_string();
    let compressed_pk = CompressedPublicKey::from_private_key(&secp, &private_key).map_err(|e| format!("Failed to create compressed public key: {:?}", e))?;
    let p2wpkh = Address::p2wpkh(&compressed_pk, Network::Bitcoin).to_string();
    let p2sh = Address::p2shwpkh(&compressed_pk, network_kind).to_string();
    Ok(BitcoinAddresses { p2pkh, p2wpkh, p2sh })
}

fn derive_ethereum_address(seed: &[u8], index: u32) -> Result<String, Box<dyn std::error::Error>> {
    use tiny_hderive::bip32::ExtendedPrivKey;
    use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey};
    let path = format!("m/44'/60'/0'/0/{}", index);
    let ext = ExtendedPrivKey::derive(seed, path.as_str()).map_err(|e| format!("HD derivation failed: {:?}", e))?;
    let secret = SecretKey::from_slice(&ext.secret())?;
    let secp = Secp256k1::new();
    let public = PublicKey::from_secret_key(&secp, &secret);
    let public_bytes = public.serialize_uncompressed();
    let mut hasher = Keccak::v256();
    hasher.update(&public_bytes[1..]);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    let address = format!("0x{}", hex::encode(&hash[12..]));
    Ok(address)
}

fn derive_solana_address(seed: &[u8], index: u32) -> Result<(String, Zeroizing<Vec<u8>>), Box<dyn std::error::Error>> {
    use tiny_hderive::bip32::ExtendedPrivKey;
    let path = format!("m/44'/501'/{}'", index);
    let ext = ExtendedPrivKey::derive(seed, path.as_str()).map_err(|e| format!("HD derivation failed: {:?}", e))?;
    let secret_bytes = ext.secret();
    let mut seed_bytes = [0u8; 32];
    seed_bytes.copy_from_slice(&secret_bytes[..32]);
    let keypair = SolanaKeypair::from_seed(&seed_bytes)?;
    let address = keypair.pubkey().to_string();
    let secret_key = Zeroizing::new(keypair.to_bytes().to_vec());
    seed_bytes.zeroize();
    Ok((address, secret_key))
}

fn derive_all_addresses(secure_seed: &SecureSeed, index: u32) -> Result<Addresses, Box<dyn std::error::Error>> {
    let seed = secure_seed.as_bytes();
    let bitcoin = derive_bitcoin_addresses(seed, index)?;
    let ethereum = derive_ethereum_address(seed, index)?;
    let (solana, _secret) = derive_solana_address(seed, index)?;
    Ok(Addresses { bitcoin, ethereum, solana })
}

fn display_addresses(addresses: &Addresses, account: u32) {
    println!("\nWallet Addresses (Account {}):", account);
    println!("\nBitcoin:");
    println!("  Legacy (P2PKH): {}", addresses.bitcoin.p2pkh);
    println!("  Native SegWit: {}", addresses.bitcoin.p2wpkh);
    println!("  Wrapped SegWit: {}", addresses.bitcoin.p2sh);
    println!("\nEthereum: {}", addresses.ethereum);
    println!("\nSolana: {}\n", addresses.solana);
}

fn generate_qr_code(data: &str, label: &str) -> Result<(), Box<dyn std::error::Error>> {
    let code = QrCode::new(data)?;
    let string = code.render::<unicode::Dense1x2>().dark_color(unicode::Dense1x2::Light).light_color(unicode::Dense1x2::Dark).build();
    println!("{}:\n{}", label, string);
    Ok(())
}

fn save_metadata(metadata: &Metadata) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(metadata)?;
    let metadata_file = get_metadata_file()?;
    fs::write(&metadata_file, json)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&metadata_file, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn load_metadata() -> Result<Option<Metadata>, Box<dyn std::error::Error>> {
    let metadata_file = get_metadata_file()?;
    if !metadata_file.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(metadata_file)?;
    let metadata: Metadata = serde_json::from_str(&contents)?;
    Ok(Some(metadata))
}

fn update_metadata(address_count: Option<u32>) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(mut metadata) = load_metadata()? {
        metadata.last_accessed = Some(chrono::Utc::now().to_rfc3339());
        if let Some(count) = address_count {
            metadata.address_count = metadata.address_count.max(count);
        }
        save_metadata(&metadata)?;
    }
    Ok(())
}

fn generate_wallet(password: &str, words: u32) -> Result<(), Box<dyn std::error::Error>> {
    if !validate_password(password) || !check_wallet_not_found()? {
        return Ok(());
    }
    let word_count = match words {
        12 => MnemonicType::Words12,
        24 => MnemonicType::Words24,
        _ => {
            println!("Word count must be 12 or 24");
            return Ok(());
        }
    };
    let mnemonic = Mnemonic::new(word_count, Language::English);
    let phrase = mnemonic.phrase().to_string();
    let secure_mnemonic = SecureMnemonic::from_phrase(phrase.clone());
    let encrypted = encrypt_mnemonic(&phrase, password)?;
    let json = serde_json::to_string_pretty(&encrypted)?;
    let wallet_file = get_wallet_file()?;
    fs::write(&wallet_file, json)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&wallet_file, fs::Permissions::from_mode(0o600))?;
    }
    let metadata = Metadata { version: "2.0".to_string(), created_at: chrono::Utc::now().to_rfc3339(), address_count: 1, last_accessed: None };
    save_metadata(&metadata)?;
    let secure_seed = secure_mnemonic.to_seed("");
    let addresses = derive_all_addresses(&secure_seed, 0)?;
    println!("\nWallet generated successfully.\n");
    println!("Write down your mnemonic phrase and store it securely offline.");
    println!("Use the `mnemonic --reveal` command to view it.\n");
    display_addresses(&addresses, 0);
    println!("Wallet stored in: {}", wallet_file.display());
    println!("Metadata stored in: {}\n", get_metadata_file()?.display());
    Ok(())
}

fn show_wallet(password: &str, account: u32, qr: bool) -> Result<(), Box<dyn std::error::Error>> {
    if !check_wallet_exists()? || !validate_account_index(account) {
        return Ok(());
    }
    let wallet_file = get_wallet_file()?;
    let contents = fs::read_to_string(wallet_file)?;
    let wallet: EncryptedWallet = serde_json::from_str(&contents)?;
    let secure_mnemonic = decrypt_mnemonic(&wallet, password)?;
    let secure_seed = secure_mnemonic.to_seed("");
    let addresses = derive_all_addresses(&secure_seed, account)?;
    update_metadata(None)?;
    display_addresses(&addresses, account);
    if qr {
        generate_qr_code(&addresses.bitcoin.p2wpkh, "Bitcoin")?;
        generate_qr_code(&addresses.ethereum, "Ethereum")?;
        generate_qr_code(&addresses.solana, "Solana")?;
    }
    Ok(())
}

fn derive_multiple_accounts(password: &str, count: u32) -> Result<(), Box<dyn std::error::Error>> {
    if !check_wallet_exists()? {
        return Ok(());
    }
    if count < 1 || count > ACCOUNT_MAX {
        println!("You can only derive between 1 and {} accounts.", ACCOUNT_MAX);
        return Ok(());
    }
    let wallet_file = get_wallet_file()?;
    let contents = fs::read_to_string(wallet_file)?;
    let wallet: EncryptedWallet = serde_json::from_str(&contents)?;
    let secure_mnemonic = decrypt_mnemonic(&wallet, password)?;
    let secure_seed = secure_mnemonic.to_seed("");
    println!("\nDeriving {} account(s)...\n", count);
    for i in 0..count {
        let addresses = derive_all_addresses(&secure_seed, i)?;
        println!("--------------------------------------------------------------");
        println!("Account {}:", i);
        println!("  Bitcoin (SegWit): {}", addresses.bitcoin.p2wpkh);
        println!("  Ethereum: {}", addresses.ethereum);
        println!("  Solana: {}", addresses.solana);
    }
    println!("--------------------------------------------------------------\n");
    update_metadata(Some(count))?;
    Ok(())
}

fn export_mnemonic(password: &str, reveal: bool) -> Result<(), Box<dyn std::error::Error>> {
    if !check_wallet_exists()? {
        return Ok(());
    }
    let wallet_file = get_wallet_file()?;
    let contents = fs::read_to_string(wallet_file)?;
    let wallet: EncryptedWallet = serde_json::from_str(&contents)?;
    let secure_mnemonic = decrypt_mnemonic(&wallet, password)?;
    if !reveal {
        println!("\nMnemonic hidden. Use --reveal to explicitly show it.\n");
        update_metadata(None)?;
        return Ok(());
    }
    println!("\nDo NOT share.\n");
    println!("Your mnemonic phrase:\n{}\n", secure_mnemonic.phrase());
    println!("Write this down on paper and store in a secure location.");
    println!("Never store it digitally, take screenshots, or share it with anyone.\n");
    update_metadata(None)?;
    Ok(())
}

fn export_private_key(password: &str, chain: &str, index: u32, qr: bool) -> Result<(), Box<dyn std::error::Error>> {
    if !check_wallet_exists()? || !validate_account_index(index) {
        return Ok(());
    }
    let wallet_file = get_wallet_file()?;
    let contents = fs::read_to_string(wallet_file)?;
    let wallet: EncryptedWallet = serde_json::from_str(&contents)?;
    let secure_mnemonic = decrypt_mnemonic(&wallet, password)?;
    let secure_seed = secure_mnemonic.to_seed("");
    let privkey = match chain {
        "bitcoin" => {
            use bitcoin::{ Network, bip32::{DerivationPath, Xpriv, ChildNumber}, secp256k1::Secp256k1 };
            let secp = Secp256k1::new();
            let xprv = Xpriv::new_master(Network::Bitcoin, secure_seed.as_bytes())?;
            let path = DerivationPath::from(vec![ChildNumber::from_hardened_idx(44)?, ChildNumber::from_hardened_idx(0)?, ChildNumber::from_hardened_idx(0)?, ChildNumber::from_normal_idx(0)?, ChildNumber::from_normal_idx(index)?]);
            let derived = xprv.derive_priv(&secp, &path)?;
            Zeroizing::new(hex::encode(derived.private_key.secret_bytes()))
        },
        "ethereum" => {
            use tiny_hderive::bip32::ExtendedPrivKey;
            let path = format!("m/44'/60'/0'/0/{}", index);
            let ext = ExtendedPrivKey::derive(secure_seed.as_bytes(), path.as_str()).map_err(|e| format!("HD derivation failed: {:?}", e))?;
            Zeroizing::new(format!("0x{}", hex::encode(ext.secret())))
        },
        "solana" => {
            let (_address, secret_key) = derive_solana_address(secure_seed.as_bytes(), index)?;
            Zeroizing::new(bs58::encode(&*secret_key).into_string())
        },
        _ => {
            return Err(format!("Unsupported chain: {}. Use: bitcoin, ethereum, or solana", chain).into());
        }
    };
    println!("\nDo NOT share.\n");
    println!("{} Private Key (Account {}):\n{}\n", chain.to_uppercase(), index, &*privkey);
    println!("Only import this into trusted wallets on secure devices.\n");
    if qr {
        generate_qr_code(&privkey, "Private Key")?;
    }
    update_metadata(None)?;
    Ok(())
}

fn restore_wallet(mnemonic: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !validate_password(password) || !check_wallet_not_found()? {
        return Ok(());
    }
    let trimmed = mnemonic.trim();
    let _parsed_mnemonic = Mnemonic::from_phrase(trimmed, Language::English).map_err(|_| "Invalid mnemonic phrase.")?;
    let secure_mnemonic = SecureMnemonic::from_phrase(trimmed.to_string());
    let encrypted = encrypt_mnemonic(secure_mnemonic.phrase(), password)?;
    let json = serde_json::to_string_pretty(&encrypted)?;
    let wallet_file = get_wallet_file()?;
    fs::write(&wallet_file, json)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&wallet_file, fs::Permissions::from_mode(0o600))?;
    }
    let metadata = Metadata { version: "2.0".to_string(), created_at: chrono::Utc::now().to_rfc3339(), address_count: 1, last_accessed: None };
    save_metadata(&metadata)?;
    let secure_seed = secure_mnemonic.to_seed("");
    let addresses = derive_all_addresses(&secure_seed, 0)?;
    println!("\nWallet restored successfully.\n");
    display_addresses(&addresses, 0);
    update_metadata(None)?;
    Ok(())
}

fn verify_wallet(password: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !check_wallet_exists()? {
        return Ok(());
    }
    let wallet_file = get_wallet_file()?;
    let contents = fs::read_to_string(wallet_file)?;
    let wallet: EncryptedWallet = serde_json::from_str(&contents)?;
    let _secure_mnemonic = decrypt_mnemonic(&wallet, password)?;
    println!("\nWallet file is valid and password is correct.");
    if let Some(metadata) = load_metadata()? {
        println!("\nWallet Info:");
        println!("   Version: {}", metadata.version);
        println!("   Created: {}", metadata.created_at);
        println!("   Accounts: {}\n", metadata.address_count);
        if let Some(last_accessed) = &metadata.last_accessed {
            println!("   Last Accessed: {}\n", last_accessed);
        }
    }
    Ok(())
}

fn delete_wallet(confirm: bool) -> Result<(), Box<dyn std::error::Error>> {
    if !check_wallet_exists()? {
        return Ok(());
    }
    if !confirm {
        println!("\nThis will permanently delete your wallet file.");
        println!("Make absolutely sure you have your mnemonic phrase backed up.");
        println!("\nUse --confirm flag to proceed: delete --confirm\n");
        return Ok(());
    }
    let wallet_file = get_wallet_file()?;
    if let Ok(metadata) = fs::metadata(&wallet_file) {
        let file_size = metadata.len() as usize;
        match OpenOptions::new().write(true).open(&wallet_file) {
            Ok(mut file) => {
                if file.seek(SeekFrom::Start(0)).is_ok() {
                    let buffer_size = 8192;
                    let zeros = vec![0u8; buffer_size];
                    let mut written = 0;
                    while written < file_size {
                        let to_write = (file_size - written).min(buffer_size);
                        match file.write_all(&zeros[..to_write]) {
                            Ok(_) => written += to_write,
                            Err(_) => {
                                eprintln!("Failed to securely overwrite wallet file");
                                break;
                            }
                        }
                    }
                    let _ = file.sync_all();
                }
            }
            Err(_) => {
                eprintln!("Could not open wallet file for secure deletion");
            }
        }
    }
    fs::remove_file(&wallet_file)?;
    let metadata_file = get_metadata_file()?;
    if metadata_file.exists() {
        fs::remove_file(metadata_file)?;
    }
    println!("\nWallet deleted successfully.");
    println!("Make sure you have your mnemonic phrase backed up.\n");
    Ok(())
}

fn change_password(old_password: &str, new_password: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !check_wallet_exists()? || !validate_password(new_password) {
        return Ok(());
    }
    let wallet_file = get_wallet_file()?;
    let contents = fs::read_to_string(&wallet_file)?;
    let wallet: EncryptedWallet = serde_json::from_str(&contents)?;
    let secure_mnemonic = decrypt_mnemonic(&wallet, old_password)?;
    let encrypted = encrypt_mnemonic(&secure_mnemonic.phrase(), new_password)?;
    let json = serde_json::to_string_pretty(&encrypted)?;
    fs::write(&wallet_file, json)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&wallet_file, fs::Permissions::from_mode(0o600))?;
    }
    println!("Password changed successfully.\n");
    update_metadata(None)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    commands::execute_command(cli.command)?;
    Ok(())
}
