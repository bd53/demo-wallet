use aes_gcm::{Aes256Gcm, aead::{Aead, KeyInit}};
use bip39::{Language, Mnemonic, MnemonicType};
use clap::Parser;
use qrcode::{QrCode, render::unicode};
use scrypt::{Params, password_hash::{SaltString, rand_core::{OsRng, RngCore}}};
use blahaj::{Sharks, Share};
use solana_sdk::signature::{Keypair as SolanaKeypair, SeedDerivable, Signer};
use std::{fs::{self, OpenOptions}, io::{Seek, SeekFrom, Write}, path::{Path, PathBuf}};
use tiny_keccak::{Hasher, Keccak};
use zeroize::{Zeroize, Zeroizing};

mod commands;
mod convert;
mod types;

use commands::Commands;
use types::*;

type DeriveResult = Result<(String, Zeroizing<Vec<u8>>), Box<dyn std::error::Error>>;

const WALLET_DIR: &str = ".demo-wallet";
const WALLET_FILE: &str = "wallet.json";
const METADATA_FILE: &str = "metadata.json";
const SHARES_DIR: &str = ".shares";
const PASSWORD_LENGTH: usize = 8;
const ACCOUNT_MAX: u32 = 20;
const SCRYPT_LOG_N: u8 = 14;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const CIPHERTEXT_MIN: usize = 17;
const ENTROPY_SIZE: usize = 32;
const MIN_THRESHOLD: u8 = 2;
const MAX_THRESHOLD: u8 = 10;

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
        set_secure_permissions(&wallet_dir)?;
    }
    Ok(wallet_dir)
}

fn get_shares_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let shares_dir = get_wallet_dir()?.join(SHARES_DIR);
    if !shares_dir.exists() {
        fs::create_dir_all(&shares_dir)?;
        set_secure_permissions(&shares_dir)?;
    }
    Ok(shares_dir)
}

fn get_wallet_file() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(get_wallet_dir()?.join(WALLET_FILE))
}

fn get_metadata_file() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(get_wallet_dir()?.join(METADATA_FILE))
}

fn get_share_file(number: u8) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(get_shares_dir()?.join(format!("share_{}.json", number)))
}

fn set_secure_permissions(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    {
        let _ = path;
        eprintln!("File permissions not set on Windows. Ensure this directory is protected.");
    }
    Ok(())
}

fn set_secure_file_permissions(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    {
        let _ = path;
        eprintln!("File permissions not set on Windows. Ensure this file is protected.");
    }
    Ok(())
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
        println!("\nPassword must contain at least one uppercase letter, one lowercase letter, one number, and one special symbol.");
        return false;
    }
    true
}

fn validate_account_index(index: u32) -> Result<(), Box<dyn std::error::Error>> {
    if index >= ACCOUNT_MAX {
        return Err(format!("Account index must be between 0 and {}.", ACCOUNT_MAX - 1).into());
    }
    Ok(())
}

fn validate_shamir_params(threshold: u8, total: u8) -> Result<(), Box<dyn std::error::Error>> {
    if !(MIN_THRESHOLD..=MAX_THRESHOLD).contains(&threshold) {
        return Err(format!("Threshold must be between {} and {}", MIN_THRESHOLD, MAX_THRESHOLD).into());
    }
    if total < threshold || total > MAX_THRESHOLD {
        return Err(format!("Total shares must be between threshold ({}) and {}", threshold, MAX_THRESHOLD).into());
    }
    Ok(())
}

fn wallet_exists() -> Result<bool, Box<dyn std::error::Error>> {
    Ok(get_wallet_file()?.exists())
}

fn check_wallet_exists() -> Result<(), Box<dyn std::error::Error>> {
    if !wallet_exists()? {
        return Err("No wallet found. Run `generate` or `generate-seedless` first.".into());
    }
    Ok(())
}

fn check_wallet_not_found() -> Result<(), Box<dyn std::error::Error>> {
    if wallet_exists()? {
        return Err("Wallet already exists. Use `delete` first if you want to create a new one.".into());
    }
    Ok(())
}

fn encrypt_data(data: &[u8], password: &str) -> Result<EncryptedData, Box<dyn std::error::Error>> {
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, 32)?;
    let mut key = Zeroizing::new(vec![0u8; 32]);
    scrypt::scrypt(password.as_bytes(), salt.as_str().as_bytes(), &params, &mut key)?;
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let nonce = &iv.into();
    let ciphertext = cipher.encrypt(nonce, data).map_err(|e| format!("Encryption failed: {:?}", e))?;
    if ciphertext.len() < CIPHERTEXT_MIN {
        return Err("Encryption produced invalid ciphertext".into());
    }
    let tag_start = ciphertext.len() - 16;
    let content = hex::encode(&ciphertext[..tag_start]);
    let tag = hex::encode(&ciphertext[tag_start..]);
    Ok(EncryptedData { iv: hex::encode(iv), content, tag, salt: salt.as_str().to_string() })
}

fn decrypt_data(encrypted: &EncryptedData, password: &str) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    let params = Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, 32)?;
    let mut key = Zeroizing::new(vec![0u8; 32]);
    scrypt::scrypt(password.as_bytes(), encrypted.salt.as_bytes(), &params, &mut key)?;
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let iv = hex::decode(&encrypted.iv)?;
    let iv_array: [u8; 12] = iv.as_slice().try_into().map_err(|_| "Invalid IV length")?;
    let nonce = &iv_array.into();
    let content = hex::decode(&encrypted.content)?;
    let tag = hex::decode(&encrypted.tag)?;
    if tag.len() != 16 {
        return Err("Invalid authentication tag length".into());
    }
    let mut ciphertext = content;
    ciphertext.extend_from_slice(&tag);
    if ciphertext.len() < CIPHERTEXT_MIN {
        return Err("Invalid ciphertext length".into());
    }
    let plaintext = Zeroizing::new(cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| "Decryption failed. Invalid password.")?);
    Ok(plaintext)
}

fn encrypt_mnemonic(mnemonic: &str, password: &str) -> Result<EncryptedWallet, Box<dyn std::error::Error>> {
    let encrypted = encrypt_data(mnemonic.as_bytes(), password)?;
    Ok(EncryptedWallet { iv: encrypted.iv, content: encrypted.content, tag: encrypted.tag, salt: encrypted.salt })
}

fn decrypt_mnemonic(wallet: &EncryptedWallet, password: &str) -> Result<SecureMnemonic, Box<dyn std::error::Error>> {
    let encrypted = EncryptedData { iv: wallet.iv.clone(), content: wallet.content.clone(), tag: wallet.tag.clone(), salt: wallet.salt.clone() };
    let plaintext = decrypt_data(&encrypted, password)?;
    let mnemonic_str = std::str::from_utf8(&plaintext)?;
    let _ = Mnemonic::from_phrase(mnemonic_str, Language::English).map_err(|_| "Invalid mnemonic in wallet file")?;
    let secure = SecureMnemonic::from_phrase(mnemonic_str.to_string());
    Ok(secure)
}

fn encrypt_share(share_data: &[u8], password: &str, share_number: u8) -> Result<EncryptedShare, Box<dyn std::error::Error>> {
    let encrypted = encrypt_data(share_data, password)?;
    Ok(EncryptedShare { number: share_number, iv: encrypted.iv, content: encrypted.content, tag: encrypted.tag, salt: encrypted.salt })
}

fn decrypt_share(share: &EncryptedShare, password: &str) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    let encrypted = EncryptedData { iv: share.iv.clone(), content: share.content.clone(), tag: share.tag.clone(), salt: share.salt.clone() };
    decrypt_data(&encrypted, password)
}

fn derive_bitcoin_addresses(seed: &[u8], index: u32) -> Result<BitcoinAddresses, Box<dyn std::error::Error>> {
    validate_account_index(index)?;
    use bitcoin::{Address, CompressedPublicKey, Network, NetworkKind, PrivateKey, PublicKey, bip32::{ChildNumber, DerivationPath, Xpriv}, secp256k1::Secp256k1};
    let secp = Secp256k1::new();
    let xprv = Xpriv::new_master(Network::Bitcoin, seed)?;
    let path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(44)?,
        ChildNumber::from_hardened_idx(0)?,
        ChildNumber::from_hardened_idx(0)?,
        ChildNumber::from_normal_idx(0)?,
        ChildNumber::from_normal_idx(index)?,
    ]);
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
    validate_account_index(index)?;
    use bip32::XPrv;
    use k256::ecdsa::SigningKey;
    let path = format!("m/44'/60'/0'/0/{}", index);
    let xprv = XPrv::derive_from_path(seed, &path.parse()?)?;
    let secret_bytes = xprv.to_bytes();
    let signing_key = SigningKey::from_bytes(&secret_bytes.into())?;
    let verifying_key = signing_key.verifying_key();
    let public_bytes = verifying_key.to_encoded_point(false);
    let mut hasher = Keccak::v256();
    hasher.update(&public_bytes.as_bytes()[1..]);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    let address = format!("0x{}", hex::encode(&hash[12..]));
    Ok(address)
}

fn derive_solana_address(seed: &[u8], index: u32) -> DeriveResult {
    validate_account_index(index)?;
    use bip32::XPrv;
    let path = format!("m/44'/501'/{}'", index);
    let xprv = XPrv::derive_from_path(seed, &path.parse()?)?;
    let secret_bytes = xprv.to_bytes();
    let mut seed_bytes = Zeroizing::new([0u8; 32]);
    seed_bytes.copy_from_slice(&secret_bytes);
    let keypair = SolanaKeypair::from_seed(&*seed_bytes)?;
    let address = keypair.pubkey().to_string();
    let secret_key = Zeroizing::new(keypair.to_bytes().to_vec());
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
    set_secure_file_permissions(&metadata_file)?;
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
    let mut metadata = load_metadata()?.unwrap_or_else(|| {
        eprintln!("Metadata file missing, initializing new metadata.");
        Metadata { version: "2.0".to_string(), created_at: chrono::Utc::now().to_rfc3339(), address_count: 1, last_accessed: None, wallet_type: WalletType::Mnemonic, shamir_config: None }
    });
    metadata.last_accessed = Some(chrono::Utc::now().to_rfc3339());
    if let Some(count) = address_count {
        metadata.address_count = metadata.address_count.max(count);
    }
    save_metadata(&metadata)?;
    Ok(())
}

fn generate_wallet(password: &str, words: u32) -> Result<(), Box<dyn std::error::Error>> {
    if !validate_password(password) {
        return Err("Password validation failed".into());
    }
    check_wallet_not_found()?;
    let word_count = match words {
        12 => MnemonicType::Words12,
        24 => MnemonicType::Words24,
        _ => return Err("Word count must be 12 or 24".into()),
    };
    let mnemonic = Mnemonic::new(word_count, Language::English);
    let phrase = Zeroizing::new(mnemonic.phrase().to_string());
    drop(mnemonic);
    let secure_mnemonic = SecureMnemonic::from_phrase(phrase.to_string());
    let encrypted = encrypt_mnemonic(&phrase, password)?;
    let json = serde_json::to_string_pretty(&encrypted)?;
    let wallet_file = get_wallet_file()?;
    let metadata = Metadata { version: "2.0".to_string(), created_at: chrono::Utc::now().to_rfc3339(), address_count: 1, last_accessed: None, wallet_type: WalletType::Mnemonic, shamir_config: None };
    save_metadata(&metadata)?;
    let secure_seed = secure_mnemonic.to_seed("");
    let addresses = derive_all_addresses(&secure_seed, 0)?;
    println!("\nWallet generated successfully.\n");
    println!("Write down your mnemonic phrase and store it securely offline.");
    println!("Use the `mnemonic --reveal` command to view it.\n");
    display_addresses(&addresses, 0);
    println!("Wallet stored in: {}", wallet_file.display());
    println!("Metadata stored in: {}\n", get_metadata_file()?.display());
    fs::write(&wallet_file, json)?;
    set_secure_file_permissions(&wallet_file)?;
    update_metadata(None)?;
    Ok(())
}

fn generate_wallet_seedless(password: &str, threshold: u8, total_shares: u8) -> Result<(), Box<dyn std::error::Error>> {
    if !validate_password(password) {
        return Err("Password validation failed".into());
    }
    check_wallet_not_found()?;
    validate_shamir_params(threshold, total_shares)?;
    let mut entropy = Zeroizing::new([0u8; ENTROPY_SIZE]);
    OsRng.fill_bytes(&mut *entropy);
    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(&*entropy);
    let shares: Vec<Share> = dealer.take(total_shares as usize).collect();
    for (i, share) in shares.iter().enumerate() {
        let share_number = (i + 1) as u8;
        let share_bytes = Vec::from(share);
        let encrypted_share = encrypt_share(&share_bytes, password, share_number)?;
        let share_json = serde_json::to_string_pretty(&encrypted_share)?;
        let share_file = get_share_file(share_number)?;
        fs::write(&share_file, share_json)?;
        set_secure_file_permissions(&share_file)?;
    }
    let metadata = Metadata { version: "2.0".to_string(), created_at: chrono::Utc::now().to_rfc3339(), address_count: 1, last_accessed: None, wallet_type: WalletType::Seedless, shamir_config: Some(ShamirConfig { threshold, total_shares }) };
    save_metadata(&metadata)?;
    let wallet_file = get_wallet_file()?;
    let seedless_marker = SeedlessMarker { wallet_type: "seedless".to_string() };
    let json = serde_json::to_string_pretty(&seedless_marker)?;
    fs::write(&wallet_file, json)?;
    set_secure_file_permissions(&wallet_file)?;
    let secure_seed = SecureSeed::from_entropy(&*entropy);
    let addresses = derive_all_addresses(&secure_seed, 0)?;
    println!("\nSeedless wallet generated successfully!\n");
    println!("Configuration: {}-of-{} (need {} shares to recover)", threshold, total_shares, threshold);
    println!("\n{} shares have been generated and saved:", total_shares);
    for i in 1..=total_shares {
        println!("  Share {}: {}", i, get_share_file(i)?.display());
    }
    println!("\nIMPORTANT BACKUP INSTRUCTIONS:");
    println!("  1. Use 'share' command to export each share");
    println!("  2. Store shares in DIFFERENT secure locations");
    println!("  3. You need ANY {} shares to recover your wallet", threshold);
    println!("  4. Shares are useless individually - no single point of failure");
    println!("\nExample distribution strategy:");
    println!("  - Share 1: USB drive at home");
    println!("  - Share 2: Encrypted cloud storage");
    println!("  - Share 3: Paper backup in safe");
    println!("  - Share 4: Hardware wallet backup");
    println!("  - Share 5: Trusted family member\n");
    display_addresses(&addresses, 0);
    update_metadata(None)?;
    Ok(())
}

fn export_share(password: &str, number: u8, qr: bool, output_path: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    check_wallet_exists()?;
    let metadata = load_metadata()?.ok_or("Metadata not found")?;
    if metadata.wallet_type != WalletType::Seedless {
        return Err("This wallet is not seedless. Use 'mnemonic' command instead.".into());
    }
    let config = metadata.shamir_config.ok_or("Shamir configuration not found")?;
    if number < 1 || number > config.total_shares {
        return Err(format!("Share number must be between 1 and {}", config.total_shares).into());
    }
    let share_file = get_share_file(number)?;
    if !share_file.exists() {
        return Err(format!("Share {} not found at {}", number, share_file.display()).into());
    }
    let contents = fs::read_to_string(&share_file)?;
    let encrypted_share: EncryptedShare = serde_json::from_str(&contents)?;
    let _share_data = decrypt_share(&encrypted_share, password)?;
    let export_data = serde_json::to_string_pretty(&encrypted_share)?;
    if let Some(path) = output_path {
        fs::write(path, &export_data)?;
        println!("\nShare {} exported to: {}", number, path);
    } else {
        println!("\n═══════════════════════════════════════════");
        println!("  SHARE {} of {} (Threshold: {})", number, config.total_shares, config.threshold);
        println!("═══════════════════════════════════════════\n");
        println!("{}\n", export_data);
    }
    if qr {
        generate_qr_code(&export_data, &format!("Share {}", number))?;
    }
    println!("Store this share securely and separately from other shares.");
    println!("   You need {} shares to recover your wallet.\n", config.threshold);
    update_metadata(None)?;
    Ok(())
}

fn restore_wallet_seedless(password: &str, share_paths: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if !validate_password(password) {
        return Err("Password validation failed".into());
    }
    check_wallet_not_found()?;
    if share_paths.is_empty() {
        return Err("No share files provided. Use --shares flag with file paths.".into());
    }
    let mut decrypted_shares: Vec<Share> = Vec::new();
    let mut threshold: Option<u8> = None;
    for path in share_paths {
        let contents = fs::read_to_string(path).map_err(|_| format!("Failed to read share file: {}", path))?;
        let encrypted_share: EncryptedShare = serde_json::from_str(&contents).map_err(|_| format!("Invalid share file format: {}", path))?;
        let share_data = decrypt_share(&encrypted_share, password)?;
        let share = Share::try_from(share_data.as_slice()).map_err(|_| format!("Invalid share data in file: {}", path))?;
        decrypted_shares.push(share);
    }
    if decrypted_shares.is_empty() {
        return Err("No valid shares could be loaded".into());
    }
    let sharks = Sharks(0);
    let secret = Zeroizing::new(sharks.recover(&decrypted_shares).map_err(|_| "Failed to recover secret from shares. Need more shares or threshold not met.")?);
    if secret.len() != ENTROPY_SIZE {
        return Err(format!("Recovered secret has invalid length: {} (expected {})", secret.len(), ENTROPY_SIZE).into());
    }
    for t in MIN_THRESHOLD..=MAX_THRESHOLD {
        let test_sharks = Sharks(t);
        if test_sharks.recover(&decrypted_shares).is_ok() {
            threshold = Some(t);
            break;
        }
    }
    let threshold = threshold.ok_or("Could not determine threshold")?;
    let total_shares = decrypted_shares.len() as u8;
    let metadata = Metadata { version: "2.0".to_string(), created_at: chrono::Utc::now().to_rfc3339(), address_count: 1, last_accessed: None, wallet_type: WalletType::Seedless, shamir_config: Some(ShamirConfig { threshold, total_shares }) };
    save_metadata(&metadata)?;
    let sharks_gen = Sharks(threshold);
    let dealer = sharks_gen.dealer(&secret);
    let new_shares: Vec<Share> = dealer.take(total_shares as usize).collect();
    for (i, share) in new_shares.iter().enumerate() {
        let share_number = (i + 1) as u8;
        let share_bytes = Vec::from(share);
        let encrypted_share = encrypt_share(&share_bytes, password, share_number)?;
        let share_json = serde_json::to_string_pretty(&encrypted_share)?;
        let share_file = get_share_file(share_number)?;
        fs::write(&share_file, share_json)?;
        set_secure_file_permissions(&share_file)?;
    }
    let wallet_file = get_wallet_file()?;
    let seedless_marker = SeedlessMarker { wallet_type: "seedless".to_string() };
    let json = serde_json::to_string_pretty(&seedless_marker)?;
    fs::write(&wallet_file, json)?;
    set_secure_file_permissions(&wallet_file)?;
    let secure_seed = SecureSeed::from_entropy(&secret);
    let addresses = derive_all_addresses(&secure_seed, 0)?;
    println!("\nSeedless wallet restored successfully!\n");
    println!("Recovered using {} shares", decrypted_shares.len());
    println!("Configuration: {}-of-{}", threshold, total_shares);
    display_addresses(&addresses, 0);
    update_metadata(None)?;
    Ok(())
}

fn show_wallet(password: &str, account: u32, qr: bool) -> Result<(), Box<dyn std::error::Error>> {
    check_wallet_exists()?;
    validate_account_index(account)?;
    let metadata = load_metadata()?.ok_or("Metadata not found")?;
    let secure_seed = match metadata.wallet_type {
        WalletType::Mnemonic => {
            let wallet_file = get_wallet_file()?;
            let contents = fs::read_to_string(wallet_file)?;
            let wallet: EncryptedWallet = serde_json::from_str(&contents)?;
            let secure_mnemonic = decrypt_mnemonic(&wallet, password)?;
            secure_mnemonic.to_seed("")
        }
        WalletType::Seedless => {
            let config = metadata.shamir_config.ok_or("Shamir configuration not found")?;
            let secret = recover_secret_from_shares(password, config.threshold)?;
            SecureSeed::from_entropy(&secret)
        }
    };
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

fn recover_secret_from_shares(password: &str, threshold: u8) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut shares: Vec<Share> = Vec::new();
    for i in 1..=MAX_THRESHOLD {
        let share_file = get_share_file(i)?;
        if !share_file.exists() {
            continue;
        }
        let contents = fs::read_to_string(&share_file)?;
        let encrypted_share: EncryptedShare = serde_json::from_str(&contents)?;
        let share_data = decrypt_share(&encrypted_share, password)?;
        let share = Share::try_from(share_data.as_slice()).map_err(|_| format!("Invalid share data in share {}", i))?;
        shares.push(share);
        if shares.len() >= threshold as usize {
            break;
        }
    }
    if shares.len() < threshold as usize {
        return Err(format!("Not enough shares found. Need {} but only found {}", threshold, shares.len()).into());
    }
    let sharks = Sharks(threshold);
    let secret = Zeroizing::new(sharks.recover(&shares).map_err(|_| "Failed to recover secret from shares")?);
    Ok(secret)
}

fn derive_multiple_accounts(password: &str, count: u32) -> Result<(), Box<dyn std::error::Error>> {
    check_wallet_exists()?;
    if !(1..=ACCOUNT_MAX).contains(&count) {
        return Err(format!("You can only derive between 1 and {} accounts.", ACCOUNT_MAX).into());
    }
    let metadata = load_metadata()?.ok_or("Metadata not found")?;
    let secure_seed = match metadata.wallet_type {
        WalletType::Mnemonic => {
            let wallet_file = get_wallet_file()?;
            let contents = fs::read_to_string(wallet_file)?;
            let wallet: EncryptedWallet = serde_json::from_str(&contents)?;
            let secure_mnemonic = decrypt_mnemonic(&wallet, password)?;
            secure_mnemonic.to_seed("")
        }
        WalletType::Seedless => {
            let config = metadata.shamir_config.ok_or("Shamir configuration not found")?;
            let secret = recover_secret_from_shares(password, config.threshold)?;
            SecureSeed::from_entropy(&secret)
        }
    };
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
    check_wallet_exists()?;
    let metadata = load_metadata()?.ok_or("Metadata not found")?;
    if metadata.wallet_type != WalletType::Mnemonic {
        return Err("This is a seedless wallet. Use 'export-share' command instead.".into());
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
    println!("Your mnemonic phrase:");
    println!("{}\n", secure_mnemonic.phrase());
    println!("Write this down on paper and store in a secure location.");
    println!("Never store it digitally, take screenshots, or share it with anyone.\n");
    update_metadata(None)?;
    Ok(())
}

fn export_private_key(password: &str, chain: &str, index: u32, qr: bool) -> Result<(), Box<dyn std::error::Error>> {
    check_wallet_exists()?;
    validate_account_index(index)?;
    let metadata = load_metadata()?.ok_or("Metadata not found")?;
    let secure_seed = match metadata.wallet_type {
        WalletType::Mnemonic => {
            let wallet_file = get_wallet_file()?;
            let contents = fs::read_to_string(wallet_file)?;
            let wallet: EncryptedWallet = serde_json::from_str(&contents)?;
            let secure_mnemonic = decrypt_mnemonic(&wallet, password)?;
            secure_mnemonic.to_seed("")
        }
        WalletType::Seedless => {
            let config = metadata.shamir_config.ok_or("Shamir configuration not found")?;
            let secret = recover_secret_from_shares(password, config.threshold)?;
            SecureSeed::from_entropy(&secret)
        }
    };
    let privkey = match chain {
        "bitcoin" => {
            use bitcoin::{Network, bip32::{ChildNumber, DerivationPath, Xpriv}, secp256k1::Secp256k1};
            let secp = Secp256k1::new();
            let xprv = Xpriv::new_master(Network::Bitcoin, secure_seed.as_bytes())?;
            let path = DerivationPath::from(vec![
                ChildNumber::from_hardened_idx(44)?,
                ChildNumber::from_hardened_idx(0)?,
                ChildNumber::from_hardened_idx(0)?,
                ChildNumber::from_normal_idx(0)?,
                ChildNumber::from_normal_idx(index)?,
            ]);
            let derived = xprv.derive_priv(&secp, &path)?;
            Zeroizing::new(hex::encode(derived.private_key.secret_bytes()))
        }
        "ethereum" => {
            use bip32::XPrv;
            let path = format!("m/44'/60'/0'/0/{}", index);
            let xprv = XPrv::derive_from_path(secure_seed.as_bytes(), &path.parse()?)?;
            let secret_bytes = xprv.to_bytes();
            Zeroizing::new(format!("0x{}", hex::encode(secret_bytes)))
        }
        "solana" => {
            let (_address, secret_key) = derive_solana_address(secure_seed.as_bytes(), index)?;
            Zeroizing::new(bs58::encode(&*secret_key).into_string())
        }
        _ => {
            return Err(format!("Unsupported chain: {}. Use: bitcoin, ethereum, or solana", chain).into());
        }
    };
    println!("\nDo NOT share.\n");
    println!("{} Private Key (Account {}):", chain.to_uppercase(), index);
    println!("{}\n", &*privkey);
    println!("Only import this into trusted wallets on secure devices.\n");
    if qr {
        generate_qr_code(&privkey, "Private Key")?;
    }
    update_metadata(None)?;
    Ok(())
}

fn restore_wallet(mnemonic: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !validate_password(password) {
        return Err("Password validation failed".into());
    }
    check_wallet_not_found()?;
    let mut trimmed = Zeroizing::new(mnemonic.trim().to_string());
    {
        let parsed = Mnemonic::from_phrase(&trimmed, Language::English).map_err(|_| "Invalid mnemonic phrase.")?;
        drop(parsed);
    }
    let secure_mnemonic = SecureMnemonic::from_phrase(trimmed.to_string());
    let encrypted = encrypt_mnemonic(&trimmed, password)?;
    trimmed.zeroize();
    let json = serde_json::to_string_pretty(&encrypted)?;
    let wallet_file = get_wallet_file()?;
    fs::write(&wallet_file, json)?;
    set_secure_file_permissions(&wallet_file)?;
    let metadata = Metadata { version: "2.0".to_string(), created_at: chrono::Utc::now().to_rfc3339(), address_count: 1, last_accessed: None, wallet_type: WalletType::Mnemonic, shamir_config: None };
    save_metadata(&metadata)?;
    let secure_seed = secure_mnemonic.to_seed("");
    let addresses = derive_all_addresses(&secure_seed, 0)?;
    println!("\nWallet restored successfully.\n");
    display_addresses(&addresses, 0);
    update_metadata(None)?;
    Ok(())
}

fn verify_wallet(password: &str) -> Result<(), Box<dyn std::error::Error>> {
    check_wallet_exists()?;
    let metadata = load_metadata()?.ok_or("Metadata not found")?;
    match metadata.wallet_type {
        WalletType::Mnemonic => {
            let wallet_file = get_wallet_file()?;
            let contents = fs::read_to_string(wallet_file)?;
            let wallet: EncryptedWallet = serde_json::from_str(&contents)?;
            let _secure_mnemonic = decrypt_mnemonic(&wallet, password)?;
            println!("\nWallet file is valid and password is correct.");
        }
        WalletType::Seedless => {
            let config = metadata.shamir_config.as_ref().ok_or("Shamir configuration not found")?;
            let _secret = recover_secret_from_shares(password, config.threshold)?;
            println!("\nSeedless wallet is valid and password is correct.");
            println!("   Recovered secret using {} shares (threshold: {})", config.threshold, config.threshold);
        }
    }
    println!("\nWallet Info:");
    println!("   Type: {:?}", metadata.wallet_type);
    println!("   Version: {}", metadata.version);
    println!("   Created: {}", metadata.created_at);
    println!("   Accounts: {}", metadata.address_count);
    if let Some(config) = &metadata.shamir_config {
        println!("   Shamir Config: {}-of-{}", config.threshold, config.total_shares);
        println!("\n   Available shares:");
        for i in 1..=config.total_shares {
            let share_file = get_share_file(i)?;
            if share_file.exists() {
                println!("     Share {}", i);
            } else {
                println!("     Share {} (missing)", i);
            }
        }
    }
    if let Some(last_accessed) = &metadata.last_accessed {
        println!("   Last Accessed: {}", last_accessed);
    }
    println!();
    Ok(())
}

fn secure_overwrite_file(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::metadata(path)?;
    let file_size = metadata.len() as usize;
    let mut file = OpenOptions::new().write(true).open(path)?;
    file.seek(SeekFrom::Start(0))?;
    let buffer_size = 8192;
    let zeros = vec![0u8; buffer_size];
    let mut remaining = file_size;
    while remaining > 0 {
        let to_write = remaining.min(buffer_size);
        let written = file.write(&zeros[..to_write])?;
        if written == 0 {
            return Err("Failed to write during secure deletion".into());
        }
        remaining -= written;
    }
    file.sync_all()?;
    Ok(())
}

fn delete_wallet(confirm: bool) -> Result<(), Box<dyn std::error::Error>> {
    check_wallet_exists()?;
    let metadata = load_metadata()?;
    let is_seedless = metadata.as_ref().map(|m| m.wallet_type == WalletType::Seedless).unwrap_or(false);
    if !confirm {
        println!("\nWARNING: This will permanently delete your wallet!");
        if is_seedless {
            println!("\nThis is a SEEDLESS wallet. Make sure you have:");
            println!("  - Exported all shares using 'export-share' command");
            println!("  - Stored shares in separate secure locations");
            println!("  - Verified you can access enough shares to recover");
        } else {
            println!("\nMake absolutely sure you have your mnemonic phrase backed up.");
        }

        println!("\nUse --confirm flag to proceed: delete --confirm\n");
        return Ok(());
    }
    let wallet_file = get_wallet_file()?;
    if let Err(e) = secure_overwrite_file(&wallet_file) {
        eprintln!("Failed to securely overwrite wallet file: {}", e);
        eprintln!("Proceeding with regular deletion...");
    }
    fs::remove_file(&wallet_file)?;
    if is_seedless && let Some(meta) = &metadata && let Some(config) = &meta.shamir_config {
        for i in 1..=config.total_shares {
            let share_file = get_share_file(i)?;
            if share_file.exists() {
                if let Err(e) = secure_overwrite_file(&share_file) {
                    eprintln!("Failed to securely overwrite share {}: {}", i, e);
                }
                fs::remove_file(share_file)?;
            }
        }
    }
    let metadata_file = get_metadata_file()?;
    if metadata_file.exists() {
        if let Err(e) = secure_overwrite_file(&metadata_file) {
            eprintln!("Failed to securely overwrite metadata file: {}", e);
        }
        fs::remove_file(metadata_file)?;
    }
    println!("\nWallet deleted successfully.");
    if is_seedless {
        println!("   Make sure you have your shares backed up in secure locations.\n");
    } else {
        println!("   Make sure you have your mnemonic phrase backed up.\n");
    }
    Ok(())
}

fn change_password(old_password: &str, new_password: &str) -> Result<(), Box<dyn std::error::Error>> {
    check_wallet_exists()?;
    if !validate_password(new_password) {
        return Err("New password validation failed".into());
    }
    let metadata = load_metadata()?.ok_or("Metadata not found")?;
    match metadata.wallet_type {
        WalletType::Mnemonic => {
            let wallet_file = get_wallet_file()?;
            let contents = fs::read_to_string(&wallet_file)?;
            let wallet: EncryptedWallet = serde_json::from_str(&contents)?;
            let secure_mnemonic = decrypt_mnemonic(&wallet, old_password)?;
            let phrase_copy = secure_mnemonic.phrase_zeroizing();
            let encrypted = encrypt_mnemonic(&phrase_copy, new_password)?;
            let json = serde_json::to_string_pretty(&encrypted)?;
            fs::write(&wallet_file, json)?;
            set_secure_file_permissions(&wallet_file)?;
        }
        WalletType::Seedless => {
            let config = metadata.shamir_config.ok_or("Shamir configuration not found")?;
            let secret = recover_secret_from_shares(old_password, config.threshold)?;
            let sharks = Sharks(config.threshold);
            let dealer = sharks.dealer(&secret);
            let shares: Vec<Share> = dealer.take(config.total_shares as usize).collect();
            for (i, share) in shares.iter().enumerate() {
                let share_number = (i + 1) as u8;
                let share_bytes = Vec::from(share);
                let encrypted_share = encrypt_share(&share_bytes, new_password, share_number)?;
                let share_json = serde_json::to_string_pretty(&encrypted_share)?;
                let share_file = get_share_file(share_number)?;
                fs::write(&share_file, share_json)?;
                set_secure_file_permissions(&share_file)?;
            }
        }
    }
    update_metadata(None)?;
    println!("\nPassword changed successfully.\n");
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    if let Err(e) = commands::execute_command(cli.command) {
        eprintln!("\nError: {}\n", e);
        std::process::exit(1);
    }
    Ok(())
}
