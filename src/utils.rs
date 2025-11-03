use qrcode::{QrCode, render::unicode};
use std::{fs::{self, OpenOptions}, io::{Seek, SeekFrom, Write}, path::{Path, PathBuf}};

use crate::constants::*;
use crate::types::*;

pub fn validate_password(password: &str) -> bool {
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

pub fn validate_account_index(index: u32) -> Result<(), Box<dyn std::error::Error>> {
    if index >= ACCOUNT_MAX {
        return Err(format!("Account index must be between 0 and {}.", ACCOUNT_MAX - 1).into());
    }
    Ok(())
}

pub fn validate_shamir_params(threshold: u8, total: u8) -> Result<(), Box<dyn std::error::Error>> {
    if !(MIN_THRESHOLD..=MAX_THRESHOLD).contains(&threshold) {
        return Err(format!("Threshold must be between {} and {}", MIN_THRESHOLD, MAX_THRESHOLD).into());
    }
    if total < threshold || total > MAX_THRESHOLD {
        return Err(format!("Total shares must be between threshold ({}) and {}", threshold, MAX_THRESHOLD).into());
    }
    Ok(())
}

pub fn get_metadata_file() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(get_wallet_dir()?.join(METADATA_FILE))
}

pub fn save_metadata(metadata: &Metadata) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(metadata)?;
    let metadata_file = get_metadata_file()?;
    fs::write(&metadata_file, json)?;
    set_secure_file_permissions(&metadata_file)?;
    Ok(())
}

pub fn load_metadata() -> Result<Option<Metadata>, Box<dyn std::error::Error>> {
    let metadata_file = get_metadata_file()?;
    if !metadata_file.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(metadata_file)?;
    let metadata: Metadata = serde_json::from_str(&contents)?;
    Ok(Some(metadata))
}

pub fn update_metadata(address_count: Option<u32>) -> Result<(), Box<dyn std::error::Error>> {
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

pub fn get_wallet_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let home = dirs::home_dir().ok_or("Could not find home directory")?;
    let wallet_dir = home.join(WALLET_DIR);
    if !wallet_dir.exists() {
        fs::create_dir_all(&wallet_dir)?;
        set_secure_permissions(&wallet_dir)?;
    }
    Ok(wallet_dir)
}

pub fn get_wallet_file() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(get_wallet_dir()?.join(WALLET_FILE))
}

pub fn wallet_exists() -> Result<bool, Box<dyn std::error::Error>> {
    Ok(get_wallet_file()?.exists())
}

pub fn check_wallet_exists() -> Result<(), Box<dyn std::error::Error>> {
    if !wallet_exists()? {
        return Err("No wallet found. Run `generate` or `generate-seedless` first.".into());
    }
    Ok(())
}

pub fn check_wallet_not_found() -> Result<(), Box<dyn std::error::Error>> {
    if wallet_exists()? {
        return Err("Wallet already exists. Use `delete` first if you want to create a new one.".into());
    }
    Ok(())
}

pub fn get_shares_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let shares_dir = get_wallet_dir()?.join(SHARES_DIR);
    if !shares_dir.exists() {
        fs::create_dir_all(&shares_dir)?;
        set_secure_permissions(&shares_dir)?;
    }
    Ok(shares_dir)
}

pub fn get_share_file(number: u8) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(get_shares_dir()?.join(format!("share_{}.json", number)))
}

pub fn secure_overwrite_file(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
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

pub fn set_secure_permissions(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
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

pub fn set_secure_file_permissions(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
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

pub fn display_addresses(addresses: &Addresses, account: u32) {
    println!("\nWallet Addresses (Account {}):", account);
    println!("\nBitcoin:");
    println!("  Legacy (P2PKH): {}", addresses.bitcoin.p2pkh);
    println!("  Native SegWit: {}", addresses.bitcoin.p2wpkh);
    println!("  Wrapped SegWit: {}", addresses.bitcoin.p2sh);
    println!("\nEthereum: {}", addresses.ethereum);
    println!("\nSolana: {}\n", addresses.solana);
}

pub fn generate_qr_code(data: &str, label: &str) -> Result<(), Box<dyn std::error::Error>> {
    let code = QrCode::new(data)?;
    let string = code.render::<unicode::Dense1x2>().dark_color(unicode::Dense1x2::Light).light_color(unicode::Dense1x2::Dark).build();
    println!("{}:\n{}", label, string);
    Ok(())
}
