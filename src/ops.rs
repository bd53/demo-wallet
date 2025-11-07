use bip39::{Language, Mnemonic, MnemonicType};
use blahaj::{Sharks, Share};
use scrypt::password_hash::rand_core::{OsRng, RngCore};
use std::fs;
use zeroize::{Zeroize, Zeroizing};

use crate::constants::*;
use crate::crypto::*;
use crate::derive::*;
use crate::types::*;
use crate::utils::*;

pub fn generate_wallet(password: &str, words: u32) -> Result<(), Box<dyn std::error::Error>> {
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

pub fn generate_wallet_seedless(password: &str, threshold: u8, total_shares: u8) -> Result<(), Box<dyn std::error::Error>> {
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
    println!("\nIMPORTANT:");
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

pub fn show_wallet(password: &str, account: u32, qr: bool) -> Result<(), Box<dyn std::error::Error>> {
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

pub fn export_mnemonic(password: &str, reveal: bool) -> Result<(), Box<dyn std::error::Error>> {
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

pub fn export_private_key(password: &str, chain: &str, index: u32, qr: bool) -> Result<(), Box<dyn std::error::Error>> {
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

pub fn export_share(password: &str, number: u8, qr: bool, output_path: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
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
    decrypt_share(&encrypted_share, password)?;
    let export_data = serde_json::to_string_pretty(&encrypted_share)?;
    if let Some(path) = output_path {
        let path_obj = std::path::Path::new(path);
        fs::write(path, &export_data)?;
        set_secure_file_permissions(path_obj)?;
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

pub fn restore_wallet(mnemonic: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
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

pub fn restore_wallet_seedless(password: &str, share_paths: &[String]) -> Result<(), Box<dyn std::error::Error>> {
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

pub fn recover_secret_from_shares(password: &str, threshold: u8) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
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

pub fn verify_wallet(password: &str) -> Result<(), Box<dyn std::error::Error>> {
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
    println!("\nInformation:");
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

pub fn change_password(old_password: &str, new_password: &str) -> Result<(), Box<dyn std::error::Error>> {
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

pub fn delete_wallet(confirm: bool) -> Result<(), Box<dyn std::error::Error>> {
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
    if is_seedless {
        if let Some(meta) = &metadata {
            if let Some(config) = &meta.shamir_config {
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
