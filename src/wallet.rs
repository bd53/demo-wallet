use bip39::{Language, Mnemonic, MnemonicType};
use scrypt::password_hash::rand_core::{OsRng, RngCore};
use blahaj::{Sharks, Share};
use std::fs;
use zeroize::Zeroizing;

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
