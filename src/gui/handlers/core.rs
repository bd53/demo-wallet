use std::sync::mpsc;
use std::thread;

use cws::derive::*;
use crate::gui::tabs::show::generate_qr_from_string;
use crate::gui::tabs::show::load_addresses_internal;
use cws::ops::*;
use cws::utils::*;

use super::super::app::WalletGui;

impl WalletGui {
    pub fn start_verify_wallet(&mut self) {
        self.is_processing = true;
        let password = self.password.clone();
        let (tx, rx) = mpsc::channel();
        self.verify_rx = Some(rx);
        thread::spawn(move || {
            let result = match verify_wallet(&password) {
                Ok(_) => match load_metadata() {
                    Ok(Some(metadata)) => {
                        let mut info = format!("Type: {:?}\nVersion: {}\nCreated: {}\nAccounts: {}", metadata.wallet_type, metadata.version, metadata.created_at, metadata.address_count);
                        if let Some(config) = metadata.shamir_config {
                            info.push_str(&format!("\nShamir: {}-of-{}", config.threshold, config.total_shares));
                        }
                        if let Some(last) = metadata.last_accessed {
                            info.push_str(&format!("\nLast Accessed: {}", last));
                        }
                        Ok(info)
                    }
                    _ => Ok("Wallet verified".to_string()),
                },
                Err(e) => Err(format!("Verification failed: {}", e)),
            };
            let _ = tx.send(result);
        });
    }

    pub fn start_wallet_generation(&mut self) {
        self.is_processing = true;
        let password = self.password.clone();
        let word_count = self.word_count;
        let threshold = self.seedless_threshold;
        let total_shares = self.seedless_shares;
        let (tx, rx) = mpsc::channel();
        self.gen_rx = Some(rx);
        thread::spawn(move || {
            let result = if word_count == 0 {
                generate_wallet_seedless(&password, threshold, total_shares).map_err(|e| e.to_string())
            } else {
                generate_wallet(&password, word_count).map_err(|e| e.to_string())
            };
            let _ = tx.send(result);
        });
    }

    pub fn start_load_addresses(&mut self) {
        self.is_processing = true;
        let password = self.password.clone();
        let account_index = self.account_index;
        let show_qr = self.show_qr;
        let (tx, rx) = mpsc::channel();
        self.addr_rx = Some(rx);
        thread::spawn(move || {
            let result = match load_addresses_internal(&password, account_index) {
                Ok(addrs) => {
                    let qr_imgs = if show_qr {
                        let qr = super::super::state::QrImages {
                            bitcoin: generate_qr_from_string(&addrs.bitcoin.p2wpkh),
                            ethereum: generate_qr_from_string(&addrs.ethereum),
                            solana: generate_qr_from_string(&addrs.solana),
                        };
                        Some(qr)
                    } else {
                        None
                    };
                    Ok((addrs, qr_imgs))
                }
                Err(e) => Err(format!("Failed to load addresses: {}", e)),
            };
            let _ = tx.send(result);
        });
    }

    pub fn start_derive_accounts(&mut self) {
        self.is_processing = true;
        let password = self.password.clone();
        let count = self.derive_count;
        let (tx, rx) = mpsc::channel();
        self.derive_rx = Some(rx);
        thread::spawn(move || {
            let result = derive_with_details(&password, count).map_err(|e| e.to_string());
            let _ = tx.send(result);
        });
    }

    pub fn start_export_mnemonic(&mut self) {
        self.is_processing = true;
        let password = self.password.clone();
        let (tx, rx) = mpsc::channel();
        self.export_rx = Some(rx);
        thread::spawn(move || {
            let result = export_mnemonic(&password, true).map_err(|e| e.to_string());
            let _ = tx.send(result);
        });
    }

    pub fn start_export_private_key(&mut self) {
        self.is_processing = true;
        let password = self.password.clone();
        let chain = self.export_chain.clone();
        let account = self.export_account;
        let (tx, rx) = mpsc::channel();
        self.export_rx = Some(rx);
        thread::spawn(move || {
            let result = export_private_key(&password, &chain, account, false).map_err(|e| e.to_string());
            let _ = tx.send(result);
        });
    }

    pub fn start_export_share(&mut self) {
        self.is_processing = true;
        let password = self.password.clone();
        let share_num = self.export_share_num;
        let (tx, rx) = mpsc::channel();
        self.export_rx = Some(rx);
        thread::spawn(move || {
            let result = export_share(&password, share_num, false, None).map_err(|e| e.to_string());
            let _ = tx.send(result);
        });
    }

    pub fn start_restore_mnemonic(&mut self) {
        self.is_processing = true;
        let mnemonic = self.restore_mnemonic.clone();
        let password = self.restore_password.clone();
        let (tx, rx) = mpsc::channel();
        self.restore_rx = Some(rx);
        thread::spawn(move || {
            let result = restore_wallet(&mnemonic, &password).map_err(|e| e.to_string());
            let _ = tx.send(result);
        });
    }

    pub fn start_restore_shares(&mut self) {
        self.is_processing = true;
        let paths: Vec<String> = self.restore_share_paths.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        if paths.is_empty() {
            self.is_processing = false;
            self.set_error("No share paths provided.");
            return;
        }
        let password = self.restore_password.clone();
        let (tx, rx) = mpsc::channel();
        self.restore_rx = Some(rx);
        thread::spawn(move || {
            let result = restore_wallet_seedless(&password, &paths).map_err(|e| e.to_string());
            let _ = tx.send(result);
        });
    }

    pub fn start_change_password(&mut self) {
        self.is_processing = true;
        let old_pwd = self.old_password.clone();
        let new_pwd = self.new_password.clone();
        let (tx, rx) = mpsc::channel();
        self.change_pwd_rx = Some(rx);
        thread::spawn(move || {
            let result = change_password(&old_pwd, &new_pwd).map_err(|e| e.to_string());
            let _ = tx.send(result);
        });
    }

    pub fn start_delete_wallet(&mut self) {
        self.is_processing = true;
        let (tx, rx) = mpsc::channel();
        self.delete_rx = Some(rx);
        thread::spawn(move || {
            let result = delete_wallet(true).map_err(|e| e.to_string());
            let _ = tx.send(result);
        });
    }
}
