use eframe::egui;
use std::sync::mpsc;
use std::thread;

use cws::convert::run_convert;
use cws::derive::*;
use crate::gui::tabs::show::{generate_qr_from_string, load_addresses_internal};
use cws::ops::*;
use cws::types::*;
use cws::utils::*;

use super::state::{View, QrImages};
use super::{tabs, ui};

type AddressResult = Result<(Addresses, Option<QrImages>), String>;
type DerivedAccounts = Vec<(u32, Addresses)>;
type DeriveResult = Result<DerivedAccounts, String>;
type ConvertResult = Result<String, String>;

pub struct WalletGui {
    pub(crate) current_view: View,
    pub(crate) wallet_loaded: bool,
    pub(crate) wallet_exists: bool,
    pub(crate) wallet_type: Option<WalletType>,
    pub(crate) password: String,
    pub(crate) show_password: bool,
    pub(crate) word_count: u32,
    pub(crate) seedless_threshold: u8,
    pub(crate) seedless_shares: u8,
    pub(crate) account_index: u32,
    pub(crate) derive_count: u32,
    pub(crate) show_qr: bool,
    pub(crate) restore_mnemonic: String,
    pub(crate) restore_password: String,
    pub(crate) restore_share_paths: String,
    pub(crate) export_chain: String,
    pub(crate) export_account: u32,
    pub(crate) export_share_num: u8,
    pub(crate) old_password: String,
    pub(crate) new_password: String,
    pub(crate) convert_key: String,
    pub(crate) convert_testnet: bool,
    pub(crate) convert_uncompressed: bool,
    pub(crate) addresses: Option<Addresses>,
    pub(crate) wallet_info: Option<String>,
    pub(crate) convert_result: Option<String>,
    pub(crate) status_message: String,
    pub(crate) error_message: String,
    pub(crate) is_processing: bool,
    pub(crate) qr_images: QrImages,
    pub(crate) derived_accounts: DerivedAccounts,
    pub(crate) gen_rx: Option<mpsc::Receiver<Result<(), String>>>,
    pub(crate) verify_rx: Option<mpsc::Receiver<Result<String, String>>>,
    pub(crate) addr_rx: Option<mpsc::Receiver<AddressResult>>,
    pub(crate) derive_rx: Option<mpsc::Receiver<DeriveResult>>,
    pub(crate) export_rx: Option<mpsc::Receiver<Result<(), String>>>,
    pub(crate) restore_rx: Option<mpsc::Receiver<Result<(), String>>>,
    pub(crate) change_pwd_rx: Option<mpsc::Receiver<Result<(), String>>>,
    pub(crate) delete_rx: Option<mpsc::Receiver<Result<(), String>>>,
    pub(crate) convert_rx: Option<mpsc::Receiver<ConvertResult>>,
}

impl Default for WalletGui {
    fn default() -> Self {
        let wallet_exists = wallet_exists().unwrap_or(false);
        let wallet_type = wallet_exists.then(|| load_metadata().ok().flatten().map(|m| m.wallet_type)).flatten();
        Self {
            current_view: View::Overview,
            wallet_loaded: false,
            wallet_exists,
            wallet_type,
            password: String::new(),
            show_password: false,
            word_count: 24,
            seedless_threshold: 3,
            seedless_shares: 5,
            account_index: 0,
            derive_count: 5,
            show_qr: false,
            restore_mnemonic: String::new(),
            restore_password: String::new(),
            restore_share_paths: String::new(),
            export_chain: "bitcoin".to_string(),
            export_account: 0,
            export_share_num: 1,
            old_password: String::new(),
            new_password: String::new(),
            convert_key: String::new(),
            convert_testnet: false,
            convert_uncompressed: false,
            addresses: None,
            wallet_info: None,
            convert_result: None,
            status_message: String::new(),
            error_message: String::new(),
            is_processing: false,
            qr_images: QrImages::default(),
            derived_accounts: Vec::new(),
            gen_rx: None,
            verify_rx: None,
            addr_rx: None,
            derive_rx: None,
            export_rx: None,
            restore_rx: None,
            change_pwd_rx: None,
            delete_rx: None,
            convert_rx: None,
        }
    }
}

impl WalletGui {
    pub fn set_status_ok(&mut self, message: &str) {
        self.status_message = message.to_string();
        self.error_message.clear();
    }

    pub fn set_error(&mut self, message: &str) {
        self.error_message = message.to_string();
        self.status_message.clear();
    }

    pub fn clear_messages(&mut self) {
        self.status_message.clear();
        self.error_message.clear();
    }

    pub fn clear_messages_and_password(&mut self) {
        self.clear_messages();
        self.password.clear();
        self.old_password.clear();
        self.new_password.clear();
        self.show_password = false;
    }

    pub fn refresh_wallet_status(&mut self) {
        self.wallet_exists = wallet_exists().unwrap_or(false);
        self.wallet_type = self.wallet_exists.then(|| load_metadata().ok().flatten().map(|m| m.wallet_type)).flatten();
    }

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
                        let qr = QrImages {
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

    pub fn start_convert(&mut self) {
        self.is_processing = true;
        let key = self.convert_key.clone();
        let testnet = self.convert_testnet;
        let uncompressed = self.convert_uncompressed;
        let (tx, rx) = mpsc::channel();
        self.convert_rx = Some(rx);
        thread::spawn(move || {
            let result = run_convert(&key, testnet, uncompressed).map_err(|e| e.to_string());
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

impl eframe::App for WalletGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        handle_pending_results(self);
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            ui::menu::show_menu_bar(self, ui);
        });
        egui::SidePanel::left("sidebar").min_width(150.0).show(ctx, |ui| {
            ui::sidebar::show_sidebar(self, ui);
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                match self.current_view {
                    View::Overview => tabs::overview::show_overview_view(self, ui),
                    View::Generate => tabs::generate::show_generate_view(self, ui),
                    View::Show => tabs::show::show_addresses_view(self, ui),
                    View::Derive => tabs::derive::show_derive_view(self, ui),
                    View::Export => tabs::export::show_export_view(self, ui),
                    View::Convert => tabs::convert::show_convert_view(self, ui),
                    View::Restore => tabs::restore::show_restore_view(self, ui),
                    View::Settings => tabs::settings::show_settings_view(self, ui),
                }
            });
        });
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui::status::show_status_bar(self, ui);
        });
    }
}

pub fn handle_pending_results(app: &mut WalletGui) {
    if let Some(rx) = app.gen_rx.take() {
        match rx.try_recv() {
            Ok(result) => {
                app.is_processing = false;
                match result {
                    Ok(_) => {
                        app.set_status_ok("Wallet generated successfully.");
                        app.refresh_wallet_status();
                        app.password.clear();
                    }
                    Err(e) => app.set_error(&format!("Generation failed: {}", e)),
                }
            }
            Err(mpsc::TryRecvError::Empty) => app.gen_rx = Some(rx),
            Err(mpsc::TryRecvError::Disconnected) => {
                app.is_processing = false;
                app.set_error("Generation thread disconnected.");
            }
        }
    }

    if let Some(rx) = app.verify_rx.take() {
        match rx.try_recv() {
            Ok(result) => {
                app.is_processing = false;
                match result {
                    Ok(info) => {
                        app.wallet_loaded = true;
                        app.set_status_ok("Wallet verified successfully.");
                        app.wallet_info = Some(info);
                    }
                    Err(e) => {
                        app.wallet_loaded = false;
                        app.set_error(&format!("Verification failed: {}", e));
                        app.wallet_info = None;
                    }
                }
            }
            Err(mpsc::TryRecvError::Empty) => app.verify_rx = Some(rx),
            Err(mpsc::TryRecvError::Disconnected) => {
                app.is_processing = false;
                app.set_error("Verification thread disconnected.");
            }
        }
    }

    if let Some(rx) = app.addr_rx.take() {
        match rx.try_recv() {
            Ok(result) => {
                app.is_processing = false;
                match result {
                    Ok((addrs, qr_imgs)) => {
                        app.addresses = Some(addrs);
                        if let Some(qr) = qr_imgs {
                            app.qr_images = qr;
                        }
                        app.set_status_ok(&format!("Addresses loaded (Account {}).", app.account_index));
                    }
                    Err(e) => {
                        app.set_error(&format!("Failed to load addresses: {}", e));
                        app.addresses = None;
                        app.qr_images = QrImages::default();
                    }
                }
            }
            Err(mpsc::TryRecvError::Empty) => app.addr_rx = Some(rx),
            Err(mpsc::TryRecvError::Disconnected) => {
                app.is_processing = false;
                app.set_error("Address loading thread disconnected.");
            }
        }
    }

    if let Some(rx) = app.derive_rx.take() {
        match rx.try_recv() {
            Ok(result) => {
                app.is_processing = false;
                match result {
                    Ok(accounts) => {
                        app.derived_accounts = accounts;
                        app.set_status_ok(&format!("Derived ({}) accounts successfully.", app.derive_count));
                        app.password.clear();
                    }
                    Err(e) => app.set_error(&format!("Failed to derive accounts: {}", e)),
                }
            }
            Err(mpsc::TryRecvError::Empty) => app.derive_rx = Some(rx),
            Err(mpsc::TryRecvError::Disconnected) => {
                app.is_processing = false;
                app.set_error("Derivation thread disconnected.");
            }
        }
    }

    if let Some(rx) = app.export_rx.take() {
        match rx.try_recv() {
            Ok(result) => {
                app.is_processing = false;
                match result {
                    Ok(_) => app.set_status_ok("Data exported successfully."),
                    Err(e) => app.set_error(&format!("Export failed: {}", e)),
                }
            }
            Err(mpsc::TryRecvError::Empty) => app.export_rx = Some(rx),
            Err(mpsc::TryRecvError::Disconnected) => {
                app.is_processing = false;
                app.set_error("Export thread disconnected.");
            }
        }
    }

    if let Some(rx) = app.restore_rx.take() {
        match rx.try_recv() {
            Ok(result) => {
                app.is_processing = false;
                match result {
                    Ok(_) => {
                        app.set_status_ok("Wallet restored successfully.");
                        app.refresh_wallet_status();
                        app.restore_mnemonic.clear();
                        app.restore_password.clear();
                        app.restore_share_paths.clear();
                    }
                    Err(e) => app.set_error(&format!("Restore failed: {}", e)),
                }
            }
            Err(mpsc::TryRecvError::Empty) => app.restore_rx = Some(rx),
            Err(mpsc::TryRecvError::Disconnected) => {
                app.is_processing = false;
                app.set_error("Restore thread disconnected.");
            }
        }
    }

    if let Some(rx) = app.change_pwd_rx.take() {
        match rx.try_recv() {
            Ok(result) => {
                app.is_processing = false;
                match result {
                    Ok(_) => {
                        app.set_status_ok("Password changed successfully.");
                        app.old_password.clear();
                        app.new_password.clear();
                    }
                    Err(e) => app.set_error(&format!("Password change failed: {}", e)),
                }
            }
            Err(mpsc::TryRecvError::Empty) => app.change_pwd_rx = Some(rx),
            Err(mpsc::TryRecvError::Disconnected) => {
                app.is_processing = false;
                app.set_error("Password change thread disconnected.");
            }
        }
    }

    if let Some(rx) = app.delete_rx.take() {
        match rx.try_recv() {
            Ok(result) => {
                app.is_processing = false;
                match result {
                    Ok(_) => {
                        app.set_status_ok("Wallet deleted successfully.");
                        app.refresh_wallet_status();
                        app.addresses = None;
                        app.wallet_info = None;
                        app.wallet_loaded = false;
                    }
                    Err(e) => app.set_error(&format!("Deletion failed: {}", e)),
                }
            }
            Err(mpsc::TryRecvError::Empty) => app.delete_rx = Some(rx),
            Err(mpsc::TryRecvError::Disconnected) => {
                app.is_processing = false;
                app.set_error("Deletion thread disconnected.");
            }
        }
    }

    if let Some(rx) = app.convert_rx.take() {
        match rx.try_recv() {
            Ok(result) => {
                app.is_processing = false;
                match result {
                    Ok(conversion_result) => {
                        app.convert_result = Some(conversion_result);
                        app.set_status_ok("Conversion successful.");
                        app.convert_key.clear();
                    }
                    Err(e) => app.set_error(&format!("Conversion failed: {}", e)),
                }
            }
            Err(mpsc::TryRecvError::Empty) => app.convert_rx = Some(rx),
            Err(mpsc::TryRecvError::Disconnected) => {
                app.is_processing = false;
                app.set_error("Conversion thread disconnected.");
            }
        }
    }
}
