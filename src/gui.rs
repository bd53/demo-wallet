use eframe::egui;

use cws::crypto::*;
use cws::derive::*;
use cws::ops::*;
use cws::types::*;
use cws::utils::*;

pub struct WalletGui { current_view: View, wallet_loaded: bool, wallet_exists: bool, wallet_type: Option<WalletType>, password: String, show_password: bool, word_count: u32, seedless_threshold: u8, seedless_shares: u8, account_index: u32, derive_count: u32, show_qr: bool, restore_mnemonic: String, restore_password: String, restore_share_paths: String, export_chain: String, export_account: u32, export_share_num: u8, old_password: String, new_password: String, addresses: Option<Addresses>, wallet_info: Option<String>, status_message: String, error_message: String }

#[derive(PartialEq)]
enum View { Overview, Generate, Show, Derive, Export, Restore, Settings }

impl Default for WalletGui {
    fn default() -> Self {
        let wallet_exists = wallet_exists().unwrap_or(false);
        let wallet_type = if wallet_exists { load_metadata().ok().flatten().map(|m| m.wallet_type) } else { None };
        Self { current_view: View::Overview, wallet_loaded: false, wallet_exists, wallet_type, password: String::new(), show_password: false, word_count: 24, seedless_threshold: 3, seedless_shares: 5, account_index: 0, derive_count: 5, show_qr: false, restore_mnemonic: String::new(), restore_password: String::new(), restore_share_paths: String::new(), export_chain: "bitcoin".to_string(), export_account: 0, export_share_num: 1, old_password: String::new(), new_password: String::new(), addresses: None, wallet_info: None, status_message: String::new(), error_message: String::new() }
    }
}

impl eframe::App for WalletGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Refresh").clicked() {
                        self.refresh_wallet_status();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Exit").clicked() {
                        std::process::exit(0);
                    }
                });
                ui.menu_button("Help", |ui| {
                    if ui.button("About").clicked() {
                        self.status_message = format!("{} v{}\n{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"), env!("CARGO_PKG_DESCRIPTION"));
                        ui.close_menu();
                    }
                });
            });
        });
        egui::SidePanel::left("sidebar").min_width(150.0).show(ctx, |ui| {
            ui.heading(env!("CARGO_PKG_NAME"));
            ui.separator();
            ui.add_space(10.0);
            if ui.selectable_label(self.current_view == View::Overview, "Overview").clicked() {
                self.current_view = View::Overview;
                self.clear_messages();
            }
            ui.separator();
            if ui.selectable_label(self.current_view == View::Generate, "Generate").clicked() {
                self.current_view = View::Generate;
                self.clear_messages();
            }
            if ui.selectable_label(self.current_view == View::Show, "Show").clicked() {
                self.current_view = View::Show;
                self.clear_messages();
            }
            if ui.selectable_label(self.current_view == View::Derive, "Derive").clicked() {
                self.current_view = View::Derive;
                self.clear_messages();
            }
            if ui.selectable_label(self.current_view == View::Export, "Export").clicked() {
                self.current_view = View::Export;
                self.clear_messages();
            }
            ui.separator();
            if ui.selectable_label(self.current_view == View::Restore, "Restore").clicked() {
                self.current_view = View::Restore;
                self.clear_messages();
            }
            if ui.selectable_label(self.current_view == View::Settings, "Settings").clicked() {
                self.current_view = View::Settings;
                self.clear_messages();
            }
            ui.add_space(20.0);
            ui.separator();
            ui.label("Status:");
            if self.wallet_exists {
                ui.colored_label(egui::Color32::GREEN, "Wallet Found");
                if let Some(ref wt) = self.wallet_type {
                    ui.label(format!("Type: {:?}", wt));
                }
            } else {
                ui.colored_label(egui::Color32::RED, "No Wallet");
            }
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                match self.current_view {
                    View::Overview => self.show_overview(ui),
                    View::Generate => self.show_generate(ui),
                    View::Show => self.show_addresses_view(ui),
                    View::Derive => self.show_derive_view(ui),
                    View::Export => self.show_export_view(ui),
                    View::Restore => self.show_restore_view(ui),
                    View::Settings => self.show_settings_view(ui),
                }
            });
        });
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if !self.error_message.is_empty() {
                    ui.colored_label(egui::Color32::RED, self.error_message.to_string());
                } else if !self.status_message.is_empty() {
                    ui.colored_label(egui::Color32::GREEN, self.status_message.to_string());
                } else {
                    ui.label("Ready");
                }
            });
        });
    }
}

impl WalletGui {
    fn clear_messages(&mut self) {
        self.status_message.clear();
        self.error_message.clear();
    }

    fn refresh_wallet_status(&mut self) {
        self.wallet_exists = wallet_exists().unwrap_or(false);
        self.wallet_type = if self.wallet_exists { load_metadata().ok().flatten().map(|m| m.wallet_type) } else { None };
    }

    fn show_overview(&mut self, ui: &mut egui::Ui) {
        ui.heading("Overview");
        ui.separator();
        ui.add_space(10.0);
        if !self.wallet_exists {
            ui.colored_label(egui::Color32::RED, "No wallet found");
            ui.label("Create a new wallet using the generate tab.");
            return;
        }
        ui.label("Wallet Information:");
        ui.add_space(5.0);
        ui.horizontal(|ui| {
            ui.label("Password:");
            let response = ui.add(egui::TextEdit::singleline(&mut self.password).password(!self.show_password).desired_width(200.0));
            ui.checkbox(&mut self.show_password, "Show");
            if ui.button("Verify Wallet").clicked() || (response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) {
                match verify_wallet(&self.password) {
                    Ok(_) => {
                        self.wallet_loaded = true;
                        self.status_message = "Wallet verified successfully.".to_string();
                        self.error_message.clear();
                        if let Ok(Some(metadata)) = load_metadata() {
                            let mut info = format!("Type: {:?}\nVersion: {}\nCreated: {}\nAccounts: {}", metadata.wallet_type, metadata.version, metadata.created_at, metadata.address_count);
                            if let Some(config) = metadata.shamir_config {
                                info.push_str(&format!("\nShamir: {}-of-{}", config.threshold, config.total_shares));
                            }
                            if let Some(last) = metadata.last_accessed {
                                info.push_str(&format!("\nLast Accessed: {}", last));
                            }
                            self.wallet_info = Some(info);
                        }
                    }
                    Err(e) => {
                        self.wallet_loaded = false;
                        self.error_message = format!("Verification failed: {}", e);
                        self.status_message.clear();
                        self.wallet_info = None;
                    }
                }
            }
        });
        ui.add_space(10.0);
        if let Some(ref info) = self.wallet_info {
            ui.group(|ui| {
                ui.label(info);
            });
        }
        if self.wallet_loaded {
            ui.add_space(10.0);
            ui.separator();
            ui.label("Quick Actions:");
            ui.horizontal(|ui| {
                if ui.button("View Addresses").clicked() {
                    self.current_view = View::Show;
                }
                if ui.button("Derive Accounts").clicked() {
                    self.current_view = View::Derive;
                }
                if ui.button("Export Keys").clicked() {
                    self.current_view = View::Export;
                }
            });
        }
    }

    fn show_generate(&mut self, ui: &mut egui::Ui) {
        ui.heading("Generate New Wallet");
        ui.separator();
        ui.add_space(10.0);
        if self.wallet_exists {
            ui.colored_label(egui::Color32::RED, "Error: A wallet already exists.");
            ui.label("You must delete the existing wallet before creating a new one.");
            ui.label("Use the settings tab to delete the current wallet.");
            return;
        }
        ui.radio_value(&mut self.word_count, 12, "Mnemonic (12 words)");
        ui.radio_value(&mut self.word_count, 24, "Mnemonic (24 words - Recommended)");
        ui.radio_value(&mut self.word_count, 0, "Seedless (Shamir Secret Sharing)");
        ui.add_space(10.0);
        if self.word_count == 0 {
            ui.label("Seedless Wallet Configuration:");
            ui.horizontal(|ui| {
                ui.label("Threshold:");
                ui.add(egui::Slider::new(&mut self.seedless_threshold, 2..=10));
            });
            ui.horizontal(|ui| {
                ui.label("Total Shares:");
                ui.add(egui::Slider::new(&mut self.seedless_shares, 3..=10));
            });
            if self.seedless_shares < self.seedless_threshold {
                self.seedless_shares = self.seedless_threshold;
            }
            ui.add_space(5.0);
            ui.label(format!("You will need ANY {} shares to recover this wallet", self.seedless_threshold));
        }
        ui.add_space(10.0);
        ui.separator();
        ui.label("Encryption Password:");
        ui.label("(min. 8 chars, must include uppercase, lowercase, number, and symbol)");
        ui.add(egui::TextEdit::singleline(&mut self.password).password(!self.show_password).desired_width(300.0));
        ui.checkbox(&mut self.show_password, "Show password");
        ui.add_space(15.0);
        if ui.button("Generate Wallet").clicked() {
            let result = if self.word_count == 0 {
                generate_wallet_seedless(&self.password, self.seedless_threshold, self.seedless_shares)
            } else {
                generate_wallet(&self.password, self.word_count)
            };
            match result {
                Ok(_) => {
                    self.status_message = "Wallet generated successfully. Check console for more details.".to_string();
                    self.error_message.clear();
                    self.refresh_wallet_status();
                    self.password.clear();
                }
                Err(e) => {
                    self.error_message = format!("Generation failed: {}", e);
                    self.status_message.clear();
                }
            }
        }
    }

    fn show_addresses_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Show Addresses");
        ui.separator();
        ui.add_space(10.0);
        if !self.wallet_exists {
            ui.colored_label(egui::Color32::RED, "No wallet found. Generate one first.");
            return;
        }
        ui.horizontal(|ui| {
            ui.label("Password:");
            ui.add(egui::TextEdit::singleline(&mut self.password).password(!self.show_password).desired_width(200.0));
            ui.checkbox(&mut self.show_password, "Show");
        });
        ui.horizontal(|ui| {
            ui.label("Account Index:");
            ui.add(egui::DragValue::new(&mut self.account_index).range(0..=19));
        });
        //todo: display qr codes in new window as well
        ui.checkbox(&mut self.show_qr, "Show QR codes (in console)");
        ui.add_space(10.0);
        if ui.button("Load Addresses").clicked() {
            match self.load_addresses_internal() {
                Ok(addrs) => {
                    self.addresses = Some(addrs);
                    self.status_message = format!("Addresses loaded for account {}", self.account_index);
                    self.error_message.clear();
                }
                Err(e) => {
                    self.error_message = format!("Failed to load addresses: {}", e);
                    self.status_message.clear();
                    self.addresses = None;
                }
            }
        }
        if let Some(ref addrs) = self.addresses {
            ui.add_space(15.0);
            ui.separator();
            ui.heading(format!("Account {} Addresses", self.account_index));
            ui.add_space(10.0);
            ui.group(|ui| {
                ui.label("Bitcoin:");
                ui.horizontal(|ui| {
                    ui.label("Legacy (P2PKH):");
                    ui.code(&addrs.bitcoin.p2pkh);
                });
                ui.horizontal(|ui| {
                    ui.label("Native SegWit:");
                    ui.code(&addrs.bitcoin.p2wpkh);
                });
                ui.horizontal(|ui| {
                    ui.label("Wrapped SegWit:");
                    ui.code(&addrs.bitcoin.p2sh);
                });
            });
            ui.add_space(5.0);
            ui.group(|ui| {
                ui.label("Ethereum:");
                ui.code(&addrs.ethereum);
            });
            ui.add_space(5.0);
            ui.group(|ui| {
                ui.label("Solana:");
                ui.code(&addrs.solana);
            });
        }
    }

    fn load_addresses_internal(&self) -> Result<Addresses, Box<dyn std::error::Error>> {
        let metadata = load_metadata()?.ok_or("Metadata not found")?;
        let secure_seed = match metadata.wallet_type {
            WalletType::Mnemonic => {
                let wallet_file = get_wallet_file()?;
                let contents = std::fs::read_to_string(wallet_file)?;
                let wallet: EncryptedWallet = serde_json::from_str(&contents)?;
                let secure_mnemonic = decrypt_mnemonic(&wallet, &self.password)?;
                secure_mnemonic.to_seed("")
            }
            WalletType::Seedless => {
                let config = metadata.shamir_config.ok_or("Shamir configuration not found")?;
                let secret = recover_secret_from_shares(&self.password, config.threshold)?;
                SecureSeed::from_entropy(&secret)
            }
        };
        derive_all_addresses(&secure_seed, self.account_index)
    }

    fn show_derive_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Derive Multiple Accounts");
        ui.separator();
        ui.add_space(10.0);
        if !self.wallet_exists {
            ui.colored_label(egui::Color32::RED, "No wallet found. Generate one first.");
            return;
        }
        ui.horizontal(|ui| {
            ui.label("Password:");
            ui.add(egui::TextEdit::singleline(&mut self.password).password(!self.show_password).desired_width(200.0));
            ui.checkbox(&mut self.show_password, "Show");
        });
        ui.horizontal(|ui| {
            ui.label("Number of accounts:");
            ui.add(egui::DragValue::new(&mut self.derive_count).range(1..=20));
        });
        ui.add_space(10.0);
        if ui.button("Derive Accounts").clicked() {
            match derive_multiple_accounts(&self.password, self.derive_count) {
                Ok(_) => {
                    self.status_message = format!("Derived {} accounts successfully. Check console for more details.", self.derive_count);
                    self.error_message.clear();
                }
                Err(e) => {
                    self.error_message = format!("Failed to derive accounts: {}", e);
                    self.status_message.clear();
                }
            }
        }
        ui.add_space(10.0);
        ui.label("Note: Derived addresses are displayed in the console/terminal.");
    }

    fn show_export_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Export Keys & Data");
        ui.separator();
        ui.add_space(10.0);
        if !self.wallet_exists {
            ui.colored_label(egui::Color32::RED, "No wallet found. Generate one first.");
            return;
        }
        ui.horizontal(|ui| {
            ui.label("Password:");
            ui.add(egui::TextEdit::singleline(&mut self.password).password(!self.show_password).desired_width(200.0));
            ui.checkbox(&mut self.show_password, "Show");
        });
        ui.add_space(15.0);
        ui.separator();
        ui.colored_label(egui::Color32::from_rgb(255, 150, 0), "Security Warning");
        ui.label("Exporting private keys and mnemonics defeats the purpose of cold storage.");
        ui.label("Only proceed if absolutely necessary and in a secure environment.");
        ui.separator();
        ui.add_space(15.0);
        if let Some(ref wt) = self.wallet_type {
            if *wt == WalletType::Mnemonic {
                ui.heading("Export Mnemonic");
                if ui.button("Show Mnemonic (DANGEROUS)").clicked() {
                    match export_mnemonic(&self.password, true) {
                        Ok(_) => {
                            self.status_message = "Mnemonic displayed in console".to_string();
                            self.error_message.clear();
                        }
                        Err(e) => {
                            self.error_message = format!("Failed: {}", e);
                            self.status_message.clear();
                        }
                    }
                }
                ui.add_space(15.0);
            }
        }
        ui.heading("Export Private Key");
        ui.horizontal(|ui| {
            ui.label("Chain:");
            egui::ComboBox::from_label("").selected_text(&self.export_chain).show_ui(ui, |ui| {
                ui.selectable_value(&mut self.export_chain, "bitcoin".to_string(), "Bitcoin");
                ui.selectable_value(&mut self.export_chain, "ethereum".to_string(), "Ethereum");
                ui.selectable_value(&mut self.export_chain, "solana".to_string(), "Solana");
            });
        });
        ui.horizontal(|ui| {
            ui.label("Account:");
            ui.add(egui::DragValue::new(&mut self.export_account).range(0..=19));
        });
        if ui.button("Export Private Key (DANGEROUS)").clicked() {
            match export_private_key(&self.password, &self.export_chain, self.export_account, false) {
                Ok(_) => {
                    self.status_message = "Private key displayed in console".to_string();
                    self.error_message.clear();
                }
                Err(e) => {
                    self.error_message = format!("Failed: {}", e);
                    self.status_message.clear();
                }
            }
        }
        if let Some(ref wt) = self.wallet_type {
            if *wt == WalletType::Seedless {
                ui.add_space(15.0);
                ui.heading("Export Share");
                if let Ok(Some(metadata)) = load_metadata() {
                    if let Some(config) = metadata.shamir_config {
                        ui.label(format!("Total shares: {}", config.total_shares));
                        ui.horizontal(|ui| {
                            ui.label("Share Number:");
                            ui.add(egui::DragValue::new(&mut self.export_share_num).range(1..=config.total_shares));
                        });
                        if ui.button("Export Share").clicked() {
                            match export_share(&self.password, self.export_share_num, false, None) {
                                Ok(_) => {
                                    self.status_message = "Share displayed in console".to_string();
                                    self.error_message.clear();
                                }
                                Err(e) => {
                                    self.error_message = format!("Failed: {}", e);
                                    self.status_message.clear();
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn show_restore_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Restore Wallet");
        ui.separator();
        ui.add_space(10.0);
        if self.wallet_exists {
            ui.colored_label(egui::Color32::RED, "Error: A wallet already exists.");
            ui.label("Delete the existing wallet before restoring.");
            return;
        }
        ui.label("Restore from Mnemonic:");
        ui.add(egui::TextEdit::multiline(&mut self.restore_mnemonic).hint_text("Enter 12 or 24 word mnemonic phrase").desired_rows(3).desired_width(f32::INFINITY));
        ui.horizontal(|ui| {
            ui.label("New Password:");
            ui.add(egui::TextEdit::singleline(&mut self.restore_password).password(!self.show_password).desired_width(200.0));
            ui.checkbox(&mut self.show_password, "Show");
        });
        if ui.button("♻️ Restore from Mnemonic").clicked() {
            match restore_wallet(&self.restore_mnemonic, &self.restore_password) {
                Ok(_) => {
                    self.status_message = "Wallet restored successfully. Check console for more details.".to_string();
                    self.error_message.clear();
                    self.refresh_wallet_status();
                    self.restore_mnemonic.clear();
                    self.restore_password.clear();
                }
                Err(e) => {
                    self.error_message = format!("Restore failed: {}", e);
                    self.status_message.clear();
                }
            }
        }
        ui.add_space(20.0);
        ui.separator();
        ui.add_space(10.0);
        ui.label("Restore Seedless Wallet from Shares:");
        ui.add(egui::TextEdit::multiline(&mut self.restore_share_paths).hint_text("Enter share file paths, one per line\nExample:\n/path/to/share_1.json\n/path/to/share_2.json\n/path/to/share_3.json").desired_rows(5).desired_width(f32::INFINITY));
        ui.horizontal(|ui| {
            ui.label("Password:");
            ui.add(egui::TextEdit::singleline(&mut self.restore_password).password(!self.show_password).desired_width(200.0));
        });
        if ui.button("Restore from Shares").clicked() {
            let paths: Vec<String> = self.restore_share_paths.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            if paths.is_empty() {
                self.error_message = "No share paths provided".to_string();
            } else {
                match restore_wallet_seedless(&self.restore_password, &paths) {
                    Ok(_) => {
                        self.status_message = "Seedless wallet restored successfully. Check console for more details.".to_string();
                        self.error_message.clear();
                        self.refresh_wallet_status();
                        self.restore_share_paths.clear();
                        self.restore_password.clear();
                    }
                    Err(e) => {
                        self.error_message = format!("Restore failed: {}", e);
                        self.status_message.clear();
                    }
                }
            }
        }
    }

    fn show_settings_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");
        ui.separator();
        ui.add_space(10.0);
        if !self.wallet_exists {
            ui.colored_label(egui::Color32::RED, "No wallet found.");
            return;
        }
        ui.heading("Change Password");
        ui.horizontal(|ui| {
            ui.label("Old Password:");
            ui.add(egui::TextEdit::singleline(&mut self.old_password).password(!self.show_password).desired_width(200.0));
        });
        ui.horizontal(|ui| {
            ui.label("New Password:");
            ui.add(egui::TextEdit::singleline(&mut self.new_password).password(!self.show_password).desired_width(200.0));
        });
        ui.checkbox(&mut self.show_password, "Show passwords");
        if ui.button("Change Password").clicked() {
            match change_password(&self.old_password, &self.new_password) {
                Ok(_) => {
                    self.status_message = "Password changed successfully.".to_string();
                    self.error_message.clear();
                    self.old_password.clear();
                    self.new_password.clear();
                }
                Err(e) => {
                    self.error_message = format!("Failed: {}", e);
                    self.status_message.clear();
                }
            }
        }
        ui.add_space(20.0);
        ui.separator();
        ui.add_space(10.0);
        ui.heading("Danger Zone");
        ui.colored_label(egui::Color32::RED, "Delete Wallet");
        ui.label("This action is PERMANENT and IRREVERSIBLE.");
        ui.label("Make sure you have backed up your mnemonic or shares.");
        ui.add_space(10.0);
        if ui.button("Delete Wallet (Permanent)").clicked() {
            match delete_wallet(true) {
                Ok(_) => {
                    self.status_message = "Wallet deleted successfully".to_string();
                    self.error_message.clear();
                    self.refresh_wallet_status();
                    self.addresses = None;
                    self.wallet_info = None;
                    self.wallet_loaded = false;
                }
                Err(e) => {
                    self.error_message = format!("Failed: {}", e);
                    self.status_message.clear();
                }
            }
        }
    }
}

pub fn run_gui() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([900.0, 650.0]).with_min_inner_size([700.0, 500.0]).with_title(env!("CARGO_PKG_NAME")),
        ..Default::default()
    };
    eframe::run_native(env!("CARGO_PKG_NAME"), options, Box::new(|_cc| Ok(Box::new(WalletGui::default()))))
}
