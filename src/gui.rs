use eframe::egui;
use image::Luma;
use qrcode::QrCode;
use std::sync::mpsc;
use std::thread;

use cws::crypto::*;
use cws::derive::*;
use cws::ops::*;
use cws::types::*;
use cws::utils::*;

pub struct WalletGui {
    current_view: View,
    wallet_loaded: bool,
    wallet_exists: bool,
    wallet_type: Option<WalletType>,
    password: String,
    show_password: bool,
    word_count: u32,
    seedless_threshold: u8,
    seedless_shares: u8,
    account_index: u32,
    derive_count: u32,
    show_qr: bool,
    restore_mnemonic: String,
    restore_password: String,
    restore_share_paths: String,
    export_chain: String,
    export_account: u32,
    export_share_num: u8,
    old_password: String,
    new_password: String,
    addresses: Option<Addresses>,
    wallet_info: Option<String>,
    status_message: String,
    error_message: String,
    is_generating: bool,
    qr_images: QrImages,
    gen_rx: Option<mpsc::Receiver<Result<(), String>>>,
}

#[derive(Default)]
struct QrImages {
    bitcoin: Option<egui::ColorImage>,
    ethereum: Option<egui::ColorImage>,
    solana: Option<egui::ColorImage>,
}

#[derive(PartialEq)]
enum View {
    Overview,
    Generate,
    Show,
    Derive,
    Export,
    Restore,
    Settings,
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
            addresses: None,
            wallet_info: None,
            status_message: String::new(),
            error_message: String::new(),
            is_generating: false,
            qr_images: QrImages::default(),
            gen_rx: None,
        }
    }
}

impl eframe::App for WalletGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_generation_result();
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            self.show_menu_bar(ui);
        });
        egui::SidePanel::left("sidebar").min_width(150.0).show(ctx, |ui| {
            self.show_sidebar(ui);
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
            self.show_status_bar(ui);
        });
    }
}

impl WalletGui {
    fn handle_generation_result(&mut self) {
        if let Some(rx) = self.gen_rx.take() {
            match rx.try_recv() {
                Ok(result) => {
                    self.is_generating = false;
                    match result {
                        Ok(_) => {
                            self.set_status_ok("Wallet generated successfully.");
                            self.refresh_wallet_status();
                            self.password.clear();
                        }
                        Err(e) => self.set_error(&format!("Generation failed: {}", e)),
                    }
                }
                Err(mpsc::TryRecvError::Empty) => {
                    self.gen_rx = Some(rx);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.is_generating = false;
                    self.set_error("Generation thread disconnected");
                }
            }
        }
    }

    fn show_menu_bar(&mut self, ui: &mut egui::Ui) {
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
    }

    fn show_sidebar(&mut self, ui: &mut egui::Ui) {
        ui.separator();
        self.sidebar_view_button(ui, View::Overview, "Overview");
        ui.separator();
        self.sidebar_view_button(ui, View::Generate, "Generate");
        self.sidebar_view_button(ui, View::Show, "Show");
        self.sidebar_view_button(ui, View::Derive, "Derive");
        self.sidebar_view_button(ui, View::Export, "Export");
        ui.separator();
        self.sidebar_view_button(ui, View::Restore, "Restore");
        self.sidebar_view_button(ui, View::Settings, "Settings");
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
    }

    fn sidebar_view_button(&mut self, ui: &mut egui::Ui, view: View, label: &str) {
        if ui.selectable_label(self.current_view == view, label).clicked() {
            self.current_view = view;
            self.clear_messages_and_password();
        }
    }

    fn show_status_bar(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if !self.error_message.is_empty() {
                ui.colored_label(egui::Color32::RED, self.error_message.as_str());
            } else if !self.status_message.is_empty() {
                ui.colored_label(egui::Color32::GREEN, self.status_message.as_str());
            } else if self.is_generating {
                ui.colored_label(egui::Color32::YELLOW, "Processing...");
            } else {
                ui.label("Ready");
            }
        });
    }

    fn set_status_ok(&mut self, message: &str) {
        self.status_message = message.to_string();
        self.error_message.clear();
    }

    fn set_error(&mut self, message: &str) {
        self.error_message = message.to_string();
        self.status_message.clear();
    }

    fn clear_messages(&mut self) {
        self.status_message.clear();
        self.error_message.clear();
    }

    fn clear_messages_and_password(&mut self) {
        self.clear_messages();
        self.password.clear();
        self.old_password.clear();
        self.new_password.clear();
        self.show_password = false;
    }

    fn refresh_wallet_status(&mut self) {
        self.wallet_exists = wallet_exists().unwrap_or(false);
        self.wallet_type = self.wallet_exists.then(|| load_metadata().ok().flatten().map(|m| m.wallet_type)).flatten();
    }

    fn generate_qr_from_string(&self, data: &str) -> Option<egui::ColorImage> {
        QrCode::new(data).ok().map(|code| {
            let image = code.render::<Luma<u8>>().build();
            let width = image.width() as usize;
            let height = image.height() as usize;
            let pixels = image.into_raw().into_iter().map(|pixel| egui::Color32::from_gray(if pixel > 128 { 255 } else { 0 })).collect();
            egui::ColorImage { size: [width, height], pixels }
        })
    }

    fn show_overview(&mut self, ui: &mut egui::Ui) {
        ui.heading("Overview");
        ui.separator();
        if !self.wallet_exists {
            ui.colored_label(egui::Color32::RED, "No wallet found");
            ui.label("Create a new wallet using the generate tab.");
            return;
        }
        ui.label("Information:");
        ui.horizontal(|ui| {
            ui.label("Password:");
            let response = ui.add(egui::TextEdit::singleline(&mut self.password).password(!self.show_password).desired_width(200.0));
            ui.checkbox(&mut self.show_password, "Show");
            let should_verify = ui.button("Verify").clicked() || (response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
            if should_verify {
                self.verify_and_load_wallet();
            }
        });
        if let Some(ref info) = self.wallet_info {
            ui.group(|ui| {
                ui.label(info);
            });
        }
        if self.wallet_loaded {
            ui.horizontal(|ui| {
                if ui.button("View Addresses").clicked() {
                    self.current_view = View::Show;
                }
                if ui.button("Derive Accounts").clicked() {
                    self.current_view = View::Derive;
                }
                if ui.button("Export Data").clicked() {
                    self.current_view = View::Export;
                }
            });
        }
    }

    fn verify_and_load_wallet(&mut self) {
        match verify_wallet(&self.password) {
            Ok(_) => {
                self.wallet_loaded = true;
                self.set_status_ok("Wallet verified successfully.");
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
                self.set_error(&format!("Verification failed: {}", e));
                self.wallet_info = None;
            }
        }
    }

    fn show_generate(&mut self, ui: &mut egui::Ui) {
        ui.heading("Generate");
        ui.separator();
        if self.wallet_exists {
            ui.colored_label(egui::Color32::RED, "Wallet already exists.");
            ui.label("You must delete the existing wallet before creating a new one.");
            ui.label("Use the settings tab to delete the current wallet.");
            return;
        }
        ui.radio_value(&mut self.word_count, 12, "Mnemonic (12 words)");
        ui.radio_value(&mut self.word_count, 24, "Mnemonic (24 words - Recommended)");
        ui.radio_value(&mut self.word_count, 0, "Seedless (Shamir Secret Sharing)");
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
            ui.label(format!("You will need ANY {} shares to recover this wallet", self.seedless_threshold));
        }
        ui.separator();
        ui.label("Encryption Password:");
        ui.label("(min. 8 chars, must include uppercase, lowercase, number, and symbol)");
        ui.add(egui::TextEdit::singleline(&mut self.password).password(!self.show_password).desired_width(300.0));
        ui.checkbox(&mut self.show_password, "Show password");
        if self.is_generating {
            ui.add_enabled(false, egui::Button::new("Generating Wallet..."));
            ui.label("Please wait, this may take a moment...");
        } else if ui.button("Generate").clicked() {
            self.start_wallet_generation();
        }
    }

    fn start_wallet_generation(&mut self) {
        self.is_generating = true;
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

    fn show_addresses_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Show");
        ui.separator();
        if !self.wallet_exists {
            ui.colored_label(egui::Color32::RED, "No wallet found.");
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
        ui.checkbox(&mut self.show_qr, "Display QR");
        if ui.button("Load").clicked() {
            self.load_and_display_addresses();
        }
        self.display_loaded_addresses(ui);
    }

    fn load_and_display_addresses(&mut self) {
        match self.load_addresses_internal() {
            Ok(addrs) => {
                if self.show_qr {
                    self.qr_images.bitcoin = self.generate_qr_from_string(&addrs.bitcoin.p2wpkh);
                    self.qr_images.ethereum = self.generate_qr_from_string(&addrs.ethereum);
                    self.qr_images.solana = self.generate_qr_from_string(&addrs.solana);
                }
                self.addresses = Some(addrs);
                self.set_status_ok(&format!("Addresses loaded (Account {}).", self.account_index));
            }
            Err(e) => {
                self.set_error(&format!("Failed to load addresses: {}", e));
                self.addresses = None;
                self.qr_images = QrImages::default();
            }
        }
    }

    fn display_loaded_addresses(&self, ui: &mut egui::Ui) {
        let Some(ref addrs) = self.addresses else {
            return;
        };
        ui.separator();
        ui.heading(format!("Account {}", self.account_index));
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
            if self.show_qr {
                if let Some(ref qr_img) = self.qr_images.bitcoin {
                    self.display_qr_image(ui, qr_img, "bitcoin_qr");
                }
            }
        });
        ui.add_space(5.0);
        ui.group(|ui| {
            ui.label("Ethereum:");
            ui.code(&addrs.ethereum);
            if self.show_qr {
                if let Some(ref qr_img) = self.qr_images.ethereum {
                    self.display_qr_image(ui, qr_img, "ethereum_qr");
                }
            }
        });
        ui.add_space(5.0);
        ui.group(|ui| {
            ui.label("Solana:");
            ui.code(&addrs.solana);
            if self.show_qr {
                if let Some(ref qr_img) = self.qr_images.solana {
                    self.display_qr_image(ui, qr_img, "solana_qr");
                }
            }
        });
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

    fn display_qr_image(&self, ui: &mut egui::Ui, qr_img: &egui::ColorImage, texture_id: &str) {
        let texture = ui.ctx().load_texture(texture_id, qr_img.clone(), Default::default());
        ui.image(&texture);
    }

    fn show_derive_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Derive");
        ui.separator();
        if !self.wallet_exists {
            ui.colored_label(egui::Color32::RED, "No wallet found.");
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
        if ui.button("Derive").clicked() {
            match derive_multiple_accounts(&self.password, self.derive_count) {
                Ok(_) => self.set_status_ok(&format!("Derived ({}) accounts successfully.", self.derive_count)),
                Err(e) => self.set_error(&format!("Failed to derive accounts: {}", e)),
            }
        }
        ui.label("Note: Derived addresses are displayed in the console/terminal.");
    }

    fn show_export_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Export");
        ui.separator();
        if !self.wallet_exists {
            ui.colored_label(egui::Color32::RED, "No wallet found.");
            return;
        }
        ui.horizontal(|ui| {
            ui.label("Password:");
            ui.add(egui::TextEdit::singleline(&mut self.password).password(!self.show_password).desired_width(200.0));
            ui.checkbox(&mut self.show_password, "Show");
        });
        ui.separator();
        ui.colored_label(egui::Color32::from_rgb(255, 150, 0), "Warning");
        ui.label("Exporting private keys and mnemonics defeats the purpose of cold storage.");
        ui.label("Only proceed if absolutely necessary and in a secure environment.");
        ui.separator();
        if let Some(ref wt) = self.wallet_type {
            if *wt == WalletType::Mnemonic {
                ui.heading("Export Mnemonic");
                if ui.button("Export").clicked() {
                    match export_mnemonic(&self.password, true) {
                        Ok(_) => self.set_status_ok("Mnemonic displayed in console."),
                        Err(e) => self.set_error(&format!("Failed: {}", e)),
                    }
                }
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
        if ui.button("Export").clicked() {
            match export_private_key(&self.password, &self.export_chain, self.export_account, false) {
                Ok(_) => self.set_status_ok("Private key displayed in console."),
                Err(e) => self.set_error(&format!("Failed: {}", e)),
            }
        }
        if let Some(ref wt) = self.wallet_type {
            if *wt == WalletType::Seedless {
                self.show_export_share_section(ui);
            }
        }
    }

    fn show_export_share_section(&mut self, ui: &mut egui::Ui) {
        ui.heading("Export Share");
        if let Ok(Some(metadata)) = load_metadata() {
            if let Some(config) = metadata.shamir_config {
                ui.label(format!("Total shares: {}", config.total_shares));
                ui.horizontal(|ui| {
                    ui.label("Share Number:");
                    ui.add(egui::DragValue::new(&mut self.export_share_num).range(1..=config.total_shares));
                });
                if ui.button("Export").clicked() {
                    match export_share(&self.password, self.export_share_num, false, None) {
                        Ok(_) => self.set_status_ok("Share displayed in console."),
                        Err(e) => self.set_error(&format!("Failed: {}", e)),
                    }
                }
            }
        }
    }

    fn show_restore_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Restore Wallet");
        ui.separator();
        if self.wallet_exists {
            ui.colored_label(egui::Color32::RED, "Wallet already exists.");
            ui.label("There is nothing to restore, a valid wallet/metadata file was found.");
            return;
        }
        ui.label("Restore from Mnemonic:");
        ui.add(egui::TextEdit::multiline(&mut self.restore_mnemonic).hint_text("Enter 12 or 24 word mnemonic phrase").desired_rows(3).desired_width(f32::INFINITY));
        ui.horizontal(|ui| {
            ui.label("New Password:");
            ui.add(egui::TextEdit::singleline(&mut self.restore_password).password(!self.show_password).desired_width(200.0));
            ui.checkbox(&mut self.show_password, "Show");
        });
        if ui.button("Restore").clicked() {
            match restore_wallet(&self.restore_mnemonic, &self.restore_password) {
                Ok(_) => {
                    self.set_status_ok("Wallet restored successfully.");
                    self.refresh_wallet_status();
                    self.restore_mnemonic.clear();
                    self.restore_password.clear();
                }
                Err(e) => self.set_error(&format!("Restore failed: {}", e)),
            }
        }
        ui.separator();
        ui.label("Restore Seedless Wallet from Shares:");
        ui.add(egui::TextEdit::multiline(&mut self.restore_share_paths).hint_text("Enter share file paths, one per line\nExample:\n/path/to/share_1.json\n/path/to/share_2.json\n/path/to/share_3.json").desired_rows(5).desired_width(f32::INFINITY));
        ui.horizontal(|ui| {
            ui.label("Password:");
            ui.add(egui::TextEdit::singleline(&mut self.restore_password).password(!self.show_password).desired_width(200.0));
        });
        if ui.button("Restore").clicked() {
            self.restore_from_shares();
        }
    }

    fn restore_from_shares(&mut self) {
        let paths: Vec<String> = self.restore_share_paths.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        if paths.is_empty() {
            self.set_error("No share paths provided");
            return;
        }
        match restore_wallet_seedless(&self.restore_password, &paths) {
            Ok(_) => {
                self.set_status_ok("Seedless wallet restored successfully.");
                self.refresh_wallet_status();
                self.restore_share_paths.clear();
                self.restore_password.clear();
            }
            Err(e) => self.set_error(&format!("Restore failed: {}", e)),
        }
    }

    fn show_settings_view(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");
        ui.separator();
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
        ui.checkbox(&mut self.show_password, "Show");
        if ui.button("Change").clicked() {
            match change_password(&self.old_password, &self.new_password) {
                Ok(_) => {
                    self.set_status_ok("Password changed successfully.");
                    self.old_password.clear();
                    self.new_password.clear();
                }
                Err(e) => self.set_error(&format!("Failed: {}", e)),
            }
        }
        ui.separator();
        ui.colored_label(egui::Color32::RED, "Delete Wallet");
        ui.label("This action is PERMANENT and IRREVERSIBLE.");
        ui.label("Make sure you have backed up your mnemonic or shares.");
        if ui.button("Delete").clicked() {
            match delete_wallet(true) {
                Ok(_) => {
                    self.set_status_ok("Wallet deleted successfully.");
                    self.refresh_wallet_status();
                    self.addresses = None;
                    self.wallet_info = None;
                    self.wallet_loaded = false;
                }
                Err(e) => self.set_error(&format!("Failed: {}", e)),
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
