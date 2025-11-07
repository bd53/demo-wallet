use eframe::egui;
use std::sync::mpsc;

use cws::types::*;
use cws::utils::*;

use super::handlers;
use super::state::{View, QrImages};
use super::tabs;
use super::ui;

type AddressResult = Result<(Addresses, Option<QrImages>), String>;
type DerivedAccounts = Vec<(u32, Addresses)>;
type DeriveResult = Result<DerivedAccounts, String>;

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
    pub(crate) addresses: Option<Addresses>,
    pub(crate) wallet_info: Option<String>,
    pub(crate) status_message: String,
    pub(crate) error_message: String,
    pub(crate) is_processing: bool,
    pub(crate) qr_images: QrImages,
    pub(crate) derived_accounts: Vec<(u32, Addresses)>,
    pub(crate) gen_rx: Option<mpsc::Receiver<Result<(), String>>>,
    pub(crate) verify_rx: Option<mpsc::Receiver<Result<String, String>>>,
    pub(crate) addr_rx: Option<mpsc::Receiver<AddressResult>>,
    pub(crate) derive_rx: Option<mpsc::Receiver<DeriveResult>>,
    pub(crate) export_rx: Option<mpsc::Receiver<Result<(), String>>>,
    pub(crate) restore_rx: Option<mpsc::Receiver<Result<(), String>>>,
    pub(crate) change_pwd_rx: Option<mpsc::Receiver<Result<(), String>>>,
    pub(crate) delete_rx: Option<mpsc::Receiver<Result<(), String>>>,
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
}

impl eframe::App for WalletGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        handlers::handle_pending_results(self);
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
