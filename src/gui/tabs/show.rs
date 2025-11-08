use eframe::egui;
use image::Luma;
use qrcode::QrCode;

use cws::crypto::*;
use cws::derive::*;
use cws::ops::recover_secret_from_shares;
use cws::types::*;
use cws::utils::*;

use super::super::app::WalletGui;

pub fn show_addresses_view(app: &mut WalletGui, ui: &mut egui::Ui) {
    ui.heading("Show");
    ui.separator();
    if !app.wallet_exists {
        ui.colored_label(egui::Color32::RED, "No wallet found.");
        return;
    }
    ui.horizontal(|ui| {
        ui.label("Password:");
        ui.add(egui::TextEdit::singleline(&mut app.password).password(!app.show_password).desired_width(200.0));
        ui.checkbox(&mut app.show_password, "Show");
    });
    ui.horizontal(|ui| {
        ui.label("Account:");
        ui.add(egui::DragValue::new(&mut app.account_index).range(0..=19));
    });
    ui.checkbox(&mut app.show_qr, "Display QR");
    if ui.button("Load").clicked() && !app.is_processing {
        app.start_load_addresses(ui.ctx().clone());
    }
    display_loaded_addresses(app, ui);
}

fn display_loaded_addresses(app: &WalletGui, ui: &mut egui::Ui) {
    let Some(ref addrs) = app.addresses else {
        return;
    };
    ui.separator();
    ui.heading(format!("Account {}", app.account_index));
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
        if app.show_qr {
            if let Some(ref qr_img) = app.qr_images.bitcoin {
                display_qr_image(ui, qr_img, "bitcoin_qr");
            }
        }
    });
    ui.add_space(5.0);
    ui.group(|ui| {
        ui.label("Ethereum:");
        ui.code(&addrs.ethereum);
        if app.show_qr {
            if let Some(ref qr_img) = app.qr_images.ethereum {
                display_qr_image(ui, qr_img, "ethereum_qr");
            }
        }
    });
    ui.add_space(5.0);
    ui.group(|ui| {
        ui.label("Solana:");
        ui.code(&addrs.solana);
        if app.show_qr {
            if let Some(ref qr_img) = app.qr_images.solana {
                display_qr_image(ui, qr_img, "solana_qr");
            }
        }
    });
}

fn display_qr_image(ui: &mut egui::Ui, qr_img: &egui::ColorImage, texture_id: &str) {
    let texture = ui.ctx().load_texture(texture_id, qr_img.clone(), Default::default());
    ui.image(&texture);
}

pub fn load_addresses_internal(password: &str, account_index: u32) -> Result<Addresses, Box<dyn std::error::Error>> {
    let metadata = load_metadata()?.ok_or("Metadata not found.")?;
    let secure_seed = match metadata.wallet_type {
        WalletType::Mnemonic => {
            let wallet_file = get_wallet_file()?;
            let contents = std::fs::read_to_string(wallet_file)?;
            let wallet: EncryptedWallet = serde_json::from_str(&contents)?;
            let secure_mnemonic = decrypt_mnemonic(&wallet, password)?;
            secure_mnemonic.to_seed("")
        }
        WalletType::Seedless => {
            let config = metadata.shamir_config.ok_or("Shamir configuration not found.")?;
            let secret = recover_secret_from_shares(password, config.threshold)?;
            SecureSeed::from_entropy(&secret)
        }
    };
    derive_all_addresses(&secure_seed, account_index)
}

pub fn generate_qr_from_string(data: &str) -> Option<egui::ColorImage> {
    QrCode::new(data).ok().map(|code| {
        let image = code.render::<Luma<u8>>().build();
        let width = image.width() as usize;
        let height = image.height() as usize;
        let pixels = image.into_raw().into_iter().map(|pixel| egui::Color32::from_gray(if pixel > 128 { 255 } else { 0 })).collect();
        egui::ColorImage { size: [width, height], pixels }
    })
}
