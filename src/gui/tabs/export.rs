use eframe::egui;
use super::super::app::WalletGui;
use cws::types::WalletType;
use cws::utils::load_metadata;

pub fn show_export_view(app: &mut WalletGui, ui: &mut egui::Ui) {
    ui.heading("Export");
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
    ui.separator();
    ui.colored_label(egui::Color32::from_rgb(255, 150, 0), "Warning");
    ui.label("Exporting private keys and mnemonics defeats the purpose of cold storage.");
    ui.label("Only proceed if absolutely necessary and in a secure environment.");
    ui.separator();
    if let Some(ref wt) = app.wallet_type {
        if *wt == WalletType::Mnemonic {
            ui.colored_label(egui::Color32::from_rgb(255, 150, 0), "Export Mnemonic");
            if ui.button("Export").clicked() && !app.is_processing {
                app.start_export_mnemonic();
            }
        }
    }
    ui.colored_label(egui::Color32::from_rgb(255, 150, 0), "Export Private Key");
    ui.horizontal(|ui| {
        ui.label("Chain:");
        egui::ComboBox::from_label("").selected_text(&app.export_chain).show_ui(ui, |ui| {
            ui.selectable_value(&mut app.export_chain, "bitcoin".to_string(), "Bitcoin");
            ui.selectable_value(&mut app.export_chain, "ethereum".to_string(), "Ethereum");
            ui.selectable_value(&mut app.export_chain, "solana".to_string(), "Solana");
        });
    });
    ui.horizontal(|ui| {
        ui.label("Account Index:");
        ui.add(egui::DragValue::new(&mut app.export_account).range(0..=19));
    });
    if ui.button("Export").clicked() && !app.is_processing {
        app.start_export_private_key();
    }
    if let Some(ref wt) = app.wallet_type {
        if *wt == WalletType::Seedless {
            show_export_share_section(app, ui);
        }
    }
}

fn show_export_share_section(app: &mut WalletGui, ui: &mut egui::Ui) {
    ui.colored_label(egui::Color32::from_rgb(255, 150, 0), "Export Share");
    if let Ok(Some(metadata)) = load_metadata() {
        if let Some(config) = metadata.shamir_config {
            ui.label(format!("Total shares: {}", config.total_shares));
            ui.horizontal(|ui| {
                ui.label("Share Number:");
                ui.add(egui::DragValue::new(&mut app.export_share_num).range(1..=config.total_shares));
            });
            if ui.button("Export").clicked() && !app.is_processing {
                app.start_export_share();
            }
        }
    }
}
