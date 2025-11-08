use eframe::egui;
use super::super::app::WalletGui;

pub fn show_status_bar(app: &WalletGui, ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        if !app.error_message.is_empty() {
            ui.colored_label(egui::Color32::RED, app.error_message.as_str());
        } else if !app.status_message.is_empty() {
            ui.colored_label(egui::Color32::GREEN, app.status_message.as_str());
        } else if app.is_processing {
            ui.colored_label(egui::Color32::YELLOW, "Processing...");
        } else if app.wallet_exists {
            ui.colored_label(egui::Color32::GREEN, "Wallet Found");
            if let Some(ref wt) = app.wallet_type {
                ui.label(format!("Type: {:?}", wt));
            }
        } else {
            ui.colored_label(egui::Color32::RED, "No Wallet");
        }
    });
}
