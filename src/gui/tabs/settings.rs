use eframe::egui;
use super::super::app::WalletGui;

pub fn show_settings_view(app: &mut WalletGui, ui: &mut egui::Ui) {
    ui.heading("Settings");
    ui.separator();
    if !app.wallet_exists {
        ui.colored_label(egui::Color32::RED, "No wallet found.");
        return;
    }
    ui.horizontal(|ui| {
        ui.label("Old Password:");
        ui.add(egui::TextEdit::singleline(&mut app.old_password).password(!app.show_password).desired_width(200.0));
    });
    ui.horizontal(|ui| {
        ui.label("New Password:");
        ui.add(egui::TextEdit::singleline(&mut app.new_password).password(!app.show_password).desired_width(200.0));
    });
    ui.checkbox(&mut app.show_password, "Show");
    if ui.button("Change").clicked() && !app.is_processing {
        app.start_change_password();
    }
    ui.separator();
    ui.colored_label(egui::Color32::RED, "Delete Wallet");
    ui.label("This action is PERMANENT and IRREVERSIBLE.");
    ui.label("Make sure you have backed up your mnemonic or shares.");
    if ui.button("Delete").clicked() && !app.is_processing {
        app.start_delete_wallet();
    }
}
