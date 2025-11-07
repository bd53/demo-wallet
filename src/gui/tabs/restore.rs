use eframe::egui;
use super::super::app::WalletGui;

pub fn show_restore_view(app: &mut WalletGui, ui: &mut egui::Ui) {
    ui.heading("Restore Wallet");
    ui.separator();
    if app.wallet_exists {
        ui.colored_label(egui::Color32::RED, "Wallet already exists.");
        ui.label("There is nothing to restore, a valid wallet/metadata file was found.");
        return;
    }
    ui.label("Restore from Mnemonic:");
    ui.add(egui::TextEdit::multiline(&mut app.restore_mnemonic).hint_text("Enter 12 or 24 word mnemonic phrase").desired_rows(3).desired_width(f32::INFINITY));
    ui.horizontal(|ui| {
        ui.label("New Password:");
        ui.add(egui::TextEdit::singleline(&mut app.restore_password).password(!app.show_password).desired_width(200.0));
        ui.checkbox(&mut app.show_password, "Show");
    });
    if ui.button("Restore").clicked() && !app.is_processing {
        app.start_restore_mnemonic();
    }
    ui.separator();
    ui.label("Restore Seedless Wallet from Shares:");
    ui.add(egui::TextEdit::multiline(&mut app.restore_share_paths).hint_text("Enter share file paths, one per line\nExample:\n/path/to/share_1.json\n/path/to/share_2.json\n/path/to/share_3.json").desired_rows(5).desired_width(f32::INFINITY));
    ui.horizontal(|ui| {
        ui.label("Password:");
        ui.add(egui::TextEdit::singleline(&mut app.restore_password).password(!app.show_password).desired_width(200.0));
    });
    if ui.button("Restore").clicked() && !app.is_processing {
        app.start_restore_shares();
    }
}
