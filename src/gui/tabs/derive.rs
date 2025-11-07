use eframe::egui;
use super::super::app::WalletGui;

pub fn show_derive_view(app: &mut WalletGui, ui: &mut egui::Ui) {
    ui.heading("Derive");
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
        ui.label("Number of accounts:");
        ui.add(egui::DragValue::new(&mut app.derive_count).range(1..=20));
    });
    if ui.button("Derive").clicked() && !app.is_processing {
        app.start_derive_accounts();
    }
    ui.label("Note: Derived addresses are displayed in the console/terminal.");
}
