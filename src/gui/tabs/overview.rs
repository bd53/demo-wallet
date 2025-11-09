use eframe::egui;
use super::super::app::WalletGui;
use cws::types::View;

pub fn show_overview_view(app: &mut WalletGui, ui: &mut egui::Ui) {
    ui.heading("Overview");
    ui.separator();
    if !app.wallet_exists {
        ui.colored_label(egui::Color32::RED, "No wallet found");
        ui.label("Create a new wallet using the generate tab.");
        return;
    }
    ui.horizontal(|ui| {
        ui.label("Password:");
        let response = ui.add(egui::TextEdit::singleline(&mut app.password).password(!app.show_password).desired_width(200.0));
        ui.checkbox(&mut app.show_password, "Show");
        let should_verify =
            ui.button("Verify").clicked() || (response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
        if should_verify && !app.is_processing {
            app.start_verify_wallet(ui.ctx().clone());
        }
    });
    if let Some(ref info) = app.wallet_info {
        ui.group(|ui| {
            ui.label(info);
        });
    }
    if app.wallet_loaded {
        ui.horizontal(|ui| {
            if ui.button("View Addresses").clicked() {
                app.current_view = View::Show;
            }
            if ui.button("Derive Accounts").clicked() {
                app.current_view = View::Derive;
            }
            if ui.button("Export Data").clicked() {
                app.current_view = View::Export;
            }
        });
    }
}
