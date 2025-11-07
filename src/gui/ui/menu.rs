use eframe::egui;
use super::super::app::WalletGui;

pub fn show_menu_bar(app: &mut WalletGui, ui: &mut egui::Ui) {
    egui::menu::bar(ui, |ui| {
        ui.menu_button("File", |ui| {
            if ui.button("Refresh").clicked() {
                app.refresh_wallet_status();
                ui.close_menu();
            }
            ui.separator();
            if ui.button("Exit").clicked() {
                std::process::exit(0);
            }
        });
        ui.menu_button("Help", |ui| {
            if ui.button("About").clicked() {
                app.status_message = format!("{} v{}\n{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"), env!("CARGO_PKG_DESCRIPTION"));
                ui.close_menu();
            }
        });
    });
}
