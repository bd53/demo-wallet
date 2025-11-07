use eframe::egui;
use super::super::app::WalletGui;
use super::super::state::View;

pub fn show_sidebar(app: &mut WalletGui, ui: &mut egui::Ui) {
    ui.separator();
    sidebar_view_button(app, ui, View::Overview, "Overview");
    ui.separator();
    sidebar_view_button(app, ui, View::Generate, "Generate");
    sidebar_view_button(app, ui, View::Show, "Show");
    sidebar_view_button(app, ui, View::Derive, "Derive");
    sidebar_view_button(app, ui, View::Export, "Export");
    ui.separator();
    sidebar_view_button(app, ui, View::Restore, "Restore");
    sidebar_view_button(app, ui, View::Settings, "Settings");
    ui.separator();
    ui.label("Status:");
    if app.wallet_exists {
        ui.colored_label(egui::Color32::GREEN, "Wallet Found");
        if let Some(ref wt) = app.wallet_type {
            ui.label(format!("Type: {:?}", wt));
        }
    } else {
        ui.colored_label(egui::Color32::RED, "No Wallet");
    }
}

fn sidebar_view_button(app: &mut WalletGui, ui: &mut egui::Ui, view: View, label: &str) {
    if ui.selectable_label(app.current_view == view, label).clicked() {
        app.current_view = view;
        app.clear_messages_and_password();
    }
}
