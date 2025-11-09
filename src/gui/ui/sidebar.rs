use eframe::egui;
use super::super::app::WalletGui;
use cws::types::View;

pub fn show_sidebar(app: &mut WalletGui, ui: &mut egui::Ui) {
    sidebar_view_button(app, ui, View::Overview, "Overview");
    sidebar_view_button(app, ui, View::Generate, "Generate");
    sidebar_view_button(app, ui, View::Show, "Show");
    sidebar_view_button(app, ui, View::Derive, "Derive");
    sidebar_view_button(app, ui, View::Export, "Export");
    sidebar_view_button(app, ui, View::Convert, "Convert");
    sidebar_view_button(app, ui, View::Restore, "Restore");
    ui.separator();
    sidebar_view_button(app, ui, View::Settings, "Settings");
}

fn sidebar_view_button(app: &mut WalletGui, ui: &mut egui::Ui, view: View, label: &str) {
    if ui.selectable_label(app.current_view == view, label).clicked() {
        app.current_view = view;
        app.clear_messages_and_password();
    }
}
