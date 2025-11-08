use eframe::egui;
use crate::gui::app::{WalletGui, Theme};

pub fn show_settings_view(app: &mut WalletGui, ui: &mut egui::Ui) {
    ui.heading("Settings");
    if !app.wallet_exists {
        ui.colored_label(egui::Color32::RED, "No wallet found.");
        return;
    }
    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label("Theme:");
                ui.radio_value(&mut app.settings.theme, Theme::Light, "Light");
                ui.radio_value(&mut app.settings.theme, Theme::Dark, "Dark");
            });
            ui.horizontal(|ui| {
                ui.label("Font Size:");
                ui.add(egui::Slider::new(&mut app.settings.font_size, 12.0..=20.0).suffix("px").step_by(1.0));
                if ui.small_button("Reset").clicked() {
                    app.settings.font_size = 14.0;
                }
            });
            ui.checkbox(&mut app.settings.compact_mode, "Compact Mode");
            ui.label(egui::RichText::new("Changes apply immediately").small().color(ui.visuals().weak_text_color()));
        });
        ui.horizontal(|ui| {
            if ui.button("Save").clicked() {
                app.save_settings();
                app.set_status_ok("Settings saved successfully.");
            }
            if ui.button("Reset").clicked() {
                app.settings = crate::gui::app::UserSettings::default();
                app.save_settings();
                app.set_status_ok("Settings reset to defaults.");
            }
            ui.label(egui::RichText::new("Settings automatically save when you close the app").small().color(ui.visuals().weak_text_color()));
        });
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label("Old Password:");
                ui.add(egui::TextEdit::singleline(&mut app.old_password).password(!app.show_password).desired_width(200.0));
            });
            ui.horizontal(|ui| {
                ui.label("New Password:");
                ui.add(egui::TextEdit::singleline(&mut app.new_password).password(!app.show_password).desired_width(200.0));
            });
            ui.checkbox(&mut app.show_password, "Show");
            ui.horizontal(|ui| {
                if ui.button("Change").clicked() && !app.is_processing {
                    app.start_change_password(ui.ctx().clone());
                }
                if (!app.old_password.is_empty() || !app.new_password.is_empty()) && ui.button("Clear").clicked() {
                    app.old_password.clear();
                    app.new_password.clear();
                }
            });
        });
        ui.group(|ui| {
            ui.colored_label(egui::Color32::RED, "This action is PERMANENT and IRREVERSIBLE.");
            ui.label("Make sure you have backed up your mnemonic or shares before proceeding.");
            ui.horizontal(|ui| {
                let delete_button = egui::Button::new("Delete").fill(egui::Color32::RED);
                if ui.add(delete_button).clicked() && !app.is_processing {
                    app.start_delete_wallet(ui.ctx().clone());
                }
            });
        });
    });
}
