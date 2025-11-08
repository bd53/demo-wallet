use eframe::egui;
use super::super::app::WalletGui;

pub fn show_convert_view(app: &mut WalletGui, ui: &mut egui::Ui) {
    ui.heading("Convert");
    ui.separator();
    ui.horizontal(|ui| {
        ui.label("Private Key:");
        ui.add(egui::TextEdit::singleline(&mut app.convert_key).password(true).desired_width(300.0));
    });
    ui.horizontal(|ui| {
        ui.checkbox(&mut app.convert_testnet, "Testnet");
        ui.checkbox(&mut app.convert_uncompressed, "Uncompressed");
    });
    if ui.button("Convert").clicked() && !app.is_processing {
        if app.convert_key.is_empty() {
            app.set_error("Please enter a private key.");
        } else {
            app.start_convert();
        }
    }
    if let Some(result) = &app.convert_result.clone() {
        ui.group(|ui| {
            for line in result.lines() {
                ui.label(line);
            }
        });
        ui.horizontal(|ui| {
            if ui.button("Copy").clicked() {
                ui.output_mut(|o| o.copied_text = result.clone());
            }
            if ui.button("Clear").clicked() {
                app.convert_result = None;
                app.convert_key.clear();
            }
        });
    }
}
