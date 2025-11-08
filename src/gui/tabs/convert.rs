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
    ui.separator();
    if let Some(result) = &app.convert_result {
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.heading("Conversion Result");
                if ui.small_button("Copy").clicked() {
                    ui.output_mut(|o| o.copied_text = result.clone());
                }
            });
            egui::ScrollArea::vertical().max_height(300.0).auto_shrink([false; 2]).show(ui, |ui| {
                for line in result.lines() {
                    ui.monospace(line);
                }
            });
        });
        ui.separator();
        if ui.button("Clear").clicked() {
            app.convert_result = None;
            app.convert_key.clear();
        }
    }
}
