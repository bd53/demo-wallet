use eframe::egui;
use super::super::app::WalletGui;

pub fn show_generate_view(app: &mut WalletGui, ui: &mut egui::Ui) {
    ui.heading("Generate");
    ui.separator();
    if app.wallet_exists {
        ui.colored_label(egui::Color32::RED, "Wallet already exists.");
        ui.label("You must delete the existing wallet before creating a new one.");
        ui.label("Use the settings tab to delete the current wallet.");
        return;
    }
    ui.radio_value(&mut app.word_count, 12, "Mnemonic (12 words)");
    ui.radio_value(&mut app.word_count, 24, "Mnemonic (24 words - Recommended)");
    ui.radio_value(&mut app.word_count, 0, "Seedless (Shamir Secret Sharing)");
    if app.word_count == 0 {
        ui.label("Seedless Wallet Configuration:");
        ui.horizontal(|ui| {
            ui.label("Threshold:");
            ui.add(egui::Slider::new(&mut app.seedless_threshold, 2..=10));
        });
        ui.horizontal(|ui| {
            ui.label("Total Shares:");
            ui.add(egui::Slider::new(&mut app.seedless_shares, 3..=10));
        });
        if app.seedless_shares < app.seedless_threshold {
            app.seedless_shares = app.seedless_threshold;
        }
        ui.label(format!("You will need ANY {} shares to recover this wallet", app.seedless_threshold));
    }
    ui.separator();
    ui.label("Encryption Password:");
    ui.label("(min. 8 chars, must include uppercase, lowercase, number, and symbol)");
    ui.add(egui::TextEdit::singleline(&mut app.password).password(!app.show_password).desired_width(300.0));
    ui.checkbox(&mut app.show_password, "Show");
    if app.is_processing {
        ui.add_enabled(false, egui::Button::new("Generating..."));
        ui.label("Please wait, this may take a moment...");
    } else if ui.button("Generate").clicked() {
        app.start_wallet_generation();
    }
}
