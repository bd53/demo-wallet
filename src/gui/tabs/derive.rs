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
        ui.label("Number:");
        ui.add(egui::DragValue::new(&mut app.derive_count).range(1..=20));
    });
    if ui.button("Derive").clicked() && !app.is_processing {
        app.start_derive_accounts(ui.ctx().clone());
    }
    ui.separator();
    if !app.derived_accounts.is_empty() {
        ui.separator();
        egui::ScrollArea::vertical().max_height(400.0).auto_shrink([false; 2]).show(ui, |ui| {
            for (index, addresses) in &app.derived_accounts {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.heading(format!("Account {}", index));
                        if ui.small_button("Copy Bitcoin").clicked() {
                            ui.output_mut(|o| o.copied_text = addresses.bitcoin.p2wpkh.clone());
                        }
                        if ui.small_button("Copy Ethereum").clicked() {
                            ui.output_mut(|o| o.copied_text = addresses.ethereum.clone());
                        }
                        if ui.small_button("Copy Solana").clicked() {
                            ui.output_mut(|o| o.copied_text = addresses.solana.clone());
                        }
                    });
                    ui.label(format!("Bitcoin (SegWit): {}", addresses.bitcoin.p2wpkh));
                    ui.label(format!("Bitcoin (P2PKH): {}", addresses.bitcoin.p2pkh));
                    ui.label(format!("Bitcoin (P2SH): {}", addresses.bitcoin.p2sh));
                    ui.label(format!("Ethereum: {}", addresses.ethereum));
                    ui.label(format!("Solana: {}", addresses.solana));
                });
            }
        });
        ui.separator();
        if ui.button("Clear").clicked() {
            app.derived_accounts.clear();
        }
    }
}
