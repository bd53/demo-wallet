mod app;
mod state;
mod tabs;
mod ui;

pub use app::WalletGui;

pub fn run_gui() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([900.0, 650.0]).with_min_inner_size([700.0, 500.0]).with_title(env!("CARGO_PKG_NAME")),
        ..Default::default()
    };
    eframe::run_native(env!("CARGO_PKG_NAME"), options, Box::new(|_cc| Ok(Box::new(WalletGui::default()))))
}
