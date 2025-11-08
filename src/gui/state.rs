use eframe::egui;

#[derive(PartialEq)]
pub enum View {
    Overview,
    Generate,
    Show,
    Derive,
    Export,
    Convert,
    Restore,
    Settings,
}

#[derive(Default)]
pub struct QrImages {
    pub bitcoin: Option<egui::ColorImage>,
    pub ethereum: Option<egui::ColorImage>,
    pub solana: Option<egui::ColorImage>,
}
