//! Abyssal Warden desktop app (egui). It holds no privileges of its own:
//! standalone, it runs the `abyssal-warden` scanner as the current user;
//! with the service running, it sends authenticated requests to it.
//! Design: docs/architecture/gui.md and ADR-0021.

// No console window behind the app in Windows release builds.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod tasks;

/// The app icon (256 px copy of assets/icons/abyssal-warden.png).
const ICON_PNG: &[u8] = include_bytes!("../../../assets/icons/abyssal-warden-256.png");

fn main() -> eframe::Result {
    let icon = eframe::icon_data::from_png_bytes(ICON_PNG).ok();
    let mut viewport = eframe::egui::ViewportBuilder::default()
        .with_title("Abyssal Warden")
        .with_app_id("abyssal-warden")
        .with_inner_size([980.0, 680.0])
        .with_min_inner_size([720.0, 480.0]);
    if let Some(i) = icon.clone() {
        viewport = viewport.with_icon(std::sync::Arc::new(i));
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "Abyssal Warden",
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, icon.as_ref())))),
    )
}
