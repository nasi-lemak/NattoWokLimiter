//! `nattowok`: the NattoWokLimiter desktop app. A native window over the
//! daemon's API; start `nwld` first.

#![cfg_attr(windows, windows_subsystem = "windows")]

mod app;
mod client;
mod data;
mod notify;

use std::sync::{Arc, Mutex};

const USAGE: &str = "usage: nattowok [--server URL]

Desktop app for NattoWokLimiter. Connects to the nwld daemon
(default http://127.0.0.1:7657, or $NWL_SERVER).";

fn main() -> eframe::Result {
    let mut server = std::env::var("NWL_SERVER").unwrap_or_else(|_| "http://127.0.0.1:7657".into());
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--server" => server = args.next().unwrap_or_else(|| exit_usage()),
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            "-V" | "--version" => {
                println!("nattowok {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            _ => exit_usage(),
        }
    }

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("NattoWok Limiter")
            .with_app_id("nattowok")
            .with_inner_size([1180.0, 820.0])
            .with_min_inner_size([760.0, 520.0]),
        ..Default::default()
    };
    eframe::run_native(
        "NattoWok Limiter",
        options,
        Box::new(move |cc| {
            // Arrows and some symbols only exist in the bundled monospace font;
            // let proportional text fall back to it.
            let mut fonts = eframe::egui::FontDefinitions::default();
            if let Some(mono) =
                fonts.families.get(&eframe::egui::FontFamily::Monospace).and_then(|f| f.first()).cloned()
            {
                fonts.families.entry(eframe::egui::FontFamily::Proportional).or_default().push(mono);
            }
            cc.egui_ctx.set_fonts(fonts);
            let client = client::Client::new(&server);
            let shared = Arc::new(Mutex::new(data::Data::new()));
            let ctx = cc.egui_ctx.clone();
            let poller = data::spawn_poller(client.clone(), shared.clone(), move || ctx.request_repaint());
            Ok(Box::new(app::NwlApp::new(&cc.egui_ctx, client, shared, poller)))
        }),
    )
}

fn exit_usage() -> ! {
    eprintln!("{USAGE}");
    std::process::exit(2)
}
