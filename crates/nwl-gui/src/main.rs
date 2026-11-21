//! `nattowok`: the NattoWokLimiter desktop app. A native window over the
//! daemon's API; start `nwld` first.
//!
//! Compiled to WebAssembly, the same app is the web dashboard nwld serves
//! (build it with `cargo xtask web`).

#![cfg_attr(windows, windows_subsystem = "windows")]
// The browser build leaves out the tray, notification buttons and the CLI.
#![cfg_attr(target_arch = "wasm32", allow(dead_code))]

mod actions;
mod app;
mod autostart;
mod client;
mod data;
mod notify;
mod tray;

use std::sync::{Arc, Mutex};

#[cfg(not(target_arch = "wasm32"))]
const USAGE: &str = "usage: nattowok [--server URL] [--hidden]

  --hidden   start in the tray (used when starting at login); the window
             opens anyway if the desktop shows no tray icon

Desktop app for NattoWokLimiter. Connects to the nwld daemon
(default http://127.0.0.1:7657, or $NWL_SERVER).";

#[cfg(not(target_arch = "wasm32"))]
fn main() -> eframe::Result {
    let mut server = std::env::var("NWL_SERVER").unwrap_or_else(|_| "http://127.0.0.1:7657".into());
    let mut hidden = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--server" => server = args.next().unwrap_or_else(|| exit_usage()),
            "--hidden" => hidden = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            "-V" | "--version" => {
                println!(
                    "nattowok {}\n{}\nSource: {}",
                    env!("CARGO_PKG_VERSION"),
                    nwl_core::NOTICE,
                    nwl_core::SOURCE
                );
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
            .with_min_inner_size([760.0, 520.0])
            .with_visible(!hidden)
            .with_icon(
                eframe::icon_data::from_png_bytes(include_bytes!("../../../packaging/icons/nattowok-64.png"))
                    .expect("bundled icon is a valid PNG"),
            ),
        ..Default::default()
    };
    eframe::run_native(
        "NattoWok Limiter",
        options,
        Box::new(move |cc| {
            set_fonts(&cc.egui_ctx);
            let client = client::Client::new(&server);
            let shared = Arc::new(Mutex::new(data::Data::new()));
            let ctx = cc.egui_ctx.clone();
            let poller = data::spawn_poller(client.clone(), shared.clone(), move || ctx.request_repaint());
            Ok(Box::new(app::NwlApp::new(&cc.egui_ctx, client, shared, poller, hidden)))
        }),
    )
}

/// In the browser (the web dashboard nwld serves): run in the page's canvas,
/// talking to the daemon that served the page.
#[cfg(target_arch = "wasm32")]
fn main() {
    use eframe::wasm_bindgen::JsCast;
    wasm_bindgen_futures::spawn_local(async {
        let document = web_sys::window().and_then(|w| w.document()).expect("running in a page");
        let canvas = document
            .get_element_by_id("nattowok")
            .and_then(|e| e.dyn_into::<web_sys::HtmlCanvasElement>().ok())
            .expect("the page has a <canvas id=\"nattowok\">");
        let result = eframe::WebRunner::new()
            .start(
                canvas,
                eframe::WebOptions::default(),
                Box::new(|cc| {
                    set_fonts(&cc.egui_ctx);
                    let client = client::Client::same_origin();
                    let shared = Arc::new(Mutex::new(data::Data::new()));
                    let ctx = cc.egui_ctx.clone();
                    let poller =
                        data::spawn_poller(client.clone(), shared.clone(), move || ctx.request_repaint());
                    Ok(Box::new(app::NwlApp::new(&cc.egui_ctx, client, shared, poller, false)))
                }),
            )
            .await;
        if let Err(e) = result {
            if let Some(status) = document.get_element_by_id("status") {
                status.set_text_content(Some(&format!("The dashboard failed to start: {e:?}")));
            }
        }
    });
}

/// Arrows and some symbols only exist in the bundled monospace font; let
/// proportional text fall back to it.
fn set_fonts(ctx: &eframe::egui::Context) {
    let mut fonts = eframe::egui::FontDefinitions::default();
    if let Some(mono) =
        fonts.families.get(&eframe::egui::FontFamily::Monospace).and_then(|f| f.first()).cloned()
    {
        fonts.families.entry(eframe::egui::FontFamily::Proportional).or_default().push(mono);
    }
    ctx.set_fonts(fonts);
}

#[cfg(not(target_arch = "wasm32"))]
fn exit_usage() -> ! {
    eprintln!("{USAGE}");
    std::process::exit(2)
}
