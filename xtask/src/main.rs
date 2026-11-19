//! Build tasks, in Rust so no other tools are needed.
//!
//! `cargo xtask web [--dev]`: builds the desktop app for the browser
//! (WebAssembly) and writes the web dashboard to `crates/nwld/web/`, where the
//! nwld build embeds it. Needs the `wasm32-unknown-unknown` target
//! (`rustup target add wasm32-unknown-unknown`).

use flate2::{write::GzEncoder, Compression};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const USAGE: &str = "usage: cargo xtask web [--dev]

  web     build the web dashboard into crates/nwld/web/ (then build nwld)
  --dev   unoptimized build, faster to compile";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["web"] => web(false),
        ["web", "--dev"] => web(true),
        ["-h" | "--help"] => {
            println!("{USAGE}");
            Ok(())
        }
        _ => Err(USAGE.to_string()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("xtask is in the workspace").to_path_buf()
}

fn web(dev: bool) -> Result<(), String> {
    let root = root();
    let profile = if dev { "dev" } else { "web" };
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let status = Command::new(cargo)
        .current_dir(&root)
        .args(["build", "--package", "nwl-gui", "--bin", "nattowok", "--target", "wasm32-unknown-unknown"])
        .args(["--profile", profile])
        .status()
        .map_err(|e| format!("running cargo: {e}"))?;
    if !status.success() {
        return Err("building the app for wasm32-unknown-unknown failed (is the target installed? \
                    `rustup target add wasm32-unknown-unknown`)"
            .into());
    }

    let target_dir = std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from);
    let profile_dir = if dev { "debug" } else { "web" };
    let wasm = target_dir.join("wasm32-unknown-unknown").join(profile_dir).join("nattowok.wasm");
    let staging = target_dir.join("web-bindgen");
    let _ = std::fs::remove_dir_all(&staging);
    wasm_bindgen_cli_support::Bindgen::new()
        .input_path(&wasm)
        .web(true)
        .map_err(|e| e.to_string())?
        .typescript(false)
        .out_name("nattowok")
        .generate(&staging)
        .map_err(|e| format!("wasm-bindgen: {e}"))?;

    // Stored compressed: smaller nwld, and served as-is with gzip encoding.
    let out = root.join("crates/nwld/web");
    std::fs::create_dir_all(&out).map_err(|e| format!("creating {}: {e}", out.display()))?;
    for name in ["nattowok.js", "nattowok_bg.wasm"] {
        let bytes = std::fs::read(staging.join(name)).map_err(|e| format!("reading {name}: {e}"))?;
        let mut gz = GzEncoder::new(Vec::new(), Compression::best());
        let z =
            gz.write_all(&bytes).and_then(|_| gz.finish()).map_err(|e| format!("compressing {name}: {e}"))?;
        println!("{name}: {} kB, {} kB compressed", bytes.len() / 1000, z.len() / 1000);
        std::fs::write(out.join(format!("{name}.gz")), z).map_err(|e| format!("writing {name}.gz: {e}"))?;
    }
    println!("web dashboard written to {}; build nwld to embed it", out.display());
    Ok(())
}
