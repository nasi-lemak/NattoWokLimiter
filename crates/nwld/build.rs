//! Embeds the web dashboard, if it was built (`cargo xtask web` writes it to
//! `web/`, or to `$NWL_WEB_DIR`). Without it nwld still builds and its web
//! page explains how to add the dashboard.

use std::path::PathBuf;

const FILES: [(&str, &str); 2] = [("JS", "nattowok.js.gz"), ("WASM", "nattowok_bg.wasm.gz")];

fn main() {
    println!("cargo:rerun-if-env-changed=NWL_WEB_DIR");
    let dir = std::env::var_os("NWL_WEB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("web"));
    println!("cargo:rerun-if-changed={}", dir.display());
    let built = FILES.iter().all(|(_, f)| dir.join(f).is_file());
    let mut code = format!("/// Whether the web dashboard is built in.\npub const BUILT: bool = {built};\n");
    for (name, file) in FILES {
        let path = dir.join(file);
        println!("cargo:rerun-if-changed={}", path.display());
        if built {
            code += &format!("pub const {name}: &[u8] = include_bytes!({:?});\n", path.display().to_string());
        } else {
            code += &format!("pub const {name}: &[u8] = &[];\n");
        }
    }
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("web.rs");
    std::fs::write(out, code).unwrap();
}
