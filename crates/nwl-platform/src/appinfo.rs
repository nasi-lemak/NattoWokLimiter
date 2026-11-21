//! Friendly names and icons for applications.
//!
//! On Linux and the BSDs, installed applications describe themselves in
//! freedesktop `.desktop` entries: a display name ("Firefox"), the command
//! they run and an icon name, which the icon theme turns into a file. The
//! [`DesktopCatalog`] matches a running program to its entry by executable
//! path, by command name, or by window class, and finds the icon file.
//!
//! The daemon runs as a system service, so besides the system directories it
//! also reads every user's `~/.local/share`.

use nwl_core::model::AppId;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// What the platform knows about an application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppInfo {
    pub name: String,
    /// A PNG or SVG file.
    pub icon: Option<PathBuf>,
}

pub trait AppCatalog: Send {
    fn lookup(&mut self, app: &AppId) -> Option<AppInfo>;
}

/// Knows nothing (macOS for now).
pub struct NoCatalog;

impl AppCatalog for NoCatalog {
    fn lookup(&mut self, _: &AppId) -> Option<AppInfo> {
        None
    }
}

/// The platform's catalog. `state_dir` holds converted icons on Windows.
pub fn native_catalog(state_dir: &Path) -> Box<dyn AppCatalog> {
    #[cfg(windows)]
    {
        return Box::new(crate::windows::appinfo::WindowsCatalog::new(state_dir.join("icons")));
    }
    #[allow(unreachable_code)]
    if cfg!(target_os = "macos") {
        let _ = state_dir;
        Box::new(NoCatalog)
    } else {
        Box::new(DesktopCatalog::new(DesktopCatalog::system_data_dirs()))
    }
}

#[derive(Debug, Clone)]
struct Entry {
    name: String,
    icon: Option<String>,
    /// Resolved executable of `TryExec`/`Exec`, when it could be found.
    exe: Option<PathBuf>,
    /// Basename of the command it runs.
    command: Option<String>,
    wm_class: Option<String>,
    /// Hidden from menus (helpers, settings panels): matched last.
    no_display: bool,
}

/// Matches programs to installed `.desktop` entries.
pub struct DesktopCatalog {
    data_dirs: Vec<PathBuf>,
    entries: Vec<Entry>,
    scanned: Option<Instant>,
}

/// How often entries are re-read, to pick up newly installed applications.
const RESCAN: Duration = Duration::from_secs(600);

/// Wrappers whose arguments name the real program.
const WRAPPERS: [&str; 3] = ["env", "sh", "bash"];

impl DesktopCatalog {
    /// `data_dirs` are XDG data directories (each with `applications/` and
    /// `icons/` inside), most important first.
    pub fn new(data_dirs: Vec<PathBuf>) -> Self {
        Self { data_dirs, entries: Vec::new(), scanned: None }
    }

    /// `$XDG_DATA_DIRS` (or its default), Flatpak and Snap exports, and every
    /// user's `~/.local/share`.
    pub fn system_data_dirs() -> Vec<PathBuf> {
        let mut dirs: Vec<PathBuf> = Vec::new();
        let mut homes: Vec<PathBuf> = std::env::var_os("HOME").map(PathBuf::from).into_iter().collect();
        if let Ok(read) = std::fs::read_dir("/home") {
            homes.extend(read.flatten().map(|e| e.path()));
        }
        dirs.extend(homes.iter().map(|h| h.join(".local/share")));
        let xdg = std::env::var("XDG_DATA_DIRS").unwrap_or_default();
        let xdg = if xdg.is_empty() { "/usr/local/share:/usr/share".to_string() } else { xdg };
        dirs.extend(xdg.split(':').filter(|d| !d.is_empty()).map(PathBuf::from));
        dirs.push("/var/lib/flatpak/exports/share".into());
        dirs.push("/var/lib/snapd/desktop".into());
        let mut seen = std::collections::HashSet::new();
        dirs.retain(|d| seen.insert(d.clone()));
        dirs
    }

    fn scan(&mut self) {
        let mut entries = Vec::new();
        for dir in &self.data_dirs {
            let Ok(read) = std::fs::read_dir(dir.join("applications")) else { continue };
            let mut files: Vec<PathBuf> = read
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "desktop"))
                .collect();
            files.sort();
            for file in files {
                if let Some(entry) = std::fs::read_to_string(&file).ok().and_then(|s| parse_entry(&s)) {
                    entries.push(entry);
                }
            }
        }
        self.entries = entries;
        self.scanned = Some(Instant::now());
    }

    fn find(&self, exe: &Path) -> Option<&Entry> {
        let base = exe.file_name()?.to_str()?;
        let canonical = std::fs::canonicalize(exe).unwrap_or_else(|_| exe.to_path_buf());
        // Visible entries first; within each, the most specific match.
        for hidden in [false, true] {
            let pool = || self.entries.iter().filter(move |e| e.no_display == hidden);
            let found = pool()
                .find(|e| e.exe.as_deref().is_some_and(|x| x == exe || x == canonical))
                .or_else(|| {
                    pool().find(|e| e.command.as_deref().is_some_and(|c| c.eq_ignore_ascii_case(base)))
                })
                .or_else(|| {
                    pool().find(|e| e.wm_class.as_deref().is_some_and(|c| c.eq_ignore_ascii_case(base)))
                })
                // A program in an app's own directory (a launcher script
                // starts `soffice.bin` next to `soffice`) belongs to it; with
                // several entries there, the plainest name ("LibreOffice").
                .or_else(|| {
                    let dir = canonical.parent().filter(|d| !is_shared_dir(d))?;
                    pool()
                        .filter(|e| e.exe.as_deref().and_then(Path::parent) == Some(dir))
                        .min_by_key(|e| e.name.len())
                });
            if found.is_some() {
                return found;
            }
        }
        None
    }

    /// The icon file for an icon name: hicolor in a preferred size, then
    /// any size, then `pixmaps`.
    fn icon_file(&self, icon: &str) -> Option<PathBuf> {
        let path = Path::new(icon);
        if path.is_absolute() {
            return path.is_file().then(|| path.to_path_buf());
        }
        const SIZES: [&str; 8] =
            ["64x64", "48x48", "128x128", "96x96", "256x256", "scalable", "32x32", "512x512"];
        for dir in &self.data_dirs {
            for size in SIZES {
                for ext in ["png", "svg"] {
                    let file =
                        dir.join("icons/hicolor").join(size).join("apps").join(format!("{icon}.{ext}"));
                    if file.is_file() {
                        return Some(file);
                    }
                }
            }
        }
        for dir in &self.data_dirs {
            for ext in ["png", "svg"] {
                let file = dir.join("pixmaps").join(format!("{icon}.{ext}"));
                if file.is_file() {
                    return Some(file);
                }
            }
        }
        None
    }
}

impl AppCatalog for DesktopCatalog {
    fn lookup(&mut self, app: &AppId) -> Option<AppInfo> {
        // Only executables have entries (on Linux an app id is a path).
        let exe = Path::new(&app.0);
        if !exe.is_absolute() {
            return None;
        }
        if self.scanned.map_or(true, |t| t.elapsed() > RESCAN) {
            self.scan();
        }
        let entry = self.find(exe)?.clone();
        Some(AppInfo { icon: entry.icon.as_deref().and_then(|i| self.icon_file(i)), name: entry.name })
    }
}

/// The `[Desktop Entry]` group of an application entry, if it is one that
/// should name programs (not hidden, not a link).
fn parse_entry(text: &str) -> Option<Entry> {
    let mut fields: HashMap<&str, &str> = HashMap::new();
    let mut in_main = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_main = line == "[Desktop Entry]";
            continue;
        }
        if !in_main || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            fields.entry(k.trim()).or_insert(v.trim());
        }
    }
    if fields.get("Type").copied().unwrap_or("Application") != "Application"
        || fields.get("Hidden") == Some(&"true")
    {
        return None;
    }
    let name = fields.get("Name")?.to_string();
    let program =
        fields.get("TryExec").map(|s| s.to_string()).or_else(|| fields.get("Exec").and_then(|e| program(e)));
    let exe = program.as_deref().and_then(resolve_program);
    let command = program.as_deref().and_then(|p| Path::new(p).file_name()?.to_str().map(String::from));
    Some(Entry {
        name,
        icon: fields.get("Icon").map(|s| s.to_string()).filter(|s| !s.is_empty()),
        exe,
        command,
        wm_class: fields.get("StartupWMClass").map(|s| s.to_string()),
        no_display: fields.get("NoDisplay") == Some(&"true"),
    })
}

/// Directories holding many unrelated programs, where sharing a directory
/// says nothing.
fn is_shared_dir(dir: &Path) -> bool {
    const SHARED: [&str; 8] = [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/libexec",
        "/usr/games",
    ];
    SHARED.iter().any(|s| dir == Path::new(s))
}

/// Splits an `Exec` line into words; double quotes group words.
fn words(exec: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let (mut quoted, mut any) = (false, false);
    for c in exec.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    out.push(std::mem::take(&mut word));
                    any = false;
                }
            }
            c => {
                word.push(c);
                any = true;
            }
        }
    }
    if any {
        out.push(word);
    }
    out
}

/// The program an `Exec` line runs, skipping `env VAR=value` and shells.
fn program(exec: &str) -> Option<String> {
    let words = words(exec);
    let word =
        words.iter().find(|w| !WRAPPERS.contains(&w.as_str()) && !w.contains('=') && !w.starts_with('-'))?;
    // `flatpak run` and similar: the real program isn't on this system's path.
    if word == "flatpak" || word.starts_with('%') {
        return None;
    }
    Some(word.clone())
}

/// An absolute, canonical path for a program name or path.
fn resolve_program(program: &str) -> Option<PathBuf> {
    let path = Path::new(program);
    let found = if path.is_absolute() {
        path.to_path_buf()
    } else {
        let dirs = std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".into());
        dirs.split(':').map(|d| Path::new(d).join(program)).find(|p| p.is_file())?
    };
    std::fs::canonicalize(&found).ok().or(Some(found))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nwl-appinfo-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("applications")).unwrap();
        dir
    }

    #[cfg(unix)]
    fn write(path: PathBuf, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn parses_exec_lines() {
        assert_eq!(program("firefox %u").as_deref(), Some("firefox"));
        assert_eq!(program("env GDK_BACKEND=x11 /opt/app/run --flag").as_deref(), Some("/opt/app/run"));
        assert_eq!(program("\"/opt/My App/app\" %F").as_deref(), Some("/opt/My App/app"));
        assert_eq!(program("flatpak run org.example.App"), None);
        let e = parse_entry("[Desktop Entry]\nName=Thing\nExec=thing\n[Desktop Action new]\nName=Other\n")
            .unwrap();
        assert_eq!(e.name, "Thing");
        assert!(parse_entry("[Desktop Entry]\nType=Link\nName=x\n").is_none());
        assert!(parse_entry("[Desktop Entry]\nName=x\nHidden=true\n").is_none());
    }

    // `.desktop` entries name Unix paths; Windows uses no catalog.
    #[cfg(unix)]
    #[test]
    fn matches_programs_and_finds_icons() {
        let dir = temp_dir("match");
        write(
            dir.join("applications/org.example.Browser.desktop"),
            "[Desktop Entry]\nType=Application\nName=Example Browser\nExec=/opt/browser/browser-launcher %u\n\
             Icon=example-browser\nStartupWMClass=browser-bin\n",
        );
        write(
            dir.join("applications/sync.desktop"),
            "[Desktop Entry]\nName=Sync Tool\nExec=env FOO=1 synctool --daemon\nIcon=/nonexistent/sync.png\n",
        );
        write(
            dir.join("applications/helper.desktop"),
            "[Desktop Entry]\nName=Helper\nExec=synctool\nNoDisplay=true\n",
        );
        write(dir.join("icons/hicolor/48x48/apps/example-browser.png"), "png");
        write(dir.join("icons/hicolor/scalable/apps/example-browser.svg"), "<svg/>");

        let mut catalog = DesktopCatalog::new(vec![dir.clone()]);
        let browser = catalog.lookup(&AppId("/opt/browser/browser-bin".into())).unwrap();
        assert_eq!(browser.name, "Example Browser", "matched by window class");
        assert_eq!(
            browser.icon,
            Some(dir.join("icons/hicolor/48x48/apps/example-browser.png")),
            "PNG preferred"
        );
        let sync = catalog.lookup(&AppId("/usr/libexec/synctool".into())).unwrap();
        assert_eq!(sync.name, "Sync Tool", "matched by command name; visible entries first");
        assert_eq!(sync.icon, None, "missing icon files are not offered");
        assert_eq!(catalog.lookup(&AppId("/usr/bin/unknown".into())), None);

        // Same directory as an entry's program (here the test's own dir).
        let suite = dir.join("suite");
        write(suite.join("launcher"), "#!/bin/sh");
        write(suite.join("worker.bin"), "");
        for (file, name) in [("suite-writer", "Suite Writer"), ("suite-start", "Suite")] {
            let text =
                format!("[Desktop Entry]\nName={name}\nExec={} --x\n", suite.join("launcher").display());
            write(dir.join(format!("applications/{file}.desktop")), &text);
        }
        let mut catalog = DesktopCatalog::new(vec![dir.clone()]);
        let worker = catalog.lookup(&AppId(suite.join("worker.bin").display().to_string())).unwrap();
        assert_eq!(worker.name, "Suite");
        assert_eq!(catalog.lookup(&AppId("System".into())), None);
    }
}
