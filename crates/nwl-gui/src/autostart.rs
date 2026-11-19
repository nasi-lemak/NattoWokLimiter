//! Starting the desktop app with the user's login, hidden in the tray.
//!
//! Uses each platform's per-user mechanism, so no administrator rights are
//! needed and only this user is affected:
//! * Linux and BSD: an XDG autostart entry, `~/.config/autostart/nattowok.desktop`;
//! * Windows: the `HKCU\…\CurrentVersion\Run` registry value;
//! * macOS: a LaunchAgent, `~/Library/LaunchAgents/com.nattowok.limiter.plist`.

use std::path::{Path, PathBuf};

/// The command that starts at login: this executable, hidden in the tray.
fn command() -> Result<PathBuf, String> {
    std::env::current_exe().map_err(|e| format!("cannot find the app's own path: {e}"))
}

// The file-based helpers below are unused on Windows, which uses the registry.
#[cfg_attr(windows, allow(dead_code))]
fn home() -> Option<PathBuf> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from)
}

/// XDG autostart entry starting `exe --hidden`.
#[cfg_attr(windows, allow(dead_code))]
fn desktop_entry(exe: &Path) -> String {
    // Desktop entry Exec values quote arguments containing spaces.
    let exe = exe.display().to_string();
    let exe = if exe.contains(' ') { format!("\"{}\"", exe.replace('"', "\\\"")) } else { exe };
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=NattoWok Limiter\n\
         Comment=Network monitor and limiter, in the tray\n\
         Exec={exe} --hidden\n\
         Icon=nattowok\n\
         Terminal=false\n\
         X-GNOME-Autostart-enabled=true\n"
    )
}

/// LaunchAgent running `exe --hidden` at login.
#[cfg_attr(windows, allow(dead_code))]
fn launch_agent(exe: &Path) -> String {
    let escape = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.nattowok.limiter</string>
    <key>ProgramArguments</key>
    <array><string>{}</string><string>--hidden</string></array>
    <key>RunAtLoad</key><true/>
</dict>
</plist>
"#,
        escape(&exe.display().to_string())
    )
}

/// The file that makes the app start at login, where the platform uses one.
#[cfg_attr(windows, allow(dead_code))]
fn entry_path() -> Option<PathBuf> {
    if cfg!(target_os = "macos") {
        home().map(|h| h.join("Library/LaunchAgents/com.nattowok.limiter.plist"))
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| home().map(|h| h.join(".config")))
            .map(|c| c.join("autostart/nattowok.desktop"))
    }
}

#[cfg(windows)]
mod registry {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
    const VALUE: &str = "NattoWok Limiter";
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    fn reg(args: &[&str]) -> Result<bool, String> {
        Command::new("reg.exe")
            .args(args)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map(|o| o.status.success())
            .map_err(|e| format!("running reg.exe: {e}"))
    }

    pub fn enabled() -> bool {
        reg(&["query", KEY, "/v", VALUE]).unwrap_or(false)
    }

    pub fn set(command: &str, on: bool) -> Result<(), String> {
        let ok = if on {
            reg(&["add", KEY, "/v", VALUE, "/t", "REG_SZ", "/d", command, "/f"])?
        } else {
            !enabled() || reg(&["delete", KEY, "/v", VALUE, "/f"])?
        };
        if ok {
            Ok(())
        } else {
            Err("changing the Windows startup entry failed".into())
        }
    }
}

/// Whether the app starts at login.
pub fn enabled() -> bool {
    #[cfg(windows)]
    {
        registry::enabled()
    }
    #[cfg(not(windows))]
    {
        entry_path().is_some_and(|p| p.exists())
    }
}

/// Turns starting at login on or off.
pub fn set(on: bool) -> Result<(), String> {
    let exe = command()?;
    #[cfg(windows)]
    {
        registry::set(&format!("\"{}\" --hidden", exe.display()), on)
    }
    #[cfg(not(windows))]
    {
        let path = entry_path().ok_or("no home directory")?;
        if !on {
            return match std::fs::remove_file(&path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    Err(format!("removing {}: {e}", path.display()))
                }
                _ => Ok(()),
            };
        }
        let content = if cfg!(target_os = "macos") { launch_agent(&exe) } else { desktop_entry(&exe) };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        }
        std::fs::write(&path, content).map_err(|e| format!("writing {}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries() {
        let entry = desktop_entry(Path::new("/usr/bin/nattowok"));
        assert!(entry.contains("\nExec=/usr/bin/nattowok --hidden\n"));
        assert!(entry.starts_with("[Desktop Entry]\nType=Application\n"));
        let spaced = desktop_entry(Path::new("/opt/My Apps/nattowok"));
        assert!(spaced.contains("\nExec=\"/opt/My Apps/nattowok\" --hidden\n"));
        let plist = launch_agent(Path::new("/Applications/A&B.app/nattowok"));
        assert!(
            plist.contains("<string>/Applications/A&amp;B.app/nattowok</string><string>--hidden</string>")
        );
    }
}
