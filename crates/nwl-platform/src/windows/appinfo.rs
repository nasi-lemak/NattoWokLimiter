//! Friendly names and icons of Windows programs: the name from the file's
//! version information (`FileDescription`, else `ProductName`), the icon
//! from its resources, converted to PNG and cached in nwld's state folder so
//! the API can serve it like a Linux icon file.

use crate::appinfo::{AppCatalog, AppInfo};
use nwl_core::model::AppId;
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use windows_sys::Win32::Graphics::Gdi::{
    DeleteObject, GetDC, GetDIBits, GetObjectW, ReleaseDC, BITMAP, BITMAPINFO, BITMAPINFOHEADER, BI_RGB,
    DIB_RGB_COLORS,
};
use windows_sys::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};
use windows_sys::Win32::UI::Shell::ExtractIconExW;
use windows_sys::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, HICON, ICONINFO};

pub struct WindowsCatalog {
    icons: PathBuf,
}

impl WindowsCatalog {
    /// `icons`: where converted icons are cached.
    pub fn new(icons: PathBuf) -> Self {
        Self { icons }
    }

    fn icon_file(&self, exe: &Path) -> Option<PathBuf> {
        // One file per program path and size/date, so updates get new icons.
        let meta = std::fs::metadata(exe).ok()?;
        let stamp = meta.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
        let key = format!("{}-{}-{stamp}", exe.display(), meta.len());
        let hash = key.bytes().fold(0xcbf29ce484222325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100000001b3));
        let file = self.icons.join(format!("{hash:016x}.png"));
        if file.is_file() {
            return Some(file);
        }
        let (w, h, rgba) = extract_icon(exe)?;
        let png = encode_png(w, h, &rgba)?;
        std::fs::create_dir_all(&self.icons).ok()?;
        std::fs::write(&file, png).ok()?;
        Some(file)
    }
}

impl AppCatalog for WindowsCatalog {
    fn lookup(&mut self, app: &AppId) -> Option<AppInfo> {
        let exe = Path::new(&app.0);
        if !exe.is_absolute() || !exe.is_file() {
            return None;
        }
        let name = describe(exe);
        let icon = self.icon_file(exe);
        if name.is_none() && icon.is_none() {
            return None;
        }
        let name = name.unwrap_or_else(|| {
            exe.file_stem()
                .map_or_else(|| app.display_name().to_string(), |s| s.to_string_lossy().into_owned())
        });
        Some(AppInfo { name, icon })
    }
}

fn wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}

/// The program's description ("Mozilla Firefox") from its version info.
fn describe(exe: &Path) -> Option<String> {
    let path = wide(exe);
    // SAFETY: `path` is NUL-terminated; buffers are sized as the API says.
    unsafe {
        let size = GetFileVersionInfoSizeW(path.as_ptr(), null_mut());
        if size == 0 {
            return None;
        }
        let mut data = vec![0u8; size as usize];
        if GetFileVersionInfoW(path.as_ptr(), 0, size, data.as_mut_ptr().cast()) == 0 {
            return None;
        }
        let query = |sub: &str| -> Option<(*const c_void, u32)> {
            let sub = wide(sub);
            let (mut ptr, mut len): (*mut c_void, u32) = (null_mut(), 0);
            (VerQueryValueW(data.as_ptr().cast(), sub.as_ptr(), &mut ptr, &mut len) != 0 && !ptr.is_null())
                .then_some((ptr as *const c_void, len))
        };
        // The file's languages, then US English (Unicode and Windows-1252).
        let mut langs: Vec<(u16, u16)> = Vec::new();
        if let Some((ptr, len)) = query("\\VarFileInfo\\Translation") {
            let pairs = std::slice::from_raw_parts(ptr as *const u16, len as usize / 2);
            langs.extend(pairs.as_chunks::<2>().0.iter().map(|p| (p[0], p[1])));
        }
        langs.extend([(0x0409, 0x04b0), (0x0409, 0x04e4)]);
        for key in ["FileDescription", "ProductName"] {
            for (lang, cp) in &langs {
                let Some((ptr, len)) = query(&format!("\\StringFileInfo\\{lang:04x}{cp:04x}\\{key}")) else {
                    continue;
                };
                let text = std::slice::from_raw_parts(ptr as *const u16, len as usize);
                let text = String::from_utf16_lossy(text);
                let text = text.trim_end_matches('\0').trim();
                if !text.is_empty() {
                    return Some(text.to_string());
                }
            }
        }
        None
    }
}

/// The program's main icon as RGBA pixels.
fn extract_icon(exe: &Path) -> Option<(u32, u32, Vec<u8>)> {
    let path = wide(exe);
    // SAFETY: handles come from the API and are released before returning;
    // buffers are sized from the bitmap's own dimensions.
    unsafe {
        let mut icon: HICON = null_mut();
        if ExtractIconExW(path.as_ptr(), 0, &mut icon, null_mut(), 1) == 0 || icon.is_null() {
            return None;
        }
        let pixels = icon_rgba(icon);
        DestroyIcon(icon);
        pixels
    }
}

unsafe fn icon_rgba(icon: HICON) -> Option<(u32, u32, Vec<u8>)> {
    let mut info: ICONINFO = std::mem::zeroed();
    if GetIconInfo(icon, &mut info) == 0 {
        return None;
    }
    let result = (|| {
        if info.hbmColor.is_null() {
            return None; // monochrome icon
        }
        let mut bmp: BITMAP = std::mem::zeroed();
        if GetObjectW(info.hbmColor, std::mem::size_of::<BITMAP>() as i32, (&mut bmp as *mut BITMAP).cast())
            == 0
        {
            return None;
        }
        let (w, h) = (bmp.bmWidth, bmp.bmHeight);
        if w <= 0 || h <= 0 || w > 512 || h > 512 {
            return None;
        }
        let mut pixels = read_bits(info.hbmColor, w, h)?;
        // Icons without an alpha channel: transparency from the mask.
        if pixels.as_chunks::<4>().0.iter().all(|p| p[3] == 0) {
            let mask = read_bits(info.hbmMask, w, h)?;
            for (p, m) in pixels.as_chunks_mut::<4>().0.iter_mut().zip(mask.as_chunks::<4>().0) {
                p[3] = if m[0] == 0 { 255 } else { 0 };
            }
        }
        for p in pixels.as_chunks_mut::<4>().0 {
            p.swap(0, 2); // BGRA -> RGBA
        }
        Some((w as u32, h as u32, pixels))
    })();
    DeleteObject(info.hbmColor);
    DeleteObject(info.hbmMask);
    result
}

/// A bitmap's pixels as 32-bit top-down BGRA.
unsafe fn read_bits(bitmap: *mut c_void, w: i32, h: i32) -> Option<Vec<u8>> {
    let mut bi: BITMAPINFO = std::mem::zeroed();
    bi.bmiHeader = BITMAPINFOHEADER {
        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: w,
        biHeight: -h,
        biPlanes: 1,
        biBitCount: 32,
        biCompression: BI_RGB,
        ..std::mem::zeroed()
    };
    let mut buf = vec![0u8; (w * h * 4) as usize];
    let dc = GetDC(null_mut());
    let lines = GetDIBits(dc, bitmap, 0, h as u32, buf.as_mut_ptr().cast(), &mut bi, DIB_RGB_COLORS);
    ReleaseDC(null_mut(), dc);
    (lines == h).then_some(buf)
}

fn encode_png(w: u32, h: u32, rgba: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut encoder = png::Encoder::new(&mut out, w, h);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    encoder.write_header().ok()?.write_image_data(rgba).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn system32(exe: &str) -> PathBuf {
        let root = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from("C:\\Windows"), PathBuf::from);
        root.join("System32").join(exe)
    }

    #[test]
    fn names_windows_programs() {
        let cmd = describe(&system32("cmd.exe")).expect("cmd.exe has version info");
        assert!(cmd.contains("Command"), "{cmd}");
        assert_eq!(describe(Path::new("C:\\no\\such\\program.exe")), None);
    }

    #[test]
    fn extracts_icons_as_png() {
        let explorer =
            std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from("C:\\Windows"), PathBuf::from);
        let (w, h, rgba) = extract_icon(&explorer.join("explorer.exe")).expect("explorer.exe has an icon");
        assert!(w >= 16 && h >= 16);
        assert_eq!(rgba.len(), (w * h * 4) as usize);
        assert!(rgba.as_chunks::<4>().0.iter().any(|p| p[3] > 0), "not fully transparent");
        let png = encode_png(w, h, &rgba).unwrap();
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");

        let dir = std::env::temp_dir().join(format!("nwl-icons-{}", std::process::id()));
        let mut catalog = WindowsCatalog::new(dir.clone());
        let info = catalog.lookup(&AppId(explorer.join("explorer.exe").display().to_string())).unwrap();
        assert!(info.icon.as_ref().is_some_and(|p| p.starts_with(&dir) && p.is_file()));
        assert!(!info.name.is_empty());
    }
}
