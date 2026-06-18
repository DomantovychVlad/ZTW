//! Портативний режим і конфіг власного сервера (PRD 5.11, 5.13).
//!
//! Портативність визначається НАЯВНІСТЮ файла-маркера `ZortilWatch.portable` поряд із
//! .exe. У цьому режимі дані WebView2 (localStorage: адреса сервера, ідентичність
//! пристрою, постійний пароль) пишуться в `<тека_exe>\data`, а не в `%LOCALAPPDATA%` —
//! тож портативна версія працює з флешки й не лишає слідів у системі.
//!
//! Конфіг власного сервера: опційний `zortilwatch.config.json` поряд із .exe
//! (`{"server": "https://my.host:8787"}`) задає типову адресу сервера для першого
//! запуску — так власник постачає клієнт, уже націлений на свій бекенд.

use std::path::PathBuf;

fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
}

/// Чи це портативний запуск (маркер поряд із .exe).
pub fn is_portable() -> bool {
    exe_dir()
        .map(|d| d.join("ZortilWatch.portable").exists())
        .unwrap_or(false)
}

/// У портативному режимі перенаправити дані WebView2 у теку поряд із .exe.
/// Викликати в `main()` ДО запуску Tauri (WebView2 читає змінну при створенні).
pub fn setup_env() {
    if !is_portable() {
        return;
    }
    if let Some(dir) = exe_dir() {
        let data = dir.join("data");
        let _ = std::fs::create_dir_all(&data);
        // Безпечно: ми у main, до запуску інших потоків.
        std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", &data);
    }
}

/// Типова адреса сервера із `zortilwatch.config.json` поряд із .exe (якщо є).
pub fn default_server() -> Option<String> {
    let path = exe_dir()?.join("zortilwatch.config.json");
    let raw = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    v.get("server")
        .and_then(|s| s.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}
