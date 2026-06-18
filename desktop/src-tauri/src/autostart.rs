//! Автозапуск при вході в Windows — per-user (`HKCU\…\Run`), без адмін-прав і без нової
//! залежності: прямий запис у реєстр через наявний `windows`-крейт. Реєструє поточний .exe
//! із прапором `--minimized`. ЛИШЕ HKCU (не HKLM) — тож ніколи не потребує адміна й оминає
//! HKLM-first-fallback баг `auto-launch`/`tauri-plugin-autostart`.
#![cfg(windows)]

use std::env;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows::Win32::System::Registry::{
    RegDeleteKeyValueW, RegGetValueW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_SZ, RRF_RT_REG_SZ,
};

const RUN_PATH: PCWSTR = w!("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
const VALUE_NAME: PCWSTR = w!("ZortilWatch");

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `"шлях\app.exe" --minimized` — шлях ОБОВ'ЯЗКОВО в лапках (може містити пробіли).
fn launch_command() -> Result<String, String> {
    let exe = env::current_exe().map_err(|e| e.to_string())?;
    Ok(format!("\"{}\" --minimized", exe.display()))
}

/// Увімкнути автозапуск: записати команду в `HKCU\…\Run\ZortilWatch`.
pub fn enable() -> Result<(), String> {
    let cmd = wide(&launch_command()?);
    let cb = (cmd.len() * 2) as u32; // байти REG_SZ, включно з NUL-терміном
    unsafe {
        RegSetKeyValueW(
            HKEY_CURRENT_USER,
            RUN_PATH,
            VALUE_NAME,
            REG_SZ.0,
            Some(cmd.as_ptr() as *const core::ffi::c_void),
            cb,
        )
    }
    .ok()
    .map_err(|e| e.to_string())
}

/// Вимкнути автозапуск: видалити значення (ідемпотентно — «вже немає» = успіх).
pub fn disable() -> Result<(), String> {
    let r = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, RUN_PATH, VALUE_NAME) };
    if r == ERROR_SUCCESS || r == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        Err(format!("RegDeleteKeyValueW: {r:?}"))
    }
}

/// Чи увімкнено автозапуск (наявність значення).
pub fn is_enabled() -> bool {
    let mut size: u32 = 0;
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            RUN_PATH,
            VALUE_NAME,
            RRF_RT_REG_SZ,
            None,
            None,
            Some(&mut size),
        )
    };
    status == ERROR_SUCCESS
}
