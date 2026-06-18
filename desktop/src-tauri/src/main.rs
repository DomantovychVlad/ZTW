// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Портативний режим: дані WebView2 поряд із .exe (до запуску Tauri/WebView2).
    app_lib::setup_portable_env();
    app_lib::run();
}
