//! Десктопна оболонка ZortilWatch (Tauri v2). Тонкий шар: команди драйвлять
//! `core::connection`, кадри H.264 (base64) йдуть у webview через Tauri Channel.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine;
use tauri::ipc::Channel;
use tauri::{Manager, State};
use zortilwatch_core::connection::Controller;
use zortilwatch_core::input::InputEvent;

#[cfg(windows)]
mod autostart;
mod portable;

/// Перенаправити дані WebView2 у портативному режимі (виклик із `main` до запуску).
pub fn setup_portable_env() {
    portable::setup_env();
}

/// Конфіг застосунку для UI: портативність + типова адреса сервера (PRD 5.11, 5.13).
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AppConfig {
    portable: bool,
    default_server: Option<String>,
}

#[tauri::command]
fn app_config() -> AppConfig {
    AppConfig {
        portable: portable::is_portable(),
        default_server: portable::default_server(),
    }
}

/// Головне вікно (за міткою «main», інакше перше) — стійко до зміни мітки.
fn main_window(app: &tauri::AppHandle) -> Option<tauri::WebviewWindow> {
    app.get_webview_window("main")
        .or_else(|| app.webview_windows().into_values().next())
}

/// Показати й сфокусувати головне вікно (з трею).
fn show_main(app: &tauri::AppHandle) {
    if let Some(w) = main_window(app) {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

/// Стан застосунку: активна сесія пульта + (опційно) фоновий host-режим.
#[derive(Default)]
struct AppState {
    conn: Arc<Mutex<Option<Controller>>>,
    host: Mutex<Option<HostHandle>>,
    transfers: Arc<Transfers>,
}

/// Активні передачі файлів пульта (PRD 5.7).
#[derive(Default)]
struct Transfers {
    /// Завантаження host→пульт: id -> (локальний файл, записано, востаннє оголошено).
    down: Mutex<std::collections::HashMap<u32, (std::fs::File, u64, u64)>>,
    /// Підтверджений host-ом offset для відвантажень (вікно відправника). u64::MAX = ще без ack.
    up_acked: Mutex<std::collections::HashMap<u32, u64>>,
    next_id: std::sync::atomic::AtomicU32,
}

/// Запущений host-режим (керований): serve-loop у фоновому потоці.
struct HostHandle {
    stop: Arc<AtomicBool>,
    /// «Згенерувати новий одноразовий код» (кнопка в UI; serve обробляє за ≤2с).
    rotate: Arc<AtomicBool>,
    /// Поточний одноразовий код (для host_status після перезавантаження webview).
    one_time: Arc<Mutex<Option<String>>>,
    /// Атендантний режим (живий тумблер UI).
    confirm: Arc<AtomicBool>,
    /// Автоблокування Windows після сесії (живий тумблер UI).
    lock_on_end: Arc<AtomicBool>,
    /// Відповіді UI на запити підтвердження: (request_id, allow).
    decide: std::sync::mpsc::Sender<(u64, bool)>,
}

/// Подія host-режиму для webview (через Tauri Channel).
#[derive(Clone, serde::Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum HostUiEvent {
    #[serde(rename_all = "camelCase")]
    OneTime { code: String },
    #[serde(rename_all = "camelCase")]
    Confirm {
        request_id: u64,
        password_kind: String,
    },
}

/// Стан host-режиму для UI.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct HostStatus {
    active: bool,
    one_time: Option<String>,
}

/// Під'єднатися до керованого `target_id` за ID+паролем. Розшифровані H.264 access units
/// (base64) стрімляться у `on_frame`. Блокує до встановлення зашифрованої сесії.
#[tauri::command]
#[allow(clippy::too_many_arguments)] // IPC-команда: аргументи = поля форми підключення
fn connect(
    state: State<'_, AppState>,
    server: String,
    device_id: String,
    client_secret: String,
    password: String,
    password_kind: String,
    target_id: String,
    on_frame: Channel<String>,
) -> Result<(), String> {
    let mut ctrl = Controller::connect(
        &server,
        &device_id,
        &client_secret,
        password.as_bytes(),
        &target_id,
        &password_kind,
    )?;
    let frames = ctrl.take_frames().ok_or("frames already taken")?;

    // Доставка кадрів у webview; файлові кадри (0xF7) пишемо на диск ТУТ (без base64-
    // прогону через webview), керівний JSON перехоплюємо для ack-вікна відвантажень.
    let transfers = state.transfers.clone();
    std::thread::spawn(move || {
        while let Ok(frame) = frames.recv() {
            if frame.first() == Some(&zortilwatch_core::files::FILE_FRAME_MAGIC) {
                if let Some((id, _off, data)) = zortilwatch_core::files::parse_file_frame(&frame) {
                    use std::io::Write;
                    let mut progress: Option<(u32, u64)> = None;
                    if let Ok(mut down) = transfers.down.lock() {
                        if let Some((f, written, announced)) = down.get_mut(&id) {
                            if f.write_all(data).is_ok() {
                                *written += data.len() as u64;
                                if *written - *announced >= 524_288 {
                                    *announced = *written;
                                    progress = Some((id, *written));
                                }
                            }
                        }
                    }
                    if let Some((id, written)) = progress {
                        let ev = format!("{{\"fsLocal\":{{\"id\":{id},\"written\":{written}}}}}");
                        let b64 = base64::engine::general_purpose::STANDARD.encode(ev.as_bytes());
                        if on_frame.send(b64).is_err() {
                            break;
                        }
                    }
                }
                continue;
            }
            if frame.first() == Some(&b'{') {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&frame) {
                    if let Some(p) = v.get("fsProgress") {
                        if let (Some(id), Some(off)) = (p["id"].as_u64(), p["offset"].as_u64()) {
                            if let Ok(mut acked) = transfers.up_acked.lock() {
                                acked.insert(id as u32, off);
                            }
                        }
                    }
                    if let Some(d) = v.get("fsDone") {
                        if let Some(id) = d["id"].as_u64() {
                            if let Ok(mut down) = transfers.down.lock() {
                                down.remove(&(id as u32)); // файл закриється (flush у Drop)
                            }
                        }
                    }
                }
                // прокинути в webview як є (прогрес-бари, списки, буфер)
            }
            let b64 = base64::engine::general_purpose::STANDARD.encode(&frame);
            if on_frame.send(b64).is_err() {
                break;
            }
        }
    });

    *state.conn.lock().map_err(|_| "state poisoned")? = Some(ctrl);
    Ok(())
}

/// Список локального каталогу для панелі файлів ("" = диски).
#[tauri::command]
fn fs_local_list(path: String) -> serde_json::Value {
    zortilwatch_core::files::list_dir(&path)
}

/// Тягнути файл із керованого у локальний шлях (resume: дописуємо з наявного розміру).
#[tauri::command]
fn fs_download(
    state: State<'_, AppState>,
    remote_path: String,
    local_path: String,
) -> Result<u32, String> {
    use std::io::{Seek, SeekFrom};
    let id = state
        .transfers
        .next_id
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&local_path)
        .map_err(|e| e.to_string())?;
    let offset = f.metadata().map(|m| m.len()).unwrap_or(0);
    f.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
    state
        .transfers
        .down
        .lock()
        .map_err(|_| "state poisoned")?
        .insert(id, (f, offset, offset));
    let guard = state.conn.lock().map_err(|_| "state poisoned")?;
    let conn = guard.as_ref().ok_or("not connected")?;
    conn.send_input(InputEvent::FsDownload {
        id,
        path: remote_path,
        offset,
    });
    Ok(id)
}

/// Слати локальний файл на керований (вікно 1МБ за ack-ами fsProgress; resume від
/// offset, який поверне host).
#[tauri::command]
fn fs_upload(
    state: State<'_, AppState>,
    local_path: String,
    remote_path: String,
) -> Result<u32, String> {
    use std::io::{Read, Seek, SeekFrom};
    let id = state
        .transfers
        .next_id
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1);
    let mut f = std::fs::File::open(&local_path).map_err(|e| e.to_string())?;
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    state
        .transfers
        .up_acked
        .lock()
        .map_err(|_| "state poisoned")?
        .insert(id, u64::MAX);
    {
        let guard = state.conn.lock().map_err(|_| "state poisoned")?;
        let conn = guard.as_ref().ok_or("not connected")?;
        conn.send_input(InputEvent::FsUploadStart {
            id,
            path: remote_path,
            size,
        });
    }
    let conn_arc = state.conn.clone();
    let transfers = state.transfers.clone();
    std::thread::spawn(move || {
        // Стартовий ack каже, з якого offset слати (resume).
        let started = std::time::Instant::now();
        let start = loop {
            if started.elapsed() > std::time::Duration::from_secs(15) {
                return;
            }
            match transfers
                .up_acked
                .lock()
                .ok()
                .and_then(|a| a.get(&id).copied())
            {
                Some(u64::MAX) => std::thread::sleep(std::time::Duration::from_millis(50)),
                Some(off) => break off,
                None => return, // скасовано
            }
        };
        if start >= size {
            return; // host уже має весь файл
        }
        if f.seek(SeekFrom::Start(start)).is_err() {
            return;
        }
        let mut sent = start;
        let mut buf = vec![0u8; zortilwatch_core::files::FILE_CHUNK];
        loop {
            // Вікно відправника ≤1МБ поверх ack-ів (не топимо канал з відео).
            let acked = match transfers
                .up_acked
                .lock()
                .ok()
                .and_then(|a| a.get(&id).copied())
            {
                Some(a) if a != u64::MAX => a,
                Some(_) => start,
                None => return, // скасовано
            };
            if sent.saturating_sub(acked) > 1_048_576 {
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            let n = match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            let frame = zortilwatch_core::files::encode_file_frame(id, sent, &buf[..n]);
            {
                let guard = match conn_arc.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                match guard.as_ref() {
                    Some(c) => c.send_raw(frame),
                    None => return, // сесію закрито
                }
            }
            sent += n as u64;
        }
    });
    Ok(id)
}

/// Скасувати передачу (обидва напрями).
#[tauri::command]
fn fs_cancel(state: State<'_, AppState>, id: u32) {
    if let Ok(mut d) = state.transfers.down.lock() {
        d.remove(&id);
    }
    if let Ok(mut a) = state.transfers.up_acked.lock() {
        a.remove(&id);
    }
    if let Ok(guard) = state.conn.lock() {
        if let Some(c) = guard.as_ref() {
            c.send_input(InputEvent::FsCancel { id });
        }
    }
}

/// Надіслати подію вводу керованому (зашифрується й піде каналом).
#[tauri::command]
fn send_input(state: State<'_, AppState>, event: InputEvent) -> Result<(), String> {
    let guard = state.conn.lock().map_err(|_| "state poisoned")?;
    match guard.as_ref() {
        Some(c) => {
            c.send_input(event);
            Ok(())
        }
        None => Err("not connected".into()),
    }
}

/// Розбудити пристрій `target_id` через помічника в його мережі (PRD 5.9).
/// Повертає чесний статус: dispatched | no_helper | unsupported.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct WakeOutcome {
    status: String,
    helpers: u32,
}

#[tauri::command]
fn wake_device(
    server: String,
    device_id: String,
    client_secret: String,
    target_id: String,
) -> Result<WakeOutcome, String> {
    let (status, helpers) = zortilwatch_core::connection::request_wake(
        &server,
        &device_id,
        &client_secret,
        &target_id,
    )?;
    Ok(WakeOutcome { status, helpers })
}

/// Завершити сесію й звільнити ресурси.
#[tauri::command]
fn disconnect(state: State<'_, AppState>) {
    if let Ok(mut guard) = state.conn.lock() {
        if let Some(c) = guard.take() {
            c.close();
        }
    }
}

/// Увімкнути host-режим: ЦЕЙ пристрій приймає вхідні підключення за одноразовим кодом
/// (генерується ядром, прилітає в `on_one_time`) та/або постійним паролем (опційно).
/// Один постійний сигналінг-WS на весь час (присутність «онлайн» не блимає між сесіями);
/// підключення обслуговуються послідовно.
#[tauri::command]
#[allow(clippy::too_many_arguments)] // IPC-команда: аргументи = налаштування host-режиму
fn start_host(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    server: String,
    device_id: String,
    client_secret: String,
    permanent_password: Option<String>,
    confirm_incoming: bool,
    lock_on_end: bool,
    on_event: Channel<HostUiEvent>,
) -> Result<(), String> {
    #[cfg(windows)]
    {
        use zortilwatch_core::connection::{HostEvent, HostOptions, Managed};
        let mut guard = state.host.lock().map_err(|_| "state poisoned")?;
        if guard.is_some() {
            return Ok(()); // вже хостимо
        }
        let stop = Arc::new(AtomicBool::new(false));
        let rotate = Arc::new(AtomicBool::new(false));
        let confirm = Arc::new(AtomicBool::new(confirm_incoming));
        let lock_end = Arc::new(AtomicBool::new(lock_on_end));
        let one_time = Arc::new(Mutex::new(None::<String>));
        let (decide_tx, decide_rx) = std::sync::mpsc::channel::<(u64, bool)>();
        let opts = HostOptions {
            permanent_password: permanent_password
                .filter(|p| !p.is_empty())
                .map(String::into_bytes),
            rotate: rotate.clone(),
            stop: stop.clone(),
            confirm_incoming: confirm.clone(),
            decisions: decide_rx,
            lock_on_end: lock_end.clone(),
        };
        let ot = one_time.clone();
        std::thread::spawn(move || {
            Managed::serve(&server, &device_id, &client_secret, opts, move |ev| {
                match ev {
                    HostEvent::OneTime(code) => {
                        if let Ok(mut g) = ot.lock() {
                            *g = Some(code.clone());
                        }
                        let _ = on_event.send(HostUiEvent::OneTime { code });
                    }
                    HostEvent::Confirm {
                        request_id,
                        password_kind,
                    } => {
                        // Людина має ПОБАЧИТИ запит — підняти вікно (могло бути в треї).
                        show_main(&app);
                        let _ = on_event.send(HostUiEvent::Confirm {
                            request_id,
                            password_kind,
                        });
                    }
                }
            });
        });
        *guard = Some(HostHandle {
            stop,
            rotate,
            one_time,
            confirm,
            lock_on_end: lock_end,
            decide: decide_tx,
        });
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (
            app,
            state,
            server,
            device_id,
            client_secret,
            permanent_password,
            confirm_incoming,
            lock_on_end,
            on_event,
        );
        Err("host-режим доступний лише на Windows".into())
    }
}

/// Перемкнути автоблокування Windows після сесії (живо).
#[tauri::command]
fn set_lock_on_end(state: State<'_, AppState>, enabled: bool) {
    if let Ok(guard) = state.host.lock() {
        if let Some(h) = guard.as_ref() {
            h.lock_on_end.store(enabled, Ordering::Relaxed);
        }
    }
}

/// Перемкнути атендантний режим наживо (без рестарту host).
#[tauri::command]
fn set_confirm_incoming(state: State<'_, AppState>, enabled: bool) {
    if let Ok(guard) = state.host.lock() {
        if let Some(h) = guard.as_ref() {
            h.confirm.store(enabled, Ordering::Relaxed);
        }
    }
}

/// Рішення людини щодо вхідного підключення (діалог «Дозволити/Відхилити»).
#[tauri::command]
fn decide_incoming(state: State<'_, AppState>, request_id: u64, allow: bool) {
    if let Ok(guard) = state.host.lock() {
        if let Some(h) = guard.as_ref() {
            let _ = h.decide.send((request_id, allow));
        }
    }
}

/// Вимкнути host-режим: нові підключення не приймаються, WS закривається (пристрій
/// офлайн) протягом ~2с; поточна сесія, якщо є, доходить природно.
#[tauri::command]
fn stop_host(state: State<'_, AppState>) {
    if let Ok(mut guard) = state.host.lock() {
        if let Some(h) = guard.take() {
            h.stop.store(true, Ordering::Relaxed);
        }
    }
}

/// Стан host-режиму (+ поточний одноразовий код — переживає перезавантаження webview).
#[tauri::command]
fn host_status(state: State<'_, AppState>) -> HostStatus {
    let guard = state.host.lock().ok();
    let host = guard.as_ref().and_then(|g| g.as_ref());
    HostStatus {
        active: host.is_some(),
        one_time: host.and_then(|h| h.one_time.lock().ok().and_then(|g| g.clone())),
    }
}

/// Згенерувати новий одноразовий код (надійде через канал on_one_time за ≤2с).
#[tauri::command]
fn refresh_one_time(state: State<'_, AppState>) {
    if let Ok(guard) = state.host.lock() {
        if let Some(h) = guard.as_ref() {
            h.rotate.store(true, Ordering::Relaxed);
        }
    }
}

/// Увімкнути/вимкнути автозапуск при вході в Windows (per-user, `HKCU\…\Run`, без адміна).
#[tauri::command]
fn set_autostart(enabled: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        if enabled {
            autostart::enable()
        } else {
            autostart::disable()
        }
    }
    #[cfg(not(windows))]
    {
        let _ = enabled;
        Err("автозапуск доступний лише на Windows".into())
    }
}

/// Чи увімкнено автозапуск при вході в Windows.
#[tauri::command]
fn get_autostart() -> bool {
    #[cfg(windows)]
    {
        autostart::is_enabled()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .on_window_event(|window, event| {
            // Закриття вікна під час host-режиму = згорнути у трей (керований лишається онлайн);
            // інакше — звичайне закриття.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let hosting = window
                    .app_handle()
                    .state::<AppState>()
                    .host
                    .lock()
                    .map(|g| g.is_some())
                    .unwrap_or(false);
                if hosting {
                    let _ = window.hide();
                    api.prevent_close();
                }
            }
        })
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            // Системний трей — для фонового/unattended host-режиму (показати вікно / вийти).
            {
                use tauri::menu::{Menu, MenuItem};
                use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
                let show =
                    MenuItem::with_id(app, "show", "Відкрити ZortilWatch", true, None::<&str>)?;
                let quit = MenuItem::with_id(app, "quit", "Вийти", true, None::<&str>)?;
                let menu = Menu::with_items(app, &[&show, &quit])?;
                let mut tray = TrayIconBuilder::new()
                    .tooltip("ZortilWatch")
                    .menu(&menu)
                    .on_menu_event(|app, e| match e.id.as_ref() {
                        "show" => show_main(app),
                        "quit" => app.exit(0),
                        _ => {}
                    })
                    .on_tray_icon_event(|tray, event| {
                        if let TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        } = event
                        {
                            show_main(tray.app_handle());
                        }
                    });
                if let Some(icon) = app.default_window_icon() {
                    tray = tray.icon(icon.clone());
                }
                tray.build(app)?;
            }

            // --minimized (автозапуск): стартувати у трей, не показуючи вікно.
            if std::env::args().any(|a| a == "--minimized") {
                if let Some(w) = main_window(app.handle()) {
                    let _ = w.hide();
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_config,
            connect,
            wake_device,
            send_input,
            disconnect,
            fs_local_list,
            fs_download,
            fs_upload,
            fs_cancel,
            start_host,
            stop_host,
            host_status,
            refresh_one_time,
            set_confirm_incoming,
            set_lock_on_end,
            decide_incoming,
            set_autostart,
            get_autostart
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
