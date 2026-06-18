//! Демо-КЕРОВАНИЙ: реєструється на сервері й обслуговує підключення пультів
//! (постійний host-цикл: один сигналінг-WS, присутність не блимає між сесіями) —
//! захоплює екран → H.264 → шле, отриманий ввід інжектує (core::connection::Managed).
//! Друкує дані, які треба ввести в пульті. Windows-only.
//!
//! Запуск (сервер піднятий): cargo run -p zortilwatch-core --example managed_host

#[cfg(not(windows))]
fn main() {
    println!("managed_host: лише Windows (захоплення/інжекція)");
}

#[cfg(windows)]
fn main() {
    use serde::Deserialize;
    use std::sync::atomic::AtomicBool;
    use std::sync::{mpsc, Arc};
    use zortilwatch_core::connection::{HostEvent, HostOptions, Managed};

    #[derive(Deserialize)]
    struct Dev {
        id: String,
        secret: String,
    }
    #[derive(Deserialize)]
    struct Creds {
        base: String,
        host: Dev,
        controller: Dev,
    }

    const PW: &str = "one-time-connect-pw";

    let path = std::env::var("SIGNAL_CREDS").unwrap_or_else(|_| ".scratch/e2e-creds.json".into());
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let raw = raw.trim_start_matches('\u{feff}');
    let creds: Creds = serde_json::from_str(raw).expect("parse creds");

    println!("=== ZortilWatch — КЕРОВАНИЙ пристрій ===");
    println!("Цей пристрій ділиться екраном. У ПУЛЬТІ введіть:");
    println!("  Сервер:        {}", creds.base);
    println!("  Мій ID:        {}", creds.controller.id);
    println!("  Мій secret:    {}", creds.controller.secret);
    println!("  ID керованого: {}", creds.host.id);
    println!("  Пароль:        {PW}");
    println!("Чекаю підключень (постійна присутність, сесії послідовно). Ctrl+C — вихід.");

    // Постійний host-цикл: реконекти/повтори всередині serve. Ctrl+C — вихід.
    let (_decide_tx, decide_rx) = mpsc::channel();
    Managed::serve(
        &creds.base,
        &creds.host.id,
        &creds.host.secret,
        HostOptions {
            permanent_password: Some(PW.as_bytes().to_vec()),
            rotate: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(AtomicBool::new(false)),
            confirm_incoming: Arc::new(AtomicBool::new(false)),
            decisions: decide_rx,
            lock_on_end: Arc::new(AtomicBool::new(false)),
        },
        |ev| {
            if let HostEvent::OneTime(code) = ev {
                println!("Одноразовий код підключення: {code}");
            }
        },
    );
}
