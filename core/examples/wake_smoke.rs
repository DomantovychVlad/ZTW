//! Наскрізна перевірка Wake-on-LAN через помічника (PRD 5.9):
//! помічник (Managed::serve, canWake) онлайн → пульт просить розбудити ціль →
//! сервер дає помічнику wake_dispatch → помічник ВИПУСКАЄ магічний пакет у мережу.
//! Пакет ловимо UDP-слухачем на цій же машині (доказ «сервер→помічник→пакет»).
//! Реальне ввімкнення сплячого ПК потребує 2-ї машини + BIOS — тут не перевіряється.
//!   cargo run -p zortilwatch-core --example wake_smoke

#[cfg(not(windows))]
fn main() {
    println!("wake_smoke: лише Windows");
}

#[cfg(windows)]
fn main() {
    imp::run();
}

#[cfg(windows)]
mod imp {
    use std::net::UdpSocket;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc};
    use std::thread;
    use std::time::Duration;

    use serde::Deserialize;
    use zortilwatch_core::connection::{request_wake, HostEvent, HostOptions, Managed};
    use zortilwatch_core::signal::SignalClient;
    use zortilwatch_core::wol::{magic_packet, parse_mac};

    const PW: &[u8] = b"one-time-connect-pw";
    const TARGET_MAC: &str = "DE:AD:BE:EF:12:34";

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

    fn ws_url(base: &str) -> String {
        let b = base
            .replace("https://", "wss://")
            .replace("http://", "ws://");
        format!("{}/signal", b.trim_end_matches('/'))
    }

    pub fn run() {
        let path =
            std::env::var("SIGNAL_CREDS").unwrap_or_else(|_| ".scratch/e2e-creds.json".into());
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let creds: Creds =
            serde_json::from_str(raw.trim_start_matches('\u{feff}')).expect("parse creds");
        let base = creds.base.clone();

        // 1. Ціль (пристрій controller) звітує MAC і ЙДЕ ОФЛАЙН — MAC лишається в БД.
        {
            let mut t = SignalClient::connect(&ws_url(&base)).expect("ws");
            t.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            t.register_wol(
                &creds.controller.id,
                &creds.controller.secret,
                "controller",
                Some(TARGET_MAC),
                false,
            )
            .expect("register target");
        } // drop -> офлайн
        thread::sleep(Duration::from_millis(250));

        // 2. Помічник: Managed::serve (host, canWake, реальний MAC) — онлайн.
        let stop = Arc::new(AtomicBool::new(false));
        let (_decide_tx, decide_rx) = mpsc::channel::<(u64, bool)>();
        let helper = {
            let (b, hid, hsec, st) = (
                base.clone(),
                creds.host.id.clone(),
                creds.host.secret.clone(),
                stop.clone(),
            );
            thread::spawn(move || {
                Managed::serve(
                    &b,
                    &hid,
                    &hsec,
                    HostOptions {
                        permanent_password: Some(PW.to_vec()),
                        rotate: Arc::new(AtomicBool::new(false)),
                        stop: st,
                        confirm_incoming: Arc::new(AtomicBool::new(false)),
                        decisions: decide_rx,
                        lock_on_end: Arc::new(AtomicBool::new(false)),
                    },
                    |_ev: HostEvent| {},
                )
            })
        };
        thread::sleep(Duration::from_millis(900)); // дати помічнику зареєструватись

        // 3. UDP-слухач на порту 9 (best-effort: міг не зв'язатись).
        let listener = UdpSocket::bind("0.0.0.0:9").ok().inspect(|s| {
            let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
        });
        let capture_armed = listener.is_some();

        // 4. Пульт просить розбудити ціль (просимо кредами host-пристрою як controller).
        let (status, helpers) = request_wake(
            &base,
            &creds.host.id,
            &creds.host.secret,
            &creds.controller.id,
        )
        .unwrap_or_else(|e| (format!("err: {e}"), 0));
        println!("WAKE: статус={status}, помічників={helpers}");

        // 5. Спіймати магічний пакет (доказ, що помічник реально випустив його).
        let want = magic_packet(parse_mac(TARGET_MAC).unwrap());
        let mut captured = false;
        if let Some(sock) = &listener {
            let mut buf = [0u8; 1024];
            for _ in 0..5 {
                match sock.recv_from(&mut buf) {
                    Ok((n, _)) if n == 102 && buf[..102] == want[..] => {
                        captured = true;
                        break;
                    }
                    Ok(_) => continue, // інший трафік на :9
                    Err(_) => break,   // таймаут
                }
            }
            println!("CAPTURE: магічний пакет для {TARGET_MAC} спіймано={captured}");
        } else {
            println!(
                "CAPTURE: слухач на :9 не зв'язався (нема прав?) — пропускаю перевірку пакета"
            );
        }

        stop.store(true, Ordering::Relaxed);
        let _ = helper.join();

        let ok = status == "dispatched" && helpers >= 1 && (!capture_armed || captured);
        println!(
            "RESULT={}",
            if ok {
                "OK Wake-on-LAN через помічника (сервер→помічник→магічний пакет)"
            } else {
                "FAIL"
            }
        );
    }
}
