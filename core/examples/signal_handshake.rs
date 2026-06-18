//! Наскрізний тест СИГНАЛІНГУ проти ЖИВОГО сервера (без str0m-медіа ще): host і
//! controller у двох потоках роблять register -> connect_request -> incoming_request
//! -> connect_accept -> обидва отримують connect_ready з правильними ролями
//! (host=offerer, controller=answerer). Креди — з .scratch/e2e-creds.json.
//!
//! Сервер має бути піднятий. Запуск:
//!   cargo run -p zortilwatch-core --example signal_handshake

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use serde::Deserialize;
use zortilwatch_core::signal::{ClientMsg, ServerMsg, SignalClient};

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
    let b = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        base.to_string()
    };
    format!("{}/signal", b.trim_end_matches('/'))
}

fn run_host(url: &str, id: &str, secret: &str, ready: Arc<Barrier>) -> Result<String, String> {
    let mut c = SignalClient::connect(url).map_err(|e| e.to_string())?;
    c.set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| e.to_string())?;
    c.register(id, secret, "host").map_err(|e| e.to_string())?;
    ready.wait(); // host онлайн -> пульт може запитувати
    loop {
        match c.recv().map_err(|e| e.to_string())? {
            ServerMsg::IncomingRequest { session_id, .. } => {
                c.send(&ClientMsg::connect_accept(&session_id))
                    .map_err(|e| e.to_string())?;
            }
            ServerMsg::ConnectReady {
                role,
                session_id,
                peer_kind,
                ..
            } => return Ok(format!("role={role} session={session_id} peer={peer_kind}")),
            ServerMsg::SessionClose { reason, .. } => {
                return Err(format!("session_close {reason:?}"))
            }
            _ => {}
        }
    }
}

fn run_controller(
    url: &str,
    id: &str,
    secret: &str,
    target: &str,
    ready: Arc<Barrier>,
) -> Result<String, String> {
    let mut c = SignalClient::connect(url).map_err(|e| e.to_string())?;
    c.set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| e.to_string())?;
    c.register(id, secret, "controller")
        .map_err(|e| e.to_string())?;
    ready.wait(); // чекаємо, поки host онлайн
    c.send(&ClientMsg::connect_request(target))
        .map_err(|e| e.to_string())?;
    loop {
        match c.recv().map_err(|e| e.to_string())? {
            ServerMsg::ConnectReady {
                role,
                session_id,
                peer_kind,
                ..
            } => return Ok(format!("role={role} session={session_id} peer={peer_kind}")),
            ServerMsg::ConnectErr { code, .. } => return Err(format!("connect_err {code}")),
            _ => {}
        }
    }
}

fn main() {
    let path = std::env::var("SIGNAL_CREDS").unwrap_or_else(|_| ".scratch/e2e-creds.json".into());
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let raw = raw.trim_start_matches('\u{feff}'); // PowerShell Out-File utf8 додає BOM
    let creds: Creds = serde_json::from_str(raw).expect("parse creds json");
    let url = ws_url(&creds.base);
    println!("signal url = {url}");

    let barrier = Arc::new(Barrier::new(2));

    let (hu, hi, hs, hb) = (
        url.clone(),
        creds.host.id.clone(),
        creds.host.secret.clone(),
        barrier.clone(),
    );
    let host = thread::spawn(move || run_host(&hu, &hi, &hs, hb));

    let (cu, ci, cs, target, cb) = (
        url.clone(),
        creds.controller.id.clone(),
        creds.controller.secret.clone(),
        creds.host.id.clone(),
        barrier.clone(),
    );
    let ctrl = thread::spawn(move || run_controller(&cu, &ci, &cs, &target, cb));

    let hr = host.join().expect("host thread panicked");
    let cr = ctrl.join().expect("controller thread panicked");
    println!("HOST: {hr:?}");
    println!("CONTROLLER: {cr:?}");

    match (&hr, &cr) {
        (Ok(h), Ok(c)) if h.contains("role=offerer") && c.contains("role=answerer") => {
            println!("RESULT=OK signaling handshake complete (host=offerer, controller=answerer)");
        }
        _ => println!("RESULT=FAIL"),
    }
}
