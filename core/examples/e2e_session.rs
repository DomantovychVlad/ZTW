//! ПОВНИЙ наскрізний потік ZortilWatch проти ЖИВОГО сервера + P2P-медіа через str0m:
//!
//!   host(=offerer) і controller(=answerer) у двох потоках:
//!   1) register + connect-handshake через WS-сигналінг (як signal_handshake);
//!   2) обмін SDP offer/answer + ICE host-кандидатами через сліпий relay сервера;
//!   3) str0m піднімає DTLS + SCTP datachannel БЕЗПОСЕРЕДНЬО між пірами (P2P, не через сервер);
//!   4) PAKE-сесія B1 поверх каналу з прив'язкою до СПРАВЖНІХ DTLS-відбитків із SDP.
//!
//! Успіх = обидва піри підтвердили сесію й вивели ОДНАКОВИЙ ключ (а сервер його не бачив).
//! Креди — з .scratch/e2e-creds.json. Сервер має бути піднятий. Запуск:
//!   cargo run -p zortilwatch-core --example e2e_session

use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value};
use str0m::change::{SdpAnswer, SdpOffer};
use str0m::channel::ChannelId;
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, Input, Output, Rtc};

use zortilwatch_core::net::new_rtc;
use zortilwatch_core::session::{Handshake, SessionMessage};
use zortilwatch_core::signal::{ClientMsg, ServerMsg, SignalClient};

const PASSWORD: &[u8] = b"one-time-connect-pw"; // у проді — одноразовий пароль підключення

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
    let b = if let Some(r) = base.strip_prefix("https://") {
        format!("wss://{r}")
    } else if let Some(r) = base.strip_prefix("http://") {
        format!("ws://{r}")
    } else {
        base.to_string()
    };
    format!("{}/signal", b.trim_end_matches('/'))
}

/// Витягнути значення `a=fingerprint:` із SDP (напр. "sha-256 AB:CD:..").
fn fingerprint(sdp: &str) -> String {
    sdp.lines()
        .find_map(|l| l.trim().strip_prefix("a=fingerprint:"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Вичерпати poll_output: відіслати Transmit, зафіксувати відкриття каналу й дані.
/// Повертає момент наступного таймауту str0m.
fn drain(
    rtc: &mut Rtc,
    sock: &UdpSocket,
    chan: &mut Option<ChannelId>,
    inbox: &mut Vec<Vec<u8>>,
) -> Instant {
    loop {
        match rtc.poll_output().expect("poll_output") {
            Output::Timeout(t) => return t,
            Output::Transmit(t) => {
                let _ = sock.send_to(&t.contents, t.destination);
            }
            Output::Event(Event::ChannelOpen(id, _label)) => *chan = Some(id),
            Output::Event(Event::ChannelData(d)) => inbox.push(d.data),
            Output::Event(_) => {}
        }
    }
}

fn write_session(rtc: &mut Rtc, cid: ChannelId, msg: &SessionMessage) {
    let bytes = serde_json::to_vec(msg).expect("serialize session msg");
    if let Some(mut ch) = rtc.channel(cid) {
        let _ = ch.write(true, &bytes);
    }
}

/// Прочитати ОДНУ UDP-датаграму (сокет із read-timeout) у rtc; на таймаут — нічого.
fn recv_one(rtc: &mut Rtc, sock: &UdpSocket, my_addr: SocketAddr) {
    let mut buf = [0u8; 2048];
    match sock.recv_from(&mut buf) {
        Ok((n, source)) => {
            let contents = buf[..n].try_into().expect("contents");
            rtc.handle_input(Input::Receive(
                Instant::now(),
                Receive {
                    proto: Protocol::Udp,
                    source,
                    destination: my_addr,
                    contents,
                },
            ))
            .expect("handle_input recv");
        }
        Err(ref e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut => {}
        Err(e) => panic!("recv_from: {e:?}"),
    }
}

/// Драйвити str0m + PAKE-рукостискання до підтвердження або дедлайну.
/// Повертає підтверджений сесійний ключ.
fn run_session(
    mut rtc: Rtc,
    sock: UdpSocket,
    my_addr: SocketAddr,
    own_fp: String,
    peer_fp: String,
) -> Result<[u8; 32], String> {
    sock.set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(|e| e.to_string())?;
    let mut chan: Option<ChannelId> = None;
    let mut inbox: Vec<Vec<u8>> = Vec::new();
    let mut hs: Option<Handshake> = None;

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(h) = hs.as_ref() {
            if h.is_confirmed() {
                return h.confirmed_key().copied().ok_or_else(|| "no key".into());
            }
            if h.is_failed() {
                return Err("session handshake FAILED (wrong pw or MITM)".into());
            }
        }
        if Instant::now() > deadline {
            return Err(format!(
                "timeout (channel_open={}, handshake_started={})",
                chan.is_some(),
                hs.is_some()
            ));
        }

        drain(&mut rtc, &sock, &mut chan, &mut inbox);

        // Канал відкрився -> стартуємо рукостискання (шлемо свій Pake).
        if hs.is_none() {
            if let Some(cid) = chan {
                let (h, msg) = Handshake::start(PASSWORD, own_fp.clone(), peer_fp.clone());
                write_session(&mut rtc, cid, &msg);
                hs = Some(h);
                drain(&mut rtc, &sock, &mut chan, &mut inbox);
            }
        }

        // Вхідні повідомлення сесії -> у рукостискання; відповіді -> назад у канал.
        let msgs = std::mem::take(&mut inbox);
        for raw in msgs {
            if let (Some(h), Some(cid)) = (hs.as_mut(), chan) {
                if let Ok(m) = serde_json::from_slice::<SessionMessage>(&raw) {
                    if let Some(resp) = h.on_message(m) {
                        write_session(&mut rtc, cid, &resp);
                        drain(&mut rtc, &sock, &mut chan, &mut inbox);
                    }
                }
            }
        }

        recv_one(&mut rtc, &sock, my_addr);
        rtc.handle_input(Input::Timeout(Instant::now()))
            .map_err(|e| e.to_string())?;
    }
}

fn payload_str(payload: &Value, key: &str) -> Option<String> {
    payload.get(key).and_then(|v| v.as_str()).map(String::from)
}

/// HOST = offerer.
fn run_host(url: &str, id: &str, secret: &str, ready: Arc<Barrier>) -> Result<[u8; 32], String> {
    let mut sc = SignalClient::connect(url).map_err(|e| e.to_string())?;
    sc.set_read_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| e.to_string())?;
    sc.register(id, secret, "host").map_err(|e| e.to_string())?;
    ready.wait();

    // Чекаємо incoming_request -> accept -> connect_ready; беремо sessionId.
    let session_id = loop {
        match sc.recv().map_err(|e| e.to_string())? {
            ServerMsg::IncomingRequest { session_id, .. } => {
                sc.send(&ClientMsg::connect_accept(&session_id))
                    .map_err(|e| e.to_string())?;
            }
            ServerMsg::ConnectReady {
                session_id, role, ..
            } => {
                if role != "offerer" {
                    return Err(format!("host expected offerer, got {role}"));
                }
                break session_id;
            }
            _ => {}
        }
    };

    // str0m: сокет + host-кандидат.
    let sock = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let my_addr = sock.local_addr().map_err(|e| e.to_string())?;
    let mut rtc = new_rtc(Instant::now());
    let host_cand = Candidate::host(my_addr, "udp").map_err(|e| e.to_string())?;
    rtc.add_local_candidate(host_cand.clone());
    let mut chan = None;
    let mut inbox = Vec::new();
    drain(&mut rtc, &sock, &mut chan, &mut inbox);

    // Створюємо offer + datachannel.
    let mut api = rtc.sdp_api();
    let _cid = api.add_channel("session".to_string());
    let (offer, pending) = api.apply().ok_or("offer has no changes")?;
    drain(&mut rtc, &sock, &mut chan, &mut inbox);
    let offer_sdp = offer.to_sdp_string();
    let own_fp = fingerprint(&offer_sdp);

    sc.send(&ClientMsg::signal(
        &session_id,
        "offer",
        json!({ "sdp": offer_sdp }),
    ))
    .map_err(|e| e.to_string())?;
    sc.send(&ClientMsg::signal(
        &session_id,
        "ice",
        json!({ "cand": host_cand.to_sdp_string() }),
    ))
    .map_err(|e| e.to_string())?;

    // Чекаємо answer + peer-кандидат.
    let mut peer_fp = String::new();
    let mut pending = Some(pending);
    let (mut answered, mut got_cand) = (false, false);
    while !(answered && got_cand) {
        match sc.recv().map_err(|e| e.to_string())? {
            ServerMsg::Signal { kind, payload, .. } => match kind.as_str() {
                "answer" => {
                    let sdp = payload_str(&payload, "sdp").ok_or("answer without sdp")?;
                    peer_fp = fingerprint(&sdp);
                    let ans = SdpAnswer::from_sdp_string(&sdp).map_err(|e| e.to_string())?;
                    rtc.sdp_api()
                        .accept_answer(pending.take().ok_or("double answer")?, ans)
                        .map_err(|e| e.to_string())?;
                    drain(&mut rtc, &sock, &mut chan, &mut inbox);
                    answered = true;
                }
                "ice" => {
                    let c = payload_str(&payload, "cand").ok_or("ice without cand")?;
                    rtc.add_remote_candidate(
                        Candidate::from_sdp_string(&c).map_err(|e| e.to_string())?,
                    );
                    drain(&mut rtc, &sock, &mut chan, &mut inbox);
                    got_cand = true;
                }
                _ => {}
            },
            ServerMsg::SessionClose { reason, .. } => {
                return Err(format!("session_close {reason:?}"))
            }
            _ => {}
        }
    }

    let key = run_session(rtc, sock, my_addr, own_fp, peer_fp)?;
    let _ = sc.send(&ClientMsg::session_close(&session_id, Some("done")));
    Ok(key)
}

/// CONTROLLER = answerer.
fn run_controller(
    url: &str,
    id: &str,
    secret: &str,
    target: &str,
    ready: Arc<Barrier>,
) -> Result<[u8; 32], String> {
    let mut sc = SignalClient::connect(url).map_err(|e| e.to_string())?;
    sc.set_read_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| e.to_string())?;
    sc.register(id, secret, "controller")
        .map_err(|e| e.to_string())?;
    ready.wait();
    sc.send(&ClientMsg::connect_request(target))
        .map_err(|e| e.to_string())?;

    let session_id = loop {
        match sc.recv().map_err(|e| e.to_string())? {
            ServerMsg::ConnectReady {
                session_id, role, ..
            } => {
                if role != "answerer" {
                    return Err(format!("controller expected answerer, got {role}"));
                }
                break session_id;
            }
            ServerMsg::ConnectErr { code, .. } => return Err(format!("connect_err {code}")),
            _ => {}
        }
    };

    let sock = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let my_addr = sock.local_addr().map_err(|e| e.to_string())?;
    let mut rtc = new_rtc(Instant::now());
    let host_cand = Candidate::host(my_addr, "udp").map_err(|e| e.to_string())?;
    rtc.add_local_candidate(host_cand.clone());
    let mut chan = None;
    let mut inbox = Vec::new();
    drain(&mut rtc, &sock, &mut chan, &mut inbox);

    // Чекаємо offer + peer-кандидат; на offer -> шлемо answer + свій кандидат.
    let mut own_fp = String::new();
    let mut peer_fp = String::new();
    let (mut offered, mut got_cand) = (false, false);
    while !(offered && got_cand) {
        match sc.recv().map_err(|e| e.to_string())? {
            ServerMsg::Signal { kind, payload, .. } => match kind.as_str() {
                "offer" => {
                    let sdp = payload_str(&payload, "sdp").ok_or("offer without sdp")?;
                    peer_fp = fingerprint(&sdp);
                    let offer = SdpOffer::from_sdp_string(&sdp).map_err(|e| e.to_string())?;
                    let answer = rtc
                        .sdp_api()
                        .accept_offer(offer)
                        .map_err(|e| e.to_string())?;
                    drain(&mut rtc, &sock, &mut chan, &mut inbox);
                    let answer_sdp = answer.to_sdp_string();
                    own_fp = fingerprint(&answer_sdp);
                    sc.send(&ClientMsg::signal(
                        &session_id,
                        "answer",
                        json!({ "sdp": answer_sdp }),
                    ))
                    .map_err(|e| e.to_string())?;
                    sc.send(&ClientMsg::signal(
                        &session_id,
                        "ice",
                        json!({ "cand": host_cand.to_sdp_string() }),
                    ))
                    .map_err(|e| e.to_string())?;
                    offered = true;
                }
                "ice" => {
                    let c = payload_str(&payload, "cand").ok_or("ice without cand")?;
                    rtc.add_remote_candidate(
                        Candidate::from_sdp_string(&c).map_err(|e| e.to_string())?,
                    );
                    drain(&mut rtc, &sock, &mut chan, &mut inbox);
                    got_cand = true;
                }
                _ => {}
            },
            ServerMsg::SessionClose { reason, .. } => {
                return Err(format!("session_close {reason:?}"))
            }
            _ => {}
        }
    }

    run_session(rtc, sock, my_addr, own_fp, peer_fp)
}

fn main() {
    let path = std::env::var("SIGNAL_CREDS").unwrap_or_else(|_| ".scratch/e2e-creds.json".into());
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let raw = raw.trim_start_matches('\u{feff}');
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

    match (&hr, &cr) {
        (Ok(hk), Ok(ck)) if hk == ck => {
            println!("HOST: session confirmed ✓");
            println!("CONTROLLER: session confirmed ✓");
            println!("RESULT=OK keys match — E2E encrypted session over server-mediated P2P str0m");
        }
        (Ok(_), Ok(_)) => println!("RESULT=FAIL both confirmed but keys DIFFER"),
        _ => println!("RESULT=FAIL host={hr:?} controller={cr:?}"),
    }
}
