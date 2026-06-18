//! НАСКРІЗНА СЕСІЯ КРІЗЬ TURN-РЕТРАНСЛЯТОР (coturn). Доводить relay-шлях, коли пряме
//! P2P неможливе: обидва піри форсують RELAY-ONLY кандидати, а ввесь str0m-трафік
//! (ICE-перевірки + DTLS + SCTP) тунелюється Send/Data-indication'ами крізь coturn.
//!
//! Потік: register/connect (як e2e_session) -> кожен робить TURN Allocate на coturn ->
//! обмін relayed-кандидатами + offer/answer -> CreatePermission на relayed-адресу піра ->
//! драйв str0m із обгорткою Transmit у Send-indication і розгорткою Data-indication ->
//! PAKE-сесія B1 поверх relayed-каналу. Успіх = ключі збіглися Й лічильники indications > 0
//! (трафік реально пройшов крізь ретранслятор — прямого шляху немає).
//!
//! coturn у WSL (lt-cred-mech). Сервер сигналінгу має бути піднятий. Запуск:
//!   cargo run -p zortilwatch-core --example e2e_relay

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
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
use zortilwatch_core::relay::turn::{self, TurnClient, TurnInbound};
use zortilwatch_core::session::{Handshake, SessionMessage};
use zortilwatch_core::signal::{ClientMsg, ServerMsg, SignalClient};

const PASSWORD: &[u8] = b"one-time-connect-pw";

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

fn fingerprint(sdp: &str) -> String {
    sdp.lines()
        .find_map(|l| l.trim().strip_prefix("a=fingerprint:"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn payload_str(p: &Value, k: &str) -> Option<String> {
    p.get(k).and_then(|v| v.as_str()).map(String::from)
}

fn turn_cfg() -> (SocketAddr, String, String) {
    let server = std::env::var("TURN_SERVER").unwrap_or_else(|_| "192.168.88.223:3478".into());
    let user = std::env::var("TURN_USER").unwrap_or_else(|_| "test".into());
    let pass = std::env::var("TURN_PASS").unwrap_or_else(|_| "test123".into());
    let addr = server
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .expect("TURN_SERVER addr");
    (addr, user, pass)
}

/// Лічильники, що доводять проходження крізь ретранслятор.
#[derive(Default, Debug)]
struct Relayed {
    sent: usize, // Send-indication'ів відіслано до coturn
    recv: usize, // Data-indication'ів отримано від coturn
}

/// Вичерпати poll_output: КОЖЕН Transmit -> Send-indication до coturn (relay-only).
fn drain(
    rtc: &mut Rtc,
    sock: &UdpSocket,
    turn_server: SocketAddr,
    chan: &mut Option<ChannelId>,
    inbox: &mut Vec<Vec<u8>>,
    r: &mut Relayed,
) {
    loop {
        match rtc.poll_output().expect("poll_output") {
            Output::Timeout(_) => return,
            Output::Transmit(t) => {
                if let Ok(wrapped) = turn::encode_send_indication(t.destination, &t.contents) {
                    if sock.send_to(&wrapped, turn_server).is_ok() {
                        r.sent += 1;
                    }
                }
            }
            Output::Event(Event::ChannelOpen(id, _)) => *chan = Some(id),
            Output::Event(Event::ChannelData(d)) => inbox.push(d.data),
            Output::Event(_) => {}
        }
    }
}

/// Прочитати одну датаграму від coturn; Data-indication -> у str0m як від піра.
fn recv_one(
    rtc: &mut Rtc,
    sock: &UdpSocket,
    turn_server: SocketAddr,
    my_relayed: SocketAddr,
    r: &mut Relayed,
) {
    let mut buf = [0u8; 2048];
    match sock.recv_from(&mut buf) {
        Ok((n, src)) => {
            if src != turn_server {
                return; // у relay-only усе йде від сервера
            }
            if let Ok(TurnInbound::Data { peer, payload }) = turn::parse_from_server(&buf[..n]) {
                if let Ok(contents) = payload[..].try_into() {
                    rtc.handle_input(Input::Receive(
                        Instant::now(),
                        Receive {
                            proto: Protocol::Udp,
                            source: peer,
                            destination: my_relayed,
                            contents,
                        },
                    ))
                    .expect("handle_input recv");
                    r.recv += 1;
                }
            }
        }
        Err(ref e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(e) => panic!("recv_from: {e:?}"),
    }
}

fn write_session(rtc: &mut Rtc, cid: ChannelId, msg: &SessionMessage) {
    let bytes = serde_json::to_vec(msg).expect("ser");
    if let Some(mut ch) = rtc.channel(cid) {
        let _ = ch.write(true, &bytes);
    }
}

/// Драйв str0m + PAKE крізь ретранслятор до підтвердження. Повертає (ключ, лічильники).
#[allow(clippy::too_many_arguments)]
fn run_session_relay(
    mut rtc: Rtc,
    sock: UdpSocket,
    turn_server: SocketAddr,
    my_relayed: SocketAddr,
    own_fp: String,
    peer_fp: String,
) -> Result<([u8; 32], Relayed), String> {
    sock.set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(|e| e.to_string())?;
    let mut chan: Option<ChannelId> = None;
    let mut inbox: Vec<Vec<u8>> = Vec::new();
    let mut hs: Option<Handshake> = None;
    let mut r = Relayed::default();
    let deadline = Instant::now() + Duration::from_secs(40);

    loop {
        if let Some(h) = hs.as_ref() {
            if let Some(key) = h.confirmed_key() {
                return Ok((*key, r));
            }
            if h.is_failed() {
                return Err("session handshake FAILED".into());
            }
        }
        if Instant::now() > deadline {
            return Err(format!(
                "relay session timeout (chan_open={}, sent={}, recv={})",
                chan.is_some(),
                r.sent,
                r.recv
            ));
        }

        drain(&mut rtc, &sock, turn_server, &mut chan, &mut inbox, &mut r);
        if hs.is_none() {
            if let Some(cid) = chan {
                let (h, msg) = Handshake::start(PASSWORD, own_fp.clone(), peer_fp.clone());
                write_session(&mut rtc, cid, &msg);
                hs = Some(h);
                drain(&mut rtc, &sock, turn_server, &mut chan, &mut inbox, &mut r);
            }
        }
        for raw in std::mem::take(&mut inbox) {
            if let (Some(h), Some(cid)) = (hs.as_mut(), chan) {
                if let Ok(m) = serde_json::from_slice::<SessionMessage>(&raw) {
                    if let Some(resp) = h.on_message(m) {
                        write_session(&mut rtc, cid, &resp);
                        drain(&mut rtc, &sock, turn_server, &mut chan, &mut inbox, &mut r);
                    }
                }
            }
        }
        recv_one(&mut rtc, &sock, turn_server, my_relayed, &mut r);
        rtc.handle_input(Input::Timeout(Instant::now()))
            .map_err(|e| e.to_string())?;
    }
}

/// Підготувати сокет + TURN-алокацію + relayed-кандидат.
fn alloc_relay() -> Result<(UdpSocket, TurnClient, SocketAddr, Candidate), String> {
    let (turn_server, user, pass) = turn_cfg();
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    let local = sock.local_addr().map_err(|e| e.to_string())?;
    let client =
        TurnClient::allocate(&sock, turn_server, &user, &pass).map_err(|e| e.to_string())?;
    let relayed = client.relayed;
    let cand = Candidate::relayed(relayed, local, "udp").map_err(|e| e.to_string())?;
    Ok((sock, client, relayed, cand))
}

fn run_host(
    url: &str,
    id: &str,
    secret: &str,
    ready: Arc<Barrier>,
) -> Result<([u8; 32], Relayed), String> {
    let mut sc = SignalClient::connect(url).map_err(|e| e.to_string())?;
    sc.set_read_timeout(Some(Duration::from_secs(25)))
        .map_err(|e| e.to_string())?;
    sc.register(id, secret, "host").map_err(|e| e.to_string())?;
    ready.wait();

    let session_id = loop {
        match sc.recv().map_err(|e| e.to_string())? {
            ServerMsg::IncomingRequest { session_id, .. } => {
                sc.send(&ClientMsg::connect_accept(&session_id))
                    .map_err(|e| e.to_string())?;
            }
            ServerMsg::ConnectReady { session_id, .. } => break session_id,
            _ => {}
        }
    };

    let (turn_server, _, _) = turn_cfg();
    let (sock, client, my_relayed, cand) = alloc_relay()?;
    let mut rtc = new_rtc(Instant::now());
    rtc.add_local_candidate(cand.clone());
    let mut chan = None;
    let mut inbox = Vec::new();
    let mut warm = Relayed::default();
    drain(
        &mut rtc,
        &sock,
        turn_server,
        &mut chan,
        &mut inbox,
        &mut warm,
    );

    // offer + datachannel.
    let mut api = rtc.sdp_api();
    let _cid = api.add_channel("relay".to_string());
    let (offer, pending) = api.apply().ok_or("offer no changes")?;
    drain(
        &mut rtc,
        &sock,
        turn_server,
        &mut chan,
        &mut inbox,
        &mut warm,
    );
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
        json!({ "cand": cand.to_sdp_string(), "relayed": my_relayed.to_string() }),
    ))
    .map_err(|e| e.to_string())?;

    let mut peer_fp = String::new();
    let mut pending = Some(pending);
    let (mut answered, mut permitted) = (false, false);
    while !(answered && permitted) {
        if let ServerMsg::Signal { kind, payload, .. } = sc.recv().map_err(|e| e.to_string())? {
            match kind.as_str() {
                "answer" => {
                    let sdp = payload_str(&payload, "sdp").ok_or("no sdp")?;
                    peer_fp = fingerprint(&sdp);
                    let ans = SdpAnswer::from_sdp_string(&sdp).map_err(|e| e.to_string())?;
                    rtc.sdp_api()
                        .accept_answer(pending.take().ok_or("dbl")?, ans)
                        .map_err(|e| e.to_string())?;
                    drain(
                        &mut rtc,
                        &sock,
                        turn_server,
                        &mut chan,
                        &mut inbox,
                        &mut warm,
                    );
                    answered = true;
                }
                "ice" => {
                    let c = payload_str(&payload, "cand").ok_or("no cand")?;
                    let peer_relayed: SocketAddr = payload_str(&payload, "relayed")
                        .ok_or("no relayed")?
                        .parse()
                        .map_err(|_| "bad relayed addr")?;
                    client
                        .create_permission(&sock, peer_relayed)
                        .map_err(|e| e.to_string())?;
                    rtc.add_remote_candidate(
                        Candidate::from_sdp_string(&c).map_err(|e| e.to_string())?,
                    );
                    drain(
                        &mut rtc,
                        &sock,
                        turn_server,
                        &mut chan,
                        &mut inbox,
                        &mut warm,
                    );
                    permitted = true;
                }
                _ => {}
            }
        }
    }

    let (key, mut r) = run_session_relay(rtc, sock, turn_server, my_relayed, own_fp, peer_fp)?;
    r.sent += warm.sent;
    r.recv += warm.recv;
    let _ = sc.send(&ClientMsg::session_close(&session_id, Some("done")));
    Ok((key, r))
}

fn run_controller(
    url: &str,
    id: &str,
    secret: &str,
    target: &str,
    ready: Arc<Barrier>,
) -> Result<([u8; 32], Relayed), String> {
    let mut sc = SignalClient::connect(url).map_err(|e| e.to_string())?;
    sc.set_read_timeout(Some(Duration::from_secs(25)))
        .map_err(|e| e.to_string())?;
    sc.register(id, secret, "controller")
        .map_err(|e| e.to_string())?;
    ready.wait();
    sc.send(&ClientMsg::connect_request(target))
        .map_err(|e| e.to_string())?;

    let session_id = loop {
        match sc.recv().map_err(|e| e.to_string())? {
            ServerMsg::ConnectReady { session_id, .. } => break session_id,
            ServerMsg::ConnectErr { code, .. } => return Err(format!("connect_err {code}")),
            _ => {}
        }
    };

    let (turn_server, _, _) = turn_cfg();
    let (sock, client, my_relayed, cand) = alloc_relay()?;
    let mut rtc = new_rtc(Instant::now());
    rtc.add_local_candidate(cand.clone());
    let mut chan = None;
    let mut inbox = Vec::new();
    let mut warm = Relayed::default();
    drain(
        &mut rtc,
        &sock,
        turn_server,
        &mut chan,
        &mut inbox,
        &mut warm,
    );

    let mut own_fp = String::new();
    let mut peer_fp = String::new();
    let (mut offered, mut permitted) = (false, false);
    while !(offered && permitted) {
        if let ServerMsg::Signal { kind, payload, .. } = sc.recv().map_err(|e| e.to_string())? {
            match kind.as_str() {
                "offer" => {
                    let sdp = payload_str(&payload, "sdp").ok_or("no sdp")?;
                    peer_fp = fingerprint(&sdp);
                    let offer = SdpOffer::from_sdp_string(&sdp).map_err(|e| e.to_string())?;
                    let answer = rtc
                        .sdp_api()
                        .accept_offer(offer)
                        .map_err(|e| e.to_string())?;
                    drain(
                        &mut rtc,
                        &sock,
                        turn_server,
                        &mut chan,
                        &mut inbox,
                        &mut warm,
                    );
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
                        json!({ "cand": cand.to_sdp_string(), "relayed": my_relayed.to_string() }),
                    ))
                    .map_err(|e| e.to_string())?;
                    offered = true;
                }
                "ice" => {
                    let c = payload_str(&payload, "cand").ok_or("no cand")?;
                    let peer_relayed: SocketAddr = payload_str(&payload, "relayed")
                        .ok_or("no relayed")?
                        .parse()
                        .map_err(|_| "bad relayed addr")?;
                    client
                        .create_permission(&sock, peer_relayed)
                        .map_err(|e| e.to_string())?;
                    rtc.add_remote_candidate(
                        Candidate::from_sdp_string(&c).map_err(|e| e.to_string())?,
                    );
                    drain(
                        &mut rtc,
                        &sock,
                        turn_server,
                        &mut chan,
                        &mut inbox,
                        &mut warm,
                    );
                    permitted = true;
                }
                _ => {}
            }
        }
    }

    let (key, mut r) = run_session_relay(rtc, sock, turn_server, my_relayed, own_fp, peer_fp)?;
    r.sent += warm.sent;
    r.recv += warm.recv;
    Ok((key, r))
}

fn main() {
    let path = std::env::var("SIGNAL_CREDS").unwrap_or_else(|_| ".scratch/e2e-creds.json".into());
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let raw = raw.trim_start_matches('\u{feff}');
    let creds: Creds = serde_json::from_str(raw).expect("parse creds");
    let url = ws_url(&creds.base);
    let (ts, _, _) = turn_cfg();
    println!("signal url = {url} | TURN relay = {ts}");

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

    let hr = host.join().expect("host panicked");
    let cr = ctrl.join().expect("controller panicked");

    match (&hr, &cr) {
        (Ok((hk, hrl)), Ok((ck, crl))) if hk == ck && hrl.recv > 0 && crl.recv > 0 => {
            println!(
                "HOST: relayed (sent {} / recv {} indications)",
                hrl.sent, hrl.recv
            );
            println!(
                "CONTROLLER: relayed (sent {} / recv {} indications)",
                crl.sent, crl.recv
            );
            println!("RESULT=OK зашифрована сесія КРІЗЬ coturn-ретранслятор — ключі збіглися, прямого шляху не було");
        }
        _ => println!("RESULT=FAIL host={hr:?} controller={cr:?}"),
    }
}
