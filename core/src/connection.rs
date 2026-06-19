//! Оркестрація сесії — просте API для оболонки (Tauri/UI) і нативного керованого.
//!
//! Зводить докупи сигналінг (`signal`), str0m (`net`), PAKE-сесію (`session`),
//! напрямкове шифрування (`crypto`), фреймінг медіа (`media`) і ретранслятор (`relay`) у
//! дві ручки:
//!   • [`Controller`] — під'єднується за ID+паролем, ВИДАЄ розшифровані H.264-кадри й
//!     ПРИЙМАЄ події вводу для надсилання керованому;
//!   • [`Managed`] (Windows) — постійний host-цикл (`serve`): ОДИН сигналінг-WS на весь
//!     час роботи (присутність «онлайн» не блимає між сесіями), вхідні підключення
//!     послідовно — захоплює екран→H.264→шле, а отримані події вводу ІНЖЕКТУЄ.
//!
//! Кандидати: host (LAN/loopback) + TURN-relay (із ефемерних кред у `connect_ready`). str0m
//! сам обирає кращу пару (напряму, якщо можна; крізь coturn — якщо ні). Якщо relay підняти
//! не вдалось — плавна деградація до прямого шляху. Сесія крутиться у фоновому потоці.

use crate::crypto::{
    StreamOpener, StreamSealer, STREAM_LABEL_INPUT_C2H as INPUT_C2H,
    STREAM_LABEL_MEDIA_H2C as MEDIA_H2C,
};
use crate::input::InputEvent;
use crate::media::{Chunker, Reassembler, DEFAULT_MAX_PAYLOAD};
use crate::net::new_rtc;
use crate::relay::turn::{self, TurnClient, TurnInbound};
use crate::session::{Handshake, SessionMessage};
use crate::signal::{ClientMsg, ServerMsg, SignalClient};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use str0m::change::{SdpAnswer, SdpOffer};
use str0m::channel::ChannelId;
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc};

/// Маркер чистого завершення сесії по datachannel: пір, що йде, шле його перед розривом,
/// інший миттєво завершує свій цикл (не чекаючи ICE-таймаута ~10с). Йде ВСЕРЕДИНІ DTLS
/// (підробити може лише сам DTLS-пір, якому й так доступний звичайний розрив).
const SESSION_BYE: &[u8] = b"ZW-BYE-1";

/// Контекст ретранслятора для маршрутизації трафіку. Обидва None -> лише прямий шлях.
#[derive(Clone, Copy, Default)]
struct Relay {
    turn_server: Option<SocketAddr>,
    my_relayed: Option<SocketAddr>,
}

// ── Спільні низькорівневі помічники ────────────────────────────────────────

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

/// Витягти (username, credential, адреса TURN-сервера) з iceServers (`connect_ready`).
/// Обирає ПЕРШИЙ UDP `turn:`-URL (не `turns:`/tcp). Чиста функція — тестується без мережі.
fn parse_turn_endpoint(ice: &Value) -> Option<(String, String, SocketAddr)> {
    let srv = ice.as_array()?.first()?;
    let username = srv.get("username")?.as_str()?.to_string();
    let credential = srv.get("credential")?.as_str()?.to_string();
    let urls = srv.get("urls")?;
    let list: Vec<String> = match urls {
        Value::String(s) => s.split_whitespace().map(String::from).collect(),
        Value::Array(a) => a
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => return None,
    };
    let turn_url = list
        .iter()
        .find(|u| u.starts_with("turn:") && !u.contains("transport=tcp"))?;
    let hostport = turn_url.strip_prefix("turn:")?.split('?').next()?;
    let server = hostport.to_socket_addrs().ok()?.next()?;
    Some((username, credential, server))
}

/// Підняти relay-кандидат із iceServers. `None` при будь-якій невдачі (плавна деградація).
/// Повертає TurnClient (для CreatePermission), relayed-адресу й адресу TURN-сервера.
fn setup_relay(sock: &UdpSocket, ice: &Value) -> Option<(TurnClient, SocketAddr, SocketAddr)> {
    let (username, credential, turn_server) = parse_turn_endpoint(ice)?;
    let client = TurnClient::allocate(sock, turn_server, &username, &credential).ok()?;
    let relayed = client.relayed;
    Some((client, relayed, turn_server))
}

fn drain(
    rtc: &mut Rtc,
    sock: &UdpSocket,
    chan: &mut Option<ChannelId>,
    inbox: &mut Vec<Vec<u8>>,
    relay: Relay,
) -> bool {
    loop {
        match rtc.poll_output() {
            Ok(Output::Timeout(_)) => return true,
            Ok(Output::Transmit(t)) => match (relay.turn_server, relay.my_relayed) {
                // Якщо str0m шле з НАШОЇ relayed-адреси — загорнути в Send-indication до coturn.
                (Some(ts), Some(mr)) if t.source == mr => {
                    if let Ok(w) = turn::encode_send_indication(t.destination, &t.contents) {
                        let _ = sock.send_to(&w, ts);
                    }
                }
                _ => {
                    let _ = sock.send_to(&t.contents, t.destination);
                }
            },
            Ok(Output::Event(Event::ChannelOpen(id, _))) => *chan = Some(id),
            Ok(Output::Event(Event::ChannelData(d))) => inbox.push(d.data),
            // Пір зник без close_notify (крах процесу, обрив мережі): ICE Disconnected =
            // кінець сесії. Інакше керований вічно лишався б «busy» для нових підключень.
            // (Теоретично str0m міг би відновитись після транзієнтного Disconnected, але
            // з єдиною парою кандидатів відновлення малоймовірне; пульт перепідключиться.)
            Ok(Output::Event(Event::IceConnectionStateChange(
                IceConnectionState::Disconnected,
            ))) => return false,
            Ok(Output::Event(_)) => {}
            // rtc у помилковому/закритому стані (напр. CloseNotify при розриві піра) — НЕ панікувати:
            // повертаємо false, і цикл одразу штатно завершує сесію (is_alive міг ще не флапнути).
            Err(_) => return false,
        }
    }
}

fn recv_one(
    rtc: &mut Rtc,
    sock: &UdpSocket,
    my_addr: SocketAddr,
    relay: Relay,
    turn: Option<&mut TurnClient>,
) {
    let mut buf = [0u8; 2048];
    match sock.recv_from(&mut buf) {
        Ok((n, src)) => {
            // Пакети від coturn: Data-indication -> подати як від піра; 438 -> оновити nonce.
            if let (Some(ts), Some(mr)) = (relay.turn_server, relay.my_relayed) {
                if src == ts {
                    match turn::parse_from_server(&buf[..n]) {
                        Ok(TurnInbound::Data { peer, payload }) => {
                            if let Ok(contents) = payload[..].try_into() {
                                let _ = rtc.handle_input(Input::Receive(
                                    Instant::now(),
                                    Receive {
                                        proto: Protocol::Udp,
                                        source: peer,
                                        destination: mr,
                                        contents,
                                    },
                                ));
                            }
                        }
                        // coturn провернув nonce — підхопити свіжий і одразу повторити Refresh,
                        // щоб алокація не згасла (інакше relay-сесія тихо вмирає за ~lifetime).
                        Ok(TurnInbound::StaleNonce { nonce }) => {
                            if let Some(tc) = turn {
                                tc.set_nonce(nonce);
                                if let Ok(bytes) = tc.refresh_request_bytes() {
                                    let _ = sock.send_to(&bytes, tc.server);
                                }
                            }
                        }
                        _ => {}
                    }
                    return;
                }
            }
            // Прямий шлях.
            if let Ok(contents) = buf[..n].try_into() {
                let _ = rtc.handle_input(Input::Receive(
                    Instant::now(),
                    Receive {
                        proto: Protocol::Udp,
                        source: src,
                        destination: my_addr,
                        contents,
                    },
                ));
            }
        }
        Err(ref e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(_) => {}
    }
}

/// Інтервал між TURN Refresh = половина виданого lifetime (мін. 60с). None без relay.
fn turn_refresh_interval(est: &Established) -> Option<Duration> {
    est.turn_client
        .as_ref()
        .map(|c| Duration::from_secs((c.lifetime_secs() / 2).max(60) as u64))
}

/// Періодичний TURN Refresh (fire-and-forget): подовжує relay-алокацію, щоб довга сесія
/// не вмерла на ~lifetime coturn. Відповідь (успіх/438) обробляє recv_one. No-op без relay.
fn maybe_refresh_turn(est: &Established, every: Option<Duration>, last: &mut Instant) {
    if let (Some(iv), Some(tc)) = (every, est.turn_client.as_ref()) {
        if last.elapsed() >= iv {
            *last = Instant::now();
            if let Ok(bytes) = tc.refresh_request_bytes() {
                let _ = est.sock.send_to(&bytes, tc.server);
            }
        }
    }
}

fn write_session(rtc: &mut Rtc, cid: ChannelId, msg: &SessionMessage) {
    if let Ok(bytes) = serde_json::to_vec(msg) {
        if let Some(mut ch) = rtc.channel(cid) {
            let _ = ch.write(true, &bytes);
        }
    }
}

fn write_raw(rtc: &mut Rtc, cid: ChannelId, bytes: &[u8]) {
    if let Some(mut ch) = rtc.channel(cid) {
        let _ = ch.write(true, bytes);
    }
}

/// Local-кандидати: host (loopback) + опційно relay; повертає також рядки SDP для обміну.
///
/// Host — loopback: на сокеті `0.0.0.0` `recv_from` не дає destination IP (потрібен
/// IP_PKTINFO), тож пряме зіставлення працює лише для loopback (та сама машина). Крос-
/// машинний шлях (LAN/NAT) іде через relay. Пряму LAN/srflx-оптимізацію (потребує
/// IP_PKTINFO) лишаємо на майбутнє — relay і так покриває крос-машину.
fn local_candidates(
    rtc: &mut Rtc,
    sock: &UdpSocket,
    relay: Relay,
) -> Result<(SocketAddr, Vec<String>), String> {
    let port = sock.local_addr().map_err(|e| e.to_string())?.port();
    let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    // ZW_FORCE_RELAY (тести/діагностика): НЕ додавати host -> змусити шлях крізь TURN.
    let force_relay = std::env::var_os("ZW_FORCE_RELAY").is_some() && relay.my_relayed.is_some();
    let mut cands = Vec::new();
    if !force_relay {
        let host = Candidate::host(loopback, "udp").map_err(|e| e.to_string())?;
        rtc.add_local_candidate(host.clone());
        cands.push(host.to_sdp_string());
    }
    if let Some(relayed) = relay.my_relayed {
        if let Ok(rc) = Candidate::relayed(relayed, loopback, "udp") {
            rtc.add_local_candidate(rc.clone());
            cands.push(rc.to_sdp_string());
        }
    }
    Ok((loopback, cands))
}

/// Застосувати кандидати піра + (за наявності) дозвіл на його relayed-адресу.
fn apply_peer_candidates(
    rtc: &mut Rtc,
    sock: &UdpSocket,
    payload: &Value,
    turn_client: &Option<TurnClient>,
) {
    if let Some(arr) = payload.get("cands").and_then(|v| v.as_array()) {
        for c in arr.iter().filter_map(|v| v.as_str()) {
            if let Ok(cand) = Candidate::from_sdp_string(c) {
                rtc.add_remote_candidate(cand);
            }
        }
    } else if let Some(c) = payload_str(payload, "cand") {
        if let Ok(cand) = Candidate::from_sdp_string(&c) {
            rtc.add_remote_candidate(cand);
        }
    }
    if let (Some(client), Some(pr)) = (turn_client, payload_str(payload, "relayed")) {
        if let Ok(peer_relayed) = pr.parse::<SocketAddr>() {
            let _ = client.create_permission(sock, peer_relayed);
        }
    }
}

/// Піднята й ПІДТВЕРДЖЕНА сесія (live rtc/sock/chan + ключ + контекст relay).
struct Established {
    rtc: Rtc,
    sock: UdpSocket,
    my_addr: SocketAddr,
    chan: ChannelId,
    key: [u8; 32],
    relay: Relay,
    /// TURN-клієнт лишається живим на час сесії — для періодичного Refresh алокації
    /// (None для прямих/STUN-сесій без relay).
    turn_client: Option<TurnClient>,
}

/// Драйв str0m + PAKE до підтвердження; не-PAKE-блоби буферизуються у `deferred`.
#[allow(clippy::too_many_arguments)] // приватний хелпер; усі аргументи — окремі сутності сесії
fn drive_until_confirmed(
    mut rtc: Rtc,
    sock: UdpSocket,
    my_addr: SocketAddr,
    password: &[u8],
    own_fp: String,
    peer_fp: String,
    relay: Relay,
    turn_client: Option<TurnClient>,
) -> Result<(Established, Vec<Vec<u8>>), String> {
    sock.set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(|e| e.to_string())?;
    let mut chan: Option<ChannelId> = None;
    let mut inbox: Vec<Vec<u8>> = Vec::new();
    let mut deferred: Vec<Vec<u8>> = Vec::new();
    let mut hs: Option<Handshake> = None;
    let deadline = Instant::now() + Duration::from_secs(30);

    loop {
        if let Some(h) = hs.as_ref() {
            if let Some(key) = h.confirmed_key() {
                return Ok((
                    Established {
                        key: *key,
                        chan: chan.ok_or("no channel")?,
                        rtc,
                        sock,
                        my_addr,
                        relay,
                        turn_client,
                    },
                    deferred,
                ));
            }
            if h.is_failed() {
                return Err("session handshake FAILED (wrong password or MITM)".into());
            }
        }
        if Instant::now() > deadline {
            return Err("session establish timeout".into());
        }

        if !drain(&mut rtc, &sock, &mut chan, &mut inbox, relay) {
            return Err("connection lost during handshake".into());
        }
        if hs.is_none() {
            if let Some(cid) = chan {
                let (h, msg) = Handshake::start(password, own_fp.clone(), peer_fp.clone());
                write_session(&mut rtc, cid, &msg);
                hs = Some(h);
                drain(&mut rtc, &sock, &mut chan, &mut inbox, relay);
            }
        }
        for raw in std::mem::take(&mut inbox) {
            match serde_json::from_slice::<SessionMessage>(&raw) {
                Ok(m) => {
                    if let (Some(h), Some(cid)) = (hs.as_mut(), chan) {
                        if let Some(resp) = h.on_message(m) {
                            write_session(&mut rtc, cid, &resp);
                            drain(&mut rtc, &sock, &mut chan, &mut inbox, relay);
                        }
                    }
                }
                Err(_) => deferred.push(raw),
            }
        }
        recv_one(&mut rtc, &sock, my_addr, relay, None); // рукостискання <30с << lifetime — Refresh не треба
        rtc.handle_input(Input::Timeout(Instant::now()))
            .map_err(|e| e.to_string())?;
    }
}

/// Попросити сервер розбудити `target_id` (PRD 5.9). Короткий WS-раунд: register →
/// wake → wake_result. Повертає (статус, кількість помічників): "dispatched" |
/// "no_helper" | "unsupported". Крос-платформно (лише сигналінг).
pub fn request_wake(
    server_base: &str,
    device_id: &str,
    client_secret: &str,
    target_id: &str,
) -> Result<(String, u32), String> {
    let mut sc = SignalClient::connect(&ws_url(server_base)).map_err(|e| e.to_string())?;
    sc.set_read_timeout(Some(Duration::from_secs(8)))
        .map_err(|e| e.to_string())?;
    sc.register(device_id, client_secret, "controller")
        .map_err(|e| e.to_string())?;
    sc.send(&ClientMsg::wake(target_id))
        .map_err(|e| e.to_string())?;
    loop {
        match sc.recv().map_err(|e| e.to_string())? {
            ServerMsg::WakeResult { status, helpers } => return Ok((status, helpers)),
            _ => continue,
        }
    }
}

// ── Пульт (controller) ──────────────────────────────────────────────────────

/// Вихідне повідомлення пульта: подія вводу/керування або сирий блоб (файлові кадри).
enum OutMsg {
    Event(InputEvent),
    Raw(Vec<u8>),
}

/// Активна сесія з боку пульта: видає розшифровані H.264-кадри (а також керівні
/// JSON-повідомлення та файлові кадри — як є) й приймає події вводу/сирі блоби.
/// Зупиняється при `close()` або коли впаде (Drop).
pub struct Controller {
    frames: Option<Receiver<Vec<u8>>>,
    input_tx: Sender<OutMsg>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    /// Розмір екрана керованого (px), якщо повідомлено.
    pub remote_screen: Option<(u32, u32)>,
}

impl Controller {
    /// Під'єднатися до керованого `target_id` за паролем і запустити сесію.
    /// `password_kind` ("one_time" | "permanent") каже керованому, який секрет
    /// підставити в PAKE (сам пароль сервер не бачить ніколи).
    /// Блокує до встановлення зашифрованого каналу, далі медіа/ввід крутяться у потоці.
    pub fn connect(
        server_base: &str,
        device_id: &str,
        client_secret: &str,
        password: &[u8],
        target_id: &str,
        password_kind: &str,
    ) -> Result<Self, String> {
        let mut sc = SignalClient::connect(&ws_url(server_base)).map_err(|e| e.to_string())?;
        // 35с: покриває атендантне підтвердження на керованому (до 30с) + встановлення.
        sc.set_read_timeout(Some(Duration::from_secs(35)))
            .map_err(|e| e.to_string())?;
        sc.register(device_id, client_secret, "controller")
            .map_err(|e| e.to_string())?;
        sc.send(&ClientMsg::connect_request_kind(target_id, password_kind))
            .map_err(|e| e.to_string())?;

        let (session_id, ice_servers) = loop {
            match sc.recv().map_err(|e| e.to_string())? {
                ServerMsg::ConnectReady {
                    session_id,
                    ice_servers,
                    ..
                } => break (session_id, ice_servers),
                ServerMsg::ConnectErr { code, .. } => return Err(format!("connect_err {code}")),
                _ => {}
            }
        };

        let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        let mut rtc = new_rtc(Instant::now());
        // Підняти relay (плавна деградація — None при невдачі).
        let turn_client = ice_servers.as_ref().and_then(|v| setup_relay(&sock, v));
        let relay = Relay {
            turn_server: turn_client.as_ref().map(|(_, _, ts)| *ts),
            my_relayed: turn_client.as_ref().map(|(_, r, _)| *r),
        };
        let turn_client = turn_client.map(|(c, _, _)| c);
        let (my_addr, my_cands) = local_candidates(&mut rtc, &sock, relay)?;
        let my_relayed_str = relay.my_relayed.map(|a| a.to_string());
        let mut chan = None;
        let mut inbox = Vec::new();
        drain(&mut rtc, &sock, &mut chan, &mut inbox, relay);

        // Відповідач: чекаємо offer -> answer + ice.
        let mut own_fp = String::new();
        let mut peer_fp = String::new();
        let (mut offered, mut got_cand) = (false, false);
        while !(offered && got_cand) {
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
                        drain(&mut rtc, &sock, &mut chan, &mut inbox, relay);
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
                            json!({ "cands": my_cands, "relayed": my_relayed_str }),
                        ))
                        .map_err(|e| e.to_string())?;
                        offered = true;
                    }
                    "ice" => {
                        apply_peer_candidates(&mut rtc, &sock, &payload, &turn_client);
                        drain(&mut rtc, &sock, &mut chan, &mut inbox, relay);
                        got_cand = true;
                    }
                    _ => {}
                }
            }
        }

        let (est, deferred) = drive_until_confirmed(
            rtc, sock, my_addr, password, own_fp, peer_fp, relay, turn_client,
        )?;
        let key = est.key;

        let (frames_tx, frames_rx) = channel::<Vec<u8>>();
        let (input_tx, input_rx) = channel::<OutMsg>();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        // Великий стек: str0m + DTLS + SCTP під навантаженням мають глибокі ланцюги викликів.
        let handle = thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(move || controller_loop(est, key, frames_tx, input_rx, deferred, stop2))
            .map_err(|e| e.to_string())?;

        Ok(Controller {
            frames: Some(frames_rx),
            input_tx,
            stop,
            handle: Some(handle),
            remote_screen: None,
        })
    }

    /// Наступний розшифрований H.264 access unit, якщо є (неблокувально).
    pub fn next_frame(&self) -> Option<Vec<u8>> {
        self.frames.as_ref().and_then(|r| r.try_recv().ok())
    }

    /// Забрати приймач кадрів для власного циклу доставки (напр. у Tauri-команді). Один раз.
    pub fn take_frames(&mut self) -> Option<Receiver<Vec<u8>>> {
        self.frames.take()
    }

    /// Надіслати подію вводу керованому (буде зашифрована й доставлена каналом).
    pub fn send_input(&self, ev: InputEvent) {
        let _ = self.input_tx.send(OutMsg::Event(ev));
    }

    /// Надіслати сирий блоб тим самим зашифрованим каналом (файлові кадри 0xF7).
    pub fn send_raw(&self, bytes: Vec<u8>) {
        let _ = self.input_tx.send(OutMsg::Raw(bytes));
    }

    /// Зупинити сесію й дочекатися завершення потоку.
    pub fn close(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn controller_loop(
    mut est: Established,
    key: [u8; 32],
    frames_tx: Sender<Vec<u8>>,
    input_rx: Receiver<OutMsg>,
    deferred: Vec<Vec<u8>>,
    stop: Arc<AtomicBool>,
) {
    use std::collections::VecDeque;
    let opener = StreamOpener::new(&key, MEDIA_H2C);
    let mut sealer = StreamSealer::new(&key, INPUT_C2H);
    let mut re = Reassembler::new();
    let relay = est.relay;
    let mut chan = Some(est.chan);
    let mut inbox = deferred;
    // Вихідна черга з backpressure (SCTP): файлові кадри не губляться при заторі.
    let mut out: VecDeque<Vec<u8>> = VecDeque::new();
    let refresh_every = turn_refresh_interval(&est);
    let mut refreshed_at = Instant::now();

    while !stop.load(Ordering::Relaxed) && est.rtc.is_alive() {
        maybe_refresh_turn(&est, refresh_every, &mut refreshed_at);
        if !drain(&mut est.rtc, &est.sock, &mut chan, &mut inbox, relay) {
            break;
        }

        // Вхідні відео-чанки -> збірка -> розшифрування -> видати кадр.
        let mut bye = false;
        for raw in std::mem::take(&mut inbox) {
            if raw == SESSION_BYE {
                bye = true; // керований чисто завершив сесію
                continue;
            }
            if let Some(sealed) = re.push(&raw) {
                if let Ok(frame) = opener.open(&sealed) {
                    if frames_tx.send(frame).is_err() {
                        return; // приймач зник
                    }
                }
            }
        }
        if bye {
            break;
        }

        // Події вводу/сирі блоби від UI -> шифр -> вихідна черга -> канал (backpressure).
        while let Ok(msg) = input_rx.try_recv() {
            let plain = match msg {
                OutMsg::Event(ev) => match serde_json::to_vec(&ev) {
                    Ok(b) => b,
                    Err(_) => continue,
                },
                OutMsg::Raw(b) => b,
            };
            out.push_back(sealer.seal(&plain));
        }
        while let Some(front) = out.front() {
            let ok = est
                .rtc
                .channel(est.chan)
                .map(|mut ch| ch.write(true, front).unwrap_or(false))
                .unwrap_or(false);
            if ok {
                out.pop_front();
            } else {
                break;
            }
        }

        if !drain(&mut est.rtc, &est.sock, &mut chan, &mut inbox, relay) {
            break;
        }
        recv_one(&mut est.rtc, &est.sock, est.my_addr, relay, est.turn_client.as_mut());
        let _ = est.rtc.handle_input(Input::Timeout(Instant::now()));
    }
    // Чисте завершення: BYE по каналу (пір миттєво завершує цикл, не чекаючи ICE-таймаута)
    // + DTLS-розрив. Кілька тактів drain+Timeout, щоб пакети реально вилетіли в сокет.
    write_raw(&mut est.rtc, est.chan, SESSION_BYE);
    for _ in 0..5 {
        if !drain(&mut est.rtc, &est.sock, &mut chan, &mut inbox, relay) {
            break;
        }
        let _ = est.rtc.handle_input(Input::Timeout(Instant::now()));
    }
    est.rtc.disconnect();
    let _ = drain(&mut est.rtc, &est.sock, &mut chan, &mut inbox, relay);
}

// ── Керований (managed) — Windows ───────────────────────────────────────────

/// Помилки host-циклу: `Ws` — сигналінг-WS зламано (потрібне перепідключення);
/// `Session` — конкретна спроба сесії не вдалась (WS живий, чекаємо наступне підключення).
#[cfg(windows)]
enum ServeErr {
    Ws,
    Session,
}

/// Подія host-режиму для UI (показ коду, запит підтвердження).
#[cfg(windows)]
pub enum HostEvent {
    /// Новий одноразовий код підключення (показати в host-панелі).
    OneTime(String),
    /// Атендантний режим: вхідний запит чекає рішення людини. UI показує діалог
    /// і відповідає через `HostOptions::decisions` (`(request_id, allow)`); ~30с
    /// на рішення, інакше — відмова.
    Confirm {
        request_id: u64,
        password_kind: String,
    },
}

/// Налаштування host-режиму для [`Managed::serve`].
#[cfg(windows)]
pub struct HostOptions {
    /// Постійний пароль власника. `None` — приймати ЛИШЕ за одноразовим кодом.
    pub permanent_password: Option<Vec<u8>>,
    /// Прапор «згенерувати новий одноразовий код зараз» (кнопка в UI). Самоскидний.
    pub rotate: Arc<AtomicBool>,
    /// Зупинка host-режиму: нові підключення не приймаються (≤2с), активна сесія доживає.
    pub stop: Arc<AtomicBool>,
    /// Атендантний режим (живий тумблер): кожне вхідне підключення потребує
    /// підтвердження людиною за пристроєм (PRD 5.3). Вимкнено = безатендантний.
    pub confirm_incoming: Arc<AtomicBool>,
    /// Відповіді UI на [`HostEvent::Confirm`]: `(request_id, allow)`.
    pub decisions: std::sync::mpsc::Receiver<(u64, bool)>,
    /// Автоблокування Windows після завершення кожної сесії (PRD 5.10; живий тумблер).
    pub lock_on_end: Arc<AtomicBool>,
}

/// Керований пристрій (Windows): захоплює екран→H.264→шле, інжектує отриманий ввід.
#[cfg(windows)]
pub struct Managed;

#[cfg(windows)]
impl Managed {
    /// Постійний host-режим: ОДИН сигналінг-WS на весь час роботи, тож присутність
    /// «онлайн» НЕ блимає між сесіями, а невдале встановлення (хибний пароль, таймаут)
    /// не скидає реєстрацію. Вхідні підключення обслуговуються послідовно; під час
    /// сесії нові відхиляються (busy). WS впав — перепідключення з бекофом ~2с.
    ///
    /// Паролі: одноразовий код генерується тут і повідомляється через `on_one_time`
    /// (показ у UI); «згорає» після сесії, встановленої ним, або за `rotate`.
    /// Постійний — опційний (PRD 5.1). Тип, яким автентифікується пульт, приходить
    /// у `incoming_request.passwordKind` (сам пароль сервер не бачить).
    pub fn serve(
        server_base: &str,
        device_id: &str,
        client_secret: &str,
        opts: HostOptions,
        on_event: impl Fn(HostEvent) + Send,
    ) {
        let mut next_request_id: u64 = 0;
        let mut one_time = crate::password::generate_one_time();
        on_event(HostEvent::OneTime(one_time.clone()));
        while !opts.stop.load(Ordering::Relaxed) {
            let mut sc = match register_host_ws(server_base, device_id, client_secret) {
                Ok(sc) => sc,
                Err(_) => {
                    sleep_unless_stop(&opts.stop, Duration::from_secs(2));
                    continue;
                }
            };
            // Запит, що прийшов «на хвості» попередньої сесії, обслуговуємо без втрати
            // (інакше «відключився і одразу перепідключився» діставав би busy).
            let mut pending: Option<(String, Option<String>)> = None;
            loop {
                if opts.stop.load(Ordering::Relaxed) {
                    return; // drop(sc) -> пристрій офлайн
                }
                if opts.rotate.swap(false, Ordering::Relaxed) {
                    one_time = crate::password::generate_one_time();
                    on_event(HostEvent::OneTime(one_time.clone()));
                }
                let (sid, kind) = match pending.take() {
                    Some(p) => p,
                    None => match sc.try_recv() {
                        Ok(Some(ServerMsg::IncomingRequest {
                            session_id,
                            password_kind,
                            ..
                        })) => (session_id, password_kind),
                        // Помічник: розбудити інший пристрій локальним магічним пакетом.
                        Ok(Some(ServerMsg::WakeDispatch { mac })) => {
                            crate::wol::send_wol_str(&mac);
                            continue;
                        }
                        Ok(_) => continue, // такт читання (2с) або стороннє повідомлення
                        Err(_) => break,   // WS закрито/зламано -> перепідключення
                    },
                };
                // Який секрет підставити в PAKE: тип каже пульт, сам пароль — ні.
                let one_time_used = kind.as_deref() == Some("one_time");
                let password: Vec<u8> = if one_time_used {
                    one_time.clone().into_bytes()
                } else {
                    match &opts.permanent_password {
                        Some(p) => p.clone(),
                        None => {
                            // Постійний не задано — підключення лише за одноразовим кодом.
                            if sc
                                .send(&ClientMsg::connect_reject(&sid, Some("no_permanent")))
                                .is_err()
                            {
                                break;
                            }
                            continue;
                        }
                    }
                };
                // Атендантний режим: спершу рішення людини за пристроєм.
                if opts.confirm_incoming.load(Ordering::Relaxed) {
                    next_request_id += 1;
                    while opts.decisions.try_recv().is_ok() {} // зачистити прострочені
                    on_event(HostEvent::Confirm {
                        request_id: next_request_id,
                        password_kind: kind.clone().unwrap_or_else(|| "permanent".into()),
                    });
                    match wait_decision(&mut sc, &opts, next_request_id) {
                        Ok(true) => {}
                        Ok(false) => {
                            // Відмова людини або таймаут — пульт дістане forbidden.
                            if sc
                                .send(&ClientMsg::connect_reject(&sid, Some("denied")))
                                .is_err()
                            {
                                break;
                            }
                            continue;
                        }
                        Err(()) => break, // WS зламався під час очікування
                    }
                }
                match serve_session(&mut sc, &sid, &password, &opts.stop, &opts.lock_on_end) {
                    Ok(next) => {
                        if one_time_used {
                            // Код діє лише в межах сеансу — «згорів», показуємо новий.
                            one_time = crate::password::generate_one_time();
                            on_event(HostEvent::OneTime(one_time.clone()));
                        }
                        pending = next;
                    }
                    Err(ServeErr::Session) => {} // WS живий — чекаємо наступне підключення
                    Err(ServeErr::Ws) => break,
                }
            }
        }
    }
}

/// Під'єднати й зареєструвати host-WS. Такт читання 2с: період перевірки stop і
/// відповіді pong на heartbeat сервера (дрібніші значення Windows округлює до ~500мс).
#[cfg(windows)]
fn register_host_ws(
    server_base: &str,
    device_id: &str,
    client_secret: &str,
) -> Result<SignalClient, String> {
    let mut sc = SignalClient::connect(&ws_url(server_base)).map_err(|e| e.to_string())?;
    sc.set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    // Звітуємо власний MAC (щоб цей пристрій можна було розбудити) + canWake=true
    // (десктоп уміє слати магічний пакет, тож може бути помічником, PRD 5.9).
    let mac = crate::wol::local_mac();
    sc.register_wol(device_id, client_secret, "host", mac.as_deref(), true)
        .map_err(|e| e.to_string())?;
    sc.set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    Ok(sc)
}

/// Чекати рішення людини (≤30с), тримаючи WS живим: pong на heartbeat, busy для
/// паралельних запитів. `Ok(allow)` — рішення/таймаут(=false); `Err` — WS зламано.
#[cfg(windows)]
fn wait_decision(sc: &mut SignalClient, opts: &HostOptions, request_id: u64) -> Result<bool, ()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if opts.stop.load(Ordering::Relaxed) || Instant::now() > deadline {
            return Ok(false);
        }
        if let Ok((rid, allow)) = opts.decisions.try_recv() {
            if rid == request_id {
                return Ok(allow);
            }
        }
        match sc.try_recv() {
            Ok(Some(ServerMsg::IncomingRequest {
                session_id: other, ..
            })) => {
                if sc
                    .send(&ClientMsg::connect_reject(&other, Some("busy")))
                    .is_err()
                {
                    return Err(());
                }
            }
            Ok(_) => {} // такт читання (2с) або стороннє повідомлення
            Err(_) => return Err(()),
        }
    }
}

#[cfg(windows)]
fn sleep_unless_stop(stop: &AtomicBool, total: Duration) {
    let deadline = Instant::now() + total;
    while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(200));
    }
}

/// Прийняти запит `session_id` і провести сесію до завершення. Повертає
/// `Ok(Some((id, password_kind)))`, якщо на самому хвості сесії прийшов новий запит
/// (обслужити наступним без busy).
#[cfg(windows)]
fn serve_session(
    sc: &mut SignalClient,
    session_id: &str,
    password: &[u8],
    stop: &AtomicBool,
    lock_on_end: &AtomicBool,
) -> Result<Option<(String, Option<String>)>, ServeErr> {
    if sc.send(&ClientMsg::connect_accept(session_id)).is_err() {
        return Err(ServeErr::Ws);
    }
    // Чекаємо connect_ready (роль + iceServers); паралельні запити тим часом — busy.
    let deadline = Instant::now() + Duration::from_secs(15);
    let (sid, ice_servers) = loop {
        if stop.load(Ordering::Relaxed) || Instant::now() > deadline {
            return Err(ServeErr::Session);
        }
        match sc.try_recv() {
            Ok(Some(ServerMsg::ConnectReady {
                session_id,
                ice_servers,
                ..
            })) => break (session_id, ice_servers),
            Ok(Some(ServerMsg::IncomingRequest {
                session_id: other, ..
            })) => {
                if sc
                    .send(&ClientMsg::connect_reject(&other, Some("busy")))
                    .is_err()
                {
                    return Err(ServeErr::Ws);
                }
            }
            Ok(_) => {}
            Err(_) => return Err(ServeErr::Ws),
        }
    };

    let (est, deferred) = establish_managed(sc, &sid, ice_servers.as_ref(), password)?;
    let key = est.key;
    // Прапор сесії окремий від stop хоста: вимкнення host не рве активну сесію.
    let session_stop = Arc::new(AtomicBool::new(false));
    // `done` спалахує одразу по виході з медіа-циклу, ДО прибирання (cap.stop ~сотні мс):
    // запит, що прийде під час прибирання, — це вже наступна сесія, а не busy.
    let done = Arc::new(AtomicBool::new(false));
    let handle = thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn({
            let ss = session_stop.clone();
            let done = done.clone();
            move || managed_loop(est, key, deferred, ss, done)
        })
        .map_err(|_| ServeErr::Session)?;

    // Пульс на час сесії НА ЦЬОМУ Ж потоці (медіа крутиться у своєму): pong на heartbeat
    // (через try_recv), busy-відмови, виявлення кінця сесії з тактом ≤2с. session_close
    // від сервера ігноруємо — життя сесії визначає сам зашифрований канал.
    let mut tail: Option<(String, Option<String>)> = None;
    let mut ws_ok = true;
    while !done.load(Ordering::Relaxed) {
        if stop.load(Ordering::Relaxed) {
            break; // нових не приймаємо; сесія доживає природно (join нижче)
        }
        match sc.try_recv() {
            Ok(Some(ServerMsg::IncomingRequest {
                session_id: other,
                password_kind: other_kind,
                ..
            })) => {
                if done.load(Ordering::Relaxed) {
                    tail = Some((other, other_kind)); // сесія щойно скінчилась — це вже НЕ busy
                    break;
                }
                if sc
                    .send(&ClientMsg::connect_reject(&other, Some("busy")))
                    .is_err()
                {
                    ws_ok = false;
                    break;
                }
            }
            // Помічник лишається доступним і під час власної сесії.
            Ok(Some(ServerMsg::WakeDispatch { mac })) => {
                crate::wol::send_wol_str(&mac);
            }
            Ok(_) => {}
            Err(_) => {
                ws_ok = false;
                break;
            }
        }
    }
    // Дочекатися повного прибирання (захоплення/кодек звільнено) перед наступною сесією.
    let _ = handle.join();
    // Автоблокування пристрою після сесії (PRD 5.10) — опція власника.
    if lock_on_end.load(Ordering::Relaxed) {
        crate::input::lock_workstation();
    }
    if ws_ok {
        Ok(tail)
    } else {
        Err(ServeErr::Ws)
    }
}

/// Підняти WebRTC (offer/ICE крізь сигналінг-WS) і довести PAKE до підтвердження.
#[cfg(windows)]
fn establish_managed(
    sc: &mut SignalClient,
    session_id: &str,
    ice_servers: Option<&Value>,
    password: &[u8],
) -> Result<(Established, Vec<Vec<u8>>), ServeErr> {
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|_| ServeErr::Session)?;
    let mut rtc = new_rtc(Instant::now());
    let turn_client = ice_servers.and_then(|v| setup_relay(&sock, v));
    let relay = Relay {
        turn_server: turn_client.as_ref().map(|(_, _, ts)| *ts),
        my_relayed: turn_client.as_ref().map(|(_, r, _)| *r),
    };
    let turn_client = turn_client.map(|(c, _, _)| c);
    let (my_addr, my_cands) =
        local_candidates(&mut rtc, &sock, relay).map_err(|_| ServeErr::Session)?;
    let my_relayed_str = relay.my_relayed.map(|a| a.to_string());
    let mut chan = None;
    let mut inbox = Vec::new();
    drain(&mut rtc, &sock, &mut chan, &mut inbox, relay);

    // Ініціатор: offer + datachannel.
    let mut api = rtc.sdp_api();
    let _cid = api.add_channel("session".to_string());
    let (offer, pending) = api.apply().ok_or(ServeErr::Session)?;
    drain(&mut rtc, &sock, &mut chan, &mut inbox, relay);
    let offer_sdp = offer.to_sdp_string();
    let own_fp = fingerprint(&offer_sdp);
    sc.send(&ClientMsg::signal(
        session_id,
        "offer",
        json!({ "sdp": offer_sdp }),
    ))
    .map_err(|_| ServeErr::Ws)?;
    sc.send(&ClientMsg::signal(
        session_id,
        "ice",
        json!({ "cands": my_cands, "relayed": my_relayed_str }),
    ))
    .map_err(|_| ServeErr::Ws)?;

    let mut peer_fp = String::new();
    let mut pending = Some(pending);
    let (mut answered, mut got_cand) = (false, false);
    let deadline = Instant::now() + Duration::from_secs(20);
    while !(answered && got_cand) {
        if Instant::now() > deadline {
            return Err(ServeErr::Session);
        }
        match sc.try_recv() {
            Ok(Some(ServerMsg::Signal { kind, payload, .. })) => match kind.as_str() {
                "answer" => {
                    let sdp = payload_str(&payload, "sdp").ok_or(ServeErr::Session)?;
                    peer_fp = fingerprint(&sdp);
                    let ans = SdpAnswer::from_sdp_string(&sdp).map_err(|_| ServeErr::Session)?;
                    rtc.sdp_api()
                        .accept_answer(pending.take().ok_or(ServeErr::Session)?, ans)
                        .map_err(|_| ServeErr::Session)?;
                    drain(&mut rtc, &sock, &mut chan, &mut inbox, relay);
                    answered = true;
                }
                "ice" => {
                    apply_peer_candidates(&mut rtc, &sock, &payload, &turn_client);
                    drain(&mut rtc, &sock, &mut chan, &mut inbox, relay);
                    got_cand = true;
                }
                _ => {}
            },
            Ok(Some(ServerMsg::IncomingRequest {
                session_id: other, ..
            })) => {
                if sc
                    .send(&ClientMsg::connect_reject(&other, Some("busy")))
                    .is_err()
                {
                    return Err(ServeErr::Ws);
                }
            }
            Ok(_) => {}
            Err(_) => return Err(ServeErr::Ws),
        }
    }

    drive_until_confirmed(
        rtc, sock, my_addr, password, own_fp, peer_fp, relay, turn_client,
    )
    .map_err(|_| ServeErr::Session)
}

/// Стелі якості від пульта (PRD 5.5; D1 — кооперативні стелі, не жорсткі перекриття).
#[cfg(windows)]
struct QualityParams {
    fps: u32,
    bitrate: u32,
    scale: u32,
}

#[cfg(windows)]
impl Default for QualityParams {
    fn default() -> Self {
        QualityParams {
            fps: 30,
            bitrate: 4_000_000,
            scale: 1,
        }
    }
}

/// Поставити пульту контрольне JSON-повідомлення тим самим шифрованим медіа-трактом.
/// Пульт відрізняє його від H.264 за першим байтом `{`, від файлових кадрів — за 0xF7.
#[cfg(windows)]
fn queue_control_json(
    sealer: &mut StreamSealer,
    chunker: &mut Chunker,
    queue: &mut std::collections::VecDeque<Vec<u8>>,
    v: &Value,
) {
    if let Ok(bytes) = serde_json::to_vec(v) {
        let sealed = sealer.seal(&bytes);
        for c in chunker.chunk(&sealed) {
            queue.push_back(c);
        }
    }
}

/// Контрольне повідомлення зі списком моніторів + активним.
#[cfg(windows)]
fn queue_monitor_control(
    sealer: &mut StreamSealer,
    chunker: &mut Chunker,
    queue: &mut std::collections::VecDeque<Vec<u8>>,
    active: u32,
) {
    use crate::capture;
    let list: Vec<Value> = capture::monitors()
        .iter()
        .map(|m| {
            json!({
                "index": m.index, "name": m.name,
                "w": m.width, "h": m.height, "primary": m.is_primary,
            })
        })
        .collect();
    queue_control_json(
        sealer,
        chunker,
        queue,
        &json!({ "monitors": list, "active": active }),
    );
}

#[cfg(windows)]
fn managed_loop(
    mut est: Established,
    key: [u8; 32],
    deferred: Vec<Vec<u8>>,
    stop: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
) {
    use crate::capture;
    use crate::encode::H264Encoder;
    use crate::input;
    use std::collections::VecDeque;

    let mut sealer = StreamSealer::new(&key, MEDIA_H2C);
    let opener = StreamOpener::new(&key, INPUT_C2H);
    let mut chunker = Chunker::new(DEFAULT_MAX_PAYLOAD);
    let mut queue: VecDeque<Vec<u8>> = VecDeque::new();
    let relay = est.relay;
    let refresh_every = turn_refresh_interval(&est);
    let mut refreshed_at = Instant::now();

    let mut capture_pair = match capture::start_primary() {
        Ok(c) => Some(c),
        Err(_) => {
            done.store(true, Ordering::Relaxed); // пульс не має чекати вічно
            return;
        }
    };
    let mut active_mon = capture::monitors()
        .iter()
        .position(|m| m.is_primary)
        .unwrap_or(0) as u32;
    queue_monitor_control(&mut sealer, &mut chunker, &mut queue, active_mon);

    let mut params = QualityParams::default();
    // Говернор (Етап 5): фактичний бітрейт ≤ стелі; сигнал — глибина черги (SCTP
    // backpressure = канал не встигає). AIMD з тактом 3с, щоб не торохтіти keyframe'ами.
    let mut actual_bitrate = params.bitrate;
    let mut governor_at = Instant::now();
    let mut last_encode = Instant::now() - Duration::from_secs(1);

    let mut enc: Option<H264Encoder> = None;
    let mut chan = Some(est.chan);
    let mut inbox = deferred;

    // Keep-alive (PRD 5.4/5.6): WGC подієвий — статичний екран НЕ дає кадрів, тож пульт
    // міг би вважати сесію мертвою (watchdog) і бачити застиглу картинку. Тримаємо
    // знімок останнього кадру й раз на 2с перекодовуємо його keyframe'ом, якщо живих
    // кадрів немає (особливо після перемикання на статичний монітор).
    let mut last_bgra: Option<(Vec<u8>, u32, u32)> = None;
    let mut snapshot_at = Instant::now() - Duration::from_secs(2);

    // Файли (PRD 5.7): активні передачі. downloads: host→пульт (файл, offset, size);
    // uploads: пульт→host (файл, записано, size). Буфер (PRD 5.8): полінг змін кожні 2с.
    let mut downloads: std::collections::HashMap<u32, (std::fs::File, u64, u64)> =
        std::collections::HashMap::new();
    let mut uploads: std::collections::HashMap<u32, (std::fs::File, u64, u64)> =
        std::collections::HashMap::new();
    let mut clip_sync = true;
    let mut clip_seq = crate::clipboard::sequence();
    let mut clip_at = Instant::now();
    // Безпека сесії (PRD 5.10): затемнення локального екрана + блок фізичного вводу.
    let mut blanker: Option<crate::blank::Blanker> = None;
    let mut input_locked = false;

    while !stop.load(Ordering::Relaxed) && est.rtc.is_alive() {
        maybe_refresh_turn(&est, refresh_every, &mut refreshed_at);
        if !drain(&mut est.rtc, &est.sock, &mut chan, &mut inbox, relay) {
            break;
        }

        // Захоплення -> (обмеження FPS) -> кодек -> шифр -> чанки.
        if let Some((_, rx)) = capture_pair.as_ref() {
            if let Ok(f) = rx.try_recv() {
                let min_interval = Duration::from_millis(1000 / params.fps.clamp(1, 240) as u64);
                if last_encode.elapsed() >= min_interval {
                    if enc.is_none() {
                        let s = params.scale.max(1);
                        match H264Encoder::new_scaled(
                            f.width,
                            f.height,
                            f.width / s,
                            f.height / s,
                            params.fps,
                            actual_bitrate,
                        ) {
                            Ok(e) => enc = Some(e),
                            Err(_) => break,
                        }
                    }
                    if let Some(e) = enc.as_mut() {
                        if let Ok(unit) = e.encode_bgra(&f.data) {
                            if !unit.is_empty() {
                                last_encode = Instant::now();
                                let sealed = sealer.seal(&unit);
                                for c in chunker.chunk(&sealed) {
                                    queue.push_back(c);
                                }
                            }
                        }
                    }
                    // Знімок для keep-alive раз на секунду (clone 1080p дорогий — не щокадру).
                    if snapshot_at.elapsed() >= Duration::from_secs(1) {
                        snapshot_at = Instant::now();
                        last_bgra = Some((f.data.clone(), f.width, f.height));
                    }
                }
            }
        }

        // Keep-alive: статичний екран ≥2с без кадрів — перекодувати знімок keyframe'ом
        // (свіжий кодек = keyframe). Тримає сесію живою й оновлює картинку статики.
        if last_encode.elapsed() >= Duration::from_secs(2) {
            if let Some((data, w, h)) = last_bgra.as_ref() {
                let s = params.scale.max(1);
                if let Ok(mut e) =
                    H264Encoder::new_scaled(*w, *h, *w / s, *h / s, params.fps, actual_bitrate)
                {
                    if let Ok(unit) = e.encode_bgra(data) {
                        if !unit.is_empty() {
                            last_encode = Instant::now();
                            let sealed = sealer.seal(&unit);
                            for c in chunker.chunk(&sealed) {
                                queue.push_back(c);
                            }
                        }
                    }
                    enc = Some(e);
                }
            }
        }

        // Говернор: знизити бітрейт при стійкому заторі, підняти до стелі при простої.
        if governor_at.elapsed() >= Duration::from_secs(3) {
            governor_at = Instant::now();
            let backlog = queue.len();
            if backlog > 96 && actual_bitrate > 256_000 {
                actual_bitrate = (actual_bitrate * 7 / 10).max(256_000);
                enc = None; // перезапуск кодека = новий keyframe зі зниженим бітрейтом
            } else if backlog == 0 && actual_bitrate < params.bitrate {
                actual_bitrate = (actual_bitrate * 5 / 4).min(params.bitrate);
                enc = None;
            }
        }

        // Вивантаження відео-чанків (backpressure SCTP).
        while let Some(c) = queue.front() {
            let ok = est
                .rtc
                .channel(est.chan)
                .map(|mut ch| ch.write(true, c).unwrap_or(false))
                .unwrap_or(false);
            if ok {
                queue.pop_front();
            } else {
                break;
            }
        }

        // Файли host→пульт: підкачувати чанки, поки канал вільний (відео в пріоритеті).
        while queue.len() < 48 && !downloads.is_empty() {
            use std::io::Read;
            let id = *downloads.keys().next().unwrap();
            let mut finished: Option<Value> = None;
            if let Some((f, off, size)) = downloads.get_mut(&id) {
                let mut buf = vec![0u8; crate::files::FILE_CHUNK];
                match f.read(&mut buf) {
                    Ok(0) => {
                        finished =
                            Some(json!({"fsDone": {"id": id, "ok": *off >= *size, "err": null}}));
                    }
                    Ok(n) => {
                        let frame = crate::files::encode_file_frame(id, *off, &buf[..n]);
                        *off += n as u64;
                        let sealed = sealer.seal(&frame);
                        for c in chunker.chunk(&sealed) {
                            queue.push_back(c);
                        }
                        if *off >= *size {
                            finished = Some(json!({"fsDone": {"id": id, "ok": true, "err": null}}));
                        }
                    }
                    Err(e) => {
                        finished =
                            Some(json!({"fsDone": {"id": id, "ok": false, "err": e.to_string()}}));
                    }
                }
            }
            if let Some(done) = finished {
                downloads.remove(&id);
                queue_control_json(&mut sealer, &mut chunker, &mut queue, &done);
            }
        }

        // Буфер обміну: дешевий полінг змін (sequence number) кожні 2с.
        if clip_at.elapsed() >= Duration::from_secs(2) {
            clip_at = Instant::now();
            if clip_sync {
                let seq = crate::clipboard::sequence();
                if seq != clip_seq {
                    clip_seq = seq;
                    if let Some(text) = crate::clipboard::get_text() {
                        if !text.is_empty() && text.len() <= 262_144 {
                            queue_control_json(
                                &mut sealer,
                                &mut chunker,
                                &mut queue,
                                &json!({"clipboard": {"text": text}}),
                            );
                        }
                    }
                }
            }
        }

        // Вхідні події: ввід -> інжекція; керівні (якість/монітор/файли/буфер) -> цикл.
        let mut bye = false;
        for raw in std::mem::take(&mut inbox) {
            if raw == SESSION_BYE {
                bye = true; // пульт чисто завершив сесію
                continue;
            }
            if let Ok(opened) = opener.open(&raw) {
                // Бінарний кадр файла (пульт → host, upload).
                if let Some((id, offset, data)) = crate::files::parse_file_frame(&opened) {
                    use std::io::{Seek, SeekFrom, Write};
                    let mut done_msg: Option<Value> = None;
                    if let Some((f, written, size)) = uploads.get_mut(&id) {
                        // Канал упорядкований — offset має збігатися; інакше мовчки пропускаємо.
                        if offset == *written
                            && f.seek(SeekFrom::Start(offset)).is_ok()
                            && f.write_all(data).is_ok()
                        {
                            let prev = *written;
                            *written += data.len() as u64;
                            // Ack що ~512КБ (вікно відправника) і завершення.
                            if *written >= *size || (*written / 524_288) != (prev / 524_288) {
                                done_msg = Some(json!({"fsProgress":
                                    {"id": id, "offset": *written, "size": *size,
                                     "done": *written >= *size}}));
                            }
                            if *written >= *size {
                                let _ = f.flush();
                            }
                        }
                    }
                    if let Some(m) = done_msg {
                        let complete = m["fsProgress"]["done"].as_bool().unwrap_or(false);
                        queue_control_json(&mut sealer, &mut chunker, &mut queue, &m);
                        if complete {
                            uploads.remove(&id);
                            queue_control_json(
                                &mut sealer,
                                &mut chunker,
                                &mut queue,
                                &json!({"fsDone": {"id": id, "ok": true, "err": null}}),
                            );
                        }
                    }
                    continue;
                }
                if let Ok(ev) = serde_json::from_slice::<InputEvent>(&opened) {
                    match ev {
                        // Зміна якості ПІД ЧАС сесії, без перепідключення: новий кодек
                        // на наступному кадрі (почне з keyframe).
                        InputEvent::Quality {
                            fps,
                            bitrate,
                            scale,
                        } => {
                            let next = QualityParams {
                                fps: fps.clamp(5, 60),
                                bitrate: bitrate.clamp(256_000, 20_000_000),
                                scale: scale.clamp(1, 4),
                            };
                            if next.fps != params.fps
                                || next.bitrate != params.bitrate
                                || next.scale != params.scale
                            {
                                actual_bitrate = next.bitrate;
                                params = next;
                                enc = None;
                                last_bgra = None; // знімок іншого масштабу — не перекодовувати
                            }
                        }
                        InputEvent::Monitor { index } => {
                            if index != active_mon {
                                if let Ok(pair) = capture::start_monitor(index) {
                                    if let Some((old, _)) = capture_pair.take() {
                                        old.stop();
                                    }
                                    capture_pair = Some(pair);
                                    active_mon = index;
                                    enc = None; // нова роздільність -> новий кодек
                                    last_bgra = None; // знімок СТАРОГО монітора — скинути
                                    queue_monitor_control(
                                        &mut sealer,
                                        &mut chunker,
                                        &mut queue,
                                        active_mon,
                                    );
                                }
                            }
                        }
                        InputEvent::FsList { path } => queue_control_json(
                            &mut sealer,
                            &mut chunker,
                            &mut queue,
                            &json!({"fsList": crate::files::list_dir(&path)}),
                        ),
                        InputEvent::FsDownload { id, path, offset } => {
                            use std::io::{Seek, SeekFrom};
                            match std::fs::File::open(&path) {
                                Ok(mut f) => {
                                    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
                                    let off = offset.min(size);
                                    let _ = f.seek(SeekFrom::Start(off));
                                    queue_control_json(
                                        &mut sealer,
                                        &mut chunker,
                                        &mut queue,
                                        &json!({"fsProgress":
                                            {"id": id, "offset": off, "size": size, "done": false}}),
                                    );
                                    downloads.insert(id, (f, off, size));
                                }
                                Err(e) => queue_control_json(
                                    &mut sealer,
                                    &mut chunker,
                                    &mut queue,
                                    &json!({"fsDone":
                                        {"id": id, "ok": false, "err": e.to_string()}}),
                                ),
                            }
                        }
                        InputEvent::FsUploadStart { id, path, size } => {
                            match std::fs::OpenOptions::new()
                                .create(true)
                                .write(true)
                                .truncate(false)
                                .open(&path)
                            {
                                Ok(f) => {
                                    // Resume: чекаємо чанки з того offset, що вже на диску.
                                    let existing =
                                        f.metadata().map(|m| m.len()).unwrap_or(0).min(size);
                                    queue_control_json(
                                        &mut sealer,
                                        &mut chunker,
                                        &mut queue,
                                        &json!({"fsProgress":
                                            {"id": id, "offset": existing, "size": size,
                                             "done": existing >= size}}),
                                    );
                                    if existing >= size {
                                        queue_control_json(
                                            &mut sealer,
                                            &mut chunker,
                                            &mut queue,
                                            &json!({"fsDone": {"id": id, "ok": true, "err": null}}),
                                        );
                                    } else {
                                        uploads.insert(id, (f, existing, size));
                                    }
                                }
                                Err(e) => queue_control_json(
                                    &mut sealer,
                                    &mut chunker,
                                    &mut queue,
                                    &json!({"fsDone":
                                        {"id": id, "ok": false, "err": e.to_string()}}),
                                ),
                            }
                        }
                        InputEvent::FsCancel { id } => {
                            downloads.remove(&id);
                            uploads.remove(&id);
                        }
                        InputEvent::Clipboard { text } => {
                            if clip_sync {
                                let _ = crate::clipboard::set_text(&text);
                                clip_seq = crate::clipboard::sequence(); // не відлунювати назад
                            }
                        }
                        InputEvent::ClipboardSync { enabled } => clip_sync = enabled,
                        InputEvent::Blank { enabled } => {
                            if enabled && blanker.is_none() {
                                blanker = Some(crate::blank::Blanker::show());
                            } else if !enabled {
                                if let Some(b) = blanker.take() {
                                    b.hide();
                                }
                            }
                        }
                        InputEvent::InputLock { enabled } => {
                            input_locked = input::block_physical(enabled) && enabled;
                        }
                        other => input::inject(&other),
                    }
                }
            }
        }
        if bye {
            break;
        }

        if !drain(&mut est.rtc, &est.sock, &mut chan, &mut inbox, relay) {
            break;
        }
        recv_one(&mut est.rtc, &est.sock, est.my_addr, relay, est.turn_client.as_mut());
        let _ = est.rtc.handle_input(Input::Timeout(Instant::now()));
    }
    // Безпека: затемнення і блок вводу НІКОЛИ не переживають сесію (людина за
    // машиною не має лишитися із чорним екраном і мертвою клавіатурою).
    if let Some(b) = blanker.take() {
        b.hide();
    }
    if input_locked {
        let _ = input::block_physical(false);
    }
    // Сесія скінчилась — повідомити пульс ДО прибирання (воно займає сотні мс).
    done.store(true, Ordering::Relaxed);
    // Симетричне чисте завершення (див. controller_loop): пульт одразу бачить кінець.
    write_raw(&mut est.rtc, est.chan, SESSION_BYE);
    for _ in 0..5 {
        if !drain(&mut est.rtc, &est.sock, &mut chan, &mut inbox, relay) {
            break;
        }
        let _ = est.rtc.handle_input(Input::Timeout(Instant::now()));
    }
    est.rtc.disconnect();
    let _ = drain(&mut est.rtc, &est.sock, &mut chan, &mut inbox, relay);
    if let Some((cap, _)) = capture_pair.take() {
        cap.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::parse_turn_endpoint;
    use serde_json::json;

    #[test]
    fn picks_udp_turn_from_real_ice_servers() {
        // Точна форма connect_ready.iceServers (mintTurnCredentials): urls = string[],
        // turns/tcp перші, UDP turn: третім.
        let ice = json!([{
            "urls": [
                "turns:turn.example:443?transport=tcp",
                "turns:turn.example:5349?transport=tcp",
                "turn:192.168.88.223:3478?transport=udp",
                "turn:192.168.88.223:3478?transport=tcp"
            ],
            "username": "1780739684:acct123",
            "credential": "+0hxRCZJKXHBnZArGiu9TR97sow="
        }]);
        let (u, c, srv) = parse_turn_endpoint(&ice).expect("parse");
        assert_eq!(u, "1780739684:acct123");
        assert_eq!(c, "+0hxRCZJKXHBnZArGiu9TR97sow=");
        assert_eq!(srv.to_string(), "192.168.88.223:3478"); // НЕ turns:443, НЕ tcp
    }

    #[test]
    fn accepts_space_separated_urls_string() {
        let ice = json!([{
            "urls": "turns:h:443?transport=tcp turn:10.0.0.5:3478?transport=udp",
            "username": "u", "credential": "c"
        }]);
        let (_, _, srv) = parse_turn_endpoint(&ice).expect("parse");
        assert_eq!(srv.to_string(), "10.0.0.5:3478");
    }

    #[test]
    fn none_when_only_tcp_or_turns() {
        // Жодного UDP turn: -> None -> плавна деградація до host-only.
        let ice = json!([{
            "urls": ["turns:h:443?transport=tcp", "turn:1.2.3.4:3478?transport=tcp"],
            "username": "u", "credential": "c"
        }]);
        assert!(parse_turn_endpoint(&ice).is_none());
    }

    #[test]
    fn none_when_empty_or_missing_fields() {
        assert!(parse_turn_endpoint(&json!([])).is_none());
        // немає username -> None ще до резолву адреси
        assert!(
            parse_turn_endpoint(&json!([{ "urls": ["turn:1.2.3.4:3478?transport=udp"] }]))
                .is_none()
        );
    }
}
