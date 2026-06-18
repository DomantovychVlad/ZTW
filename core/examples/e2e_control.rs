//! ДИСТАНЦІЙНЕ КЕРУВАННЯ поверх зашифрованої сесії: пульт шле події вводу, керований їх
//! ІНЖЕКТУЄ (SendInput). Це друга половина remote-control (відео керований->пульт уже є в
//! e2e_media; тут ввід пульт->керований). Двонапрямний шифр-канал: окремі ключі на напрям
//! (StreamSealer/StreamOpener з різними label) — лічильникові nonce не перетинаються.
//!
//! Валідація НЕДЕСТРУКТИВНА: керований повідомляє пульту свою поточну (нормалізовану)
//! позицію курсора, пульт відлунює MouseMove рівно туди ж, керований інжектує — курсор
//! НЕ зрушується (delta≈0).
//!
//! Windows-only (SendInput/cursor). Сервер сигналінгу має бути піднятий. Запуск:
//!   cargo run -p zortilwatch-core --example e2e_control

#[cfg(not(windows))]
fn main() {
    println!("e2e_control: лише Windows (SendInput)");
}

#[cfg(windows)]
fn main() {
    imp::run();
}

#[cfg(windows)]
mod imp {
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

    use zortilwatch_core::crypto::{StreamOpener, StreamSealer};
    use zortilwatch_core::input::{self, InputEvent};
    use zortilwatch_core::net::new_rtc;
    use zortilwatch_core::session::{Handshake, SessionMessage};
    use zortilwatch_core::signal::{ClientMsg, ServerMsg, SignalClient};

    const PASSWORD: &[u8] = b"one-time-connect-pw";
    const CTRL_H2C: &[u8] = b"zortilwatch ctrl h2c v1"; // керований->пульт (позиція курсора)
    const CTRL_C2H: &[u8] = b"zortilwatch ctrl c2h v1"; // пульт->керований (події вводу)
    const N_EVENTS: usize = 5;

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

    fn drain(
        rtc: &mut Rtc,
        sock: &UdpSocket,
        chan: &mut Option<ChannelId>,
        inbox: &mut Vec<Vec<u8>>,
    ) {
        loop {
            match rtc.poll_output().expect("poll_output") {
                Output::Timeout(_) => return,
                Output::Transmit(t) => {
                    let _ = sock.send_to(&t.contents, t.destination);
                }
                Output::Event(Event::ChannelOpen(id, _)) => *chan = Some(id),
                Output::Event(Event::ChannelData(d)) => inbox.push(d.data),
                Output::Event(_) => {}
            }
        }
    }

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

    fn write_raw(rtc: &mut Rtc, cid: ChannelId, bytes: &[u8]) {
        if let Some(mut ch) = rtc.channel(cid) {
            let _ = ch.write(true, bytes);
        }
    }

    struct Established {
        rtc: Rtc,
        sock: UdpSocket,
        my_addr: SocketAddr,
        chan: ChannelId,
        key: [u8; 32],
    }

    /// Драйв str0m + PAKE до підтвердження. Блоби, що НЕ є PAKE-повідомленнями (контрол,
    /// який прийшов, поки цей бік ще завершував рукостискання), буферизуються у `deferred`.
    fn drive_until_confirmed(
        mut rtc: Rtc,
        sock: UdpSocket,
        my_addr: SocketAddr,
        own_fp: String,
        peer_fp: String,
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
                            chan: chan.expect("chan"),
                            rtc,
                            sock,
                            my_addr,
                        },
                        deferred,
                    ));
                }
                if h.is_failed() {
                    return Err("session handshake FAILED".into());
                }
            }
            if Instant::now() > deadline {
                return Err("session establish timeout".into());
            }

            drain(&mut rtc, &sock, &mut chan, &mut inbox);
            if hs.is_none() {
                if let Some(cid) = chan {
                    let (h, msg) = Handshake::start(PASSWORD, own_fp.clone(), peer_fp.clone());
                    write_session(&mut rtc, cid, &msg);
                    hs = Some(h);
                    drain(&mut rtc, &sock, &mut chan, &mut inbox);
                }
            }
            for raw in std::mem::take(&mut inbox) {
                match serde_json::from_slice::<SessionMessage>(&raw) {
                    Ok(m) => {
                        if let (Some(h), Some(cid)) = (hs.as_mut(), chan) {
                            if let Some(resp) = h.on_message(m) {
                                write_session(&mut rtc, cid, &resp);
                                drain(&mut rtc, &sock, &mut chan, &mut inbox);
                            }
                        }
                    }
                    // Не PAKE -> контрол-повідомлення, що випередило підтвердження. Відкласти.
                    Err(_) => deferred.push(raw),
                }
            }
            recv_one(&mut rtc, &sock, my_addr);
            rtc.handle_input(Input::Timeout(Instant::now()))
                .map_err(|e| e.to_string())?;
        }
    }

    /// HOST = керований: шле свою позицію курсора, приймає й ІНЖЕКТУЄ події вводу.
    /// Повертає (скільки подій інжектовано, зсув курсора в px після інжекції).
    fn run_host(
        url: &str,
        id: &str,
        secret: &str,
        ready: Arc<Barrier>,
    ) -> Result<(usize, i32), String> {
        let mut sc = SignalClient::connect(url).map_err(|e| e.to_string())?;
        sc.set_read_timeout(Some(Duration::from_secs(20)))
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

        let sock = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let my_addr = sock.local_addr().map_err(|e| e.to_string())?;
        let mut rtc = new_rtc(Instant::now());
        let cand = Candidate::host(my_addr, "udp").map_err(|e| e.to_string())?;
        rtc.add_local_candidate(cand.clone());
        let mut chan = None;
        let mut inbox = Vec::new();
        drain(&mut rtc, &sock, &mut chan, &mut inbox);

        let mut api = rtc.sdp_api();
        let _cid = api.add_channel("control".to_string());
        let (offer, pending) = api.apply().ok_or("offer no changes")?;
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
            json!({ "cand": cand.to_sdp_string() }),
        ))
        .map_err(|e| e.to_string())?;

        let mut peer_fp = String::new();
        let mut pending = Some(pending);
        let (mut answered, mut got_cand) = (false, false);
        while !(answered && got_cand) {
            if let ServerMsg::Signal { kind, payload, .. } = sc.recv().map_err(|e| e.to_string())? {
                match kind.as_str() {
                    "answer" => {
                        let sdp = payload_str(&payload, "sdp").ok_or("no sdp")?;
                        peer_fp = fingerprint(&sdp);
                        let ans = SdpAnswer::from_sdp_string(&sdp).map_err(|e| e.to_string())?;
                        rtc.sdp_api()
                            .accept_answer(pending.take().ok_or("dbl")?, ans)
                            .map_err(|e| e.to_string())?;
                        drain(&mut rtc, &sock, &mut chan, &mut inbox);
                        answered = true;
                    }
                    "ice" => {
                        let c = payload_str(&payload, "cand").ok_or("no cand")?;
                        rtc.add_remote_candidate(
                            Candidate::from_sdp_string(&c).map_err(|e| e.to_string())?,
                        );
                        drain(&mut rtc, &sock, &mut chan, &mut inbox);
                        got_cand = true;
                    }
                    _ => {}
                }
            }
        }

        let (mut est, deferred) = drive_until_confirmed(rtc, sock, my_addr, own_fp, peer_fp)?;
        println!("HOST(керований): session confirmed ✓ — шлю позицію курсора, чекаю ввід…");

        // Поточна позиція курсора -> нормалізована -> пульту (sealed h2c).
        let mut sealer = StreamSealer::new(&est.key, CTRL_H2C);
        let opener = StreamOpener::new(&est.key, CTRL_C2H);
        let (px, py) = input::cursor_pos();
        let (w, h) = input::screen_size();
        let nx = px as f32 / (w.max(2) - 1) as f32;
        let ny = py as f32 / (h.max(2) - 1) as f32;
        let pos = sealer.seal(&serde_json::to_vec(&(nx, ny)).expect("ser"));
        write_raw(&mut est.rtc, est.chan, &pos);

        // Приймаємо й інжектуємо події вводу (sealed c2h) до N або дедлайну.
        let mut chan_opt = Some(est.chan);
        let mut inbox = deferred;
        let mut injected = 0usize;
        let deadline = Instant::now() + Duration::from_secs(20);
        while injected < N_EVENTS {
            if Instant::now() > deadline {
                return Err(format!("отримано лише {injected}/{N_EVENTS} подій"));
            }
            drain(&mut est.rtc, &est.sock, &mut chan_opt, &mut inbox);
            for raw in std::mem::take(&mut inbox) {
                if let Ok(opened) = opener.open(&raw) {
                    if let Ok(ev) = serde_json::from_slice::<InputEvent>(&opened) {
                        input::inject(&ev);
                        injected += 1;
                    }
                }
            }
            recv_one(&mut est.rtc, &est.sock, est.my_addr);
            est.rtc
                .handle_input(Input::Timeout(Instant::now()))
                .map_err(|e| e.to_string())?;
        }

        thread::sleep(Duration::from_millis(80)); // дати інжекції осісти
        let (px2, py2) = input::cursor_pos();
        let delta = (px2 - px).abs().max((py2 - py).abs());
        let _ = sc.send(&ClientMsg::session_close(&session_id, Some("done")));
        Ok((injected, delta))
    }

    /// CONTROLLER = пульт: отримує позицію курсора, шле N подій MouseMove рівно туди ж.
    fn run_controller(
        url: &str,
        id: &str,
        secret: &str,
        target: &str,
        ready: Arc<Barrier>,
    ) -> Result<usize, String> {
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
                ServerMsg::ConnectReady { session_id, .. } => break session_id,
                ServerMsg::ConnectErr { code, .. } => return Err(format!("connect_err {code}")),
                _ => {}
            }
        };

        let sock = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let my_addr = sock.local_addr().map_err(|e| e.to_string())?;
        let mut rtc = new_rtc(Instant::now());
        let cand = Candidate::host(my_addr, "udp").map_err(|e| e.to_string())?;
        rtc.add_local_candidate(cand.clone());
        let mut chan = None;
        let mut inbox = Vec::new();
        drain(&mut rtc, &sock, &mut chan, &mut inbox);

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
                            json!({ "cand": cand.to_sdp_string() }),
                        ))
                        .map_err(|e| e.to_string())?;
                        offered = true;
                    }
                    "ice" => {
                        let c = payload_str(&payload, "cand").ok_or("no cand")?;
                        rtc.add_remote_candidate(
                            Candidate::from_sdp_string(&c).map_err(|e| e.to_string())?,
                        );
                        drain(&mut rtc, &sock, &mut chan, &mut inbox);
                        got_cand = true;
                    }
                    _ => {}
                }
            }
        }

        let (mut est, deferred) = drive_until_confirmed(rtc, sock, my_addr, own_fp, peer_fp)?;
        println!("CONTROLLER(пульт): session confirmed ✓ — приймаю позицію, шлю ввід…");

        let opener = StreamOpener::new(&est.key, CTRL_H2C);
        let mut sealer = StreamSealer::new(&est.key, CTRL_C2H);

        // Дочекатися позиції курсора (з deferred або нових ChannelData).
        let mut chan_opt = Some(est.chan);
        let mut inbox = deferred;
        let deadline = Instant::now() + Duration::from_secs(20);
        let (nx, ny) = loop {
            let mut found = None;
            for raw in std::mem::take(&mut inbox) {
                if let Ok(opened) = opener.open(&raw) {
                    if let Ok(p) = serde_json::from_slice::<(f32, f32)>(&opened) {
                        found = Some(p);
                    }
                }
            }
            if let Some(p) = found {
                break p;
            }
            if Instant::now() > deadline {
                return Err("не дочекався позиції курсора".into());
            }
            drain(&mut est.rtc, &est.sock, &mut chan_opt, &mut inbox);
            recv_one(&mut est.rtc, &est.sock, est.my_addr);
            est.rtc
                .handle_input(Input::Timeout(Instant::now()))
                .map_err(|e| e.to_string())?;
        };

        // Шлемо N подій MouseMove рівно у поточну позицію (недеструктивно).
        for _ in 0..N_EVENTS {
            let ev = InputEvent::MouseMove { x: nx, y: ny };
            let msg = sealer.seal(&serde_json::to_vec(&ev).expect("ser"));
            write_raw(&mut est.rtc, est.chan, &msg);
            drain(&mut est.rtc, &est.sock, &mut chan_opt, &mut inbox);
            recv_one(&mut est.rtc, &est.sock, est.my_addr);
            let _ = est.rtc.handle_input(Input::Timeout(Instant::now()));
        }
        // Флаш, щоб усі події дійшли.
        let flush = Instant::now() + Duration::from_secs(3);
        while Instant::now() < flush {
            drain(&mut est.rtc, &est.sock, &mut chan_opt, &mut inbox);
            recv_one(&mut est.rtc, &est.sock, est.my_addr);
            let _ = est.rtc.handle_input(Input::Timeout(Instant::now()));
        }
        Ok(N_EVENTS)
    }

    pub fn run() {
        let path =
            std::env::var("SIGNAL_CREDS").unwrap_or_else(|_| ".scratch/e2e-creds.json".into());
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let raw = raw.trim_start_matches('\u{feff}');
        let creds: Creds = serde_json::from_str(raw).expect("parse creds");
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

        let hr = host.join().expect("host panicked");
        let cr = ctrl.join().expect("controller panicked");

        match (&hr, &cr) {
            (Ok((injected, delta)), Ok(sent)) if injected == sent && *delta <= 5 => {
                println!("CONTROLLER: надіслано {sent} подій вводу (зашифровано)");
                println!(
                    "HOST: інжектовано {injected} подій; зсув курсора {delta}px (недеструктивно)"
                );
                println!("RESULT=OK дистанційний ввід пульт→керований крізь зашифровану сесію — інжектовано, курсор не зрушено");
            }
            (Ok((injected, delta)), Ok(sent)) => {
                println!("RESULT=FAIL injected={injected} sent={sent} delta={delta}px")
            }
            _ => println!("RESULT=FAIL host={hr:?} controller={cr:?}"),
        }
    }
}
