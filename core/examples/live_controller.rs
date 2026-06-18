//! Живий пульт для тесту 6б: підключається через СПРАВЖНІЙ сервер до host-пристрою
//! (за замовч. — host із .scratch/e2e-creds.json, тобто служба-воркер), приймає H.264-потік,
//! розшифровує (PAKE-ключ), валідує й зберігає в .scratch/live_recv.h264.
//!
//! PAKE-пароль має збігатися з device.json служби (тут: "one-time-connect-pw").
//! Windows-only. Запуск: cargo run -p zortilwatch-core --example live_controller

#[cfg(not(windows))]
fn main() {
    println!("live_controller: лише Windows");
}

#[cfg(windows)]
fn main() {
    imp::run();
}

#[cfg(windows)]
mod imp {
    use std::io::Write;
    use std::net::{SocketAddr, UdpSocket};
    use std::time::{Duration, Instant};

    use serde::Deserialize;
    use serde_json::{json, Value};
    use str0m::change::SdpOffer;
    use str0m::channel::ChannelId;
    use str0m::net::{Protocol, Receive};
    use str0m::{Candidate, Event, Input, Output, Rtc};

    use zortilwatch_core::crypto::StreamOpener;
    use zortilwatch_core::media::Reassembler;
    use zortilwatch_core::net::new_rtc;
    use zortilwatch_core::session::{Handshake, SessionMessage};
    use zortilwatch_core::signal::{ClientMsg, ServerMsg, SignalClient};

    const PASSWORD: &[u8] = b"one-time-connect-pw"; // = device.json служби
    const MEDIA_LABEL: &[u8] = b"zortilwatch media h2c v1";
    const WANT_FRAMES: usize = 30;

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

    fn drain(rtc: &mut Rtc, sock: &UdpSocket, chan: &mut Option<ChannelId>, inbox: &mut Vec<Vec<u8>>) {
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
                    Receive { proto: Protocol::Udp, source, destination: my_addr, contents },
                ))
                .expect("handle_input");
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
    fn is_annexb(f: &[u8]) -> bool {
        f.starts_with(&[0, 0, 0, 1]) || f.starts_with(&[0, 0, 1])
    }
    fn has_nal_type(f: &[u8], t: u8) -> bool {
        let mut i = 0usize;
        while i + 3 < f.len() {
            if f[i] == 0 && f[i + 1] == 0 && f[i + 2] == 1 {
                if f[i + 3] & 0x1f == t {
                    return true;
                }
                i += 3;
            } else {
                i += 1;
            }
        }
        false
    }

    struct Established {
        rtc: Rtc,
        sock: UdpSocket,
        my_addr: SocketAddr,
        chan: ChannelId,
        key: [u8; 32],
    }
    fn drive_until_confirmed(
        mut rtc: Rtc,
        sock: UdpSocket,
        my_addr: SocketAddr,
        own_fp: String,
        peer_fp: String,
    ) -> Result<Established, String> {
        sock.set_read_timeout(Some(Duration::from_millis(50))).map_err(|e| e.to_string())?;
        let mut chan: Option<ChannelId> = None;
        let mut inbox: Vec<Vec<u8>> = Vec::new();
        let mut hs: Option<Handshake> = None;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(h) = hs.as_ref() {
                if let Some(key) = h.confirmed_key() {
                    return Ok(Established { key: *key, chan: chan.expect("chan"), rtc, sock, my_addr });
                }
                if h.is_failed() {
                    return Err("PAKE FAILED (пароль?)".into());
                }
            }
            if Instant::now() > deadline {
                return Err("establish timeout".into());
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
            rtc.handle_input(Input::Timeout(Instant::now())).map_err(|e| e.to_string())?;
        }
    }

    fn run_controller(creds: &Creds) -> Result<(usize, usize, bool), String> {
        let url = ws_url(&creds.base);
        let mut sc = SignalClient::connect(&url).map_err(|e| e.to_string())?;
        sc.set_read_timeout(Some(Duration::from_secs(20))).map_err(|e| e.to_string())?;
        sc.register(&creds.controller.id, &creds.controller.secret, "controller")
            .map_err(|e| e.to_string())?;
        println!("пульт зареєстровано; під'єднуюсь до host={}", creds.host.id);
        sc.send(&ClientMsg::connect_request(&creds.host.id)).map_err(|e| e.to_string())?;

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
                        let answer = rtc.sdp_api().accept_offer(offer).map_err(|e| e.to_string())?;
                        drain(&mut rtc, &sock, &mut chan, &mut inbox);
                        let answer_sdp = answer.to_sdp_string();
                        own_fp = fingerprint(&answer_sdp);
                        sc.send(&ClientMsg::signal(&session_id, "answer", json!({ "sdp": answer_sdp })))
                            .map_err(|e| e.to_string())?;
                        sc.send(&ClientMsg::signal(&session_id, "ice", json!({ "cands": [cand.to_sdp_string()] })))
                            .map_err(|e| e.to_string())?;
                        offered = true;
                    }
                    "ice" => {
                        if let Some(arr) = payload.get("cands").and_then(|v| v.as_array()) {
                            for c in arr.iter().filter_map(|v| v.as_str()) {
                                if let Ok(cand) = Candidate::from_sdp_string(c) {
                                    rtc.add_remote_candidate(cand);
                                    got_cand = true;
                                }
                            }
                        } else if let Some(c) = payload_str(&payload, "cand") {
                            if let Ok(cand) = Candidate::from_sdp_string(&c) {
                                rtc.add_remote_candidate(cand);
                                got_cand = true;
                            }
                        }
                        drain(&mut rtc, &sock, &mut chan, &mut inbox);
                    }
                    _ => {}
                }
            }
        }

        let mut est = drive_until_confirmed(rtc, sock, my_addr, own_fp, peer_fp)?;
        println!("сесію підтверджено ✓ — приймаю H.264 від служби…");

        let out = std::path::Path::new(".scratch").join("live_recv.h264");
        let _ = std::fs::create_dir_all(".scratch");
        let mut file = std::fs::File::create(&out).map_err(|e| e.to_string())?;

        let mut re = Reassembler::new();
        let opener = StreamOpener::new(&est.key, MEDIA_LABEL);
        let mut chan_opt = Some(est.chan);
        let mut inbox = Vec::new();
        let (mut frames, mut bytes, mut keyframe) = (0usize, 0usize, false);
        let deadline = Instant::now() + Duration::from_secs(20);
        while frames < WANT_FRAMES && Instant::now() < deadline {
            drain(&mut est.rtc, &est.sock, &mut chan_opt, &mut inbox);
            for m in std::mem::take(&mut inbox) {
                if let Some(sealed) = re.push(&m) {
                    let frame = opener.open(&sealed).map_err(|e| e.to_string())?;
                    if !is_annexb(&frame) {
                        return Err("кадр не Annex-B".into());
                    }
                    if has_nal_type(&frame, 7) {
                        keyframe = true;
                    }
                    file.write_all(&frame).map_err(|e| e.to_string())?;
                    bytes += frame.len();
                    frames += 1;
                }
            }
            recv_one(&mut est.rtc, &est.sock, est.my_addr);
            est.rtc.handle_input(Input::Timeout(Instant::now())).map_err(|e| e.to_string())?;
        }
        println!("збережено {}", out.display());
        Ok((frames, bytes, keyframe))
    }

    pub fn run() {
        let path = std::env::var("SIGNAL_CREDS").unwrap_or_else(|_| ".scratch/e2e-creds.json".into());
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let creds: Creds = serde_json::from_str(raw.trim_start_matches('\u{feff}')).expect("parse creds");
        match run_controller(&creds) {
            Ok((frames, bytes, keyframe)) if frames > 0 && keyframe => {
                println!("RESULT=OK служба→сервер→пульт: прийнято {frames} кадрів H.264 ({bytes} байт), keyframe(SPS)=так");
            }
            Ok((frames, bytes, keyframe)) => {
                eprintln!("RESULT=FAIL frames={frames} bytes={bytes} keyframe={keyframe}");
                std::process::exit(2);
            }
            Err(e) => {
                eprintln!("RESULT=FAIL {e}");
                std::process::exit(2);
            }
        }
    }
}
