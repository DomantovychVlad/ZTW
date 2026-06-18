//! НАСКРІЗНЕ МЕДІА (DXGI): як e2e_media, але керований захоплює через **DXGI Desktop
//! Duplication** (start_primary_dxgi, з перемиканням desktop) замість WGC. Доводить, що
//! Tier-B-джерело стрімить крізь СПРАВЖНІЙ сигнальний сервер (server-mediated P2P str0m +
//! PAKE), а пульт збирає й валідує H.264.
//!
//! Windows-only. Сервер має бути піднятий. Запуск:
//!   cargo run -p zortilwatch-core --example dxgi_e2e

#[cfg(not(windows))]
fn main() {
    println!("dxgi_e2e: лише Windows (DXGI-захоплення + Media Foundation)");
}

#[cfg(windows)]
fn main() {
    imp::run();
}

#[cfg(windows)]
mod imp {
    use std::collections::VecDeque;
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

    use zortilwatch_core::capture::dxgi::start_primary_dxgi;
    use zortilwatch_core::crypto::{StreamOpener, StreamSealer};
    use zortilwatch_core::encode::H264Encoder;
    use zortilwatch_core::media::{Chunker, Reassembler, DEFAULT_MAX_PAYLOAD};
    use zortilwatch_core::net::new_rtc;
    use zortilwatch_core::session::{Handshake, SessionMessage};
    use zortilwatch_core::signal::{ClientMsg, ServerMsg, SignalClient};

    const PASSWORD: &[u8] = b"one-time-connect-pw";
    const N_FRAMES: usize = 12;
    const MEDIA_LABEL: &[u8] = b"zortilwatch media h2c v1"; // напрям керований->пульт

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

    fn payload_str(p: &Value, k: &str) -> Option<String> {
        p.get(k).and_then(|v| v.as_str()).map(String::from)
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
        sock.set_read_timeout(Some(Duration::from_millis(50)))
            .map_err(|e| e.to_string())?;
        let mut chan: Option<ChannelId> = None;
        let mut inbox: Vec<Vec<u8>> = Vec::new();
        let mut hs: Option<Handshake> = None;
        let deadline = Instant::now() + Duration::from_secs(30);

        loop {
            if let Some(h) = hs.as_ref() {
                if let Some(key) = h.confirmed_key() {
                    return Ok(Established {
                        key: *key,
                        chan: chan.expect("chan"),
                        rtc,
                        sock,
                        my_addr,
                    });
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

    // ── HOST = offerer: DXGI-захоплення + кодек + стрім ──
    fn run_host(url: &str, id: &str, secret: &str, ready: Arc<Barrier>) -> Result<usize, String> {
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
        let _cid = api.add_channel("media".to_string());
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

        let mut est = drive_until_confirmed(rtc, sock, my_addr, own_fp, peer_fp)?;
        println!("HOST: session confirmed ✓ — DXGI-захоплення, кодую і стрімлю {N_FRAMES} кадрів…");

        // DXGI-джерело замість WGC (з перемиканням desktop). Решта конвеєра ідентична.
        let (cap, rx) = start_primary_dxgi().map_err(|e| e.to_string())?;
        let mut enc: Option<H264Encoder> = None;
        let mut chunker = Chunker::new(DEFAULT_MAX_PAYLOAD);
        let mut sealer = StreamSealer::new(&est.key, MEDIA_LABEL);
        let mut queue: VecDeque<Vec<u8>> = VecDeque::new();
        let mut encoded = 0usize;
        let mut total_bytes = 0usize;
        let mut dims = (0u32, 0u32);
        let mut chan_opt = Some(est.chan);
        let mut inbox = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut drained_at: Option<Instant> = None;

        loop {
            if encoded >= N_FRAMES && queue.is_empty() {
                let t = *drained_at.get_or_insert_with(Instant::now);
                if Instant::now() - t > Duration::from_secs(2) {
                    break;
                }
            }
            if Instant::now() > deadline {
                return Err(format!("media timeout (encoded {encoded})"));
            }

            drain(&mut est.rtc, &est.sock, &mut chan_opt, &mut inbox);

            if encoded < N_FRAMES {
                if let Ok(f) = rx.try_recv() {
                    if enc.is_none() {
                        dims = (f.width, f.height);
                        enc = Some(
                            H264Encoder::new(f.width, f.height, 30, 4_000_000)
                                .map_err(|e| e.to_string())?,
                        );
                    }
                    let unit = enc
                        .as_mut()
                        .unwrap()
                        .encode_bgra(&f.data)
                        .map_err(|e| e.to_string())?;
                    if !unit.is_empty() {
                        total_bytes += unit.len();
                        let sealed = sealer.seal(&unit);
                        for c in chunker.chunk(&sealed) {
                            queue.push_back(c);
                        }
                        encoded += 1;
                    }
                }
            }

            while let Some(c) = queue.front() {
                let accepted = est
                    .rtc
                    .channel(est.chan)
                    .map(|mut ch| ch.write(true, c).unwrap_or(false))
                    .unwrap_or(false);
                if accepted {
                    queue.pop_front();
                } else {
                    break;
                }
            }
            drain(&mut est.rtc, &est.sock, &mut chan_opt, &mut inbox);
            recv_one(&mut est.rtc, &est.sock, est.my_addr);
            est.rtc
                .handle_input(Input::Timeout(Instant::now()))
                .map_err(|e| e.to_string())?;
        }

        cap.stop();
        let _ = sc.send(&ClientMsg::session_close(&session_id, Some("done")));
        println!(
            "HOST: закодовано/надіслано {encoded} кадрів H.264 ({}x{}, {total_bytes} байт)",
            dims.0, dims.1
        );
        Ok(encoded)
    }

    #[derive(Debug)]
    struct MediaStat {
        frames: usize,
        bytes: usize,
        keyframe: bool,
    }

    // ── CONTROLLER = answerer: прийом + валідація ──
    fn run_controller(
        url: &str,
        id: &str,
        secret: &str,
        target: &str,
        ready: Arc<Barrier>,
    ) -> Result<MediaStat, String> {
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

        let mut est = drive_until_confirmed(rtc, sock, my_addr, own_fp, peer_fp)?;
        println!("CONTROLLER: session confirmed ✓ — приймаю H.264-потік…");

        let mut re = Reassembler::new();
        let opener = StreamOpener::new(&est.key, MEDIA_LABEL);
        let mut chan_opt = Some(est.chan);
        let mut inbox = Vec::new();
        let mut stat = MediaStat {
            frames: 0,
            bytes: 0,
            keyframe: false,
        };
        let deadline = Instant::now() + Duration::from_secs(25);
        while stat.frames < N_FRAMES {
            if Instant::now() > deadline {
                return Err(format!("отримано лише {}/{N_FRAMES} кадрів", stat.frames));
            }
            drain(&mut est.rtc, &est.sock, &mut chan_opt, &mut inbox);
            for m in std::mem::take(&mut inbox) {
                if let Some(sealed) = re.push(&m) {
                    let frame = opener.open(&sealed).map_err(|e| e.to_string())?;
                    if !is_annexb(&frame) {
                        return Err("розшифрований кадр не Annex-B".into());
                    }
                    if has_nal_type(&frame, 7) {
                        stat.keyframe = true;
                    }
                    stat.bytes += frame.len();
                    stat.frames += 1;
                }
            }
            recv_one(&mut est.rtc, &est.sock, est.my_addr);
            est.rtc
                .handle_input(Input::Timeout(Instant::now()))
                .map_err(|e| e.to_string())?;
        }
        Ok(stat)
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
            (Ok(sent), Ok(stat)) if stat.frames == *sent && stat.keyframe => {
                println!(
                    "RESULT=OK DXGI→H.264→AEAD(PAKE-ключ)→СЕРВЕР→розшифр.→валідація: надіслано {sent}, прийнято {} ({} байт H.264), keyframe(SPS)=так",
                    stat.frames, stat.bytes
                );
            }
            (Ok(sent), Ok(stat)) => println!(
                "RESULT=FAIL sent={sent} received={} keyframe={}",
                stat.frames, stat.keyframe
            ),
            _ => println!("RESULT=FAIL host={hr:?} controller={cr:?}"),
        }
    }
}
