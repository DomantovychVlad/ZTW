//! IN-PROCESS LOOPBACK (крок 6б, автономно): DXGI-захоплення → H.264 → E2E(PAKE-ключ)
//! → ЖИВИЙ WebRTC SCTP datachannel (два str0m-піри в одному процесі через 127.0.0.1,
//! SDP/ICE обмінюються напряму — БЕЗ сигнального сервера) → пульт збирає чанки,
//! розшифровує й валідує H.264-потік.
//!
//! Доводить увесь медіа-шлях воркера Tier B без адміна/служби/сервера/другого пристрою.
//! Той самий host-патерн, що `e2e_media.rs`, лише джерело кадрів — `DxgiCapture` замість WGC.
//!
//! Windows-only. Запуск: `cargo run -p zortilwatch-core --example dxgi_loopback`

#[cfg(not(windows))]
fn main() {
    println!("dxgi_loopback: лише Windows (DXGI-захоплення + Media Foundation)");
}

#[cfg(windows)]
fn main() {
    imp::run();
}

#[cfg(windows)]
mod imp {
    use std::collections::VecDeque;
    use std::net::{SocketAddr, UdpSocket};
    use std::sync::mpsc::{channel, Receiver, Sender};
    use std::thread;
    use std::time::{Duration, Instant};

    use str0m::change::{SdpAnswer, SdpOffer};
    use str0m::channel::ChannelId;
    use str0m::net::{Protocol, Receive};
    use str0m::{Candidate, Event, Input, Output, Rtc};

    use zortilwatch_core::capture::dxgi::DxgiCapture;
    use zortilwatch_core::crypto::{StreamOpener, StreamSealer};
    use zortilwatch_core::encode::H264Encoder;
    use zortilwatch_core::media::{Chunker, Reassembler, DEFAULT_MAX_PAYLOAD};
    use zortilwatch_core::net::new_rtc;
    use zortilwatch_core::session::{Handshake, SessionMessage};

    const PASSWORD: &[u8] = b"one-time-connect-pw";
    const N_FRAMES: usize = 12;
    const MEDIA_LABEL: &[u8] = b"zortilwatch media h2c v1"; // напрям керований->пульт

    // SDP/ICE-обмін напряму між потоками (замість сигнального сервера): (sdp, candidate).
    type Sdp = (String, String);

    fn fingerprint(sdp: &str) -> String {
        sdp.lines()
            .find_map(|l| l.trim().strip_prefix("a=fingerprint:"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
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

    struct Established {
        rtc: Rtc,
        sock: UdpSocket,
        my_addr: SocketAddr,
        chan: ChannelId,
        key: [u8; 32],
    }

    /// Драйвити str0m + PAKE до підтвердження; повернути живий стан (канал відкритий, ключ є).
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

    // ── H.264 валідація (Annex-B) ──
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
    fn run_host(offer_tx: Sender<Sdp>, answer_rx: Receiver<Sdp>) -> Result<usize, String> {
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
        offer_tx
            .send((offer_sdp, cand.to_sdp_string()))
            .map_err(|e| e.to_string())?;

        let (answer_sdp, ctrl_cand) = answer_rx.recv().map_err(|e| e.to_string())?;
        let peer_fp = fingerprint(&answer_sdp);
        let ans = SdpAnswer::from_sdp_string(&answer_sdp).map_err(|e| e.to_string())?;
        rtc.sdp_api()
            .accept_answer(pending, ans)
            .map_err(|e| e.to_string())?;
        drain(&mut rtc, &sock, &mut chan, &mut inbox);
        rtc.add_remote_candidate(Candidate::from_sdp_string(&ctrl_cand).map_err(|e| e.to_string())?);
        drain(&mut rtc, &sock, &mut chan, &mut inbox);

        let mut est = drive_until_confirmed(rtc, sock, my_addr, own_fp, peer_fp)?;
        println!("HOST: сесію підтверджено ✓ — DXGI-захоплення, кодую і стрімлю {N_FRAMES} кадрів…");

        let mut cap = DxgiCapture::new().map_err(|e| e.to_string())?;
        let (cw, ch) = (cap.width(), cap.height());
        let mut enc =
            H264Encoder::new_scaled(cw, ch, cw / 2, ch / 2, 30, 4_000_000).map_err(|e| e.to_string())?;
        let mut chunker = Chunker::new(DEFAULT_MAX_PAYLOAD);
        let mut sealer = StreamSealer::new(&est.key, MEDIA_LABEL); // E2E поверх DTLS
        let mut queue: VecDeque<Vec<u8>> = VecDeque::new();
        let mut encoded = 0usize;
        let mut total_bytes = 0usize;
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
                match cap.next_frame(4) {
                    Ok(Some(f)) => {
                        let unit = enc.encode_bgra(&f.data).map_err(|e| e.to_string())?;
                        if !unit.is_empty() {
                            total_bytes += unit.len();
                            let sealed = sealer.seal(&unit); // [nonce|ciphertext+tag]
                            for c in chunker.chunk(&sealed) {
                                queue.push_back(c);
                            }
                            encoded += 1;
                        }
                    }
                    Ok(None) => {} // статичний кадр — норма
                    Err(e) => {
                        eprintln!("HOST: пересоздаю захоплення після: {e}");
                        cap = DxgiCapture::new().map_err(|e| e.to_string())?;
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

        println!("HOST: надіслано {encoded} кадрів H.264 ({cw}x{ch}, {total_bytes} байт)");
        Ok(encoded)
    }

    #[derive(Debug)]
    struct MediaStat {
        frames: usize,
        bytes: usize,
        keyframe: bool,
    }

    // ── CONTROLLER = answerer: прийом + розшифр. + валідація ──
    fn run_controller(offer_rx: Receiver<Sdp>, answer_tx: Sender<Sdp>) -> Result<MediaStat, String> {
        let sock = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let my_addr = sock.local_addr().map_err(|e| e.to_string())?;
        let mut rtc = new_rtc(Instant::now());
        let cand = Candidate::host(my_addr, "udp").map_err(|e| e.to_string())?;
        rtc.add_local_candidate(cand.clone());
        let mut chan = None;
        let mut inbox = Vec::new();
        drain(&mut rtc, &sock, &mut chan, &mut inbox);

        let (offer_sdp, host_cand) = offer_rx.recv().map_err(|e| e.to_string())?;
        let peer_fp = fingerprint(&offer_sdp);
        let offer = SdpOffer::from_sdp_string(&offer_sdp).map_err(|e| e.to_string())?;
        let answer = rtc.sdp_api().accept_offer(offer).map_err(|e| e.to_string())?;
        drain(&mut rtc, &sock, &mut chan, &mut inbox);
        let answer_sdp = answer.to_sdp_string();
        let own_fp = fingerprint(&answer_sdp);
        answer_tx
            .send((answer_sdp, cand.to_sdp_string()))
            .map_err(|e| e.to_string())?;
        rtc.add_remote_candidate(Candidate::from_sdp_string(&host_cand).map_err(|e| e.to_string())?);
        drain(&mut rtc, &sock, &mut chan, &mut inbox);

        let mut est = drive_until_confirmed(rtc, sock, my_addr, own_fp, peer_fp)?;
        println!("CONTROLLER: сесію підтверджено ✓ — приймаю H.264-потік…");

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
                        stat.keyframe = true; // SPS
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
        // Два канали SDP/ICE напряму між потоками (без сигнального сервера).
        let (offer_tx, offer_rx) = channel::<Sdp>();
        let (answer_tx, answer_rx) = channel::<Sdp>();

        let host = thread::spawn(move || run_host(offer_tx, answer_rx));
        let ctrl = thread::spawn(move || run_controller(offer_rx, answer_tx));

        let hr = host.join().expect("host panicked");
        let cr = ctrl.join().expect("controller panicked");

        match (&hr, &cr) {
            (Ok(sent), Ok(stat)) if stat.frames == *sent && stat.keyframe => {
                println!(
                    "RESULT=OK DXGI→H.264→AEAD(PAKE-ключ)→WebRTC→розшифр.→валідація: надіслано {sent}, прийнято {} ({} байт H.264), keyframe(SPS)=так",
                    stat.frames, stat.bytes
                );
            }
            (Ok(sent), Ok(stat)) => {
                eprintln!(
                    "RESULT=FAIL sent={sent} received={} keyframe={}",
                    stat.frames, stat.keyframe
                );
                std::process::exit(2);
            }
            _ => {
                eprintln!("RESULT=FAIL host={hr:?} controller={cr:?}");
                std::process::exit(2);
            }
        }
    }
}
