//! Перевірка ОРКЕСТРАЦІЇ (core::connection) наскрізно через ПУБЛІЧНЕ API:
//! Managed::serve (постійний host-цикл) + Controller::connect. Сценарій:
//!   1) сесія за ПОСТІЙНИМ паролем (15 кадрів H.264 + ввід + проба busy);
//!   2) присутність online МІЖ сесіями (без блимання — один сигналінг-WS);
//!   3) host і controller НА ОДНОМУ ID співіснують (реєстрація пульта не вибиває host);
//!   4) сесія за ОДНОРАЗОВИМ кодом (passwordKind=one_time) + ротація коду після сесії.
//!
//! Windows-only (захоплення/кодек/інжекція). Сервер сигналінгу має бути піднятий. Запуск:
//!   cargo run -p zortilwatch-core --example connection_smoke

#[cfg(not(windows))]
fn main() {
    println!("connection_smoke: лише Windows");
}

#[cfg(windows)]
fn main() {
    imp::run();
}

#[cfg(windows)]
mod imp {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc};
    use std::thread;
    use std::time::{Duration, Instant};

    use serde::Deserialize;
    use zortilwatch_core::connection::{Controller, HostEvent, HostOptions, Managed};
    use zortilwatch_core::input::{cursor_pos, screen_size, InputEvent};
    use zortilwatch_core::signal::{ClientMsg, ServerMsg, SignalClient};

    const PW: &[u8] = b"one-time-connect-pw";
    const WANT_FRAMES: usize = 15;

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

    struct SessionStats {
        frames: usize,
        bytes: usize,
        keyframe: bool,
        sent_input: usize,
        /// (host online, код відповіді на паралельний connect_request) — лише сесія 1.
        probe: Option<(bool, String)>,
        /// Кількість моніторів із контрольного повідомлення сесії (JSON по медіа-тракту).
        monitors: usize,
        /// Keyframe ПІСЛЯ перемикання якості = кодек перестворено без перепідключення.
        kf_after_switch: bool,
        /// Файли крізь сесію: download (host→пульт) і upload (пульт→host) звірені байт-у-байт.
        file_down_ok: bool,
        file_up_ok: bool,
        /// Буфер обміну пульт→host (true і якщо пропущено: нетекстовий вміст у користувача).
        clip_ok: bool,
    }

    fn ws_url(base: &str) -> String {
        let b = base
            .replace("https://", "wss://")
            .replace("http://", "ws://");
        format!("{}/signal", b.trim_end_matches('/'))
    }

    /// Чи host online за list_presence; `with_connect` — додатково спробувати
    /// connect_request і повернути код помилки (під час сесії очікуємо forbidden=busy).
    /// БЕЗ with_connect — лише читання присутності (між сесіями запит почав би сесію).
    fn presence_probe(
        base: &str,
        dev: &Dev,
        host_id: &str,
        with_connect: bool,
    ) -> Result<(bool, String), String> {
        let mut sc = SignalClient::connect(&ws_url(base)).map_err(|e| e.to_string())?;
        sc.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        sc.register(&dev.id, &dev.secret, "controller")
            .map_err(|e| e.to_string())?;
        sc.send(&ClientMsg::list_presence(vec![host_id.to_string()]))
            .map_err(|e| e.to_string())?;
        let online = loop {
            if let ServerMsg::PresenceState { entries, .. } =
                sc.recv().map_err(|e| e.to_string())?
            {
                break entries
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(|e| e.get("online"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
            }
        };
        if !with_connect {
            return Ok((online, String::new()));
        }
        sc.send(&ClientMsg::connect_request(host_id))
            .map_err(|e| e.to_string())?;
        let code = loop {
            if let ServerMsg::ConnectErr { code, .. } = sc.recv().map_err(|e| e.to_string())? {
                break code;
            }
        };
        Ok((online, code))
    }

    /// Розділення ролей (Етап 4/одна машина — дві ролі): реєструємо CONTROLLER-роль
    /// ІЗ ТИМ САМИМ ID, що в активного host. До фіксу це ВИБИВАЛО host-присутність.
    /// Повертає (online під час співіснування, online після відпадання controller-ролі).
    fn coexist_probe(base: &str, host_dev: &Dev, ctrl_dev: &Dev) -> Result<(bool, bool), String> {
        let mut same_id = SignalClient::connect(&ws_url(base)).map_err(|e| e.to_string())?;
        same_id
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        same_id
            .register(&host_dev.id, &host_dev.secret, "controller")
            .map_err(|e| e.to_string())?;
        let (during, _) = presence_probe(base, ctrl_dev, &host_dev.id, false)?;
        drop(same_id); // controller-роль відпала — host-слот має лишитись
        thread::sleep(Duration::from_millis(300));
        let (after, _) = presence_probe(base, ctrl_dev, &host_dev.id, false)?;
        Ok((during, after))
    }

    fn is_annexb(f: &[u8]) -> bool {
        f.starts_with(&[0, 0, 0, 1]) || f.starts_with(&[0, 0, 1])
    }
    fn has_nal(f: &[u8], t: u8) -> bool {
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

    /// Одна сесія пульта: connect → кадри + ворушіння курсором → (опц. проба) → close.
    ///
    /// WGC подієвий: кадри йдуть лише при ЗМІНАХ екрана. Самодостатнє джерело змін —
    /// ворушіння курсором (±2px довкола поточної позиції, з відновленням) крізь
    /// СПРАВЖНІЙ тракт вводу: пульт → шифр → канал → інжекція → зміна екрана → кадр.
    #[allow(clippy::too_many_arguments)] // тест-сценарій: прапори перевірок
    fn run_session(
        base: &str,
        ctrl_dev: &Dev,
        host_id: &str,
        password: &[u8],
        kind: &str,
        with_probe: bool,
        quality_switch: bool,
        // Тека для файлових перевірок (download/upload/clipboard крізь сесію).
        file_dir: Option<&std::path::Path>,
    ) -> Result<SessionStats, String> {
        let ctrl = Controller::connect(
            base,
            &ctrl_dev.id,
            &ctrl_dev.secret,
            password,
            host_id,
            kind,
        )?;

        let (sw, sh) = screen_size();
        let orig = cursor_pos();
        let (nx, ny) = (
            orig.0 as f32 / (sw.saturating_sub(1)) as f32,
            orig.1 as f32 / (sh.saturating_sub(1)) as f32,
        );
        let step = 2.0 / sw as f32;

        let mut st = SessionStats {
            frames: 0,
            bytes: 0,
            keyframe: false,
            sent_input: 0,
            probe: None,
            monitors: 0,
            kf_after_switch: false,
            file_down_ok: file_dir.is_none(),
            file_up_ok: file_dir.is_none(),
            clip_ok: file_dir.is_none(),
        };
        // Файлова перевірка: src.bin (host-сторона; та сама машина) → download id=101;
        // потім upload id=102 у dst.bin; вкінці буфер обміну (із відновленням).
        const SRC_LEN: usize = 1_500_000;
        let src_bytes: Vec<u8> = (0..SRC_LEN).map(|i| (i * 31 % 251) as u8).collect();
        let (src_path, dst_path) = if let Some(dir) = file_dir {
            let s = dir.join("src.bin");
            std::fs::write(&s, &src_bytes).map_err(|e| e.to_string())?;
            (Some(s), Some(dir.join("dst.bin")))
        } else {
            (None, None)
        };
        let mut down_buf: Vec<u8> = Vec::new();
        let mut fs_phase = 0u8; // 0=ще ні, 1=download, 2=upload, 3=clipboard, 4=готово
        let mut up_acked = false;
        let clip_test = format!("zw-clip-{}", std::process::id());
        let mut clip_old: Option<String> = None;
        let mut clip_sent_at: Option<Instant> = None;
        // Полінг буфера РІДКО: часте OpenClipboard з тесту блокує set_text хоста (гонка).
        let mut clip_check_at = Instant::now();

        let mut switched = false;
        let mut last_wiggle = Instant::now();
        let deadline =
            Instant::now() + Duration::from_secs(if file_dir.is_some() { 50 } else { 25 });
        while (st.frames < WANT_FRAMES || fs_phase != 4 && file_dir.is_some())
            && Instant::now() < deadline
        {
            if let Some(f) = ctrl.next_frame() {
                if f.first() == Some(&0xF7) {
                    // Файловий кадр download-у.
                    if let Some((101, _off, data)) = zortilwatch_core::files::parse_file_frame(&f) {
                        down_buf.extend_from_slice(data);
                    }
                } else if f.first() == Some(&b'{') {
                    // Контрольні повідомлення сесії (монітори/файли).
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&f) {
                        if let Some(m) = v.get("monitors").and_then(|m| m.as_array()) {
                            st.monitors = m.len();
                        }
                        if v["fsProgress"]["id"].as_u64() == Some(102) {
                            up_acked = true;
                        }
                        if let Some(id) = v["fsDone"]["id"].as_u64() {
                            if id == 101 && fs_phase == 1 {
                                st.file_down_ok = down_buf == src_bytes;
                                // → upload
                                ctrl.send_input(InputEvent::FsUploadStart {
                                    id: 102,
                                    path: dst_path.as_ref().unwrap().to_string_lossy().into(),
                                    size: SRC_LEN as u64,
                                });
                                fs_phase = 2;
                            } else if id == 102 && fs_phase == 2 {
                                st.file_up_ok = std::fs::read(dst_path.as_ref().unwrap())
                                    .map(|b| b == src_bytes)
                                    .unwrap_or(false);
                                // → буфер (лише якщо поточний вміст текстовий — відновимо)
                                clip_old = zortilwatch_core::clipboard::get_text();
                                if clip_old.is_some() {
                                    ctrl.send_input(InputEvent::Clipboard {
                                        text: clip_test.clone(),
                                    });
                                    clip_sent_at = Some(Instant::now());
                                    fs_phase = 3;
                                } else {
                                    println!("CLIP: пропущено (нетекстовий вміст буфера)");
                                    st.clip_ok = true;
                                    fs_phase = 4;
                                }
                            }
                        }
                    }
                } else if is_annexb(&f) {
                    st.frames += 1;
                    st.bytes += f.len();
                    if has_nal(&f, 7) {
                        st.keyframe = true;
                        if switched {
                            st.kf_after_switch = true;
                        }
                    }
                }
            } else {
                thread::sleep(Duration::from_millis(3));
            }
            // Зміна якості ПОСЕРЕД сесії (без перепідключення): host має перестворити
            // кодек (половинна роздільність, нижчий бітрейт) і видати НОВИЙ keyframe.
            if quality_switch && !switched && st.frames >= 5 {
                switched = true;
                ctrl.send_input(InputEvent::Quality {
                    fps: 30,
                    bitrate: 1_500_000,
                    scale: 2,
                });
            }
            // Файлова фаза: стартувати download після перших кадрів.
            if fs_phase == 0 && st.frames >= 3 {
                if let Some(s) = &src_path {
                    ctrl.send_input(InputEvent::FsDownload {
                        id: 101,
                        path: s.to_string_lossy().into(),
                        offset: 0,
                    });
                    fs_phase = 1;
                }
            }
            // Upload: по стартовому ack злити всі чанки (вих. черга ядра має backpressure).
            if fs_phase == 2 && up_acked {
                up_acked = false;
                let mut off = 0usize;
                while off < SRC_LEN {
                    let end = (off + zortilwatch_core::files::FILE_CHUNK).min(SRC_LEN);
                    ctrl.send_raw(zortilwatch_core::files::encode_file_frame(
                        102,
                        off as u64,
                        &src_bytes[off..end],
                    ));
                    off = end;
                }
            }
            // Буфер: host мав записати текст у системний буфер цієї ж машини.
            if fs_phase == 3 && clip_check_at.elapsed() >= Duration::from_millis(300) {
                clip_check_at = Instant::now();
                if zortilwatch_core::clipboard::get_text().as_deref() == Some(clip_test.as_str()) {
                    st.clip_ok = true;
                    if let Some(old) = clip_old.take() {
                        let _ = zortilwatch_core::clipboard::set_text(&old); // відновити
                    }
                    fs_phase = 4;
                } else if clip_sent_at
                    .map(|t| t.elapsed().as_secs() > 8)
                    .unwrap_or(false)
                {
                    fs_phase = 4; // не дочекались — clip_ok лишиться false
                }
            }
            if last_wiggle.elapsed() >= Duration::from_millis(40) {
                last_wiggle = Instant::now();
                let dx = if st.sent_input.is_multiple_of(2) {
                    step
                } else {
                    0.0
                };
                ctrl.send_input(InputEvent::MouseMove { x: nx + dx, y: ny });
                st.sent_input += 1;
            }
            // Сесія точно активна (кадри йдуть) — перевірити присутність host + busy.
            if with_probe && st.frames >= 1 && st.probe.is_none() {
                st.probe = Some(
                    presence_probe(base, ctrl_dev, host_id, true)
                        .unwrap_or_else(|e| (false, format!("probe: {e}"))),
                );
            }
        }
        // Повернути курсор у вихідну позицію (недеструктивний прогін).
        ctrl.send_input(InputEvent::MouseMove { x: nx, y: ny });
        thread::sleep(Duration::from_millis(150));
        ctrl.close();
        Ok(st)
    }

    pub fn run() {
        let path =
            std::env::var("SIGNAL_CREDS").unwrap_or_else(|_| ".scratch/e2e-creds.json".into());
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let raw = raw.trim_start_matches('\u{feff}');
        let creds: Creds = serde_json::from_str(raw).expect("parse creds");

        let base = creds.base.clone();
        let host_id = creds.host.id.clone();

        // Керований: ПОСТІЙНИЙ host-цикл (один WS на всі сесії), живе до сигналу stop.
        // Одноразові коди прилітають у канал (показ у UI в реальному застосунку).
        let stop = Arc::new(AtomicBool::new(false));
        let confirm = Arc::new(AtomicBool::new(false)); // атендантний режим (живий тумблер)
        let auto_allow = Arc::new(AtomicBool::new(true)); // «людина» в смоуку: дозволити чи ні
        let (code_tx, code_rx) = mpsc::channel::<String>();
        let (decide_tx, decide_rx) = mpsc::channel::<(u64, bool)>();
        let host = {
            let (base, hid, hsec, stop_h) = (
                base.clone(),
                creds.host.id.clone(),
                creds.host.secret.clone(),
                stop.clone(),
            );
            let (confirm_h, allow_h) = (confirm.clone(), auto_allow.clone());
            thread::spawn(move || {
                Managed::serve(
                    &base,
                    &hid,
                    &hsec,
                    HostOptions {
                        permanent_password: Some(PW.to_vec()),
                        rotate: Arc::new(AtomicBool::new(false)),
                        stop: stop_h,
                        confirm_incoming: confirm_h,
                        decisions: decide_rx,
                        lock_on_end: Arc::new(AtomicBool::new(false)),
                    },
                    move |ev| match ev {
                        HostEvent::OneTime(code) => {
                            let _ = code_tx.send(code);
                        }
                        // «Людина за пристроєм»: миттєве рішення за прапором auto_allow.
                        HostEvent::Confirm { request_id, .. } => {
                            let _ = decide_tx.send((request_id, allow_h.load(Ordering::Relaxed)));
                        }
                    },
                )
            })
        };
        let code1 = code_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_default();
        println!("OTP: початковий одноразовий код = {code1}");

        // Дочекатися реєстрації host (до 10с — перший конект свіжозібраного бінарника
        // буває повільним), а не покладатися на фіксований сон.
        let mut pre_online = false;
        for _ in 0..20 {
            thread::sleep(Duration::from_millis(500));
            if matches!(
                presence_probe(&base, &creds.controller, &host_id, false),
                Ok((true, _))
            ) {
                pre_online = true;
                break;
            }
        }
        println!("PRE: host online до сесії 1 = {pre_online}");

        // ── Сесія 1: ПОСТІЙНИЙ пароль (з пробою присутності/busy під час сесії) ──
        let fdir = std::env::temp_dir().join(format!("zw-smoke-files-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&fdir);
        let s1 = match run_session(
            &base,
            &creds.controller,
            &host_id,
            PW,
            "permanent",
            true,
            true,
            Some(&fdir),
        ) {
            Ok(s) => s,
            Err(e) => {
                stop.store(true, Ordering::Relaxed);
                let _ = host.join();
                println!("RESULT=FAIL session1 (permanent) connect: {e}");
                return;
            }
        };
        println!(
            "SESSION1 (permanent): {} кадрів H.264 ({} байт), keyframe={}, {} подій вводу; моніторів={}, keyframe після зміни якості={}",
            s1.frames, s1.bytes, s1.keyframe, s1.sent_input, s1.monitors, s1.kf_after_switch
        );
        println!(
            "FILES: download(1.5МБ, байт-у-байт)={}, upload={}, clipboard={}",
            s1.file_down_ok, s1.file_up_ok, s1.clip_ok
        );
        let _ = std::fs::remove_dir_all(&fdir);

        // ── МІЖ сесіями: присутність має ЛИШАТИСЬ online (тут раніше було блимання) ──
        thread::sleep(Duration::from_millis(300));
        let (between_online, _) = presence_probe(&base, &creds.controller, &host_id, false)
            .unwrap_or_else(|e| {
                eprintln!("between-probe: {e}");
                (false, String::new())
            });
        println!("BETWEEN: host online між сесіями = {between_online}");

        // ── Ролі на одному ID: controller-реєстрація НЕ вибиває host ──
        let (coexist_during, coexist_after) = coexist_probe(&base, &creds.host, &creds.controller)
            .unwrap_or_else(|e| {
                eprintln!("coexist-probe: {e}");
                (false, false)
            });
        println!("COEXIST: host online при controller-реєстрації того ж ID = {coexist_during}; після її відпадання = {coexist_after}");

        // ── Сесія 2: ОДНОРАЗОВИЙ код ──
        let s2 = match run_session(
            &base,
            &creds.controller,
            &host_id,
            code1.as_bytes(),
            "one_time",
            false,
            false,
            None,
        ) {
            Ok(s) => s,
            Err(e) => {
                stop.store(true, Ordering::Relaxed);
                let _ = host.join();
                println!("RESULT=FAIL session2 (one_time) connect: {e}");
                return;
            }
        };
        println!(
            "SESSION2 (one_time): {} кадрів H.264 ({} байт), keyframe={}",
            s2.frames, s2.bytes, s2.keyframe
        );

        // Код «згорів» — ядро має видати НОВИЙ.
        let code2 = code_rx
            .recv_timeout(Duration::from_secs(10))
            .unwrap_or_default();
        let rotated = !code2.is_empty() && code2 != code1;
        println!("OTP: код після сесії = {code2} (ротовано={rotated})");

        // ── Атендантний режим: «людина» дозволяє → сесія йде; відмовляє → forbidden ──
        confirm.store(true, Ordering::Relaxed);
        auto_allow.store(true, Ordering::Relaxed);
        let attended_ok = match run_session(
            &base,
            &creds.controller,
            &host_id,
            PW,
            "permanent",
            false,
            false,
            None,
        ) {
            Ok(s) => {
                println!(
                    "ATTENDED-ALLOW: {} кадрів H.264, keyframe={}",
                    s.frames, s.keyframe
                );
                s.frames >= WANT_FRAMES && s.keyframe
            }
            Err(e) => {
                println!("ATTENDED-ALLOW: FAIL {e}");
                false
            }
        };
        auto_allow.store(false, Ordering::Relaxed);
        let deny_err = match run_session(
            &base,
            &creds.controller,
            &host_id,
            PW,
            "permanent",
            false,
            false,
            None,
        ) {
            Ok(_) => "UNEXPECTED-OK".to_string(),
            Err(e) => e,
        };
        let deny_ok = deny_err.contains("forbidden");
        println!("ATTENDED-DENY: пульт дістав «{deny_err}» (очікувано forbidden)");
        confirm.store(false, Ordering::Relaxed);

        stop.store(true, Ordering::Relaxed);
        let _ = host.join(); // serve виходить ≤2с після stop (такт читання)

        let (online1, reject_code) = s1.probe.unwrap_or((false, "no-probe".into()));
        let ok = pre_online
            && s1.frames >= WANT_FRAMES
            && s1.keyframe
            && online1
            && reject_code == "forbidden"
            && between_online
            && coexist_during
            && coexist_after
            && s2.frames >= WANT_FRAMES
            && s2.keyframe
            && rotated
            && attended_ok
            && deny_ok
            && s1.monitors >= 1
            && s1.kf_after_switch
            && s1.file_down_ok
            && s1.file_up_ok
            && s1.clip_ok;
        if ok {
            println!("PRESENCE: online до/під час/між сесіями; busy → forbidden; ролі співіснують на одному ID");
            println!("RESULT=OK core::connection — permanent + one_time + attended (allow/deny), ротація коду, розділені ролі");
        } else {
            println!(
                "RESULT=FAIL pre={pre_online} s1={}/{} kf1={} online1={online1} reject={reject_code} between={between_online} coexist={coexist_during}/{coexist_after} s2={}/{} kf2={} rotated={rotated} attended={attended_ok} deny={deny_ok}",
                s1.frames, WANT_FRAMES, s1.keyframe, s2.frames, WANT_FRAMES, s2.keyframe
            );
        }
    }
}
