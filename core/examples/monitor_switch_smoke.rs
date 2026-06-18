//! Наскрізна перевірка ПЕРЕМИКАННЯ моніторів (PRD 5.6) через реальну сесію:
//! Managed::serve + Controller::connect → отримати список моніторів → перемкнути на
//! інший → переконатися, що host підтвердив active=index і видав новий keyframe.
//! Потребує 2+ моніторів і піднятого сервера. Windows-only.
//!   cargo run -p zortilwatch-core --example monitor_switch_smoke

#[cfg(not(windows))]
fn main() {
    println!("monitor_switch_smoke: лише Windows");
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

    const PW: &[u8] = b"one-time-connect-pw";

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

    fn has_keyframe(f: &[u8]) -> bool {
        // SPS (NAL 7) у Annex-B = ознака keyframe.
        let mut i = 0usize;
        while i + 3 < f.len() {
            if f[i] == 0 && f[i + 1] == 0 && f[i + 2] == 1 {
                if f[i + 3] & 0x1f == 7 {
                    return true;
                }
                i += 3;
            } else {
                i += 1;
            }
        }
        false
    }

    pub fn run() {
        let path =
            std::env::var("SIGNAL_CREDS").unwrap_or_else(|_| ".scratch/e2e-creds.json".into());
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let creds: Creds =
            serde_json::from_str(raw.trim_start_matches('\u{feff}')).expect("parse creds");
        let base = creds.base.clone();
        let host_id = creds.host.id.clone();

        let stop = Arc::new(AtomicBool::new(false));
        let (code_tx, _code_rx) = mpsc::channel::<String>();
        let (_decide_tx, decide_rx) = mpsc::channel::<(u64, bool)>();
        let host = {
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
                    move |ev| {
                        if let HostEvent::OneTime(c) = ev {
                            let _ = code_tx.send(c);
                        }
                    },
                )
            })
        };
        thread::sleep(Duration::from_millis(600));

        let ctrl = match Controller::connect(
            &base,
            &creds.controller.id,
            &creds.controller.secret,
            PW,
            &host_id,
            "permanent",
        ) {
            Ok(c) => c,
            Err(e) => {
                stop.store(true, Ordering::Relaxed);
                let _ = host.join();
                println!("RESULT=FAIL connect: {e}");
                return;
            }
        };

        // Невеликий рух курсором, щоб WGC видавав кадри (подієвий захват).
        let (sw, sh) = screen_size();
        let o = cursor_pos();
        let (nx, ny) = (o.0 as f32 / sw as f32, o.1 as f32 / sh as f32);

        let mut monitors = 0usize;
        let mut target = 0u32;
        let mut switch_sent = false;
        let mut active_after: Option<u32> = None;
        let mut kf_after_switch = false;
        let mut last_wiggle = Instant::now();
        let mut switch_at: Option<Instant> = None;
        let deadline = Instant::now() + Duration::from_secs(35);

        while Instant::now() < deadline {
            if let Some(f) = ctrl.next_frame() {
                if f.first() == Some(&b'{') {
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&f) {
                        if let Some(arr) = v.get("monitors").and_then(|m| m.as_array()) {
                            monitors = arr.len();
                            let active =
                                v.get("active").and_then(|a| a.as_u64()).unwrap_or(0) as u32;
                            if !switch_sent && monitors >= 2 {
                                // Перемкнути на наступний монітор (не активний).
                                target = (active + 1) % monitors as u32;
                                println!("MONITORS: {monitors}; активний={active} → перемикаю на {target}");
                                ctrl.send_input(InputEvent::Monitor { index: target });
                                switch_sent = true;
                                switch_at = Some(Instant::now());
                            } else if switch_sent && active == target {
                                active_after = Some(active);
                            }
                        }
                    }
                } else if switch_sent && has_keyframe(&f) {
                    // keyframe ПІСЛЯ запиту на перемикання = новий кодек на новому моніторі.
                    if switch_at
                        .map(|t| t.elapsed() > Duration::from_millis(50))
                        .unwrap_or(false)
                    {
                        kf_after_switch = true;
                    }
                }
            } else {
                thread::sleep(Duration::from_millis(3));
            }
            if last_wiggle.elapsed() >= Duration::from_millis(50) {
                last_wiggle = Instant::now();
                ctrl.send_input(InputEvent::MouseMove {
                    x: nx + 0.002,
                    y: ny,
                });
                ctrl.send_input(InputEvent::MouseMove { x: nx, y: ny });
            }
            if active_after.is_some() && kf_after_switch {
                break;
            }
        }

        ctrl.close();
        stop.store(true, Ordering::Relaxed);
        let _ = host.join();

        let ok = monitors >= 2 && active_after == Some(target) && kf_after_switch;
        println!(
            "SWITCH: моніторів={monitors}, підтверджено active={:?}, keyframe після перемикання={kf_after_switch}",
            active_after
        );
        println!(
            "RESULT={}",
            if ok {
                "OK перемикання моніторів наскрізно"
            } else {
                "FAIL"
            }
        );
    }
}
