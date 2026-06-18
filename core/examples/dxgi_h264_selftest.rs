//! Self-test (крок 6а Tier B): DXGI-захоплення поточного робочого стола → H.264 → файл.
//!
//! Працює в звичайній сесії користувача на `Default` БЕЗ адміна/служби/secure-desktop —
//! доводить, що DXGI-кадри годують наявний MF-енкодер і дають валідний H.264-потік
//! (той самий шлях, що піде у воркер Tier B). Артефакт — `.scratch/dxgi_selftest.h264`.
//!
//! Запуск: `cargo run -p zortilwatch-core --example dxgi_h264_selftest`

#[cfg(not(windows))]
fn main() {
    eprintln!("лише Windows");
}

#[cfg(windows)]
fn main() {
    use std::io::Write;
    use std::time::{Duration, Instant};
    use zortilwatch_core::capture::dxgi::DxgiCapture;
    use zortilwatch_core::encode::H264Encoder;

    let mut cap = match DxgiCapture::new() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("DXGI-захоплення НЕ створено: {e}");
            std::process::exit(1);
        }
    };
    let (w, h) = (cap.width(), cap.height());
    println!("DXGI-захоплення: {w}x{h}");

    // Половинна роздільність (як у реального стрімінгу), 30 fps, ~6 Мбіт/с.
    let (out_w, out_h) = (w / 2, h / 2);
    let mut enc = match H264Encoder::new_scaled(w, h, out_w, out_h, 30, 6_000_000) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("енкодер НЕ створено: {e}");
            std::process::exit(1);
        }
    };
    println!("H264-енкодер: вхід {w}x{h} → потік {}x{}", out_w & !1, out_h & !1);

    let out_dir = std::path::Path::new(".scratch");
    let _ = std::fs::create_dir_all(out_dir);
    let out_path = out_dir.join("dxgi_selftest.h264");
    let mut file = std::fs::File::create(&out_path).expect("створити вихідний файл");

    let target_frames = 60u32;
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut bitstream: Vec<u8> = Vec::new();
    let mut frames = 0u32;
    let mut timeouts = 0u32;
    let mut recreated = 0u32;
    let mut last_tick = Instant::now();

    while frames < target_frames && Instant::now() < deadline {
        match cap.next_frame(200) {
            Ok(Some(frame)) => {
                debug_assert_eq!(frame.data.len(), frame.expected_len());
                match enc.encode_bgra(&frame.data) {
                    Ok(h264) => {
                        if !h264.is_empty() {
                            file.write_all(&h264).expect("запис H264");
                            bitstream.extend_from_slice(&h264);
                        }
                    }
                    Err(e) => eprintln!("encode помилка: {e}"),
                }
                frames += 1;
            }
            Ok(None) => timeouts += 1, // статичний екран — норма
            Err(e) => {
                eprintln!("пересоздаю захоплення після: {e}");
                cap = match DxgiCapture::new() {
                    Ok(c) => {
                        recreated += 1;
                        c
                    }
                    Err(e2) => {
                        eprintln!("пересоздання не вдалось: {e2}");
                        break;
                    }
                };
            }
        }
        if last_tick.elapsed() >= Duration::from_secs(1) {
            println!("  …{frames} кадрів, {} КБ H264", bitstream.len() / 1024);
            last_tick = Instant::now();
        }
    }

    // Flush буферизованих кадрів.
    if let Ok(tail) = enc.drain() {
        if !tail.is_empty() {
            file.write_all(&tail).expect("запис drain");
            bitstream.extend_from_slice(&tail);
        }
    }

    // Розбір NAL (Annex-B) — доказ валідного H.264.
    let (mut sps, mut pps, mut idr, mut non_idr, mut other) = (0u32, 0u32, 0u32, 0u32, 0u32);
    let b = &bitstream;
    let mut i = 0usize;
    while i + 3 < b.len() {
        // 3-байтовий старт-код 00 00 01 (4-байтовий 00 00 00 01 ловиться як його хвіст).
        if b[i] == 0 && b[i + 1] == 0 && b[i + 2] == 1 {
            let nal_type = b[i + 3] & 0x1F;
            match nal_type {
                7 => sps += 1,
                8 => pps += 1,
                5 => idr += 1,
                1 => non_idr += 1,
                _ => other += 1,
            }
            i += 3;
        } else {
            i += 1;
        }
    }

    println!("\n── підсумок ──");
    println!("кадрів захоплено/закодовано: {frames} (таймаутів {timeouts}, пересоздань {recreated})");
    println!("H264 усього: {} байт ({} КБ)", bitstream.len(), bitstream.len() / 1024);
    println!("NAL: SPS={sps} PPS={pps} IDR={idr} P={non_idr} інших={other}");
    println!("файл: {}", out_path.display());

    let valid = frames > 0 && !bitstream.is_empty() && sps >= 1 && pps >= 1 && idr >= 1;
    if valid {
        println!("РЕЗУЛЬТАТ=OK: DXGI-кадри → валідний H.264 (є SPS+PPS+IDR)");
    } else {
        eprintln!("РЕЗУЛЬТАТ=FAIL: потік неповний (немає кадрів або SPS/PPS/IDR)");
        std::process::exit(2);
    }
}
