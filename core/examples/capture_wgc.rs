//! PoC безперервного захоплення через WGC. Бере до 10 кадрів основного монітора,
//! друкує розміри й приблизний FPS. Запуск:
//!   cargo run -p zortilwatch-core --example capture_wgc

#[cfg(windows)]
fn main() {
    use std::time::{Duration, Instant};
    use zortilwatch_core::capture;

    let (control, rx) = match capture::start_primary() {
        Ok(v) => v,
        Err(e) => {
            println!("RESULT=START_FAILED: {e}");
            return;
        }
    };

    let start = Instant::now();
    let mut count = 0u32;
    while count < 10 {
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(frame) => {
                count += 1;
                println!(
                    "frame #{count}: {}x{}, {} bytes (expected {})",
                    frame.width,
                    frame.height,
                    frame.data.len(),
                    frame.expected_len()
                );
            }
            Err(_) => {
                println!("(no frame within 5s — екран статичний? WGC подієвий)");
                break;
            }
        }
    }

    let secs = start.elapsed().as_secs_f64().max(0.001);
    if count > 0 {
        println!(
            "RESULT=OK captured {count} frames in {secs:.2}s (~{:.1} fps)",
            count as f64 / secs
        );
    } else {
        println!("RESULT=NO_FRAMES");
    }

    control.stop();
}

#[cfg(not(windows))]
fn main() {
    println!("WGC-захоплення доступне лише на Windows");
}
