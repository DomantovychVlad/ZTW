//! PoC кодування: синтетичний BGRA-градієнт -> H.264 через Media Foundation.
//! Запуск: cargo run -p zortilwatch-core --example encode_smoke

#[cfg(windows)]
fn main() {
    use zortilwatch_core::encode::H264Encoder;

    const W: u32 = 1920;
    const H: u32 = 1080;
    const FPS: u32 = 30;

    let mut enc = match H264Encoder::new(W, H, FPS, 8_000_000) {
        Ok(e) => e,
        Err(e) => {
            println!("RESULT=NEW_FAILED: {e}");
            return;
        }
    };

    // Синтетичний BGRA-градієнт (реальна картинка кодується змістовно).
    let mut frame = vec![0u8; (W * H * 4) as usize];
    for y in 0..H {
        for x in 0..W {
            let i = ((y * W + x) * 4) as usize;
            frame[i] = (x % 256) as u8; // B
            frame[i + 1] = (y % 256) as u8; // G
            frame[i + 2] = ((x + y) % 256) as u8; // R
            frame[i + 3] = 255; // A
        }
    }

    let mut total = 0usize;
    for n in 0..6u32 {
        // Трохи змінюємо кадр, щоб P-кадри мали вміст.
        let idx = (n * 4) as usize;
        frame[idx] = frame[idx].wrapping_add(17);
        match enc.encode_bgra(&frame) {
            Ok(h264) => {
                total += h264.len();
                let annexb = h264.len() >= 4 && h264[0] == 0 && h264[1] == 0 && h264[3] == 1;
                println!(
                    "frame #{}: {} bytes H.264, annexb_start={annexb}",
                    n + 1,
                    h264.len()
                );
            }
            Err(e) => {
                println!("RESULT=ENCODE_FAILED: {e}");
                return;
            }
        }
    }

    match enc.drain() {
        Ok(rest) => {
            let annexb = rest.len() >= 4 && rest[0] == 0 && rest[1] == 0 && rest[3] == 1;
            println!("drain: {} bytes H.264, annexb_start={annexb}", rest.len());
            total += rest.len();
        }
        Err(e) => println!("drain failed: {e}"),
    }

    if total > 0 {
        println!("RESULT=OK total {total} bytes H.264");
    } else {
        println!("RESULT=NO_OUTPUT");
    }
}

#[cfg(not(windows))]
fn main() {
    println!("Кодування Media Foundation доступне лише на Windows");
}
