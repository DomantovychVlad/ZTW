//! Перевірка DXGI-джерела `capture::dxgi::start_primary_dxgi` (фоновий потік +
//! перемикання desktop → `Receiver<Frame>`). Тягне кадри й валідує щільний BGRA8.
//! Автономно, без адміна (на `Default`). Запуск:
//!   cargo run -p zortilwatch-core --example dxgi_source_probe

#[cfg(not(windows))]
fn main() {
    println!("dxgi_source_probe: лише Windows");
}

#[cfg(windows)]
fn main() {
    use std::time::{Duration, Instant};
    use zortilwatch_core::capture::dxgi::{monitors_dxgi, start_primary_dxgi};

    let mons = monitors_dxgi();
    println!("моніторів: {}", mons.len());
    for m in &mons {
        println!(
            "  [{}] {} {}x{}{}",
            m.index,
            m.name,
            m.width,
            m.height,
            if m.is_primary { " (основний)" } else { "" }
        );
    }

    let (stream, rx) = start_primary_dxgi().expect("start_primary_dxgi");
    let outputs = mons.len().max(1) as u32;
    let mut total_ok = true;
    for out in 0..outputs {
        stream.set_output(out);
        // дренуємо застарілі кадри попереднього виходу, тоді збираємо свіжі
        while rx.try_recv().is_ok() {}
        let mut got = 0u32;
        let mut dims = (0u32, 0u32);
        let deadline = Instant::now() + Duration::from_secs(5);
        while got < 5 && Instant::now() < deadline {
            if let Ok(f) = rx.recv_timeout(Duration::from_millis(500)) {
                assert_eq!(f.data.len(), f.expected_len(), "кадр не щільний BGRA8");
                dims = (f.width, f.height);
                got += 1;
            }
        }
        println!("вихід {out}: {got} кадрів, {}x{}", dims.0, dims.1);
        if got == 0 {
            total_ok = false;
        }
    }
    stream.stop();

    if total_ok {
        println!("РЕЗУЛЬТАТ=OK: DXGI-джерело віддає кадри з усіх {outputs} виходів (перемикання працює)");
    } else {
        eprintln!("РЕЗУЛЬТАТ=FAIL: якийсь вихід не дав кадрів");
        std::process::exit(2);
    }
}
