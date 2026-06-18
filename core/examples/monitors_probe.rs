//! Швидка перевірка розпізнавання моніторів (PRD 5.6) без сесії.
//! Запуск: cargo run -p zortilwatch-core --example monitors_probe

#[cfg(not(windows))]
fn main() {
    println!("monitors_probe: лише Windows");
}

#[cfg(windows)]
fn main() {
    let list = zortilwatch_core::capture::monitors();
    println!("Розпізнано моніторів: {}", list.len());
    for m in &list {
        println!(
            "  [{}] {} — {}x{}{}",
            m.index,
            m.name,
            m.width,
            m.height,
            if m.is_primary {
                "  ★основний"
            } else {
                ""
            }
        );
    }
    println!("RESULT={}", if list.is_empty() { "FAIL" } else { "OK" });
}
