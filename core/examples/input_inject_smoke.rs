//! Недеструктивний PoC інжекції вводу: інжектуємо рух миші в ПОТОЧНУ позицію курсора
//! (нормалізовану), тож курсор не зсувається видимо — але шлях SendInput перевірено.
//! Запуск: cargo run -p zortilwatch-core --example input_inject_smoke

#[cfg(windows)]
fn main() {
    use std::{thread, time::Duration};
    use zortilwatch_core::input::{self, InputEvent};

    let (w, h) = input::screen_size();
    let (ox, oy) = input::cursor_pos();
    println!("screen {w}x{h}, cursor at ({ox},{oy})");

    // Рух у поточну позицію -> без видимого зсуву.
    let nx = ox as f32 / w.saturating_sub(1) as f32;
    let ny = oy as f32 / h.saturating_sub(1) as f32;
    input::inject(&InputEvent::MouseMove { x: nx, y: ny });
    thread::sleep(Duration::from_millis(30));

    let (nx2, ny2) = input::cursor_pos();
    let (dx, dy) = ((nx2 - ox).abs(), (ny2 - oy).abs());
    println!("after inject-to-current: ({nx2},{ny2}), delta=({dx},{dy})");

    if dx <= 2 && dy <= 2 {
        println!("RESULT=OK SendInput працює, курсор стабільний (недеструктивно)");
    } else {
        println!("RESULT=UNEXPECTED_MOVE delta=({dx},{dy})");
    }
}

#[cfg(not(windows))]
fn main() {
    println!("Інжекція вводу доступна лише на Windows");
}
