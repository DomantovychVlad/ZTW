//! Модель подій вводу (пульт -> керований).
//!
//! Координати миші нормалізовані 0..1, щоб не залежати від роздільності віддаленого
//! екрана: керований сам масштабує їх під свій дисплей. Фактична інжекція (SendInput)
//! — окремий платформний шар; тут лише серіалізовна модель і перетворення координат.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum InputEvent {
    /// Рух миші в нормалізованих координатах (0..1).
    MouseMove { x: f32, y: f32 },
    /// Натискання/відпускання кнопки миші.
    MouseButton { button: MouseButton, down: bool },
    /// Прокручування (нормалізовані дельти).
    Scroll { dx: f32, dy: f32 },
    /// Клавіша за віртуальним кодом; комбінації — послідовність down/up.
    Key { code: u32, down: bool },
    /// Кооперативні стелі якості від пульта (PRD 5.5, рішення D1): цільова частота
    /// кадрів, стеля бітрейту, масштаб роздільності (1=повна, 2=половина).
    /// Не інжектується — обробляє медіа-цикл керованого (зміна БЕЗ перепідключення).
    Quality { fps: u32, bitrate: u32, scale: u32 },
    /// Перемкнути захоплення на інший монітор (PRD 5.6). Теж не інжектується.
    Monitor { index: u32 },
    /// Файли (PRD 5.7): список каталогу керованого ("" = диски). Відповідь — h2c JSON.
    FsList { path: String },
    /// Тягнути файл із керованого від `offset` (відновлення перерваної передачі).
    FsDownload { id: u32, path: String, offset: u64 },
    /// Намір слати файл НА керований; host відповість fsProgress з offset, з якого
    /// чекає чанки (resume), далі підуть бінарні кадри 0xF7.
    FsUploadStart { id: u32, path: String, size: u64 },
    /// Скасувати передачу.
    FsCancel { id: u32 },
    /// Текст буфера пульта -> керований (PRD 5.8).
    Clipboard { text: String },
    /// Вимикач синхронізації буфера (приватність, PRD 5.8).
    ClipboardSync { enabled: bool },
    /// Затемнити/відкрити екран керованого (PRD 5.10; локально чорно, пульт бачить).
    Blank { enabled: bool },
    /// Заблокувати/розблокувати фізичні мишу й клавіатуру керованого (PRD 5.10;
    /// BlockInput діє лише з правами адміністратора — інакше тихо без ефекту).
    InputLock { enabled: bool },
}

/// Перетворити нормалізовану координату (0..1) у піксель для екрана `dimension`.
/// Значення затискаються в межі екрана.
pub fn to_pixel(normalized: f32, dimension: u32) -> i32 {
    let clamped = normalized.clamp(0.0, 1.0);
    (clamped * dimension.saturating_sub(1) as f32).round() as i32
}

#[cfg(windows)]
pub use win::{block_physical, cursor_pos, inject, lock_workstation, screen_size};

/// Інжекція вводу на керованому пристрої (Windows, SendInput).
#[cfg(windows)]
mod win {
    use super::{InputEvent, MouseButton};
    use windows::Win32::Foundation::POINT;
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYBD_EVENT_FLAGS,
        KEYEVENTF_KEYUP, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN,
        MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE,
        MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_WHEEL, MOUSEINPUT,
        MOUSE_EVENT_FLAGS, VIRTUAL_KEY,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        GetCursorPos, GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN,
    };

    fn send(input: INPUT) {
        unsafe {
            SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
        }
    }

    fn mouse(flags: MOUSE_EVENT_FLAGS, dx: i32, dy: i32, data: i32) -> INPUT {
        INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx,
                    dy,
                    mouseData: data as u32,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    /// Застосувати подію вводу. Координати миші нормалізовані 0..1 -> абсолютні (основний монітор).
    pub fn inject(event: &InputEvent) {
        match *event {
            InputEvent::MouseMove { x, y } => {
                let ax = (x.clamp(0.0, 1.0) * 65535.0).round() as i32;
                let ay = (y.clamp(0.0, 1.0) * 65535.0).round() as i32;
                send(mouse(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, ax, ay, 0));
            }
            InputEvent::MouseButton { button, down } => {
                let f = match (button, down) {
                    (MouseButton::Left, true) => MOUSEEVENTF_LEFTDOWN,
                    (MouseButton::Left, false) => MOUSEEVENTF_LEFTUP,
                    (MouseButton::Right, true) => MOUSEEVENTF_RIGHTDOWN,
                    (MouseButton::Right, false) => MOUSEEVENTF_RIGHTUP,
                    (MouseButton::Middle, true) => MOUSEEVENTF_MIDDLEDOWN,
                    (MouseButton::Middle, false) => MOUSEEVENTF_MIDDLEUP,
                };
                send(mouse(f, 0, 0, 0));
            }
            InputEvent::Scroll { dx, dy } => {
                if dy != 0.0 {
                    send(mouse(MOUSEEVENTF_WHEEL, 0, 0, (dy * 120.0) as i32));
                }
                if dx != 0.0 {
                    send(mouse(MOUSEEVENTF_HWHEEL, 0, 0, (dx * 120.0) as i32));
                }
            }
            InputEvent::Key { code, down } => {
                let flags = if down {
                    KEYBD_EVENT_FLAGS(0)
                } else {
                    KEYEVENTF_KEYUP
                };
                let input = INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: VIRTUAL_KEY(code as u16),
                            wScan: 0,
                            dwFlags: flags,
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                };
                send(input);
            }
            // Керівні повідомлення медіа-циклу/файлів/буфера — НЕ ввід; інжекції не мають.
            _ => {}
        }
    }

    /// Блокування фізичного вводу (миша/клавіатура) на час сесії (PRD 5.10).
    /// SendInput-інжекція пульта ПРАЦЮЄ і при блокуванні (BlockInput ріже лише
    /// апаратний ввід). Потребує прав адміністратора; без них — false.
    pub fn block_physical(enabled: bool) -> bool {
        unsafe { windows::Win32::UI::Input::KeyboardAndMouse::BlockInput(enabled).is_ok() }
    }

    /// Заблокувати робочу станцію (екран входу Windows) — автоблокування після сесії (PRD 5.10).
    pub fn lock_workstation() {
        unsafe {
            let _ = windows::Win32::System::Shutdown::LockWorkStation();
        }
    }

    /// Розмір основного екрана в пікселях.
    pub fn screen_size() -> (u32, u32) {
        unsafe {
            let w = GetSystemMetrics(SM_CXSCREEN).max(1) as u32;
            let h = GetSystemMetrics(SM_CYSCREEN).max(1) as u32;
            (w, h)
        }
    }

    /// Поточна позиція курсора в пікселях.
    pub fn cursor_pos() -> (i32, i32) {
        let mut p = POINT::default();
        unsafe {
            let _ = GetCursorPos(&mut p);
        }
        (p.x, p.y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_json_roundtrip() {
        let events = vec![
            InputEvent::MouseMove { x: 0.5, y: 0.25 },
            InputEvent::MouseButton {
                button: MouseButton::Left,
                down: true,
            },
            InputEvent::Scroll { dx: 0.0, dy: -1.0 },
            InputEvent::Key {
                code: 65,
                down: true,
            },
        ];
        for e in events {
            let s = serde_json::to_string(&e).unwrap();
            let back: InputEvent = serde_json::from_str(&s).unwrap();
            assert_eq!(e, back);
        }
    }

    #[test]
    fn to_pixel_maps_and_clamps() {
        assert_eq!(to_pixel(0.0, 1920), 0);
        assert_eq!(to_pixel(1.0, 1920), 1919);
        assert_eq!(to_pixel(0.5, 1921), 960);
        assert_eq!(to_pixel(-0.5, 1920), 0);
        assert_eq!(to_pixel(2.0, 1920), 1919);
    }
}
