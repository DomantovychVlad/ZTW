//! Спільний буфер обміну (PRD 5.8), текст. Win32 без сторонніх залежностей.
//! Зміни ловимо дешево через GetClipboardSequenceNumber (полінг у медіа-циклі).

#[cfg(windows)]
pub use win::{get_text, sequence, set_text};

#[cfg(windows)]
mod win {
    use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL, HWND};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardSequenceNumber,
        OpenClipboard, SetClipboardData,
    };
    use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};

    const CF_UNICODETEXT: u32 = 13;

    /// Номер версії буфера ОС — змінюється на кожну зміну вмісту.
    pub fn sequence() -> u32 {
        unsafe { GetClipboardSequenceNumber() }
    }

    /// Прочитати текст буфера (None — порожньо/не текст/зайнято іншим процесом).
    pub fn get_text() -> Option<String> {
        unsafe {
            OpenClipboard(Some(HWND::default())).ok()?;
            let result = (|| {
                let h = GetClipboardData(CF_UNICODETEXT).ok()?;
                let p = GlobalLock(HGLOBAL(h.0)) as *const u16;
                if p.is_null() {
                    return None;
                }
                let mut len = 0usize;
                while *p.add(len) != 0 {
                    len += 1;
                }
                let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
                let _ = GlobalUnlock(HGLOBAL(h.0));
                Some(s)
            })();
            let _ = CloseClipboard();
            result
        }
    }

    /// Записати текст у буфер. Буфер ОС — глобальний м'ютекс: якщо його тримає інший
    /// процес, OpenClipboard падає — ретраїмо (до 5 разів по 30мс).
    pub fn set_text(text: &str) -> bool {
        for attempt in 0..5 {
            if attempt > 0 {
                std::thread::sleep(std::time::Duration::from_millis(30));
            }
            if set_text_once(text) {
                return true;
            }
        }
        false
    }

    fn set_text_once(text: &str) -> bool {
        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            if OpenClipboard(Some(HWND::default())).is_err() {
                return false;
            }
            let ok = (|| {
                EmptyClipboard().ok()?;
                let bytes = wide.len() * 2;
                let h = GlobalAlloc(GMEM_MOVEABLE, bytes).ok()?;
                // h треба звільнити самим, доки власність НЕ перейшла до буфера ОС.
                let p = GlobalLock(h) as *mut u16;
                if p.is_null() {
                    let _ = GlobalFree(Some(h));
                    return None;
                }
                std::ptr::copy_nonoverlapping(wide.as_ptr(), p, wide.len());
                let _ = GlobalUnlock(h);
                if SetClipboardData(CF_UNICODETEXT, Some(HANDLE(h.0))).is_err() {
                    let _ = GlobalFree(Some(h)); // власність НЕ перейшла — звільняємо
                    return None;
                }
                Some(()) // успіх: власність h перейшла до буфера ОС
            })()
            .is_some();
            let _ = CloseClipboard();
            ok
        }
    }
}
