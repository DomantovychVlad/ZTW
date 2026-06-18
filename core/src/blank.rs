//! Затемнення екрана керованого під час сесії (PRD 5.10).
//!
//! Чорне topmost-вікно на весь ВІРТУАЛЬНИЙ екран, ВИКЛЮЧЕНЕ із захоплення
//! (`SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`, Win10 2004+): людина біля
//! машини бачить чорне, а WGC-захоплення (і отже пульт) — справжній екран.
//! Вікно живе у власному потоці з message pump; `hide()` шле WM_CLOSE і чекає.

#[cfg(windows)]
pub use win::Blanker;

#[cfg(windows)]
mod win {
    use std::sync::atomic::{AtomicIsize, Ordering};
    use std::sync::Arc;
    use std::thread::JoinHandle;
    use windows::core::w;
    use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::Graphics::Gdi::{GetStockObject, BLACK_BRUSH, HBRUSH};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, GetSystemMetrics,
        PostMessageW, PostQuitMessage, RegisterClassW, SetWindowDisplayAffinity, TranslateMessage,
        MSG, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
        WDA_EXCLUDEFROMCAPTURE, WM_CLOSE, WM_DESTROY, WNDCLASSW, WS_EX_NOACTIVATE,
        WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_POPUP, WS_VISIBLE,
    };

    unsafe extern "system" fn wndproc(h: HWND, m: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
        if m == WM_DESTROY {
            PostQuitMessage(0);
            return LRESULT(0);
        }
        DefWindowProcW(h, m, wp, lp)
    }

    /// Активне затемнення; `hide()` (або Drop) прибирає вікно.
    pub struct Blanker {
        hwnd: Arc<AtomicIsize>,
        thread: Option<JoinHandle<()>>,
    }

    impl Blanker {
        /// Показати чорний оверлей. Вікно з'являється асинхронно (мс).
        pub fn show() -> Self {
            let hwnd = Arc::new(AtomicIsize::new(0));
            let hw = hwnd.clone();
            let thread = std::thread::spawn(move || unsafe {
                let Ok(hinst) = GetModuleHandleW(None) else {
                    return;
                };
                let class = w!("ZW_BLANK_WND");
                let wc = WNDCLASSW {
                    lpfnWndProc: Some(wndproc),
                    hInstance: hinst.into(),
                    lpszClassName: class,
                    hbrBackground: HBRUSH(GetStockObject(BLACK_BRUSH).0),
                    ..Default::default()
                };
                RegisterClassW(&wc); // повторна реєстрація дає помилку — байдуже, клас уже є
                let (x, y) = (
                    GetSystemMetrics(SM_XVIRTUALSCREEN),
                    GetSystemMetrics(SM_YVIRTUALSCREEN),
                );
                let (w_, h_) = (
                    GetSystemMetrics(SM_CXVIRTUALSCREEN).max(1),
                    GetSystemMetrics(SM_CYVIRTUALSCREEN).max(1),
                );
                let Ok(win) = CreateWindowExW(
                    WS_EX_TOPMOST | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
                    class,
                    w!("ZortilWatch"),
                    WS_POPUP | WS_VISIBLE,
                    x,
                    y,
                    w_,
                    h_,
                    None,
                    None,
                    Some(hinst.into()),
                    None,
                ) else {
                    return;
                };
                // Ключ: вікно НЕ потрапляє в захоплення — пульт бачить екран, людина — чорне.
                let _ = SetWindowDisplayAffinity(win, WDA_EXCLUDEFROMCAPTURE);
                hw.store(win.0 as isize, Ordering::Release);
                let mut msg = MSG::default();
                while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            });
            Blanker {
                hwnd,
                thread: Some(thread),
            }
        }

        /// Прибрати оверлей і дочекатися завершення потоку вікна.
        pub fn hide(mut self) {
            self.close_join();
        }

        fn close_join(&mut self) {
            let raw = self.hwnd.swap(0, Ordering::AcqRel);
            if raw != 0 {
                unsafe {
                    let _ = PostMessageW(
                        Some(HWND(raw as *mut core::ffi::c_void)),
                        WM_CLOSE,
                        WPARAM(0),
                        LPARAM(0),
                    );
                }
            }
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    impl Drop for Blanker {
        fn drop(&mut self) {
            self.close_join(); // безпека: затемнення НІКОЛИ не переживає сесію
        }
    }
}
