//! Захоплення екрана.
//!
//! Stage 2: безперервне захоплення звичайного робочого стола через WGC
//! (Windows.Graphics.Capture, крейт `windows-capture`, MIT). WGC потребує інтерактивної
//! сесії й НЕ бачить екран входу/UAC — той випадок піде через DXGI-DDA під SYSTEM (Етап 4).
//! Кадри нормалізуються до щільно упакованого BGRA8 (без рядкового вирівнювання).

/// Кадр екрана: щільно упакований BGRA8.
#[derive(Clone)]
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub data: Vec<u8>,
}

impl Frame {
    /// Очікувана довжина для BGRA8: width*height*4.
    pub fn expected_len(&self) -> usize {
        self.width as usize * self.height as usize * 4
    }
}

#[derive(Debug)]
pub struct CaptureError(pub String);

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "capture error: {}", self.0)
    }
}

impl std::error::Error for CaptureError {}

#[cfg(windows)]
mod wgc {
    use super::{CaptureError, Frame};
    use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
    use windows_capture::capture::{CaptureControl, Context, GraphicsCaptureApiHandler};
    use windows_capture::frame::Frame as WcFrame;
    use windows_capture::graphics_capture_api::InternalCaptureControl;
    use windows_capture::monitor::Monitor;
    use windows_capture::settings::{
        ColorFormat, CursorCaptureSettings, DirtyRegionSettings, DrawBorderSettings,
        MinimumUpdateIntervalSettings, SecondaryWindowSettings, Settings,
    };

    type HandlerError = Box<dyn std::error::Error + Send + Sync>;

    pub struct Handler {
        sender: SyncSender<Frame>,
        scratch: Vec<u8>,
    }

    impl GraphicsCaptureApiHandler for Handler {
        type Flags = SyncSender<Frame>;
        type Error = HandlerError;

        fn new(ctx: Context<Self::Flags>) -> Result<Self, Self::Error> {
            Ok(Self {
                sender: ctx.flags,
                scratch: Vec::new(),
            })
        }

        fn on_frame_arrived(
            &mut self,
            frame: &mut WcFrame,
            capture_control: InternalCaptureControl,
        ) -> Result<(), Self::Error> {
            let width = frame.width();
            let height = frame.height();
            let fb = frame.buffer()?;
            let packed = fb.as_nopadding_buffer(&mut self.scratch);
            let f = Frame {
                width,
                height,
                data: packed.to_vec(),
            };
            match self.sender.try_send(f) {
                Ok(()) => {}
                // Споживач не встигає — свідомо пропускаємо кадр (краще, ніж відставати).
                Err(TrySendError::Full(_)) => {}
                // Споживач зник — зупиняємо захоплення.
                Err(TrySendError::Disconnected(_)) => capture_control.stop(),
            }
            Ok(())
        }

        fn on_closed(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    /// Активне захоплення; `stop()` коректно завершує фоновий потік WGC.
    pub struct Capture {
        control: Option<CaptureControl<Handler, HandlerError>>,
    }

    impl Capture {
        pub fn stop(mut self) {
            if let Some(c) = self.control.take() {
                let _ = c.stop();
            }
        }
    }

    /// Опис монітора для адресації з пульта (PRD 5.6). `index` — позиція в enumerate.
    pub struct MonitorInfo {
        pub index: u32,
        pub name: String,
        pub width: u32,
        pub height: u32,
        pub is_primary: bool,
        /// Лівий-верхній кут монітора на ВІРТУАЛЬНОМУ робочому столі (для абсолютної
        /// інжекції миші на потрібний екран). 0,0 для WGC (Tier A position — окремо).
        pub x: i32,
        pub y: i32,
    }

    /// Перелік моніторів. Порожній — якщо перелік недоступний.
    pub fn monitors() -> Vec<MonitorInfo> {
        let primary_idx = Monitor::primary().and_then(|m| m.index()).unwrap_or(0);
        Monitor::enumerate()
            .map(|list| {
                list.iter()
                    .enumerate()
                    .map(|(i, m)| {
                        // name() інколи дає порожнє (напр. для основного) — підставляємо «Монітор N».
                        let name = match m.name() {
                            Ok(n) if !n.trim().is_empty() => n,
                            _ => format!("Монітор {}", i + 1),
                        };
                        MonitorInfo {
                            index: i as u32,
                            name,
                            width: m.width().unwrap_or(0),
                            height: m.height().unwrap_or(0),
                            is_primary: m.index().map(|x| x == primary_idx).unwrap_or(false),
                            x: 0, // WGC не дає позицію тривіально; Tier A-мультимонітор — окремо
                            y: 0,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn start_with(monitor: Monitor) -> Result<(Capture, Receiver<Frame>), CaptureError> {
        let (tx, rx) = sync_channel::<Frame>(2);
        let settings = Settings::new(
            monitor,
            CursorCaptureSettings::WithoutCursor,
            DrawBorderSettings::WithoutBorder,
            SecondaryWindowSettings::Default,
            MinimumUpdateIntervalSettings::Default,
            DirtyRegionSettings::Default,
            ColorFormat::Bgra8,
            tx,
        );
        let control =
            Handler::start_free_threaded(settings).map_err(|e| CaptureError(e.to_string()))?;
        Ok((
            Capture {
                control: Some(control),
            },
            rx,
        ))
    }

    /// Почати захоплення основного монітора у фоновому потоці. Повертає керування й
    /// приймач кадрів (BGRA8). Буфер каналу малий — нові кадри витісняють застарілі.
    pub fn start_primary() -> Result<(Capture, Receiver<Frame>), CaptureError> {
        start_with(Monitor::primary().map_err(|e| CaptureError(e.to_string()))?)
    }

    /// Почати захоплення монітора за позицією з [`monitors`].
    pub fn start_monitor(index: u32) -> Result<(Capture, Receiver<Frame>), CaptureError> {
        let list = Monitor::enumerate().map_err(|e| CaptureError(e.to_string()))?;
        let monitor = list
            .into_iter()
            .nth(index as usize)
            .ok_or_else(|| CaptureError(format!("монітора {index} не існує")))?;
        start_with(monitor)
    }
}

#[cfg(windows)]
pub use wgc::{monitors, start_monitor, start_primary, Capture, MonitorInfo};

/// DXGI Desktop Duplication — захоплення для керованого на secure-desktop (Етап 4 / Tier B).
///
/// На відміну від WGC, дістає екран входу/UAC, якщо процес — `LOCAL_SYSTEM`, а потік
/// захоплення прив'язано до input-desktop (`SetThreadDesktop`). Pull-API: викликач сам
/// крутить цикл і пересоздає захоплення на `Err` (ACCESS_LOST = перемикання desktop/режиму).
/// Десктоп-прив'язку та перемикання тримає викликач (служба), тут — лише примітив захоплення.
/// Кадр — щільно упакований BGRA8 (як WGC), тож той самий шлях у [`crate::encode`].
#[cfg(windows)]
pub mod dxgi {
    use super::{CaptureError, Frame, MonitorInfo};
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
    use std::sync::Arc;
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};
    use windows::core::Interface;
    use windows::Win32::Foundation::{HANDLE, HMODULE};
    use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_HARDWARE;
    use windows::Win32::Graphics::Direct3D11::{
        D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
        D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_FLAG, D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ,
        D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
    };
    use windows::Win32::Graphics::Dxgi::{
        IDXGIAdapter, IDXGIDevice, IDXGIOutput, IDXGIOutput1, IDXGIOutputDuplication, IDXGIResource,
        DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO,
    };
    use windows::Win32::System::StationsAndDesktops::{
        CloseDesktop, GetUserObjectInformationW, OpenInputDesktop, SetThreadDesktop,
        DESKTOP_ACCESS_FLAGS, DESKTOP_CONTROL_FLAGS, HDESK, UOI_NAME,
    };

    /// Активне дублювання виходу (монітора) на поточному desktop потоку.
    pub struct DxgiCapture {
        device: ID3D11Device,
        context: ID3D11DeviceContext,
        dup: IDXGIOutputDuplication,
        width: u32,
        height: u32,
    }

    impl DxgiCapture {
        /// Створити пристрій D3D11 і дублювання ПЕРВИННОГО виходу (екран 0).
        pub fn new() -> Result<Self, CaptureError> {
            Self::new_output(0)
        }

        /// Створити дублювання виходу `output_index` (мультимонітор). Якщо такого індексу
        /// немає — відкат на вихід 0. `DuplicateOutput` дає E_ACCESSDENIED поза SYSTEM/не на тому desktop.
        pub fn new_output(output_index: u32) -> Result<Self, CaptureError> {
            unsafe { Self::new_inner(output_index) }
        }

        unsafe fn new_inner(output_index: u32) -> Result<Self, CaptureError> {
            let mut device: Option<ID3D11Device> = None;
            let mut context: Option<ID3D11DeviceContext> = None;
            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_HARDWARE,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_FLAG(0),
                None,
                D3D11_SDK_VERSION,
                Some(&mut device),
                None,
                Some(&mut context),
            )
            .map_err(|e| CaptureError(format!("D3D11CreateDevice: {e}")))?;
            let device = device.ok_or_else(|| CaptureError("пристрій D3D11 null".into()))?;
            let context = context.ok_or_else(|| CaptureError("контекст D3D11 null".into()))?;

            let dxgi_device: IDXGIDevice =
                device.cast().map_err(|e| CaptureError(format!("cast IDXGIDevice: {e}")))?;
            let adapter: IDXGIAdapter =
                dxgi_device.GetAdapter().map_err(|e| CaptureError(format!("GetAdapter: {e}")))?;
            // Бажаний вихід; якщо індекс поза межами — відкат на 0 (первинний).
            let output: IDXGIOutput = adapter
                .EnumOutputs(output_index)
                .or_else(|_| adapter.EnumOutputs(0))
                .map_err(|e| CaptureError(format!("EnumOutputs({output_index}): {e}")))?;
            let output1: IDXGIOutput1 =
                output.cast().map_err(|e| CaptureError(format!("cast IDXGIOutput1: {e}")))?;
            let dup = output1.DuplicateOutput(&device).map_err(|e| {
                CaptureError(format!("DuplicateOutput (E_ACCESSDENIED = не SYSTEM/не той desktop): {e}"))
            })?;
            let desc = dup.GetDesc();
            Ok(Self {
                device,
                context,
                dup,
                width: desc.ModeDesc.Width,
                height: desc.ModeDesc.Height,
            })
        }

        pub fn width(&self) -> u32 {
            self.width
        }

        pub fn height(&self) -> u32 {
            self.height
        }

        /// Дочекатися наступного кадру (до `timeout_ms`). `Ok(Some)` — новий кадр (щільний
        /// BGRA8); `Ok(None)` — таймаут (немає змін); `Err` — втрата (ACCESS_LOST тощо),
        /// викликач має пересоздати [`DxgiCapture`].
        pub fn next_frame(&mut self, timeout_ms: u32) -> Result<Option<Frame>, CaptureError> {
            unsafe {
                let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
                let mut resource: Option<IDXGIResource> = None;
                match self.dup.AcquireNextFrame(timeout_ms, &mut info, &mut resource) {
                    Ok(()) => {
                        let frame = self.readback(resource.as_ref());
                        let _ = self.dup.ReleaseFrame();
                        frame.map(Some)
                    }
                    Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => Ok(None),
                    Err(e) => Err(CaptureError(format!("AcquireNextFrame: {e}"))),
                }
            }
        }

        /// Скопіювати desktop-текстуру в staging і зчитати в щільний BGRA8 (зрізаючи
        /// рядкове вирівнювання `RowPitch`).
        unsafe fn readback(&self, resource: Option<&IDXGIResource>) -> Result<Frame, CaptureError> {
            let res = resource.ok_or_else(|| CaptureError("кадр без ресурсу".into()))?;
            let tex: ID3D11Texture2D =
                res.cast().map_err(|e| CaptureError(format!("cast ID3D11Texture2D: {e}")))?;
            let mut desc = D3D11_TEXTURE2D_DESC::default();
            tex.GetDesc(&mut desc);
            let staging_desc = D3D11_TEXTURE2D_DESC {
                MipLevels: 1,
                ArraySize: 1,
                Usage: D3D11_USAGE_STAGING,
                BindFlags: 0,
                CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
                MiscFlags: 0,
                ..desc
            };
            let mut staging: Option<ID3D11Texture2D> = None;
            self.device
                .CreateTexture2D(&staging_desc, None, Some(&mut staging))
                .map_err(|e| CaptureError(format!("CreateTexture2D(staging): {e}")))?;
            let staging = staging.ok_or_else(|| CaptureError("staging-текстура null".into()))?;
            self.context.CopyResource(&staging, &tex);

            let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
            self.context
                .Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
                .map_err(|e| CaptureError(format!("Map(staging): {e}")))?;

            let (w, h) = (desc.Width, desc.Height);
            let row = (w * 4) as usize;
            let pitch = mapped.RowPitch as usize;
            let mut data = vec![0u8; row * h as usize];
            let src = mapped.pData as *const u8;
            for y in 0..h as usize {
                std::ptr::copy_nonoverlapping(
                    src.add(y * pitch),
                    data.as_mut_ptr().add(y * row),
                    row,
                );
            }
            self.context.Unmap(&staging, 0);
            Ok(Frame { width: w, height: h, data })
        }
    }

    /// Стоп-ручка фонового DXGI-джерела (див. [`start_primary_dxgi`]). Зупиняє потік
    /// захоплення (на Drop теж). Дзеркалить роль `wgc::Capture`.
    pub struct DxgiStream {
        stop: Arc<AtomicBool>,
        output: Arc<AtomicU32>,
        handle: Option<JoinHandle<()>>,
    }

    impl DxgiStream {
        /// Перемкнути захоплення на монітор (вихід) `index`; фоновий потік пересоздасть
        /// дублювання на наступній ітерації (індекс поза межами → відкат на 0).
        pub fn set_output(&self, index: u32) {
            self.output.store(index, Ordering::Relaxed);
        }
        pub fn stop(mut self) {
            self.shutdown();
        }
        fn shutdown(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    impl Drop for DxgiStream {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    /// Запустити DXGI-захоплення активного input-desktop у фоновому потоці зі стеженням
    /// за перемиканням `Default↔Winlogon↔Screen-saver` (керований на secure-desktop, Tier B).
    /// Форма дзеркалить [`super::start_primary`]: стоп-ручка + приймач щільних BGRA8-кадрів
    /// (малий буфер — нові кадри витісняють застарілі). Для secure-desktop процес має бути
    /// `LOCAL_SYSTEM`; на `Default` досить звичайного користувача.
    pub fn start_primary_dxgi() -> Result<(DxgiStream, Receiver<Frame>), CaptureError> {
        let (tx, rx) = sync_channel::<Frame>(2);
        let stop = Arc::new(AtomicBool::new(false));
        let output = Arc::new(AtomicU32::new(0));
        let (stop2, output2) = (stop.clone(), output.clone());
        let handle = std::thread::Builder::new()
            .name("dxgi-capture".into())
            .spawn(move || unsafe { source_loop(tx, stop2, output2) })
            .map_err(|e| CaptureError(format!("spawn dxgi thread: {e}")))?;
        Ok((
            DxgiStream {
                stop,
                output,
                handle: Some(handle),
            },
            rx,
        ))
    }

    /// Перелік моніторів (виходів адаптера за замовчуванням) для адресації з пульта.
    /// Порожній — якщо недоступно. (Мульти-GPU: поки лише виходи дефолтного адаптера.)
    pub fn monitors_dxgi() -> Vec<MonitorInfo> {
        unsafe { monitors_inner() }.unwrap_or_default()
    }

    unsafe fn monitors_inner() -> Result<Vec<MonitorInfo>, CaptureError> {
        let mut device: Option<ID3D11Device> = None;
        D3D11CreateDevice(
            None,
            D3D_DRIVER_TYPE_HARDWARE,
            HMODULE::default(),
            D3D11_CREATE_DEVICE_FLAG(0),
            None,
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            None,
        )
        .map_err(|e| CaptureError(format!("D3D11CreateDevice: {e}")))?;
        let device = device.ok_or_else(|| CaptureError("пристрій D3D11 null".into()))?;
        let dxgi_device: IDXGIDevice =
            device.cast().map_err(|e| CaptureError(format!("cast IDXGIDevice: {e}")))?;
        let adapter: IDXGIAdapter =
            dxgi_device.GetAdapter().map_err(|e| CaptureError(format!("GetAdapter: {e}")))?;
        let mut list = Vec::new();
        for i in 0..16u32 {
            let output = match adapter.EnumOutputs(i) {
                Ok(o) => o,
                Err(_) => break, // більше виходів немає
            };
            if let Ok(desc) = output.GetDesc() {
                let r = desc.DesktopCoordinates;
                let end = desc
                    .DeviceName
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(desc.DeviceName.len());
                let name = String::from_utf16_lossy(&desc.DeviceName[..end]);
                list.push(MonitorInfo {
                    index: i,
                    name: if name.trim().is_empty() {
                        format!("Монітор {}", i + 1)
                    } else {
                        name
                    },
                    width: (r.right - r.left).max(0) as u32,
                    height: (r.bottom - r.top).max(0) as u32,
                    is_primary: r.left == 0 && r.top == 0,
                    x: r.left,
                    y: r.top,
                });
            }
        }
        Ok(list)
    }

    /// Цикл фонового потоку: стежити за input-desktop, (пере)створювати захоплення,
    /// штовхати кадри. Завершується по `stop` або зникненні споживача.
    unsafe fn source_loop(tx: SyncSender<Frame>, stop: Arc<AtomicBool>, output: Arc<AtomicU32>) {
        let mut bound: Option<HDESK> = None; // активний прив'язаний desktop (тримати відкритим)
        let mut current = String::new();
        let mut cap: Option<DxgiCapture> = None;
        let mut current_output = u32::MAX; // змусити перше створення
        let mut last_poll = Instant::now();

        while !stop.load(Ordering::Relaxed) {
            // Запит на інший монітор (вихід) — пересоздати захоплення на потрібному.
            let desired = output.load(Ordering::Relaxed);
            if desired != current_output {
                current_output = desired;
                cap = None;
            }
            // Стежимо за перемиканням input-desktop (опитування 200мс або при втраті захоплення).
            if cap.is_none() || last_poll.elapsed() >= Duration::from_millis(200) {
                last_poll = Instant::now();
                if let Some((hdesk, name)) = open_input_desktop() {
                    if name != current {
                        if SetThreadDesktop(hdesk).is_ok() {
                            if let Some(old) = bound.take() {
                                let _ = CloseDesktop(old); // закрити ПОПЕРЕДНІЙ, не активний
                            }
                            bound = Some(hdesk);
                            current = name;
                            cap = None; // девайс desktop-relative — пересоздати
                        } else {
                            let _ = CloseDesktop(hdesk);
                        }
                    } else {
                        let _ = CloseDesktop(hdesk);
                    }
                }
            }

            if cap.is_none() {
                match DxgiCapture::new_output(current_output) {
                    Ok(c) => cap = Some(c),
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(300));
                        continue;
                    }
                }
            }

            let mut c = cap.take().unwrap();
            match c.next_frame(100) {
                Ok(Some(frame)) => {
                    match tx.try_send(frame) {
                        Ok(()) | Err(TrySendError::Full(_)) => cap = Some(c), // повний — пропуск кадру
                        Err(TrySendError::Disconnected(_)) => break,          // споживач зник
                    }
                }
                Ok(None) => cap = Some(c),
                Err(_) => {} // ACCESS_LOST/інше — дроп c, ітерація пересоздасть
            }
        }

        if let Some(d) = bound {
            let _ = CloseDesktop(d);
        }
    }

    /// Поточний input-desktop: (хендл, ім'я). GENERIC_ALL достатньо, щоб прив'язати потік.
    unsafe fn open_input_desktop() -> Option<(HDESK, String)> {
        let hdesk =
            OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_ACCESS_FLAGS(0x1000_0000))
                .ok()?;
        let mut buf = [0u16; 256];
        let mut needed = 0u32;
        let name = if GetUserObjectInformationW(
            HANDLE(hdesk.0),
            UOI_NAME,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            (buf.len() * 2) as u32,
            Some(&mut needed),
        )
        .is_ok()
        {
            let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            String::from_utf16_lossy(&buf[..end])
        } else {
            "<?>".into()
        };
        Some((hdesk, name))
    }
}
