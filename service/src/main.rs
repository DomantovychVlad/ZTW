//! Системна служба ZortilWatch (Tier B) — кроки 1–4.
//!
//! • Крок 1: SCM-скелет + install/uninstall (LocalSystem, AutoStart).
//! • Крок 2: монітор активної консольної сесії.
//! • Крок 3: запуск ВОРКЕРА в активну сесію користувача з-під SYSTEM (подолання
//!   ізоляції session 0): мінтинг токена (WTSQueryUserToken) + CreateProcessAsUserW
//!   на `winsta0\default`.
//! • Крок 4: захоплення воркером інтерактивного desktop через DXGI Desktop
//!   Duplication (D3D11CreateDevice → DuplicateOutput → AcquireNextFrame), з CPU-
//!   зчитуванням першого кадру як доказом реального вмісту. Secure-desktop /
//!   перемикання desktop / енкодер — наступні кроки (docs/stage4-secure-desktop.md).
//!
//! Режим за аргументом (один .exe): `install` | `uninstall` | `--worker` | (без арг) = SCM-служба.

#[cfg(not(windows))]
fn main() {
    eprintln!("zortilwatch-service: лише Windows");
}

#[cfg(windows)]
fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    let res = match arg.as_str() {
        "install" => svc::install(),
        "uninstall" => svc::uninstall(),
        "--worker" => svc::run_worker(),
        "" => svc::run_dispatcher(),
        other => {
            eprintln!("невідомий аргумент: {other}. Вживайте: install | uninstall");
            Ok(())
        }
    };
    if let Err(e) = res {
        eprintln!("zortilwatch-service: {e}");
        svc::log(&format!("FATAL {e}"));
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod svc {
    use std::ffi::OsString;
    use std::sync::mpsc;
    use std::time::Duration;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
    use windows::Win32::Security::{
        AdjustTokenPrivileges, DuplicateTokenEx, LookupPrivilegeValueW, SecurityImpersonation,
        SetTokenInformation, TokenPrimary, TokenSessionId, LUID_AND_ATTRIBUTES,
        SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE,
        TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
    use windows::Win32::System::RemoteDesktop::{ProcessIdToSessionId, WTSGetActiveConsoleSessionId};
    use windows::Win32::System::StationsAndDesktops::{
        GetThreadDesktop, GetUserObjectInformationW, UOI_NAME,
    };
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId,
        OpenProcessToken, TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW,
        CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
    };
    use windows_service::service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_dispatcher;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    pub const SERVICE_NAME: &str = "ZortilWatch";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
    const NO_SESSION: u32 = 0xFFFF_FFFF;
    type Res = Result<(), Box<dyn std::error::Error>>;

    fn log_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
        std::path::Path::new(&dir).join("ZortilWatch").join(name)
    }

    /// Дописати рядок у заданий лог-файл під ProgramData\ZortilWatch.
    fn log_to(file: &str, msg: &str) {
        use std::io::Write;
        let path = log_path(file);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            let _ = writeln!(f, "[{ts}] {msg}");
        }
    }

    pub fn log(msg: &str) {
        log_to("service.log", msg);
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn active_console_session() -> u32 {
        unsafe { WTSGetActiveConsoleSessionId() }
    }

    // ── Привілеї LocalSystem (присутні, але ВИМКНЕНІ) ──
    /// Увімкнути привілей у токені процесу (потрібні для WTSQueryUserToken / CreateProcessAsUser).
    unsafe fn enable_privilege(name: &str) -> windows::core::Result<()> {
        let mut token = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )?;
        let mut luid = LUID::default();
        let wname = wide(name);
        let r = LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(wname.as_ptr()), &mut luid);
        if r.is_ok() {
            let tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            let _ = AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None);
        }
        let _ = CloseHandle(token);
        r
    }

    fn enable_required_privileges() {
        for p in [
            "SeTcbPrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeIncreaseQuotaPrivilege",
        ] {
            unsafe {
                if enable_privilege(p).is_err() {
                    log(&format!("privilege {p}: не вдалось увімкнути"));
                }
            }
        }
    }

    /// Запустити воркер (--worker) у консольній сесії `session` на `winsta0\default`,
    /// але з токеном **LOCAL_SYSTEM** — потрібно для `DuplicateOutput` на secure-desktop
    /// (Winlogon/UAC; крок 5). Дублюємо ВЛАСНИЙ токен служби (вона вже SYSTEM у session 0)
    /// і переносимо в активну сесію через `SetTokenInformation(TokenSessionId)` (вимагає
    /// SeTcbPrivilege — увімкнено). Працює і коли користувач залогінений, і на екрані входу.
    /// Повертає HANDLE процесу (для нагляду/завершення).
    unsafe fn spawn_worker(session: u32, exe: &std::path::Path) -> Result<HANDLE, String> {
        let mut self_token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &mut self_token)
            .map_err(|e| format!("OpenProcessToken(self): {e}"))?;

        let mut primary = HANDLE::default();
        let dup = DuplicateTokenEx(
            self_token,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut primary,
        );
        let _ = CloseHandle(self_token);
        dup.map_err(|e| format!("DuplicateTokenEx(self): {e}"))?;

        // Перенести SYSTEM-токен у консольну сесію (інакше воркер лишиться в session 0,
        // невидимий на робочому столі). SeTcbPrivilege уже увімкнено в run_service.
        if let Err(e) = SetTokenInformation(
            primary,
            TokenSessionId,
            &session as *const u32 as *const core::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
        ) {
            let _ = CloseHandle(primary);
            return Err(format!("SetTokenInformation(SessionId={session}): {e}"));
        }

        let mut env: *mut core::ffi::c_void = std::ptr::null_mut();
        let has_env = CreateEnvironmentBlock(&mut env, Some(primary), false).is_ok() && !env.is_null();

        let mut desktop = wide("winsta0\\default");
        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            lpDesktop: PWSTR(desktop.as_mut_ptr()),
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();
        let mut cmd = wide(&format!("\"{}\" --worker", exe.display()));
        let (flags, env_ptr) = if has_env {
            (
                CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                Some(env as *const core::ffi::c_void),
            )
        } else {
            (CREATE_NO_WINDOW, None)
        };

        let created = CreateProcessAsUserW(
            Some(primary),
            PCWSTR::null(),
            Some(PWSTR(cmd.as_mut_ptr())),
            None,
            None,
            false,
            flags,
            env_ptr,
            PCWSTR::null(),
            &si,
            &mut pi,
        );

        if has_env {
            let _ = DestroyEnvironmentBlock(env);
        }
        let _ = CloseHandle(primary);
        created.map_err(|e| format!("CreateProcessAsUserW: {e}"))?;
        let _ = CloseHandle(pi.hThread);
        Ok(pi.hProcess)
    }

    /// Чи процес ще живий (WaitForSingleObject з нульовим таймаутом).
    unsafe fn is_alive(h: HANDLE) -> bool {
        WaitForSingleObject(h, 0).0 == 0x0000_0102 // WAIT_TIMEOUT = ще працює
    }

    unsafe fn kill(h: HANDLE) {
        let _ = TerminateProcess(h, 1);
        let _ = CloseHandle(h);
    }

    // ── SCM lifecycle ──
    windows_service::define_windows_service!(ffi_service_main, service_main);

    pub fn run_dispatcher() -> Res {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
        Ok(())
    }

    fn service_main(_args: Vec<OsString>) {
        if let Err(e) = run_service() {
            log(&format!("service_main error: {e}"));
        }
    }

    fn status(state: ServiceState, accept: ServiceControlAccept) -> ServiceStatus {
        ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        }
    }

    /// Дати BUILTIN\Users право Modify на лог-теку — для дев-доступу до логів і провіженгу
    /// device.json (сам воркер тепер SYSTEM і пише напряму). УВАГА: цей грант успадковується
    /// файлами; device.json із секретом окремо замикається в [`secure_device_config`].
    fn ensure_log_dir_writable() {
        if let Some(dir) = log_path("x").parent() {
            let _ = std::fs::create_dir_all(dir);
            let _ = std::process::Command::new("icacls")
                .arg(dir)
                .args(["/grant", "*S-1-5-32-545:(OI)(CI)M"]) // Users: Modify, успадковано
                .output();
        }
    }

    /// Замкнути DACL `device.json` (постійний пароль + client_secret) лише на SYSTEM +
    /// Administrators: прибрати успадкований доступ BUILTIN\Users, щоб локальний користувач
    /// НЕ читав/не підміняв секрети. Воркер (SYSTEM) читає файл далі. Теку (логи) не чіпаємо.
    fn secure_device_config() {
        let path = log_path("device.json");
        if path.exists() {
            // /inheritance:r прибирає успадковані ACE (зокрема Users:Modify з теки);
            // S-1-5-18 = SYSTEM, S-1-5-32-544 = Administrators.
            let _ = std::process::Command::new("icacls")
                .arg(&path)
                .args([
                    "/inheritance:r",
                    "/grant",
                    "*S-1-5-18:(F)",
                    "/grant",
                    "*S-1-5-32-544:(F)",
                ])
                .output();
        }
    }

    fn run_service() -> Res {
        log("=== ZortilWatch service: старт ===");
        enable_required_privileges();
        ensure_log_dir_writable();
        secure_device_config();
        let exe = std::env::current_exe()?;

        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
        let event_handler = move |control| match control {
            ServiceControl::Stop => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
        handle.set_service_status(status(ServiceState::Running, ServiceControlAccept::STOP))?;
        log(&format!(
            "running як SYSTEM; активна консольна сесія = {}",
            active_console_session()
        ));

        // Нагляд за воркером: тримати рівно один у поточній активній сесії.
        let mut worker: Option<(u32, HANDLE)> = None;
        loop {
            let session = active_console_session();
            let alive = worker.as_ref().map(|&(_, h)| unsafe { is_alive(h) }).unwrap_or(false);
            let same_session = worker.as_ref().map(|&(s, _)| s) == Some(session);

            if session != NO_SESSION {
                if worker.is_none() || !alive || !same_session {
                    if let Some((_, h)) = worker.take() {
                        unsafe { kill(h) };
                    }
                    match unsafe { spawn_worker(session, &exe) } {
                        Ok(h) => {
                            log(&format!("воркер запущено в сесії {session}"));
                            worker = Some((session, h));
                        }
                        Err(e) => log(&format!("воркер НЕ запущено (сесія {session}): {e}")),
                    }
                }
            } else if let Some((_, h)) = worker.take() {
                unsafe { kill(h) }; // нема активної сесії — прибрати воркер
            }

            match shutdown_rx.recv_timeout(Duration::from_secs(2)) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }

        if let Some((_, h)) = worker.take() {
            unsafe { kill(h) };
        }
        log("=== ZortilWatch service: зупинка ===");
        handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty()))?;
        Ok(())
    }

    // ── Воркер (--worker): захоплює інтерактивний desktop через DXGI-DDA ──
    pub fn run_worker() -> Res {
        let session = unsafe {
            let mut s = 0u32;
            let _ = ProcessIdToSessionId(GetCurrentProcessId(), &mut s);
            s
        };
        let desktop = unsafe { current_desktop_name() };
        log_to(
            "worker.log",
            &format!("=== воркер старт: сесія={session}, desktop={desktop} ==="),
        );
        // Є device.json → host-стрім (крок 6б); інакше — лише-захоплення (крок 4, доказ).
        // Жодна гілка не повертається (працює, доки служба не вб'є воркер).
        match stream::load_config() {
            Some(cfg) => {
                log_to(
                    "worker.log",
                    &format!("device.json є — host-стрім на {}", cfg.server_base),
                );
                stream::serve(cfg)
            }
            None => {
                log_to("worker.log", "device.json немає — режим лише-захоплення");
                unsafe { cap::run(session) }
            }
        }
    }

    /// Ім'я поточного робочого столу потоку ("Default" / "Winlogon" / "Screen-saver").
    unsafe fn current_desktop_name() -> String {
        let hdesk = GetThreadDesktop(GetCurrentThreadId());
        let Ok(hdesk) = hdesk else {
            return "<?>".into();
        };
        let mut buf = [0u16; 256];
        let mut needed = 0u32;
        let ok = GetUserObjectInformationW(
            windows::Win32::Foundation::HANDLE(hdesk.0),
            UOI_NAME,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            (buf.len() * 2) as u32,
            Some(&mut needed),
        );
        if ok.is_err() {
            return "<?>".into();
        }
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }

    // ── Крок 4: DXGI Desktop Duplication у воркері ──
    //
    // На інтерактивному desktop (Default) звичайного токена користувача достатньо;
    // SYSTEM потрібен лише для secure-desktop (Winlogon/UAC) — це крок 5. Тут доводимо
    // сам конвеєр захоплення: D3D11 → DuplicateOutput → AcquireNextFrame, плюс одне
    // CPU-зчитування центрального пікселя першого кадру (доказ реального вмісту, а не
    // лише метаданих; заразом валідує readback-шлях для майбутнього енкодера, крок 6).
    mod cap {
        use std::time::{Duration, Instant};
        use windows::core::Interface;
        use windows::Win32::Foundation::{HANDLE, HMODULE};
        use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_HARDWARE;
        use windows::Win32::System::StationsAndDesktops::{
            CloseDesktop, GetUserObjectInformationW, OpenInputDesktop, SetThreadDesktop,
            DESKTOP_ACCESS_FLAGS, DESKTOP_CONTROL_FLAGS, HDESK, UOI_NAME,
        };
        use windows::Win32::Graphics::Direct3D11::{
            D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
            D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_FLAG, D3D11_MAPPED_SUBRESOURCE,
            D3D11_MAP_READ, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
        };
        use windows::Win32::Graphics::Dxgi::{
            IDXGIAdapter, IDXGIDevice, IDXGIOutput, IDXGIOutput1, IDXGIOutputDuplication,
            IDXGIResource, DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_WAIT_TIMEOUT,
            DXGI_OUTDUPL_FRAME_INFO,
        };

        struct Cap {
            device: ID3D11Device,
            context: ID3D11DeviceContext,
            dup: IDXGIOutputDuplication,
            width: u32,
            height: u32,
        }

        /// Створити пристрій D3D11 і дублювання першого виходу (монітора).
        /// `DuplicateOutput` поверне E_ACCESSDENIED, якщо ми не SYSTEM/не на тому desktop.
        unsafe fn create() -> Result<Cap, String> {
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
            .map_err(|e| format!("D3D11CreateDevice: {e}"))?;
            let device = device.ok_or("D3D11CreateDevice: пристрій null")?;
            let context = context.ok_or("D3D11CreateDevice: контекст null")?;

            let dxgi_device: IDXGIDevice =
                device.cast().map_err(|e| format!("cast IDXGIDevice: {e}"))?;
            let adapter: IDXGIAdapter =
                dxgi_device.GetAdapter().map_err(|e| format!("GetAdapter: {e}"))?;
            let output: IDXGIOutput =
                adapter.EnumOutputs(0).map_err(|e| format!("EnumOutputs(0): {e}"))?;
            let output1: IDXGIOutput1 =
                output.cast().map_err(|e| format!("cast IDXGIOutput1: {e}"))?;
            let dup = output1.DuplicateOutput(&device).map_err(|e| {
                format!("DuplicateOutput (E_ACCESSDENIED = не SYSTEM / не той desktop): {e}")
            })?;
            let desc = dup.GetDesc();
            Ok(Cap {
                device,
                context,
                dup,
                width: desc.ModeDesc.Width,
                height: desc.ModeDesc.Height,
            })
        }

        /// Скопіювати кадр у staging-текстуру й проаналізувати центральний рядок.
        /// Повертає (кількість ненульових байт у рядку, всього байт у рядку, опис 3 зразків).
        /// Доказ, що захоплено реальний вміст екрана, а не порожній буфер.
        unsafe fn frame_stats(cap: &Cap, tex: &ID3D11Texture2D) -> Option<(u32, u32, String)> {
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
            cap.device
                .CreateTexture2D(&staging_desc, None, Some(&mut staging))
                .ok()?;
            let staging = staging?;
            // CopyResource асинхронний, але Map(READ) без DO_NOT_WAIT блокує до завершення.
            cap.context.CopyResource(&staging, tex);
            let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
            cap.context
                .Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
                .ok()?;
            let (w, h) = (desc.Width, desc.Height);
            let row = (h / 2) as usize * mapped.RowPitch as usize;
            let total = w * 4;
            let p = mapped.pData as *const u8;
            let mut nonzero = 0u32;
            for i in 0..total as usize {
                if *p.add(row + i) != 0 {
                    nonzero += 1;
                }
            }
            let (q, m, t) = (
                row + (w / 4) as usize * 4,
                row + (w / 2) as usize * 4,
                row + (w * 3 / 4) as usize * 4,
            );
            let samples = format!(
                "x¼=({},{},{},{}) x½=({},{},{},{}) x¾=({},{},{},{})",
                *p.add(q), *p.add(q + 1), *p.add(q + 2), *p.add(q + 3),
                *p.add(m), *p.add(m + 1), *p.add(m + 2), *p.add(m + 3),
                *p.add(t), *p.add(t + 1), *p.add(t + 2), *p.add(t + 3),
            );
            cap.context.Unmap(&staging, 0);
            Some((nonzero, total, samples))
        }

        /// Поточний input-desktop: (хендл, ім'я "Default"/"Winlogon"/"Screen-saver").
        /// None — якщо недоступний. GENERIC_ALL достатньо, щоб прив'язати потік і читати ім'я.
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

        /// Цикл захоплення воркера зі стеженням за перемиканням input-desktop
        /// (Default↔Winlogon↔Screen-saver). На зміні: SetThreadDesktop + пересоздати
        /// захоплення (девайс desktop-relative). Не повертається (доки служба не вб'є).
        pub unsafe fn run(_session: u32) -> ! {
            let mut bound: Option<HDESK> = None; // активний прив'язаний desktop (тримати відкритим)
            let mut current = String::new(); // ім'я поточного desktop
            let mut cap: Option<Cap> = None;
            let mut frames: u64 = 0;
            let mut since = Instant::now();
            let mut last_poll = Instant::now();
            let mut probes = 0u32; // спроби довести вміст на ПОТОЧНОМУ desktop
            let mut proved_on = String::new(); // desktop, де вміст уже доведено

            loop {
                // 1) Стежимо за input-desktop. Опитуємо періодично + обов'язково коли
                //    захоплення втрачене (ACCESS_LOST = ймовірне перемикання Default↔Winlogon).
                if cap.is_none() || last_poll.elapsed() >= Duration::from_millis(200) {
                    last_poll = Instant::now();
                    if let Some((hdesk, name)) = open_input_desktop() {
                        if name != current {
                            if SetThreadDesktop(hdesk).is_ok() {
                                super::log_to(
                                    "worker.log",
                                    &format!(
                                        "перемикання desktop: {} → {name}",
                                        if current.is_empty() { "(старт)" } else { &current }
                                    ),
                                );
                                if let Some(old) = bound.take() {
                                    let _ = CloseDesktop(old); // закрити ПОПЕРЕДНІЙ, не активний
                                }
                                bound = Some(hdesk);
                                current = name;
                                cap = None; // девайс desktop-relative — пересоздати
                                probes = 0;
                            } else {
                                super::log_to(
                                    "worker.log",
                                    &format!("SetThreadDesktop({name}) не вдалось (права?) — лишаюсь на {current}"),
                                );
                                let _ = CloseDesktop(hdesk);
                            }
                        } else {
                            let _ = CloseDesktop(hdesk);
                        }
                    }
                }

                // 2) Забезпечити захоплення на поточному desktop.
                if cap.is_none() {
                    match create() {
                        Ok(c) => {
                            super::log_to(
                                "worker.log",
                                &format!(
                                    "DXGI-захоплення створено на desktop={current}: {}x{}",
                                    c.width, c.height
                                ),
                            );
                            cap = Some(c);
                        }
                        Err(e) => {
                            super::log_to(
                                "worker.log",
                                &format!("захоплення на desktop={current} НЕ створено: {e}"),
                            );
                            std::thread::sleep(Duration::from_millis(300));
                            continue;
                        }
                    }
                }

                // Беремо Cap у володіння на ітерацію (щоб на помилці просто не повертати → дроп).
                let c = cap.take().unwrap();
                let (w, h) = (c.width, c.height);
                let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
                let mut resource: Option<IDXGIResource> = None;
                match c.dup.AcquireNextFrame(100, &mut info, &mut resource) {
                    Ok(()) => {
                        frames += 1;
                        // Доводимо вміст один раз на КОЖНОМУ новому desktop, лише на справді
                        // оновленому кадрі (LastPresentTime!=0; перший кадр часто порожній).
                        if proved_on != current && info.LastPresentTime != 0 && probes < 30 {
                            probes += 1;
                            if let Some(tex) =
                                resource.as_ref().and_then(|r| r.cast::<ID3D11Texture2D>().ok())
                            {
                                if let Some((nonzero, total, samples)) = frame_stats(&c, &tex) {
                                    if nonzero > 0 {
                                        super::log_to(
                                            "worker.log",
                                            &format!(
                                                "ВМІСТ ДОВЕДЕНО на desktop={current}: ненульових {nonzero}/{total}; {samples}"
                                            ),
                                        );
                                        proved_on = current.clone();
                                    } else if probes == 30 {
                                        super::log_to(
                                            "worker.log",
                                            &format!("УВАГА: 30 кадрів на desktop={current}, рядок усе ще нульовий"),
                                        );
                                    }
                                }
                            }
                        }
                        let _ = c.dup.ReleaseFrame();
                        cap = Some(c);
                    }
                    Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => cap = Some(c), // нема кадру — норма
                    Err(e) => {
                        let lost = e.code() == DXGI_ERROR_ACCESS_LOST;
                        super::log_to(
                            "worker.log",
                            &format!(
                                "{} на desktop={current} ({e}) — пересоздаю",
                                if lost { "ACCESS_LOST" } else { "AcquireNextFrame помилка" }
                            ),
                        );
                        // c НЕ повертаємо → дроп звільняє device+dup; ітерація вище пересоздасть.
                    }
                }

                if since.elapsed() >= Duration::from_secs(2) {
                    let secs = since.elapsed().as_secs_f64();
                    super::log_to(
                        "worker.log",
                        &format!(
                            "захоплення живе: {w}x{h}, {frames} кадрів/{secs:.1}с (~{:.0}/с), desktop={current}",
                            frames as f64 / secs
                        ),
                    );
                    frames = 0;
                    since = Instant::now();
                }
            }
        }
    }

    // ── Крок 6б: host-стрім воркера (реєстрація на сигналі → WebRTC → стрім DXGI) ──
    //
    // Воркер сам драйвить WebRTC-піра (host=offerer) на публічних примітивах core, як
    // приклад e2e_media. Конфіг пристрою (machine-wide, бо служба стартує до логіну):
    // %ProgramData%\ZortilWatch\device.json. Немає файлу — лишаємось у режимі лише-захоплення
    // (mod cap, доказ). Перемикання desktop і захоплення secure-desktop дає core::capture::dxgi.
    mod stream {
        use std::cell::RefCell;
        use std::collections::VecDeque;
        use std::net::{SocketAddr, UdpSocket};
        use std::time::{Duration, Instant};

        use serde::Deserialize;
        use serde_json::{json, Value};
        use str0m::change::SdpAnswer;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::StationsAndDesktops::{
            CloseDesktop, GetUserObjectInformationW, OpenInputDesktop, SetThreadDesktop,
            DESKTOP_ACCESS_FLAGS, DESKTOP_CONTROL_FLAGS, HDESK, UOI_NAME,
        };
        use str0m::channel::ChannelId;
        use str0m::net::{Protocol, Receive};
        use str0m::{Candidate, Event, Input, Output, Rtc};

        use zortilwatch_core::blank::Blanker;
        use zortilwatch_core::capture::dxgi::{monitors_dxgi, start_primary_dxgi};
        use zortilwatch_core::crypto::{
            StreamOpener, StreamSealer, STREAM_LABEL_INPUT_C2H, STREAM_LABEL_MEDIA_H2C,
        };
        use zortilwatch_core::encode::H264Encoder;
        use zortilwatch_core::input::{self, InputEvent};
        use zortilwatch_core::media::{Chunker, DEFAULT_MAX_PAYLOAD};
        use zortilwatch_core::net::new_rtc;
        use zortilwatch_core::session::{Handshake, SessionMessage};
        use zortilwatch_core::signal::{ClientMsg, ServerMsg, SignalClient};

        const SESSION_BYE: &[u8] = b"ZW-BYE-1"; // пульт чисто завершив сесію (як у Tier A)

        /// Конфіг пристрою для host-стріму (%ProgramData%\ZortilWatch\device.json).
        #[derive(Deserialize)]
        pub struct DeviceConfig {
            pub server_base: String,
            pub device_id: String,
            pub client_secret: String,
            /// Постійний пароль для PAKE (пульт вводить його ж).
            pub password: String,
        }

        /// Прочитати device.json. None — файлу немає/невалідний (тоді режим лише-захоплення).
        pub fn load_config() -> Option<DeviceConfig> {
            let raw = std::fs::read_to_string(super::log_path("device.json")).ok()?;
            serde_json::from_str(raw.trim_start_matches('\u{feff}')).ok()
        }

        fn ws_url(base: &str) -> String {
            let b = if let Some(r) = base.strip_prefix("https://") {
                format!("wss://{r}")
            } else if let Some(r) = base.strip_prefix("http://") {
                format!("ws://{r}")
            } else {
                base.to_string()
            };
            format!("{}/signal", b.trim_end_matches('/'))
        }

        fn fingerprint(sdp: &str) -> String {
            sdp.lines()
                .find_map(|l| l.trim().strip_prefix("a=fingerprint:"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        }

        fn payload_str(p: &Value, k: &str) -> Option<String> {
            p.get(k).and_then(|v| v.as_str()).map(String::from)
        }

        /// Застосувати ICE-кандидати піра. Браузер шле `payload.cands` = масив SDP-рядків
        /// (trickle, по одному на повідомлення); Rust-пульт міг слати одиничний `cand`.
        fn apply_cands(rtc: &mut Rtc, payload: &Value) {
            if let Some(arr) = payload.get("cands").and_then(|v| v.as_array()) {
                for c in arr.iter().filter_map(|v| v.as_str()) {
                    if let Ok(cand) = Candidate::from_sdp_string(c) {
                        rtc.add_remote_candidate(cand);
                    }
                }
            } else if let Some(c) = payload.get("cand").and_then(|v| v.as_str()) {
                if let Ok(cand) = Candidate::from_sdp_string(c) {
                    rtc.add_remote_candidate(cand);
                }
            }
        }

        /// Надіслати пульту контрольне повідомлення зі списком моніторів + активним (той
        /// самий шифр-тракт; пульт відрізняє JSON від H.264 за першим байтом `{`).
        fn send_monitors(
            sealer: &mut StreamSealer,
            chunker: &mut Chunker,
            queue: &mut VecDeque<Vec<u8>>,
            active: u32,
        ) {
            let list: Vec<Value> = monitors_dxgi()
                .iter()
                .map(|m| {
                    json!({ "index": m.index, "name": m.name,
                            "w": m.width, "h": m.height, "primary": m.is_primary })
                })
                .collect();
            if let Ok(bytes) = serde_json::to_vec(&json!({ "monitors": list, "active": active })) {
                let sealed = sealer.seal(&bytes);
                for c in chunker.chunk(&sealed) {
                    queue.push_back(c);
                }
            }
        }

        thread_local! {
            // Прив'язка потоку-інжектора до input-desktop: тримаємо хендл відкритим,
            // закриваємо попередній при перемиканні (як у потоці захоплення).
            static INPUT_DESK: RefCell<Option<(HDESK, String)>> = const { RefCell::new(None) };
        }

        /// Прив'язати ПОТОЧНИЙ потік до активного input-desktop (Default↔Winlogon), щоб
        /// SendInput потрапляв на той самий стіл, що показує захоплення. Деградує тихо:
        /// якщо не вдалось — лишаємось на попередньому desktop (як було).
        unsafe fn ensure_input_desktop() {
            let hdesk = match OpenInputDesktop(
                DESKTOP_CONTROL_FLAGS(0),
                false,
                DESKTOP_ACCESS_FLAGS(0x1000_0000),
            ) {
                Ok(h) => h,
                Err(_) => return,
            };
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
            INPUT_DESK.with(|cell| {
                let mut cur = cell.borrow_mut();
                if cur.as_ref().map(|(_, n)| n == &name).unwrap_or(false) {
                    let _ = CloseDesktop(hdesk); // той самий стіл — нічого не міняємо
                } else if SetThreadDesktop(hdesk).is_ok() {
                    if let Some((old, _)) = cur.take() {
                        let _ = CloseDesktop(old);
                    }
                    *cur = Some((hdesk, name));
                } else {
                    let _ = CloseDesktop(hdesk);
                }
            });
        }

        fn drain(rtc: &mut Rtc, sock: &UdpSocket, chan: &mut Option<ChannelId>, inbox: &mut Vec<Vec<u8>>) {
            loop {
                match rtc.poll_output() {
                    Ok(Output::Timeout(_)) => return,
                    Ok(Output::Transmit(t)) => {
                        let _ = sock.send_to(&t.contents, t.destination);
                    }
                    Ok(Output::Event(Event::ChannelOpen(id, _))) => *chan = Some(id),
                    Ok(Output::Event(Event::ChannelData(d))) => inbox.push(d.data),
                    Ok(Output::Event(_)) => {}
                    Err(_) => return,
                }
            }
        }

        fn recv_one(rtc: &mut Rtc, sock: &UdpSocket, my_addr: SocketAddr) {
            // Err (WouldBlock/Timeout/ConnectionReset) — не фатально, просто немає пакета.
            let mut buf = [0u8; 2048];
            if let Ok((n, source)) = sock.recv_from(&mut buf) {
                if let Ok(contents) = buf[..n].try_into() {
                    let _ = rtc.handle_input(Input::Receive(
                        Instant::now(),
                        Receive {
                            proto: Protocol::Udp,
                            source,
                            destination: my_addr,
                            contents,
                        },
                    ));
                }
            }
        }

        fn write_session(rtc: &mut Rtc, cid: ChannelId, msg: &SessionMessage) {
            if let Ok(bytes) = serde_json::to_vec(msg) {
                if let Some(mut ch) = rtc.channel(cid) {
                    let _ = ch.write(true, &bytes);
                }
            }
        }

        struct Established {
            rtc: Rtc,
            sock: UdpSocket,
            my_addr: SocketAddr,
            chan: ChannelId,
            key: [u8; 32],
        }

        /// Драйвити str0m + PAKE до підтвердження ключа.
        fn drive_until_confirmed(
            mut rtc: Rtc,
            sock: UdpSocket,
            my_addr: SocketAddr,
            own_fp: String,
            peer_fp: String,
            password: &[u8],
        ) -> Result<Established, String> {
            sock.set_read_timeout(Some(Duration::from_millis(50)))
                .map_err(|e| e.to_string())?;
            let mut chan: Option<ChannelId> = None;
            let mut inbox: Vec<Vec<u8>> = Vec::new();
            let mut hs: Option<Handshake> = None;
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                if let Some(h) = hs.as_ref() {
                    if let Some(key) = h.confirmed_key() {
                        return Ok(Established {
                            key: *key,
                            chan: chan.expect("chan"),
                            rtc,
                            sock,
                            my_addr,
                        });
                    }
                    if h.is_failed() {
                        return Err("PAKE FAILED".into());
                    }
                }
                if Instant::now() > deadline {
                    return Err("session establish timeout".into());
                }
                drain(&mut rtc, &sock, &mut chan, &mut inbox);
                if hs.is_none() {
                    if let Some(cid) = chan {
                        let (h, msg) = Handshake::start(password, own_fp.clone(), peer_fp.clone());
                        write_session(&mut rtc, cid, &msg);
                        hs = Some(h);
                        drain(&mut rtc, &sock, &mut chan, &mut inbox);
                    }
                }
                for raw in std::mem::take(&mut inbox) {
                    if let (Some(h), Some(cid)) = (hs.as_mut(), chan) {
                        if let Ok(m) = serde_json::from_slice::<SessionMessage>(&raw) {
                            if let Some(resp) = h.on_message(m) {
                                write_session(&mut rtc, cid, &resp);
                                drain(&mut rtc, &sock, &mut chan, &mut inbox);
                            }
                        }
                    }
                }
                recv_one(&mut rtc, &sock, my_addr);
                rtc.handle_input(Input::Timeout(Instant::now()))
                    .map_err(|e| e.to_string())?;
            }
        }

        /// Постійний host-серв: реєстрація → прийом → сесія → reconnect. Не повертається.
        pub fn serve(cfg: DeviceConfig) -> ! {
            let url = ws_url(&cfg.server_base);
            loop {
                if let Err(e) = serve_once(&url, &cfg) {
                    super::log_to("worker.log", &format!("host-стрім: {e}; reconnect за 2с"));
                }
                std::thread::sleep(Duration::from_secs(2));
            }
        }

        fn serve_once(url: &str, cfg: &DeviceConfig) -> Result<(), String> {
            let mut sc = SignalClient::connect(url).map_err(|e| e.to_string())?;
            sc.set_read_timeout(Some(Duration::from_secs(2)))
                .map_err(|e| e.to_string())?;
            sc.register(&cfg.device_id, &cfg.client_secret, "host")
                .map_err(|e| e.to_string())?;
            super::log_to("worker.log", "host-стрім зареєстровано — чекаю підключень");
            let password = cfg.password.as_bytes();
            loop {
                match sc.try_recv() {
                    Ok(Some(ServerMsg::IncomingRequest { session_id, .. })) => {
                        super::log_to("worker.log", &format!("вхідне підключення {session_id}"));
                        match serve_session(&mut sc, &session_id, password) {
                            Ok(()) => super::log_to("worker.log", "сесію завершено"),
                            Err(e) if e == "ws" => return Ok(()), // WS зламано → reconnect
                            Err(e) => super::log_to("worker.log", &format!("сесія: {e}")),
                        }
                    }
                    Ok(Some(_)) => {}                 // інше повідомлення — ігнор
                    Ok(None) => {}                    // такт читання (2с)
                    Err(_) => return Ok(()),          // WS закрито → reconnect
                }
            }
        }

        /// Прийняти один запит і провести сесію до завершення (стрім DXGI).
        fn serve_session(sc: &mut SignalClient, session_id: &str, password: &[u8]) -> Result<(), String> {
            sc.send(&ClientMsg::connect_accept(session_id)).map_err(|_| "ws".to_string())?;

            // Чекаємо connect_ready; паралельні запити — busy.
            let deadline = Instant::now() + Duration::from_secs(15);
            let sid = loop {
                if Instant::now() > deadline {
                    return Err("connect_ready timeout".into());
                }
                match sc.try_recv() {
                    Ok(Some(ServerMsg::ConnectReady { session_id, .. })) => break session_id,
                    Ok(Some(ServerMsg::IncomingRequest { session_id: other, .. })) => {
                        let _ = sc.send(&ClientMsg::connect_reject(&other, Some("busy")));
                    }
                    Ok(_) => {}
                    Err(_) => return Err("ws".into()),
                }
            };

            // str0m-пір (host=offerer). Loopback-кандидат (127.0.0.1) — для пульта на цій же
            // машині; srflx/TURN для віддаленого пульта додамо за потреби.
            let sock = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
            let my_addr = sock.local_addr().map_err(|e| e.to_string())?;
            let mut rtc = new_rtc(Instant::now());
            let cand = Candidate::host(my_addr, "udp").map_err(|e| e.to_string())?;
            rtc.add_local_candidate(cand.clone());
            let mut chan = None;
            let mut inbox = Vec::new();
            drain(&mut rtc, &sock, &mut chan, &mut inbox);

            let mut api = rtc.sdp_api();
            let _cid = api.add_channel("media".to_string());
            let (offer, pending) = api.apply().ok_or("offer no changes")?;
            drain(&mut rtc, &sock, &mut chan, &mut inbox);
            let offer_sdp = offer.to_sdp_string();
            let own_fp = fingerprint(&offer_sdp);
            sc.send(&ClientMsg::signal(&sid, "offer", json!({ "sdp": offer_sdp })))
                .map_err(|_| "ws".to_string())?;
            sc.send(&ClientMsg::signal(&sid, "ice", json!({ "cands": [cand.to_sdp_string()] })))
                .map_err(|_| "ws".to_string())?;

            // Чекаємо answer; далі ще ~2с збираємо trickle-ICE пульта (браузер шле
            // payload.cands масивом, по одному кандидату). Жодного конкретного кандидата
            // НЕ вимагаємо — для loopback вистачить нашого host-кандидата + prflx.
            let mut peer_fp = String::new();
            let mut pending = Some(pending);
            let mut answered = false;
            let mut deadline = Instant::now() + Duration::from_secs(20);
            loop {
                if Instant::now() > deadline {
                    if answered {
                        break;
                    }
                    return Err("answer timeout".into());
                }
                match sc.try_recv() {
                    Ok(Some(ServerMsg::Signal { kind, payload, .. })) => match kind.as_str() {
                        "answer" => {
                            let sdp = payload_str(&payload, "sdp").ok_or("no sdp")?;
                            peer_fp = fingerprint(&sdp);
                            let ans = SdpAnswer::from_sdp_string(&sdp).map_err(|e| e.to_string())?;
                            rtc.sdp_api()
                                .accept_answer(pending.take().ok_or("dbl answer")?, ans)
                                .map_err(|e| e.to_string())?;
                            drain(&mut rtc, &sock, &mut chan, &mut inbox);
                            answered = true;
                            deadline = Instant::now() + Duration::from_secs(2); // вікно на trickle
                        }
                        "ice" => {
                            apply_cands(&mut rtc, &payload);
                            drain(&mut rtc, &sock, &mut chan, &mut inbox);
                        }
                        _ => {}
                    },
                    Ok(Some(ServerMsg::IncomingRequest { session_id: other, .. })) => {
                        let _ = sc.send(&ClientMsg::connect_reject(&other, Some("busy")));
                    }
                    Ok(_) => {}
                    Err(_) => return Err("ws".into()),
                }
            }

            let mut est = drive_until_confirmed(rtc, sock, my_addr, own_fp, peer_fp, password)?;
            super::log_to("worker.log", "сесію підтверджено — стрімлю DXGI");

            // Стрім: DXGI-джерело (з перемиканням desktop) → H264 → E2E → чанки → datachannel.
            let (cap, rx) = start_primary_dxgi().map_err(|e| e.to_string())?;
            let mut enc: Option<H264Encoder> = None;
            let mut chunker = Chunker::new(DEFAULT_MAX_PAYLOAD);
            let mut sealer = StreamSealer::new(&est.key, STREAM_LABEL_MEDIA_H2C);
            let input_opener = StreamOpener::new(&est.key, STREAM_LABEL_INPUT_C2H); // ввід пульт→host
            let mut queue: VecDeque<Vec<u8>> = VecDeque::new();
            let mut chan_opt = Some(est.chan);
            let mut inbox = Vec::new();
            let mut last_encode = Instant::now() - Duration::from_secs(1);
            let mut injected = 0u64;
            let mut last_rebind = Instant::now() - Duration::from_secs(1);
            let mut active_mon = 0u32;
            send_monitors(&mut sealer, &mut chunker, &mut queue, active_mon); // показати список у пульті
            let mons = monitors_dxgi(); // кеш геометрії моніторів — для адресної інжекції миші
            let mut blanker: Option<Blanker> = None; // затемнення (PRD 5.10), не переживає сесію
            let mut input_locked = false; // блок фізичного вводу (BlockInput)

            while est.rtc.is_alive() {
                drain(&mut est.rtc, &est.sock, &mut chan_opt, &mut inbox);

                // Крок 7: вхідний ввід (пульт → host). Розшифрувати міткою ctrl c2h і
                // інжектити (миша/клавіатура/скрол; керівні повідомлення inject ігнорує).
                // SendInput діє на desktop потоку-викликача — тож перед інжекцією прив'язуємо
                // потік до АКТИВНОГО input-desktop (Default↔Winlogon), щоб ввід ішов на той
                // самий стіл, що показує захоплення (керування і на secure-desktop).
                let pending = std::mem::take(&mut inbox);
                if !pending.is_empty() && last_rebind.elapsed() >= Duration::from_millis(200) {
                    last_rebind = Instant::now();
                    unsafe { ensure_input_desktop() };
                }
                let mut bye = false;
                for raw in pending {
                    if raw == SESSION_BYE {
                        bye = true;
                        continue;
                    }
                    if let Ok(opened) = input_opener.open(&raw) {
                        if let Ok(ev) = serde_json::from_slice::<InputEvent>(&opened) {
                            match ev {
                                // Перемкнути монітор: змінити вихід DXGI + оновити список у пульті
                                // + скинути кодек (нова роздільність → новий keyframe).
                                InputEvent::Monitor { index } => {
                                    cap.set_output(index);
                                    active_mon = index;
                                    send_monitors(&mut sealer, &mut chunker, &mut queue, active_mon);
                                    enc = None;
                                    super::log_to("worker.log", &format!("перемикання монітора: {index}"));
                                }
                                // Затемнення (PRD 5.10): чорний оверлей із WDA_EXCLUDEFROMCAPTURE
                                // (локально чорно, пульт бачить). NB: перевірити взаємодію з DXGI-DDA.
                                InputEvent::Blank { enabled } => {
                                    if enabled && blanker.is_none() {
                                        blanker = Some(Blanker::show());
                                    } else if !enabled {
                                        if let Some(b) = blanker.take() {
                                            b.hide();
                                        }
                                    }
                                    super::log_to("worker.log", &format!("затемнення: {enabled}"));
                                }
                                // Блок фізичної миші/клавіатури (BlockInput; інжекція пульта діє далі).
                                InputEvent::InputLock { enabled } => {
                                    input_locked = input::block_physical(enabled) && enabled;
                                    super::log_to(
                                        "worker.log",
                                        &format!("блок вводу: {enabled} (застосовано={input_locked})"),
                                    );
                                }
                                other => {
                                    // Мишу мапимо на АКТИВНИЙ монітор (VIRTUALDESK), щоб
                                    // керування йшло на той екран, що показує захоплення.
                                    match mons.iter().find(|m| m.index == active_mon) {
                                        Some(m) => {
                                            input::inject_on_monitor(&other, m.x, m.y, m.width, m.height)
                                        }
                                        None => input::inject(&other),
                                    }
                                    injected += 1;
                                    if injected == 1 || injected.is_multiple_of(200) {
                                        super::log_to(
                                            "worker.log",
                                            &format!("ввід інжектовано: {injected}"),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                if bye {
                    super::log_to("worker.log", "пульт завершив сесію (BYE)");
                    break;
                }

                if let Ok(f) = rx.try_recv() {
                    if last_encode.elapsed() >= Duration::from_millis(33) {
                        if enc.is_none() {
                            match H264Encoder::new_scaled(f.width, f.height, f.width / 2, f.height / 2, 30, 4_000_000) {
                                Ok(e) => enc = Some(e),
                                // break (не return!), щоб дійти до блоку прибирання нижче й
                                // ЗНЯТИ BlockInput/затемнення — інакше фізичний ввід лишиться
                                // заблокованим після сесії (симетрично з Tier A managed_loop).
                                Err(e) => {
                                    super::log_to(
                                        "worker.log",
                                        &format!("енкодер не створено: {e}; завершую сесію"),
                                    );
                                    break;
                                }
                            }
                        }
                        if let Some(e) = enc.as_mut() {
                            if let Ok(unit) = e.encode_bgra(&f.data) {
                                if !unit.is_empty() {
                                    last_encode = Instant::now();
                                    let sealed = sealer.seal(&unit);
                                    for c in chunker.chunk(&sealed) {
                                        queue.push_back(c);
                                    }
                                }
                            }
                        }
                    }
                }

                while let Some(c) = queue.front() {
                    let ok = est
                        .rtc
                        .channel(est.chan)
                        .map(|mut ch| ch.write(true, c).unwrap_or(false))
                        .unwrap_or(false);
                    if ok {
                        queue.pop_front();
                    } else {
                        break;
                    }
                }
                drain(&mut est.rtc, &est.sock, &mut chan_opt, &mut inbox);
                recv_one(&mut est.rtc, &est.sock, est.my_addr);
                if est.rtc.handle_input(Input::Timeout(Instant::now())).is_err() {
                    break;
                }
            }

            // Безпека: затемнення й блок вводу НІКОЛИ не переживають сесію.
            if let Some(b) = blanker.take() {
                b.hide();
            }
            if input_locked {
                let _ = input::block_physical(false);
            }
            cap.stop();
            let _ = sc.send(&ClientMsg::session_close(session_id, Some("done")));
            Ok(())
        }
    }

    // ── Install / Uninstall (потрібні адмін-права) ──
    pub fn install() -> Res {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )?;
        let info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from("ZortilWatch Service"),
            service_type: SERVICE_TYPE,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: std::env::current_exe()?,
            launch_arguments: vec![],
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        };
        let service =
            manager.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
        let _ = service.set_description("ZortilWatch — керований доступ, зокрема на екрані входу.");
        println!("Службу '{SERVICE_NAME}' встановлено (AutoStart, LocalSystem).");
        log("install: службу створено");
        Ok(())
    }

    pub fn uninstall() -> Res {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service = manager.open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )?;
        if let Ok(s) = service.query_status() {
            if s.current_state != ServiceState::Stopped {
                let _ = service.stop();
                std::thread::sleep(Duration::from_secs(2));
            }
        }
        service.delete()?;
        println!("Службу '{SERVICE_NAME}' видалено.");
        log("uninstall: службу видалено");
        Ok(())
    }
}
