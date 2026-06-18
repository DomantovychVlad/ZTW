# Етап 4 — Керований на екрані входу / secure-desktop (Windows-служба)

План реалізації для [TASKS.md](../TASKS.md) Етап 4. Підтверджено проти Microsoft Learn
і **вихідного коду RustDesk** (`src/platform/windows.cc` + `windows.rs`). RustDesk —
**AGPL**: лише вивчення архітектури, **код не копіюємо**; реалізуємо з документації MS Learn.

## Несуче рішення

Поточний пайплайн (WGC + Media Foundation + SendInput) **структурно не дістає** до
екрана входу/UAC/secure-desktop. WGC — пісочниця WinRT, що вимагає інтерактивної сесії;
для Winlogon/UAC немає capture-item. **Робочий метод:** **DXGI Desktop Duplication**
(`IDXGIOutput1::DuplicateOutput`) у процесі під **SYSTEM**, чий потік захоплення прив'язано
до поточного **input-desktop** через `SetThreadDesktop(OpenInputDesktop(...))`.
`DuplicateOutput` повертає `E_ACCESSDENIED`, якщо процес не LOCAL_SYSTEM — це й є контракт
доступу до secure-desktop.

## Архітектура: два процеси (як у RustDesk)

```
SYSTEM-СЛУЖБА (session 0, автозапуск, LocalSystem)
  • windows-service: SCM-lifecycle
  • монітор сесій/десктопів; мінтить токени; наглядає за воркером
  • НЕ торкається кадрів
        │ CreateProcessAsUserW(token, lpDesktop)  + named pipe (control)
        ▼
ВОРКЕР (у активній сесії, на input-desktop)
  • SetThreadDesktop(OpenInputDesktop()) на потоці захоплення
  • DXGI Desktop Duplication → BGRA → H.264 (MF) → WebRTC datachannel
  • SendInput на тому ж потоці; стежить за зміною імені input-desktop і виходить
```

Мережа/WebRTC — у **воркері** (не гнати ~500 МБ/с BGRA крізь IPC у session 0). Служба
володіє лише lifecycle+нагляд. При перемиканні десктопу — простий шлях: старий воркер
виходить, спавниться новий (короткий «reconnecting»-розрив, ~200–500 мс).

## Мінтинг токена (session-0 isolation)

- **Користувач залогінений:** `WTSGetActiveConsoleSessionId` → `WTSQueryUserToken`
  (потрібен `SeTcbPrivilege`) → `DuplicateTokenEx` → `CreateEnvironmentBlock` →
  `CreateProcessAsUserW(lpDesktop=L"winsta0\\default")`.
- **Екран входу (нікого немає):** `WTSQueryUserToken` не дасть токен. Технiка RustDesk —
  **викрасти токен `winlogon.exe`** цільової сесії: `CreateToolhelp32Snapshot` →
  знайти `winlogon.exe` з потрібним `ProcessIdToSessionId` → `OpenProcess` →
  `OpenProcessToken(TOKEN_ALL_ACCESS)` → `CreateProcessAsUserW`. Цей токен — SYSTEM,
  валідний у консольній сесії навіть без логіну.
- `lpDesktop` задає лише ПОЧАТКОВИЙ desktop і **не слідує** за перемиканнями — воркер
  мусить динамічно `SetThreadDesktop` на поточний input-desktop.

## Цикл захоплення + перемикання десктопу

`AcquireNextFrame` повертає `DXGI_ERROR_ACCESS_LOST` на КОЖНОМУ перемиканні Default↔Winlogon,
появі/зникненні UAC, зміні роздільної/режиму DWM — це **норма**, не помилка: відпустити
duplication і пересоздати (часто й D3D-девайс, бо він desktop-relative).

```
loop {
  if try_change_desktop() {            // input-desktop змінився (OpenInputDesktop+UOI_NAME порівняння імен)
      drop(dup); drop(device);         // прив'язані до старого десктопу
      (device, dup) = create_capture(); // на новому: SetThreadDesktop → D3D11CreateDevice → DuplicateOutput
  }
  match dup.AcquireNextFrame(15ms, …) {
      Ok        => { encode(); dup.ReleaseFrame(); }   // ReleaseFrame ОБОВ'ЯЗКОВО щоразу
      ACCESS_LOST => { dup = recreate(); }
      WAIT_TIMEOUT => {}
      SESSION_DISCONNECTED => break,
  }
}
```

**UAC-промпт — це зміна DESKTOP, а не сесії:** `WM_WTSSESSION_CHANGE` НЕ спрацює; ловить
лише опитування `OpenInputDesktop`+`GetUserObjectInformationW(UOI_NAME)` (~10–30 Гц на
потоці воркера). Імена: `"Default"`, `"Winlogon"`, `"Screen-saver"`. На рівні сесії
(lock/unlock) додатково `WTSRegisterSessionNotification`/`WM_WTSSESSION_CHANGE`.

## Ввід + Ctrl+Alt+Del

`SendInput` діє лише на desktop потоку-викликача → інжекція з того ж desktop-прив'язаного
потоку. CAD не синтезувати через SendInput — лише **`SendSAS`** (sas.dll): потрібна політика
`HKLM\...\Policies\System\SoftwareSASGeneration=3` + UAC увімкнено; викликати з SYSTEM,
`SendSAS(FALSE)`. На Winlogon вимкнути clipboard-listeners (відоме джерело крашів у lock).

## Крейти (пермісивні) + привілеї

- `windows-service` (MIT/Apache) — SCM control handler + install (`account_name: None` =
  LocalSystem, `ServiceStartType::AutoStart`).
- `windows` (MIT/Apache) — features: `Win32_System_RemoteDesktop`,
  `Win32_System_StationsAndDesktops`, `Win32_Security`, `Win32_System_Threading`,
  `Win32_System_Environment`, `Win32_System_Diagnostics_ToolHelp`, `Win32_Graphics_Dxgi`,
  `Win32_Graphics_Direct3D11`, `Win32_UI_Input_KeyboardAndMouse`. `SendSAS` — оголосити FFI вручну.
- Привілеї (є в токені LocalSystem, але **вимкнені** — увімкнути через
  `LookupPrivilegeValueW`+`AdjustTokenPrivileges`): `SeTcbPrivilege` (WTSQueryUserToken),
  `SeAssignPrimaryTokenPrivilege`, `SeIncreaseQuotaPrivilege` (CreateProcessAsUser).

## Порядок збірки (інкрементально)

1. `windows-service` скелет + install/uninstall (AutoStart LocalSystem) → стартує на boot.
2. Монітор: `WTSGetActiveConsoleSessionId` + `WTSRegisterSessionNotification`, лог переходів.
3. Мінтинг токена → `CreateProcessAsUserW` тривіального воркера в `winsta0\default`.
4. Захоплення воркера: `SetThreadDesktop(OpenInputDesktop)` → `D3D11CreateDevice` →
   `DuplicateOutput` → `AcquireNextFrame` (інтерактивний desktop).
5. **Віха:** цикл перемикання (крок вище) + викликати UAC → переконатися, що видно
   secure-desktop. Це доказ усієї тези.
6. Перенести наш MF-H.264-енкодер + WebRTC у воркер; переконект при рестарті воркера.
7. Ввід на тому ж desktop-потоці + `SendSAS` для CAD.

## Топ-граблі

- DXGI-duplication тримати у воркері в активній сесії, **не** в session 0 (на Win11 у
  session-0 процесі duplication гине при lock).
- `E_ACCESSDENIED` від `DuplicateOutput` = не SYSTEM / не той desktop.
- ліміт 4 одночасні duplications/сесію → `DXGI_ERROR_NOT_CURRENTLY_AVAILABLE`; не текти об'єктами.
- desktop ставити ДО створення D3D-девайса (вони desktop-relative).

## Джерела

RustDesk (reference, не копіювати): `src/platform/windows.{rs,cc}`, `libs/scrap/src/dxgi/mod.rs`,
`src/server/input_service.rs`. MS Learn: WTSQueryUserToken, IDXGIOutput1::DuplicateOutput,
IDXGIOutputDuplication::AcquireNextFrame, OpenInputDesktop, SendSAS, DXGIDesktopDuplication sample.
`windows-service` crate (mullvad). Підтвердження «DXGI-as-SYSTEM, не WGC»: discuss-webrtc,
LizardByte/Sunshine #3487, gnif/LookingGlass #263.
