import { useCallback, useEffect, useRef, useState } from "react";
import {
  getPlatform,
  type ConfirmRequest,
  type InputEvent,
  type PasswordKind,
  type RemoteMonitor,
  type SessionHandle,
} from "./platform";

/** Пресети якості (кооперативні стелі; «авто» — говернор сам тримає бітрейт). */
const QUALITY_PRESETS: Record<string, { fps: number; bitrate: number; scale: number }> = {
  auto: { fps: 30, bitrate: 4_000_000, scale: 1 },
  quality: { fps: 30, bitrate: 8_000_000, scale: 1 },
  speed: { fps: 30, bitrate: 1_500_000, scale: 2 },
};
import { api, type AccountInfo } from "./api";
import { Auth } from "./screens/Auth";
import { AddressBook } from "./screens/AddressBook";
import "./App.css";

const platform = getPlatform();

type SelfDevice = { publicId: string; clientSecret: string };

function loadJSON<T>(key: string): T | null {
  const s = localStorage.getItem(key);
  if (!s) return null;
  try {
    return JSON.parse(s) as T;
  } catch {
    return null;
  }
}

/** Зрозуміле повідомлення для помилки підключення (коди сервера + транспортні збої). */
function humanConnectError(raw: string): string {
  const m = raw.toLowerCase();
  if (m.includes("rate_limited"))
    return "Забагато спроб підключення. Зачекайте хвилину й спробуйте знову.";
  if (m.includes("offline")) return "Пристрій зараз офлайн.";
  if (m.includes("busy")) return "Пристрій зайнятий — досягнуто ліміту одночасних підключень.";
  if (m.includes("forbidden")) return "Підключення відхилено: вас заблоковано або керований відмовив.";
  if (m.includes("not_found")) return "Пристрій із таким ID не знайдено.";
  if (m.includes("pake") || m.includes("timeout"))
    return "Не вдалося підтвердити пароль вчасно — перевірте пароль або підтвердження на керованому.";
  if (m.includes("ice") || m.includes("dtls") || m.includes("websocket"))
    return "Не вдалося встановити з'єднання (мережа або NAT). Спробуйте ще раз.";
  return raw;
}

/** Чи містить Annex-B буфер NAL заданого типу (7=SPS, 5=IDR). */
function hasNal(buf: Uint8Array, type: number): boolean {
  for (let i = 0; i + 3 < buf.length; ) {
    if (buf[i] === 0 && buf[i + 1] === 0 && buf[i + 2] === 1) {
      if ((buf[i + 3] & 0x1f) === type) return true;
      i += 3;
    } else {
      i += 1;
    }
  }
  return false;
}

export function App() {
  const [server, setServer] = useState(
    () => localStorage.getItem("zw_server") || "http://127.0.0.1:8787",
  );

  // Першозапуск десктопа: якщо адресу сервера ще не збережено, узяти типову з
  // zortilwatch.config.json поряд із .exe (постачання клієнта на власний сервер).
  useEffect(() => {
    if (localStorage.getItem("zw_server")) return;
    void platform
      .appConfig?.()
      .then((cfg) => {
        if (cfg.defaultServer) setServer(cfg.defaultServer);
      })
      .catch(() => {});
  }, []);
  const [account, setAccount] = useState<AccountInfo | null>(() =>
    loadJSON<AccountInfo>("zw_account"),
  );
  const [selfDevice, setSelfDevice] = useState<SelfDevice | null>(() => {
    const a = loadJSON<AccountInfo>("zw_account");
    return a ? loadJSON<SelfDevice>("zw_dev_" + a.accountId) : null;
  });
  const [session, setSession] = useState<SessionHandle | null>(null);
  const [targetId, setTargetId] = useState("");
  const [connecting, setConnecting] = useState(false);
  const [connectError, setConnectError] = useState("");
  const [control, setControl] = useState(true); // контроль активний за замовчуванням
  // Монітори керованого (з контрольного повідомлення сесії) + якість.
  const [monitors, setMonitors] = useState<RemoteMonitor[]>([]);
  const [activeMon, setActiveMon] = useState(0);
  const [qMode, setQMode] = useState("auto");
  const [custom, setCustom] = useState({ fps: 30, bitrate: 4_000_000, scale: 1 });
  // Файли (PRD 5.7) і буфер (PRD 5.8).
  const fsCapable = !!platform.fsDownload;
  const [filesOpen, setFilesOpen] = useState(false);
  const [localL, setLocalL] = useState<import("./platform").FsListing | null>(null);
  const [remoteL, setRemoteL] = useState<import("./platform").FsListing | null>(null);
  const [localSel, setLocalSel] = useState("");
  const [remoteSel, setRemoteSel] = useState("");
  const [xfers, setXfers] = useState<
    Record<number, { label: string; written: number; size: number; done: boolean; err?: string }>
  >({});
  const [clipSync, setClipSync] = useState(true);
  const lastClipRef = useRef("");
  const sessionRef = useRef<SessionHandle | null>(null);
  sessionRef.current = session;

  const canvasRef = useRef<HTMLCanvasElement>(null);
  const decoderRef = useRef<VideoDecoder | null>(null);
  const startedRef = useRef(false);
  const lastFrameRef = useRef(0);
  const controlRef = useRef(false);
  controlRef.current = control;

  // Watchdog: якщо кадри припинились (керований зник) — авто-повернення в книгу.
  useEffect(() => {
    if (!session) return;
    lastFrameRef.current = performance.now();
    const id = setInterval(() => {
      if (startedRef.current && performance.now() - lastFrameRef.current > 4000) {
        session.disconnect();
        decoderRef.current?.close();
        decoderRef.current = null;
        startedRef.current = false;
        setSession(null);
        setControl(true);
      }
    }, 1000);
    return () => clearInterval(id);
  }, [session]);

  // ── Host-режим (цей пристрій як керований) — лише десктоп (web не реалізує) ──
  const hostCapable = !!platform.startHost;
  const [hostActive, setHostActive] = useState(false);
  const [hostPassword, setHostPassword] = useState(() =>
    account ? localStorage.getItem("zw_hostpw_" + account.accountId) ?? "" : "",
  );
  const [oneTime, setOneTime] = useState<string | null>(null);
  const [hostError, setHostError] = useState("");
  const [autostart, setAutostart] = useState(false);
  const [confirmIncoming, setConfirmIncoming] = useState(
    () => !!account && localStorage.getItem("zw_host_confirm_" + account.accountId) === "1",
  );
  const [lockOnEnd, setLockOnEnd] = useState(
    () => !!account && localStorage.getItem("zw_host_lock_" + account.accountId) === "1",
  );
  // Безпека сесії (пульт): затемнення екрана керованого + блок його фізичного вводу.
  const [blank, setBlank] = useState(false);
  const [inputLock, setInputLock] = useState(false);
  // Вхідний запит, що чекає рішення людини (атендантний режим).
  const [pendingConfirm, setPendingConfirm] = useState<ConfirmRequest | null>(null);

  const startHostNow = async (permanent: string, confirm: boolean) => {
    if (!selfDevice) return;
    await platform.startHost?.({
      server,
      deviceId: selfDevice.publicId,
      clientSecret: selfDevice.clientSecret,
      permanentPassword: permanent || null, // порожньо — лише одноразовий код
      confirmIncoming: confirm,
      lockOnEnd,
      onOneTime: setOneTime,
      onConfirm: setPendingConfirm,
    });
  };

  const toggleLockOnEnd = async () => {
    if (!account) return;
    const next = !lockOnEnd;
    setLockOnEnd(next);
    localStorage.setItem("zw_host_lock_" + account.accountId, next ? "1" : "0");
    await platform.setLockOnEnd?.(next); // живий тумблер
  };

  // Рішення людини; ядро чекає ~30с, далі відмовляє саме — діалог прибираємо теж.
  const decide = (allow: boolean) => {
    if (!pendingConfirm) return;
    void platform.decideIncoming?.(pendingConfirm.requestId, allow);
    setPendingConfirm(null);
  };
  useEffect(() => {
    if (!pendingConfirm) return;
    const t = setTimeout(() => setPendingConfirm(null), 30_000);
    return () => clearTimeout(t);
  }, [pendingConfirm]);

  const toggleConfirmIncoming = async () => {
    if (!account) return;
    const next = !confirmIncoming;
    setConfirmIncoming(next);
    localStorage.setItem("zw_host_confirm_" + account.accountId, next ? "1" : "0");
    await platform.setConfirmIncoming?.(next); // живий тумблер, без рестарту host
  };

  // При старті: підтягнути стан автозапуску; синхронізувати host; якщо host БУВ увімкнений
  // (намір збережено) — авто-відновити (патерн RustDesk: процес сам піднімає host із конфігу).
  useEffect(() => {
    platform
      .getAutostart?.()
      .then(setAutostart)
      .catch(() => {});
    void (async () => {
      const st = await platform.hostStatus?.();
      if (st?.active) {
        // Host уже крутиться (перезавантаження webview) — код беремо зі стану ядра.
        setHostActive(true);
        setOneTime(st.oneTime ?? null);
        return;
      }
      const intended =
        account && localStorage.getItem("zw_host_on_" + account.accountId) === "1";
      if (intended && selfDevice) {
        try {
          await startHostNow(hostPassword, confirmIncoming);
          setHostActive(true);
        } catch {
          /* не вдалось авто-відновити — лишаємо вимкненим */
        }
      }
    })();
  }, []);

  const toggleHost = async () => {
    setHostError("");
    if (!account || !selfDevice) return;
    try {
      if (hostActive) {
        await platform.stopHost?.();
        localStorage.removeItem("zw_host_on_" + account.accountId);
        setHostActive(false);
        setOneTime(null);
      } else {
        if (hostPassword && hostPassword.length < 4) {
          setHostError("Постійний пароль — мінімум 4 символи (або лишіть порожнім)");
          return;
        }
        localStorage.setItem("zw_hostpw_" + account.accountId, hostPassword);
        await startHostNow(hostPassword, confirmIncoming);
        localStorage.setItem("zw_host_on_" + account.accountId, "1"); // намір для авто-відновлення
        setHostActive(true);
      }
    } catch (e) {
      setHostError((e as Error).message);
    }
  };

  // Новий код прилетить через onOneTime (ядро ротує за ≤2с); webview-перезавантаження
  // підстраховує повторне опитування hostStatus.
  const refreshOneTime = async () => {
    setHostError("");
    try {
      await platform.refreshOneTime?.();
      setTimeout(() => {
        void platform.hostStatus?.().then((st) => {
          if (st?.oneTime) setOneTime(st.oneTime);
        });
      }, 2500);
    } catch (e) {
      setHostError((e as Error).message);
    }
  };

  const toggleAutostart = async () => {
    setHostError("");
    try {
      const next = !autostart;
      await platform.setAutostart?.(next);
      setAutostart(next);
    } catch (e) {
      setHostError((e as Error).message);
    }
  };

  const onFrame = useCallback((h264: Uint8Array) => {
    lastFrameRef.current = performance.now();
    // Контрольне повідомлення сесії (JSON, перший байт '{') — не відео.
    if (h264.length > 0 && h264[0] === 0x7b) {
      try {
        /* eslint-disable @typescript-eslint/no-explicit-any */
        const ctrl = JSON.parse(new TextDecoder().decode(h264)) as any;
        /* eslint-enable @typescript-eslint/no-explicit-any */
        if (Array.isArray(ctrl.monitors)) {
          setMonitors(ctrl.monitors as RemoteMonitor[]);
          setActiveMon(ctrl.active ?? 0);
        }
        if (ctrl.fsList) setRemoteL(ctrl.fsList);
        if (ctrl.fsProgress) {
          const p = ctrl.fsProgress;
          setXfers((x) => ({
            ...x,
            [p.id]: { ...(x[p.id] ?? { label: `#${p.id}` }), written: p.offset, size: p.size, done: !!p.done },
          }));
        }
        if (ctrl.fsLocal) {
          const p = ctrl.fsLocal;
          setXfers((x) => ({
            ...x,
            [p.id]: { ...(x[p.id] ?? { label: `#${p.id}`, size: 0 }), written: p.written, done: false },
          }));
        }
        if (ctrl.fsDone) {
          const d = ctrl.fsDone;
          setXfers((x) => ({
            ...x,
            [d.id]: { ...(x[d.id] ?? { label: `#${d.id}`, written: 0, size: 0 }), done: true, err: d.err ?? undefined },
          }));
        }
        if (ctrl.clipboard?.text != null) {
          lastClipRef.current = ctrl.clipboard.text;
          void navigator.clipboard?.writeText(ctrl.clipboard.text).catch(() => {});
        }
      } catch {
        /* не JSON — ігноруємо */
      }
      return;
    }
    const canvas = canvasRef.current;
    if (!canvas) return;
    if (!decoderRef.current) {
      const dec = new VideoDecoder({
        output: (frame) => {
          const ctx = canvas.getContext("2d");
          if (ctx) {
            if (canvas.width !== frame.displayWidth) canvas.width = frame.displayWidth;
            if (canvas.height !== frame.displayHeight) canvas.height = frame.displayHeight;
            ctx.drawImage(frame, 0, 0);
          }
          frame.close();
        },
        error: () => {},
      });
      dec.configure({ codec: "avc1.42E01E", optimizeForLatency: true });
      decoderRef.current = dec;
    }
    const dec = decoderRef.current;
    const key = hasNal(h264, 7) || hasNal(h264, 5);
    if (!startedRef.current) {
      if (!key) return;
      startedRef.current = true;
    }
    try {
      dec.decode(
        new EncodedVideoChunk({
          type: key ? "key" : "delta",
          timestamp: performance.now() * 1000,
          data: h264,
        }),
      );
    } catch {
      /* ігноруємо збій декоду окремого кадру */
    }
  }, []);

  const onAuthed = async (a: AccountInfo) => {
    localStorage.setItem("zw_server", server);
    localStorage.setItem("zw_account", JSON.stringify(a));
    let dev = loadJSON<SelfDevice>("zw_dev_" + a.accountId);
    if (!dev) {
      const nd = await api.createDevice(server, a.token, "Пульт (" + platform.kind + ")");
      dev = { publicId: nd.publicId, clientSecret: nd.clientSecret };
      localStorage.setItem("zw_dev_" + a.accountId, JSON.stringify(dev));
    }
    setSelfDevice(dev);
    setAccount(a);
  };

  const logout = () => {
    localStorage.removeItem("zw_account");
    setAccount(null);
    setSelfDevice(null);
  };

  const doConnect = async (target: string, password: string, kind: PasswordKind) => {
    if (!selfDevice) {
      setConnectError("Немає ідентичності пристрою пульта");
      return;
    }
    setConnecting(true);
    setConnectError("");
    startedRef.current = false;
    setMonitors([]);
    setActiveMon(0);
    setQMode("auto");
    setBlank(false);
    setInputLock(false);
    // Скинути стан попередньої сесії, щоб файли/передачі/буфер не протекли в нову.
    setFilesOpen(false);
    setLocalL(null);
    setRemoteL(null);
    setLocalSel("");
    setRemoteSel("");
    setXfers({});
    setClipSync(true);
    lastClipRef.current = "";
    try {
      // Разовий код вводять із чужого екрана — нормалізуємо (регістр/пробіли/дефіси).
      const pw =
        kind === "one_time" ? password.replace(/[\s-]/g, "").toUpperCase() : password;
      const s = await platform.connect({
        server,
        deviceId: selfDevice.publicId,
        clientSecret: selfDevice.clientSecret,
        password: pw,
        passwordKind: kind,
        targetId: target,
        onFrame,
      });
      setSession(s);
      setTargetId(target);
    } catch (e) {
      setConnectError(humanConnectError((e as Error).message));
    } finally {
      setConnecting(false);
    }
  };

  const doWake = async (targetId: string) => {
    if (!selfDevice) throw new Error("Немає ідентичності пристрою пульта");
    return await platform.wake({
      server,
      deviceId: selfDevice.publicId,
      clientSecret: selfDevice.clientSecret,
      targetId,
    });
  };

  const disconnect = () => {
    session?.disconnect();
    setSession(null);
    decoderRef.current?.close();
    decoderRef.current = null;
    startedRef.current = false;
    setControl(true);
  };

  const send = (ev: InputEvent) => {
    if (controlRef.current) session?.sendInput(ev);
  };
  // Якість/монітор — НЕ ввід: працюють і в режимі «Перегляд» (повз тумблер керування).
  const sendQuality = (p: { fps: number; bitrate: number; scale: number }) =>
    session?.sendInput({ t: "quality", ...p });
  const changeQMode = (mode: string) => {
    setQMode(mode);
    sendQuality(mode === "custom" ? custom : QUALITY_PRESETS[mode]);
  };
  const changeCustom = (p: Partial<typeof custom>) => {
    const next = { ...custom, ...p };
    setCustom(next);
    sendQuality(next);
  };
  const switchMonitor = (index: number) => {
    setActiveMon(index); // оптимістично; контрольне повідомлення підтвердить
    session?.sendInput({ t: "monitor", index });
  };

  // ── Файли: навігація обох панелей і передачі ──
  const joinPath = (dir: string, name: string) =>
    dir === "" ? name : dir.replace(/[\\/]+$/, "") + "\\" + name;
  const parentPath = (p: string) => {
    const trimmed = p.replace(/[\\/]+$/, "");
    const i = trimmed.lastIndexOf("\\");
    if (i <= 2) return ""; // диск (C:) → корені
    return trimmed.slice(0, i);
  };
  const loadLocal = (path: string) => {
    setLocalSel("");
    void platform.fsLocalList?.(path).then(setLocalL).catch(() => {});
  };
  const loadRemote = (path: string) => {
    setRemoteSel("");
    session?.sendInput({ t: "fs_list", path });
  };
  const openFiles = () => {
    setFilesOpen(true);
    if (!localL) loadLocal("");
    if (!remoteL) loadRemote("");
  };
  const startDownload = async () => {
    if (!remoteSel || !remoteL || !localL) return;
    const remote = joinPath(remoteL.path, remoteSel);
    const local = joinPath(localL.path === "" ? "C:\\" : localL.path, remoteSel);
    const id = await platform.fsDownload?.(remote, local);
    if (id != null) setXfers((x) => ({ ...x, [id]: { label: "← " + remoteSel, written: 0, size: 0, done: false } }));
  };
  const startUpload = async () => {
    if (!localSel || !localL || !remoteL) return;
    const local = joinPath(localL.path, localSel);
    const remote = joinPath(remoteL.path === "" ? "C:\\" : remoteL.path, localSel);
    const id = await platform.fsUpload?.(local, remote);
    if (id != null) setXfers((x) => ({ ...x, [id]: { label: "→ " + localSel, written: 0, size: 0, done: false } }));
  };
  const toggleClipSync = () => {
    const next = !clipSync;
    setClipSync(next);
    session?.sendInput({ t: "clipboard_sync", enabled: next });
  };
  // Буфер пульт→керований: полінг локального буфера (лише десктоп, під фокусом).
  useEffect(() => {
    if (!session || !clipSync || platform.kind !== "desktop") return;
    const t = setInterval(async () => {
      if (!document.hasFocus()) return;
      try {
        const text = await navigator.clipboard.readText();
        if (text && text !== lastClipRef.current && text.length <= 262_144) {
          lastClipRef.current = text;
          sessionRef.current?.sendInput({ t: "clipboard", text });
        }
      } catch {
        /* буфер недоступний без фокуса — пропустити */
      }
    }, 2000);
    return () => clearInterval(t);
  }, [session, clipSync]);
  const norm = (clientX: number, clientY: number) => {
    const r = canvasRef.current!.getBoundingClientRect();
    return { x: (clientX - r.left) / r.width, y: (clientY - r.top) / r.height };
  };
  const buttonOf = (b: number): "left" | "right" | "middle" =>
    b === 2 ? "right" : b === 1 ? "middle" : "left";

  // Діалог підтвердження вхідного підключення — на БУДЬ-ЯКОМУ екрані (машина може
  // хостити й одночасно керувати іншою).
  const confirmDialog = pendingConfirm && (
    <div className="modal-bg">
      <div className="card" onClick={(e) => e.stopPropagation()}>
        <h3 className="modal-title">Вхідне підключення</h3>
        <p className="muted">
          Хтось хоче підключитися до цього пристрою (
          {pendingConfirm.passwordKind === "one_time" ? "разовий код" : "постійний пароль"}
          ). Дозволити?
        </p>
        <div className="row" style={{ marginTop: 14 }}>
          <button className="btn btn-primary" onClick={() => decide(true)}>
            Дозволити
          </button>
          <button className="tbtn danger" onClick={() => decide(false)}>
            Відхилити
          </button>
        </div>
      </div>
    </div>
  );

  // ── Маршрутизація екранів ──
  if (!account) {
    return (
      <Auth
        server={server}
        setServer={setServer}
        platformKind={platform.kind}
        onAuthed={onAuthed}
      />
    );
  }

  if (!session) {
    return (
      <>
        {confirmDialog}
        <AddressBook
        server={server}
        token={account.token}
        selfId={selfDevice?.publicId ?? "—"}
          connecting={connecting}
          connectError={connectError}
          onConnect={doConnect}
          onWake={doWake}
          onLogout={logout}
          host={
            hostCapable
              ? {
                  active: hostActive,
                  password: hostPassword,
                  oneTime,
                  error: hostError,
                  onPasswordChange: setHostPassword,
                  onToggle: () => void toggleHost(),
                  onRefreshOneTime: () => void refreshOneTime(),
                  autostart,
                  onToggleAutostart: () => void toggleAutostart(),
                  confirmIncoming,
                  onToggleConfirm: () => void toggleConfirmIncoming(),
                  lockOnEnd,
                  onToggleLockOnEnd: () => void toggleLockOnEnd(),
                }
              : null
          }
        />
      </>
    );
  }

  return (
    <div className="session">
      {confirmDialog}
      <canvas
        ref={canvasRef}
        tabIndex={0}
        className={"screen-full" + (control ? " control" : "")}
        onMouseMove={(e) => {
          const { x, y } = norm(e.clientX, e.clientY);
          send({ t: "mouse_move", x, y });
        }}
        onMouseDown={(e) => {
          if (controlRef.current) e.preventDefault();
          send({ t: "mouse_button", button: buttonOf(e.button), down: true });
        }}
        onMouseUp={(e) => send({ t: "mouse_button", button: buttonOf(e.button), down: false })}
        onContextMenu={(e) => e.preventDefault()}
        onWheel={(e) => send({ t: "scroll", dx: -e.deltaX / 120, dy: -e.deltaY / 120 })}
        onKeyDown={(e) => {
          if (controlRef.current) e.preventDefault();
          send({ t: "key", code: e.keyCode, down: true });
        }}
        onKeyUp={(e) => {
          if (controlRef.current) e.preventDefault();
          send({ t: "key", code: e.keyCode, down: false });
        }}
      />

      <div className="overlay-bar">
        <span className="dot" />
        <span className="peer">{targetId}</span>
        <span className="spacer" />
        {monitors.length > 1 ? (
          <select
            className="osel"
            title={`Моніторів: ${monitors.length}`}
            value={String(activeMon)}
            onChange={(e) => switchMonitor(Number(e.target.value))}
          >
            {monitors.map((m) => (
              <option key={m.index} value={m.index}>
                {`Монітор ${m.index + 1}/${monitors.length}${m.primary ? " ★" : ""}`}
              </option>
            ))}
          </select>
        ) : (
          monitors.length === 1 && <span className="oinfo">1 монітор</span>
        )}
        <select
          className="osel"
          title="Якість зображення"
          value={qMode}
          onChange={(e) => changeQMode(e.target.value)}
        >
          <option value="auto">Авто</option>
          <option value="quality">Найкраща якість</option>
          <option value="speed">Найвища швидкість</option>
          <option value="custom">Власні…</option>
        </select>
        {qMode === "custom" && (
          <>
            <select
              className="osel"
              title="Кадри/с"
              value={String(custom.fps)}
              onChange={(e) => changeCustom({ fps: Number(e.target.value) })}
            >
              {[15, 30, 60].map((f) => (
                <option key={f} value={f}>{`${f} к/с`}</option>
              ))}
            </select>
            <select
              className="osel"
              title="Бітрейт (стеля)"
              value={String(custom.bitrate)}
              onChange={(e) => changeCustom({ bitrate: Number(e.target.value) })}
            >
              {[1_000_000, 2_000_000, 4_000_000, 8_000_000].map((b) => (
                <option key={b} value={b}>{`${b / 1_000_000} Мбіт/с`}</option>
              ))}
            </select>
            <select
              className="osel"
              title="Масштаб роздільності"
              value={String(custom.scale)}
              onChange={(e) => changeCustom({ scale: Number(e.target.value) })}
            >
              <option value="1">100%</option>
              <option value="2">50%</option>
            </select>
          </>
        )}
        <button
          className="obtn"
          onClick={() => setControl((c) => !c)}
          title="Перемкнути керування/перегляд"
        >
          {control ? "🖱 Керування" : "👁 Перегляд"}
        </button>
        <button
          className="obtn"
          onClick={() => canvasRef.current?.requestFullscreen?.()}
          title="На весь екран"
        >
          ⛶
        </button>
        {fsCapable && (
          <button className="obtn" onClick={openFiles} title="Передача файлів">
            📁 Файли
          </button>
        )}
        <button
          className="obtn"
          onClick={toggleClipSync}
          title="Синхронізація буфера обміну (приватність)"
        >
          {clipSync ? "📋 Буфер: УВІМК" : "📋 Буфер: вимк"}
        </button>
        <button
          className="obtn"
          onClick={() => {
            const next = !blank;
            setBlank(next);
            session?.sendInput({ t: "blank", enabled: next });
          }}
          title="Затемнити екран керованого (людина поруч бачить чорне, ви — екран)"
        >
          {blank ? "🌓 Екран: чорний" : "🌓 Затемнити"}
        </button>
        <button
          className="obtn"
          onClick={() => {
            const next = !inputLock;
            setInputLock(next);
            session?.sendInput({ t: "input_lock", enabled: next });
          }}
          title="Заблокувати фізичні мишу/клавіатуру керованого (потрібні права адміністратора на ньому)"
        >
          {inputLock ? "⛔ Ввід: заблоковано" : "⛔ Блок вводу"}
        </button>
        <button className="obtn danger" onClick={disconnect}>
          Завершити
        </button>
      </div>

      {filesOpen && (
        <div className="files-panel">
          <div className="files-head">
            <b>Файли</b>
            <span className="spacer" />
            <button className="obtn" onClick={() => setFilesOpen(false)}>
              Закрити
            </button>
          </div>
          <div className="files-cols">
            {(
              [
                ["Цей пристрій", localL, localSel, setLocalSel, loadLocal],
                ["Керований", remoteL, remoteSel, setRemoteSel, loadRemote],
              ] as const
            ).map(([title, list, sel, setSel, load]) => (
              <div className="files-col" key={title}>
                <div className="files-path">
                  <b>{title}</b>: {list?.path || "Диски"}
                  {list && list.path !== "" && (
                    <button className="link" onClick={() => load(parentPath(list.path))}>
                      ⬆ вгору
                    </button>
                  )}
                </div>
                {list?.err && <p className="status err">{list.err}</p>}
                <div className="files-list">
                  {(list?.entries ?? []).map((e) => (
                    <div
                      key={e.name}
                      className={"fent" + (sel === e.name ? " sel" : "")}
                      onClick={() => (e.dir ? load(joinPath(list!.path, e.name)) : setSel(e.name))}
                    >
                      {e.dir ? "📁" : "📄"} {e.name}
                      {!e.dir && <span className="muted"> {(e.size / 1024).toFixed(0)} КБ</span>}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
          <div className="row files-actions">
            <button className="tbtn accent" disabled={!localSel} onClick={() => void startUpload()}>
              → Надіслати на керований
            </button>
            <button className="tbtn accent" disabled={!remoteSel} onClick={() => void startDownload()}>
              ← Завантажити сюди
            </button>
          </div>
          {Object.entries(xfers).map(([id, x]) => (
            <div className="xfer" key={id}>
              <span>{x.label}</span>
              <span className="muted">
                {x.err
                  ? "помилка: " + x.err
                  : x.done
                    ? "готово"
                    : x.size > 0
                      ? `${((x.written / x.size) * 100).toFixed(0)}%`
                      : `${(x.written / 1048576).toFixed(1)} МБ`}
              </span>
              {!x.done && (
                <button className="link" onClick={() => void platform.fsCancel?.(Number(id))}>
                  скасувати
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
