import { useEffect, useState } from "react";
import { api, type Device, type Group } from "../api";
import type { PasswordKind } from "../platform";
import { Field } from "../widgets";

/** Розбити код на групи по 4 для читабельності (вводити можна як завгодно). */
function fmtCode(code: string): string {
  return code.replace(/(.{4})(?=.)/g, "$1 ");
}

/** Зрозумілі повідомлення для кодів помилок сервера. */
function human(e: Error): string {
  if (e.message === "group_exists") return "Група з таким ім'ям уже існує";
  if (e.message === "not_found" || e.message === "group_not_found")
    return "Групу не знайдено (можливо, її щойно видалили)";
  if (e.message === "device_not_found") return "Пристрій не знайдено";
  return e.message;
}

export function AddressBook(props: {
  server: string;
  token: string;
  selfId: string;
  connecting: boolean;
  connectError: string;
  onConnect: (targetId: string, password: string, kind: PasswordKind) => void;
  onWake: (targetId: string) => Promise<{ status: string; helpers: number }>;
  onLogout: () => void;
  /** Host-режим (керований) — лише десктоп; null на вебі (пульт-only). */
  host?: {
    active: boolean;
    password: string;
    /** Поточний одноразовий код підключення (генерує ядро). */
    oneTime: string | null;
    error: string;
    onPasswordChange: (s: string) => void;
    onToggle: () => void;
    onRefreshOneTime: () => void;
    autostart: boolean;
    onToggleAutostart: () => void;
    /** Атендантний режим: підтверджувати кожне підключення вручну. */
    confirmIncoming: boolean;
    onToggleConfirm: () => void;
    /** Автоблокування Windows після кожної сесії (PRD 5.10). */
    lockOnEnd: boolean;
    onToggleLockOnEnd: () => void;
  } | null;
}) {
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [groups, setGroups] = useState<Group[] | null>(null);
  const [err, setErr] = useState("");
  const [target, setTarget] = useState<Device | null>(null);
  const [password, setPassword] = useState("");
  const [pwKind, setPwKind] = useState<PasswordKind>("one_time");
  const [newDev, setNewDev] = useState<{ publicId: string; clientSecret: string } | null>(null);
  // Модалка групи: без id — створення, з id — перейменування.
  const [groupModal, setGroupModal] = useState<{ id?: string; name: string } | null>(null);
  const [groupErr, setGroupErr] = useState("");
  const [groupBusy, setGroupBusy] = useState(false);
  // «Безпека»: 2FA + журнал аудиту + чорний список для МОГО пристрою (PRD 5.10).
  const [secOpen, setSecOpen] = useState(false);
  const [totpSetup, setTotpSetup] = useState<{ secret: string; uri: string } | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [secMsg, setSecMsg] = useState("");
  const [auditRows, setAuditRows] = useState<
    { event: string; deviceId?: string; fromInfo?: string; at: string }[] | null
  >(null);
  const [blockedText, setBlockedText] = useState("");
  // Пробудження (PRD 5.9): busy + повідомлення на пристрій.
  const [waking, setWaking] = useState<string | null>(null);
  const [wakeMsg, setWakeMsg] = useState<Record<string, string>>({});

  const wake = async (publicId: string) => {
    setWaking(publicId);
    setWakeMsg((m) => ({ ...m, [publicId]: "Будимо…" }));
    try {
      const r = await props.onWake(publicId);
      const text =
        r.status === "dispatched"
          ? `Сигнал надіслано (помічників: ${r.helpers}). ПК має увімкнутись за ~хвилину.`
          : r.status === "no_helper"
            ? "Немає помічника онлайн у мережі цього ПК."
            : "Пробудження недоступне (Wake-on-LAN не налаштовано).";
      setWakeMsg((m) => ({ ...m, [publicId]: text }));
    } catch (e) {
      setWakeMsg((m) => ({ ...m, [publicId]: human(e as Error) }));
    } finally {
      setWaking(null);
    }
  };

  const openSecurity = async () => {
    setSecOpen(true);
    setSecMsg("");
    setTotpSetup(null);
    setTotpCode("");
    try {
      setAuditRows(await api.audit(props.server, props.token));
    } catch {
      setAuditRows([]);
    }
    const self = (devices ?? []).find((d) => d.publicId === props.selfId);
    setBlockedText((self?.blockedIds ?? []).join(", "));
  };
  const doTotpSetup = async () => {
    setSecMsg("");
    try {
      setTotpSetup(await api.totpSetup(props.server, props.token));
    } catch (e) {
      setSecMsg(human(e as Error));
    }
  };
  const doTotpEnable = async () => {
    if (!totpSetup) return;
    setSecMsg("");
    try {
      await api.totpEnable(props.server, props.token, totpSetup.secret, totpCode.trim());
      setSecMsg("2FA увімкнено. Тепер вхід вимагатиме код.");
      setTotpSetup(null);
      setTotpCode("");
    } catch (e) {
      setSecMsg(e instanceof Error && e.message === "totp_invalid" ? "Хибний код" : human(e as Error));
    }
  };
  const doTotpDisable = async () => {
    setSecMsg("");
    try {
      await api.totpDisable(props.server, props.token, totpCode.trim());
      setSecMsg("2FA вимкнено.");
      setTotpCode("");
    } catch (e) {
      setSecMsg(e instanceof Error && e.message === "totp_invalid" ? "Хибний код (або 2FA не ввімкнено)" : human(e as Error));
    }
  };
  const saveBlocked = async () => {
    setSecMsg("");
    const ids = blockedText
      .split(/[\s,;]+/)
      .map((s) => s.trim())
      .filter((s) => /^[1-9]\d{8}$/.test(s)); // ID-простір: 9 цифр, перша не нуль
    try {
      await api.setDeviceLists(props.server, props.token, props.selfId, ids, []);
      setSecMsg(`Чорний список збережено (${ids.length} ID).`);
    } catch (e) {
      setSecMsg(human(e as Error));
    }
  };

  const reload = async () => {
    setErr("");
    try {
      const [ds, gs] = await Promise.all([
        api.listDevices(props.server, props.token),
        api.listGroups(props.server, props.token),
      ]);
      setDevices(ds);
      setGroups(gs);
    } catch (e) {
      setErr(human(e as Error));
    }
  };
  useEffect(() => {
    void reload();
    const id = setInterval(() => void reload(), 5000); // живе оновлення присутності
    return () => clearInterval(id);
  }, []);

  const addDevice = async () => {
    setErr("");
    try {
      const d = await api.createDevice(props.server, props.token, "Керований пристрій");
      setNewDev({ publicId: d.publicId, clientSecret: d.clientSecret });
      void reload();
    } catch (e) {
      setErr(human(e as Error));
    }
  };

  const saveGroup = async () => {
    if (!groupModal) return;
    const name = groupModal.name.trim();
    if (!name) return;
    setGroupBusy(true);
    setGroupErr("");
    try {
      if (groupModal.id) await api.renameGroup(props.server, props.token, groupModal.id, name);
      else await api.createGroup(props.server, props.token, name);
      setGroupModal(null);
      void reload();
    } catch (e) {
      setGroupErr(human(e as Error));
    } finally {
      setGroupBusy(false);
    }
  };

  // Видалення групи не чіпає пристрої — вони лишаються в книзі без групи.
  const removeGroup = async (id: string) => {
    setErr("");
    try {
      await api.deleteGroup(props.server, props.token, id);
      void reload();
    } catch (e) {
      setErr(human(e as Error));
    }
  };

  const moveDevice = async (publicId: string, groupId: string | null) => {
    setErr("");
    try {
      await api.setDeviceGroup(props.server, props.token, publicId, groupId);
      void reload();
    } catch (e) {
      setErr(human(e as Error));
    }
  };

  const inGroup = (gid: string | null) =>
    (devices ?? []).filter((d) => (d.groupId ?? null) === gid);

  const renderDev = (d: Device) => (
    <div className="dev" key={d.publicId}>
      <div className="dev-info">
        <span className={"odot " + (d.online ? "on" : "off")} title={d.online ? "онлайн" : "офлайн"} />
        <span className="dev-alias">{d.alias || "Пристрій"}</span>
        <span className="muted"> · {d.publicId}</span>
        {d.publicId === props.selfId && <span className="badge">це я</span>}
      </div>
      <div className="row">
        {groups && groups.length > 0 && (
          <select
            className="grp-select"
            title="Група пристрою"
            value={d.groupId ?? ""}
            onChange={(e) => void moveDevice(d.publicId, e.target.value === "" ? null : e.target.value)}
          >
            <option value="">Без групи</option>
            {groups.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </select>
        )}
        {d.publicId !== props.selfId &&
          (d.online ? (
            <button className="tbtn accent" onClick={() => setTarget(d)}>
              Підключитися
            </button>
          ) : d.wake === "ready" ? (
            <button
              className="tbtn"
              disabled={waking === d.publicId}
              onClick={() => void wake(d.publicId)}
              title="Розбудити через помічника в його мережі"
            >
              {waking === d.publicId ? "Будимо…" : "🔌 Розбудити"}
            </button>
          ) : d.wake === "no_helper" ? (
            <span className="muted" title="Жоден помічник (інший пристрій із ZortilWatch) не онлайн у мережі цього ПК">
              офлайн · нема помічника
            </span>
          ) : (
            <span className="muted" title="Пристрій не повідомив підтримку Wake-on-LAN (увімкніть WoL у BIOS і запустіть на ньому ZortilWatch хоч раз)">
              офлайн
            </span>
          ))}
      </div>
      {wakeMsg[d.publicId] && <p className="wake-msg muted">{wakeMsg[d.publicId]}</p>}
    </div>
  );

  return (
    <div className="book">
      <div className="book-head">
        <div>
          <h2 className="book-title">Адресна книга</h2>
          <p className="muted">
            Ваш ID пульта: <b>{props.selfId}</b>
          </p>
        </div>
        <div className="row">
          <button className="tbtn" onClick={addDevice}>
            + Пристрій
          </button>
          <button className="tbtn" onClick={() => setGroupModal({ name: "" })}>
            + Група
          </button>
          <button className="tbtn" onClick={() => void reload()}>
            Оновити
          </button>
          <button className="tbtn" onClick={() => void openSecurity()}>
            Безпека
          </button>
          <button className="tbtn" onClick={props.onLogout}>
            Вийти
          </button>
        </div>
      </div>

      {props.host && (
        <div className="host-panel">
          <div className="host-head">
            <div>
              <div className="host-title">
                <span className={"odot " + (props.host.active ? "on" : "off")} /> Цей пристрій — керований
              </div>
              <p className="muted">
                {props.host.active
                  ? "Приймає підключення за постійним паролем · ID " + props.selfId
                  : "Вимкнено — інші не можуть під'єднатися до цього пристрою"}
              </p>
            </div>
            <button
              className={"tbtn " + (props.host.active ? "danger" : "accent")}
              onClick={props.host.onToggle}
            >
              {props.host.active ? "Вимкнути" : "Увімкнути"}
            </button>
          </div>
          {props.host.active && props.host.oneTime && (
            <div className="otp">
              <div>
                <div className="otp-label">Одноразовий код підключення</div>
                <div className="otp-code">{fmtCode(props.host.oneTime)}</div>
                <p className="muted">
                  Продиктуйте його тому, хто підключається. Діє один сеанс.
                </p>
              </div>
              <button className="tbtn" onClick={props.host.onRefreshOneTime} title="Згенерувати новий код">
                Оновити код
              </button>
            </div>
          )}
          {!props.host.active && (
            <Field
              label="Постійний пароль (необов'язково — порожній = лише разовий код)"
              value={props.host.password}
              onChange={props.host.onPasswordChange}
              type="password"
            />
          )}
          <label className="host-autostart">
            <input
              type="checkbox"
              checked={props.host.autostart}
              onChange={props.host.onToggleAutostart}
            />
            Запускати при вході в Windows (фоном, доступний без присутності)
          </label>
          <label className="host-autostart">
            <input
              type="checkbox"
              checked={props.host.confirmIncoming}
              onChange={props.host.onToggleConfirm}
            />
            Підтверджувати кожне підключення вручну (атендантний режим)
          </label>
          <label className="host-autostart">
            <input
              type="checkbox"
              checked={props.host.lockOnEnd}
              onChange={props.host.onToggleLockOnEnd}
            />
            Блокувати Windows після завершення кожної сесії
          </label>
          {props.host.error && <p className="status err">{props.host.error}</p>}
        </div>
      )}

      {err && <p className="status err">{err}</p>}

      {newDev && (
        <div className="newdev">
          <b>Новий пристрій створено.</b> На тій машині запустіть «керований» із цими даними
          (secret показується ОДИН раз):
          <div className="kv">
            ID: <code>{newDev.publicId}</code>
          </div>
          <div className="kv">
            secret: <code>{newDev.clientSecret}</code>
          </div>
          <button className="link" onClick={() => setNewDev(null)}>
            Сховати
          </button>
        </div>
      )}

      {devices === null || groups === null ? (
        <p className="muted">Завантаження…</p>
      ) : devices.length === 0 ? (
        <p className="muted">Пристроїв ще немає. Натисніть «+ Пристрій».</p>
      ) : groups.length === 0 ? (
        <div className="dev-list">{devices.map(renderDev)}</div>
      ) : (
        <>
          {inGroup(null).length > 0 && (
            <section className="grp">
              <div className="grp-head">
                <span className="grp-name">Без групи</span>
                <span className="grp-count">{inGroup(null).length}</span>
              </div>
              <div className="dev-list">{inGroup(null).map(renderDev)}</div>
            </section>
          )}
          {groups.map((g) => (
            <section className="grp" key={g.id}>
              <div className="grp-head">
                <span className="grp-name">{g.name}</span>
                <span className="grp-count">{inGroup(g.id).length}</span>
                <span className="spacer" />
                <button className="gbtn" onClick={() => setGroupModal({ id: g.id, name: g.name })}>
                  Перейменувати
                </button>
                <button className="gbtn danger" onClick={() => void removeGroup(g.id)}>
                  Видалити
                </button>
              </div>
              {inGroup(g.id).length === 0 ? (
                <p className="muted">Порожньо — перенесіть пристрій селектором у його рядку.</p>
              ) : (
                <div className="dev-list">{inGroup(g.id).map(renderDev)}</div>
              )}
            </section>
          ))}
        </>
      )}

      {secOpen && (
        <div className="modal-bg" onClick={() => setSecOpen(false)}>
          <div className="card sec-card" onClick={(e) => e.stopPropagation()}>
            <h3 className="modal-title">Безпека</h3>

            <div className="sec-block">
              <b>Двофакторна автентифікація (2FA)</b>
              {!totpSetup ? (
                <div className="row" style={{ marginTop: 8 }}>
                  <button className="tbtn accent" onClick={() => void doTotpSetup()}>
                    Налаштувати 2FA
                  </button>
                  <button className="tbtn" onClick={() => void doTotpDisable()}>
                    Вимкнути (з кодом нижче)
                  </button>
                </div>
              ) : (
                <div className="newdev" style={{ marginTop: 8 }}>
                  Додайте секрет у застосунок-автентифікатор (Google Authenticator, Aegis…):
                  <div className="kv">
                    секрет: <code>{totpSetup.secret}</code>
                  </div>
                  Потім введіть код нижче й натисніть «Підтвердити».
                </div>
              )}
              <Field label="Код 2FA (6 цифр)" value={totpCode} onChange={setTotpCode} />
              {totpSetup && (
                <button className="btn btn-primary" onClick={() => void doTotpEnable()}>
                  Підтвердити й увімкнути
                </button>
              )}
            </div>

            <div className="sec-block">
              <b>Чорний список для мого пристрою ({props.selfId})</b>
              <p className="muted">ID пультів (9 цифр), яким заборонено підключатися; через кому.</p>
              <Field label="Заблоковані ID" value={blockedText} onChange={setBlockedText} placeholder="111111111, 222222222" />
              <button className="tbtn" onClick={() => void saveBlocked()}>
                Зберегти список
              </button>
            </div>

            <div className="sec-block">
              <b>Журнал аудиту</b>
              <div className="audit-list">
                {auditRows === null ? (
                  <p className="muted">Завантаження…</p>
                ) : auditRows.length === 0 ? (
                  <p className="muted">Подій ще немає.</p>
                ) : (
                  auditRows.slice(0, 50).map((r, i) => (
                    <div className="audit-row" key={i}>
                      <span>{new Date(r.at).toLocaleString()}</span>
                      <span>{r.event}</span>
                      <span className="muted">
                        {r.deviceId ?? ""} {r.fromInfo ?? ""}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>

            {secMsg && <p className="status">{secMsg}</p>}
            <button className="link" onClick={() => setSecOpen(false)}>
              Закрити
            </button>
          </div>
        </div>
      )}

      {groupModal && (
        <div className="modal-bg" onClick={() => !groupBusy && setGroupModal(null)}>
          <div className="card" onClick={(e) => e.stopPropagation()}>
            <h3 className="modal-title">{groupModal.id ? "Перейменувати групу" : "Нова група"}</h3>
            <Field
              label="Назва групи"
              value={groupModal.name}
              onChange={(name) => setGroupModal({ ...groupModal, name })}
              placeholder="Дім, Робота, Клієнти…"
            />
            {groupErr && <p className="status err">{groupErr}</p>}
            <div className="row">
              <button
                className="btn btn-primary"
                disabled={groupBusy || !groupModal.name.trim()}
                onClick={() => void saveGroup()}
              >
                Зберегти
              </button>
              <button className="tbtn" disabled={groupBusy} onClick={() => setGroupModal(null)}>
                Скасувати
              </button>
            </div>
          </div>
        </div>
      )}

      {target && (
        <div className="modal-bg" onClick={() => !props.connecting && setTarget(null)}>
          <div className="card" onClick={(e) => e.stopPropagation()}>
            <h3 className="modal-title">Підключення до {target.alias || target.publicId}</h3>
            <div className="kind-row" role="radiogroup" aria-label="Тип пароля">
              <label className="kind-opt">
                <input
                  type="radio"
                  name="pwkind"
                  checked={pwKind === "one_time"}
                  onChange={() => setPwKind("one_time")}
                />
                Разовий код з екрана
              </label>
              <label className="kind-opt">
                <input
                  type="radio"
                  name="pwkind"
                  checked={pwKind === "permanent"}
                  onChange={() => setPwKind("permanent")}
                />
                Постійний пароль
              </label>
            </div>
            <Field
              label={pwKind === "one_time" ? "Разовий код (8 символів)" : "Постійний пароль"}
              value={password}
              onChange={setPassword}
              type={pwKind === "one_time" ? "text" : "password"}
              placeholder={pwKind === "one_time" ? "напр. AB2C 3DEF" : undefined}
            />
            {props.connectError && <p className="status err">{props.connectError}</p>}
            <div className="row">
              <button
                className="btn btn-primary"
                disabled={props.connecting}
                onClick={() => props.onConnect(target.publicId, password, pwKind)}
              >
                {props.connecting ? "Підключення…" : "Підключитися"}
              </button>
              <button className="tbtn" disabled={props.connecting} onClick={() => setTarget(null)}>
                Скасувати
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
