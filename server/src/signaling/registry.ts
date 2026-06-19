import { randomUUID } from "node:crypto";
import type { ConnectErrCode, PresenceEntry, ServerMessage, SignalKind } from "./protocol";

// Абстракція з'єднання — дозволяє юніт-тести з мок-сокетами (без реального WS).
export interface Connection {
  send(msg: ServerMessage): void;
  close(reason?: string): void;
}

export type DeviceKind = "host" | "controller";

export interface RegistryOptions {
  /** Макс. одночасних вхідних сесій на керований пристрій. */
  maxInboundPerHost?: number;
  /** Генератор ID сесії (інжектується для детермінованих тестів). */
  makeSessionId?: () => string;
  /** Постачальник ICE/TURN-конфігу для пристрою (інжектується). */
  iceServersFor?: (deviceId: string) => unknown;
  /** Хуки аудиту (PRD 5.10): сесію прийнято / завершено. Реєстр лишається чистим. */
  onSessionStart?: (s: { sessionId: string; controllerId: string; hostId: string }) => void;
  onSessionEnd?: (s: { sessionId: string; controllerId: string; hostId: string }) => void;
}

export interface ConnectResult {
  ok: boolean;
  sessionId?: string;
  code?: ConnectErrCode;
}

interface SlotEntry {
  deviceId: string;
  kind: DeviceKind;
  conn: Connection;
  lastSeen: number;
  sessions: Set<string>;
  /** Публічна (WAN) IP цього з'єднання — для добору помічника в тій самій мережі. */
  wanIp?: string;
  /** Чи може цей пристрій будити інші (надсилати магічний пакет). */
  canWake: boolean;
  /** Орендар-власник пристрою — WoL добирає помічника ЛИШЕ в межах того ж акаунта. */
  accountId?: string;
}

/** Підсумок розсилки магічного пакета (PRD 5.9). */
export type WakeOutcome = "dispatched" | "no_helper" | "unsupported";

/** Один пристрій = ДВА незалежні слоти ролей: host (приймає підключення) і controller
 *  (сам підключається). Та сама машина може хостити і керувати одночасно — реєстрація
 *  пульта НЕ вибиває host-присутність цього ж ID. */
type Slots = Partial<Record<DeviceKind, SlotEntry>>;

interface Session {
  id: string;
  controllerId: string;
  /** Слот, з якого прийшов запит (для маршрутизації відповідей і self-сесій). */
  controllerKind: DeviceKind;
  hostId: string;
  status: "pending" | "ready";
}

/**
 * Реєстр присутності та сесій rendezvous. Тримає онлайн-пристрої й активні
 * парування у пам'яті; релеїть сигналінг СЛІПО (payload не парситься), лише між
 * членами сесії. Не торкається БД і WS — це чиста, тестована логіка.
 */
export class Registry {
  private devices = new Map<string, Slots>();
  private sessions = new Map<string, Session>();
  private readonly maxInbound: number;
  private readonly makeSessionId: () => string;
  private readonly iceServersFor: (deviceId: string) => unknown;
  private readonly onSessionStart?: RegistryOptions["onSessionStart"];
  private readonly onSessionEnd?: RegistryOptions["onSessionEnd"];

  constructor(opts: RegistryOptions = {}) {
    this.maxInbound = opts.maxInboundPerHost ?? 4;
    this.makeSessionId = opts.makeSessionId ?? (() => randomUUID());
    this.iceServersFor = opts.iceServersFor ?? (() => undefined);
    this.onSessionStart = opts.onSessionStart;
    this.onSessionEnd = opts.onSessionEnd;
  }

  private slot(deviceId: string, kind: DeviceKind): SlotEntry | undefined {
    return this.devices.get(deviceId)?.[kind];
  }

  /** Позначити роль пристрою онлайн. Те саме ID+роль з іншим з'єднанням — старе закривається. */
  online(
    deviceId: string,
    kind: DeviceKind,
    conn: Connection,
    meta: { wanIp?: string; canWake?: boolean; accountId?: string } = {},
    now = Date.now(),
  ): void {
    const slots = this.devices.get(deviceId) ?? {};
    const existing = slots[kind];
    if (existing && existing.conn !== conn) {
      existing.conn.close("replaced");
    }
    slots[kind] = {
      deviceId,
      kind,
      conn,
      lastSeen: now,
      sessions: existing?.sessions ?? new Set(),
      wanIp: meta.wanIp,
      canWake: meta.canWake ?? false,
      accountId: meta.accountId,
    };
    this.devices.set(deviceId, slots);
  }

  /** Чи є слот валідним WoL-помічником для цілі: вміє будити, та сама мережа І той самий
   *  орендар (без accountId цілі — НЕ помічник, fail-closed проти крос-тенант пробудження). */
  private isHelperFor(
    e: SlotEntry | undefined,
    wanIp: string,
    accountId: string | null | undefined,
  ): boolean {
    return !!e && e.canWake && e.wanIp === wanIp && !!accountId && e.accountId === accountId;
  }

  /** Скільки помічників (canWake) того ж акаунта онлайн у мережі `wanIp`, окрім `exceptId`. (PRD 5.9) */
  helpersOnNetwork(
    wanIp: string | null | undefined,
    exceptId: string,
    accountId: string | null | undefined,
  ): number {
    if (!wanIp) return 0;
    let n = 0;
    for (const [id, slots] of this.devices) {
      if (id === exceptId) continue;
      const helper = (["host", "controller"] as const).some((k) =>
        this.isHelperFor(slots[k], wanIp, accountId),
      );
      if (helper) n++;
    }
    return n;
  }

  /**
   * Розіслати магічний пакет на `mac` через помічників ТОГО Ж АКАУНТА в мережі `targetWanIp`
   * (PRD 5.9). `mac` null => пристрій не повідомив підтримку WoL ("unsupported").
   * Один пристрій = один пакет (дедуп за deviceId), ціль виключаємо. Крос-тенант пробудження
   * заблоковано: чужий пристрій у тій самій фізичній мережі помічником не стає.
   */
  dispatchWake(
    targetId: string,
    mac: string | null | undefined,
    targetWanIp: string | null | undefined,
    accountId: string | null | undefined,
  ): { status: WakeOutcome; helpers: number } {
    if (!mac) return { status: "unsupported", helpers: 0 };
    const sent = new Set<string>();
    for (const [id, slots] of this.devices) {
      if (id === targetId || sent.has(id) || !targetWanIp) continue;
      const conn = (["host", "controller"] as const)
        .map((k) => slots[k])
        .find((e) => this.isHelperFor(e, targetWanIp, accountId))?.conn;
      if (conn) {
        conn.send({ v: 1, type: "wake_dispatch", mac });
        sent.add(id);
      }
    }
    return sent.size === 0
      ? { status: "no_helper", helpers: 0 }
      : { status: "dispatched", helpers: sent.size };
  }

  /** «Онлайн» в адресній книзі = можна підключитись = host-слот зареєстрований. */
  isOnline(deviceId: string): boolean {
    return this.slot(deviceId, "host") !== undefined;
  }

  touch(deviceId: string, now = Date.now()): void {
    const slots = this.devices.get(deviceId);
    if (!slots) return;
    for (const kind of ["host", "controller"] as const) {
      const e = slots[kind];
      if (e) e.lastSeen = now;
    }
  }

  /**
   * Зняти РОЛЬ пристрою з онлайну й розірвати сесії цієї ролі. `conn` (якщо передано)
   * захищає від гонки заміни: закриття ЗАМІНЕНОГО сокета не чіпає нову реєстрацію.
   */
  offline(deviceId: string, kind: DeviceKind, conn?: Connection): void {
    const slots = this.devices.get(deviceId);
    const entry = slots?.[kind];
    if (!slots || !entry) return;
    if (conn && entry.conn !== conn) return;
    delete slots[kind];
    if (!slots.host && !slots.controller) this.devices.delete(deviceId);
    for (const sid of [...entry.sessions]) {
      this.teardown(sid, "peer_offline", deviceId, kind);
    }
  }

  presence(ids: string[]): PresenceEntry[] {
    return ids.map((id) => {
      const host = this.slot(id, "host");
      return host
        ? { id, online: true, lastSeen: host.lastSeen, busy: host.sessions.size > 0 }
        : { id, online: false };
    });
  }

  /**
   * Запит пульта на з'єднання з targetId. Створює сесію у стані "pending" і
   * надсилає керованому `incoming_request` (із типом пароля, яким автентифікуватиметься
   * пульт — сам пароль сервер не бачить). Уніфікована відповідь на недоступність
   * (offline) — щоб не давати оракула для перебору ID.
   */
  requestConnect(
    controllerId: string,
    controllerKind: DeviceKind,
    targetId: string,
    passwordKind?: string,
  ): ConnectResult {
    const host = this.slot(targetId, "host");
    if (!host) return { ok: false, code: "offline" };
    if (host.sessions.size >= this.maxInbound) return { ok: false, code: "busy" };

    const sessionId = this.makeSessionId();
    this.sessions.set(sessionId, {
      id: sessionId,
      controllerId,
      controllerKind,
      hostId: targetId,
      status: "pending",
    });
    host.sessions.add(sessionId);
    this.slot(controllerId, controllerKind)?.sessions.add(sessionId);

    host.conn.send({
      v: 1,
      type: "incoming_request",
      sessionId,
      fromKind: "controller",
      passwordKind,
      iceServers: this.iceServersFor(targetId),
    });
    return { ok: true, sessionId };
  }

  /** Керований підтвердив — обидва отримують `connect_ready` із ролями. */
  acceptConnect(sessionId: string, byDeviceId: string, byKind: DeviceKind): boolean {
    const s = this.sessions.get(sessionId);
    if (!s || s.hostId !== byDeviceId || byKind !== "host" || s.status !== "pending") {
      return false;
    }
    s.status = "ready";
    this.onSessionStart?.({ sessionId, controllerId: s.controllerId, hostId: s.hostId });
    // Керований = ініціатор (offerer, володіє медіа); пульт = відповідач (answerer).
    this.slot(s.hostId, "host")?.conn.send({
      v: 1,
      type: "connect_ready",
      sessionId,
      role: "offerer",
      peerKind: "controller",
      iceServers: this.iceServersFor(s.hostId),
    });
    this.slot(s.controllerId, s.controllerKind)?.conn.send({
      v: 1,
      type: "connect_ready",
      sessionId,
      role: "answerer",
      peerKind: "host",
      iceServers: this.iceServersFor(s.controllerId),
    });
    return true;
  }

  /** Керований відхилив вхідне підключення. */
  rejectConnect(
    sessionId: string,
    byDeviceId: string,
    byKind: DeviceKind,
    reason?: string,
  ): boolean {
    const s = this.sessions.get(sessionId);
    if (!s || s.hostId !== byDeviceId || byKind !== "host") return false;
    this.slot(s.controllerId, s.controllerKind)?.conn.send({
      v: 1,
      type: "connect_err",
      code: "forbidden",
    });
    this.teardown(sessionId, reason ?? "rejected", byDeviceId, byKind);
    return true;
  }

  /** Сліпо переслати сигнал ІНШОМУ члену сесії. Не-член сесії — ігнорується. */
  relaySignal(
    sessionId: string,
    fromDeviceId: string,
    fromKind: DeviceKind,
    kind: SignalKind,
    payload: unknown,
  ): boolean {
    const s = this.sessions.get(sessionId);
    if (!s) return false;
    const peer = this.peerSlotOf(s, fromDeviceId, fromKind);
    if (!peer) return false;
    peer.conn.send({ v: 1, type: "signal", sessionId, kind, payload });
    return true;
  }

  closeSession(
    sessionId: string,
    reason: string | undefined,
    byDeviceId: string,
    byKind: DeviceKind,
  ): boolean {
    const s = this.sessions.get(sessionId);
    if (!s || this.peerSlotOf(s, byDeviceId, byKind) === undefined) return false;
    this.teardown(sessionId, reason ?? "closed", byDeviceId, byKind);
    return true;
  }

  /** Слот ПІРА відправника. Сторони розрізняються парою (id, роль) — це коректно
   *  і для self-сесії, де одна машина керує сама собою (controllerId === hostId). */
  private peerSlotOf(s: Session, deviceId: string, kind: DeviceKind): SlotEntry | undefined {
    if (s.controllerId === deviceId && s.controllerKind === kind) {
      return this.slot(s.hostId, "host");
    }
    if (s.hostId === deviceId && kind === "host") {
      return this.slot(s.controllerId, s.controllerKind);
    }
    return undefined;
  }

  private teardown(
    sessionId: string,
    reason: string,
    initiatorId: string,
    initiatorKind: DeviceKind,
  ): void {
    const s = this.sessions.get(sessionId);
    if (!s) return;
    this.sessions.delete(sessionId);
    if (s.status === "ready") {
      this.onSessionEnd?.({ sessionId, controllerId: s.controllerId, hostId: s.hostId });
    }
    const sides: Array<{ id: string; kind: DeviceKind }> = [
      { id: s.controllerId, kind: s.controllerKind },
      { id: s.hostId, kind: "host" },
    ];
    for (const side of sides) {
      const entry = this.slot(side.id, side.kind);
      if (!entry) continue;
      entry.sessions.delete(sessionId);
      if (!(side.id === initiatorId && side.kind === initiatorKind)) {
        entry.conn.send({ v: 1, type: "session_close", sessionId, reason });
      }
    }
  }
}
