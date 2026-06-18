import { z } from "zod";

// Протокол сигналінгу ZortilWatch. Сервер — «сліпий» брокер: payload у `signal`
// для нього непрозорий (E2E через PAKE-пароль, рішення B1).

export const PROTOCOL_VERSION = 1;

export type ConnectErrCode = "offline" | "busy" | "not_found" | "forbidden" | "rate_limited";

export interface PresenceEntry {
  id: string;
  online: boolean;
  lastSeen?: number;
  busy?: boolean;
}

// ── Клієнт -> Сервер (валідуємо на вході) ──────────────────────────────────
const envelope = { v: z.literal(PROTOCOL_VERSION), rid: z.string().optional() };

export const RegisterMsg = z.object({
  ...envelope,
  type: z.literal("register"),
  deviceId: z.string().regex(/^[1-9]\d{8}$/),
  clientSecret: z.string().min(1),
  clientKind: z.enum(["host", "controller"]),
  version: z.string().optional(),
  // Wake-on-LAN (PRD 5.9): власний MAC + чи може бути помічником.
  mac: z.string().max(32).optional(),
  canWake: z.boolean().optional(),
});

export const WakeMsg = z.object({
  ...envelope,
  type: z.literal("wake"),
  targetId: z.string(),
});

export const ListPresenceMsg = z.object({
  ...envelope,
  type: z.literal("list_presence"),
  ids: z.array(z.string()).max(500),
});

export const ConnectRequestMsg = z.object({
  ...envelope,
  type: z.literal("connect_request"),
  targetId: z.string(),
  // Тип пароля, яким автентифікуватиметься пульт (PAKE вимагає, щоб керований
  // знав, який секрет підставити). Сам пароль сервер не бачить ніколи.
  // Відсутність (старі клієнти) керований трактує як "permanent".
  passwordKind: z.enum(["one_time", "permanent"]).optional(),
});

export const ConnectAcceptMsg = z.object({
  ...envelope,
  type: z.literal("connect_accept"),
  sessionId: z.string(),
});

export const ConnectRejectMsg = z.object({
  ...envelope,
  type: z.literal("connect_reject"),
  sessionId: z.string(),
  reason: z.string().optional(),
});

export const SignalMsg = z.object({
  ...envelope,
  type: z.literal("signal"),
  sessionId: z.string(),
  kind: z.enum(["offer", "answer", "ice", "end"]),
  payload: z.unknown(), // НЕПРОЗОРИЙ для сервера
});

export const SessionCloseMsg = z.object({
  ...envelope,
  type: z.literal("session_close"),
  sessionId: z.string(),
  reason: z.string().optional(),
});

export const ClientMessage = z.discriminatedUnion("type", [
  RegisterMsg,
  ListPresenceMsg,
  ConnectRequestMsg,
  ConnectAcceptMsg,
  ConnectRejectMsg,
  SignalMsg,
  SessionCloseMsg,
  WakeMsg,
]);
export type ClientMessage = z.infer<typeof ClientMessage>;

export type SignalKind = "offer" | "answer" | "ice" | "end";

// ── Сервер -> Клієнт (будуємо самі) ────────────────────────────────────────
export type ServerMessage =
  | { v: 1; type: "register_ok"; deviceId: string; serverTime: number; rid?: string }
  | { v: 1; type: "register_err"; code: string; reason: string; rid?: string }
  | { v: 1; type: "presence_state"; entries: PresenceEntry[]; rid?: string }
  | { v: 1; type: "presence_update"; id: string; online: boolean; busy?: boolean }
  | { v: 1; type: "connect_err"; code: ConnectErrCode; rid?: string; retryAfter?: number }
  | {
      v: 1;
      type: "incoming_request";
      sessionId: string;
      fromKind: string;
      passwordKind?: string;
      iceServers?: unknown;
    }
  | {
      v: 1;
      type: "connect_ready";
      sessionId: string;
      role: "offerer" | "answerer";
      peerKind: string;
      iceServers?: unknown;
    }
  | { v: 1; type: "signal"; sessionId: string; kind: SignalKind; payload: unknown }
  | { v: 1; type: "session_close"; sessionId: string; reason?: string }
  | { v: 1; type: "wake_dispatch"; mac: string }
  | { v: 1; type: "wake_result"; status: WakeStatus; helpers: number; rid?: string }
  | { v: 1; type: "error"; code: string; reason: string; rid?: string };

/** Чесний підсумок спроби розбудити (PRD 5.9). */
export type WakeStatus = "dispatched" | "no_helper" | "unsupported";
