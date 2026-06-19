// Платформний шов (рішення A1).
// Уся решта UI залежить ЛИШЕ від цього інтерфейсу — ніколи від @tauri-apps/api
// чи WASM напряму. Desktop -> Rust-ядро через Tauri IPC; web -> браузерний WebRTC + WASM.

import { createWebPlatform } from "./web";
import { createDesktopPlatform } from "./tauri";

export type PlatformKind = "desktop" | "web";

/** Подія вводу — дзеркалить core::input::InputEvent (serde tag "t", snake_case).
 *  quality/monitor — керівні повідомлення медіа-циклу керованого (не інжектуються). */
export type InputEvent =
  | { t: "mouse_move"; x: number; y: number }
  | { t: "mouse_button"; button: "left" | "right" | "middle"; down: boolean }
  | { t: "scroll"; dx: number; dy: number }
  | { t: "key"; code: number; down: boolean }
  | { t: "quality"; fps: number; bitrate: number; scale: number }
  | { t: "monitor"; index: number }
  | { t: "fs_list"; path: string }
  | { t: "fs_cancel"; id: number }
  | { t: "clipboard"; text: string }
  | { t: "clipboard_sync"; enabled: boolean }
  | { t: "blank"; enabled: boolean }
  | { t: "input_lock"; enabled: boolean };

/** Монітор керованого (контрольне повідомлення сесії). */
export interface RemoteMonitor {
  index: number;
  name: string;
  w: number;
  h: number;
  primary: boolean;
}

/** Тип пароля підключення: разовий код з екрана керованого чи постійний власника. */
export type PasswordKind = "one_time" | "permanent";

export interface ConnectOpts {
  server: string;
  deviceId: string;
  clientSecret: string;
  password: string;
  /** Каже керованому, який секрет підставити в PAKE (сервер пароля не бачить). */
  passwordKind: PasswordKind;
  targetId: string;
  /** Викликається на кожен розшифрований H.264 access unit (Annex-B). */
  onFrame: (h264: Uint8Array) => void;
  /** Сесія завершилась ПІСЛЯ встановлення (керований надіслав BYE, обрив datachannel/ICE).
   *  Дозволяє миттєво повернутись у книгу, не чекаючи watchdog кадрів. */
  onClose?: (reason: string) => void;
}

export interface SessionHandle {
  sendInput(ev: InputEvent): void;
  disconnect(): void;
}

/** Запит підтвердження вхідного підключення (атендантний режим). */
export interface ConfirmRequest {
  requestId: number;
  passwordKind: string;
}

/** Параметри host-режиму (цей пристрій як керований). */
export interface HostOpts {
  server: string;
  deviceId: string;
  clientSecret: string;
  /** Постійний пароль (порожньо/null — приймати лише за одноразовим кодом). */
  permanentPassword: string | null;
  /** Атендантний режим: кожне підключення підтверджує людина за пристроєм. */
  confirmIncoming: boolean;
  /** Автоблокування Windows після кожної сесії (PRD 5.10). */
  lockOnEnd: boolean;
  /** Поточний одноразовий код (генерує ядро; оновлюється після сесії/вручну). */
  onOneTime: (code: string) => void;
  /** Вхідний запит чекає рішення (відповісти через decideIncoming, ~30с). */
  onConfirm: (req: ConfirmRequest) => void;
}

/** Стан host-режиму. */
export interface HostStatus {
  active: boolean;
  oneTime?: string | null;
}

export interface Platform {
  readonly kind: PlatformKind;
  /** Короткий людський опис активної платформи. */
  describe(): string;
  /** Під'єднатися до керованого за ID+паролем і почати приймати кадри екрана. */
  connect(opts: ConnectOpts): Promise<SessionHandle>;
  /** Розбудити пристрій через помічника в його мережі (PRD 5.9). Чесний статус. */
  wake(opts: {
    server: string;
    deviceId: string;
    clientSecret: string;
    targetId: string;
  }): Promise<{ status: "dispatched" | "no_helper" | "unsupported"; helpers: number }>;
  /** Host-режим (керований) — лише десктоп; web (пульт-only) не реалізує (undefined). */
  startHost?(opts: HostOpts): Promise<void>;
  stopHost?(): Promise<void>;
  hostStatus?(): Promise<HostStatus>;
  /** Згенерувати новий одноразовий код (прилетить через onOneTime за ≤2с). */
  refreshOneTime?(): Promise<void>;
  /** Перемкнути атендантний режим наживо (без рестарту host). */
  setConfirmIncoming?(enabled: boolean): Promise<void>;
  /** Перемкнути автоблокування після сесії наживо. */
  setLockOnEnd?(enabled: boolean): Promise<void>;
  /** Рішення людини щодо вхідного підключення. */
  decideIncoming?(requestId: number, allow: boolean): Promise<void>;
  /** Автозапуск при вході в Windows (per-user) — лише десктоп. */
  setAutostart?(enabled: boolean): Promise<void>;
  getAutostart?(): Promise<boolean>;
  /** Конфіг застосунку (портативність + типова адреса сервера) — лише десктоп. */
  appConfig?(): Promise<{ portable: boolean; defaultServer?: string | null }>;
  /** Файли (PRD 5.7) — лише десктоп: локальний список і передачі через сесію. */
  fsLocalList?(path: string): Promise<FsListing>;
  fsDownload?(remotePath: string, localPath: string): Promise<number>;
  fsUpload?(localPath: string, remotePath: string): Promise<number>;
  fsCancel?(id: number): Promise<void>;
}

/** Запис списку каталогу (локального чи віддаленого). */
export interface FsEntry {
  name: string;
  dir: boolean;
  size: number;
}
export interface FsListing {
  path: string;
  entries: FsEntry[];
  err?: string | null;
}

export function getPlatform(): Platform {
  // Tauri v2 додає __TAURI_INTERNALS__ у window; відсутність => браузерний веб-клієнт.
  const isTauri =
    typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
  return isTauri ? createDesktopPlatform() : createWebPlatform();
}
