import type { ConnectOpts, InputEvent, Platform, SessionHandle } from "./index";
import init, {
  WasmHandshake,
  WasmOpener,
  WasmReassembler,
  WasmSealer,
} from "../wasm/zortilwatch_web_wasm";

// Веб-реалізація пульта: браузерний WebRTC (роль ВІДПОВІДАЧА) + крипто/PAKE/медіа ядра,
// скомпільоване у WASM. Реюзає ТОЧНО ті ж crypto/session/media, що нативний керований —
// PAKE, напрямкові ключі та формат кадрів збігаються побайтно. Мережу/SDP робить браузер;
// WASM лише драйвить рукостискання й шифрування поверх datachannel «session».

const PROTOCOL_VERSION = 1;
// Покриває атендантне підтвердження на керованому (до 30с) + PAKE/встановлення.
const PAKE_TIMEOUT_MS = 45_000;
// Маркер чистого завершення сесії від керованого (= core::connection SESSION_BYE = b"ZW-BYE-1").
// Шлеться сирим (не чанк, не шифр), тож звіряємо побайтно ДО передачі в reassembler.
const SESSION_BYE = new Uint8Array([0x5a, 0x57, 0x2d, 0x42, 0x59, 0x45, 0x2d, 0x31]);

function isSessionBye(b: Uint8Array): boolean {
  if (b.length !== SESSION_BYE.length) return false;
  for (let i = 0; i < b.length; i++) if (b[i] !== SESSION_BYE[i]) return false;
  return true;
}

let wasmInit: Promise<unknown> | null = null;
/** Ліниво ініціалізувати WASM-модуль (один раз). */
function wasmReady(): Promise<unknown> {
  return (wasmInit ??= init());
}

function wsUrl(base: string): string {
  // http://→ws://, https://→wss://
  return base.replace(/^http/, "ws").replace(/\/+$/, "") + "/signal";
}

/** Рядок DTLS-відбитка після `a=fingerprint:` (напр. "sha-256 AB:CD:…") — формат, що його
 *  очікує session_binding ядра (той самий парсинг, що в нативному core::connection). */
function fingerprintFromSdp(sdp: string): string {
  const m = sdp.match(/a=fingerprint:(.+)/);
  return m ? m[1].trim() : "";
}

/** Копія у свіжий ArrayBuffer: `RTCDataChannel.send` очікує ArrayBuffer-бекенд, а wasm-bindgen
 *  повертає `Uint8Array<ArrayBufferLike>` (TS не пропускає через можливий SharedArrayBuffer).
 *  Усі вихідні повідомлення дрібні (PAKE + події вводу), тож копія несуттєва. */
function toArrayBuffer(u: Uint8Array): ArrayBuffer {
  const b = new ArrayBuffer(u.byteLength);
  new Uint8Array(b).set(u);
  return b;
}

interface Envelope {
  v: number;
  type: string;
  [k: string]: unknown;
}

export function createWebPlatform(): Platform {
  return {
    kind: "web",
    describe: () => "Веб-клієнт (роль пульта): браузерний WebRTC + WASM-крипто ядра.",

    // Пробудження (PRD 5.9): короткий WS — register(controller) → wake → wake_result.
    wake(opts) {
      return new Promise((resolve, reject) => {
        const ws = new WebSocket(wsUrl(opts.server));
        const done = (cb: () => void) => {
          try {
            ws.close();
          } catch {
            /* ignore */
          }
          cb();
        };
        const timer = setTimeout(() => done(() => reject(new Error("wake timeout"))), 9000);
        ws.onerror = () => {
          clearTimeout(timer);
          done(() => reject(new Error("WebSocket error")));
        };
        ws.onopen = () =>
          ws.send(
            JSON.stringify({
              v: PROTOCOL_VERSION,
              type: "register",
              deviceId: opts.deviceId,
              clientSecret: opts.clientSecret,
              clientKind: "controller",
            }),
          );
        ws.onmessage = (ev) => {
          let m: Envelope;
          try {
            m = JSON.parse(typeof ev.data === "string" ? ev.data : "");
          } catch {
            return;
          }
          if (m.type === "register_ok") {
            ws.send(JSON.stringify({ v: PROTOCOL_VERSION, type: "wake", targetId: opts.targetId }));
          } else if (m.type === "register_err") {
            clearTimeout(timer);
            done(() => reject(new Error(String(m.reason ?? m.code ?? "register failed"))));
          } else if (m.type === "wake_result") {
            clearTimeout(timer);
            done(() =>
              resolve({
                status: m.status as "dispatched" | "no_helper" | "unsupported",
                helpers: Number(m.helpers ?? 0),
              }),
            );
          }
        };
      });
    },

    async connect(opts: ConnectOpts): Promise<SessionHandle> {
      await wasmReady();

      const ws = new WebSocket(wsUrl(opts.server));
      ws.binaryType = "arraybuffer";
      const send = (m: Envelope) => ws.send(JSON.stringify(m));

      let pc: RTCPeerConnection | null = null;
      let channel: RTCDataChannel | null = null;
      let sessionId = "";

      // Крипто-стан (після підтвердження PAKE).
      let hs: WasmHandshake | null = null;
      let opener: WasmOpener | null = null;
      let sealer: WasmSealer | null = null;
      const reasm = new WasmReassembler();
      let phase: "signaling" | "pake" | "media" = "signaling";
      const deferred: Uint8Array[] = []; // медіа, що випередило підтвердження

      let settled = false;
      let resolveConn!: (h: SessionHandle) => void;
      let rejectConn!: (e: Error) => void;
      const ready = new Promise<SessionHandle>((res, rej) => {
        resolveConn = res;
        rejectConn = rej;
      });

      const cleanup = () => {
        try {
          channel?.close();
        } catch {
          /* ignore */
        }
        try {
          pc?.close();
        } catch {
          /* ignore */
        }
        try {
          if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) ws.close();
        } catch {
          /* ignore */
        }
      };
      const fail = (msg: string) => {
        const wasSettled = settled;
        if (!settled) {
          settled = true;
          rejectConn(new Error(msg));
        }
        cleanup();
        // Сесія вже була живою — це не відмова connect(), а кінець сесії: сповістити App.
        if (wasSettled) opts.onClose?.(msg);
      };

      const timer = setTimeout(() => fail("PAKE timeout"), PAKE_TIMEOUT_MS);

      const handle: SessionHandle = {
        sendInput(ev: InputEvent) {
          if (!sealer || !channel || channel.readyState !== "open") return;
          const plain = new TextEncoder().encode(JSON.stringify(ev));
          channel.send(toArrayBuffer(sealer.seal(plain)));
        },
        disconnect() {
          settled = true;
          clearTimeout(timer);
          if (sessionId && ws.readyState === WebSocket.OPEN) {
            try {
              send({ v: PROTOCOL_VERSION, type: "session_close", sessionId });
            } catch {
              /* ignore */
            }
          }
          cleanup();
        },
      };

      // ── Одне розшифроване відео: зібрати чанки → розшифрувати → видати кадр ──
      const onMedia = (bytes: Uint8Array) => {
        if (isSessionBye(bytes)) {
          fail("сесію завершено керованим"); // чисте завершення: одразу в книгу
          return;
        }
        const sealed = reasm.push(bytes); // Uint8Array | undefined (повний блоб AU)
        if (!sealed || !opener) return;
        try {
          opts.onFrame(opener.open(sealed)); // H.264 Annex-B access unit
        } catch {
          /* зіпсований/непідтверджений кадр — пропустити */
        }
      };

      const startPake = () => {
        if (!pc || !channel) return;
        const ownFp = fingerprintFromSdp(pc.localDescription?.sdp ?? "");
        const peerFp = fingerprintFromSdp(pc.remoteDescription?.sdp ?? "");
        const seed = crypto.getRandomValues(new Uint8Array(32));
        const pw = new TextEncoder().encode(opts.password);
        hs = new WasmHandshake(pw, ownFp, peerFp, seed);
        phase = "pake";
        channel.send(toArrayBuffer(hs.firstMessage()));
      };

      const onChannelMessage = (data: ArrayBuffer) => {
        const bytes = new Uint8Array(data);
        if (phase === "media") {
          onMedia(bytes);
          return;
        }
        // phase === "pake"
        if (!hs || !channel) return;
        try {
          const resp = hs.onMessage(bytes); // Uint8Array | undefined; кидає, якщо не session-msg
          if (resp && resp.length) channel.send(toArrayBuffer(resp));
        } catch {
          deferred.push(bytes); // медіа, що випередило підтвердження
          return;
        }
        if (hs.isConfirmed()) {
          try {
            opener = hs.videoOpener();
            sealer = hs.inputSealer();
          } catch (e) {
            fail("cipher init: " + (e as Error).message);
            return;
          }
          phase = "media";
          clearTimeout(timer);
          for (const m of deferred.splice(0)) onMedia(m);
          if (!settled) {
            settled = true;
            resolveConn(handle);
          }
          // Сигналінг завершено — закрити WS (як нативні піри, що відкидають SignalClient
          // після встановлення). Далі все йде datachannel'ом; пізні signaling-повідомлення
          // (зокрема session_close через закриття WS керованого) не торкаються сесії.
          try {
            ws.close();
          } catch {
            /* ignore */
          }
        }
      };

      // ── Сигналінг ──
      ws.onerror = () => fail("WebSocket error");
      ws.onclose = () => {
        if (!settled) fail("WebSocket closed before session");
      };
      ws.onopen = () =>
        send({
          v: PROTOCOL_VERSION,
          type: "register",
          deviceId: opts.deviceId,
          clientSecret: opts.clientSecret,
          clientKind: "controller",
        });

      ws.onmessage = async (ev) => {
        let msg: Envelope;
        try {
          msg = JSON.parse(typeof ev.data === "string" ? ev.data : "");
        } catch {
          return;
        }
        switch (msg.type) {
          case "register_ok":
            send({
              v: PROTOCOL_VERSION,
              type: "connect_request",
              targetId: opts.targetId,
              passwordKind: opts.passwordKind,
            });
            break;
          case "register_err":
            fail("register: " + (msg.reason ?? msg.code ?? "відмовлено"));
            break;
          case "connect_err":
            fail("connect: " + String(msg.code ?? "помилка"));
            break;
          case "connect_ready": {
            sessionId = String(msg.sessionId);
            const iceServers = (msg.iceServers as RTCIceServer[] | undefined) ?? [];
            pc = new RTCPeerConnection({ iceServers });
            // Розрив після встановлення ловить App.tsx (watchdog кадрів) + datachannel.onclose.
            pc.onconnectionstatechange = () => {
              if (pc?.connectionState === "failed") fail("ICE/DTLS failed");
            };
            // Відповідач: канал «session» створює керований (offerer) — НЕ створюємо свій.
            pc.ondatachannel = (e) => {
              channel = e.channel;
              channel.binaryType = "arraybuffer";
              channel.onopen = () => startPake();
              channel.onmessage = (m) => onChannelMessage(m.data as ArrayBuffer);
              channel.onclose = () => {
                if (!settled) fail("datachannel closed");
              };
            };
            pc.onicecandidate = (e) => {
              if (e.candidate && sessionId) {
                send({
                  v: PROTOCOL_VERSION,
                  type: "signal",
                  sessionId,
                  kind: "ice",
                  payload: { cands: [e.candidate.candidate], relayed: null },
                });
              }
            };
            break;
          }
          case "signal": {
            if (!pc || msg.sessionId !== sessionId) return;
            const payload = (msg.payload ?? {}) as Record<string, unknown>;
            if (msg.kind === "offer") {
              await pc.setRemoteDescription({ type: "offer", sdp: String(payload.sdp) });
              const answer = await pc.createAnswer();
              await pc.setLocalDescription(answer);
              send({
                v: PROTOCOL_VERSION,
                type: "signal",
                sessionId,
                kind: "answer",
                payload: { sdp: answer.sdp },
              });
            } else if (msg.kind === "ice") {
              const cands = (payload.cands as string[] | undefined) ?? [];
              for (const c of cands) {
                try {
                  await pc.addIceCandidate({ candidate: c, sdpMid: "0", sdpMLineIndex: 0 });
                } catch {
                  /* кандидат не підійшов — пропустити */
                }
              }
            } else if (msg.kind === "end") {
              fail("сесію завершено віддалено");
            }
            break;
          }
          case "session_close":
            // Після встановлення сесію рве лише сам datachannel (rtc), не сигналінг:
            // server-side teardown (напр. розрив чийогось сигналінг-WS) шле
            // session_close — це НЕ привід рвати живу WebRTC-сесію.
            if (!settled) fail("сесію закрито");
            break;
        }
      };

      return ready;
    },
  };
}
