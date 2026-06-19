import type { FastifyInstance } from "fastify";
import type { RawData, WebSocket } from "ws";
import { env } from "../config";
import { findDeviceByPublicId, updateDeviceWol } from "../db/devices";
import { writeAudit } from "../db/audit";
import { verifyClientSecret } from "../auth/secrets";
import { mintTurnCredentials } from "../lib/turn";
import { RateLimiter } from "../lib/ratelimit";
import { ClientMessage } from "../signaling/protocol";
import type { Connection } from "../signaling/registry";
import { Registry } from "../signaling/registry";

const HEARTBEAT_MS = 30_000;
// Антиперебір ID: один автентифікований пульт — не більше 20 запитів на з'єднання за 60с.
const CONNECT_LIMIT = 20;
const CONNECT_WINDOW_MS = 60_000;

function iceServersFor(deviceId: string) {
  const c = mintTurnCredentials({
    secret: env.TURN_STATIC_AUTH_SECRET,
    userId: deviceId,
    host: env.TURN_HOST,
    ttlSeconds: env.TURN_TTL_SECONDS,
  });
  return [{ urls: c.urls, username: c.username, credential: c.credential }];
}

/** Зареєструвати WebSocket-ендпоінт сигналінгу. Повертає Registry (для тестів). */
export function registerSignaling(app: FastifyInstance): Registry {
  // Аудит сесій (PRD 5.10): пишемо на акаунт ВЛАСНИКА керованого; збій БД не валить сигналінг.
  const audit = (event: string, hostId: string, controllerId: string) => {
    void (async () => {
      const host = await findDeviceByPublicId(hostId);
      if (host) await writeAudit(host.accountId, hostId, event, `controller:${controllerId}`);
    })().catch((err) => app.log.warn({ err }, "audit write failed"));
  };
  const registry = new Registry({
    iceServersFor,
    onSessionStart: (s) => audit("session_start", s.hostId, s.controllerId),
    onSessionEnd: (s) => audit("session_end", s.hostId, s.controllerId),
  });
  const connectLimiter = new RateLimiter(CONNECT_LIMIT, CONNECT_WINDOW_MS, {
    enabled: env.NODE_ENV !== "test", // у тестах вимкнено; логіку покрито ratelimit.test.ts
  });
  const alive = new WeakSet<WebSocket>();

  app.get("/signal", { websocket: true }, (socket: WebSocket, req) => {
    const conn: Connection = {
      send: (msg) => socket.send(JSON.stringify(msg)),
      close: (reason) => socket.close(1000, reason?.slice(0, 120)),
    };
    // Публічна (WAN) IP клієнта — щоб зіставити помічника й ціль у тій самій мережі (PRD 5.9).
    const wanIp = req.ip;
    let deviceId: string | null = null;
    let clientKind: "host" | "controller" | null = null;
    alive.add(socket);
    socket.on("pong", () => alive.add(socket));

    socket.on("message", async (raw: RawData) => {
      let msg;
      try {
        msg = ClientMessage.parse(JSON.parse(raw.toString()));
      } catch {
        conn.send({ v: 1, type: "error", code: "bad_message", reason: "invalid message" });
        return;
      }

      if (msg.type === "register") {
        // Збій БД не має вбивати сервер (unhandled rejection в async-хендлері) —
        // відповідаємо register_err, клієнтський serve-loop повторить спробу.
        let device;
        try {
          device = await findDeviceByPublicId(msg.deviceId);
        } catch (err) {
          app.log.error({ err }, "register: device lookup failed");
          conn.send({ v: 1, type: "register_err", code: "unavailable", reason: "temporary failure", rid: msg.rid });
          conn.close("unavailable");
          return;
        }
        if (
          !device ||
          !device.clientSecretHash ||
          !verifyClientSecret(device.clientSecretHash, msg.clientSecret)
        ) {
          conn.send({ v: 1, type: "register_err", code: "auth", reason: "bad credentials", rid: msg.rid });
          conn.close("auth");
          return;
        }
        // Повторний register на цьому ж сокеті (зміна ідентичності/ролі) — звільнити стару.
        if (deviceId && clientKind) registry.offline(deviceId, clientKind, conn);
        deviceId = msg.deviceId;
        clientKind = msg.clientKind;
        registry.online(deviceId, msg.clientKind, conn, { wanIp, canWake: msg.canWake });
        // Запам'ятати MAC + мережу для Wake-on-LAN (PRD 5.9); збій БД не критичний.
        void updateDeviceWol(deviceId, msg.mac, wanIp ?? null);
        conn.send({ v: 1, type: "register_ok", deviceId, serverTime: Date.now(), rid: msg.rid });
        return;
      }

      if (!deviceId || !clientKind) {
        conn.send({ v: 1, type: "error", code: "not_registered", reason: "register first" });
        return;
      }

      switch (msg.type) {
        case "list_presence":
          conn.send({ v: 1, type: "presence_state", entries: registry.presence(msg.ids), rid: msg.rid });
          break;
        case "connect_request": {
          // Антиперебір ID: обмежуємо частоту запитів на з'єднання від одного пульта.
          const rl = connectLimiter.check(deviceId);
          if (!rl.allowed) {
            conn.send({
              v: 1,
              type: "connect_err",
              code: "rate_limited",
              rid: msg.rid,
              retryAfter: rl.retryAfterSec,
            });
            break;
          }
          // Білий/чорний списки керованого (PRD 5.10). Уніфіковане forbidden — без оракулів.
          // Збій БД => fail-CLOSED: ACL — контроль безпеки; не можемо перевірити => відмова
          // (інакше блокований пульт пролізе під час недоступності БД).
          let aclOk = true;
          try {
            const target = await findDeviceByPublicId(msg.targetId);
            if (target) {
              const blocked = target.blockedIds.includes(deviceId);
              const allowlisted =
                target.allowedIds.length === 0 || target.allowedIds.includes(deviceId);
              aclOk = !blocked && allowlisted;
            }
          } catch (err) {
            app.log.warn({ err }, "acl lookup failed");
            aclOk = false; // fail-closed
          }
          if (!aclOk) {
            conn.send({ v: 1, type: "connect_err", code: "forbidden", rid: msg.rid });
            audit("connect_denied_acl", msg.targetId, deviceId);
            break;
          }
          const res = registry.requestConnect(deviceId, clientKind, msg.targetId, msg.passwordKind);
          if (!res.ok && res.code) {
            conn.send({ v: 1, type: "connect_err", code: res.code, rid: msg.rid });
          }
          break;
        }
        case "connect_accept":
          registry.acceptConnect(msg.sessionId, deviceId, clientKind);
          break;
        case "connect_reject":
          registry.rejectConnect(msg.sessionId, deviceId, clientKind, msg.reason);
          break;
        case "signal":
          registry.relaySignal(msg.sessionId, deviceId, clientKind, msg.kind, msg.payload);
          break;
        case "wake": {
          // Розбудити ціль через помічника в її мережі (PRD 5.9). Ціль зазвичай ОФЛАЙН,
          // тож MAC і остання мережа — з БД; помічники добираються за живою WAN-IP.
          let mac: string | null = null;
          let targetWanIp: string | null = null;
          try {
            const target = await findDeviceByPublicId(msg.targetId);
            mac = target?.macAddress ?? null;
            targetWanIp = target?.lastWanIp ?? null;
          } catch (err) {
            app.log.warn({ err }, "wake lookup failed");
          }
          const res = registry.dispatchWake(msg.targetId, mac, targetWanIp);
          conn.send({ v: 1, type: "wake_result", status: res.status, helpers: res.helpers, rid: msg.rid });
          if (res.status === "dispatched") audit("wake_dispatched", msg.targetId, deviceId);
          break;
        }
        case "session_close":
          registry.closeSession(msg.sessionId, msg.reason, deviceId, clientKind);
          break;
      }
    });

    socket.on("close", () => {
      if (deviceId && clientKind) registry.offline(deviceId, clientKind, conn);
    });
  });

  // Heartbeat: мертві сокети відсікаються (ws ping/pong).
  const interval = setInterval(() => {
    for (const client of app.websocketServer.clients) {
      if (!alive.has(client)) {
        client.terminate();
        continue;
      }
      alive.delete(client);
      client.ping();
    }
  }, HEARTBEAT_MS);
  interval.unref();

  app.addHook("onClose", (_app, done) => {
    clearInterval(interval);
    done();
  });

  return registry;
}
