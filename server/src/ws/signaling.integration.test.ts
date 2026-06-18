import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { WebSocket } from "ws";
import type { FastifyInstance } from "fastify";
import { buildServer } from "../app";
import { createAccount } from "../db/accounts";
import { registerDevice } from "../db/devices";
import { generateClientSecret, hashClientSecret } from "../auth/secrets";

let app: FastifyInstance;
let url: string;

beforeAll(async () => {
  app = await buildServer();
  await app.listen({ port: 0, host: "127.0.0.1" });
  const addr = app.server.address() as AddressInfo;
  url = `ws://127.0.0.1:${addr.port}/signal`;
});
afterAll(async () => {
  await app.close();
});

// Мінімальний WS-клієнт із очікуванням повідомлення за предикатом.
function client(u: string) {
  const ws = new WebSocket(u);
  const inbox: any[] = [];
  const waiters: { pred: (m: any) => boolean; resolve: (m: any) => void }[] = [];
  ws.on("message", (raw) => {
    const m = JSON.parse(raw.toString());
    const i = waiters.findIndex((w) => w.pred(m));
    if (i >= 0) {
      const [w] = waiters.splice(i, 1);
      w.resolve(m);
    } else {
      inbox.push(m);
    }
  });
  return {
    opened: new Promise<void>((res, rej) => {
      ws.once("open", () => res());
      ws.once("error", rej);
    }),
    send: (m: unknown) => ws.send(JSON.stringify(m)),
    waitFor: (pred: (m: any) => boolean, ms = 4000) =>
      new Promise<any>((res, rej) => {
        const found = inbox.findIndex(pred);
        if (found >= 0) {
          const [m] = inbox.splice(found, 1);
          return res(m);
        }
        const t = setTimeout(() => rej(new Error("timeout waiting for ws message")), ms);
        waiters.push({ pred, resolve: (m) => { clearTimeout(t); res(m); } });
      }),
    close: () => ws.close(),
  };
}

describe("WS-сигналінг (наскрізний смоук)", () => {
  it("чорний список host-пристрою ріже connect_request (forbidden, PRD 5.10)", async () => {
    const acc = await createAccount("acl-ws@example.com", "h");
    const hostSecret = generateClientSecret();
    const ctrlSecret = generateClientSecret();
    const host = await registerDevice(acc.id, { clientSecretHash: hashClientSecret(hostSecret) });
    const ctrl = await registerDevice(acc.id, { clientSecretHash: hashClientSecret(ctrlSecret) });
    const { prisma } = await import("../db/client");
    await prisma.device.update({
      where: { publicId: host.publicId },
      data: { blockedIds: [ctrl.publicId] },
    });

    const h = client(url);
    const c = client(url);
    await Promise.all([h.opened, c.opened]);
    h.send({ v: 1, type: "register", deviceId: host.publicId, clientSecret: hostSecret, clientKind: "host" });
    await h.waitFor((m) => m.type === "register_ok");
    c.send({ v: 1, type: "register", deviceId: ctrl.publicId, clientSecret: ctrlSecret, clientKind: "controller" });
    await c.waitFor((m) => m.type === "register_ok");

    c.send({ v: 1, type: "connect_request", targetId: host.publicId });
    const err = await c.waitFor((m) => m.type === "connect_err");
    expect(err.code).toBe("forbidden"); // заблокований — навіть із правильним паролем не дійде
    // Дати фоновому audit-запису завершитись до TRUNCATE наступного тесту.
    await new Promise((r) => setTimeout(r, 200));
    h.close();
    c.close();
  });

  it("wake: магічний пакет іде помічнику в тій самій мережі (PRD 5.9)", async () => {
    const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
    const acc = await createAccount("wol@example.com", "h");
    const tSec = generateClientSecret();
    const hSec = generateClientSecret();
    const cSec = generateClientSecret();
    const target = await registerDevice(acc.id, { clientSecretHash: hashClientSecret(tSec) });
    const helper = await registerDevice(acc.id, { clientSecretHash: hashClientSecret(hSec) });
    const ctrl = await registerDevice(acc.id, { clientSecretHash: hashClientSecret(cSec) });

    // Ціль звітує MAC і ЙДЕ ОФЛАЙН — MAC лишається в БД (це і є сценарій пробудження).
    const t = client(url);
    await t.opened;
    t.send({ v: 1, type: "register", deviceId: target.publicId, clientSecret: tSec, clientKind: "host", mac: "DE:AD:BE:EF:00:11", canWake: true });
    await t.waitFor((m) => m.type === "register_ok");
    t.close();
    await sleep(150);

    // Помічник онлайн у тій самій мережі (localhost = спільна WAN-IP).
    const h = client(url);
    await h.opened;
    h.send({ v: 1, type: "register", deviceId: helper.publicId, clientSecret: hSec, clientKind: "host", canWake: true });
    await h.waitFor((m) => m.type === "register_ok");

    const c = client(url);
    await c.opened;
    c.send({ v: 1, type: "register", deviceId: ctrl.publicId, clientSecret: cSec, clientKind: "controller" });
    await c.waitFor((m) => m.type === "register_ok");
    c.send({ v: 1, type: "wake", targetId: target.publicId });

    const dispatch = await h.waitFor((m) => m.type === "wake_dispatch");
    expect(dispatch.mac).toBe("DE:AD:BE:EF:00:11");
    const result = await c.waitFor((m) => m.type === "wake_result");
    expect(result.status).toBe("dispatched");
    expect(result.helpers).toBeGreaterThanOrEqual(1);
    await sleep(150); // фоновий аудит перед TRUNCATE
    h.close();
    c.close();
  });

  it("wake: чесний статус no_helper / unsupported", async () => {
    const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
    const acc = await createAccount("wol2@example.com", "h");
    const tSec = generateClientSecret();
    const cSec = generateClientSecret();
    const withMac = await registerDevice(acc.id, { clientSecretHash: hashClientSecret(tSec) });
    const noMac = await registerDevice(acc.id, { clientSecretHash: hashClientSecret(tSec) });
    const ctrl = await registerDevice(acc.id, { clientSecretHash: hashClientSecret(cSec) });

    // Ціль із MAC, але БЕЗ помічника онлайн → no_helper.
    const t = client(url);
    await t.opened;
    t.send({ v: 1, type: "register", deviceId: withMac.publicId, clientSecret: tSec, clientKind: "host", mac: "AA:BB:CC:DD:EE:FF", canWake: true });
    await t.waitFor((m) => m.type === "register_ok");
    t.close();
    await sleep(150);

    const c = client(url);
    await c.opened;
    c.send({ v: 1, type: "register", deviceId: ctrl.publicId, clientSecret: cSec, clientKind: "controller" });
    await c.waitFor((m) => m.type === "register_ok");

    c.send({ v: 1, type: "wake", targetId: withMac.publicId });
    expect((await c.waitFor((m) => m.type === "wake_result")).status).toBe("no_helper");

    // Ціль без MAC (ніколи не звітувала) → unsupported.
    c.send({ v: 1, type: "wake", targetId: noMac.publicId });
    expect((await c.waitFor((m) => m.type === "wake_result")).status).toBe("unsupported");
    c.close();
  });

  it("два клієнти: реєстрація, присутність, підключення, сліпий релей", async () => {
    const acc = await createAccount("smoke@example.com", "h");
    const hostSecret = generateClientSecret();
    const ctrlSecret = generateClientSecret();
    const host = await registerDevice(acc.id, { alias: "Host", clientSecretHash: hashClientSecret(hostSecret) });
    const ctrl = await registerDevice(acc.id, { alias: "Ctrl", clientSecretHash: hashClientSecret(ctrlSecret) });

    const H = client(url);
    const C = client(url);
    await Promise.all([H.opened, C.opened]);

    H.send({ v: 1, type: "register", deviceId: host.publicId, clientSecret: hostSecret, clientKind: "host" });
    C.send({ v: 1, type: "register", deviceId: ctrl.publicId, clientSecret: ctrlSecret, clientKind: "controller" });
    await H.waitFor((m) => m.type === "register_ok");
    await C.waitFor((m) => m.type === "register_ok");

    // Присутність: пульт бачить хост онлайн.
    C.send({ v: 1, type: "list_presence", ids: [host.publicId] });
    const pres = await C.waitFor((m) => m.type === "presence_state");
    expect(pres.entries[0]).toMatchObject({ id: host.publicId, online: true });

    // Підключення: пульт -> запит; хост -> вхідне; хост приймає; обидва -> ready.
    C.send({ v: 1, type: "connect_request", targetId: host.publicId });
    const incoming = await H.waitFor((m) => m.type === "incoming_request");
    expect(incoming.sessionId).toBeTruthy();

    H.send({ v: 1, type: "connect_accept", sessionId: incoming.sessionId });
    const hostReady = await H.waitFor((m) => m.type === "connect_ready");
    const ctrlReady = await C.waitFor((m) => m.type === "connect_ready");
    expect(hostReady.role).toBe("offerer"); // керований = ініціатор
    expect(ctrlReady.role).toBe("answerer"); // пульт = відповідач
    expect(ctrlReady.iceServers).toBeTruthy(); // TURN-обліковки видані

    // Сліпий релей: offer від хоста доходить ЛИШЕ до пульта, payload незмінний.
    const payload = { sdp: "v=0\r\n...opaque..." };
    H.send({ v: 1, type: "signal", sessionId: incoming.sessionId, kind: "offer", payload });
    const got = await C.waitFor((m) => m.type === "signal" && m.kind === "offer");
    expect(got.payload).toEqual(payload);

    H.close();
    C.close();
  });

  it("невірний client_secret -> register_err", async () => {
    const acc = await createAccount("bad@example.com", "h");
    const secret = generateClientSecret();
    const dev = await registerDevice(acc.id, { clientSecretHash: hashClientSecret(secret) });

    const X = client(url);
    await X.opened;
    X.send({ v: 1, type: "register", deviceId: dev.publicId, clientSecret: "deadbeef", clientKind: "host" });
    const err = await X.waitFor((m) => m.type === "register_err");
    expect(err.code).toBe("auth");
    X.close();
  });
});
