import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildServer } from "../app";

let app: FastifyInstance;

beforeAll(async () => {
  app = await buildServer();
  await app.ready();
});
afterAll(async () => {
  await app.close();
});

const PW = "password123";

describe("HTTP API (integration)", () => {
  it("реєстрація -> пристрій -> список -> TURN -> вхід", async () => {
    const reg = await app.inject({
      method: "POST",
      url: "/accounts",
      payload: { email: "api@example.com", password: PW },
    });
    expect(reg.statusCode).toBe(201);
    const token = reg.json().token as string;
    expect(token).toBeTruthy();
    const auth = { authorization: `Bearer ${token}` };

    const dev = await app.inject({ method: "POST", url: "/devices", headers: auth, payload: { alias: "Мій ПК" } });
    expect(dev.statusCode).toBe(201);
    const device = dev.json();
    expect(device.publicId).toMatch(/^[1-9]\d{8}$/);
    expect(device.clientSecret).toMatch(/^[0-9a-f]{64}$/);

    const list = await app.inject({ method: "GET", url: "/devices", headers: auth });
    expect(list.statusCode).toBe(200);
    expect(list.json()).toHaveLength(1);

    const turn = await app.inject({ method: "GET", url: "/turn-credentials", headers: auth });
    expect(turn.statusCode).toBe(200);
    expect(String(turn.json().username)).toContain(":");

    const login = await app.inject({ method: "POST", url: "/sessions", payload: { email: "api@example.com", password: PW } });
    expect(login.statusCode).toBe(200);
    expect(login.json().token).toBeTruthy();
  });

  it("захищений маршрут без токена -> 401", async () => {
    const r = await app.inject({ method: "GET", url: "/devices" });
    expect(r.statusCode).toBe(401);
  });

  it("дублікат email -> 409", async () => {
    await app.inject({ method: "POST", url: "/accounts", payload: { email: "dupe@example.com", password: PW } });
    const r = await app.inject({ method: "POST", url: "/accounts", payload: { email: "dupe@example.com", password: PW } });
    expect(r.statusCode).toBe(409);
  });

  it("невірний пароль -> 401", async () => {
    await app.inject({ method: "POST", url: "/accounts", payload: { email: "pw@example.com", password: PW } });
    const r = await app.inject({ method: "POST", url: "/sessions", payload: { email: "pw@example.com", password: "wrongpassword" } });
    expect(r.statusCode).toBe(401);
  });

  it("GET /devices не віддає секретні хеші, але віддає groupId", async () => {
    const auth = await registerAccount("safe@example.com");
    await app.inject({ method: "POST", url: "/devices", headers: auth, payload: {} });
    const list = await app.inject({ method: "GET", url: "/devices", headers: auth });
    expect(list.statusCode).toBe(200);
    const d = list.json()[0];
    expect(d).not.toHaveProperty("clientSecretHash");
    expect(d).not.toHaveProperty("permanentPasswordHash");
    expect(d).toHaveProperty("groupId");
    expect(d).toHaveProperty("online");
  });
});

async function registerAccount(email: string) {
  const reg = await app.inject({ method: "POST", url: "/accounts", payload: { email, password: PW } });
  expect(reg.statusCode).toBe(201);
  return { authorization: `Bearer ${reg.json().token as string}` };
}

describe("групи адресної книги (integration)", () => {
  it("CRUD: створити -> список -> перейменувати -> видалити", async () => {
    const auth = await registerAccount("grp@example.com");

    const created = await app.inject({ method: "POST", url: "/groups", headers: auth, payload: { name: "Дім" } });
    expect(created.statusCode).toBe(201);
    const gid = created.json().id as string;
    expect(created.json().name).toBe("Дім");

    const list = await app.inject({ method: "GET", url: "/groups", headers: auth });
    expect(list.statusCode).toBe(200);
    expect(list.json()).toEqual([{ id: gid, name: "Дім" }]);

    const renamed = await app.inject({ method: "PATCH", url: `/groups/${gid}`, headers: auth, payload: { name: "Офіс" } });
    expect(renamed.statusCode).toBe(200);
    expect((await app.inject({ method: "GET", url: "/groups", headers: auth })).json()[0].name).toBe("Офіс");

    const deleted = await app.inject({ method: "DELETE", url: `/groups/${gid}`, headers: auth });
    expect(deleted.statusCode).toBe(204);
    expect((await app.inject({ method: "GET", url: "/groups", headers: auth })).json()).toHaveLength(0);
  });

  it("дубль імені -> 409 (створення і перейменування)", async () => {
    const auth = await registerAccount("grp409@example.com");
    await app.inject({ method: "POST", url: "/groups", headers: auth, payload: { name: "Дім" } });
    const second = await app.inject({ method: "POST", url: "/groups", headers: auth, payload: { name: "Дім" } });
    expect(second.statusCode).toBe(409);

    const other = await app.inject({ method: "POST", url: "/groups", headers: auth, payload: { name: "Робота" } });
    const ren = await app.inject({
      method: "PATCH",
      url: `/groups/${other.json().id}`,
      headers: auth,
      payload: { name: "Дім" },
    });
    expect(ren.statusCode).toBe(409);
  });

  it("чужа група невидима: PATCH/DELETE -> 404", async () => {
    const owner = await registerAccount("grpown@example.com");
    const intruder = await registerAccount("grpintr@example.com");
    const g = await app.inject({ method: "POST", url: "/groups", headers: owner, payload: { name: "Дім" } });
    const gid = g.json().id as string;

    expect((await app.inject({ method: "PATCH", url: `/groups/${gid}`, headers: intruder, payload: { name: "X" } })).statusCode).toBe(404);
    expect((await app.inject({ method: "DELETE", url: `/groups/${gid}`, headers: intruder })).statusCode).toBe(404);
    // список чужого порожній
    expect((await app.inject({ method: "GET", url: "/groups", headers: intruder })).json()).toHaveLength(0);
  });

  it("призначення пристрою в групу і зняття; чужа група -> 404", async () => {
    const auth = await registerAccount("grpdev@example.com");
    const other = await registerAccount("grpdev2@example.com");

    const dev = await app.inject({ method: "POST", url: "/devices", headers: auth, payload: { alias: "ПК" } });
    const publicId = dev.json().publicId as string;
    const g = await app.inject({ method: "POST", url: "/groups", headers: auth, payload: { name: "Дім" } });
    const gid = g.json().id as string;
    const foreign = await app.inject({ method: "POST", url: "/groups", headers: other, payload: { name: "Чужа" } });

    const assign = await app.inject({ method: "PATCH", url: `/devices/${publicId}`, headers: auth, payload: { groupId: gid } });
    expect(assign.statusCode).toBe(200);
    expect((await app.inject({ method: "GET", url: "/devices", headers: auth })).json()[0].groupId).toBe(gid);

    // чужу групу призначити не можна
    const bad = await app.inject({
      method: "PATCH",
      url: `/devices/${publicId}`,
      headers: auth,
      payload: { groupId: foreign.json().id },
    });
    expect(bad.statusCode).toBe(404);

    // чужий пристрій невидимий
    const badDev = await app.inject({ method: "PATCH", url: `/devices/${publicId}`, headers: other, payload: { groupId: null } });
    expect(badDev.statusCode).toBe(404);

    const unassign = await app.inject({ method: "PATCH", url: `/devices/${publicId}`, headers: auth, payload: { groupId: null } });
    expect(unassign.statusCode).toBe(200);
    expect((await app.inject({ method: "GET", url: "/devices", headers: auth })).json()[0].groupId).toBeNull();
  });

  it("групи без токена -> 401", async () => {
    expect((await app.inject({ method: "GET", url: "/groups" })).statusCode).toBe(401);
    expect((await app.inject({ method: "POST", url: "/groups", payload: { name: "X" } })).statusCode).toBe(401);
  });

  it("2FA: setup -> enable -> вхід вимагає код -> disable", async () => {
    const { hotp } = await import("../auth/totp");
    const email = "totp@example.com";
    const auth = await registerAccount(email);

    const setup = await app.inject({ method: "POST", url: "/totp/setup", headers: auth });
    const { secret, uri } = setup.json();
    expect(String(uri)).toContain("otpauth://totp/");

    const code = () => hotp(secret, BigInt(Math.floor(Date.now() / 1000 / 30)));
    // хибний код не вмикає
    const bad = await app.inject({ method: "POST", url: "/totp/enable", headers: auth, payload: { secret, code: "000000" } });
    expect(bad.statusCode).toBe(400);
    const en = await app.inject({ method: "POST", url: "/totp/enable", headers: auth, payload: { secret, code: code() } });
    expect(en.statusCode).toBe(200);

    // вхід без коду -> totp_required; з кодом -> ок
    const noCode = await app.inject({ method: "POST", url: "/sessions", payload: { email, password: PW } });
    expect(noCode.statusCode).toBe(401);
    expect(noCode.json().error).toBe("totp_required");
    const withCode = await app.inject({ method: "POST", url: "/sessions", payload: { email, password: PW, totpCode: code() } });
    expect(withCode.statusCode).toBe(200);

    const dis = await app.inject({ method: "POST", url: "/totp/disable", headers: auth, payload: { code: code() } });
    expect(dis.statusCode).toBe(200);
    const plain = await app.inject({ method: "POST", url: "/sessions", payload: { email, password: PW } });
    expect(plain.statusCode).toBe(200);
  });

  it("білий/чорний списки пристрою зберігаються через PATCH /devices", async () => {
    const auth = await registerAccount("acl@example.com");
    const dev = await app.inject({ method: "POST", url: "/devices", headers: auth, payload: {} });
    const publicId = dev.json().publicId as string;
    const patch = await app.inject({
      method: "PATCH",
      url: `/devices/${publicId}`,
      headers: auth,
      payload: { blockedIds: ["111111111"], allowedIds: [] },
    });
    expect(patch.statusCode).toBe(200);
    const { findDeviceByPublicId } = await import("../db/devices");
    const row = await findDeviceByPublicId(publicId);
    expect(row?.blockedIds).toEqual(["111111111"]);
  });

  it("журнал аудиту віддається власнику", async () => {
    const auth = await registerAccount("audit@example.com");
    const r = await app.inject({ method: "GET", url: "/audit", headers: auth });
    expect(r.statusCode).toBe(200);
    expect(Array.isArray(r.json())).toBe(true);
  });

  it("CORS-префлайт дозволяє PATCH і DELETE (браузерний клієнт)", async () => {
    const r = await app.inject({
      method: "OPTIONS",
      url: "/devices/123456789",
      headers: {
        origin: "http://localhost:1420",
        "access-control-request-method": "PATCH",
        "access-control-request-headers": "authorization,content-type",
      },
    });
    expect(r.statusCode).toBe(204);
    const allowed = String(r.headers["access-control-allow-methods"]);
    expect(allowed).toContain("PATCH");
    expect(allowed).toContain("DELETE");
  });
});
