import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { env } from "../config";
import { hashPassword, verifyPassword } from "../auth/passwords";
import { issueAccessToken } from "../auth/tokens";
import { requireAccount } from "../auth/guard";
import { generateClientSecret, hashClientSecret } from "../auth/secrets";
import { createAccount, findAccountByEmail, findAccountById, setTotpSecret } from "../db/accounts";
import { listDevices, registerDevice, updateDeviceLists } from "../db/devices";
import { assignDeviceGroup, createGroup, deleteGroup, listGroups, renameGroup } from "../db/groups";
import { listAudit } from "../db/audit";
import { generateTotpSecret, totpUri, verifyTotp } from "../auth/totp";
import { mintTurnCredentials } from "../lib/turn";
import type { Registry } from "../signaling/registry";

const Credentials = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(200),
  /// Код TOTP — обов'язковий, коли на акаунті ввімкнено 2FA.
  totpCode: z.string().max(16).optional(),
});
const TotpEnable = z.object({ secret: z.string().min(16).max(64), code: z.string().max(16) });
const TotpDisable = z.object({ code: z.string().max(16) });

const NewDevice = z.object({ alias: z.string().max(120).optional() });
const GroupName = z.object({ name: z.string().min(1).max(80) });
const DevicePatch = z.object({
  groupId: z.string().min(1).nullable().optional(),
  blockedIds: z.array(z.string().regex(/^\d{9}$/)).max(200).optional(),
  allowedIds: z.array(z.string().regex(/^\d{9}$/)).max(200).optional(),
});

export function registerRoutes(app: FastifyInstance, registry: Registry): void {
  // Реєстрація акаунта.
  app.post("/accounts", async (req, reply) => {
    const { email, password } = Credentials.parse(req.body);
    if (await findAccountByEmail(email)) {
      return reply.code(409).send({ error: "email_taken" });
    }
    const acc = await createAccount(email, await hashPassword(password));
    const token = await issueAccessToken(env.JWT_SECRET, acc.id);
    return reply.code(201).send({ accountId: acc.id, token });
  });

  // Вхід (+ другий фактор, якщо ввімкнено — PRD 5.10).
  app.post("/sessions", async (req, reply) => {
    const { email, password, totpCode } = Credentials.parse(req.body);
    const acc = await findAccountByEmail(email);
    if (!acc || !(await verifyPassword(acc.passwordHash, password))) {
      return reply.code(401).send({ error: "invalid_credentials" });
    }
    if (acc.totpSecret) {
      if (!totpCode) return reply.code(401).send({ error: "totp_required" });
      if (!verifyTotp(acc.totpSecret, totpCode)) {
        return reply.code(401).send({ error: "totp_invalid" });
      }
    }
    const token = await issueAccessToken(env.JWT_SECRET, acc.id);
    return reply.send({ accountId: acc.id, token, totpEnabled: !!acc.totpSecret });
  });

  // 2FA: видати кандидата-секрет (вмикається лише після підтвердження кодом).
  app.post("/totp/setup", async (req) => {
    const accountId = await requireAccount(req);
    const acc = await findAccountById(accountId);
    const secret = generateTotpSecret();
    return { secret, uri: totpUri(secret, acc?.email ?? accountId) };
  });
  app.post("/totp/enable", async (req, reply) => {
    const accountId = await requireAccount(req);
    const { secret, code } = TotpEnable.parse(req.body);
    if (!verifyTotp(secret, code)) return reply.code(400).send({ error: "totp_invalid" });
    await setTotpSecret(accountId, secret);
    return reply.send({ ok: true });
  });
  app.post("/totp/disable", async (req, reply) => {
    const accountId = await requireAccount(req);
    const { code } = TotpDisable.parse(req.body);
    const acc = await findAccountById(accountId);
    if (!acc?.totpSecret || !verifyTotp(acc.totpSecret, code)) {
      return reply.code(400).send({ error: "totp_invalid" });
    }
    await setTotpSecret(accountId, null);
    return reply.send({ ok: true });
  });

  // Журнал аудиту (PRD 5.10): останні події акаунта.
  app.get("/audit", async (req) => {
    const accountId = await requireAccount(req);
    const rows = await listAudit(accountId);
    return rows.map((r) => ({
      event: r.event,
      deviceId: r.deviceId,
      fromInfo: r.fromInfo,
      at: r.startedAt,
    }));
  });

  // Ефемерні TURN-обліковки для поточної сесії.
  app.get("/turn-credentials", async (req) => {
    const accountId = await requireAccount(req);
    return mintTurnCredentials({
      secret: env.TURN_STATIC_AUTH_SECRET,
      userId: accountId,
      host: env.TURN_HOST,
      ttlSeconds: env.TURN_TTL_SECONDS,
    });
  });

  // Адресна книга акаунта. Віддаємо ЛИШЕ публічні поля — хеші (clientSecretHash,
  // permanentPasswordHash) не залишають сервер.
  app.get("/devices", async (req) => {
    const accountId = await requireAccount(req);
    const devices = await listDevices(accountId);
    return devices.map((d) => ({
      publicId: d.publicId,
      alias: d.alias,
      groupId: d.groupId,
      lastSeenAt: d.lastSeenAt,
      online: registry.isOnline(d.publicId),
      // Власник бачить ACL своїх пристроїв (це ЙОГО списки, не секрети).
      blockedIds: d.blockedIds,
      allowedIds: d.allowedIds,
      // Чесний статус пробудження (PRD 5.9): чи можна розбудити цей (офлайн) пристрій.
      // "unsupported" — MAC невідомий; "ready" — є помічник онлайн у його мережі;
      // "no_helper" — MAC є, але жодного помічника в тій мережі зараз немає.
      wake: !d.macAddress
        ? "unsupported"
        : registry.helpersOnNetwork(d.lastWanIp, d.publicId) > 0
          ? "ready"
          : "no_helper",
    }));
  });

  // Реєстрація нового пристрою: повертає client_secret ОДИН раз.
  app.post("/devices", async (req, reply) => {
    const accountId = await requireAccount(req);
    const { alias } = NewDevice.parse(req.body ?? {});
    const clientSecret = generateClientSecret();
    const device = await registerDevice(accountId, {
      alias,
      clientSecretHash: hashClientSecret(clientSecret),
    });
    return reply.code(201).send({
      publicId: device.publicId,
      clientSecret,
      alias: device.alias,
    });
  });

  // Оновити пристрій: група (groupId, null = прибрати) та/або білий/чорний списки.
  app.patch("/devices/:publicId", async (req, reply) => {
    const accountId = await requireAccount(req);
    const { publicId } = req.params as { publicId: string };
    const { groupId, blockedIds, allowedIds } = DevicePatch.parse(req.body);
    if (groupId !== undefined) {
      const result = await assignDeviceGroup(accountId, publicId, groupId);
      if (result === "not_found") return reply.code(404).send({ error: "device_not_found" });
      if (result === "group_not_found") return reply.code(404).send({ error: "group_not_found" });
    }
    if (blockedIds || allowedIds) {
      const ok = await updateDeviceLists(accountId, publicId, blockedIds, allowedIds);
      if (!ok) return reply.code(404).send({ error: "device_not_found" });
    }
    return reply.send({ ok: true });
  });

  // Групи адресної книги.
  app.get("/groups", async (req) => {
    const accountId = await requireAccount(req);
    const groups = await listGroups(accountId);
    return groups.map((g) => ({ id: g.id, name: g.name }));
  });

  app.post("/groups", async (req, reply) => {
    const accountId = await requireAccount(req);
    const { name } = GroupName.parse(req.body);
    const group = await createGroup(accountId, name);
    if (!group) return reply.code(409).send({ error: "group_exists" });
    return reply.code(201).send({ id: group.id, name: group.name });
  });

  app.patch("/groups/:groupId", async (req, reply) => {
    const accountId = await requireAccount(req);
    const { groupId } = req.params as { groupId: string };
    const { name } = GroupName.parse(req.body);
    const result = await renameGroup(accountId, groupId, name);
    if (result === "not_found") return reply.code(404).send({ error: "not_found" });
    if (result === "duplicate") return reply.code(409).send({ error: "group_exists" });
    return reply.send({ ok: true });
  });

  app.delete("/groups/:groupId", async (req, reply) => {
    const accountId = await requireAccount(req);
    const { groupId } = req.params as { groupId: string };
    if (!(await deleteGroup(accountId, groupId))) {
      return reply.code(404).send({ error: "not_found" });
    }
    return reply.code(204).send();
  });
}
