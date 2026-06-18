// HTTP-клієнт сервера ZortilWatch (fetch, Bearer-токени).

export interface AccountInfo {
  accountId: string;
  token: string;
  /** Чи ввімкнено 2FA (приходить із входу; після реєстрації — false). */
  totpEnabled?: boolean;
}
export interface Device {
  publicId: string;
  alias?: string | null;
  groupId?: string | null;
  lastSeenAt?: string | null;
  online?: boolean;
  /** ACL власника (PRD 5.10): чорний/білий списки ID пультів. */
  blockedIds?: string[];
  allowedIds?: string[];
  /** Чесний статус пробудження (PRD 5.9): ready | no_helper | unsupported. */
  wake?: "ready" | "no_helper" | "unsupported";
}
export interface NewDevice {
  publicId: string;
  clientSecret: string;
  alias?: string | null;
}
export interface Group {
  id: string;
  name: string;
}

async function req<T>(
  server: string,
  path: string,
  opts: { method?: string; token?: string; body?: unknown } = {},
): Promise<T> {
  const headers: Record<string, string> = {};
  // content-type лише з тілом: Fastify відхиляє порожнє тіло із заявленим JSON (DELETE тощо).
  if (opts.body !== undefined) headers["content-type"] = "application/json";
  if (opts.token) headers["authorization"] = "Bearer " + opts.token;
  const res = await fetch(server.replace(/\/+$/, "") + path, {
    method: opts.method ?? "GET",
    headers,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
  });
  const text = await res.text();
  const body = text ? JSON.parse(text) : {};
  if (!res.ok) {
    throw new Error(body?.error ? String(body.error) : "HTTP " + res.status);
  }
  return body as T;
}

export const api = {
  register: (server: string, email: string, password: string) =>
    req<AccountInfo>(server, "/accounts", { method: "POST", body: { email, password } }),
  login: (server: string, email: string, password: string, totpCode?: string) =>
    req<AccountInfo>(server, "/sessions", {
      method: "POST",
      body: totpCode ? { email, password, totpCode } : { email, password },
    }),
  totpSetup: (server: string, token: string) =>
    req<{ secret: string; uri: string }>(server, "/totp/setup", { method: "POST", token, body: {} }),
  totpEnable: (server: string, token: string, secret: string, code: string) =>
    req<{ ok: true }>(server, "/totp/enable", { method: "POST", token, body: { secret, code } }),
  totpDisable: (server: string, token: string, code: string) =>
    req<{ ok: true }>(server, "/totp/disable", { method: "POST", token, body: { code } }),
  audit: (server: string, token: string) =>
    req<{ event: string; deviceId?: string; fromInfo?: string; at: string }[]>(server, "/audit", {
      token,
    }),
  listDevices: (server: string, token: string) =>
    req<Device[]>(server, "/devices", { token }),
  createDevice: (server: string, token: string, alias: string) =>
    req<NewDevice>(server, "/devices", { method: "POST", token, body: { alias } }),
  setDeviceGroup: (server: string, token: string, publicId: string, groupId: string | null) =>
    req<{ ok: true }>(server, "/devices/" + publicId, { method: "PATCH", token, body: { groupId } }),
  setDeviceLists: (
    server: string,
    token: string,
    publicId: string,
    blockedIds: string[],
    allowedIds: string[],
  ) =>
    req<{ ok: true }>(server, "/devices/" + publicId, {
      method: "PATCH",
      token,
      body: { blockedIds, allowedIds },
    }),
  listGroups: (server: string, token: string) => req<Group[]>(server, "/groups", { token }),
  createGroup: (server: string, token: string, name: string) =>
    req<Group>(server, "/groups", { method: "POST", token, body: { name } }),
  renameGroup: (server: string, token: string, id: string, name: string) =>
    req<{ ok: true }>(server, "/groups/" + id, { method: "PATCH", token, body: { name } }),
  deleteGroup: (server: string, token: string, id: string) =>
    req<unknown>(server, "/groups/" + id, { method: "DELETE", token }), // 204 без тіла
};
