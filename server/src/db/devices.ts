import { Prisma } from "@prisma/client";
import { prisma } from "./client";
import { generateDeviceId } from "../lib/ids";

const MAX_ID_RETRIES = 5;

/**
 * Зареєструвати пристрій для акаунта зі стабільним 9-значним publicId.
 * Колізію ID (унікальний індекс, помилка P2002) обробляємо повтором — на 900M-просторі
 * це майже ніколи не >1 спроби.
 */
export async function registerDevice(
  accountId: string,
  opts: { alias?: string; clientSecretHash?: string } = {},
) {
  for (let attempt = 0; attempt < MAX_ID_RETRIES; attempt++) {
    try {
      return await prisma.device.create({
        data: {
          publicId: generateDeviceId(),
          accountId,
          alias: opts.alias,
          clientSecretHash: opts.clientSecretHash,
        },
      });
    } catch (e) {
      if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002") {
        continue; // колізія publicId — пробуємо ще
      }
      throw e;
    }
  }
  throw new Error("could not allocate a unique device id");
}

export function findDeviceByPublicId(publicId: string) {
  return prisma.device.findUnique({ where: { publicId } });
}

/** Зберегти дані пристрою на реєстрації: lastSeenAt (адресна книга показує його як
 *  "останній контакт" для офлайн-пристроїв) + WoL (PRD 5.9): MAC (якщо звітнуто) + WAN-IP.
 *  Не чіпає MAC, якщо його не передано (щоб controller-реєстрація не стирала host-MAC). */
export function updateDeviceWol(publicId: string, mac: string | undefined, wanIp: string | null) {
  const data: { macAddress?: string; lastWanIp?: string | null; lastSeenAt: Date } = {
    lastWanIp: wanIp,
    lastSeenAt: new Date(),
  };
  if (mac) data.macAddress = mac;
  return prisma.device.update({ where: { publicId }, data }).catch(() => undefined);
}

/** Оновити білий/чорний списки пристрою (PRD 5.10). Tenant-scoped. */
export async function updateDeviceLists(
  accountId: string,
  publicId: string,
  blocked: string[] | undefined,
  allowed: string[] | undefined,
): Promise<boolean> {
  const data: { blockedIds?: string[]; allowedIds?: string[] } = {};
  if (blocked) data.blockedIds = blocked;
  if (allowed) data.allowedIds = allowed;
  if (!data.blockedIds && !data.allowedIds) return true;
  const r = await prisma.device.updateMany({ where: { publicId, accountId }, data });
  return r.count > 0;
}

/** Адресна книга акаунта (лише його пристрої — ізоляція орендаря). */
export function listDevices(accountId: string) {
  return prisma.device.findMany({
    where: { accountId },
    orderBy: { createdAt: "asc" },
  });
}
