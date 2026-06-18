import { prisma } from "./client";

/** Журнал аудиту (PRD 5.10): хто, коли, з якого пристрою. Помилки запису не мають
 *  валити сигналінг — виклики обгортаються catch на боці викликача. */
export function writeAudit(
  accountId: string,
  deviceId: string | null,
  event: string,
  fromInfo?: string,
) {
  return prisma.auditLog.create({
    data: { accountId, deviceId, event, fromInfo },
  });
}

export function listAudit(accountId: string, limit = 100) {
  return prisma.auditLog.findMany({
    where: { accountId },
    orderBy: { startedAt: "desc" },
    take: limit,
  });
}
