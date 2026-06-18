import { Prisma } from "@prisma/client";
import { prisma } from "./client";

/** Дубль імені в межах акаунта (@@unique[accountId, name]) -> null, не виняток. */
export async function createGroup(accountId: string, name: string) {
  try {
    return await prisma.group.create({ data: { accountId, name } });
  } catch (e) {
    if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002") {
      return null;
    }
    throw e;
  }
}

/** Групи акаунта (лише його — ізоляція орендаря). */
export function listGroups(accountId: string) {
  return prisma.group.findMany({
    where: { accountId },
    orderBy: { createdAt: "asc" },
  });
}

export async function renameGroup(
  accountId: string,
  groupId: string,
  name: string,
): Promise<"ok" | "not_found" | "duplicate"> {
  try {
    // updateMany зі скоупом accountId: чужа група = 0 рядків, а не помилка доступу.
    const r = await prisma.group.updateMany({ where: { id: groupId, accountId }, data: { name } });
    return r.count === 0 ? "not_found" : "ok";
  } catch (e) {
    if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002") {
      return "duplicate";
    }
    throw e;
  }
}

/** Пристрої групи лишаються в книзі без групи (onDelete: SetNull у схемі). */
export async function deleteGroup(accountId: string, groupId: string): Promise<boolean> {
  const r = await prisma.group.deleteMany({ where: { id: groupId, accountId } });
  return r.count > 0;
}

/** Призначити пристрій у групу акаунта або зняти (groupId=null). */
export async function assignDeviceGroup(
  accountId: string,
  publicId: string,
  groupId: string | null,
): Promise<"ok" | "not_found" | "group_not_found"> {
  if (groupId !== null) {
    // Цільова група мусить належати ТОМУ Ж акаунту, інакше FK дозволив би міжорендне посилання.
    const group = await prisma.group.findFirst({ where: { id: groupId, accountId } });
    if (!group) return "group_not_found";
  }
  const r = await prisma.device.updateMany({ where: { publicId, accountId }, data: { groupId } });
  return r.count === 0 ? "not_found" : "ok";
}
