import { prisma } from "./client";

// Дата-шар акаунтів. Багатокористувацька ізоляція забезпечується тим, що всі
// запити, прив'язані до орендаря, фільтруються за accountId (нижче у devices/groups).

export function createAccount(email: string, passwordHash: string) {
  return prisma.account.create({ data: { email, passwordHash } });
}

export function findAccountByEmail(email: string) {
  return prisma.account.findUnique({ where: { email } });
}

export function findAccountById(id: string) {
  return prisma.account.findUnique({ where: { id } });
}

/** Увімкнути/вимкнути 2FA: зберегти секрет TOTP або зняти (null). (PRD 5.10) */
export function setTotpSecret(accountId: string, secret: string | null) {
  return prisma.account.update({ where: { id: accountId }, data: { totpSecret: secret } });
}
