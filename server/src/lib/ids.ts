import { randomInt } from "node:crypto";

// 9-значний публічний ID пристрою (перша цифра не нуль).
const MIN = 100_000_000;
const MAX = 999_999_999;

/**
 * Згенерувати стабільний 9-значний публічний ID (CSPRNG, НЕ послідовний —
 * послідовні ID роблять перебір тривіальним). Унікальність забезпечує
 * @unique у БД + повтор при колізії на боці виклику.
 */
export function generateDeviceId(): string {
  // randomInt(min, max) повертає [min, max); +1 щоб включити MAX.
  return String(randomInt(MIN, MAX + 1));
}

/** Формат публічного ID: рівно 9 цифр, перша не нуль. */
export function isValidDeviceId(id: string): boolean {
  return /^[1-9]\d{8}$/.test(id);
}
