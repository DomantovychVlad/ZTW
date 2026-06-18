import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

// client_secret пристрою — високоентропійний (тому достатньо швидкого SHA-256,
// на відміну від паролів акаунтів, де Argon2id). Реєстрація сокета автентифікується ним.

export function generateClientSecret(): string {
  return randomBytes(32).toString("hex");
}

export function hashClientSecret(secret: string): string {
  return createHash("sha256").update(secret).digest("hex");
}

export function verifyClientSecret(storedHash: string, secret: string): boolean {
  const a = Buffer.from(storedHash, "hex");
  const b = Buffer.from(hashClientSecret(secret), "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}
