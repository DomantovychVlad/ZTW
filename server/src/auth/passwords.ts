import { hash, verify } from "@node-rs/argon2";

// Argon2id (рекомендація OWASP #1). Профіль: пам'ять 19 MiB, 2 ітерації, паралелізм 1.
const OPTS = { memoryCost: 19456, timeCost: 2, parallelism: 1 } as const;

export function hashPassword(password: string): Promise<string> {
  return hash(password, OPTS);
}

export function verifyPassword(storedHash: string, password: string): Promise<boolean> {
  return verify(storedHash, password);
}
