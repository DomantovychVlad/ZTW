import { describe, expect, it } from "vitest";
import { hashPassword, verifyPassword } from "./passwords";

describe("passwords (Argon2id)", () => {
  it("хеш не містить пароля і верифікується", async () => {
    const h = await hashPassword("correct horse battery staple");
    expect(h).not.toContain("correct horse");
    expect(h.startsWith("$argon2id$")).toBe(true);
    expect(await verifyPassword(h, "correct horse battery staple")).toBe(true);
  });

  it("невірний пароль не проходить", async () => {
    const h = await hashPassword("s3cret");
    expect(await verifyPassword(h, "wrong")).toBe(false);
  });

  it("різні солі -> різні хеші того ж пароля", async () => {
    expect(await hashPassword("x")).not.toBe(await hashPassword("x"));
  });
});
