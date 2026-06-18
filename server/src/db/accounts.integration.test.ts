import { describe, expect, it } from "vitest";
import { createAccount, findAccountByEmail, findAccountById } from "./accounts";
import { hashPassword, verifyPassword } from "../auth/passwords";

describe("accounts (integration)", () => {
  it("create -> findByEmail/findById, пароль верифікується", async () => {
    const acc = await createAccount("a@example.com", await hashPassword("s3cret"));
    expect(acc.id).toBeTruthy();

    const byEmail = await findAccountByEmail("a@example.com");
    expect(byEmail?.id).toBe(acc.id);
    expect(await verifyPassword(byEmail!.passwordHash, "s3cret")).toBe(true);

    const byId = await findAccountById(acc.id);
    expect(byId?.email).toBe("a@example.com");
  });

  it("email унікальний", async () => {
    await createAccount("dup@example.com", "h");
    await expect(createAccount("dup@example.com", "h")).rejects.toThrow();
  });
});
