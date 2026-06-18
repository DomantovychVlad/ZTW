import { describe, expect, it } from "vitest";
import { issueAccessToken, verifyAccessToken } from "./tokens";

const SECRET = "test-secret-please-change";

describe("tokens (JWT)", () => {
  it("issue -> verify повертає accountId", async () => {
    const t = await issueAccessToken(SECRET, "acc_42");
    expect(await verifyAccessToken(SECRET, t)).toBe("acc_42");
  });

  it("підроблений токен відхиляється", async () => {
    const t = await issueAccessToken(SECRET, "acc_42");
    await expect(verifyAccessToken(SECRET, `${t}x`)).rejects.toThrow();
  });

  it("інший секрет відхиляється", async () => {
    const t = await issueAccessToken(SECRET, "acc_42");
    await expect(verifyAccessToken("other-secret", t)).rejects.toThrow();
  });
});
