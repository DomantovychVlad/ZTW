import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { mintTurnCredentials } from "./turn";

const base = {
  secret: "shared-secret",
  userId: "acc_123",
  host: "turn.example.com",
  nowMs: 1_700_000_000_000,
};

describe("mintTurnCredentials", () => {
  it("username = `${expiry}:${userId}`, expiry = now/1000 + ttl", () => {
    const c = mintTurnCredentials({ ...base, ttlSeconds: 3600 });
    expect(c.username).toBe(`${Math.floor(base.nowMs / 1000) + 3600}:acc_123`);
    expect(c.ttl).toBe(3600);
  });

  it("credential = base64(HMAC-SHA1(secret, username))", () => {
    const c = mintTurnCredentials({ ...base, ttlSeconds: 3600 });
    const expected = createHmac("sha1", base.secret).update(c.username).digest("base64");
    expect(c.credential).toBe(expected);
  });

  it("детермінований за фіксованого часу", () => {
    expect(mintTurnCredentials(base)).toEqual(mintTurnCredentials(base));
  });

  it("різний секрет -> різна обліковка", () => {
    const a = mintTurnCredentials(base);
    const b = mintTurnCredentials({ ...base, secret: "other" });
    expect(a.credential).not.toBe(b.credential);
  });

  it("urls містять TURNS на 443 і TURN UDP 3478", () => {
    const c = mintTurnCredentials(base);
    expect(c.urls.some((u) => u.startsWith("turns:") && u.includes(":443"))).toBe(true);
    expect(c.urls.some((u) => u.startsWith("turn:") && u.includes(":3478") && u.includes("udp"))).toBe(
      true,
    );
  });
});
