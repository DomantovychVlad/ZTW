import { describe, expect, it } from "vitest";
import { generateClientSecret, hashClientSecret, verifyClientSecret } from "./secrets";

describe("client secrets", () => {
  it("генерує 64 hex-символи (32 байти)", () => {
    expect(generateClientSecret()).toMatch(/^[0-9a-f]{64}$/);
  });

  it("верифікує правильний секрет і відхиляє неправильний", () => {
    const s = generateClientSecret();
    const h = hashClientSecret(s);
    expect(verifyClientSecret(h, s)).toBe(true);
    expect(verifyClientSecret(h, generateClientSecret())).toBe(false);
  });

  it("verify не падає на хеші іншої довжини", () => {
    expect(verifyClientSecret("abcd", "secret")).toBe(false);
  });
});
