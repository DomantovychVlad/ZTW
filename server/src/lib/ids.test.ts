import { describe, expect, it } from "vitest";
import { generateDeviceId, isValidDeviceId } from "./ids";

describe("generateDeviceId", () => {
  it("повертає рівно 9 цифр, перша не нуль", () => {
    for (let i = 0; i < 1000; i++) {
      expect(generateDeviceId()).toMatch(/^[1-9]\d{8}$/);
    }
  });

  it("у межах 100000000..999999999", () => {
    for (let i = 0; i < 1000; i++) {
      const n = Number(generateDeviceId());
      expect(n).toBeGreaterThanOrEqual(100_000_000);
      expect(n).toBeLessThanOrEqual(999_999_999);
    }
  });

  it("дає різні значення (не константа)", () => {
    const set = new Set(Array.from({ length: 200 }, () => generateDeviceId()));
    expect(set.size).toBeGreaterThan(190);
  });
});

describe("isValidDeviceId", () => {
  it("приймає чинні", () => {
    expect(isValidDeviceId("123456789")).toBe(true);
    expect(isValidDeviceId("900000001")).toBe(true);
  });

  it("відхиляє нечинні", () => {
    for (const bad of ["", "012345678", "12345678", "1234567890", "abcdefghi", "12 345 67"]) {
      expect(isValidDeviceId(bad)).toBe(false);
    }
  });
});
