import { describe, expect, it } from "vitest";
import { RateLimiter } from "./ratelimit";

describe("RateLimiter", () => {
  it("дозволяє до ліміту, потім блокує з retryAfter", () => {
    const rl = new RateLimiter(3, 60_000);
    const t0 = 1_000_000;
    expect(rl.check("a", t0).allowed).toBe(true);
    expect(rl.check("a", t0).allowed).toBe(true);
    expect(rl.check("a", t0).allowed).toBe(true);
    const denied = rl.check("a", t0);
    expect(denied.allowed).toBe(false);
    expect(denied.retryAfterSec).toBeGreaterThan(0);
    expect(denied.retryAfterSec).toBeLessThanOrEqual(60);
  });

  it("скидає лічильник після завершення вікна", () => {
    const rl = new RateLimiter(1, 1_000);
    const t0 = 5_000;
    expect(rl.check("a", t0).allowed).toBe(true);
    expect(rl.check("a", t0).allowed).toBe(false);
    // через вікно — знову дозволено
    expect(rl.check("a", t0 + 1_001).allowed).toBe(true);
  });

  it("ключі ізольовані один від одного", () => {
    const rl = new RateLimiter(1, 60_000);
    const t0 = 0;
    expect(rl.check("a", t0).allowed).toBe(true);
    expect(rl.check("b", t0).allowed).toBe(true);
    expect(rl.check("a", t0).allowed).toBe(false);
    expect(rl.check("b", t0).allowed).toBe(false);
  });

  it("retryAfter спадає в межах вікна (мінімум 1с)", () => {
    const rl = new RateLimiter(1, 10_000);
    const t0 = 0;
    rl.check("a", t0);
    expect(rl.check("a", t0).retryAfterSec).toBe(10);
    expect(rl.check("a", t0 + 9_500).retryAfterSec).toBe(1);
  });

  it("enabled:false завжди дозволяє (вимкнення в тестах)", () => {
    const rl = new RateLimiter(1, 60_000, { enabled: false });
    const t0 = 0;
    for (let i = 0; i < 100; i++) expect(rl.check("a", t0).allowed).toBe(true);
  });
});
