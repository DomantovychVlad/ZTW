import { describe, expect, it } from "vitest";
import { base32Decode, base32Encode, generateTotpSecret, hotp, totpUri, verifyTotp } from "./totp";

describe("TOTP (RFC 6238)", () => {
  it("base32 туди-назад", () => {
    const buf = Buffer.from("zortilwatch-2fa!");
    expect(base32Decode(base32Encode(buf)).equals(buf)).toBe(true);
  });

  it("RFC 4226 тест-вектори HOTP (секрет '12345678901234567890')", () => {
    const secret = base32Encode(Buffer.from("12345678901234567890"));
    // Додаток D RFC 4226: лічильники 0..3.
    expect(hotp(secret, 0n)).toBe("755224");
    expect(hotp(secret, 1n)).toBe("287082");
    expect(hotp(secret, 2n)).toBe("359152");
    expect(hotp(secret, 3n)).toBe("969429");
  });

  it("verifyTotp приймає поточний крок і ±1, відкидає інше", () => {
    const secret = generateTotpSecret();
    const now = 1_781_000_000_000;
    const step = BigInt(Math.floor(now / 1000 / 30));
    expect(verifyTotp(secret, hotp(secret, step), now)).toBe(true);
    expect(verifyTotp(secret, hotp(secret, step - 1n), now)).toBe(true);
    expect(verifyTotp(secret, hotp(secret, step + 1n), now)).toBe(true);
    expect(verifyTotp(secret, hotp(secret, step + 5n), now)).toBe(false);
    expect(verifyTotp(secret, "12345", now)).toBe(false); // не 6 цифр
    expect(verifyTotp(secret, "abcdef", now)).toBe(false);
  });

  it("totpUri містить секрет і issuer", () => {
    const uri = totpUri("ABC234", "user@example.com");
    expect(uri).toContain("secret=ABC234");
    expect(uri).toContain("issuer=ZortilWatch");
    expect(uri).toContain("ZortilWatch%3Auser%40example.com");
  });
});
