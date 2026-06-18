import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

// TOTP (RFC 6238, HMAC-SHA1, 30с, 6 цифр) на node:crypto — без нових залежностей.
// Сумісно з Google Authenticator/Aegis тощо (otpauth:// з base32-секретом).

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s: string): Buffer {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of s.toUpperCase().replace(/=+$/, "")) {
    const idx = B32.indexOf(ch);
    if (idx < 0) continue; // пробіли/дефіси з ручного вводу
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** Новий секрет TOTP (base32, 20 байт ентропії — стандарт для SHA1). */
export function generateTotpSecret(): string {
  return base32Encode(randomBytes(20));
}

/** otpauth:// URL для QR/ручного додавання в застосунок-автентифікатор. */
export function totpUri(secret: string, account: string): string {
  const label = encodeURIComponent(`ZortilWatch:${account}`);
  return `otpauth://totp/${label}?secret=${secret}&issuer=ZortilWatch&algorithm=SHA1&digits=6&period=30`;
}

/** Код для заданого лічильника (внутрішнє; тестоване окремо). */
export function hotp(secret: string, counter: bigint): string {
  const key = base32Decode(secret);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(counter);
  const h = createHmac("sha1", key).update(msg).digest();
  const off = h[h.length - 1] & 0x0f;
  const code =
    (((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3]) % 1_000_000;
  return code.toString().padStart(6, "0");
}

/** Перевірити код з вікном ±1 крок (годинниковий дрейф). */
export function verifyTotp(secret: string, code: string, nowMs = Date.now()): boolean {
  const clean = code.replace(/\s+/g, "");
  if (!/^\d{6}$/.test(clean)) return false;
  const step = BigInt(Math.floor(nowMs / 1000 / 30));
  for (const delta of [0n, -1n, 1n]) {
    const expect = hotp(secret, step + delta);
    if (
      expect.length === clean.length &&
      timingSafeEqual(Buffer.from(expect), Buffer.from(clean))
    ) {
      return true;
    }
  }
  return false;
}
