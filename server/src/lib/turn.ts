import { createHmac } from "node:crypto";

export interface TurnCredentials {
  username: string;
  credential: string;
  ttl: number;
  urls: string[];
}

export interface MintTurnOptions {
  /** == coturn static-auth-secret */
  secret: string;
  /** Вільне поле (для логів/квот); coturn його не перевіряє при use-auth-secret. */
  userId: string;
  /** TURN FQDN (== coturn realm / cert CN). */
  host: string;
  /** Час життя обліковки, секунд. */
  ttlSeconds?: number;
  /** Інжектований годинник для детермінованих тестів. */
  nowMs?: number;
}

/**
 * Ефемерні TURN-обліковки за моделлю coturn `use-auth-secret`:
 *   username   = `${expiryUnixSeconds}:${userId}`   (timestamp = момент протермінування)
 *   credential = base64(HMAC-SHA1(secret, username))
 * coturn перераховує той самий HMAC і приймає, поки timestamp у майбутньому.
 */
export function mintTurnCredentials(opts: MintTurnOptions): TurnCredentials {
  const ttl = opts.ttlSeconds ?? 12 * 3600;
  const now = opts.nowMs ?? Date.now();
  const expiry = Math.floor(now / 1000) + ttl;
  const username = `${expiry}:${opts.userId}`;
  const credential = createHmac("sha1", opts.secret).update(username).digest("base64");

  return {
    username,
    credential,
    ttl,
    // TURNS на 443 першим — пробиває найсуворіші фаєрволи (виглядає як HTTPS).
    urls: [
      `turns:${opts.host}:443?transport=tcp`,
      `turns:${opts.host}:5349?transport=tcp`,
      `turn:${opts.host}:3478?transport=udp`,
      `turn:${opts.host}:3478?transport=tcp`,
    ],
  };
}
