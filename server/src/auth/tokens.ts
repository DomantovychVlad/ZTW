import { SignJWT, jwtVerify } from "jose";

const enc = new TextEncoder();

/** Видати короткоживучий access-токен акаунта (HS256). */
export async function issueAccessToken(
  secret: string,
  accountId: string,
  ttlSeconds = 900,
): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(accountId)
    .setIssuedAt()
    .setExpirationTime(Math.floor(Date.now() / 1000) + ttlSeconds)
    .sign(enc.encode(secret));
}

/** Перевірити токен; повертає accountId (sub) або кидає помилку. */
export async function verifyAccessToken(secret: string, token: string): Promise<string> {
  const { payload } = await jwtVerify(token, enc.encode(secret), { algorithms: ["HS256"] });
  if (!payload.sub) throw new Error("token missing subject");
  return payload.sub;
}
