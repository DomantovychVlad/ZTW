import type { FastifyRequest } from "fastify";
import { env } from "../config";
import { verifyAccessToken } from "./tokens";

export class AuthError extends Error {}

/** Витягти й перевірити Bearer-токен; повертає accountId або кидає AuthError. */
export async function requireAccount(req: FastifyRequest): Promise<string> {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    throw new AuthError("missing bearer token");
  }
  try {
    return await verifyAccessToken(env.JWT_SECRET, header.slice("Bearer ".length));
  } catch {
    throw new AuthError("invalid token");
  }
}
