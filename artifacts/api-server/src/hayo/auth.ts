import { SignJWT, jwtVerify } from "jose";
import type { Request, Response } from "express";
import { db } from "@workspace/db";
import { users } from "@workspace/db/schema";
import { eq } from "drizzle-orm";
import type { User } from "@workspace/db/schema";
import { createHash } from "crypto";
import { randomBytes } from "crypto";

const COOKIE_NAME = "app_session_id";
const JWT_SECRET = new TextEncoder().encode(process.env.SESSION_SECRET || "hayo-ai-secret-change-me-in-production");
const ONE_YEAR_MS = 1000 * 60 * 60 * 24 * 365;

export { COOKIE_NAME };

export function hashPassword(password: string): string {
  const salt = createHash("sha256").update(password + "hayo-salt").digest("hex");
  return createHash("sha256").update(password + salt).digest("hex");
}

export async function createSessionToken(userId: number, role: string): Promise<string> {
  return new SignJWT({ userId, role })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("1y")
    .sign(JWT_SECRET);
}

export async function verifySessionToken(token: string): Promise<{ userId: number; role: string } | null> {
  try {
    const { payload } = await jwtVerify(token, JWT_SECRET);
    return { userId: payload.userId as number, role: payload.role as string };
  } catch {
    return null;
  }
}

export async function authenticateRequest(req: Request): Promise<User | null> {
  const token = req.cookies?.[COOKIE_NAME];
  if (!token) return null;

  const payload = await verifySessionToken(token);
  if (!payload) return null;

  const result = await db.select().from(users).where(eq(users.id, payload.userId)).limit(1);
  return result[0] ?? null;
}

export function getSessionCookieOptions(req: Request) {
  const isSecure = req.headers["x-forwarded-proto"] === "https" || req.secure;
  return {
    httpOnly: true,
    secure: isSecure,
    sameSite: isSecure ? ("none" as const) : ("lax" as const),
    path: "/",
  };
}

export function setCookie(res: Response, req: Request, token: string) {
  const opts = getSessionCookieOptions(req);
  res.cookie(COOKIE_NAME, token, { ...opts, maxAge: ONE_YEAR_MS });
}

export function clearCookie(res: Response, req: Request) {
  const opts = getSessionCookieOptions(req);
  res.clearCookie(COOKIE_NAME, { ...opts, maxAge: -1 });
}
