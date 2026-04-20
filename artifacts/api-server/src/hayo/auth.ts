import { SignJWT, jwtVerify } from "jose";
import type { NextFunction, Request, Response } from "express";
import { db } from "@workspace/db";
import { users } from "@workspace/db/schema";
import { eq } from "drizzle-orm";
import type { User } from "@workspace/db/schema";
import { createHash } from "crypto";
import { randomBytes } from "crypto";

const COOKIE_NAME = "app_session_id";
const JWT_SECRET = new TextEncoder().encode(process.env.SESSION_SECRET || "hayo-ai-secret-change-me-in-production");
const ONE_YEAR_MS = 1000 * 60 * 60 * 24 * 365;
const OWNER_EMAIL = (process.env.OWNER_EMAIL || "Fmf0038@gmail.com").trim().toLowerCase();

export { COOKIE_NAME, OWNER_EMAIL };

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

  // If database is not available, cannot authenticate
  if (!db) {
    console.warn("[Auth] Database not available — authentication skipped");
    return null;
  }

  const payload = await verifySessionToken(token);
  if (!payload) return null;

  try {
    const result = await db.select().from(users).where(eq(users.id, payload.userId)).limit(1);
    return result[0] ?? null;
  } catch (err: any) {
    console.warn("[Auth] Failed to fetch user from database:", err.message);
    return null;
  }
}

export function isOwnerUser(user: User | null): boolean {
  if (!user || user.role !== "admin") return false;
  const email = typeof user.email === "string" ? user.email.trim().toLowerCase() : "";
  return email === OWNER_EMAIL;
}

export async function requireOwnerApi(req: Request, res: Response, next: NextFunction): Promise<void> {
  const user = await authenticateRequest(req);
  if (!user) {
    res.status(401).json({ success: false, error: "Please login (10001)" });
    return;
  }

  if (!isOwnerUser(user)) {
    res.status(403).json({ success: false, error: "صلاحيات مالك المنصة مطلوبة" });
    return;
  }

  next();
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
