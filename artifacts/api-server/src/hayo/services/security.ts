/**
 * HAYO AI Security System
 * Rate limiting, bot detection, brute force protection, security headers
 */

// ─── In-memory rate limiter ─────────────────────────────────────
const rateLimitStore = new Map<string, { count: number; resetAt: number }>();

export function rateLimit(
  key: string,
  maxRequests: number = 60,
  windowMs: number = 60_000, // 1 minute
): { allowed: boolean; remaining: number; retryAfter?: number } {
  const now = Date.now();
  const entry = rateLimitStore.get(key);

  if (!entry || now > entry.resetAt) {
    rateLimitStore.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, remaining: maxRequests - 1 };
  }

  if (entry.count >= maxRequests) {
    return { allowed: false, remaining: 0, retryAfter: Math.ceil((entry.resetAt - now) / 1000) };
  }

  entry.count++;
  return { allowed: true, remaining: maxRequests - entry.count };
}

// Cleanup old entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of rateLimitStore) {
    if (now > val.resetAt) rateLimitStore.delete(key);
  }
}, 5 * 60_000);

// ─── Brute Force Protection (login attempts) ────────────────────
const loginAttempts = new Map<string, { count: number; blockedUntil: number }>();

export function checkLoginAttempt(ip: string): { allowed: boolean; remainingAttempts: number; blockedFor?: number } {
  const now = Date.now();
  const entry = loginAttempts.get(ip);

  if (entry && now < entry.blockedUntil) {
    return { allowed: false, remainingAttempts: 0, blockedFor: Math.ceil((entry.blockedUntil - now) / 1000) };
  }

  if (!entry || now > entry.blockedUntil) {
    loginAttempts.set(ip, { count: 1, blockedUntil: 0 });
    return { allowed: true, remainingAttempts: 4 };
  }

  entry.count++;
  if (entry.count >= 5) {
    // Block for 15 minutes after 5 failed attempts
    entry.blockedUntil = now + 15 * 60_000;
    return { allowed: false, remainingAttempts: 0, blockedFor: 900 };
  }

  return { allowed: true, remainingAttempts: 5 - entry.count };
}

export function resetLoginAttempts(ip: string): void {
  loginAttempts.delete(ip);
}

// ─── Bot Detection (basic heuristics) ───────────────────────────
const BOT_USER_AGENTS = [
  /bot/i, /crawler/i, /spider/i, /scraper/i, /wget/i, /curl/i,
  /python-requests/i, /httpx/i, /axios/i, /node-fetch/i,
  /go-http/i, /java\//i, /php\//i, /ruby/i,
];

const ALLOWED_BOTS = [/googlebot/i, /bingbot/i, /slurp/i]; // SEO bots OK

export function detectBot(userAgent: string): { isBot: boolean; isMalicious: boolean; botName?: string } {
  if (!userAgent || userAgent.length < 10) return { isBot: true, isMalicious: true };

  for (const allowed of ALLOWED_BOTS) {
    if (allowed.test(userAgent)) return { isBot: true, isMalicious: false, botName: userAgent.match(allowed)?.[0] };
  }

  for (const pattern of BOT_USER_AGENTS) {
    if (pattern.test(userAgent)) return { isBot: true, isMalicious: true, botName: userAgent.match(pattern)?.[0] };
  }

  return { isBot: false, isMalicious: false };
}

// ─── Security Headers Middleware ─────────────────────────────────
export function securityHeaders(req: any, res: any, next: any) {
  // Prevent XSS
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("X-XSS-Protection", "1; mode=block");

  // Referrer policy
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

  // Permissions policy
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");

  // Strict transport (HTTPS only)
  if (process.env.NODE_ENV === "production") {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }

  next();
}

// ─── API Rate Limit Middleware ───────────────────────────────────
export function apiRateLimiter(maxPerMinute: number = 60) {
  return (req: any, res: any, next: any) => {
    const ip = req.ip || req.headers["x-forwarded-for"] || "unknown";
    const key = `api:${ip}`;
    const result = rateLimit(key, maxPerMinute);

    res.setHeader("X-RateLimit-Limit", maxPerMinute);
    res.setHeader("X-RateLimit-Remaining", result.remaining);

    if (!result.allowed) {
      res.setHeader("Retry-After", result.retryAfter || 60);
      return res.status(429).json({
        error: "طلبات كثيرة جداً. انتظر قليلاً.",
        retryAfter: result.retryAfter,
      });
    }

    next();
  };
}

// ─── Auth Rate Limit (stricter for login) ───────────────────────
export function authRateLimiter() {
  return (req: any, res: any, next: any) => {
    const ip = req.ip || req.headers["x-forwarded-for"] || "unknown";

    // Bot check
    const ua = req.headers["user-agent"] || "";
    const bot = detectBot(ua);
    if (bot.isMalicious) {
      return res.status(403).json({ error: "Access denied" });
    }

    // Brute force check
    const check = checkLoginAttempt(ip);
    if (!check.allowed) {
      return res.status(429).json({
        error: `محاولات كثيرة. محظور لمدة ${Math.ceil((check.blockedFor || 900) / 60)} دقيقة.`,
        blockedFor: check.blockedFor,
      });
    }

    next();
  };
}

// ─── Input Sanitization ─────────────────────────────────────────
export function sanitizeInput(input: string): string {
  return input
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/\//g, "&#x2F;");
}

// SQL injection patterns (for logging/alerting)
const SQL_PATTERNS = [
  /('|--|;|\/\*|\*\/|xp_|exec|execute|insert|update|delete|drop|alter|create|union|select.*from)/i,
  /(or|and)\s+\d+\s*=\s*\d+/i,
  /union\s+(all\s+)?select/i,
];

export function detectSQLInjection(input: string): boolean {
  return SQL_PATTERNS.some(p => p.test(input));
}

// ─── System health check ────────────────────────────────────────
export async function systemHealthCheck(): Promise<{
  status: "ok" | "degraded" | "down";
  checks: Record<string, { ok: boolean; latency?: number; error?: string }>;
}> {
  const checks: Record<string, { ok: boolean; latency?: number; error?: string }> = {};

  // Database check
  try {
    const start = Date.now();
    const { db } = await import("@workspace/db");
    const { sql } = await import("drizzle-orm");
    await db.execute(sql`SELECT 1`);
    checks.database = { ok: true, latency: Date.now() - start };
  } catch (e: any) {
    checks.database = { ok: false, error: e.message };
  }

  // Memory
  const mem = process.memoryUsage();
  const heapUsedMB = Math.round(mem.heapUsed / 1024 / 1024);
  checks.memory = { ok: heapUsedMB < 500, latency: heapUsedMB };

  // Uptime
  checks.uptime = { ok: true, latency: Math.round(process.uptime()) };

  const allOk = Object.values(checks).every(c => c.ok);
  const anyDown = Object.values(checks).some(c => !c.ok);

  return {
    status: anyDown ? "degraded" : "ok",
    checks,
  };
}
