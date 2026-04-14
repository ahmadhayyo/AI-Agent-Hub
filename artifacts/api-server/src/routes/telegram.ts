/**
 * Telegram Bot Setup Routes
 * GET  /api/telegram/status
 * POST /api/telegram/setup
 * POST /api/telegram/test
 * POST /api/telegram/send
 */
import { Router } from "express";

const router = Router();

// ─── GET /api/telegram/status ─────────────────────────────────────────
router.get("/telegram/status", async (_req, res) => {
  const tradingToken = process.env.TELEGRAM_BOT_TOKEN;
  const bridgeToken  = process.env.TELEGRAM_BRIDGE_BOT_TOKEN;
  const appUrl       = process.env.APP_URL || "";
  const ownerId      = process.env.TELEGRAM_OWNER_CHAT_ID || "";

  const bots: any[] = [];

  for (const [label, token, path] of [
    ["Trading Bot", tradingToken, "/api/telegram/whook/trading"],
    ["Bridge Bot",  bridgeToken,  "/api/telegram/whook/bridge"],
  ] as const) {
    if (!token) {
      bots.push({ label, status: "not_configured", token: null });
      continue;
    }

    try {
      const r = await fetch(`https://api.telegram.org/bot${token}/getMe`);
      const d = await r.json() as any;
      const wh = await fetch(`https://api.telegram.org/bot${token}/getWebhookInfo`);
      const whd = await wh.json() as any;

      bots.push({
        label,
        status: d.ok ? "active" : "error",
        username: d.result?.username,
        firstName: d.result?.first_name,
        webhookUrl: whd.result?.url || null,
        pendingUpdates: whd.result?.pending_update_count || 0,
        lastError: whd.result?.last_error_message || null,
        expectedWebhook: appUrl ? `${appUrl}${path}` : null,
      });
    } catch (e: any) {
      bots.push({ label, status: "error", error: e.message });
    }
  }

  res.json({
    configured: bots.some(b => b.status === "active"),
    appUrl,
    ownerId,
    bots,
  });
});

// ─── POST /api/telegram/setup — Register webhooks ─────────────────────
router.post("/telegram/setup", async (req, res) => {
  const { appUrl } = req.body as { appUrl?: string };
  const url = (appUrl || process.env.APP_URL || "").replace(/\/$/, "");

  if (!url) {
    res.status(400).json({ error: "appUrl required or set APP_URL env var" });
    return;
  }

  const tradingToken = process.env.TELEGRAM_BOT_TOKEN;
  const bridgeToken  = process.env.TELEGRAM_BRIDGE_BOT_TOKEN;
  const results: any[] = [];

  for (const [label, token, path] of [
    ["Trading Bot", tradingToken, "/api/telegram/whook/trading"],
    ["Bridge Bot",  bridgeToken,  "/api/telegram/whook/bridge"],
  ] as const) {
    if (!token) {
      results.push({ label, success: false, error: "Token not configured" });
      continue;
    }

    try {
      const webhookUrl = `${url}${path}`;
      const encoded = encodeURIComponent(webhookUrl);
      const r = await fetch(
        `https://api.telegram.org/bot${token}/setWebhook?url=${encoded}&drop_pending_updates=true&allowed_updates=["message","callback_query"]`,
        { method: "POST" }
      );
      const d = await r.json() as any;
      results.push({
        label,
        success: d.ok,
        webhookUrl,
        description: d.description || "ok",
      });
    } catch (e: any) {
      results.push({ label, success: false, error: e.message });
    }
  }

  res.json({ results, appUrl: url });
});

// ─── POST /api/telegram/test — Send test message to owner ─────────────
router.post("/telegram/test", async (req, res) => {
  const { bot = "bridge", message = "🧪 HAYO AI — رسالة اختبار ✅" } = req.body as {
    bot?: "trading" | "bridge";
    message?: string;
  };

  const token   = bot === "trading"
    ? process.env.TELEGRAM_BOT_TOKEN
    : process.env.TELEGRAM_BRIDGE_BOT_TOKEN;
  const ownerId = process.env.TELEGRAM_OWNER_CHAT_ID;

  if (!token) {
    res.status(400).json({ error: `${bot} bot token not configured` });
    return;
  }
  if (!ownerId) {
    res.status(400).json({ error: "TELEGRAM_OWNER_CHAT_ID not set" });
    return;
  }

  try {
    const r = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: ownerId, text: message, parse_mode: "Markdown" }),
    });
    const d = await r.json() as any;
    if (d.ok) {
      res.json({ success: true, messageId: d.result?.message_id });
    } else {
      res.status(400).json({ success: false, error: d.description });
    }
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

// ─── POST /api/telegram/send — Send custom message to owner ───────────
router.post("/telegram/send", async (req, res) => {
  const { text, bot = "bridge", parseMode = "Markdown" } = req.body as {
    text: string;
    bot?: "trading" | "bridge";
    parseMode?: "Markdown" | "HTML";
  };

  if (!text) {
    res.status(400).json({ error: "text required" });
    return;
  }

  const token   = bot === "trading"
    ? process.env.TELEGRAM_BOT_TOKEN
    : process.env.TELEGRAM_BRIDGE_BOT_TOKEN;
  const ownerId = process.env.TELEGRAM_OWNER_CHAT_ID;

  if (!token || !ownerId) {
    res.status(400).json({ error: "Telegram not configured" });
    return;
  }

  try {
    const r = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: ownerId, text: text.substring(0, 4096), parse_mode: parseMode }),
    });
    const d = await r.json() as any;
    res.json({ success: d.ok, messageId: d.result?.message_id, error: d.description });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

export default router;
