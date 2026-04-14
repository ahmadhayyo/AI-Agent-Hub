/**
 * Chat Stream Routes — SSE streaming + Image + Video generation
 * POST /api/chat/stream
 * POST /api/chat/generate-image
 * POST /api/chat/generate-video
 */
import { Router } from "express";
import { callPowerAI, callProvider, type AIProvider } from "../hayo/providers.js";
import { authenticateRequest } from "../hayo/auth.js";
import {
  getConversation,
  getConversationMessages,
  addMessage,
  incrementUsage,
} from "../hayo/db.js";

const router = Router();

function getGeminiKey(): string {
  return process.env.GOOGLE_API_KEY3 || process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || "";
}

function getReplicateKey(): string {
  return process.env.REPLICATE_API_TOKEN || "";
}

// ─── POST /api/chat/stream — SSE Streaming ────────────────────────────
router.post("/chat/stream", async (req, res) => {
  const body = req.body || {};

  const rawConversationId = body.conversationId;
  const rawMessage = body.message || body.content || body.prompt;
  const rawMessages = body.messages;
  const rawModel = body.model || body.provider || "auto";
  const rawAttachments = body.attachments;
  const rawSystemPrompt = body.systemPrompt;

  let llmMessages: { role: string; content: string }[] = [];
  let systemPrompt = rawSystemPrompt || "أنت مساعد ذكاء اصطناعي متخصص في HAYO AI. أجب بدقة وإيجاز باللغة العربية.";
  let userMessageText = "";
  let shouldPersist = false;
  let conversationId: number | null = null;
  let userId: number | null = null;

  const user = await authenticateRequest(req);

  if (rawMessages && Array.isArray(rawMessages) && rawMessages.length > 0) {
    llmMessages = rawMessages;
    userMessageText = rawMessages.filter((m: any) => m.role === "user").slice(-1)[0]?.content || "";
    if (user) { userId = user.id; }

    if (rawConversationId && user) {
      conversationId = rawConversationId;
      const conv = await getConversation(conversationId!, user.id);
      if (conv) {
        await addMessage({
          conversationId: conversationId!,
          role: "user",
          content: userMessageText,
          attachments: rawAttachments as any,
        });
        systemPrompt = (conv as any).systemPrompt || systemPrompt;

        const history = await getConversationMessages(conversationId!);
        llmMessages = history
          .filter((m: any) => m.role !== "system")
          .slice(-20)
          .map((m: any) => ({ role: m.role as "user" | "assistant", content: m.content }));
        shouldPersist = true;
      }
    }
  } else if (rawConversationId && rawMessage) {
    if (!user) { res.status(401).json({ error: "غير مصرّح" }); return; }
    userId = user.id;
    conversationId = rawConversationId;
    const conv = await getConversation(conversationId!, user.id);
    if (!conv) { res.status(404).json({ error: "المحادثة غير موجودة" }); return; }

    await addMessage({
      conversationId: conversationId!,
      role: "user",
      content: rawMessage,
      attachments: rawAttachments as any,
    });

    const history = await getConversationMessages(conversationId!);
    llmMessages = history
      .filter((m: any) => m.role !== "system")
      .slice(-20)
      .map((m: any) => ({ role: m.role as "user" | "assistant", content: m.content }));
    systemPrompt = (conv as any).systemPrompt || systemPrompt;
    userMessageText = rawMessage;
    shouldPersist = true;
  } else if (rawMessage) {
    llmMessages = [{ role: "user", content: rawMessage }];
    userMessageText = rawMessage;
    if (user) { userId = user.id; }
  } else {
    res.status(400).json({ error: "يرجى إرسال رسالة للبدء" });
    return;
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");

  const send = (data: object) => {
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  let fullText = "";

  try {
    const provider = rawModel || "auto";
    let streamed = false;

    // Try streaming with DeepSeek
    const deepseekKey = process.env.DEEPSEEK_API_KEY;
    if (deepseekKey && (provider === "deepseek" || provider === "auto")) {
      try {
        const response = await fetch("https://api.deepseek.com/v1/chat/completions", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${deepseekKey}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: "deepseek-chat",
            max_tokens: 4096,
            stream: true,
            messages: [
              { role: "system", content: systemPrompt },
              ...llmMessages,
            ],
          }),
          signal: AbortSignal.timeout(90000),
        });

        if (response.ok && response.body) {
          send({ type: "start", model: "deepseek-chat" });
          const reader = response.body.getReader();
          const decoder = new TextDecoder();
          let buffer = "";

          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split("\n");
            buffer = lines.pop() || "";
            for (const line of lines) {
              if (!line.startsWith("data: ")) continue;
              const raw = line.slice(6).trim();
              if (raw === "[DONE]") break;
              try {
                const chunk = JSON.parse(raw);
                const delta = chunk.choices?.[0]?.delta?.content;
                if (delta) {
                  fullText += delta;
                  send({ type: "chunk", text: delta });
                }
              } catch {}
            }
          }
          streamed = true;
        }
      } catch (e: any) {
        console.warn("[chat-stream] DeepSeek streaming failed:", e.message?.slice(0, 80));
      }
    }

    // Try streaming with Anthropic Claude
    if (!streamed && (provider === "claude" || provider === "auto")) {
      try {
        const { createAnthropicClient } = await import("../hayo/llm.js");
        const anthropic = createAnthropicClient();
        send({ type: "start", model: "claude-sonnet-4-20250514" });

        const stream = anthropic.messages.stream({
          model: "claude-sonnet-4-20250514",
          max_tokens: 4096,
          system: systemPrompt,
          messages: llmMessages.map((m: any) => ({ role: m.role, content: m.content })),
        });

        for await (const event of stream) {
          if (event.type === "content_block_delta" && (event.delta as any).type === "text_delta") {
            const text = (event.delta as any).text;
            fullText += text;
            send({ type: "chunk", text });
          }
        }
        streamed = true;
      } catch (e: any) {
        console.warn("[chat-stream] Claude streaming failed:", e.message?.slice(0, 80));
      }
    }

    // Try streaming with Gemini
    if (!streamed && (provider === "gemini" || provider === "auto")) {
      const gemKey = getGeminiKey();
      if (gemKey) {
        try {
          const gemRes = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${gemKey}`,
            {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                systemInstruction: { parts: [{ text: systemPrompt }] },
                contents: llmMessages.map((m: any) => ({
                  role: m.role === "assistant" ? "model" : "user",
                  parts: [{ text: m.content }],
                })),
                generationConfig: { maxOutputTokens: 4096 },
              }),
              signal: AbortSignal.timeout(60000),
            }
          );
          const gd = await gemRes.json() as any;
          const text = gd.candidates?.[0]?.content?.parts?.[0]?.text || "";
          if (text) {
            send({ type: "start", model: "gemini-2.5-flash" });
            fullText = text;
            send({ type: "chunk", text });
            streamed = true;
          }
        } catch (e: any) {
          console.warn("[chat-stream] Gemini failed:", e.message?.slice(0, 80));
        }
      }
    }

    // Fallback: non-streaming via callPowerAI
    if (!streamed) {
      send({ type: "start", model: "auto" });
      const result = await callPowerAI(systemPrompt, userMessageText, 4096);
      fullText = result.content;
      send({ type: "chunk", text: result.content });
    }

    let aiMsgId: number | null = null;
    if (shouldPersist && conversationId) {
      aiMsgId = await addMessage({
        conversationId,
        role: "assistant",
        content: fullText,
      });
    }
    if (userId) {
      await incrementUsage(userId);
    }

    send({ type: "done", messageId: aiMsgId, fullText });
    res.end();
  } catch (e: any) {
    send({ type: "error", error: e.message || "خطأ غير معروف" });
    res.end();
  }
});

// ─── POST /api/chat/generate-image ────────────────────────────────────
router.post("/chat/generate-image", async (req, res) => {
  const { prompt, style = "realistic", size = "1024x1024" } = req.body as {
    prompt: string;
    style?: string;
    size?: string;
  };

  if (!prompt) {
    res.status(400).json({ error: "prompt required" });
    return;
  }

  try {
    const replicateKey = getReplicateKey();
    const openaiKey    = process.env.OPENAI_API_KEY;

    if (openaiKey) {
      const r = await fetch("https://api.openai.com/v1/images/generations", {
        method: "POST",
        headers: { Authorization: `Bearer ${openaiKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "dall-e-3",
          prompt: `${prompt}. Style: ${style}`,
          n: 1,
          size,
        }),
        signal: AbortSignal.timeout(60000),
      });
      const d = await r.json() as any;
      if (r.ok && d.data?.[0]?.url) {
        res.json({ imageUrl: d.data[0].url, model: "dall-e-3" });
        return;
      }
    }

    if (replicateKey) {
      const r = await fetch("https://api.replicate.com/v1/models/black-forest-labs/flux-schnell/predictions", {
        method: "POST",
        headers: { Authorization: `Bearer ${replicateKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({ input: { prompt, num_outputs: 1 } }),
        signal: AbortSignal.timeout(90000),
      });
      const d = await r.json() as any;
      if (r.ok && d.id) {
        for (let i = 0; i < 30; i++) {
          await new Promise(r => setTimeout(r, 3000));
          const poll = await fetch(`https://api.replicate.com/v1/predictions/${d.id}`, {
            headers: { Authorization: `Bearer ${replicateKey}` },
          });
          const status = await poll.json() as any;
          if (status.status === "succeeded" && status.output?.[0]) {
            res.json({ imageUrl: status.output[0], model: "flux-schnell" });
            return;
          }
          if (status.status === "failed") break;
        }
      }
    }

    const gemKey = getGeminiKey();
    const svgPrompt = `Create a minimal artistic SVG image for: "${prompt}". Return ONLY the SVG code, nothing else. Make it colorful and visually interesting. Size: 512x512.`;
    let svgContent = "";
    if (gemKey) {
      const gemRes = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${gemKey}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            contents: [{ role: "user", parts: [{ text: svgPrompt }] }],
            generationConfig: { maxOutputTokens: 2048 },
          }),
        }
      );
      const gd = await gemRes.json() as any;
      svgContent = gd.candidates?.[0]?.content?.parts?.[0]?.text || "";
    }
    const svgMatch = svgContent.match(/<svg[\s\S]*<\/svg>/i);
    if (svgMatch) {
      const b64 = Buffer.from(svgMatch[0]).toString("base64");
      res.json({ imageUrl: `data:image/svg+xml;base64,${b64}`, model: "gemini-svg" });
      return;
    }

    res.status(503).json({ error: "لا يوجد مزود توليد صور متاح. أضف REPLICATE_API_TOKEN أو OPENAI_API_KEY." });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

// ─── POST /api/chat/generate-video ────────────────────────────────────
router.post("/chat/generate-video", async (req, res) => {
  const { prompt, duration = 5 } = req.body as { prompt: string; duration?: number };

  if (!prompt) {
    res.status(400).json({ error: "prompt required" });
    return;
  }

  const replicateKey = getReplicateKey();

  if (!replicateKey) {
    res.status(503).json({
      error: "توليد الفيديو يتطلب REPLICATE_API_TOKEN. أضفه في الإعدادات.",
      fallback: true,
    });
    return;
  }

  try {
    const r = await fetch("https://api.replicate.com/v1/models/minimax/video-01/predictions", {
      method: "POST",
      headers: { Authorization: `Bearer ${replicateKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({ input: { prompt, duration } }),
      signal: AbortSignal.timeout(300000),
    });
    const d = await r.json() as any;
    if (!r.ok) {
      res.status(500).json({ error: d.detail || "فشل توليد الفيديو" });
      return;
    }

    for (let i = 0; i < 60; i++) {
      await new Promise(r => setTimeout(r, 5000));
      const poll = await fetch(`https://api.replicate.com/v1/predictions/${d.id}`, {
        headers: { Authorization: `Bearer ${replicateKey}` },
      });
      const status = await poll.json() as any;
      if (status.status === "succeeded" && status.output) {
        res.json({ videoUrl: status.output, model: "minimax-video-01" });
        return;
      }
      if (status.status === "failed") {
        res.status(500).json({ error: "فشل توليد الفيديو: " + (status.error || "خطأ غير معروف") });
        return;
      }
    }

    res.status(504).json({ error: "انتهت مهلة توليد الفيديو" });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

export default router;
