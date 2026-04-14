/**
 * Multi-Model AI Provider System
 * claude:    Claude Opus 4.6   — Anthropic (PRIMARY ✅)
 * gpt4:      GPT-4o            — OpenAI    (working ✅)
 * gemini:    Gemini 2.5 Flash  — Google    (no key ❌)
 * geminiPro: Gemini 2.5 Pro   — Google    (no key ❌)
 * deepseek:  DeepSeek R1       — DeepSeek  (working ✅)
 *
 * Active keys: OPENAI_API_KEY (gpt-4o-2024-08-06) + OPENAI_API_KEY_ (DeepSeek)
 */
import { createAnthropicClient } from "./llm";

export type AIProvider = "claude" | "gpt4" | "gemini" | "geminiPro" | "deepseek";

/** DeepSeek API key — stored as DEEPSEEK_API_KEY or OPENAI_API_KEY_ (both valid) */
const dsKey = () => process.env.DEEPSEEK_API_KEY || process.env.OPENAI_API_KEY_ || "";

export interface ProviderConfig {
  id: AIProvider;
  name: string;
  model: string;
  icon: string;
  color: string;
  role: string;
  envKey: string;
}

export const PROVIDER_CONFIGS: Record<AIProvider, ProviderConfig> = {
  claude: {
    id: "claude",
    name: "Claude Opus",
    model: "claude-opus-4-6",
    icon: "🟣",
    color: "#7C3AED",
    role: "coordinator",
    envKey: "AI_INTEGRATIONS_ANTHROPIC_API_KEY",
  },
  gpt4: {
    id: "gpt4",
    name: "GPT-4o",
    model: "gpt-4o-2024-08-06",
    icon: "🟡",
    color: "#10A37F",
    role: "coder",
    envKey: "OPENAI_API_KEY",
  },
  gemini: {
    id: "gemini",
    name: "Gemini 2.5 Flash",
    model: "gemini-2.5-flash",
    icon: "🔵",
    color: "#3B82F6",
    role: "reviewer",
    envKey: "GOOGLE_API_KEY3",
  },
  geminiPro: {
    id: "geminiPro",
    name: "Gemini 2.5 Pro",
    model: "gemini-2.5-pro",
    icon: "💎",
    color: "#06B6D4",
    role: "deep-analyst",
    envKey: "GOOGLE_API_KEY3",
  },
  deepseek: {
    id: "deepseek",
    name: "DeepSeek R1",
    model: "deepseek-reasoner",
    icon: "⚡",
    color: "#F59E0B",
    role: "planner",
    envKey: "DEEPSEEK_API_KEY",
  },
};

export function isProviderAvailable(provider: AIProvider): boolean {
  if (provider === "claude") {
    return !!(process.env.ANTHROPIC_API_KEY || process.env.AI_INTEGRATIONS_ANTHROPIC_API_KEY);
  }
  if (provider === "gpt4") {
    return !!(process.env.OPENAI_API_KEY);
  }
  if (provider === "deepseek") {
    return !!(dsKey());
  }
  const config = PROVIDER_CONFIGS[provider];
  return !!(process.env[config.envKey]);
}

export function getAvailableProviders(): ProviderConfig[] {
  return Object.values(PROVIDER_CONFIGS).map(p => ({
    ...p,
    available: isProviderAvailable(p.id as AIProvider),
  } as any));
}

/**
 * Call a specific AI provider with a prompt.
 * Falls back to the best available model when the requested one is unavailable.
 * Priority fallback: gpt4 (OpenAI) → deepseek-chat → deepseek-reasoner
 */
export async function callProvider(
  provider: AIProvider,
  systemPrompt: string,
  userMessage: string
): Promise<{ content: string; provider: AIProvider; duration: number }> {
  const startTime = Date.now();

  let enrichedPrompt = systemPrompt;
  try {
    const { withModelInstruction, resolveModelId } = await import("./system-prompts.js");
    enrichedPrompt = withModelInstruction(resolveModelId(provider), systemPrompt);
  } catch {}

  // Determine the actual provider to use (fallback to best available)
  let actualProvider: AIProvider = provider;
  if (!isProviderAvailable(provider)) {
    if (isProviderAvailable("gpt4")) actualProvider = "gpt4";
    else actualProvider = "deepseek";
  }

  try {
    let content = "";

    switch (actualProvider) {
      case "claude": {
        const anthropic = createAnthropicClient();
        const result = await anthropic.messages.create({
          model: PROVIDER_CONFIGS.claude.model,
          max_tokens: 8192,
          system: systemPrompt,
          messages: [{ role: "user", content: userMessage }],
        });
        content = result.content[0].type === "text" ? result.content[0].text : "";
        break;
      }

      case "gpt4": {
        // GPT-4o via OpenAI ✅
        const res = await fetch("https://api.openai.com/v1/chat/completions", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: PROVIDER_CONFIGS.gpt4.model, // gpt-4o-2024-08-06
            max_tokens: 4096,
            messages: [
              { role: "system", content: systemPrompt },
              { role: "user", content: userMessage },
            ],
          }),
          signal: AbortSignal.timeout(60000),
        });
        const data = await res.json() as any;
        if (!res.ok || data.error) throw new Error(`OpenAI error: ${data.error?.message || res.status}`);
        content = data.choices?.[0]?.message?.content || "";
        break;
      }

      case "gemini":
      case "geminiPro": {
        const geminiKey = process.env.GOOGLE_API_KEY3 || process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
        const geminiBody = JSON.stringify({
          systemInstruction: { parts: [{ text: systemPrompt }] },
          contents: [{ role: "user", parts: [{ text: userMessage }] }],
          generationConfig: { maxOutputTokens: 8192, temperature: 0.3 },
        });
        const modelsToTry = actualProvider === "geminiPro"
          ? ["gemini-2.5-pro", "gemini-2.5-flash"]
          : ["gemini-2.5-flash"];
        let geminiData: any;
        let geminiOk = false;
        let usedModel = "";
        for (const model of modelsToTry) {
          for (let retry = 0; retry < 2; retry++) {
            try {
              const res = await fetch(
                `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${geminiKey}`,
                {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: geminiBody,
                  signal: AbortSignal.timeout(60000),
                }
              );
              geminiData = await res.json() as any;
              if (res.status === 503 || res.status === 429) {
                if (retry === 0) { await new Promise(r => setTimeout(r, 4000)); continue; }
                break;
              }
              if (!res.ok || geminiData.error) {
                if (retry === 0) { await new Promise(r => setTimeout(r, 2000)); continue; }
                break;
              }
              geminiOk = true;
              usedModel = model;
              break;
            } catch { if (retry === 0) { await new Promise(r => setTimeout(r, 2000)); continue; } break; }
          }
          if (geminiOk) break;
        }
        if (!geminiOk) {
          throw new Error(`Gemini: خوادم Google مشغولة — حاول بعد قليل`);
        }
        content = geminiData.candidates?.[0]?.content?.parts?.[0]?.text || "";
        if (usedModel && usedModel !== PROVIDER_CONFIGS[actualProvider].model) {
          content = `[تم استخدام ${usedModel} بدلاً من ${PROVIDER_CONFIGS[actualProvider].model} بسبب ضغط الخوادم]\n\n${content}`;
        }
        break;
      }

      case "deepseek": {
        const res = await fetch("https://api.deepseek.com/v1/chat/completions", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${dsKey()}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: PROVIDER_CONFIGS.deepseek.model,
            max_tokens: 4096,
            messages: [
              { role: "system", content: systemPrompt },
              { role: "user", content: userMessage },
            ],
          }),
          signal: AbortSignal.timeout(60000),
        });
        const data = await res.json() as any;
        if (!res.ok || data.error) {
          throw new Error(`DeepSeek API error ${res.status}: ${data.error?.message || JSON.stringify(data)}`);
        }
        content = data.choices?.[0]?.message?.content || "";
        break;
      }
    }

    return {
      content,
      provider: actualProvider,
      duration: Date.now() - startTime,
    };
  } catch (error: any) {
    throw new Error(`[${actualProvider}] ${error.message}`);
  }
}

/**
 * Power AI call — uses the strongest available model for heavy tasks.
 * Priority (as of 2025): GPT-4o → DeepSeek Chat → DeepSeek Reasoner
 * (Anthropic has active, Gemini has no key)
 */
export async function callPowerAI(
  systemPrompt: string,
  userMessage: string,
  maxTokens = 8192
): Promise<{ content: string; modelUsed: string }> {
  let enrichedPrompt = systemPrompt;
  try { const { withModelInstruction } = await import("./system-prompts.js"); enrichedPrompt = withModelInstruction("gpt-4o", systemPrompt); } catch {}

  const openaiKey = process.env.OPENAI_API_KEY;
  const hasAnthropicKey = process.env.ANTHROPIC_API_KEY || (process.env.AI_INTEGRATIONS_ANTHROPIC_API_KEY && process.env.AI_INTEGRATIONS_ANTHROPIC_BASE_URL);
  const geminiKey = process.env.GOOGLE_API_KEY3 || process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;

  // 3. GPT-4o (fallback ✅)
  if (openaiKey) {
    try {
      const res = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: { Authorization: `Bearer ${openaiKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "gpt-4o-2024-08-06",
          max_tokens: Math.min(maxTokens, 4096),
          messages: [{ role: "system", content: systemPrompt }, { role: "user", content: userMessage }],
        }),
        signal: AbortSignal.timeout(90000),
      });
      const data = await res.json() as any;
      if (res.ok && !data.error) {
        const content = data.choices?.[0]?.message?.content || "";
        if (content) return { content, modelUsed: "gpt-4o-2024-08-06" };
      }
      console.warn("[callPowerAI] gpt-4o failed:", data.error?.message?.slice(0, 80));
    } catch (e: any) {
      console.warn("[callPowerAI] gpt-4o error:", e.message?.slice(0, 80));
    }
  }

  // 1. Claude Opus 4.6 (PRIMARY (try if key exists — may fail due to low credits)
  if (hasAnthropicKey) {
    try {
      const anthropic = createAnthropicClient();
      const result = await anthropic.messages.create({
        model: "claude-opus-4-6",
        max_tokens: Math.min(maxTokens, 8192),
        system: systemPrompt,
        messages: [{ role: "user", content: userMessage }],
      });
      const block = result.content[0];
      return { content: block.type === "text" ? block.text : "", modelUsed: "claude-opus-4-6" };
    } catch (e: any) {
      console.warn("[callPowerAI] claude-opus-4-6 failed:", e.message?.slice(0, 80));
    }
  }

  // 4. Gemini 2.5 Flash (if key becomes available)
  if (geminiKey) {
    try {
      const res = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${geminiKey}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            systemInstruction: { parts: [{ text: systemPrompt }] },
            contents: [{ role: "user", parts: [{ text: userMessage }] }],
            generationConfig: { maxOutputTokens: Math.min(maxTokens, 8192), temperature: 0.2 },
          }),
          signal: AbortSignal.timeout(60000),
        }
      );
      const data = await res.json() as any;
      if (res.ok && !data.error) {
        const content = data.candidates?.[0]?.content?.parts?.[0]?.text || "";
        if (content) return { content, modelUsed: "gemini-2.5-flash" };
      }
    } catch (e: any) {
      console.warn("[callPowerAI] Gemini error:", e.message?.slice(0, 80));
    }
  }

  // 2. DeepSeek Chat (SECONDARY (fast, working ✅)
  if (dsKey()) {
    try {
      const res = await fetch("https://api.deepseek.com/v1/chat/completions", {
        method: "POST",
        headers: { Authorization: `Bearer ${dsKey()}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "deepseek-chat",
          max_tokens: Math.min(maxTokens, 8192),
          messages: [{ role: "system", content: systemPrompt }, { role: "user", content: userMessage }],
        }),
        signal: AbortSignal.timeout(120000),
      });
      const data = await res.json() as any;
      if (res.ok && !data.error) {
        const content = data.choices?.[0]?.message?.content || "";
        if (content) return { content, modelUsed: "deepseek-chat" };
      }
      console.warn("[callPowerAI] deepseek-chat failed:", data.error?.message?.slice(0, 80));
    } catch (e: any) {
      console.warn("[callPowerAI] deepseek-chat error:", e.message?.slice(0, 80));
    }
  }

  // 5. DeepSeek Reasoner (slow but powerful ✅ — last resort)
  if (dsKey()) {
    const res = await fetch("https://api.deepseek.com/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${dsKey()}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "deepseek-reasoner",
        max_tokens: Math.min(maxTokens, 8192),
        messages: [{ role: "system", content: systemPrompt }, { role: "user", content: userMessage }],
      }),
      signal: AbortSignal.timeout(180000),
    });
    const data = await res.json() as any;
    if (res.ok && !data.error) return { content: data.choices?.[0]?.message?.content || "", modelUsed: "deepseek-reasoner" };
  }

  throw new Error("لا يوجد نموذج AI قوي متاح. يرجى التحقق من الإعدادات.");
}

/**
 * Fast AI call for Office Suite / quick tasks.
 * Priority: DeepSeek Chat (fast ✅) → GPT-4o (✅) → Anthropic (❌ no credits)
 * The `model` param is kept for API compatibility but DeepSeek is used first.
 */
export async function callOfficeAI(
  systemPrompt: string,
  userMessage: string,
  maxTokens = 8192,
  model: "claude-haiku-4-5" | "claude-sonnet-4-6" = "claude-haiku-4-5"
): Promise<string> {
  let enrichedPrompt = systemPrompt;
  try { const { withModelInstruction } = await import("./system-prompts.js"); enrichedPrompt = withModelInstruction("gpt-4o", systemPrompt); } catch {}

  // 1. DeepSeek Chat — fast and working ✅
  if (dsKey()) {
    try {
      const res = await fetch("https://api.deepseek.com/v1/chat/completions", {
        method: "POST",
        headers: { Authorization: `Bearer ${dsKey()}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "deepseek-chat",
          max_tokens: Math.min(maxTokens, 8192),
          messages: [{ role: "system", content: systemPrompt }, { role: "user", content: userMessage }],
        }),
        signal: AbortSignal.timeout(90000),
      });
      const data = await res.json() as any;
      if (res.ok && !data.error) {
        const content = data.choices?.[0]?.message?.content || "";
        if (content) return content;
      }
    } catch (e: any) {
      console.warn("[callOfficeAI] deepseek-chat error:", e.message?.slice(0, 80));
    }
  }

  // 2. GPT-4o — working ✅
  const openaiKey = process.env.OPENAI_API_KEY;
  if (openaiKey) {
    try {
      const res = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: { Authorization: `Bearer ${openaiKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "gpt-4o-2024-08-06",
          max_tokens: Math.min(maxTokens, 4096),
          messages: [{ role: "system", content: systemPrompt }, { role: "user", content: userMessage }],
        }),
        signal: AbortSignal.timeout(60000),
      });
      const data = await res.json() as any;
      if (res.ok && !data.error) return data.choices?.[0]?.message?.content || "";
    } catch (e: any) {
      console.warn("[callOfficeAI] gpt-4o error:", e.message?.slice(0, 80));
    }
  }

  // 3. Anthropic fallback (may fail due to low credits)
  const hasAnthropicKey = process.env.ANTHROPIC_API_KEY || (process.env.AI_INTEGRATIONS_ANTHROPIC_API_KEY && process.env.AI_INTEGRATIONS_ANTHROPIC_BASE_URL);
  if (hasAnthropicKey) {
    try {
      const anthropic = createAnthropicClient();
      const result = await anthropic.messages.create({
        model,
        max_tokens: maxTokens,
        system: systemPrompt,
        messages: [{ role: "user", content: userMessage }],
      });
      const block = result.content[0];
      return block.type === "text" ? block.text : "";
    } catch (e: any) {
      console.warn(`[callOfficeAI] ${model} failed:`, e.message?.slice(0, 80));
    }
  }

  throw new Error("لا يوجد مزود AI متاح. يرجى التحقق من الإعدادات.");
}

/**
 * Fast AI call — DeepSeek Chat first, fallback to callPowerAI.
 * Returns { content, modelUsed } like callPowerAI.
 * Used for quick validation passes where speed matters more than depth.
 */
export async function callFastAI(
  systemPrompt: string,
  userMessage: string,
  maxTokens = 8192,
): Promise<{ content: string; modelUsed: string }> {
  let enrichedPrompt = systemPrompt;
  try { const { withModelInstruction } = await import("./system-prompts.js"); enrichedPrompt = withModelInstruction("gpt-4o", systemPrompt); } catch {}

  // 1. DeepSeek Chat — fastest available
  if (dsKey()) {
    try {
      const res = await fetch("https://api.deepseek.com/v1/chat/completions", {
        method: "POST",
        headers: { Authorization: `Bearer ${dsKey()}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "deepseek-chat",
          max_tokens: Math.min(maxTokens, 8192),
          messages: [{ role: "system", content: systemPrompt }, { role: "user", content: userMessage }],
        }),
        signal: AbortSignal.timeout(90000),
      });
      const data = await res.json() as any;
      if (res.ok && !data.error) {
        const content = data.choices?.[0]?.message?.content || "";
        if (content) return { content, modelUsed: "deepseek-chat" };
      }
      console.warn("[callFastAI] deepseek-chat failed:", data.error?.message?.slice(0, 80));
    } catch (e: any) {
      console.warn("[callFastAI] deepseek-chat error:", e.message?.slice(0, 80));
    }
  }
  // 2. Fallback to the full power AI chain
  return callPowerAI(systemPrompt, userMessage, maxTokens);
}
