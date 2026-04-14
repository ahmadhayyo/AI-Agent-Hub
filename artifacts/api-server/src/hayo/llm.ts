import Anthropic from "@anthropic-ai/sdk";

export function createAnthropicClient(): Anthropic {
  const directKey = process.env.ANTHROPIC_API_KEY;
  const proxyKey = process.env.AI_INTEGRATIONS_ANTHROPIC_API_KEY;
  const proxyBase = process.env.AI_INTEGRATIONS_ANTHROPIC_BASE_URL;

  if (proxyKey && proxyBase) {
    return new Anthropic({ apiKey: proxyKey, baseURL: proxyBase });
  }
  if (directKey) {
    return new Anthropic({ apiKey: directKey });
  }
  if (proxyKey) {
    return new Anthropic({ apiKey: proxyKey });
  }
  throw new Error("No Anthropic API key configured.");
}

function getClient(): Anthropic {
  return createAnthropicClient();
}

export type Message = {
  role: "user" | "assistant";
  content: string;
};

// ── OpenAI-compatible SSE streaming helper ─────────────────────────────────
async function streamOpenAICompat(
  url: string,
  authHeader: string,
  model: string,
  systemContent: string,
  messages: Message[],
  onStream: (chunk: string) => void
): Promise<string> {
  const res = await fetch(url, {
    method: "POST",
    headers: { Authorization: authHeader, "Content-Type": "application/json" },
    body: JSON.stringify({
      model,
      max_tokens: 4096,
      stream: true,
      messages: [{ role: "system", content: systemContent }, ...messages],
    }),
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`API error ${res.status}: ${errText}`);
  }

  let fullText = "";
  const reader = res.body?.getReader();
  const decoder = new TextDecoder();
  if (reader) {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = decoder.decode(value, { stream: true });
      for (const line of chunk.split("\n")) {
        const trimmed = line.trim();
        if (trimmed.startsWith("data: ") && !trimmed.includes("[DONE]")) {
          try {
            const data = JSON.parse(trimmed.slice(6));
            const delta = data.choices?.[0]?.delta?.content;
            if (delta) {
              fullText += delta;
              onStream(delta);
            }
          } catch {}
        }
      }
    }
  }
  return fullText;
}

// ── Non-streaming OpenAI-compatible call ───────────────────────────────────
async function callOpenAICompat(
  url: string,
  authHeader: string,
  model: string,
  systemContent: string,
  messages: Message[]
): Promise<string> {
  const res = await fetch(url, {
    method: "POST",
    headers: { Authorization: authHeader, "Content-Type": "application/json" },
    body: JSON.stringify({
      model,
      max_tokens: 4096,
      messages: [{ role: "system", content: systemContent }, ...messages],
    }),
  });
  const data = await res.json() as any;
  if (!res.ok || data.error) throw new Error(data.error?.message || `API error ${res.status}`);
  return data.choices?.[0]?.message?.content || "";
}

// ── Gemini helper with streaming simulation ────────────────────────────────
async function callGemini(
  systemContent: string,
  messages: Message[],
  onStream?: (chunk: string) => void
): Promise<string> {
  const key = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
  if (!key) throw new Error("GEMINI_API_KEY not set");

  // Use streamGenerateContent for streaming, generateContent otherwise
  const endpoint = onStream ? "streamGenerateContent" : "generateContent";
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:${endpoint}?key=${key}${onStream ? "&alt=sse" : ""}`;

  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: systemContent }] },
      contents: messages.map((m) => ({
        role: m.role === "assistant" ? "model" : "user",
        parts: [{ text: m.content }],
      })),
      generationConfig: { maxOutputTokens: 8192 },
    }),
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Gemini error ${res.status}: ${errText}`);
  }

  if (!onStream) {
    const data = await res.json() as any;
    if (data.error) throw new Error(data.error?.message || `Gemini error`);
    return data.candidates?.[0]?.content?.parts?.[0]?.text || "";
  }

  // Streaming mode
  let fullText = "";
  const reader = res.body?.getReader();
  const decoder = new TextDecoder();
  if (reader) {
    let buffer = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.startsWith("data: ")) continue;
        try {
          const data = JSON.parse(line.slice(6)) as any;
          const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
          if (text) {
            fullText += text;
            onStream(text);
          }
        } catch {}
      }
    }
  }
  return fullText;
}

// ── Anthropic streaming ────────────────────────────────────────────────────
async function streamClaude(
  claudeModel: string,
  systemContent: string,
  messages: Message[],
  onStream: (chunk: string) => void
): Promise<string> {
  const client = getClient();
  let fullText = "";
  const stream = await client.messages.create({
    model: claudeModel,
    max_tokens: 8192,
    system: systemContent,
    messages: messages.map((m) => ({ role: m.role, content: m.content })),
    stream: true,
  });
  for await (const event of stream) {
    if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
      fullText += event.delta.text;
      onStream(event.delta.text);
    }
  }
  return fullText;
}

async function callClaude(
  claudeModel: string,
  systemContent: string,
  messages: Message[]
): Promise<string> {
  const client = getClient();
  const response = await client.messages.create({
    model: claudeModel,
    max_tokens: 8192,
    system: systemContent,
    messages: messages.map((m) => ({ role: m.role, content: m.content })),
  });
  const block = response.content[0];
  return block.type === "text" ? block.text : "";
}

// ── Model routing map ──────────────────────────────────────────────────────
type ModelRoute =
  | { type: "claude"; model: string }
  | { type: "openai-compat"; url: string; envKey: string; model: string }
  | { type: "gemini" };

const DEFAULT_CLAUDE_MODEL = "claude-sonnet-4-5-20250929";
const CLAUDE_OPUS_MODEL   = "claude-opus-4-5-20251101";

function resolveModel(modelId?: string): ModelRoute {
  switch (modelId) {
    case "claude-opus":
      return { type: "claude", model: CLAUDE_OPUS_MODEL };
    case "gpt-4o":
      // Prefer OPENAI_API_KEY_5 which has gpt-4o access
      return { type: "openai-compat", url: "https://api.openai.com/v1/chat/completions", envKey: "OPENAI_API_KEY_5", model: "gpt-4o-2024-08-06" };
    case "deepseek-coder":
      return { type: "openai-compat", url: "https://api.deepseek.com/v1/chat/completions", envKey: "DEEPSEEK_API_KEY", model: "deepseek-reasoner" };
    case "gemini-pro":
      return { type: "gemini" };
    case "groq-llama":
      return { type: "openai-compat", url: "https://api.groq.com/openai/v1/chat/completions", envKey: "GROQ_API_KEY", model: "llama-3.3-70b-versatile" };
    case "mistral-large":
      return { type: "openai-compat", url: "https://api.mistral.ai/v1/chat/completions", envKey: "MISTRAL_API_KEY", model: "mistral-large-latest" };
    case "claude-sonnet":
    default:
      return { type: "claude", model: DEFAULT_CLAUDE_MODEL };
  }
}

// ── Main invokeLLM ─────────────────────────────────────────────────────────
export async function invokeLLM(
  messages: Message[],
  systemPrompt?: string,
  onStream?: (text: string) => void,
  model?: string
): Promise<string> {
  const systemContent =
    systemPrompt ||
    "أنت مساعد ذكاء اصطناعي متقدم من HAYO AI. أجب بشكل مفيد ودقيق. يمكنك الرد بالعربية أو الإنجليزية حسب لغة المستخدم.";

  const route = resolveModel(model);

  // DeepSeek fallback helper (always available)
  const deepseekFallback = async (): Promise<string> => {
    const apiKey = process.env.DEEPSEEK_API_KEY || process.env.OPENAI_API_KEY_;
    if (!apiKey) throw new Error("No fallback model available");
    if (onStream)
      return streamOpenAICompat("https://api.deepseek.com/v1/chat/completions", `Bearer ${apiKey}`, "deepseek-chat", systemContent, messages, onStream);
    return callOpenAICompat("https://api.deepseek.com/v1/chat/completions", `Bearer ${apiKey}`, "deepseek-chat", systemContent, messages);
  };

  try {
    if (route.type === "claude") {
      if (onStream) return await streamClaude(route.model, systemContent, messages, onStream);
      return await callClaude(route.model, systemContent, messages);
    }

    if (route.type === "gemini") {
      return await callGemini(systemContent, messages, onStream);
    }

    if (route.type === "openai-compat") {
      // Support fallback env var names for Replit AI integrations
      const fallbacks: Record<string, string> = {
        DEEPSEEK_API_KEY: "OPENAI_API_KEY_",
        OPENAI2_API_KEY: "OPENAI_API_KEY_6",
        HAYO_AI_AGENT: "OPENAI_API_KEY",
      };
      const apiKey = process.env[route.envKey] || (fallbacks[route.envKey] ? process.env[fallbacks[route.envKey]] : undefined);
      if (!apiKey) {
        console.warn(`[llm] ${route.envKey} not set, falling back to DeepSeek`);
        return deepseekFallback();
      }
      const authHeader = `Bearer ${apiKey}`;
      if (onStream) return streamOpenAICompat(route.url, authHeader, route.model, systemContent, messages, onStream);
      return callOpenAICompat(route.url, authHeader, route.model, systemContent, messages);
    }
  } catch (err: any) {
    console.error(`[llm] ${model} failed (${err.message}), falling back to DeepSeek`);
    return deepseekFallback();
  }

  // Final fallback
  return deepseekFallback();
}

export async function streamLLMToResponse(
  messages: Message[],
  systemPrompt: string | undefined,
  writeChunk: (chunk: string) => void,
  model?: string
): Promise<string> {
  return invokeLLM(messages, systemPrompt, writeChunk, model);
}
