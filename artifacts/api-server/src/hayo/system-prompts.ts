/**
 * System Prompts Manager — Customizable AI Model Instructions
 * Allows per-model custom instructions (like ChatGPT Custom Instructions)
 * Instructions are stored in-memory with defaults; use DB for persistence if needed.
 */

export type ModelId = "claude" | "gpt-4o" | "deepseek" | "gemini" | "groq" | "mistral";

export interface ModelInstruction {
  modelId: ModelId;
  name: string;
  icon: string;
  defaultInstruction: string;
  customInstruction?: string;
}

const DEFAULT_INSTRUCTIONS: Record<ModelId, Omit<ModelInstruction, "modelId">> = {
  claude: {
    name: "Claude Opus",
    icon: "🟣",
    defaultInstruction:
      "أنت Claude Opus، مساعد ذكاء اصطناعي متقدم من Anthropic. أجب دائماً بدقة عالية وتحليل عميق. تخصصك: التحليل المعقد، الكتابة الإبداعية، حل المشكلات الصعبة. استخدم العربية الفصيحة عند التحدث بالعربية.",
  },
  "gpt-4o": {
    name: "GPT-4o",
    icon: "🟡",
    defaultInstruction:
      "أنت GPT-4o، نموذج متعدد الوسائط من OpenAI. أجب بدقة وإيجاز. تخصصك: الكود، التحليل، الرياضيات، الإبداع. عند استقبال صور أو ملفات، حللها بدقة. استخدم أسلوباً واضحاً ومنظماً.",
  },
  deepseek: {
    name: "DeepSeek",
    icon: "⚡",
    defaultInstruction:
      "أنت DeepSeek، نموذج ذكاء اصطناعي قوي. تتميز في: البرمجة، الرياضيات، التفكير المنطقي العميق. أجب بشكل منهجي خطوة بخطوة. إذا كان السؤال تقنياً، قدم الكود مع الشرح.",
  },
  gemini: {
    name: "Gemini",
    icon: "🔵",
    defaultInstruction:
      "أنت Gemini من Google، نموذج متعدد الوسائط. تتميز في: تحليل الصور والفيديو، البحث العلمي، الإجابات الموسوعية. قدم معلومات دقيقة ومحدثة. استخدم تنسيقاً واضحاً مع نقاط عند الضرورة.",
  },
  groq: {
    name: "Groq LLaMA",
    icon: "🚀",
    defaultInstruction:
      "أنت Groq LLaMA، نموذج سريع الاستجابة. تتميز في: الإجابات الفورية، المهام البسيطة والمتوسطة، المحادثة الطبيعية. أجب بسرعة ووضوح. للمهام المعقدة، وضح إذا كنت بحاجة لنموذج أقوى.",
  },
  mistral: {
    name: "Mistral",
    icon: "🌬️",
    defaultInstruction:
      "أنت Mistral، نموذج أوروبي متميز. تتميز في: اللغات المتعددة، الكتابة الأكاديمية، التحليل الدقيق. أجب بأسلوب أكاديمي مهني عند الطلب. دعم ممتاز للغة الفرنسية والعربية والإنجليزية.",
  },
};

// In-memory store (persisted across requests within same server instance)
const customInstructions = new Map<ModelId, string>();

/**
 * Get the active instruction for a model (custom if set, otherwise default)
 */
export function getModelInstruction(modelId: ModelId): string {
  const custom = customInstructions.get(modelId);
  if (custom !== undefined) return custom;
  return DEFAULT_INSTRUCTIONS[modelId]?.defaultInstruction || "";
}

/**
 * Set a custom instruction for a model
 */
export function setModelInstruction(modelId: ModelId, instruction: string): void {
  customInstructions.set(modelId, instruction.trim());
}

/**
 * Reset a model's instruction to its default
 */
export function resetModelInstruction(modelId: ModelId): void {
  customInstructions.delete(modelId);
}

/**
 * Get all model instructions (for the settings UI)
 */
export function getAllInstructions(): (ModelInstruction & { isCustomized: boolean })[] {
  const modelIds: ModelId[] = ["claude", "gpt-4o", "deepseek", "gemini", "groq", "mistral"];
  return modelIds.map(id => ({
    modelId: id,
    ...DEFAULT_INSTRUCTIONS[id],
    customInstruction: customInstructions.get(id),
    isCustomized: customInstructions.has(id),
    activeInstruction: getModelInstruction(id),
  }));
}

/**
 * Prepend the model's active instruction to any system prompt
 * If the system prompt already starts with the instruction, don't duplicate it.
 */
export function withModelInstruction(modelId: ModelId, systemPrompt: string): string {
  const instruction = getModelInstruction(modelId);
  if (!instruction) return systemPrompt;
  if (systemPrompt.includes(instruction.substring(0, 30))) return systemPrompt;
  return `${instruction}\n\n${systemPrompt}`.trim();
}

/**
 * Quick lookup map from provider string to ModelId
 */
export function resolveModelId(provider: string): ModelId {
  const map: Record<string, ModelId> = {
    claude:    "claude",
    gpt4:      "gpt-4o",
    "gpt-4o":  "gpt-4o",
    openai:    "gpt-4o",
    deepseek:  "deepseek",
    gemini:    "gemini",
    geminiPro: "gemini",
    groq:      "groq",
    mistral:   "mistral",
  };
  return map[provider] || "gpt-4o";
}
