/**
 * Prompt Factory Routes
 * POST /api/prompt-factory/generate
 * POST /api/prompt-factory/refine
 * POST /api/prompt-factory/test
 */
import { Router } from "express";
import { callPowerAI, callOfficeAI } from "../hayo/providers.js";

const router = Router();

// ─── POST /api/prompt-factory/generate ───────────────────────────────
router.post("/prompt-factory/generate", async (req, res) => {
  const {
    request,
    type = "general",
    model = "gpt4",
    language = "ar",
  } = req.body as {
    request: string;
    type?: string;
    model?: string;
    language?: string;
  };

  if (!request) {
    res.status(400).json({ error: "request required" });
    return;
  }

  const typeDescriptions: Record<string, string> = {
    general:     "برومبت شامل لأي غرض",
    code:        "برومبت لكتابة الكود والبرمجة",
    image:       "برومبت لتوليد الصور",
    analysis:    "برومبت للتحليل والبحث",
    creative:    "برومبت للكتابة الإبداعية",
    business:    "برومبت للأعمال والتسويق",
    education:   "برومبت للتعليم والشرح",
    translation: "برومبت للترجمة والتحرير",
  };

  try {
    const result = await callPowerAI(
      `أنت خبير في هندسة البرومبت (Prompt Engineering). مهمتك تحويل الأفكار البسيطة إلى برومبتات احترافية فعّالة.

قواعد البرومبت الاحترافي:
1. ابدأ بتحديد دور الـ AI: "أنت [خبير/متخصص] في..."
2. حدد السياق والهدف بوضوح
3. اذكر القيود والمتطلبات
4. حدد تنسيق الإجابة المطلوب
5. أضف أمثلة إن لزم
6. استخدم لغة ${language === "ar" ? "عربية" : "إنجليزية"} فصيحة واضحة

نوع البرومبت المطلوب: ${typeDescriptions[type] || type}
النموذج المستهدف: ${model}`,
      `حوّل هذا الطلب إلى برومبت احترافي متكامل:\n\n"${request}"\n\nأعد البرومبت النهائي فقط، جاهزاً للاستخدام المباشر.`,
      4096
    );

    res.json({
      result: result.content,
      model: result.modelUsed,
      type,
      originalRequest: request,
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

// ─── POST /api/prompt-factory/refine ─────────────────────────────────
router.post("/prompt-factory/refine", async (req, res) => {
  const {
    prompt,
    feedback,
    goal,
  } = req.body as {
    prompt: string;
    feedback: string;
    goal?: string;
  };

  if (!prompt || !feedback) {
    res.status(400).json({ error: "prompt and feedback required" });
    return;
  }

  try {
    const result = await callPowerAI(
      `أنت خبير في تحسين البرومبتات. مهمتك تطوير البرومبت الموجود بناءً على الملاحظات المقدمة.`,
      `البرومبت الحالي:\n${prompt}\n\nالملاحظات والتحسينات المطلوبة:\n${feedback}${goal ? `\n\nالهدف النهائي: ${goal}` : ""}\n\nأعد البرومبت المحسّن فقط.`,
      4096
    );

    res.json({
      refined: result.content,
      original: prompt,
      model: result.modelUsed,
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

// ─── POST /api/prompt-factory/test ───────────────────────────────────
router.post("/prompt-factory/test", async (req, res) => {
  const {
    prompt,
    testInput,
    provider = "auto",
  } = req.body as {
    prompt: string;
    testInput: string;
    provider?: string;
  };

  if (!prompt || !testInput) {
    res.status(400).json({ error: "prompt and testInput required" });
    return;
  }

  try {
    const startTime = Date.now();
    const result = await callPowerAI(prompt, testInput, 4096);
    const duration = Date.now() - startTime;

    res.json({
      output: result.content,
      modelUsed: result.modelUsed,
      duration,
      promptLength: prompt.length,
      inputLength: testInput.length,
      outputLength: result.content.length,
    });
  } catch (e: any) {
    res.status(500).json({ error: e.message });
  }
});

export default router;
