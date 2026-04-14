/**
 * MQ4/MQ5 EA & Indicator Factory — DREAM ENGINE
 * Multi-pass AI: batch analysis → massive strategy generation → combined code
 */
import { callPowerAI, callOfficeAI } from "../providers.js";

export interface AnalyzedFile {
  name: string; type: string; platform: string;
  signals: string[]; indicators: string[]; logic: string;
  strengths: string[]; weaknesses: string[]; parameters: string[];
  codePatterns: string[]; compatibleWith: string[];
}

export interface StrategyProposal {
  id: string; name: string; description: string; category: string;
  filesUsed: string[]; indicators: string[]; filters: string[];
  entryLogic: string; exitLogic: string; riskManagement: string;
  timeframe: string; confidence: number; complexity: string;
}

function detectType(name: string, content: string) {
  const ext = name.split(".").pop()?.toLowerCase() || "";
  const platform = ["mq5","ex5"].includes(ext) ? "mq5" : "mq4";
  const lc = content.toLowerCase();
  if (lc.includes("#property indicator") || (lc.includes("oncalculate") && !lc.includes("ordersend"))) return { type: "indicator" as const, platform };
  if (lc.includes("ontick") && (lc.includes("ordersend") || lc.includes("ctrade"))) return { type: "ea" as const, platform };
  if (ext === "mqh") return { type: "include" as const, platform };
  return { type: "unknown" as const, platform };
}

// ═══ PASS 1+2: Batch analyze → massive strategy generation ═══
export async function analyzeFiles(
  files: Array<{ name: string; content: string }>,
  userNotes: string = ""
): Promise<{
  analyzedFiles: AnalyzedFile[];
  summary: string;
  proposedStrategies: StrategyProposal[];
  totalIndicators: string[];
  totalSignals: number;
}> {
  const mqFiles = files.map(f => ({ ...f, ...detectType(f.name, f.content) }));

  // ─── PASS 1: Batch analyze (15 files per batch) ──────────────
  const BATCH = 15;
  const allAnalyzed: AnalyzedFile[] = [];

  for (let i = 0; i < mqFiles.length; i += BATCH) {
    const batch = mqFiles.slice(i, i + BATCH);
    const previews = batch.map(f =>
      `=== ${f.name} [${f.type}/${f.platform}] ===\n${f.content.substring(0, 2000)}\n===END===`
    ).join("\n");

    const r = await callPowerAI(
      `أنت خبير MetaTrader. حلل كل ملف بعمق. أعد JSON:
{"files":[{"name":"","type":"","platform":"","signals":[""],"indicators":[""],"logic":"شرح 50+ كلمة","strengths":[""],"weaknesses":[""],"parameters":[""],"codePatterns":[""],"compatibleWith":[""]}]}`,
      `حلل بعمق (دفعة ${Math.floor(i/BATCH)+1}):\n${previews}`,
      8192
    );
    try {
      const c = r.content.replace(/```json\n?/g,"").replace(/```\n?/g,"").trim();
      const m = c.match(/\{[\s\S]*\}/);
      if (m) allAnalyzed.push(...(JSON.parse(m[0]).files || []));
    } catch {
      batch.forEach(f => allAnalyzed.push({ name:f.name, type:f.type, platform:f.platform, signals:[], indicators:[], logic:"قيد التحليل", strengths:[], weaknesses:[], parameters:[], codePatterns:[], compatibleWith:[] }));
    }
  }

  // ─── PASS 2: Cross-analyze → MANY strategies ─────────────────
  const allInd = [...new Set(allAnalyzed.flatMap(f => f.indicators))];
  const digest = allAnalyzed.map(f =>
    `${f.name}: [${f.indicators.join(",")}] signals=[${f.signals.slice(0,3).join(",")}] patterns=[${f.codePatterns.slice(0,2).join(",")}]`
  ).join("\n");

  const minStrats = Math.max(10, Math.min(30, Math.floor(mqFiles.length * 0.5)));
  const notesSection = userNotes.trim() ? `\n\nملاحظات المستخدم (مهمة جداً):\n${userNotes}` : "";

  const cross = await callPowerAI(
    `أنت كبير مهندسي استراتيجيات التداول. لديك تحليل ${mqFiles.length} ملف.
أنشئ ${minStrats}+ استراتيجية مبتكرة. الأنواع المطلوبة:
- Trend Following (3+)
- Mean Reversion (2+)
- Breakout (2+)
- Scalping (2+)
- Multi-Timeframe (2+)
- فلاتر ذكية (2+)
- خوارزميات هجينة (3+)
- مؤشرات مخصصة مدمجة (2+)

كل استراتيجية: filesUsed=[3+ ملفات], filters=[2+ فلتر], entryLogic=[50+ كلمة], complexity=[simple|medium|advanced]

أعد JSON:
{"summary":"ملخص 100+ كلمة","strategies":[{"id":"s1","name":"","description":"30+ كلمة","category":"trend|reversal|breakout|scalping|swing|mtf|filter|hybrid|custom_indicator","filesUsed":["f1","f2","f3"],"indicators":[""],"filters":["فلتر"],"entryLogic":"50+ كلمة","exitLogic":"","riskManagement":"","timeframe":"H1","confidence":85,"complexity":"advanced"}]}`,
    `تحليل ${mqFiles.length} ملف:\n${digest}\nمؤشرات: ${allInd.join(", ")}\nملفات: ${mqFiles.map(f=>f.name).join(", ")}\n\nأنشئ ${minStrats}+ استراتيجية.${notesSection}`,
    16000
  );

  let strategies: StrategyProposal[] = [];
  let summary = "";
  try {
    const c = cross.content.replace(/```json\n?/g,"").replace(/```\n?/g,"").trim();
    const m = c.match(/\{[\s\S]*\}/);
    if (m) {
      const p = JSON.parse(m[0]);
      summary = p.summary || "";
      strategies = (p.strategies || []).map((s: any, i: number) => ({
        ...s, id: s.id || `s${i+1}`, filters: s.filters || [], complexity: s.complexity || "medium", category: s.category || "hybrid",
      }));
    }
  } catch {}

  return { analyzedFiles: allAnalyzed, summary, proposedStrategies: strategies, totalIndicators: allInd, totalSignals: allAnalyzed.flatMap(f=>f.signals).length };
}

// ═══ PASS 3+4: Generate massive combined code ═══
export async function generateCode(
  strategies: StrategyProposal[],
  sourceFiles: Array<{ name: string; content: string }>,
  platform: "mq4" | "mq5",
  outputType: "ea" | "indicator",
  userNotes: string = "",
): Promise<{ code: string; analysis: string }> {
  const usedNames = [...new Set(strategies.flatMap(s => s.filesUsed))];
  const relevant = sourceFiles
    .filter(f => usedNames.some(u => f.name.toLowerCase().includes(u.toLowerCase().replace(/\.(mq4|mq5)$/,""))))
    .map(f => `// ─── ${f.name} ───\n${f.content.substring(0,3000)}`).join("\n\n");
  const allCode = relevant || sourceFiles.slice(0,20).map(f => `// ${f.name}\n${f.content.substring(0,1500)}`).join("\n\n");

  const isMQ5 = platform === "mq5";
  const lang = isMQ5 ? "MQL5" : "MQL4";
  const isEA = outputType === "ea";
  const allInd = [...new Set(strategies.flatMap(s => s.indicators))];
  const allFilt = [...new Set(strategies.flatMap(s => s.filters || []))];

  const stratDesc = strategies.map((s,i) =>
    `[${i+1}] ${s.name} (${s.category})\n  مؤشرات: ${s.indicators.join(",")}\n  فلاتر: ${(s.filters||[]).join(",")}\n  دخول: ${s.entryLogic}\n  خروج: ${s.exitLogic}\n  مخاطر: ${s.riskManagement}`
  ).join("\n\n");

  const typeRules = isEA
    ? (isMQ5 ? "#include <Trade/Trade.mqh>, CTrade, OnTick()" : "OrderSend(), OP_BUY/SELL, OnTick()")
    : (isMQ5 ? "OnCalculate(), SetIndexBuffer(), indicator_buffers" : "IndicatorBuffers(), SetIndexBuffer(), start()");

  const notesSection = userNotes.trim() ? `\n\nتعليمات المستخدم:\n${userNotes}` : "";

  const sys = `أنت أفضل مطور ${lang} في العالم. اكتب ${isEA ? "Expert Advisor" : "Indicator"} ضخم يدمج ${strategies.length} استراتيجية.

القواعد: ${typeRules}
الكود يجب أن يكون:
- 1000+ سطر كحد أدنى — اكتب كود ضخم ومفصل
- يدمج: ${allInd.join(", ")}
- فلاتر: ${allFilt.join(", ")}
- ${isEA ? "نظام تصويت: كل استراتيجية تصوّت BUY/SELL → تنفيذ عند اتفاق الأغلبية" : "composite buffer يجمع كل الإشارات"}
- ${isEA ? "إدارة مخاطر: Dynamic Lot, Adaptive SL/TP, Trailing, BreakEven, MaxDailyLoss, SpreadFilter" : "ألوان وأنماط مختلفة لكل buffer"}
- input parameters لكل شيء
- ${isEA ? "Dashboard على الشارت" : "Label يعرض القيم"}
- تعليقات عربية مفصلة
- functions منظمة لكل استراتيجية

أعد الكود فقط. يبدأ بـ //+------------------------------------------------------------------+`;

  const usr = `${strategies.length} استراتيجية للدمج:\n\n${stratDesc}\n\nالمنصة: ${lang} | النوع: ${isEA?"EA":"Indicator"}${notesSection}\n\nالأكواد المصدرية:\n${allCode}`;

  // AI #1: Write
  const gen = await callPowerAI(sys, usr, 16000);
  let code = gen.content.replace(/^```(?:mql[45]?)?\n?/i,"").replace(/\n?```\s*$/i,"").trim();
  if (!code.startsWith("//+")) { const idx = code.indexOf("//+--"); if (idx > 0) code = code.substring(idx); }

  // AI #2: Review
  try {
    const rev = await callOfficeAI(
      `مدقق ${lang}. أصلح أخطاء التجميع. تأكد: دوال معرّفة، أنواع صحيحة، ${isMQ5?"CTrade":"OrderSend"} صحيح. أعد الكود المصلح فقط.`,
      `أصلح:\n\n${code.substring(0,25000)}`, 16000, "claude-sonnet-4-6"
    );
    const fixed = rev.replace(/^```(?:mql[45]?)?\n?/i,"").replace(/\n?```\s*$/i,"").trim();
    if (fixed.length > 200 && fixed.includes("//+")) code = fixed;
  } catch {}

  return {
    code,
    analysis: `✅ ${isEA?"Expert Advisor":"Indicator"} بـ ${lang}\n📊 ${strategies.length} استراتيجية مدمجة\n📏 ${code.split("\n").length} سطر\n🔧 ${allInd.join(", ")}\n🛡️ ${allFilt.join(", ")}\n🤖 ${gen.modelUsed} + Sonnet`,
  };
}

// ═══ Custom generation with notes ═══
export async function generateCustomCode(
  prompt: string,
  sourceFiles: Array<{ name: string; content: string }>,
  platform: "mq4" | "mq5",
  outputType: "ea" | "indicator",
  userNotes: string = "",
): Promise<{ code: string; analysis: string }> {
  const s: StrategyProposal = {
    id:"custom", name:prompt.substring(0,50), description:prompt,
    category:"hybrid", filesUsed:sourceFiles.map(f=>f.name),
    indicators:[], filters:[], entryLogic:prompt, exitLogic:"",
    riskManagement:"Dynamic SL/TP + Trailing", timeframe:"H1",
    confidence:70, complexity:"advanced",
  };
  return generateCode([s], sourceFiles, platform, outputType, userNotes);
}

// ═══════════════════════════════════════════════════════════════════
// Fix compile errors — user pastes MetaEditor errors → AI fixes code
// ═══════════════════════════════════════════════════════════════════
export async function fixCompileErrors(
  code: string,
  errors: string,
  platform: "mq4" | "mq5",
  outputType: "ea" | "indicator",
  userNotes: string = "",
): Promise<{ code: string; fixes: string[]; analysis: string }> {
  const lang = platform === "mq5" ? "MQL5" : "MQL4";

  const notesSection = userNotes.trim() ? `\n\nملاحظات إضافية من المستخدم:\n${userNotes}` : "";

  // AI #1: Fix based on errors
  const fixResult = await callPowerAI(
    `أنت خبير ${lang} متخصص في إصلاح أخطاء التجميع (compile errors) في MetaEditor.

مهمتك:
1. اقرأ أخطاء التجميع بدقة
2. حدد السبب الجذري لكل خطأ
3. أصلح الكود بالكامل — لا تحذف وظائف، فقط أصلح الأخطاء
4. تأكد أن:
   - كل الدوال معرّفة ومستخدمة بشكل صحيح
   - الأنواع (int, double, string, bool, datetime, color) صحيحة
   - ${platform === "mq5" ? "CTrade و CPositionInfo مستخدمة بشكل صحيح" : "OrderSend() مع العدد الصحيح من المعلمات"}
   - لا يوجد variable shadowing أو redefinition
   - كل الـ arrays معرّفة بشكل صحيح
   - لا يوجد missing semicolons أو brackets
   - ${platform === "mq5" ? "OnCalculate يُرجع rates_total" : "return(0) في start()"}
5. أعد الكود المصلح بالكامل (كل الأسطر — لا تختصر)

أعد JSON:
{"fixedCode": "الكود المصلح الكامل", "fixes": ["وصف الإصلاح 1", "وصف الإصلاح 2"]}`,
    `أخطاء التجميع من MetaEditor:\n--- ERRORS ---\n${errors.substring(0, 5000)}\n--- END ERRORS ---\n\nالكود الأصلي:\n\`\`\`${lang.toLowerCase()}\n${code}\n\`\`\`${notesSection}\n\nأصلح كل الأخطاء وأعد الكود كاملاً.`,
    16000
  );

  let fixedCode = code;
  let fixes: string[] = [];

  try {
    const cleaned = fixResult.content.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
    const m = cleaned.match(/\{[\s\S]*\}/);
    if (m) {
      const parsed = JSON.parse(m[0]);
      if (parsed.fixedCode && parsed.fixedCode.length > 100) {
        fixedCode = parsed.fixedCode.replace(/^```(?:mql[45]?)?\n?/i, "").replace(/\n?```\s*$/i, "").trim();
      }
      fixes = parsed.fixes || [];
    }
  } catch {
    // Try extracting code directly
    const codeMatch = fixResult.content.match(/\/\/\+--[\s\S]*/);
    if (codeMatch && codeMatch[0].length > 200) {
      fixedCode = codeMatch[0].replace(/\n?```\s*$/i, "").trim();
      fixes = ["تم الإصلاح التلقائي"];
    }
  }

  // AI #2: Validate the fix
  try {
    const validateResult = await callOfficeAI(
      `مدقق ${lang}. تأكد أن الكود خالٍ من أخطاء التجميع. أصلح أي خطأ متبقٍ. أعد الكود المصلح فقط بدون شرح.`,
      `تأكد من صحة هذا الكود ${lang}:\n\n${fixedCode.substring(0, 30000)}`,
      16000,
      "claude-sonnet-4-6"
    );
    const validated = validateResult.replace(/^```(?:mql[45]?)?\n?/i, "").replace(/\n?```\s*$/i, "").trim();
    if (validated.length > 200 && validated.includes("//+")) {
      fixedCode = validated;
    }
  } catch {}

  return {
    code: fixedCode,
    fixes,
    analysis: `🔧 تم إصلاح ${fixes.length} خطأ\n📏 ${fixedCode.split("\n").length} سطر\n🤖 AI #1: ${fixResult.modelUsed} | AI #2: Sonnet`,
  };
}

