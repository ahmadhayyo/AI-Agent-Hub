/**
 * Smart Bug Fixer REST Routes — HAYO AI
 * Powered by Claude Opus 4.6 → Sonnet 4.6 → GPT-4o fallback chain
 */

import { Router, type Request, type Response } from "express";
import { spawn } from "child_process";
import { readdirSync, readFileSync, statSync } from "fs";
import path from "path";
import { z } from "zod";

const router = Router();

type IssueSeverity = "critical" | "warning" | "info";
type IssueCategory = "type" | "build" | "performance" | "security" | "style";

interface FixerIssue {
  id: string;
  file: string;
  line: number;
  severity: IssueSeverity;
  message: string;
  suggestion: string;
  category: IssueCategory;
}

const anthropicResponseSchema = z.object({
  error: z.object({ message: z.string().optional() }).optional(),
  content: z.array(z.object({ text: z.string().optional() }).passthrough()).optional(),
}).passthrough();

const openAiResponseSchema = z.object({
  error: z.object({ message: z.string().optional() }).optional(),
  choices: z.array(
    z.object({
      message: z.object({ content: z.string().optional() }).optional(),
    }).passthrough()
  ).optional(),
}).passthrough();

const aiIssueSchema = z.object({
  id: z.union([z.string(), z.number()]).optional(),
  file: z.string(),
  line: z.number().int().nonnegative(),
  severity: z.enum(["critical", "warning", "info"]),
  message: z.string(),
  suggestion: z.string(),
  category: z.enum(["type", "build", "performance", "security", "style"]),
}).passthrough();

const incomingIssueSchema = z.object({
  id: z.union([z.string(), z.number()]).optional(),
  file: z.string().default(""),
  line: z.number().int().nonnegative().optional().default(0),
  severity: z.enum(["critical", "warning", "info"]).optional().default("info"),
  message: z.string().optional().default(""),
  suggestion: z.string().optional().default(""),
  category: z.enum(["type", "build", "performance", "security", "style"]).optional().default("type"),
}).passthrough();

const scanResponseSchema = z.object({
  issues: z.array(aiIssueSchema).default([]),
}).passthrough();

const fixRequestSchema = z.object({
  issueId: z.string().optional(),
  file: z.string().min(1),
  line: z.number().int().nonnegative().optional().default(0),
  message: z.string().min(1),
  suggestion: z.string().optional(),
});

const fixAllRequestSchema = z.object({
  issues: z.array(incomingIssueSchema).default([]),
});

const diagnoseResponseSchema = z.object({
  healthScore: z.number().int().min(0).max(100).optional(),
  summary: z.string().optional(),
  buildStatus: z.enum(["pass", "fail", "warning"]).optional(),
  recommendations: z.array(z.string()).optional(),
  issues: z.array(z.unknown()).optional(),
}).passthrough();

type AiIssueInput = z.infer<typeof aiIssueSchema>;
type IncomingIssueInput = z.infer<typeof incomingIssueSchema>;
type DiagnoseResponse = z.infer<typeof diagnoseResponseSchema>;

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  return "Unknown error";
}

function getExecErrorOutput(error: unknown): string {
  if (typeof error === "object" && error !== null && "stdout" in error) {
    const stdout = (error as { stdout?: string | Buffer }).stdout;
    if (typeof stdout === "string") return stdout;
    if (Buffer.isBuffer(stdout)) return stdout.toString("utf8");
  }
  return getErrorMessage(error);
}

async function runCommand(command: string, args: string[], options: { cwd?: string; timeoutMs?: number } = {}): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let finished = false;
    const timeoutMs = options.timeoutMs ?? 60_000;
    const timer = setTimeout(() => {
      if (finished) return;
      child.kill("SIGKILL");
      reject(new Error(`Command timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    child.stdout?.on("data", (chunk: Buffer) => { stdout += chunk.toString(); });
    child.stderr?.on("data", (chunk: Buffer) => { stderr += chunk.toString(); });
    child.on("error", (error) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      resolve({ stdout, stderr, code: code ?? 1 });
    });
  });
}

function normalizeIssue(issue: AiIssueInput, idx: number): FixerIssue {
  return {
    id: String(issue.id ?? `issue-${idx}`),
    file: issue.file,
    line: issue.line,
    severity: issue.severity,
    message: issue.message,
    suggestion: issue.suggestion,
    category: issue.category,
  };
}

function normalizeIncomingIssue(issue: IncomingIssueInput, idx: number): FixerIssue {
  return {
    id: String(issue.id ?? `issue-${idx}`),
    file: issue.file,
    line: issue.line,
    severity: issue.severity,
    message: issue.message,
    suggestion: issue.suggestion,
    category: issue.category,
  };
}

// ── callClaudeOpus: Opus 4.6 → Sonnet 4.6 → GPT-4o ──────────────────────────
async function callClaudeOpus(
  system: string,
  user: string,
  maxTokens = 4096
): Promise<{ content: string; modelUsed: string }> {
  const anthropicKey = process.env.ANTHROPIC_API_KEY;
  const openaiKey    = process.env.OPENAI_API_KEY;

  // 1. Claude Opus 4.6 ─────────────────────────────────────────────────────────
  if (anthropicKey) {
    for (const model of ["claude-opus-4-5", "claude-sonnet-4-6"] as const) {
      try {
        const res = await fetch("https://api.anthropic.com/v1/messages", {
          method: "POST",
          headers: {
            "x-api-key": anthropicKey,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
          },
          body: JSON.stringify({
            model,
            max_tokens: Math.min(maxTokens, 8192),
            system,
            messages: [{ role: "user", content: user }],
          }),
          signal: AbortSignal.timeout(90_000),
        });
        const parsedResponse = anthropicResponseSchema.safeParse(await res.json());
        if (!parsedResponse.success) {
          console.warn(`[Fixer] ${model} invalid response payload`);
          continue;
        }
        const data = parsedResponse.data;
        if (res.ok && !data.error) {
          const text = data.content?.[0]?.text || "";
          if (text) {
            console.log(`[Fixer] model: ${model}`);
            return { content: text, modelUsed: model };
          }
        }
        console.warn(`[Fixer] ${model} failed:`, data.error?.message?.slice(0, 80));
      } catch (e: unknown) {
        console.warn(`[Fixer] ${model} error:`, getErrorMessage(e).slice(0, 60));
      }
    }
  }

  // 2. GPT-4o fallback ─────────────────────────────────────────────────────────
  if (openaiKey) {
    try {
      const res = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${openaiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "gpt-4o-2024-08-06",
          max_tokens: Math.min(maxTokens, 4096),
          messages: [
            { role: "system", content: system },
            { role: "user",   content: user   },
          ],
        }),
        signal: AbortSignal.timeout(90_000),
      });
      const parsedResponse = openAiResponseSchema.safeParse(await res.json());
      if (!parsedResponse.success) {
        console.warn("[Fixer] gpt-4o invalid response payload");
        throw new Error("Invalid GPT response payload");
      }
      const data = parsedResponse.data;
      if (res.ok && !data.error) {
        const text = data.choices?.[0]?.message?.content || "";
        if (text) {
          console.log("[Fixer] model: gpt-4o-2024-08-06");
          return { content: text, modelUsed: "gpt-4o-2024-08-06" };
        }
      }
      console.warn("[Fixer] gpt-4o failed:", data.error?.message?.slice(0, 80));
    } catch (e: unknown) {
      console.warn("[Fixer] gpt-4o error:", getErrorMessage(e).slice(0, 60));
    }
  }

  throw new Error("لا يوجد نموذج AI متاح — تحقق من ANTHROPIC_API_KEY أو OPENAI_API_KEY");
}

// ── Helpers ────────────────────────────────────────────────────────────────────
function err(res: Response, e: unknown, fallback = "فشل العملية") {
  const msg = e instanceof Error ? e.message : String(e);
  console.error("[Fixer]", msg);
  res.status(500).json({ success: false, error: msg || fallback });
}

const SKIP_DIRS  = new Set(["node_modules", "dist", "build", ".git", ".next", "coverage", "__pycache__"]);
const SCAN_EXTS  = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".json", ".css", ".html"]);

function scanDirectory(dir: string, collected: string[] = [], maxFiles = 80): string[] {
  try {
    const entries = readdirSync(dir);
    for (const entry of entries) {
      if (collected.length >= maxFiles) break;
      if (entry.startsWith(".") || SKIP_DIRS.has(entry)) continue;
      const full = path.join(dir, entry);
      try {
        const stat = statSync(full);
        if (stat.isDirectory()) {
          scanDirectory(full, collected, maxFiles);
        } else if (SCAN_EXTS.has(path.extname(entry).toLowerCase())) {
          collected.push(full);
        }
      } catch {}
    }
  } catch {}
  return collected;
}

function readFileSafe(p: string, maxBytes = 8000): string {
  try {
    const buf = readFileSync(p);
    return buf.slice(0, maxBytes).toString("utf8");
  } catch { return ""; }
}

// ── quickScan: 14 regex patterns for static analysis ─────────────────────────
interface QuickIssue {
  id: string; file: string; line: number;
  severity: "critical" | "warning" | "info";
  message: string; suggestion: string; category: IssueCategory;
}

const PATTERNS: Array<{
  regex: RegExp; severity: QuickIssue["severity"];
  message: string; suggestion: string; category: IssueCategory;
}> = [
  // 1. eval() — code injection
  { regex: /\beval\s*\(/g, severity: "critical",
    message: "استخدام eval() خطير ويفتح ثغرات حقن الكود",
    suggestion: "استبدل eval() بـ JSON.parse() أو دوال آمنة أخرى", category: "security" },
  // 2. innerHTML — XSS
  { regex: /\.innerHTML\s*=/g, severity: "critical",
    message: "innerHTML قد يسبب ثغرة XSS إذا كانت البيانات من مستخدم",
    suggestion: "استخدم textContent أو إطار عمل مثل React بدلاً من innerHTML", category: "security" },
  // 3. hardcoded passwords
  { regex: /password\s*=\s*["'][^"']{4,}["']/gi, severity: "critical",
    message: "كلمة مرور مُدمجة في الكود",
    suggestion: "انقل كلمات المرور إلى متغيرات البيئة (process.env)", category: "security" },
  // 4. hardcoded API keys/secrets
  { regex: /(?:api[_-]?key|secret|token)\s*=\s*["'][A-Za-z0-9_\-]{16,}["']/gi, severity: "critical",
    message: "مفتاح API أو سر مُدمج في الكود",
    suggestion: "استخدم process.env.YOUR_KEY بدلاً من الكتابة المباشرة", category: "security" },
  // 5. console.log in production
  { regex: /\bconsole\.log\s*\(/g, severity: "info",
    message: "console.log() مُستخدم — قد يُسرب معلومات في الإنتاج",
    suggestion: "استبدل بـ logger مُخصص أو احذف قبل النشر", category: "style" },
  // 6. empty catch blocks
  { regex: /catch\s*\([^)]*\)\s*\{\s*\}/g, severity: "warning",
    message: "كتلة catch فارغة — الأخطاء تُبتلع بصمت",
    suggestion: "أضف معالجة للخطأ أو على الأقل console.error()", category: "build" },
  // 7. var usage
  { regex: /\bvar\s+/g, severity: "info",
    message: "استخدام var القديم بدلاً من let/const",
    suggestion: "استبدل var بـ const (للثوابت) أو let (للمتغيرات)", category: "style" },
  // 8. loose equality ==
  { regex: /[^!=<>]={2}(?!=)/g, severity: "warning",
    message: "مقارنة ضعيفة == بدلاً من ===",
    suggestion: "استخدم === للمقارنة الصارمة وتجنب تحويلات النوع التلقائية", category: "build" },
  // 9. TODO / FIXME
  { regex: /\/\/\s*(TODO|FIXME|HACK|XXX)\b/gi, severity: "info",
    message: "تعليق TODO/FIXME متروك في الكود",
    suggestion: "حل المشكلة أو أنشئ Issue في نظام تتبع المهام", category: "style" },
  // 10. require() in ESM
  { regex: /\brequire\s*\(/g, severity: "warning",
    message: "استخدام require() في مشروع ESM/TypeScript",
    suggestion: "استبدل بـ import ... from '...' للتوافق مع ESM", category: "style" },
  // 11. debugger statement
  { regex: /\bdebugger\b/g, severity: "warning",
    message: "بيان debugger مُتروك في الكود",
    suggestion: "احذف debugger قبل النشر", category: "build" },
  // 12. hardcoded localhost URLs
  { regex: /["']https?:\/\/localhost[:/]/g, severity: "warning",
    message: "رابط localhost مُدمج في الكود",
    suggestion: "استخدم متغيرات البيئة (process.env.API_URL) بدلاً من localhost", category: "build" },
  // 13. TypeScript any type
  { regex: /:\s*any\b/g, severity: "info",
    message: "استخدام النوع any في TypeScript — يُضعف سلامة الأنواع",
    suggestion: "حدد النوع الفعلي أو استخدم unknown إذا كان غير معروف", category: "type" },
  // 14. setTimeout/setInterval with string
  { regex: /setTimeout\s*\(\s*["']/g, severity: "critical",
    message: "setTimeout مع سلسلة نصية — مكافئ لـ eval() وخطير",
    suggestion: "مرر دالة مباشرة: setTimeout(() => { ... }, delay)", category: "security" },
];

function quickScan(dir: string): QuickIssue[] {
  const files  = scanDirectory(dir, [], 80);
  const issues: QuickIssue[] = [];
  let   idxCounter = 0;

  for (const filePath of files) {
    const ext = path.extname(filePath).toLowerCase();
    // Only scan code files, skip json/css/html for most patterns
    const isCode = [".ts", ".tsx", ".js", ".jsx", ".mjs"].includes(ext);
    if (!isCode) continue;

    const src  = readFileSafe(filePath, 50_000);
    const lines = src.split("\n");
    const rel  = filePath.replace("/home/runner/workspace/artifacts/hayo-ai/src/", "");

    for (const pat of PATTERNS) {
      // Reset lastIndex for global regex
      pat.regex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = pat.regex.exec(src)) !== null) {
        // Find line number
        const lineNo = src.slice(0, match.index).split("\n").length;
        // Skip minified lines (> 500 chars)
        if ((lines[lineNo - 1] || "").length > 500) { pat.regex.lastIndex++; continue; }
        issues.push({
          id: `qs-${++idxCounter}`,
          file: rel,
          line: lineNo,
          severity: pat.severity,
          message: pat.message,
          suggestion: pat.suggestion,
          category: pat.category,
        });
        // Max 3 occurrences per pattern per file
        if (issues.filter(i => i.file === rel && i.message === pat.message).length >= 3) break;
      }
    }
  }
  return issues;
}

async function runTsc(): Promise<string> {
  try {
    const result = await runCommand(
      "pnpm",
      ["--filter", "@workspace/hayo-ai", "tsc", "--noEmit"],
      { cwd: "/home/runner/workspace", timeoutMs: 60_000 }
    );
    return `${result.stdout}${result.stderr}`.trim();
  } catch (e: unknown) {
    return getExecErrorOutput(e);
  }
}

function parseTscOutput(raw: string) {
  const lines = raw.split("\n").filter(Boolean);
  const errors: Array<{ file: string; line: number; message: string }> = [];
  for (const line of lines) {
    const m = line.match(/^(.+?)\((\d+),\d+\):\s*error TS\d+:\s*(.+)$/);
    if (m) {
      errors.push({ file: m[1].replace(/^.*?artifacts\/hayo-ai\//, ""), line: parseInt(m[2]), message: m[3] });
    }
  }
  return { errors, passed: errors.length === 0, raw };
}

// ── POST /api/fixer/scan ────────────────────────────────────────────────────────
router.post("/scan", async (_req: Request, res: Response) => {
  try {
    // 1. Run TypeScript check first for real errors
    const tscRaw = await runTsc();
    const { errors: tscErrors } = parseTscOutput(tscRaw);

    // 2. Collect sample source files for AI analysis
    const srcDir = "/home/runner/workspace/artifacts/hayo-ai/src";
    const files = scanDirectory(srcDir, [], 20);
    const snippets = files.slice(0, 8).map(f => {
      const rel = f.replace("/home/runner/workspace/artifacts/hayo-ai/src/", "");
      const code = readFileSafe(f, 3000);
      return `\n\n=== ${rel} ===\n${code}`;
    }).join("");

    // 3. Build prompt
    const tscSection = tscErrors.length
      ? `\n\nأخطاء TypeScript الحقيقية:\n${tscErrors.map(e => `- ${e.file}:${e.line} — ${e.message}`).join("\n")}`
      : "\n\nلا توجد أخطاء TypeScript.";

    const prompt = `أنت محلل كود متخصص. حلل الكود التالي وأرجع قائمة JSON من المشكلات.

أرجع JSON فقط بالشكل:
{
  "issues": [
    {
      "id": "uuid-string",
      "file": "المسار النسبي",
      "line": 1,
      "severity": "critical|warning|info",
      "message": "وصف المشكلة بالعربية",
      "suggestion": "اقتراح الإصلاح التفصيلي بالعربية",
      "category": "type|build|performance|security|style"
    }
  ]
}

القواعد:
- أخطاء TypeScript = critical
- مشكلات الأداء والأمان = warning
- تنسيق الكود = info
- الحد الأقصى 30 مشكلة
- لا تتجاوز الملفات الفعلية

${tscSection}

الكود للتحليل:${snippets}`;

    const { content } = await callClaudeOpus(
      "أنت مصلح كود ذكي. أرجع JSON صحيح فقط بلا تعليقات.",
      prompt,
      4096
    );

    // Parse AI response
    let issues: FixerIssue[] = [];
    try {
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsedJson = JSON.parse(jsonMatch[0]) as unknown;
        const parsed = scanResponseSchema.parse(parsedJson);
        issues = parsed.issues.map(normalizeIssue);
      }
    } catch {
      // Fallback: use only tsc errors
      issues = tscErrors.map((e, i) => ({
        id: `tsc-${i}`,
        file: e.file,
        line: e.line,
        severity: "critical",
        message: e.message,
        suggestion: `أصلح خطأ TypeScript في السطر ${e.line}: ${e.message}`,
        category: "type",
      }));
    }

    // 4. Run quickScan (regex static analysis) and merge
    const quickIssues = quickScan(srcDir);
    // Merge: prefer AI issues, append quickScan issues not already covered
    const aiKeys = new Set(issues.map(i => `${i.file}:${i.line}`));
    const newFromQuick = quickIssues.filter(q => !aiKeys.has(`${q.file}:${q.line}`));
    issues = [...issues, ...newFromQuick].slice(0, 50);

    const summary = {
      total: issues.length,
      critical: issues.filter(i => i.severity === "critical").length,
      warnings: issues.filter(i => i.severity === "warning").length,
      info: issues.filter(i => i.severity === "info").length,
      scannedFiles: files.length,
    };

    res.json({ success: true, issues, summary });
  } catch (e) { err(res, e); }
});

// ── POST /api/fixer/fix ────────────────────────────────────────────────────────
router.post("/fix", async (req: Request, res: Response) => {
  try {
    const parsedBody = fixRequestSchema.safeParse(req.body);
    if (!parsedBody.success) {
      res.status(400).json({ error: "بيانات ناقصة" });
      return;
    }
    const { file, line, message, suggestion, issueId } = parsedBody.data;
    if (!file || !message) { res.status(400).json({ error: "بيانات ناقصة" }); return; }

    const fullPath = `/home/runner/workspace/artifacts/hayo-ai/src/${file}`;
    const code = readFileSafe(fullPath, 6000);

    const { content } = await callClaudeOpus(
      "أنت مصلح كود خبير. اشرح كيفية إصلاح المشكلة بوضوح.",
      `الملف: ${file} (سطر ${line})
المشكلة: ${message}
الاقتراح: ${suggestion}

الكود الحالي:
\`\`\`typescript
${code.slice(0, 4000)}
\`\`\`

اشرح خطوات الإصلاح الدقيقة وأرجع الكود المُصلح إن أمكن.`,
      2048
    );

    res.json({ success: true, fixedId: issueId ?? null, explanation: content, file, line });
  } catch (e) { err(res, e); }
});

// ── POST /api/fixer/fix-all — batch fix grouped by file ───────────────────────
router.post("/fix-all", async (req: Request, res: Response) => {
  try {
    const parsedBody = fixAllRequestSchema.safeParse(req.body);
    if (!parsedBody.success) {
      res.status(400).json({ error: "بيانات ناقصة" });
      return;
    }
    const issues = parsedBody.data.issues.map(normalizeIncomingIssue);
    if (!issues?.length) { res.json({ success: true, fixed: 0, fixedIds: [] }); return; }

    // Group issues by file
    const byFile = new Map<string, FixerIssue[]>();
    for (const iss of issues.slice(0, 30)) {
      const list = byFile.get(iss.file) ?? [];
      list.push(iss);
      byFile.set(iss.file, list);
    }

    const allFixedIds: string[] = [];
    const fileSummaries: string[] = [];

    // Process each file group in parallel (max 5 files at once)
    const fileEntries = [...byFile.entries()].slice(0, 5);
    await Promise.all(fileEntries.map(async ([filePath, fileIssues]) => {
      const fullPath = `/home/runner/workspace/artifacts/hayo-ai/src/${filePath}`;
      const code     = readFileSafe(fullPath, 6000);
      const issueList = fileIssues.map((iss, i) =>
        `${i + 1}. [${iss.severity}] سطر ${iss.line}: ${iss.message}`
      ).join("\n");

      try {
        const { content, modelUsed } = await callClaudeOpus(
          "أنت مصلح كود متخصص. حلل المشكلات في الملف وقدّم حلاً واضحاً لكل مشكلة.",
          `الملف: ${filePath}\n\nالمشكلات (${fileIssues.length}):\n${issueList}\n\nالكود:\n\`\`\`\n${code.slice(0, 4000)}\n\`\`\`\n\nاشرح كيفية إصلاح كل مشكلة بوضوح.`,
          2048
        );
        fileSummaries.push(`📄 **${filePath}** (${fileIssues.length} مشكلة) — ${modelUsed}\n${content.slice(0, 300)}`);
        allFixedIds.push(...fileIssues.map(i => i.id));
      } catch (e: unknown) {
        console.warn(`[Fixer fix-all] ${filePath} failed:`, getErrorMessage(e));
      }
    }));

    res.json({
      success: true,
      fixed: allFixedIds.length,
      fixedIds: allFixedIds,
      filesProcessed: fileEntries.length,
      summary: fileSummaries.join("\n\n"),
    });
  } catch (e) { err(res, e); }
});

// ── POST /api/fixer/build-check ────────────────────────────────────────────────
router.post("/build-check", async (_req: Request, res: Response) => {
  try {
    const raw = await runTsc();
    const { errors, passed } = parseTscOutput(raw);

    let aiSummary = "";
    if (errors.length > 0) {
      try {
        const { content } = await callClaudeOpus(
          "أنت محلل أخطاء TypeScript. لخّص الأخطاء باختصار بالعربية.",
          `أخطاء البناء:\n${raw.slice(0, 4000)}`,
          512
        );
        aiSummary = content;
      } catch {}
    }

    const output = passed
      ? "✅ البناء ناجح — لا توجد أخطاء TypeScript\n\nالمشروع جاهز للنشر."
      : `❌ ${errors.length} خطأ في البناء\n\n${aiSummary ? `📋 الملخص:\n${aiSummary}\n\n` : ""}📄 الخرج الكامل:\n${raw.slice(0, 6000)}`;

    res.json({ success: true, passed, errorCount: errors.length, output });
  } catch (e) { err(res, e); }
});

// ── POST /api/fixer/diagnose ────────────────────────────────────────────────────
router.post("/diagnose", async (_req: Request, res: Response) => {
  try {
    // Run build check
    const raw = await runTsc();
    const { errors, passed } = parseTscOutput(raw);

    // Collect file stats
    const srcDir = "/home/runner/workspace/artifacts/hayo-ai/src";
    const files = scanDirectory(srcDir, [], 80);
    const pageFiles = files.filter(f => f.includes("/pages/")).length;
    const compFiles = files.filter(f => f.includes("/components/")).length;

    const { content } = await callClaudeOpus(
      "أنت محلل مشاريع خبير. قيّم المشروع وأرجع JSON فقط.",
      `حلل هذا المشروع وأرجع JSON بالشكل:
{
  "healthScore": 0-100,
  "summary": "ملخص صحة المشروع بالعربية",
  "buildStatus": "pass|fail|warning",
  "recommendations": ["توصية 1", "توصية 2", "توصية 3"],
  "issues": []
}

إحصاءات المشروع:
- إجمالي الملفات: ${files.length}
- صفحات: ${pageFiles}
- مكونات: ${compFiles}
- أخطاء TypeScript: ${errors.length}
- حالة البناء: ${passed ? "ناجح" : "فاشل"}
${errors.length > 0 ? "\nعينة من الأخطاء:\n" + errors.slice(0, 5).map(e => `- ${e.file}:${e.line}: ${e.message}`).join("\n") : ""}

قيّم المشروع بناءً على هذه المعطيات وأعطِ توصيات عملية.`,
      1500
    );

    let result: DiagnoseResponse = {};
    try {
      const m = content.match(/\{[\s\S]*\}/);
      if (m) {
        const parsed = diagnoseResponseSchema.safeParse(JSON.parse(m[0]) as unknown);
        if (parsed.success) {
          result = parsed.data;
        }
      }
    } catch {}

    res.json({
      success: true,
      healthScore: result.healthScore ?? (passed ? 85 : 60),
      summary: result.summary ?? (passed ? "المشروع بحالة جيدة" : `يوجد ${errors.length} خطأ في البناء`),
      buildStatus: result.buildStatus ?? (passed ? "pass" : "fail"),
      recommendations: result.recommendations ?? [],
      issues: result.issues ?? [],
    });
  } catch (e) { err(res, e); }
});

export default router;
