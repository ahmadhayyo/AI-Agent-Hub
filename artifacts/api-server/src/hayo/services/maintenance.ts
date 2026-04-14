/**
 * System Maintenance Service
 * AI-powered diagnostics + repair for HAYO AI platform
 */
import { callPowerAI, callOfficeAI } from "../providers.js";
import { readFileSync, readdirSync, statSync, existsSync, writeFileSync } from "fs";
import { join, relative, extname } from "path";

// ─── Types ──────────────────────────────────────────────────────
export interface DiagnosticResult {
  category: string;
  status: "ok" | "warning" | "error";
  message: string;
  file?: string;
  line?: number;
  fix?: string;
}

export interface HealthReport {
  overall: "healthy" | "warnings" | "critical";
  score: number;
  diagnostics: DiagnosticResult[];
  timestamp: string;
  scannedFiles: number;
  scannedLines: number;
}

// ─── Scan project files ─────────────────────────────────────────
function getProjectFiles(baseDir: string, extensions: string[] = [".ts", ".tsx"]): string[] {
  const files: string[] = [];
  const MAX_FILES = 200;

  function walk(dir: string) {
    if (files.length >= MAX_FILES) return;
    try {
      const entries = readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (files.length >= MAX_FILES) return;
        const full = join(dir, entry.name);
        if (entry.isDirectory()) {
          if (["node_modules", ".git", "dist", "build", ".next", ".cache", "coverage"].includes(entry.name)) continue;
          walk(full);
        } else if (extensions.some(ext => entry.name.endsWith(ext))) {
          files.push(full);
        }
      }
    } catch {}
  }
  walk(baseDir);
  return files;
}

// ─── Quick structural scan (no AI) ──────────────────────────────
export function quickScan(projectRoot: string): HealthReport {
  const diagnostics: DiagnosticResult[] = [];
  let totalLines = 0;

  // Check environment variables
  const requiredEnvs = ["DATABASE_URL", "JWT_SECRET"];
  for (const env of requiredEnvs) {
    if (!process.env[env]) {
      diagnostics.push({ category: "env", status: "error", message: `متغير البيئة ${env} غير مضبوط` });
    } else {
      diagnostics.push({ category: "env", status: "ok", message: `${env} مضبوط ✓` });
    }
  }

  // AI Provider check — at least one must be available
  const hasAI = !!(process.env.OPENAI_API_KEY || process.env.OPENAI_API_KEY_ || process.env.DEEPSEEK_API_KEY || process.env.ANTHROPIC_API_KEY || process.env.GEMINI_API_KEY);
  diagnostics.push({ category: "env", status: hasAI ? "ok" : "error", message: hasAI ? "مزود AI متاح ✓" : "لا يوجد مزود AI — OPENAI_API_KEY أو DEEPSEEK_API_KEY مطلوب" });

  // Optional envs
  const optionalEnvs = ["ANTHROPIC_API_KEY", "STRIPE_SECRET_KEY", "TWELVE_DATA_API_KEY", "TELEGRAM_BOT_TOKEN", "OPENAI_API_KEY", "GEMINI_API_KEY", "DEEPSEEK_API_KEY"];
  for (const env of optionalEnvs) {
    diagnostics.push({
      category: "env",
      status: process.env[env] ? "ok" : "warning",
      message: process.env[env] ? `${env} مضبوط ✓` : `${env} غير مضبوط (اختياري)`,
    });
  }

  // Scan source files for common issues
  const srcFiles = getProjectFiles(join(projectRoot, "src"));
  for (const file of srcFiles) {
    try {
      const content = readFileSync(file, "utf-8");
      const lines = content.split("\n");
      totalLines += lines.length;
      const relPath = relative(projectRoot, file);

      // Check for console.log in production
      lines.forEach((line, i) => {
        if (line.includes("console.log(") && !line.trim().startsWith("//")) {
          diagnostics.push({ category: "code", status: "warning", message: `console.log في الكود`, file: relPath, line: i + 1 });
        }
      });

      // Check for TODO/FIXME
      lines.forEach((line, i) => {
        if (/(TODO|FIXME|HACK|XXX)/.test(line)) {
          diagnostics.push({ category: "code", status: "warning", message: `${line.match(/(TODO|FIXME|HACK|XXX)/)?.[0]} — ` + line.trim().substring(0, 80), file: relPath, line: i + 1 });
        }
      });

      // Check for hardcoded secrets (basic check)
      lines.forEach((line, i) => {
        if (/(?:password|secret|apikey|api_key)\s*[:=]\s*["'][^"']{8,}/i.test(line) && !line.includes("process.env") && !line.includes("hint")) {
          diagnostics.push({ category: "security", status: "error", message: `احتمال وجود مفتاح/كلمة مرور مكتوبة في الكود`, file: relPath, line: i + 1 });
        }
      });

      // TypeScript: check for 'any' overuse
      const anyCount = (content.match(/: any/g) || []).length;
      if (anyCount > 20) {
        diagnostics.push({ category: "quality", status: "warning", message: `${anyCount} استخدام لـ 'any' — قد يخفي أخطاء`, file: relPath });
      }

    } catch {}
  }

  // Calculate score
  const errors = diagnostics.filter(d => d.status === "error").length;
  const warnings = diagnostics.filter(d => d.status === "warning").length;
  const score = Math.max(0, 100 - errors * 10 - warnings * 2);

  return {
    overall: errors > 3 ? "critical" : errors > 0 || warnings > 10 ? "warnings" : "healthy",
    score,
    diagnostics,
    timestamp: new Date().toISOString(),
    scannedFiles: srcFiles.length,
    scannedLines: totalLines,
  };
}

// ─── AI Deep Diagnosis ──────────────────────────────────────────
export async function aiDiagnose(
  targetFiles: string[],
  projectRoot: string,
  userNote: string = "",
): Promise<{ report: string; fixes: Array<{ file: string; description: string; code: string }> }> {

  const fileContents = targetFiles.slice(0, 10).map(f => {
    const fullPath = join(projectRoot, f);
    if (!existsSync(fullPath)) return `// FILE NOT FOUND: ${f}`;
    const content = readFileSync(fullPath, "utf-8");
    return `// ═══ ${f} (${content.split("\n").length} سطر) ═══\n${content.substring(0, 5000)}`;
  }).join("\n\n");

  const notesSection = userNote.trim() ? `\n\nملاحظات المسؤول:\n${userNote}` : "";

  const result = await callPowerAI(
    `أنت مهندس صيانة برمجيات خبير. مهمتك فحص الكود وتحديد الأخطاء ونقاط الضعف واقتراح إصلاحات دقيقة.

افحص:
1. أخطاء منطقية (logic errors)
2. أخطاء TypeScript / type mismatches
3. ثغرات أمنية (SQL injection, XSS, auth bypass)
4. مشاكل أداء (memory leaks, N+1 queries)
5. دوال غير مستخدمة أو ميتة
6. imports مفقودة أو زائدة
7. معالجة أخطاء (error handling) ناقصة

أعد JSON:
{
  "report": "تقرير شامل بالعربية",
  "fixes": [
    {"file": "path/to/file.ts", "description": "وصف الإصلاح", "code": "الكود المصلح (snippet)"}
  ]
}`,
    `افحص هذه الملفات:${notesSection}\n\n${fileContents}`,
    16000
  );

  try {
    const cleaned = result.content.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
    const m = cleaned.match(/\{[\s\S]*\}/);
    if (m) {
      const parsed = JSON.parse(m[0]);
      return { report: parsed.report || "تم الفحص", fixes: parsed.fixes || [] };
    }
  } catch {}

  return { report: result.content, fixes: [] };
}

// ─── AI Fix Specific Problem — WITH WRITE ACCESS ────────────────
export async function aiFix(
  filePath: string,
  projectRoot: string,
  problem: string,
  autoApply: boolean = false,
): Promise<{ fixedCode: string; explanation: string; applied: boolean; backupPath?: string }> {

  const fullPath = join(projectRoot, filePath);
  if (!existsSync(fullPath)) throw new Error(`الملف غير موجود: ${filePath}`);

  const content = readFileSync(fullPath, "utf-8");

  // AI #1 (Opus): Fix
  const fix = await callPowerAI(
    `أنت مهندس برمجيات خبير بصلاحيات كاملة لإصلاح أي ملف في المشروع.
مهمتك: إصلاح المشكلة المحددة وإعادة الكود المصلح الكامل.

قواعد:
1. أعد الملف كاملاً — لا تحذف أي دالة أو import
2. أصلح المشكلة فقط ولا تغيّر منطق العمل
3. تأكد أن الكود يعمل بدون أخطاء TypeScript
4. أضف تعليق // FIXED: في المكان المصلح

أعد JSON:
{"fixedCode": "الكود المصلح الكامل — كل الأسطر", "explanation": "شرح مفصل بالعربية لكل تغيير"}`,
    `الملف: ${filePath} (${content.split("\n").length} سطر)\nالمشكلة: ${problem}\n\nالكود الكامل:\n${content}`,
    16000
  );

  let fixedCode = content;
  let explanation = "فشل التحليل";

  try {
    const cleaned = fix.content.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
    const m = cleaned.match(/\{[\s\S]*\}/);
    if (m) {
      const parsed = JSON.parse(m[0]);
      if (parsed.fixedCode && parsed.fixedCode.length > 50) {
        fixedCode = parsed.fixedCode;
        explanation = parsed.explanation || "تم الإصلاح";
      }
    }
  } catch {}

  // AI #2 (Sonnet): Validate fix
  try {
    const validate = await callOfficeAI(
      `تأكد أن الكود صحيح ولا يحتوي أخطاء. أصلح أي خطأ متبقٍ. أعد الكود المصلح فقط.`,
      fixedCode.substring(0, 25000),
      16000,
      "claude-sonnet-4-6"
    );
    if (validate.length > 100) fixedCode = validate;
  } catch {}

  // Auto-apply: write directly to file with backup
  let applied = false;
  let backupPath: string | undefined;

  if (autoApply && fixedCode !== content) {
    try {
      // Create backup
      const backupDir = join(projectRoot, ".hayo-backups");
      if (!existsSync(backupDir)) {
        const { mkdirSync } = await import("fs");
        mkdirSync(backupDir, { recursive: true });
      }
      const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
      const backupName = filePath.replace(/[\/\\]/g, "_") + `.${timestamp}.bak`;
      backupPath = join(backupDir, backupName);
      writeFileSync(backupPath, content, "utf-8");

      // Write fixed code
      writeFileSync(fullPath, fixedCode, "utf-8");
      applied = true;
    } catch (e: any) {
      explanation += `\n⚠️ فشل الكتابة التلقائية: ${e.message}`;
    }
  }

  return { fixedCode, explanation, applied, backupPath: backupPath ? relative(projectRoot, backupPath) : undefined };
}

// ─── Read any file content ──────────────────────────────────────
export function readFile(filePath: string, projectRoot: string): { content: string; lines: number; size: number } {
  const fullPath = join(projectRoot, filePath);
  if (!existsSync(fullPath)) throw new Error(`الملف غير موجود: ${filePath}`);
  const content = readFileSync(fullPath, "utf-8");
  return { content, lines: content.split("\n").length, size: content.length };
}

// ─── Batch AI Fix — fix multiple files at once ──────────────────
export async function batchAiFix(
  fixes: Array<{ file: string; problem: string }>,
  projectRoot: string,
  autoApply: boolean = false,
): Promise<Array<{ file: string; success: boolean; explanation: string; applied: boolean }>> {
  const results = [];
  for (const fix of fixes.slice(0, 10)) {
    try {
      const result = await aiFix(fix.file, projectRoot, fix.problem, autoApply);
      results.push({ file: fix.file, success: true, explanation: result.explanation, applied: result.applied });
    } catch (e: any) {
      results.push({ file: fix.file, success: false, explanation: e.message, applied: false });
    }
  }
  return results;
}

// ─── Executive Auto-Execute: Scan → Diagnose → Fix All ──────────
/**
 * Full autonomous maintenance pipeline:
 * 1. Quick structural scan
 * 2. AI deep diagnosis of the most critical files
 * 3. Auto-apply all suggested fixes with backups
 * Returns a comprehensive execution report.
 */
export async function autoExecute(
  projectRoot: string,
  scope: "frontend" | "backend" | "services" | "all" = "all",
): Promise<{
  phase1: { score: number; errors: number; warnings: number };
  phase2: { filesAnalyzed: number; fixesFound: number; report: string };
  phase3: { applied: number; failed: number; results: Array<{ file: string; success: boolean; explanation: string }> };
  summary: string;
}> {
  // ── Phase 1: Quick Scan ──────────────────────────────────────────
  const scan = quickScan(projectRoot);
  const errorFiles = [...new Set(scan.diagnostics.filter(d => d.status === "error" && d.file).map(d => d.file!))];

  // ── Phase 2: AI Diagnosis ────────────────────────────────────────
  const structure = getProjectStructure(projectRoot);
  const scopeFilter: Record<string, string> = {
    all: "src/",
    frontend: "src/pages/",
    backend: "src/hayo/",
    services: "src/hayo/services/",
  };
  const prefix = scopeFilter[scope] || "src/";
  const targetFiles = [
    ...errorFiles,
    ...structure.files.filter(f => f.path.startsWith(prefix) && !errorFiles.includes(f.path)).slice(0, 6).map(f => f.path),
  ].slice(0, 10);

  const diagnosis = await aiDiagnose(targetFiles, projectRoot,
    `تشخيص تنفيذي شامل — اكتشف وأصلح جميع المشاكل تلقائياً في النطاق: ${scope}`
  );

  // ── Phase 3: Auto-Apply All Fixes ───────────────────────────────
  const fixableItems = diagnosis.fixes.filter(f => f.file && f.description);
  const phase3Results: Array<{ file: string; success: boolean; explanation: string }> = [];

  for (const fix of fixableItems.slice(0, 8)) {
    try {
      const result = await aiFix(fix.file, projectRoot, fix.description, true);
      phase3Results.push({ file: fix.file, success: true, explanation: result.explanation });
    } catch (e: any) {
      phase3Results.push({ file: fix.file, success: false, explanation: e.message?.slice(0, 200) || "خطأ غير معروف" });
    }
  }

  const appliedCount = phase3Results.filter(r => r.success).length;
  const failedCount  = phase3Results.filter(r => !r.success).length;

  const summary = [
    `✅ المرحلة 1 — الفحص: درجة ${scan.score}/100 | ${scan.diagnostics.filter(d => d.status === "error").length} خطأ, ${scan.diagnostics.filter(d => d.status === "warning").length} تحذير`,
    `🧠 المرحلة 2 — التشخيص: ${targetFiles.length} ملف فُحص | ${fixableItems.length} إصلاح محدد`,
    `🔧 المرحلة 3 — التنفيذ: ${appliedCount} تم تطبيقه | ${failedCount} فشل`,
    appliedCount > 0 ? `\n✅ تم إصلاح: ${phase3Results.filter(r => r.success).map(r => r.file).join(", ")}` : "",
    failedCount > 0  ? `\n❌ فشل: ${phase3Results.filter(r => !r.success).map(r => r.file).join(", ")}` : "",
  ].filter(Boolean).join("\n");

  return {
    phase1: { score: scan.score, errors: errorFiles.length, warnings: scan.diagnostics.filter(d => d.status === "warning").length },
    phase2: { filesAnalyzed: targetFiles.length, fixesFound: fixableItems.length, report: diagnosis.report },
    phase3: { applied: appliedCount, failed: failedCount, results: phase3Results },
    summary,
  };
}

// ─── Restore from backup ────────────────────────────────────────
export function restoreBackup(backupPath: string, originalPath: string, projectRoot: string): boolean {
  const fullBackup = join(projectRoot, backupPath);
  const fullOriginal = join(projectRoot, originalPath);
  if (!existsSync(fullBackup)) throw new Error(`النسخة الاحتياطية غير موجودة: ${backupPath}`);
  const backup = readFileSync(fullBackup, "utf-8");
  writeFileSync(fullOriginal, backup, "utf-8");
  return true;
}

// ─── Get project structure ──────────────────────────────────────
export function getProjectStructure(projectRoot: string): { files: Array<{ path: string; size: number; lines: number }>; totalFiles: number; totalLines: number } {
  const files = getProjectFiles(projectRoot, [".ts", ".tsx", ".js", ".jsx"]);
  const result = files.map(f => {
    const relPath = relative(projectRoot, f);
    try {
      const content = readFileSync(f, "utf-8");
      return { path: relPath, size: statSync(f).size, lines: content.split("\n").length };
    } catch {
      return { path: relPath, size: 0, lines: 0 };
    }
  });
  return {
    files: result.sort((a, b) => b.lines - a.lines),
    totalFiles: result.length,
    totalLines: result.reduce((s, f) => s + f.lines, 0),
  };
}
