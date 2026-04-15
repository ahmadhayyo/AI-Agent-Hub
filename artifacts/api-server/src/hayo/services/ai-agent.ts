import fs from "fs";
import path from "path";
import { spawn } from "child_process";
import { createHash } from "crypto";
import { createAnthropicClient } from "../llm";

const PROJECT_ROOT = path.resolve(process.cwd(), "../..");
const HAYO_FRONTEND = path.join(PROJECT_ROOT, "artifacts/hayo-ai/src");
const HAYO_BACKEND = path.join(PROJECT_ROOT, "artifacts/api-server/src/hayo");

const IGNORED_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", ".cache",
  ".local", ".config", "coverage", "__pycache__", ".turbo",
]);
const ALLOWED_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".css", ".json", ".html", ".md",
]);

export interface FileOp {
  action: "create" | "edit" | "delete" | "read";
  filePath: string;
  content?: string;
  description: string;
}

export interface AgentResponse {
  message: string;
  operations: FileOp[];
  executedOps: { action: string; filePath: string; success: boolean; error?: string }[];
  steps?: AgentStep[];
  retry?: {
    attempted: boolean;
    recovered: number;
    remainingFailed: number;
  };
  toolbelt?: {
    checks: Array<{ name: string; ok: boolean; detail: string }>;
    passed: number;
    failed: number;
  };
  memory?: {
    sessionId: string;
    summary: string;
  };
}

interface AgentAttachment {
  name: string;
  type?: string;
  size?: number;
  extractedText?: string;
}

type AgentPhase = "plan" | "execute" | "verify";

interface AgentStep {
  phase: AgentPhase;
  status: "done" | "failed";
  detail: string;
  progress: number;
  at: string;
}

interface AgentMemoryEntry {
  at: string;
  command: string;
  summary: string;
  ops: number;
  success: number;
  failed: number;
}

interface AgentMemoryStore {
  sessions: Record<string, AgentMemoryEntry[]>;
}

const MEMORY_FILE = path.join(PROJECT_ROOT, ".hayo-agent-memory.json");

function readMemoryStore(): AgentMemoryStore {
  try {
    if (!fs.existsSync(MEMORY_FILE)) return { sessions: {} };
    const raw = fs.readFileSync(MEMORY_FILE, "utf-8");
    const parsed = JSON.parse(raw) as AgentMemoryStore;
    if (!parsed || typeof parsed !== "object" || !parsed.sessions) return { sessions: {} };
    return parsed;
  } catch {
    return { sessions: {} };
  }
}

function writeMemoryStore(store: AgentMemoryStore): void {
  try {
    fs.writeFileSync(MEMORY_FILE, JSON.stringify(store, null, 2), "utf-8");
  } catch {
    // best-effort memory persistence
  }
}

function appendMemoryEntry(store: AgentMemoryStore, sessionId: string, entry: AgentMemoryEntry): void {
  const existing = store.sessions[sessionId] || [];
  const next = [...existing, entry].slice(-25);
  store.sessions[sessionId] = next;
  writeMemoryStore(store);
}

function runCommandQuick(
  cmd: string,
  args: string[],
  timeoutMs: number,
): Promise<{ ok: boolean; detail: string }> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      cwd: PROJECT_ROOT,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let done = false;
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      child.kill("SIGKILL");
      resolve({ ok: false, detail: `timeout ${timeoutMs}ms` });
    }, timeoutMs);

    child.stdout?.on("data", (buf: Buffer) => { stdout += buf.toString("utf-8"); });
    child.stderr?.on("data", (buf: Buffer) => { stderr += buf.toString("utf-8"); });
    child.on("error", (err: Error) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ ok: false, detail: err.message });
    });
    child.on("close", (code) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      const output = `${stdout}\n${stderr}`.trim().slice(0, 400);
      resolve({
        ok: code === 0,
        detail: output || `exit ${code ?? 1}`,
      });
    });
  });
}

async function runToolbeltChecks(): Promise<Array<{ name: string; ok: boolean; detail: string }>> {
  const checks: Array<{ name: string; ok: boolean; detail: string }> = [];

  const git = await runCommandQuick("git", ["status", "--porcelain"], 8_000);
  checks.push({
    name: "git-status",
    ok: git.ok,
    detail: git.detail || (git.ok ? "repo ready" : "git status failed"),
  });

  const frontend = await runCommandQuick("pnpm", ["--filter", "@workspace/hayo-ai", "typecheck"], 25_000);
  checks.push({
    name: "frontend-typecheck",
    ok: frontend.ok,
    detail: frontend.detail,
  });

  const backend = await runCommandQuick("pnpm", ["--filter", "@workspace/api-server", "typecheck"], 25_000);
  checks.push({
    name: "backend-typecheck",
    ok: backend.ok,
    detail: backend.detail,
  });

  return checks;
}

function getProjectTree(dir: string, prefix = "", depth = 0, maxDepth = 4): string {
  if (depth > maxDepth || !fs.existsSync(dir)) return "";
  let result = "";
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true })
      .filter(e => !IGNORED_DIRS.has(e.name) && !e.name.startsWith("."))
      .sort((a, b) => {
        if (a.isDirectory() && !b.isDirectory()) return -1;
        if (!a.isDirectory() && b.isDirectory()) return 1;
        return a.name.localeCompare(b.name);
      });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        result += `${prefix}📁 ${entry.name}/\n`;
        result += getProjectTree(fullPath, prefix + "  ", depth + 1, maxDepth);
      } else if (ALLOWED_EXTENSIONS.has(path.extname(entry.name))) {
        const size = fs.statSync(fullPath).size;
        result += `${prefix}📄 ${entry.name} (${(size / 1024).toFixed(1)}KB)\n`;
      }
    }
  } catch {}
  return result;
}

function readFilesSafe(filePaths: string[]): string {
  let result = "";
  for (const fp of filePaths) {
    const abs = resolvePath(fp);
    if (!abs) { result += `\n--- ${fp} (خارج المشروع) ---\n`; continue; }
    if (!fs.existsSync(abs)) { result += `\n--- ${fp} (غير موجود) ---\n`; continue; }
    try {
      const stat = fs.statSync(abs);
      if (stat.isDirectory()) {
        const entries = fs.readdirSync(abs, { withFileTypes: true });
        const listing = entries
          .filter(e => !e.name.startsWith(".") && e.name !== "node_modules")
          .map(e => `${e.isDirectory() ? "📁" : "📄"} ${e.name}`)
          .join("\n");
        result += `\n--- ${fp} (مجلد) ---\n${listing}\n`;
        continue;
      }
      const content = fs.readFileSync(abs, "utf-8");
      const lines = content.split("\n").length;
      if (lines > 500) {
        result += `\n--- ${fp} (${lines} سطر — أول 300 سطر) ---\n${content.split("\n").slice(0, 300).join("\n")}\n...\n`;
      } else {
        result += `\n--- ${fp} ---\n${content}\n`;
      }
    } catch (e: any) {
      result += `\n--- ${fp} (خطأ: ${e.message}) ---\n`;
    }
  }
  return result;
}

function resolvePath(fp: string): string | null {
  if (fp.startsWith("/")) return null;
  let joined: string;
  if (fp.startsWith("artifacts/") || fp.startsWith("packages/")) {
    joined = path.join(PROJECT_ROOT, fp);
  } else if (fp.startsWith("src/")) {
    joined = path.join(HAYO_FRONTEND, fp.replace(/^src\//, ""));
  } else {
    joined = path.join(PROJECT_ROOT, fp);
  }
  const resolved = path.resolve(joined);
  const rel = path.relative(PROJECT_ROOT, resolved);
  if (rel.startsWith("..") || path.isAbsolute(rel)) return null;
  return resolved;
}

function executeOps(ops: FileOp[]): AgentResponse["executedOps"] {
  const results: AgentResponse["executedOps"] = [];
  for (const op of ops) {
    const abs = resolvePath(op.filePath);
    if (!abs) {
      results.push({ action: op.action, filePath: op.filePath, success: false, error: "مسار خارج المشروع" });
      continue;
    }
    try {
      switch (op.action) {
        case "create":
        case "edit": {
          const dir = path.dirname(abs);
          if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
          fs.writeFileSync(abs, op.content || "", "utf-8");
          results.push({ action: op.action, filePath: op.filePath, success: true });
          break;
        }
        case "delete": {
          if (fs.existsSync(abs)) {
            fs.unlinkSync(abs);
            results.push({ action: op.action, filePath: op.filePath, success: true });
          } else {
            results.push({ action: op.action, filePath: op.filePath, success: false, error: "الملف غير موجود" });
          }
          break;
        }
        case "read": {
          results.push({ action: op.action, filePath: op.filePath, success: true });
          break;
        }
      }
    } catch (e: any) {
      results.push({ action: op.action, filePath: op.filePath, success: false, error: e.message });
    }
  }
  return results;
}

function getRelevantContext(command: string): string {
  const contexts: string[] = [];

  if (/صفح|page|route/i.test(command)) {
    const appTsx = path.join(HAYO_FRONTEND, "App.tsx");
    if (fs.existsSync(appTsx)) contexts.push(readFilesSafe(["artifacts/hayo-ai/src/App.tsx"]));
    const pagesDir = path.join(HAYO_FRONTEND, "pages");
    if (fs.existsSync(pagesDir)) {
      const pages = fs.readdirSync(pagesDir).filter(f => f.endsWith(".tsx")).map(f => `📄 ${f}`);
      contexts.push(`\n--- الصفحات الموجودة ---\n${pages.join("\n")}`);
    }
  }

  if (/router|trpc|api|endpoint/i.test(command)) {
    contexts.push(readFilesSafe(["artifacts/api-server/src/hayo/router.ts"]));
  }

  if (/component|مكون|ui/i.test(command)) {
    const compDir = path.join(HAYO_FRONTEND, "components");
    if (fs.existsSync(compDir)) {
      const comps = fs.readdirSync(compDir, { recursive: true })
        .filter((f: any) => String(f).endsWith(".tsx"))
        .map((f: any) => `📄 ${f}`);
      contexts.push(`\n--- المكونات الموجودة ---\n${comps.join("\n")}`);
    }
  }

  if (/nav|sidebar|قائمة|dashboard/i.test(command)) {
    contexts.push(readFilesSafe([
      "artifacts/hayo-ai/src/components/DashboardLayout.tsx",
      "artifacts/hayo-ai/src/pages/Dashboard.tsx",
    ]));
  }

  return contexts.join("\n");
}

export async function executeAgentCommand(
  command: string,
  conversationHistory: { role: "user" | "assistant"; content: string }[],
  sessionId = "",
  attachments: AgentAttachment[] = [],
  autoExecute: boolean = false,
): Promise<AgentResponse> {
  const anthropic = createAnthropicClient();
  const normalizedSessionId = sessionId.trim() || `sess-${createHash("sha1").update(command).digest("hex").slice(0, 12)}`;
  const memoryStore = readMemoryStore();
  const memoryTrail = (memoryStore.sessions[normalizedSessionId] || []).slice(-6);
  const memoryContext = memoryTrail.length > 0
    ? memoryTrail.map((entry, idx) => (
      `${idx + 1}) ${entry.at} | ${entry.summary} | ops=${entry.ops} success=${entry.success} failed=${entry.failed}`
    )).join("\n")
    : "لا توجد ذاكرة سابقة لهذه الجلسة";

  const frontendTree = getProjectTree(HAYO_FRONTEND, "", 0, 3);
  const backendTree = getProjectTree(HAYO_BACKEND, "", 0, 3);
  const relevantContext = getRelevantContext(command);

  const attachmentsContext = attachments.length > 0
    ? attachments.map((att, idx) => {
      const header = `[#${idx + 1}] ${att.name} (${att.type || "unknown"}, ${att.size || 0} bytes)`;
      const body = (att.extractedText || "").slice(0, 15_000);
      return body ? `${header}\n${body}` : `${header}\n(لا يوجد نص مستخرج)`;
    }).join("\n\n---\n\n")
    : "";

  const systemPrompt = `أنت AI Agent تنفيذي داخل منصة HAYO AI. مهمتك تنفيذ أوامر المطور داخل المشروع مباشرة.

## بنية المشروع:
- Frontend: React + Vite + TypeScript (artifacts/hayo-ai/src/)
- Backend: Express + tRPC (artifacts/api-server/src/hayo/)
- التصميم: Tailwind CSS + shadcn/ui
- الـ Routing: wouter
- الحالة: tRPC + React Query
- اللغة الأساسية: العربية (RTL)

## شجرة Frontend:
${frontendTree}

## شجرة Backend:
${backendTree}

${relevantContext ? `## سياق إضافي:\n${relevantContext}` : ""}

## قواعد التنفيذ:
1. أنت تنفذ الأوامر مباشرة — لا تسأل أسئلة إلا إذا الأمر غامض جداً
2. عند إنشاء صفحة: أنشئ ملف .tsx + أضفها للـ router في App.tsx + أضفها للقائمة الجانبية
3. عند تعديل ملف: اقرأه أولاً ثم عدّل فقط ما يلزم
4. التزم بنمط الكود الموجود في المشروع
5. كل الواجهات بالعربية مع دعم RTL
6. استخدم Tailwind CSS + shadcn/ui components
7. استخدم lucide-react للأيقونات

## الملفات/الصور المرفوعة من المستخدم:
${attachmentsContext || "لا توجد مرفقات"}

## ذاكرة الجلسة (Session Memory):
${memoryContext}

## صيغة الرد:
أجب بـ JSON فقط بهذا الشكل:
{
  "message": "شرح مختصر لما سيتم تنفيذه",
  "operations": [
    {
      "action": "create" | "edit" | "delete" | "read",
      "filePath": "المسار النسبي من جذر المشروع",
      "content": "المحتوى الكامل للملف (فقط لـ create و edit)",
      "description": "وصف العملية"
    }
  ]
}

ملاحظات مهمة:
- لـ "edit": ضع المحتوى الكامل الجديد للملف بعد التعديل (وليس فقط التغيير)
- لـ "read": لا تحتاج content — سأقرأ الملف وأعرضه
- المسارات تبدأ من: artifacts/hayo-ai/src/ أو artifacts/api-server/src/hayo/
- أجب بـ JSON فقط — بدون markdown أو backticks أو شرح خارجي`;

  const messages = [
    ...conversationHistory.slice(-10),
    { role: "user" as const, content: command },
  ];

  const msg = await anthropic.messages.create({
    model: "claude-sonnet-4-20250514",
    max_tokens: 16384,
    system: systemPrompt,
    messages,
  });

  const rawText = (msg.content[0] as any).text || "";

  const executionSteps: AgentResponse["steps"] = [];
  const pushStep = (phase: AgentPhase, status: "done" | "failed", detail: string, progress: number) => {
    executionSteps.push({
      phase,
      status,
      detail,
      progress: Math.max(0, Math.min(100, progress)),
      at: new Date().toISOString(),
    });
  };

  pushStep("plan", "done", "بدء تخطيط المهمة التنفيذية", 8);
  let parsed: { message: string; operations: FileOp[] };
  try {
    const jsonMatch = rawText.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error("لم يتم العثور على JSON في الرد");
    parsed = JSON.parse(jsonMatch[0]);
    pushStep("plan", "done", `تم إعداد الخطة واستخراج ${parsed.operations?.length || 0} عمليات`, 28);
  } catch {
    return {
      message: rawText,
      operations: [],
      executedOps: [],
      steps: [{
        phase: "plan",
        status: "failed",
        detail: "فشل استخراج خطة عمليات صالحة من النموذج",
        progress: 0,
        at: new Date().toISOString(),
      }],
    };
  }

  const ops = (parsed.operations || []).map(op => ({
    ...op,
    filePath: op.filePath.replace(/^\/+/, ""),
  }));

  const readOps = ops.filter(op => op.action === "read");
  const writeOps = ops.filter(op => op.action !== "read");
  let extraContent = "";

  if (readOps.length > 0) {
    const readPaths = readOps.map(op => op.filePath);
    extraContent = readFilesSafe(readPaths);
    pushStep("execute", "done", `تمت قراءة ${readOps.length} ملفات/مسارات للسياق`, 45);
  }

  const readResults = readOps.map(op => ({ action: op.action, filePath: op.filePath, success: true }));
  let writeResults: AgentResponse["executedOps"] = [];
  let retryMeta: AgentResponse["retry"] = {
    attempted: false,
    recovered: 0,
    remainingFailed: 0,
  };

  if (autoExecute && writeOps.length > 0) {
    writeResults = executeOps(writeOps);
    const ok = writeResults.filter(r => r.success).length;
    const fail = writeResults.length - ok;
    pushStep("execute", fail > 0 ? "failed" : "done", `تنفيذ تلقائي: ${ok} نجح / ${fail} فشل`, 62);

    if (fail > 0) {
      const failedOps = writeOps.filter((_, idx) => !writeResults[idx]?.success);
      if (failedOps.length > 0) {
        retryMeta.attempted = true;
        const retryResults = executeOps(failedOps);
        const recovered = retryResults.filter((r) => r.success).length;
        retryMeta.recovered = recovered;
        retryMeta.remainingFailed = failedOps.length - recovered;
        pushStep(
          "execute",
          retryMeta.remainingFailed > 0 ? "failed" : "done",
          `Self-Heal Retry: ${recovered} استرجاع / ${retryMeta.remainingFailed} ما زال فاشلاً`,
          74,
        );
      }
    }
  } else if (!autoExecute && writeOps.length > 0) {
    pushStep("execute", "done", `وضع يدوي: ${writeOps.length} عمليات جاهزة للتطبيق`, 62);
  }

  const verifyTargets = writeResults
    .filter(r => r.success && (r.action === "create" || r.action === "edit"))
    .map(r => r.filePath);
  if (verifyTargets.length > 0) {
    const verificationSummary = verifyTargets.map((p) => {
      const abs = resolvePath(p);
      if (!abs || !fs.existsSync(abs)) return `✗ ${p} غير موجود بعد التنفيذ`;
      const stats = fs.statSync(abs);
      return stats.isFile()
        ? `✓ ${p} (${Math.max(1, Math.round(stats.size / 1024))}KB)`
        : `✗ ${p} ليس ملفاً`;
    }).join("\n");
    extraContent += `\n\n---\n\n## تقرير التحقق بعد التنفيذ\n${verificationSummary}`;
    pushStep("verify", "done", `اكتمل التحقق على ${verifyTargets.length} ملفات`, 88);
  } else {
    pushStep("verify", "done", "لا توجد تعديلات مطبقة تحتاج تحقق ملفات", 88);
  }

  const toolbeltChecks = await runToolbeltChecks();
  const passedChecks = toolbeltChecks.filter((c) => c.ok).length;
  const failedChecks = toolbeltChecks.length - passedChecks;
  pushStep(
    "verify",
    failedChecks > 0 ? "failed" : "done",
    `Toolbelt checks: ${passedChecks} ناجح / ${failedChecks} فشل`,
    100,
  );

  const successCount = [...readResults, ...writeResults].filter((r) => r.success).length;
  const failedCount = [...readResults, ...writeResults].filter((r) => !r.success).length;
  const memorySummary = `آخر تنفيذ: ${ops.length} عملية | نجاح ${successCount} | فشل ${failedCount}`;
  appendMemoryEntry(memoryStore, normalizedSessionId, {
    at: new Date().toISOString(),
    command: command.slice(0, 500),
    summary: memorySummary,
    ops: ops.length,
    success: successCount,
    failed: failedCount,
  });

  return {
    message: parsed.message + (extraContent ? "\n\n" + extraContent : ""),
    operations: ops,
    executedOps: [...readResults, ...writeResults],
    steps: executionSteps,
    retry: retryMeta,
    toolbelt: {
      checks: toolbeltChecks,
      passed: passedChecks,
      failed: failedChecks,
    },
    memory: {
      sessionId: normalizedSessionId,
      summary: memorySummary,
    },
  };
}
