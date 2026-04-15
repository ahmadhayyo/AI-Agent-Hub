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
const ALLOWED_WORKSPACE_ROOTS = [
  "artifacts/hayo-ai/src",
  "artifacts/api-server/src/hayo",
  "shared",
] as const;
const BLOCKED_PATH_SEGMENTS = new Set([
  "node_modules",
  ".git",
  ".cursor",
  ".vscode",
  "dist",
  "build",
]);
const BLOCKED_FILE_PATTERNS = [
  /^\.env(\..+)?$/i,
  /^id_rsa(\..+)?$/i,
  /\.pem$/i,
  /\.key$/i,
  /\.crt$/i,
  /secret/i,
];
const READ_EXTRA_ALLOW_PATTERNS = [
  /^package\.json$/i,
  /^pnpm-lock\.yaml$/i,
  /^pnpm-workspace\.yaml$/i,
  /^tsconfig(\..+)?\.json$/i,
  /^README\.md$/i,
];

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
    profile: ToolbeltProfile[];
    pre: ToolbeltCheck[];
    post: ToolbeltCheck[];
    passed: number;
    failed: number;
  };
  plan?: AgentExecutionPlan;
  guardrails?: AgentGuardrailReport;
  memory?: {
    sessionId: string;
    summary: string;
    recalledSession?: number;
    recalledProject?: number;
    topics?: string[];
    pinnedCount?: number;
    recalledEntries?: Array<{
      source: "session" | "project" | "pinned";
      at: string;
      summary: string;
      commandHash?: string;
    }>;
  };
}

interface AgentAttachment {
  name: string;
  type?: string;
  size?: number;
  extractedText?: string;
}

type AgentPhase = "plan" | "execute" | "verify";
type ToolbeltProfile = "frontend" | "backend" | "quality";
type SubtaskStatus = "pending" | "done" | "failed" | "blocked";

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
  topics?: string[];
  touchedFiles?: string[];
  commandHash?: string;
}

interface AgentMemoryStore {
  sessions: Record<string, AgentMemoryEntry[]>;
  project?: AgentMemoryEntry[];
  pinned?: AgentMemoryEntry[];
}

export interface AgentMemorySuggestion {
  id: string;
  kind: "session" | "project";
  at: string;
  summary: string;
  topics: string[];
  touchedFiles: string[];
  commandPreview: string;
}

export interface AgentMemoryActionResult {
  action: "pin" | "forget" | "use";
  ok: boolean;
  changed: number;
  message: string;
}

export interface AgentMemorySnapshot {
  sessionId: string;
  session: AgentMemoryEntry[];
  project: AgentMemoryEntry[];
  pinned: AgentMemoryEntry[];
}

interface ToolbeltCheck {
  name: string;
  ok: boolean;
  detail: string;
  stage: "pre" | "post";
}

interface AgentSubtask {
  id: string;
  title: string;
  detail: string;
  status: SubtaskStatus;
  opCount: number;
}

interface AgentExecutionPlan {
  summary: string;
  profiles: ToolbeltProfile[];
  subtasks: AgentSubtask[];
}

interface GuardrailBlock {
  action: FileOp["action"];
  filePath: string;
  reason: string;
}

interface AgentGuardrailReport {
  allowedRoots: string[];
  blockedCount: number;
  blocked: GuardrailBlock[];
  executedWithinPolicy: boolean;
}

interface PathPolicyDecision {
  allowed: boolean;
  normalizedPath: string;
  reason?: string;
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
  const projectExisting = store.project || [];
  store.project = [...projectExisting, entry].slice(-250);
  writeMemoryStore(store);
}

function entryMatchesIdentity(
  entry: AgentMemoryEntry,
  at: string,
  commandHash?: string,
): boolean {
  if (entry.at !== at) return false;
  if (!commandHash) return true;
  return (entry.commandHash || "") === commandHash;
}

function normalizeTopicToken(token: string): string {
  return token
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9\u0600-\u06ff_-]+/g, "")
    .slice(0, 40);
}

function extractCommandTopics(command: string, ops: FileOp[]): string[] {
  const textTokens = command
    .split(/\s+/)
    .map(normalizeTopicToken)
    .filter((t) => t.length >= 3);
  const fileTokens = ops
    .flatMap((op) => op.filePath.split(/[\/._-]/g))
    .map(normalizeTopicToken)
    .filter((t) => t.length >= 3);
  return Array.from(new Set([...textTokens, ...fileTokens])).slice(0, 20);
}

function memoryScoreForTopics(entry: AgentMemoryEntry, topics: string[]): number {
  const entryTopics = entry.topics || [];
  const entryFiles = entry.touchedFiles || [];
  let score = 0;
  for (const topic of topics) {
    if (entryTopics.includes(topic)) score += 3;
    if (entryFiles.some((fp) => fp.includes(topic))) score += 2;
  }
  return score;
}

function getProjectMemoryMatches(
  store: AgentMemoryStore,
  command: string,
  ops: FileOp[],
): AgentMemoryEntry[] {
  const topics = extractCommandTopics(command, ops);
  const source = store.project || [];
  const ranked = source
    .map((entry, idx) => ({
      entry,
      score: memoryScoreForTopics(entry, topics),
      idx,
    }))
    .filter((item) => item.score > 0)
    .sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      return b.idx - a.idx;
    })
    .slice(0, 6)
    .map((item) => item.entry);
  return ranked;
}

function getPinnedMemoryMatches(
  store: AgentMemoryStore,
  command: string,
  ops: FileOp[],
): AgentMemoryEntry[] {
  const topics = extractCommandTopics(command, ops);
  const source = store.pinned || [];
  const ranked = source
    .map((entry, idx) => ({
      entry,
      score: memoryScoreForTopics(entry, topics),
      idx,
    }))
    .sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      return b.idx - a.idx;
    })
    .slice(0, 8)
    .map((item) => item.entry);
  return ranked;
}

export function getAgentMemorySnapshot(sessionId = "", maxItems = 20): AgentMemorySnapshot {
  const normalizedSessionId = sessionId.trim();
  const store = readMemoryStore();
  const cap = Math.max(1, Math.min(200, Math.floor(maxItems)));
  return {
    sessionId: normalizedSessionId,
    session: normalizedSessionId ? (store.sessions[normalizedSessionId] || []).slice(-cap) : [],
    project: (store.project || []).slice(-cap),
    pinned: (store.pinned || []).slice(-cap),
  };
}

export function pinAgentMemoryEntry(input: {
  sessionId?: string;
  source: "session" | "project";
  at: string;
  commandHash?: string;
}): { ok: boolean; pinnedCount: number; message: string } {
  const store = readMemoryStore();
  const sessionId = (input.sessionId || "").trim();
  const sourceItems = input.source === "project"
    ? (store.project || [])
    : (store.sessions[sessionId] || []);
  const target = sourceItems.find((entry) => entryMatchesIdentity(entry, input.at, input.commandHash));
  if (!target) {
    return {
      ok: false,
      pinnedCount: (store.pinned || []).length,
      message: "لم يتم العثور على الذكرى المطلوبة للتثبيت",
    };
  }

  const pinned = store.pinned || [];
  const exists = pinned.some((entry) => entryMatchesIdentity(entry, target.at, target.commandHash));
  if (!exists) {
    store.pinned = [...pinned, target].slice(-120);
    writeMemoryStore(store);
  }
  return {
    ok: true,
    pinnedCount: (store.pinned || []).length,
    message: exists ? "الذكرى مثبتة مسبقاً" : "تم تثبيت الذكرى في Project Memory",
  };
}

export function forgetAgentMemory(input: {
  sessionId?: string;
  mode: "session" | "project" | "pinned" | "topic";
  at?: string;
  commandHash?: string;
  topic?: string;
}): { ok: boolean; removed: number; message: string } {
  const store = readMemoryStore();
  const sessionId = (input.sessionId || "").trim();
  const topic = normalizeTopicToken(input.topic || "");
  let removed = 0;

  if (input.mode === "session") {
    if (!sessionId) return { ok: false, removed: 0, message: "sessionId مطلوب لمسح ذاكرة الجلسة" };
    const before = store.sessions[sessionId] || [];
    if (input.at) {
      const next = before.filter((entry) => !entryMatchesIdentity(entry, input.at || "", input.commandHash));
      removed = before.length - next.length;
      store.sessions[sessionId] = next;
    } else {
      removed = before.length;
      store.sessions[sessionId] = [];
    }
  } else if (input.mode === "project") {
    const before = store.project || [];
    if (input.at) {
      const next = before.filter((entry) => !entryMatchesIdentity(entry, input.at || "", input.commandHash));
      removed = before.length - next.length;
      store.project = next;
    } else {
      removed = before.length;
      store.project = [];
    }
  } else if (input.mode === "pinned") {
    const before = store.pinned || [];
    if (input.at) {
      const next = before.filter((entry) => !entryMatchesIdentity(entry, input.at || "", input.commandHash));
      removed = before.length - next.length;
      store.pinned = next;
    } else {
      removed = before.length;
      store.pinned = [];
    }
  } else if (input.mode === "topic") {
    if (!topic) return { ok: false, removed: 0, message: "topic مطلوب لنمط النسيان بالموضوع" };
    const stripTopic = (entries: AgentMemoryEntry[]): AgentMemoryEntry[] => entries.filter((entry) => {
      const topics = entry.topics || [];
      return !topics.includes(topic);
    });
    const beforeSession = sessionId ? (store.sessions[sessionId] || []) : [];
    const beforeProject = store.project || [];
    const beforePinned = store.pinned || [];
    if (sessionId) {
      const nextSession = stripTopic(beforeSession);
      removed += beforeSession.length - nextSession.length;
      store.sessions[sessionId] = nextSession;
    }
    const nextProject = stripTopic(beforeProject);
    const nextPinned = stripTopic(beforePinned);
    removed += beforeProject.length - nextProject.length;
    removed += beforePinned.length - nextPinned.length;
    store.project = nextProject;
    store.pinned = nextPinned;
  }

  writeMemoryStore(store);
  return {
    ok: true,
    removed,
    message: removed > 0 ? `تم حذف ${removed} عناصر من الذاكرة` : "لا توجد عناصر مطابقة للحذف",
  };
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

type ToolbeltCommand = {
  name: string;
  cmd: string;
  args: string[];
  timeoutMs: number;
};

function normalizeAgentPath(filePath: string): string {
  const normalized = filePath
    .replace(/\\/g, "/")
    .replace(/^\/+/, "")
    .replace(/\/{2,}/g, "/")
    .trim();
  if (normalized.startsWith("src/")) {
    return `artifacts/hayo-ai/${normalized}`;
  }
  return normalized;
}

function pathInsideAllowedRoots(relativePath: string): boolean {
  return ALLOWED_WORKSPACE_ROOTS.some((root) => (
    relativePath === root || relativePath.startsWith(`${root}/`)
  ));
}

function pathMatchesExtraReadAllowlist(relativePath: string): boolean {
  const base = path.posix.basename(relativePath);
  return READ_EXTRA_ALLOW_PATTERNS.some((pattern) => pattern.test(base) || pattern.test(relativePath));
}

function evaluatePathPolicy(action: FileOp["action"], filePath: string): PathPolicyDecision {
  const normalized = normalizeAgentPath(filePath);
  if (!normalized) {
    return { allowed: false, normalizedPath: normalized, reason: "مسار فارغ" };
  }
  if (normalized.includes("..")) {
    return { allowed: false, normalizedPath: normalized, reason: "محاولة خروج من نطاق المشروع" };
  }

  const segments = normalized.split("/").filter(Boolean);
  const blockedSegment = segments.find((seg) => BLOCKED_PATH_SEGMENTS.has(seg));
  if (blockedSegment) {
    return {
      allowed: false,
      normalizedPath: normalized,
      reason: `مسار محظور (${blockedSegment})`,
    };
  }

  const base = segments[segments.length - 1] || "";
  const blockedPattern = BLOCKED_FILE_PATTERNS.find((pattern) => pattern.test(base) || pattern.test(normalized));
  if (blockedPattern) {
    return {
      allowed: false,
      normalizedPath: normalized,
      reason: "الوصول إلى ملف حسّاس محظور بسياسة الأمان",
    };
  }

  if (pathInsideAllowedRoots(normalized)) {
    return { allowed: true, normalizedPath: normalized };
  }

  if (action === "read" && pathMatchesExtraReadAllowlist(normalized)) {
    return { allowed: true, normalizedPath: normalized };
  }

  return {
    allowed: false,
    normalizedPath: normalized,
    reason: "المسار خارج نطاق الجذور المسموح بها",
  };
}

function applyGuardrails(ops: FileOp[]): { allowedOps: FileOp[]; blocked: GuardrailBlock[] } {
  const allowedOps: FileOp[] = [];
  const blocked: GuardrailBlock[] = [];
  for (const op of ops) {
    const decision = evaluatePathPolicy(op.action, op.filePath);
    if (!decision.allowed) {
      blocked.push({
        action: op.action,
        filePath: op.filePath,
        reason: decision.reason || "غير مسموح",
      });
      continue;
    }
    allowedOps.push({
      ...op,
      filePath: decision.normalizedPath,
    });
  }
  return { allowedOps, blocked };
}

function detectToolbeltProfiles(command: string, ops: FileOp[]): ToolbeltProfile[] {
  const set = new Set<ToolbeltProfile>(["quality"]);
  const text = command.toLowerCase();

  const touchesFrontend = ops.some((op) => op.filePath.startsWith("artifacts/hayo-ai/src/"));
  const touchesBackend = ops.some((op) => op.filePath.startsWith("artifacts/api-server/src/hayo/"));

  if (touchesFrontend || /frontend|ui|tsx|react|page|component|واجهة|صفحة|مكون/i.test(text)) {
    set.add("frontend");
  }
  if (touchesBackend || /backend|api|trpc|router|server|خلفي|مسار|خدمة/i.test(text)) {
    set.add("backend");
  }

  return Array.from(set);
}

function classifyOpArea(filePath: string): "frontend" | "backend" | "shared" | "other" {
  if (filePath.startsWith("artifacts/hayo-ai/src/")) return "frontend";
  if (filePath.startsWith("artifacts/api-server/src/hayo/")) return "backend";
  if (filePath.startsWith("shared/")) return "shared";
  return "other";
}

function buildExecutionPlan(command: string, ops: FileOp[], profiles: ToolbeltProfile[]): AgentExecutionPlan {
  const buckets = new Map<string, FileOp[]>();
  for (const op of ops) {
    const area = classifyOpArea(op.filePath);
    const key = `${area}:${op.action === "read" ? "context" : "change"}`;
    const existing = buckets.get(key) || [];
    existing.push(op);
    buckets.set(key, existing);
  }

  const subtasks: AgentSubtask[] = [];
  let idx = 1;
  for (const [key, bucketOps] of buckets.entries()) {
    const [area, mode] = key.split(":");
    const title = mode === "context"
      ? `قراءة سياق ${area}`
      : `تعديلات ${area}`;
    subtasks.push({
      id: `task-${idx}`,
      title,
      detail: `${bucketOps.length} عملية ضمن ${area}`,
      status: "pending",
      opCount: bucketOps.length,
    });
    idx += 1;
  }

  const shortCommand = command.trim().slice(0, 90);
  const summary = `خطة تنفيذ: ${ops.length} عمليات (${subtasks.length} مهام فرعية) | الطلب: ${shortCommand || "بدون نص"}`;
  return { summary, profiles, subtasks };
}

function finalizeExecutionPlan(
  basePlan: AgentExecutionPlan,
  ops: FileOp[],
  executedOps: AgentResponse["executedOps"],
  blocked: GuardrailBlock[],
): AgentExecutionPlan {
  const blockedSet = new Set(blocked.map((b) => `${b.action}:${normalizeAgentPath(b.filePath)}`));
  const executedMap = new Map<string, { success: boolean }>();
  for (const item of executedOps) {
    executedMap.set(`${item.action}:${normalizeAgentPath(item.filePath)}`, { success: item.success });
  }

  const nextSubtasks = basePlan.subtasks.map((task) => {
    const taskOps = ops.filter((op) => {
      const area = classifyOpArea(op.filePath);
      const mode = op.action === "read" ? "context" : "change";
      const key = `${area}:${mode}`;
      const taskArea = task.title.includes("frontend")
        ? "frontend"
        : task.title.includes("backend")
          ? "backend"
          : task.title.includes("shared")
            ? "shared"
            : "other";
      const taskMode = task.title.includes("قراءة سياق") ? "context" : "change";
      return key === `${taskArea}:${taskMode}`;
    });

    if (taskOps.length === 0) {
      return task;
    }

    let hasBlocked = false;
    let hasFailed = false;
    let done = 0;
    for (const op of taskOps) {
      const opKey = `${op.action}:${normalizeAgentPath(op.filePath)}`;
      if (blockedSet.has(opKey)) {
        hasBlocked = true;
        continue;
      }
      const result = executedMap.get(opKey);
      if (!result) continue;
      if (!result.success) {
        hasFailed = true;
      } else {
        done += 1;
      }
    }

    const status: SubtaskStatus = hasBlocked
      ? "blocked"
      : hasFailed
        ? "failed"
        : done === taskOps.length
          ? "done"
          : "pending";

    return {
      ...task,
      status,
    };
  });

  return {
    ...basePlan,
    subtasks: nextSubtasks,
  };
}

async function runToolbeltChecksByProfile(
  profiles: ToolbeltProfile[],
  stage: "pre" | "post",
): Promise<ToolbeltCheck[]> {
  const commands: ToolbeltCommand[] = [];

  commands.push({
    name: stage === "pre" ? "git-status-pre" : "git-status-post",
    cmd: "git",
    args: ["status", "--porcelain"],
    timeoutMs: 8_000,
  });

  if (profiles.includes("frontend")) {
    commands.push({
      name: stage === "pre" ? "frontend-typecheck-pre" : "frontend-typecheck-post",
      cmd: "pnpm",
      args: ["--filter", "@workspace/hayo-ai", "typecheck"],
      timeoutMs: 45_000,
    });
    if (stage === "post") {
      commands.push({
        name: "frontend-build-post",
        cmd: "pnpm",
        args: ["--filter", "@workspace/hayo-ai", "build"],
        timeoutMs: 60_000,
      });
    }
  }

  if (profiles.includes("backend")) {
    commands.push({
      name: stage === "pre" ? "backend-typecheck-pre" : "backend-typecheck-post",
      cmd: "pnpm",
      args: ["--filter", "@workspace/api-server", "typecheck"],
      timeoutMs: 45_000,
    });
    if (stage === "post") {
      commands.push({
        name: "backend-test-post",
        cmd: "pnpm",
        args: ["--filter", "@workspace/api-server", "run", "--if-present", "test"],
        timeoutMs: 60_000,
      });
    }
  }

  if (profiles.includes("quality")) {
    commands.push({
      name: stage === "pre" ? "workspace-lint-pre" : "workspace-lint-post",
      cmd: "pnpm",
      args: ["-w", "run", "--if-present", "lint"],
      timeoutMs: 45_000,
    });
    if (stage === "post") {
      commands.push({
        name: "workspace-test-post",
        cmd: "pnpm",
        args: ["-w", "run", "--if-present", "test"],
        timeoutMs: 60_000,
      });
    }
  }

  const checks: ToolbeltCheck[] = [];
  for (const command of commands) {
    const out = await runCommandQuick(command.cmd, command.args, command.timeoutMs);
    checks.push({
      name: command.name,
      ok: out.ok,
      detail: out.detail,
      stage,
    });
  }
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
  const initialProjectMemory = getProjectMemoryMatches(memoryStore, command, []);
  const projectMemoryContext = initialProjectMemory.length > 0
    ? initialProjectMemory.map((entry, idx) => (
      `${idx + 1}) ${entry.at} | ${entry.summary} | topics=${(entry.topics || []).join(", ")}`
    )).join("\n")
    : "لا توجد ذاكرة مشروع مطابقة حتى الآن";

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

## ذاكرة المشروع طويلة الأمد (Project Memory):
${projectMemoryContext}

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

  const opsRaw = (parsed.operations || []).map(op => ({
    ...op,
    filePath: normalizeAgentPath(op.filePath),
  }));
  const guardrailsResult = applyGuardrails(opsRaw);
  const ops = guardrailsResult.allowedOps;
  const blocked = guardrailsResult.blocked;
  const toolbeltProfiles = detectToolbeltProfiles(command, ops);
  let executionPlan = buildExecutionPlan(command, ops, toolbeltProfiles);

  pushStep(
    "plan",
    blocked.length > 0 ? "failed" : "done",
    `سياسة المسارات: ${ops.length} مسموح / ${blocked.length} محظور`,
    36,
  );
  pushStep(
    "plan",
    "done",
    `خطة فرعية: ${executionPlan.subtasks.length} مهام | Toolbelt profile: ${toolbeltProfiles.join(", ")}`,
    42,
  );

  const preChecks = await runToolbeltChecksByProfile(toolbeltProfiles, "pre");
  const prePassed = preChecks.filter((c) => c.ok).length;
  const preFailed = preChecks.length - prePassed;
  pushStep(
    "verify",
    preFailed > 0 ? "failed" : "done",
    `Pre-checks: ${prePassed} ناجح / ${preFailed} فشل`,
    48,
  );

  const readOps = ops.filter((op) => op.action === "read");
  const writeOps = ops.filter((op) => op.action !== "read");
  let extraContent = "";

  if (readOps.length > 0) {
    const readPaths = readOps.map((op) => op.filePath);
    extraContent = readFilesSafe(readPaths);
    pushStep("execute", "done", `تمت قراءة ${readOps.length} ملفات/مسارات للسياق`, 45);
  }

  const readResults = readOps.map((op) => ({ action: op.action, filePath: op.filePath, success: true }));
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
    pushStep("execute", fail > 0 ? "failed" : "done", `تنفيذ تلقائي: ${ok} نجح / ${fail} فشل`, 68);

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
          78,
        );
      }
    }
  } else if (!autoExecute && writeOps.length > 0) {
    pushStep("execute", "done", `وضع يدوي: ${writeOps.length} عمليات جاهزة للتطبيق`, 68);
  }

  const blockedExecutionResults: AgentResponse["executedOps"] = blocked.map((item) => ({
    action: item.action,
    filePath: item.filePath,
    success: false,
    error: item.reason,
  }));

  if (blocked.length > 0) {
    const blockedReport = blocked
      .slice(0, 10)
      .map((item) => `- ${item.action} ${item.filePath}: ${item.reason}`)
      .join("\n");
    extraContent += `\n\n---\n\n## Guardrails (عمليات محظورة)\n${blockedReport}`;
    pushStep("execute", "failed", `تم منع ${blocked.length} عملية بواسطة guardrails`, 82);
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
    pushStep("verify", "done", `اكتمل التحقق على ${verifyTargets.length} ملفات`, 90);
  } else {
    pushStep("verify", "done", "لا توجد تعديلات مطبقة تحتاج تحقق ملفات", 90);
  }

  const postChecks = await runToolbeltChecksByProfile(toolbeltProfiles, "post");
  const allChecks = [...preChecks, ...postChecks];
  const passedChecks = allChecks.filter((c) => c.ok).length;
  const failedChecks = allChecks.length - passedChecks;
  pushStep(
    "verify",
    failedChecks > 0 ? "failed" : "done",
    `Toolbelt checks: ${passedChecks} ناجح / ${failedChecks} فشل`,
    100,
  );

  const allExecutedOps = [...readResults, ...writeResults, ...blockedExecutionResults];
  executionPlan = finalizeExecutionPlan(executionPlan, ops, allExecutedOps, blocked);

  const successCount = allExecutedOps.filter((r) => r.success).length;
  const failedCount = allExecutedOps.filter((r) => !r.success).length;
  const memoryTopics = extractCommandTopics(command, ops);
  const touchedFiles = ops
    .filter((op) => op.action !== "read")
    .map((op) => op.filePath)
    .slice(0, 24);
  const memorySummary = `آخر تنفيذ: ${ops.length + blocked.length} عملية | نجاح ${successCount} | فشل ${failedCount}`;
  appendMemoryEntry(memoryStore, normalizedSessionId, {
    at: new Date().toISOString(),
    command: command.slice(0, 500),
    summary: memorySummary,
    ops: ops.length + blocked.length,
    success: successCount,
    failed: failedCount,
    topics: memoryTopics,
    touchedFiles,
    commandHash: createHash("sha1").update(command).digest("hex").slice(0, 16),
  });

  const guardrails: AgentGuardrailReport = {
    allowedRoots: [...ALLOWED_WORKSPACE_ROOTS],
    blockedCount: blocked.length,
    blocked,
    executedWithinPolicy: blocked.length === 0,
  };

  return {
    message: parsed.message + (extraContent ? "\n\n" + extraContent : ""),
    operations: ops,
    executedOps: allExecutedOps,
    steps: executionSteps,
    retry: retryMeta,
    toolbelt: {
      profile: toolbeltProfiles,
      pre: preChecks,
      post: postChecks,
      passed: passedChecks,
      failed: failedChecks,
    },
    plan: executionPlan,
    guardrails,
    memory: {
      sessionId: normalizedSessionId,
      summary: memorySummary,
      recalledSession: memoryTrail.length,
      recalledProject: initialProjectMemory.length,
      topics: memoryTopics,
    },
  };
}
