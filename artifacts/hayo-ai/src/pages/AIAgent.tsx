import { useState, useRef, useEffect, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";
import { getLoginUrl } from "@/const";
import { isOwnerUser } from "@/lib/owner";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { toast } from "sonner";
import { motion, AnimatePresence } from "framer-motion";
import {
  Bot, Send, Loader2, Home, CheckCircle2, XCircle,
  FileCode, FilePlus, Trash2, Eye, Play, Zap, Terminal,
  ChevronDown, ChevronUp, Copy, RotateCcw, Paperclip, Plus, Image as ImageIcon, X,
} from "lucide-react";

interface FileOp {
  action: "create" | "edit" | "delete" | "read";
  filePath: string;
  content?: string;
  description: string;
}

type ExecutedOp = { action: string; filePath: string; success: boolean; error?: string };
type FixerLog = { type: string; message: string };
type FixerResult = { file: string; success: boolean; applied: boolean; explanation: string; backupPath?: string };

interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  operations?: FileOp[];
  executedOps?: ExecutedOp[];
  fixerLogs?: FixerLog[];
  fixerResults?: FixerResult[];
  steps?: AgentStep[];
  attachments?: AttachmentItem[];
  timestamp: Date;
}

type AgentStep = {
  phase: "plan" | "execute" | "verify";
  status: "done" | "failed";
  detail: string;
  progress?: number;
  at?: string;
};

type ToolbeltProfile = "frontend" | "backend" | "quality";
type ToolbeltCheck = {
  name: string;
  ok: boolean;
  detail: string;
  stage: "pre" | "post";
};
type AgentSubtask = {
  id: string;
  title: string;
  detail: string;
  status: "pending" | "done" | "failed" | "blocked";
  opCount: number;
};
type AgentPlan = {
  summary: string;
  profiles: ToolbeltProfile[];
  subtasks: AgentSubtask[];
};
type GuardrailBlock = {
  action: "create" | "edit" | "delete" | "read";
  filePath: string;
  reason: string;
};
type AgentGuardrails = {
  allowedRoots: string[];
  blockedCount: number;
  blocked: GuardrailBlock[];
  executedWithinPolicy: boolean;
};
type MemoryAction = "pin" | "forget" | "use";
type MemoryActionItem = {
  id: string;
  kind: "session" | "project";
  at: string;
  summary: string;
  topics: string[];
  touchedFiles: string[];
  commandPreview: string;
};
type MemoryActionResult = {
  action: MemoryAction;
  ok: boolean;
  changed: number;
  message: string;
};

type MemoryOperationApiResult = {
  ok: boolean;
  message: string;
  snapshot: {
    sessionId: string;
    session: MemoryActionItem[];
    project: MemoryActionItem[];
    pinned: MemoryActionItem[];
  };
  pinnedCount?: number;
  removed?: number;
};

type LiveAgentExecution = {
  steps: AgentStep[];
  plan?: AgentPlan;
  guardrails?: AgentGuardrails;
  toolbelt?: AgentExecuteApiResponse["toolbelt"];
  retry?: AgentExecuteApiResponse["retry"];
  memory?: AgentExecuteApiResponse["memory"];
};

type MemorySnapshot = {
  sessionId: string;
  session: Array<{
    at: string;
    command: string;
    summary: string;
    topics?: string[];
    touchedFiles?: string[];
    commandHash?: string;
  }>;
  project: Array<{
    at: string;
    command: string;
    summary: string;
    topics?: string[];
    touchedFiles?: string[];
    commandHash?: string;
  }>;
  pinned: Array<{
    at: string;
    command: string;
    summary: string;
    topics?: string[];
    touchedFiles?: string[];
    commandHash?: string;
  }>;
};

type AttachmentItem = {
  name: string;
  type: string;
  size: number;
  preview?: string;
  extractedText?: string;
};

const ACCEPT_ALL_UPLOADS = "image/*,video/*,audio/*,.pdf,.doc,.docx,.txt,.csv,.json,.py,.js,.ts,.tsx,.jsx,.html,.css,.xml,.md,.xlsx,.xls,.zip,.rar,.7z,.tar,.gz,.pptx,.ppt,.svg,.sql,.yaml,.yml,.toml,.env,.sh,.bat,.ps1,.rb,.php,.java,.cpp,.c,.h,.hpp,.go,.rs,.swift,.kt,.dart,.lua,.r,.m,.mq4,.mq5,.mqh,.ex4,.ex5,.mp3,.wav,.ogg,.mp4,.webm,.mov";
const MAX_FILE_SIZE = 500 * 1024 * 1024; // Owner-only page, allow large files

function FixerExecutionPanel({
  logs,
  results,
}: {
  logs: FixerLog[];
  results: FixerResult[];
}) {
  if (!logs?.length && !results?.length) return null;

  return (
    <div className="space-y-2 pt-2 border-t border-white/10">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
        <div className="bg-black/20 rounded-lg border border-white/10 p-2.5 max-h-44 overflow-y-auto">
          <p className="text-[11px] font-bold text-cyan-300 mb-1">بث المراحل</p>
          {logs.map((log, i) => (
            <div key={`${log.type}-${i}`} className="text-[11px] text-muted-foreground border-b border-white/5 pb-1 mb-1 last:mb-0 last:border-0">
              <span className="text-primary ml-1">[{log.type}]</span>
              {log.message}
            </div>
          ))}
        </div>
        <div className="bg-black/20 rounded-lg border border-white/10 p-2.5 max-h-44 overflow-y-auto">
          <p className="text-[11px] font-bold text-emerald-300 mb-1">نتائج الإصلاح</p>
          {results.map((r, i) => (
            <div key={`${r.file}-${i}`} className="text-[11px] border-b border-white/5 pb-1 mb-1 last:mb-0 last:border-0">
              <span className={r.success ? "text-emerald-400" : "text-red-400"}>{r.success ? "✓" : "✗"}</span>
              <span className="mx-1 font-mono">{r.file}</span>
              <span className="text-muted-foreground">{r.applied ? "مطبّق" : "اقتراح"}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

const ACTION_ICONS: Record<string, typeof FilePlus> = {
  create: FilePlus,
  edit: FileCode,
  delete: Trash2,
  read: Eye,
};

const ACTION_COLORS: Record<string, string> = {
  create: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
  edit: "text-blue-400 bg-blue-500/10 border-blue-500/30",
  delete: "text-red-400 bg-red-500/10 border-red-500/30",
  read: "text-amber-400 bg-amber-500/10 border-amber-500/30",
};

const ACTION_LABELS: Record<string, string> = {
  create: "إنشاء",
  edit: "تعديل",
  delete: "حذف",
  read: "قراءة",
};

const EXAMPLE_COMMANDS = [
  "أنشئ صفحة جديدة اسمها لوحة الإحصائيات بها رسوم بيانية",
  "أضف زر جديد في الصفحة الرئيسية يفتح صفحة المساعد الذكي",
  "عدّل صفحة Dashboard وأضف بطاقة إحصائية جديدة لعدد الزيارات",
  "اقرأ ملف App.tsx وأخبرني بكل الصفحات المسجلة",
  "أنشئ مكون UI جديد اسمه StatCard يعرض رقم وعنوان وأيقونة",
  "/fixer project --backend",
  "/fixer targeted --path=artifacts/hayo-ai/src/pages/ReverseEngineer.tsx",
];

interface FixerCommandConfig {
  scope: "project" | "targeted";
  targetPath?: string;
  includeBackend: boolean;
  autoApply: boolean;
  maxFixes: number;
}

interface FixerExecuteApiResponse {
  error?: string;
  target?: string;
  summary?: { total?: number };
  issues?: unknown[];
  fixed?: number;
  applied?: number;
  executionLog?: FixerLog[];
  results?: FixerResult[];
}

interface AgentExecuteApiResponse {
  message: string;
  operations: FileOp[];
  executedOps: ExecutedOp[];
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
  plan?: AgentPlan;
  guardrails?: AgentGuardrails;
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

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  return "Unknown error";
}

function parseFixerCommand(command: string): { config: FixerCommandConfig | null; error?: string } {
  const trimmed = command.trim();
  if (!trimmed.toLowerCase().startsWith("/fixer")) return { config: null };

  const parts = trimmed.split(/\s+/).slice(1);
  let scope: "project" | "targeted" = "project";
  let targetPath: string | undefined;
  let includeBackend = false;
  let autoApply = true;
  let maxFixes = 12;

  for (const part of parts) {
    if (part === "project" || part === "full") {
      scope = "project";
      continue;
    }
    if (part === "targeted" || part === "target") {
      scope = "targeted";
      continue;
    }
    if (part === "--backend") {
      includeBackend = true;
      continue;
    }
    if (part === "--dry-run") {
      autoApply = false;
      continue;
    }
    if (part.startsWith("--path=")) {
      targetPath = part.slice("--path=".length);
      continue;
    }
    if (part.startsWith("--max=")) {
      const n = Number(part.slice("--max=".length));
      if (Number.isFinite(n) && n > 0) {
        maxFixes = Math.max(1, Math.min(30, Math.floor(n)));
      }
      continue;
    }
  }

  if (scope === "targeted" && !targetPath) {
    return {
      config: null,
      error: "أمر /fixer targeted يحتاج --path=مسار-ملف-أو-مجلد",
    };
  }

  return {
    config: { scope, targetPath, includeBackend, autoApply, maxFixes },
  };
}

function formatFileSize(size: number): string {
  if (!Number.isFinite(size) || size <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let value = size;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  return `${value.toFixed(value >= 100 || idx === 0 ? 0 : 1)} ${units[idx]}`;
}

function getFileIconLabel(type: string): string {
  if (type.startsWith("image/")) return "🖼️";
  if (type.startsWith("video/")) return "🎬";
  if (type.startsWith("audio/")) return "🎵";
  if (type.includes("pdf")) return "📕";
  if (type.includes("zip") || type.includes("rar") || type.includes("tar")) return "🗜️";
  return "📎";
}

function detectLangForMarkdown(fileName: string): string {
  const ext = fileName.split(".").pop()?.toLowerCase() || "";
  const map: Record<string, string> = {
    ts: "ts", tsx: "tsx", js: "js", jsx: "jsx",
    py: "python", java: "java", go: "go", rs: "rust", php: "php",
    c: "c", cpp: "cpp", h: "c", hpp: "cpp", cs: "csharp",
    html: "html", css: "css", json: "json", md: "markdown", sql: "sql",
    sh: "bash", yaml: "yaml", yml: "yaml", xml: "xml", txt: "text",
    mq4: "cpp", mq5: "cpp", mqh: "cpp",
  };
  return map[ext] || "";
}

function AgentStepsPanel({ steps }: { steps: AgentStep[] }) {
  if (!steps.length) return null;
  return (
    <div className="space-y-1.5 pt-2 border-t border-white/10">
      <p className="text-[11px] font-bold text-cyan-300">مراحل التنفيذ</p>
      {steps.map((step, idx) => (
        <div key={`${step.phase}-${idx}`} className="text-[11px] rounded border border-white/10 bg-black/20 p-2">
          <span className={step.status === "done" ? "text-emerald-400" : "text-red-400"}>
            {step.status === "done" ? "✓" : "✗"}
          </span>
          <span className="mx-1 text-primary">[{step.phase}]</span>
          <span className="text-muted-foreground">{step.detail}</span>
        </div>
      ))}
    </div>
  );
}

function AttachmentChips({
  attachments,
  removable = false,
  onRemove,
}: {
  attachments: AttachmentItem[];
  removable?: boolean;
  onRemove?: (idx: number) => void;
}) {
  if (!attachments.length) return null;
  return (
    <div className="flex flex-wrap gap-2">
      {attachments.map((att, idx) => (
        <div key={`${att.name}-${idx}`} className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg border border-white/10 bg-black/20 text-[11px]">
          {att.preview ? (
            <img src={att.preview} alt={att.name} className="w-6 h-6 rounded object-cover" />
          ) : (
            <ImageIcon className="w-3.5 h-3.5 text-violet-300" />
          )}
          <div className="max-w-[180px]">
            <div className="truncate">{att.name}</div>
            <div className="text-muted-foreground">{formatFileSize(att.size)}</div>
          </div>
          {removable && onRemove ? (
            <button
              type="button"
              onClick={() => onRemove(idx)}
              className="text-white/60 hover:text-red-300 transition-colors"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          ) : null}
        </div>
      ))}
    </div>
  );
}

function OperationCard({ op, executed }: { op: FileOp; executed?: { success: boolean; error?: string } }) {
  const [showContent, setShowContent] = useState(false);
  const Icon = ACTION_ICONS[op.action] || FileCode;

  return (
    <div className={`rounded-xl border p-3 space-y-2 ${ACTION_COLORS[op.action]}`}>
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Icon className="w-4 h-4 shrink-0" />
          <span className="text-xs font-bold">{ACTION_LABELS[op.action]}</span>
          <code className="text-[10px] bg-black/20 px-1.5 py-0.5 rounded font-mono" dir="ltr">{op.filePath}</code>
        </div>
        <div className="flex items-center gap-1.5">
          {executed && (
            executed.success
              ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              : <XCircle className="w-3.5 h-3.5 text-red-400" />
          )}
          {op.content && (
            <button onClick={() => setShowContent(!showContent)} className="text-white/40 hover:text-white/70">
              {showContent ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            </button>
          )}
        </div>
      </div>
      <p className="text-[10px] opacity-70">{op.description}</p>
      {executed?.error && (
        <p className="text-[10px] text-red-400">خطأ: {executed.error}</p>
      )}
      <AnimatePresence>
        {showContent && op.content && (
          <motion.div initial={{ height: 0 }} animate={{ height: "auto" }} exit={{ height: 0 }} className="overflow-hidden">
            <div className="relative">
              <pre className="text-[10px] bg-black/30 rounded-lg p-3 overflow-x-auto max-h-64 font-mono leading-relaxed" dir="ltr">
                {op.content.slice(0, 5000)}
                {op.content.length > 5000 && "\n... (تم اختصار المحتوى)"}
              </pre>
              <button
                onClick={() => { navigator.clipboard.writeText(op.content || ""); toast.success("تم النسخ"); }}
                className="absolute top-2 left-2 p-1 bg-white/10 rounded hover:bg-white/20"
              >
                <Copy className="w-3 h-3 text-white/60" />
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function AgentExecutionInspector({
  execution,
  inProgress,
}: {
  execution: AgentExecuteApiResponse | null;
  inProgress: boolean;
}) {
  const plan = execution?.plan;
  const guardrails = execution?.guardrails;
  const toolbelt = execution?.toolbelt;
  const steps = execution?.steps || [];

  const progress = steps.length
    ? Math.max(0, Math.min(100, steps[steps.length - 1]?.progress ?? 0))
    : 0;

  const hasContent = !!execution;
  if (!hasContent && !inProgress) return null;

  return (
    <aside className="w-full lg:w-[360px] xl:w-[390px] shrink-0 border border-border rounded-2xl bg-card/80 p-3 space-y-3 h-fit lg:sticky lg:top-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-bold text-violet-300">لوحة التفكير والتنفيذ</h3>
        <span className={`text-[10px] px-2 py-1 rounded-full border ${
          inProgress
            ? "text-amber-300 border-amber-500/30 bg-amber-500/10"
            : "text-emerald-300 border-emerald-500/30 bg-emerald-500/10"
        }`}>
          {inProgress ? "قيد التشغيل" : "جاهز"}
        </span>
      </div>

      <div className="bg-black/20 border border-white/10 rounded-lg p-2.5">
        <div className="text-[11px] text-muted-foreground mb-1">التقدم التنفيذي</div>
        <div className="h-2 rounded-full bg-white/10 overflow-hidden">
          <div
            className="h-full bg-violet-400 transition-all duration-500"
            style={{ width: `${Math.max(inProgress ? 8 : 0, progress)}%` }}
          />
        </div>
        <div className="text-[10px] text-muted-foreground mt-1">{Math.max(inProgress ? 8 : 0, progress)}%</div>
      </div>

      <div className="bg-black/20 border border-white/10 rounded-lg p-2.5 space-y-2">
        <div className="text-[11px] font-bold text-cyan-300">الخطة الفرعية</div>
        <div className="text-[11px] text-muted-foreground">{plan?.summary || "لا توجد خطة بعد"}</div>
        {plan?.profiles?.length ? (
          <div className="flex flex-wrap gap-1">
            {plan.profiles.map((p) => (
              <span key={p} className="text-[10px] px-1.5 py-0.5 rounded bg-violet-500/10 border border-violet-500/30 text-violet-200">
                {p}
              </span>
            ))}
          </div>
        ) : null}
        <div className="max-h-36 overflow-y-auto space-y-1">
          {(plan?.subtasks || []).map((task) => {
            const statusColor =
              task.status === "done"
                ? "text-emerald-300 border-emerald-500/30"
                : task.status === "failed"
                  ? "text-red-300 border-red-500/30"
                  : task.status === "blocked"
                    ? "text-amber-300 border-amber-500/30"
                    : "text-white/70 border-white/20";
            return (
              <div key={task.id} className={`text-[10px] border rounded p-1.5 ${statusColor}`}>
                <div className="font-semibold">{task.title} ({task.opCount})</div>
                <div className="opacity-80">{task.detail}</div>
              </div>
            );
          })}
          {!plan?.subtasks?.length && (
            <div className="text-[10px] text-muted-foreground">سيتم ملء المهام بعد أول تنفيذ.</div>
          )}
        </div>
      </div>

      <div className="bg-black/20 border border-white/10 rounded-lg p-2.5 space-y-2">
        <div className="text-[11px] font-bold text-amber-300">حماية Guardrails</div>
        <div className="text-[10px] text-muted-foreground">
          المسارات المسموحة: {(guardrails?.allowedRoots || []).join(" • ") || "—"}
        </div>
        <div className="text-[10px]">
          {guardrails
            ? `المحظور: ${guardrails.blockedCount} | الحالة: ${guardrails.executedWithinPolicy ? "ضمن السياسة" : "تم حظر عمليات"}`
            : "لا توجد بيانات guardrails بعد"}
        </div>
        {!!guardrails?.blocked?.length && (
          <div className="max-h-28 overflow-y-auto space-y-1">
            {guardrails.blocked.slice(0, 8).map((b, i) => (
              <div key={`${b.filePath}-${i}`} className="text-[10px] border border-red-500/20 rounded p-1 text-red-200 bg-red-500/5">
                <div className="font-mono">{b.action} {b.filePath}</div>
                <div>{b.reason}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="bg-black/20 border border-white/10 rounded-lg p-2.5 space-y-2">
        <div className="text-[11px] font-bold text-emerald-300">Toolbelt (Pre/Post)</div>
        <div className="text-[10px] text-muted-foreground">
          {toolbelt ? `ناجح ${toolbelt.passed} / فاشل ${toolbelt.failed}` : "لا توجد نتائج فحوص بعد"}
        </div>
        <div className="max-h-36 overflow-y-auto space-y-1">
          {[...(toolbelt?.pre || []), ...(toolbelt?.post || [])].map((check, i) => (
            <div key={`${check.name}-${i}`} className={`text-[10px] rounded border p-1.5 ${
              check.ok ? "border-emerald-500/30 text-emerald-200" : "border-red-500/30 text-red-200"
            }`}>
              <div className="font-mono">{check.stage} · {check.name}</div>
              <div className="opacity-80 whitespace-pre-wrap">{check.detail}</div>
            </div>
          ))}
          {!toolbelt?.pre?.length && !toolbelt?.post?.length && (
            <div className="text-[10px] text-muted-foreground">ستظهر نتائج الفحوص هنا.</div>
          )}
        </div>
      </div>

      <div className="bg-black/20 border border-white/10 rounded-lg p-2.5 space-y-2">
        <div className="text-[11px] font-bold text-indigo-300">Project Memory</div>
        <div className="text-[10px] text-muted-foreground">
          {execution?.memory?.summary || "لا توجد بيانات ذاكرة بعد"}
        </div>
        <div className="text-[10px] text-muted-foreground">
          استرجاع الجلسة: {execution?.memory?.recalledSession ?? 0} | استرجاع المشروع: {execution?.memory?.recalledProject ?? 0}
        </div>
        <div className="flex flex-wrap gap-1">
          {(execution?.memory?.topics || []).map((topic) => (
            <span
              key={topic}
              className="text-[10px] px-1.5 py-0.5 rounded border border-indigo-500/30 bg-indigo-500/10 text-indigo-200"
            >
              {topic}
            </span>
          ))}
          {!(execution?.memory?.topics || []).length && (
            <span className="text-[10px] text-muted-foreground">ستظهر المواضيع المسترجعة هنا.</span>
          )}
        </div>
      </div>
    </aside>
  );
}

export default function AIAgent() {
  const { isAuthenticated, user, loading: authLoading } = useAuth();
  const [input, setInput] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [activeExecution, setActiveExecution] = useState<AgentExecuteApiResponse | null>(null);
  const [autoExecute, setAutoExecute] = useState(false);
  const [fixerRunning, setFixerRunning] = useState(false);
  const [pendingAttachments, setPendingAttachments] = useState<AttachmentItem[]>([]);
  const chatEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const sessionIdRef = useRef(`sess-${crypto.randomUUID()}`);
  const [memoryBusy, setMemoryBusy] = useState(false);

  const memorySnapshotQ = trpc.aiAgent.memorySnapshot.useQuery(
    { sessionId: sessionIdRef.current, maxItems: 24 },
    { staleTime: 10_000 },
  );

  const memoryMut = trpc.aiAgent.memoryAction.useMutation({
    onSuccess: (data: { ok: boolean; message?: string; changed?: number }) => {
      if (data.ok) {
        toast.success(data.message || `تم تنفيذ العملية (${data.changed ?? 0})`);
      } else {
        toast.error(data.message || "فشلت عملية الذاكرة");
      }
      void memorySnapshotQ.refetch();
    },
    onError: (err: { message: string }) => {
      toast.error(`Memory Action Error: ${err.message}`);
    },
  });

  const handlePinMemory = async (item: MemoryActionItem) => {
    setMemoryBusy(true);
    try {
      await memoryMut.mutateAsync({
        action: "pin",
        sessionId: sessionIdRef.current,
        source: item.kind,
        at: item.at,
      });
    } finally {
      setMemoryBusy(false);
    }
  };

  const handleForgetMemory = async (item: MemoryActionItem) => {
    setMemoryBusy(true);
    try {
      await memoryMut.mutateAsync({
        action: "forget",
        sessionId: sessionIdRef.current,
        mode: item.kind === "session" ? "session" : "project",
        at: item.at,
      });
    } finally {
      setMemoryBusy(false);
    }
  };

  const executeMut = trpc.aiAgent.execute.useMutation({
    onSuccess: (data: AgentExecuteApiResponse) => {
      setActiveExecution(data);
      const assistantMsg: ChatMessage = {
        id: crypto.randomUUID(),
        role: "assistant",
        content: data.message,
        operations: data.operations,
        executedOps: data.executedOps,
        steps: data.steps || [],
        timestamp: new Date(),
      };
      setMessages(prev => [...prev, assistantMsg]);
      const metaLines: string[] = [];
      if (data.retry?.attempted) {
        metaLines.push(`🔁 Self-Heal: تم استرجاع ${data.retry.recovered} / المتبقي ${data.retry.remainingFailed}`);
      }
      if (data.toolbelt) {
        metaLines.push(`🧪 Toolbelt: ${data.toolbelt.passed} ناجح / ${data.toolbelt.failed} فشل`);
      }
      if (data.memory?.summary) {
        metaLines.push(`🧠 ذاكرة الجلسة: ${data.memory.summary}`);
      }
      if (metaLines.length) toast.info(metaLines.join(" | "));

      if (data.executedOps.length > 0) {
        const succeeded = data.executedOps.filter((o: ExecutedOp) => o.success).length;
        const failed = data.executedOps.filter((o: ExecutedOp) => !o.success).length;
        if (failed === 0) {
          toast.success(`تم تنفيذ ${succeeded} عملية بنجاح`);
        } else {
          toast.error(`${succeeded} نجحت، ${failed} فشلت`);
        }
      }
    },
    onError: (err: { message: string }) => {
      toast.error(`خطأ: ${err.message}`);
      setMessages(prev => [...prev, {
        id: crypto.randomUUID(),
        role: "assistant",
        content: `حدث خطأ: ${err.message}`,
        timestamp: new Date(),
      }]);
    },
  });

  const applyMut = trpc.aiAgent.applyOps.useMutation({
    onSuccess: (data: { results: ExecutedOp[] }) => {
      const succeeded = data.results.filter((o: ExecutedOp) => o.success).length;
      const failed = data.results.filter((o: ExecutedOp) => !o.success).length;
      if (failed === 0) {
        toast.success(`تم تنفيذ ${succeeded} عملية بنجاح`);
      } else {
        toast.error(`${succeeded} نجحت، ${failed} فشلت`);
      }

      setMessages(prev => prev.map((msg, i) => {
        if (i === prev.length - 1 && msg.role === "assistant") {
          return { ...msg, executedOps: data.results };
        }
        return msg;
      }));
      setActiveExecution((prev) => (
        prev
          ? {
            ...prev,
            executedOps: data.results,
          }
          : prev
      ));
    },
    onError: (err: { message: string }) => toast.error(`فشل التنفيذ: ${err.message}`),
  });

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const liveProgress = useMemo(() => {
    const latestAssistant = [...messages].reverse().find((m) => m.role === "assistant" && m.steps?.length);
    if (!latestAssistant?.steps?.length) return 0;
    return Math.max(0, Math.min(100, latestAssistant.steps[latestAssistant.steps.length - 1]?.progress ?? 0));
  }, [messages]);

  const handleFileSelect = async (files: FileList) => {
    const maxSize = MAX_FILE_SIZE;
    const items: AttachmentItem[] = [];

    for (const file of Array.from(files)) {
      if (file.size > maxSize) {
        toast.error(`${file.name}: الحجم يتجاوز ${Math.round(maxSize / 1024 / 1024)}MB`);
        continue;
      }

      const isImage = file.type.startsWith("image/");
      const isTextLike =
        file.type.startsWith("text/")
        || /\.(ts|tsx|js|jsx|json|md|txt|py|java|go|rs|sql|yaml|yml|toml|env|xml|html|css|sh)$/i.test(file.name);
      const isZip = /\.(zip)$/i.test(file.name) || file.type.includes("zip");
      const isRar = /\.(rar)$/i.test(file.name) || file.type.includes("rar");

      let extractedText: string | undefined;
      let preview: string | undefined;

      try {
        if (isImage) {
          preview = URL.createObjectURL(file);
          extractedText = `[صورة مرفقة: ${file.name}]`;
        } else if (isTextLike) {
          const text = await file.text();
          extractedText = `### ${file.name}\n\`\`\`\n${text.slice(0, 40_000)}\n\`\`\``;
        } else if (isZip || isRar) {
          const textEntries: Array<{ name: string; content: string }> = [];
          if (isZip) {
            const JSZip = (await import("jszip")).default;
            const zip = await JSZip.loadAsync(await file.arrayBuffer());
            for (const [name, entry] of Object.entries(zip.files)) {
              if ((entry as any).dir) continue;
              const ext = name.split(".").pop()?.toLowerCase() || "";
              if (!["ts", "tsx", "js", "jsx", "json", "md", "txt", "py", "html", "css"].includes(ext)) continue;
              const content = await (entry as any).async("text");
              textEntries.push({ name, content: content.slice(0, 8000) });
            }
          } else {
            extractedText = `📦 ${file.name} (RAR)\nتم إرفاق الأرشيف للتحليل، وسيتم التعامل معه كسياق ملف مضغوط.`;
          }
          if (!extractedText) {
            extractedText = `📦 ${file.name}\n${textEntries.slice(0, 40).map(f => `\n### ${f.name}\n\`\`\`\n${f.content}\n\`\`\``).join("\n")}`;
          }
        } else {
          extractedText = `[ملف مرفق: ${file.name} | النوع: ${file.type || "unknown"}]`;
        }
      } catch {
        extractedText = `[تعذر استخراج محتوى ${file.name}]`;
      }

      items.push({
        name: file.name,
        type: file.type || "application/octet-stream",
        size: file.size,
        preview,
        extractedText,
      });
    }

    if (items.length > 0) {
      setPendingAttachments(prev => [...prev, ...items].slice(0, 12));
      toast.success(`تمت إضافة ${items.length} مرفقات`);
    }
  };

  const handleSend = async () => {
    if ((!input.trim() && pendingAttachments.length === 0) || executeMut.isPending || fixerRunning) return;

    const commandText = input.trim();
    const fallbackAttachmentPrompt = "حلل المرفقات المرسلة وطبّق المطلوب بأفضل تنفيذ ممكن";
    const finalCommand = commandText || fallbackAttachmentPrompt;

    const userMsg: ChatMessage = {
      id: crypto.randomUUID(),
      role: "user",
      content: finalCommand,
      attachments: pendingAttachments,
      timestamp: new Date(),
    };
    setMessages(prev => [...prev, userMsg]);
    const command = finalCommand;
    const fixerParse = parseFixerCommand(command);

    const parseError = fixerParse.error;
    if (parseError) {
      setMessages(prev => [...prev, {
        id: crypto.randomUUID(),
        role: "assistant",
        content: parseError,
        timestamp: new Date(),
      }]);
      toast.error(parseError);
      setInput("");
      return;
    }

    if (fixerParse.config) {
      setInput("");
      setPendingAttachments([]);
      setFixerRunning(true);
      try {
        const res = await fetch("/api/fixer/execute", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify(fixerParse.config),
        });
        const data = (await res.json()) as FixerExecuteApiResponse;
        if (!res.ok) throw new Error(data.error || "فشل تنفيذ المصلح الذكي");

        const content = [
          "نتيجة المصلح الذكي التنفيذي:",
          `• النطاق: ${data.target || fixerParse.config.scope}`,
          `• المشاكل المكتشفة: ${data.summary?.total ?? data.issues?.length ?? 0}`,
          `• الإصلاحات: ${data.fixed ?? 0}`,
          `• المطبّق تلقائياً: ${data.applied ?? 0}`,
        ].join("\n");

        setMessages(prev => [...prev, {
          id: crypto.randomUUID(),
          role: "assistant",
          content,
          fixerLogs: data.executionLog || [],
          fixerResults: data.results || [],
          timestamp: new Date(),
        }]);
        toast.success(`المصلح الذكي: ${data.fixed ?? 0} إصلاح / ${data.applied ?? 0} تطبيق`);
      } catch (err: unknown) {
        const message = `فشل تشغيل المصلح الذكي: ${getErrorMessage(err)}`;
        setMessages(prev => [...prev, {
          id: crypto.randomUUID(),
          role: "assistant",
          content: message,
          timestamp: new Date(),
        }]);
        toast.error(message);
      } finally {
        setFixerRunning(false);
      }
      return;
    }

    const history = messages.map(m => ({
      role: m.role,
      content: m.content,
    }));

    const attachmentsPayload = pendingAttachments.map((att) => ({
      name: att.name,
      type: att.type,
      size: att.size,
      extractedText: att.extractedText,
    }));

    executeMut.mutate({
      command,
      conversationHistory: history,
      sessionId: sessionIdRef.current,
      attachments: attachmentsPayload,
      autoExecute,
    });

    setInput("");
    setPendingAttachments([]);
  };

  const handleApply = (ops: FileOp[]) => {
    const writeOps = ops.filter(o => o.action !== "read");
    if (writeOps.length === 0) return;
    applyMut.mutate({ operations: writeOps });
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const removeAttachment = (idx: number) => {
    setPendingAttachments(prev => {
      const target = prev[idx];
      if (target?.preview?.startsWith("blob:")) {
        URL.revokeObjectURL(target.preview);
      }
      return prev.filter((_, i) => i !== idx);
    });
  };

  useEffect(() => {
    return () => {
      pendingAttachments.forEach((att) => {
        if (att.preview?.startsWith("blob:")) {
          URL.revokeObjectURL(att.preview);
        }
      });
    };
  }, [pendingAttachments]);

  if (authLoading) {
    return (
      <div className="h-screen flex items-center justify-center bg-background">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  if (!isAuthenticated || !isOwnerUser(user)) {
    return (
      <div className="h-screen flex items-center justify-center bg-background p-4">
        <div className="bg-card border border-border rounded-2xl p-8 max-w-md w-full text-center space-y-4">
          <Bot className="w-16 h-16 mx-auto text-violet-400 opacity-60" />
          <h2 className="text-2xl font-bold">AI Agent التنفيذي</h2>
          <p className="text-muted-foreground">هذه الصفحة متاحة لمالك المنصة فقط</p>
          <Button asChild className="w-full"><a href={getLoginUrl()}>تسجيل الدخول</a></Button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col" dir="rtl">
      <header className="h-12 bg-card border-b border-border flex items-center justify-between px-4 shrink-0">
        <div className="flex items-center gap-3">
          <Link href="/" className="text-muted-foreground hover:text-primary transition-colors">
            <Home className="w-4 h-4" />
          </Link>
          <div className="w-px h-5 bg-border" />
          <Bot className="w-5 h-5 text-violet-400" />
          <span className="font-bold text-sm">AI Agent التنفيذي</span>
          <span className="text-xs bg-violet-400/10 text-violet-400 px-2 py-0.5 rounded-full">Claude Opus</span>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setAutoExecute(!autoExecute)}
            className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border transition-all ${
              autoExecute
                ? "bg-emerald-500/20 border-emerald-500/40 text-emerald-400"
                : "bg-white/5 border-white/15 text-white/50 hover:bg-white/10"
            }`}
          >
            <Zap className="w-3 h-3" />
            تنفيذ تلقائي: {autoExecute ? "مفعّل" : "يدوي"}
          </button>
          <button
            onClick={() => { setMessages([]); setActiveExecution(null); toast.info("تم مسح المحادثة"); }}
            className="text-muted-foreground hover:text-foreground transition-colors"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </header>

      <div className="flex-1 w-full max-w-[1400px] mx-auto px-4 py-4">
        <div className="flex flex-col xl:flex-row gap-4 h-full">
          <div className="flex-1 min-w-0 flex flex-col border border-border rounded-2xl bg-card/40">
        <div className="flex-1 overflow-y-auto px-4 py-6 space-y-4">
          {messages.length === 0 && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="flex flex-col items-center justify-center h-full gap-6 py-16"
            >
              <div className="w-20 h-20 rounded-3xl bg-gradient-to-br from-violet-500/20 to-indigo-500/20 border border-violet-500/30 flex items-center justify-center">
                <Bot className="w-10 h-10 text-violet-400" />
              </div>
              <div className="text-center space-y-2">
                <h2 className="text-xl font-bold">AI Agent التنفيذي</h2>
                <p className="text-muted-foreground text-sm max-w-md">
                  اكتب أي أمر وسأنفذه مباشرة داخل مشروعك — إنشاء صفحات، تعديل كود، حذف ملفات، والمزيد
                </p>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-w-2xl w-full">
                {EXAMPLE_COMMANDS.map((cmd, i) => (
                  <button
                    key={i}
                    onClick={() => setInput(cmd)}
                    className="text-right text-xs bg-card border border-border rounded-xl px-4 py-3 hover:bg-secondary/50 transition-colors text-muted-foreground hover:text-foreground"
                  >
                    <Terminal className="w-3 h-3 inline-block ml-1.5 text-violet-400" />
                    {cmd}
                  </button>
                ))}
              </div>
              <div className="flex items-center gap-2 text-xs text-muted-foreground mt-4">
                <div className="flex items-center gap-1 px-2 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <Zap className="w-3 h-3" /> تنفيذ تلقائي
                </div>
                <span>= ينفذ الأوامر فوراً بدون مراجعة</span>
              </div>
            </motion.div>
          )}

          {messages.map((msg) => (
            <motion.div
              key={msg.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}
            >
              <div className={`max-w-[85%] rounded-2xl p-4 space-y-3 ${
                msg.role === "user"
                  ? "bg-violet-600/20 border border-violet-500/30"
                  : "bg-card border border-border"
              }`}>
                <div className="flex items-center gap-2 mb-1">
                  {msg.role === "assistant" ? (
                    <Bot className="w-4 h-4 text-violet-400 shrink-0" />
                  ) : (
                    <Terminal className="w-4 h-4 text-violet-300 shrink-0" />
                  )}
                  <span className="text-[10px] text-muted-foreground">
                    {msg.role === "user" ? "أنت" : "AI Agent"} · {msg.timestamp.toLocaleTimeString("ar-SA")}
                  </span>
                </div>

                <div className="text-sm whitespace-pre-wrap leading-relaxed">{msg.content}</div>
                {msg.attachments?.length ? (
                  <AttachmentChips attachments={msg.attachments} />
                ) : null}

                {msg.operations && msg.operations.length > 0 && (
                  <div className="space-y-2 pt-2 border-t border-white/10">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-white/60">
                        العمليات ({msg.operations.length})
                      </span>
                      {!msg.executedOps?.length && msg.operations.some(o => o.action !== "read") && (
                        <Button
                          size="sm"
                          onClick={() => handleApply(msg.operations!)}
                          disabled={applyMut.isPending}
                          className="gap-1.5 text-xs bg-emerald-600 hover:bg-emerald-700 text-white h-7"
                        >
                          {applyMut.isPending ? (
                            <><Loader2 className="w-3 h-3 animate-spin" /> تنفيذ...</>
                          ) : (
                            <><Play className="w-3 h-3" /> تطبيق الكل</>
                          )}
                        </Button>
                      )}
                    </div>
                    {msg.operations.map((op, i) => {
                      const exec = msg.executedOps?.[i];
                      return <OperationCard key={i} op={op} executed={exec} />;
                    })}
                  </div>
                )}
                {msg.steps?.length ? (
                  <AgentStepsPanel steps={msg.steps} />
                ) : null}
                {(msg.fixerLogs?.length || msg.fixerResults?.length) ? (
                  <FixerExecutionPanel
                    logs={msg.fixerLogs || []}
                    results={msg.fixerResults || []}
                  />
                ) : null}
              </div>
            </motion.div>
          ))}

          {(executeMut.isPending || fixerRunning) && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="flex justify-start"
            >
              <div className="bg-card border border-border rounded-2xl p-4 flex items-center gap-3">
                <Loader2 className="w-5 h-5 animate-spin text-violet-400" />
                <div>
                  <div className="text-sm font-medium">
                    {fixerRunning ? "جاري تشغيل المصلح الذكي..." : "جاري التحليل والتنفيذ..."}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {fixerRunning ? "فحص عميق + إصلاح تلقائي مع سجل تنفيذي" : "Claude يحلل الأمر ويجهز العمليات"}
                  </div>
                  {!fixerRunning ? (
                    <div className="mt-2">
                      <div className="h-1.5 rounded-full bg-white/10 overflow-hidden">
                        <div
                          className="h-full bg-violet-400 transition-all duration-500"
                          style={{ width: `${Math.max(10, liveProgress)}%` }}
                        />
                      </div>
                      <div className="text-[10px] text-muted-foreground mt-1">تقدم تنفيذي: {Math.max(10, liveProgress)}%</div>
                    </div>
                  ) : null}
                </div>
              </div>
            </motion.div>
          )}

          <div ref={chatEndRef} />
        </div>

        <div className="border-t border-border bg-card/50 backdrop-blur-xl p-4 rounded-b-2xl">
          <input
            ref={fileInputRef}
            type="file"
            multiple
            className="hidden"
            accept={ACCEPT_ALL_UPLOADS}
            onChange={(e) => {
              if (e.target.files) void handleFileSelect(e.target.files);
              e.currentTarget.value = "";
            }}
          />
          {pendingAttachments.length > 0 ? (
            <div className="mb-3">
              <AttachmentChips
                attachments={pendingAttachments}
                removable
                onRemove={removeAttachment}
              />
            </div>
          ) : null}
          <div className="flex items-end gap-3">
            <div className="flex gap-1 shrink-0">
              <Button
                type="button"
                variant="outline"
                onClick={() => fileInputRef.current?.click()}
                className="h-[48px] w-[48px] px-0"
                title="إضافة مرفقات"
              >
                <Plus className="w-4 h-4" />
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={() => fileInputRef.current?.click()}
                className="h-[48px] w-[48px] px-0"
                title="إرفاق ملف/صورة"
              >
                <Paperclip className="w-4 h-4" />
              </Button>
            </div>
            <div className="flex-1 relative">
              <textarea
                ref={inputRef}
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="اكتب أمراً تنفيذياً... مثل: أنشئ صفحة إعدادات جديدة"
                className="w-full bg-secondary/50 border border-border rounded-xl px-4 py-3 text-sm resize-none min-h-[48px] max-h-32 focus:outline-none focus:ring-2 focus:ring-violet-500/50 focus:border-violet-500/50"
                rows={1}
                dir="rtl"
              />
            </div>
            <Button
              onClick={handleSend}
              disabled={(!input.trim() && pendingAttachments.length === 0) || executeMut.isPending || fixerRunning}
              className="gap-2 bg-violet-600 hover:bg-violet-700 text-white shrink-0 h-[48px] px-5"
            >
              {(executeMut.isPending || fixerRunning) ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Send className="w-4 h-4" />
              )}
              أرسل
            </Button>
          </div>
          <div className="flex items-center justify-between mt-2">
            <div className="text-[10px] text-muted-foreground">
              Enter للإرسال · Shift+Enter لسطر جديد
            </div>
            <div className="text-[10px] text-muted-foreground flex items-center gap-1">
              <div className={`w-1.5 h-1.5 rounded-full ${autoExecute ? "bg-emerald-400" : "bg-amber-400"}`} />
              {autoExecute ? "التنفيذ التلقائي مفعّل — الأوامر تُنفذ فوراً" : "الوضع اليدوي — راجع العمليات قبل التنفيذ"}
            </div>
          </div>
          <div className="mt-2 text-[10px] text-muted-foreground">
            لأمر المصلح الذكي: <code className="font-mono">/fixer project --backend</code> أو <code className="font-mono">/fixer targeted --path=artifacts/hayo-ai/src/pages/ReverseEngineer.tsx</code>
          </div>
          <div className="mt-1 text-[10px] text-muted-foreground">
            يمكنك رفع أي ملف/صورة عبر زر <code className="font-mono">+</code> أو <code className="font-mono">📎</code> وسيستخدمها الوكيل كسياق تنفيذي.
          </div>
        </div>
          </div>
          <AgentExecutionInspector
            execution={activeExecution}
            inProgress={executeMut.isPending && !fixerRunning}
          />
        </div>
      </div>
    </div>
  );
}
