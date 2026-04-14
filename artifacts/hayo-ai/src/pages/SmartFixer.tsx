import DashboardLayout from "@/components/DashboardLayout";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { toast } from "sonner";
import {
  Wrench, Sparkles, AlertCircle, CheckCircle, AlertTriangle,
  Info, Zap, Code2, Play, TrendingUp, Loader2, RefreshCw,
  FileCode, ChevronRight, X, Activity, Shield, Hammer
} from "lucide-react";
import { useState, useMemo } from "react";
import { useTranslation } from "react-i18next";

// ── Interfaces ────────────────────────────────────────────────────────────────
interface Issue {
  id: string;
  file: string;
  line: number;
  severity: "critical" | "warning" | "info";
  message: string;
  suggestion: string;
  category: string;
}

interface ScanSummary {
  total: number;
  critical: number;
  warnings: number;
  info: number;
  scannedFiles: number;
}

interface DiagnosisResult {
  healthScore: number;
  issues: Issue[];
  recommendations: string[];
  buildStatus: "pass" | "fail" | "warning";
  summary: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function api(path: string, body: object) {
  return fetch(`/api/fixer${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body),
  }).then(async (r) => {
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || "فشل الطلب");
    return d;
  });
}

const SEV_CFG = {
  critical: { label: "حرج",      color: "text-red-400",    bg: "bg-red-500/15 border-red-500/30",    icon: AlertCircle },
  warning:  { label: "تحذير",    color: "text-orange-400", bg: "bg-orange-500/15 border-orange-500/30", icon: AlertTriangle },
  info:     { label: "معلومة",   color: "text-blue-400",   bg: "bg-blue-500/15 border-blue-500/30",  icon: Info },
} as const;

const CAT_ICONS: Record<string, React.ElementType> = {
  type: Code2,
  build: Hammer,
  performance: Zap,
  security: Shield,
  style: Sparkles,
  default: FileCode,
};

function SevBadge({ sev }: { sev: Issue["severity"] }) {
  const c = SEV_CFG[sev];
  const Icon = c.icon;
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] font-bold px-1.5 py-0.5 rounded border ${c.bg} ${c.color}`}>
      <Icon className="w-2.5 h-2.5" />{c.label}
    </span>
  );
}

function HealthRing({ score }: { score: number }) {
  const r = 28; const circ = 2 * Math.PI * r;
  const off = circ - (score / 100) * circ;
  const col = score >= 80 ? "#22c55e" : score >= 50 ? "#f59e0b" : "#ef4444";
  return (
    <svg width="72" height="72" viewBox="0 0 72 72">
      <circle cx="36" cy="36" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="7" />
      <circle cx="36" cy="36" r={r} fill="none" stroke={col} strokeWidth="7"
        strokeDasharray={circ} strokeDashoffset={off}
        strokeLinecap="round" transform="rotate(-90 36 36)" style={{ transition: "stroke-dashoffset 0.6s ease" }} />
      <text x="36" y="40" textAnchor="middle" fontSize="14" fontWeight="bold" fill={col}>{score}</text>
    </svg>
  );
}

// ── MAIN COMPONENT ────────────────────────────────────────────────────────────
export default function SmartFixer() {
  const { t } = useTranslation();

  // State
  const [issues, setIssues]               = useState<Issue[]>([]);
  const [summary, setSummary]             = useState<ScanSummary | null>(null);
  const [selIssue, setSelIssue]           = useState<Issue | null>(null);
  const [fixedIds, setFixedIds]           = useState<Set<string>>(new Set());
  const [diagnosis, setDiagnosis]         = useState<DiagnosisResult | null>(null);
  const [showDiag, setShowDiag]           = useState(false);
  const [buildOutput, setBuildOutput]     = useState<string>("");
  const [showBuild, setShowBuild]         = useState(false);

  // Loading flags
  const [scanning, setScanning]           = useState(false);
  const [fixingId, setFixingId]           = useState<string | null>(null);
  const [fixingAll, setFixingAll]         = useState(false);
  const [buildChecking, setBuildChecking] = useState(false);
  const [diagnosing, setDiagnosing]       = useState(false);

  // Filter
  const [sevFilter, setSevFilter] = useState<"all" | Issue["severity"]>("all");

  // Computed
  const visibleIssues = useMemo(() =>
    sevFilter === "all" ? issues : issues.filter(i => i.severity === sevFilter),
    [issues, sevFilter]
  );

  const statsCards = [
    { label: "إجمالي",    value: summary?.total ?? 0,    icon: Activity,       color: "text-primary",    bg: "from-primary/20 to-primary/5" },
    { label: "حرجة",      value: summary?.critical ?? 0, icon: AlertCircle,    color: "text-red-400",    bg: "from-red-500/20 to-red-500/5" },
    { label: "تحذيرات",   value: summary?.warnings ?? 0, icon: AlertTriangle,  color: "text-orange-400", bg: "from-orange-500/20 to-orange-500/5" },
    { label: "مُصلحة",    value: fixedIds.size,           icon: CheckCircle,    color: "text-emerald-400",bg: "from-emerald-500/20 to-emerald-500/5" },
  ];

  // ── Actions ─────────────────────────────────────────────────────────────────
  async function scanProject() {
    setScanning(true); setIssues([]); setSummary(null); setFixedIds(new Set());
    try {
      const d = await api("/scan", {});
      setIssues(d.issues || []);
      setSummary(d.summary);
      if (!d.issues?.length) toast.success("لا توجد مشكلات — المشروع نظيف!");
      else toast.info(`تم اكتشاف ${d.issues.length} مشكلة`);
    } catch (e: any) { toast.error(e.message); }
    finally { setScanning(false); }
  }

  async function fixIssue(issue: Issue) {
    setFixingId(issue.id);
    try {
      await api("/fix", { issueId: issue.id, file: issue.file, line: issue.line, message: issue.message, suggestion: issue.suggestion });
      setFixedIds(p => new Set([...p, issue.id]));
      toast.success(`تم إصلاح: ${issue.file}`);
      if (selIssue?.id === issue.id) setSelIssue(null);
    } catch (e: any) { toast.error(e.message); }
    finally { setFixingId(null); }
  }

  async function fixAll() {
    setFixingAll(true);
    try {
      const d = await api("/fix-all", { issues: issues.filter(i => !fixedIds.has(i.id)) });
      const ids = new Set([...fixedIds, ...(d.fixedIds || [])]);
      setFixedIds(ids);
      toast.success(`تم إصلاح ${d.fixed ?? 0} مشكلة`);
    } catch (e: any) { toast.error(e.message); }
    finally { setFixingAll(false); }
  }

  async function buildCheck() {
    setBuildChecking(true); setBuildOutput(""); setShowBuild(true);
    try {
      const d = await api("/build-check", {});
      setBuildOutput(d.output || "✅ لا أخطاء في البناء");
      toast.success(d.passed ? "البناء ناجح" : `${d.errorCount} خطأ في البناء`);
    } catch (e: any) { toast.error(e.message); setBuildOutput(e.message); }
    finally { setBuildChecking(false); }
  }

  async function runDiagnosis() {
    setDiagnosing(true); setShowDiag(true);
    try {
      const d = await api("/diagnose", {});
      setDiagnosis(d);
    } catch (e: any) { toast.error(e.message); setShowDiag(false); }
    finally { setDiagnosing(false); }
  }

  const unfixedCount = issues.filter(i => !fixedIds.has(i.id)).length;

  // ── Render ──────────────────────────────────────────────────────────────────
  return (
    <DashboardLayout>
      <div className="h-full flex flex-col gap-3 p-3 overflow-hidden" dir="rtl">

        {/* ── HEADER ── */}
        <div className="bg-card/70 backdrop-blur-sm border border-border rounded-2xl p-4 shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500/30 to-cyan-500/20 border border-emerald-500/30 flex items-center justify-center shrink-0">
              <Wrench className="w-5 h-5 text-emerald-400" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h1 className="text-lg font-bold">المصلح الذكي</h1>
                <span className="text-xs text-muted-foreground/70 font-normal">Smart Bug Fixer</span>
                <span className="text-[10px] px-2 py-0.5 bg-emerald-500/20 border border-emerald-500/30 text-emerald-300 rounded-full font-mono">Powered by Claude Opus 4.6</span>
              </div>
              <p className="text-xs text-muted-foreground mt-0.5">اكتشاف وإصلاح أخطاء المشروع تلقائياً باستخدام الذكاء الاصطناعي</p>
            </div>
            {/* Action bar */}
            <div className="flex items-center gap-2 shrink-0 flex-wrap justify-end">
              <Button size="sm" onClick={scanProject} disabled={scanning}
                className="gap-1.5 bg-primary/80 hover:bg-primary text-xs">
                {scanning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
                {scanning ? "جارٍ المسح…" : "مسح المشروع"}
              </Button>
              <Button size="sm" variant="outline" onClick={fixAll}
                disabled={fixingAll || unfixedCount === 0}
                className="gap-1.5 text-xs border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10">
                {fixingAll ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />}
                {fixingAll ? "إصلاح…" : `إصلاح الكل (${unfixedCount})`}
              </Button>
              <Button size="sm" variant="outline" onClick={buildCheck}
                disabled={buildChecking} className="gap-1.5 text-xs">
                {buildChecking ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                فحص البناء
              </Button>
              <Button size="sm" variant="outline" onClick={runDiagnosis}
                disabled={diagnosing} className="gap-1.5 text-xs border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10">
                {diagnosing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <TrendingUp className="w-3.5 h-3.5" />}
                تشخيص شامل
              </Button>
            </div>
          </div>
        </div>

        {/* ── STATS DASHBOARD ── */}
        <div className="grid grid-cols-4 gap-2 shrink-0">
          {statsCards.map((c, i) => {
            const Icon = c.icon;
            return (
              <div key={i} className={`bg-gradient-to-br ${c.bg} backdrop-blur-sm border border-border rounded-xl p-3 flex items-center gap-3`}>
                <div className={`w-8 h-8 rounded-lg bg-card/50 flex items-center justify-center shrink-0`}>
                  <Icon className={`w-4 h-4 ${c.color}`} />
                </div>
                <div>
                  <div className={`text-xl font-bold tabular-nums ${c.color}`}>{c.value}</div>
                  <div className="text-[10px] text-muted-foreground">{c.label}</div>
                </div>
              </div>
            );
          })}
        </div>

        {/* ── MAIN PANELS ── */}
        <div className="flex-1 min-h-0 flex gap-3">

          {/* ── LEFT: Issues List ── */}
          <div className="w-80 shrink-0 flex flex-col gap-2">
            {/* Filter tabs */}
            <div className="bg-card/70 backdrop-blur-sm border border-border rounded-xl p-1.5 flex gap-1 shrink-0">
              {(["all","critical","warning","info"] as const).map(f => (
                <button key={f} onClick={() => setSevFilter(f)}
                  className={`flex-1 text-[10px] font-medium py-1 rounded-lg transition-all ${
                    sevFilter === f
                      ? "bg-primary/20 text-primary border border-primary/30"
                      : "text-muted-foreground hover:text-foreground"
                  }`}>
                  {f === "all" ? "الكل" : SEV_CFG[f].label}
                </button>
              ))}
            </div>

            {/* List */}
            <div className="flex-1 min-h-0 bg-card/70 backdrop-blur-sm border border-border rounded-xl overflow-hidden flex flex-col">
              {scanning ? (
                <div className="flex-1 flex flex-col items-center justify-center gap-3 text-muted-foreground p-6">
                  <Loader2 className="w-8 h-8 animate-spin text-primary" />
                  <p className="text-sm">جارٍ مسح المشروع…</p>
                </div>
              ) : visibleIssues.length === 0 ? (
                <div className="flex-1 flex flex-col items-center justify-center gap-3 p-6 text-center">
                  <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-emerald-500/20 to-cyan-500/10 border border-emerald-500/20 flex items-center justify-center">
                    <Wrench className="w-6 h-6 text-emerald-400 opacity-60" />
                  </div>
                  <div>
                    <p className="text-sm font-semibold text-muted-foreground">
                      {issues.length === 0 ? "اضغط «مسح المشروع» للبدء" : "لا توجد مشكلات بهذا الفلتر"}
                    </p>
                    <p className="text-[11px] text-muted-foreground/50 mt-1">يستخدم Claude Opus 4.6 لتحليل الكود</p>
                  </div>
                </div>
              ) : (
                <div className="flex-1 overflow-y-auto divide-y divide-border/50">
                  {visibleIssues.map(issue => {
                    const isFixed = fixedIds.has(issue.id);
                    const isSel   = selIssue?.id === issue.id;
                    const CatIcon = CAT_ICONS[issue.category] ?? CAT_ICONS.default;
                    return (
                      <button key={issue.id} onClick={() => setSelIssue(isSel ? null : issue)}
                        className={`w-full text-right px-3 py-2.5 flex items-start gap-2.5 transition-all hover:bg-white/4 ${
                          isSel ? "bg-primary/8 border-r-2 border-primary" : ""
                        } ${isFixed ? "opacity-40" : ""}`}>
                        <CatIcon className="w-3.5 h-3.5 mt-0.5 text-muted-foreground shrink-0" />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-1.5 mb-0.5 flex-wrap">
                            <SevBadge sev={issue.severity} />
                            {isFixed && <span className="text-[9px] text-emerald-400 font-bold">✓ مُصلح</span>}
                          </div>
                          <p className="text-xs text-foreground/90 leading-snug line-clamp-2">{issue.message}</p>
                          <p className="text-[10px] text-muted-foreground/60 mt-0.5 font-mono truncate">
                            {issue.file}:{issue.line}
                          </p>
                        </div>
                        <ChevronRight className={`w-3 h-3 text-muted-foreground shrink-0 mt-1 transition-transform ${isSel ? "rotate-90" : ""}`} />
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          {/* ── RIGHT: Detail Panel ── */}
          <div className="flex-1 min-w-0 flex flex-col gap-2">
            {selIssue ? (
              <>
                {/* Detail header */}
                <div className="bg-card/70 backdrop-blur-sm border border-border rounded-xl p-4 shrink-0">
                  <div className="flex items-start gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-2 flex-wrap">
                        <SevBadge sev={selIssue.severity} />
                        <span className="text-[10px] px-1.5 py-0.5 bg-muted/30 rounded text-muted-foreground font-mono">{selIssue.category}</span>
                        {fixedIds.has(selIssue.id) && (
                          <span className="text-[10px] px-2 py-0.5 bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 rounded">✓ مُصلح</span>
                        )}
                      </div>
                      <h2 className="text-sm font-semibold leading-snug">{selIssue.message}</h2>
                      <p className="text-[11px] text-muted-foreground/70 mt-1 font-mono">
                        📄 {selIssue.file} — سطر {selIssue.line}
                      </p>
                    </div>
                    <button onClick={() => setSelIssue(null)} className="text-muted-foreground hover:text-foreground shrink-0">
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                {/* Suggestion */}
                <div className="bg-card/70 backdrop-blur-sm border border-emerald-500/20 rounded-xl p-4 flex-1 min-h-0 overflow-y-auto">
                  <div className="flex items-center gap-2 mb-3">
                    <Sparkles className="w-4 h-4 text-emerald-400" />
                    <span className="text-sm font-semibold text-emerald-300">اقتراح الإصلاح</span>
                    <span className="text-[10px] text-muted-foreground/50 mr-auto font-mono">Claude Opus 4.6</span>
                  </div>
                  <p className="text-sm leading-relaxed text-muted-foreground whitespace-pre-wrap">{selIssue.suggestion}</p>
                </div>

                {/* Fix button */}
                {!fixedIds.has(selIssue.id) && (
                  <Button onClick={() => fixIssue(selIssue)} disabled={!!fixingId}
                    className="w-full gap-2 bg-emerald-600/80 hover:bg-emerald-600 shrink-0">
                    {fixingId === selIssue.id
                      ? <><Loader2 className="w-4 h-4 animate-spin" />جارٍ الإصلاح…</>
                      : <><Zap className="w-4 h-4" />إصلاح هذه المشكلة</>}
                  </Button>
                )}
              </>
            ) : (
              <div className="flex-1 bg-card/70 backdrop-blur-sm border border-border rounded-xl flex flex-col items-center justify-center gap-4 p-8 text-center">
                <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-emerald-500/20 to-cyan-500/10 border border-emerald-500/20 flex items-center justify-center">
                  <Code2 className="w-8 h-8 text-emerald-400 opacity-60" />
                </div>
                <div>
                  <p className="text-sm font-semibold text-muted-foreground">اختر مشكلة من القائمة</p>
                  <p className="text-[11px] text-muted-foreground/50 mt-1">لعرض تفاصيل الخطأ واقتراح الإصلاح</p>
                </div>
                {issues.length === 0 && !scanning && (
                  <Button onClick={scanProject} size="sm" variant="outline" className="gap-1.5 text-xs mt-2">
                    <RefreshCw className="w-3.5 h-3.5" />ابدأ بمسح المشروع
                  </Button>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── DIAGNOSIS DIALOG ── */}
      <Dialog open={showDiag} onOpenChange={setShowDiag}>
        <DialogContent className="max-w-lg" dir="rtl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 flex-wrap">
              <TrendingUp className="w-5 h-5 text-cyan-400" />
              التشخيص الشامل
              <span className="text-[10px] px-2 py-0.5 bg-cyan-500/20 border border-cyan-500/30 text-cyan-300 rounded-full font-normal font-mono">مدعوم بـ Claude Opus 4.6</span>
            </DialogTitle>
          </DialogHeader>
          {diagnosing ? (
            <div className="flex flex-col items-center justify-center py-12 gap-3">
              <Loader2 className="w-8 h-8 animate-spin text-cyan-400" />
              <p className="text-sm text-muted-foreground">Claude Opus 4.6 يحلل المشروع…</p>
            </div>
          ) : diagnosis ? (
            <div className="space-y-4">
              {/* Health score */}
              <div className="flex items-center gap-4 p-4 bg-card/50 rounded-xl border border-border">
                <HealthRing score={diagnosis.healthScore} />
                <div className="flex-1">
                  <p className="font-bold text-lg">{diagnosis.healthScore}% صحة المشروع</p>
                  <p className="text-sm text-muted-foreground">{diagnosis.summary}</p>
                  <span className={`text-[11px] mt-1 inline-block font-mono px-2 py-0.5 rounded ${
                    diagnosis.buildStatus === "pass"
                      ? "bg-emerald-500/15 text-emerald-400"
                      : diagnosis.buildStatus === "fail"
                      ? "bg-red-500/15 text-red-400"
                      : "bg-orange-500/15 text-orange-400"
                  }`}>
                    Build: {diagnosis.buildStatus.toUpperCase()}
                  </span>
                </div>
              </div>
              {/* Recommendations */}
              {diagnosis.recommendations.length > 0 && (
                <div className="space-y-1.5">
                  <p className="text-xs font-semibold text-muted-foreground">التوصيات</p>
                  {diagnosis.recommendations.map((r, i) => (
                    <div key={i} className="text-xs p-2.5 bg-muted/20 rounded-lg border border-border text-right">
                      <span className="text-primary ml-2">{i + 1}.</span>{r}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : null}
        </DialogContent>
      </Dialog>

      {/* ── BUILD CHECK DIALOG ── */}
      <Dialog open={showBuild} onOpenChange={setShowBuild}>
        <DialogContent className="max-w-2xl" dir="rtl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Play className="w-5 h-5 text-cyan-400" />
              نتيجة فحص البناء
            </DialogTitle>
          </DialogHeader>
          {buildChecking ? (
            <div className="flex items-center justify-center py-10 gap-3">
              <Loader2 className="w-6 h-6 animate-spin text-cyan-400" />
              <p className="text-sm text-muted-foreground">جارٍ تشغيل TypeScript compiler…</p>
            </div>
          ) : (
            <pre className="bg-[#0d1117] rounded-xl p-4 text-xs font-mono text-emerald-300/80 max-h-96 overflow-y-auto whitespace-pre-wrap leading-relaxed">
              {buildOutput || "لا يوجد خرج"}
            </pre>
          )}
        </DialogContent>
      </Dialog>
    </DashboardLayout>
  );
}
