/**
 * HAYO AI — System Maintenance & Executive Agent Dashboard
 * Admin-only: health check, AI diagnosis, code repair, autonomous execution
 */
import { useState } from "react";
import { useAuth } from "@/_core/hooks/useAuth";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { toast } from "sonner";
import {
  Shield, Activity, AlertTriangle, CheckCircle2, XCircle, Loader2,
  Home, FileCode, Brain, Wrench, Search, Copy,
  Eye, Zap, Play, ChevronRight, Rocket, Crosshair,
  Smartphone, ScanSearch, MessageSquare, Bot, FileText,
  TrendingUp, BookOpen, Fingerprint, Moon, Send,
  Network, Settings, Lock, Link2, LayoutDashboard, CreditCard,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import LanguageSwitcher from "@/components/LanguageSwitcher";

type Tab = "health" | "scan" | "diagnose" | "fix" | "executive" | "targeted";

interface TargetedModule {
  id: string;
  label: string;
  icon: any;
  color: string;
  files: string[];
}

const TARGETED_MODULES: TargetedModule[] = [
  { id: "appbuilder", label: "منشئ التطبيقات", icon: Smartphone, color: "text-blue-400", files: ["artifacts/hayo-ai/src/pages/AppBuilder.tsx", "artifacts/api-server/src/hayo/services/eas-builder.ts"] },
  { id: "reverse", label: "الهندسة العكسية", icon: ScanSearch, color: "text-emerald-400", files: ["artifacts/hayo-ai/src/pages/ReverseEngineer.tsx", "artifacts/api-server/src/hayo/services/reverse-engineer.ts", "artifacts/api-server/src/routes/reverse.ts"] },
  { id: "chat", label: "الدردشة", icon: MessageSquare, color: "text-cyan-400", files: ["artifacts/hayo-ai/src/pages/Chat.tsx", "artifacts/api-server/src/hayo/providers.ts"] },
  { id: "codeagent", label: "وكيل الكود", icon: Bot, color: "text-violet-400", files: ["artifacts/hayo-ai/src/pages/CodeAgent.tsx", "artifacts/api-server/src/hayo/services/llm.ts"] },
  { id: "office", label: "أعمال مكتبية", icon: FileText, color: "text-orange-400", files: ["artifacts/hayo-ai/src/pages/OfficeSuite.tsx", "artifacts/api-server/src/routes/office.ts"] },
  { id: "trading", label: "التداول", icon: TrendingUp, color: "text-green-400", files: ["artifacts/hayo-ai/src/pages/TradingAnalysis.tsx", "artifacts/api-server/src/hayo/services/oanda.ts"] },
  { id: "studies", label: "الدراسات", icon: BookOpen, color: "text-pink-400", files: ["artifacts/hayo-ai/src/pages/Studies.tsx", "artifacts/api-server/src/routes/studies.ts"] },
  { id: "osint", label: "OSINT", icon: Fingerprint, color: "text-red-400", files: ["artifacts/hayo-ai/src/pages/OSINTTools.tsx", "artifacts/api-server/src/hayo/services/osint.ts"] },
  { id: "islam", label: "رسالة الإسلام", icon: Moon, color: "text-amber-400", files: ["artifacts/hayo-ai/src/pages/IslamMessage.tsx", "artifacts/api-server/src/hayo/services/islam.ts"] },
  { id: "telegram", label: "تيليجرام", icon: Send, color: "text-sky-400", files: ["artifacts/hayo-ai/src/pages/TelegramSetup.tsx", "artifacts/api-server/src/routes/telegram.ts"] },
  { id: "mindmap", label: "خريطة العقل", icon: Network, color: "text-indigo-400", files: ["artifacts/hayo-ai/src/pages/MindMap.tsx", "artifacts/api-server/src/hayo/services/mindmap.ts"] },
  { id: "router", label: "الموجّه الرئيسي", icon: Settings, color: "text-yellow-400", files: ["artifacts/api-server/src/hayo/router.ts"] },
  { id: "auth", label: "المصادقة والأمان", icon: Lock, color: "text-rose-400", files: ["artifacts/api-server/src/hayo/auth.ts", "artifacts/api-server/src/hayo/security.ts"] },
  { id: "routes-index", label: "فهرس المسارات", icon: Link2, color: "text-teal-400", files: ["artifacts/api-server/src/routes/index.ts"] },
  { id: "home", label: "الصفحة الرئيسية", icon: LayoutDashboard, color: "text-purple-400", files: ["artifacts/hayo-ai/src/pages/Home.tsx", "artifacts/hayo-ai/src/components/DashboardLayout.tsx"] },
  { id: "pricing", label: "التسعير والدفع", icon: CreditCard, color: "text-lime-400", files: ["artifacts/hayo-ai/src/pages/Pricing.tsx", "artifacts/api-server/src/hayo/services/payment.ts"] },
];

export default function SystemMaintenance() {
  const { user, isAuthenticated, loading } = useAuth();
  const [tab, setTab] = useState<Tab>("executive");

  const healthQ = trpc.maintenance.healthCheck.useQuery(undefined, { enabled: isAuthenticated && user?.role === "admin" });
  const structureQ = trpc.maintenance.projectStructure.useQuery(undefined, { enabled: isAuthenticated && user?.role === "admin" });

  const [scanResult, setScanResult] = useState<any>(null);
  const scanMut = trpc.maintenance.quickScan.useMutation({
    onSuccess: (data) => { setScanResult(data); toast.success(`فحص سريع: ${data.score}/100`); },
    onError: (e) => toast.error(e.message),
  });

  const [diagScope, setDiagScope] = useState<"all" | "frontend" | "backend" | "routes" | "services">("all");
  const [diagNote, setDiagNote] = useState("");
  const [diagResult, setDiagResult] = useState<any>(null);
  const diagMut = trpc.maintenance.aiDiagnose.useMutation({
    onSuccess: (data) => { setDiagResult(data); toast.success("تم التشخيص!"); },
    onError: (e) => toast.error(e.message),
  });

  const [fixFile, setFixFile] = useState("");
  const [fixProblem, setFixProblem] = useState("");
  const [fixResult, setFixResult] = useState<any>(null);
  const [autoApply, setAutoApply] = useState(true);
  const fixMut = trpc.maintenance.aiFix.useMutation({
    onSuccess: (data) => {
      setFixResult(data);
      toast.success(data.applied ? "✅ تم الإصلاح والحفظ تلقائياً!" : "✅ تم إنشاء الإصلاح");
    },
    onError: (e) => toast.error(e.message),
  });

  // Targeted fix
  const [targetedModule, setTargetedModule] = useState<string | null>(null);
  const [targetedResult, setTargetedResult] = useState<any>(null);
  const [targetedLoading, setTargetedLoading] = useState(false);

  const doTargetedFix = async (mod: TargetedModule) => {
    setTargetedModule(mod.id);
    setTargetedResult(null);
    setTargetedLoading(true);
    try {
      const results: any[] = [];
      for (const filePath of mod.files) {
        try {
          const r = await diagMut.mutateAsync({ scope: "all", userNote: `فحص ملف محدد: ${filePath} — ابحث عن أخطاء في الكود، مشاكل في الأنواع، استيرادات مفقودة، دوال غير معرّفة، أخطاء منطقية` });
          results.push({ file: filePath, report: r.report, fixes: r.fixes || [] });
        } catch (e: any) {
          results.push({ file: filePath, report: `خطأ: ${e.message}`, fixes: [] });
        }
      }
      setTargetedResult({ module: mod, results });
      const totalFixes = results.reduce((sum, r) => sum + r.fixes.length, 0);
      toast.success(`تم فحص ${mod.label}: ${totalFixes} مشكلة`);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setTargetedLoading(false);
    }
  };

  const applyAllTargetedFixes = async () => {
    if (!targetedResult) return;
    const allFixes = targetedResult.results.flatMap((r: any) => r.fixes.map((f: any) => ({ ...f, sourceFile: r.file })));
    if (allFixes.length === 0) { toast.info("لا توجد إصلاحات لتطبيقها"); return; }
    let applied = 0;
    for (const fix of allFixes) {
      try {
        await fixMut.mutateAsync({ filePath: fix.file || fix.sourceFile, problem: fix.description, autoApply: true });
        applied++;
      } catch { /* continue */ }
    }
    toast.success(`✅ تم تطبيق ${applied}/${allFixes.length} إصلاح`);
  };

  // Executive auto-execute
  const [execScope, setExecScope] = useState<"all" | "frontend" | "backend" | "services">("all");
  const [execResult, setExecResult] = useState<any>(null);
  const execMut = trpc.maintenance.autoExecute.useMutation({
    onSuccess: (data) => {
      setExecResult(data);
      toast.success(`🚀 تنفيذ مكتمل! ${data.phase3.applied} إصلاح مطبّق`);
    },
    onError: (e) => toast.error(e.message),
  });

  if (loading) return <div className="h-screen flex items-center justify-center bg-background"><Loader2 className="w-8 h-8 animate-spin text-primary" /></div>;
  if (!isAuthenticated || user?.role !== "admin") return (
    <div className="h-screen flex items-center justify-center bg-background p-4">
      <div className="bg-card border border-red-500/30 rounded-2xl p-8 max-w-md text-center space-y-4">
        <Shield className="w-16 h-16 mx-auto text-red-400 opacity-60" />
        <h2 className="text-2xl font-bold">وصول المسؤول فقط</h2>
        <p className="text-muted-foreground">هذه الصفحة متاحة للمالك فقط</p>
        <Button asChild><Link href="/">العودة</Link></Button>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-background text-foreground" dir="rtl">
      <header className="h-12 bg-card border-b border-border flex items-center justify-between px-4 sticky top-0 z-30">
        <div className="flex items-center gap-3">
          <Link href="/" className="text-muted-foreground hover:text-primary"><Home className="w-4 h-4" /></Link>
          <div className="w-px h-5 bg-border" />
          <Shield className="w-5 h-5 text-red-400" />
          <span className="font-bold text-sm">صيانة النظام</span>
          <span className="text-[9px] bg-red-500/10 text-red-400 px-2 py-0.5 rounded-full">Admin Only</span>
        </div>
        <LanguageSwitcher />
      </header>

      <div className="max-w-6xl mx-auto p-6 space-y-6">
        {/* Tabs */}
        <div className="flex gap-2 flex-wrap">
          {([
            { id: "executive" as Tab, label: "🚀 تنفيذي ذكي", icon: Rocket },
            { id: "targeted" as Tab, label: "🎯 إصلاح مخصص", icon: Crosshair },
            { id: "health" as Tab, label: "حالة النظام", icon: Activity },
            { id: "scan" as Tab, label: "فحص سريع", icon: Search },
            { id: "diagnose" as Tab, label: "تشخيص AI", icon: Brain },
            { id: "fix" as Tab, label: "إصلاح AI", icon: Wrench },
          ]).map(t => (
            <button key={t.id} onClick={() => setTab(t.id)} className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition-all ${tab === t.id ? "bg-primary/15 text-primary border border-primary/30" : "text-muted-foreground hover:bg-secondary/50 border border-transparent"} ${t.id === "executive" ? "border-amber-500/30 text-amber-400" : ""}`}>
              <t.icon className="w-4 h-4" /> {t.label}
            </button>
          ))}
        </div>

        {/* ═══ Executive Mode ═══ */}
        {tab === "executive" && (
          <div className="space-y-6">
            {/* Hero Card */}
            <div className="bg-gradient-to-br from-amber-500/10 via-orange-500/5 to-red-500/10 border border-amber-500/20 rounded-2xl p-6 space-y-4">
              <div className="flex items-start gap-4">
                <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-amber-500 to-orange-600 flex items-center justify-center shadow-lg">
                  <Rocket className="w-7 h-7 text-white" />
                </div>
                <div>
                  <h2 className="text-xl font-bold">المنفّذ التلقائي الذكي</h2>
                  <p className="text-sm text-muted-foreground mt-1">
                    يعمل كمهندس مستقل: يفحص المشروع → يشخّص المشاكل بـ AI → يُصلح ويحفظ الملفات تلقائياً مع نسخ احتياطية
                  </p>
                </div>
              </div>

              {/* Pipeline Steps */}
              <div className="flex items-center gap-2 text-xs text-muted-foreground overflow-x-auto py-1">
                {[
                  { icon: Search, label: "فحص هيكلي", color: "text-blue-400" },
                  { icon: ChevronRight, label: "", color: "" },
                  { icon: Brain, label: "تشخيص AI", color: "text-violet-400" },
                  { icon: ChevronRight, label: "", color: "" },
                  { icon: Wrench, label: "إصلاح تلقائي", color: "text-amber-400" },
                  { icon: ChevronRight, label: "", color: "" },
                  { icon: CheckCircle2, label: "نسخ احتياطية", color: "text-emerald-400" },
                ].map((step, i) => step.label ? (
                  <div key={i} className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-card border border-border ${step.color}`}>
                    <step.icon className="w-3.5 h-3.5" />
                    <span>{step.label}</span>
                  </div>
                ) : <step.icon key={i} className="w-4 h-4 text-muted-foreground/40 shrink-0" />)}
              </div>

              {/* Scope selector */}
              <div className="space-y-2">
                <label className="text-xs text-muted-foreground">نطاق التنفيذ:</label>
                <div className="flex gap-2 flex-wrap">
                  {([
                    { id: "all" as const, label: "🌐 كل المشروع" },
                    { id: "frontend" as const, label: "🖥️ الواجهة" },
                    { id: "backend" as const, label: "⚙️ الخلفية" },
                    { id: "services" as const, label: "🔧 الخدمات" },
                  ]).map(s => (
                    <button key={s.id} onClick={() => setExecScope(s.id)} className={`px-3 py-1.5 rounded-lg text-xs border transition-all ${execScope === s.id ? "bg-amber-500/15 border-amber-500 text-amber-400" : "border-border text-muted-foreground hover:border-amber-500/30"}`}>{s.label}</button>
                  ))}
                </div>
              </div>

              <Button
                onClick={() => execMut.mutate({ scope: execScope })}
                disabled={execMut.isPending}
                className="w-full py-6 gap-3 bg-gradient-to-r from-amber-500 to-orange-600 hover:from-amber-600 hover:to-orange-700 text-white font-bold text-base shadow-lg shadow-amber-500/20"
              >
                {execMut.isPending ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    المنفّذ يعمل... (قد يستغرق 2-4 دقائق)
                  </>
                ) : (
                  <>
                    <Rocket className="w-5 h-5" />
                    🚀 تشغيل المنفّذ التلقائي الشامل
                  </>
                )}
              </Button>
            </div>

            {/* Results */}
            {execResult && (
              <div className="space-y-4">
                {/* Summary Banner */}
                <div className={`rounded-2xl p-5 border ${execResult.phase3.applied > 0 ? "bg-emerald-500/10 border-emerald-500/30" : "bg-amber-500/10 border-amber-500/30"}`}>
                  <div className="flex items-center gap-3 mb-3">
                    <CheckCircle2 className={`w-6 h-6 ${execResult.phase3.applied > 0 ? "text-emerald-400" : "text-amber-400"}`} />
                    <h3 className="font-bold text-lg">
                      {execResult.phase3.applied > 0 ? `✅ تم تطبيق ${execResult.phase3.applied} إصلاح` : "⚠️ لا توجد إصلاحات مطلوبة"}
                    </h3>
                  </div>
                  <pre className="text-sm text-muted-foreground whitespace-pre-wrap leading-relaxed">{execResult.summary}</pre>
                </div>

                {/* Phase Cards */}
                <div className="grid md:grid-cols-3 gap-4">
                  <div className="bg-card border border-border rounded-xl p-4 space-y-2">
                    <div className="flex items-center gap-2">
                      <Search className="w-4 h-4 text-blue-400" />
                      <span className="text-sm font-bold">المرحلة 1 — الفحص</span>
                    </div>
                    <div className={`text-3xl font-bold ${execResult.phase1.score >= 80 ? "text-emerald-400" : execResult.phase1.score >= 50 ? "text-amber-400" : "text-red-400"}`}>{execResult.phase1.score}/100</div>
                    <p className="text-xs text-muted-foreground">{execResult.phase1.errors} أخطاء • {execResult.phase1.warnings} تحذيرات</p>
                  </div>
                  <div className="bg-card border border-border rounded-xl p-4 space-y-2">
                    <div className="flex items-center gap-2">
                      <Brain className="w-4 h-4 text-violet-400" />
                      <span className="text-sm font-bold">المرحلة 2 — التشخيص</span>
                    </div>
                    <div className="text-3xl font-bold text-violet-400">{execResult.phase2.fixesFound}</div>
                    <p className="text-xs text-muted-foreground">{execResult.phase2.filesAnalyzed} ملف فُحص</p>
                  </div>
                  <div className="bg-card border border-border rounded-xl p-4 space-y-2">
                    <div className="flex items-center gap-2">
                      <Wrench className="w-4 h-4 text-amber-400" />
                      <span className="text-sm font-bold">المرحلة 3 — التنفيذ</span>
                    </div>
                    <div className="text-3xl font-bold text-emerald-400">{execResult.phase3.applied}</div>
                    <p className="text-xs text-muted-foreground">{execResult.phase3.failed} فشل</p>
                  </div>
                </div>

                {/* AI Report */}
                <div className="bg-card border border-border rounded-xl p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="font-bold text-sm flex items-center gap-2"><Eye className="w-4 h-4 text-primary" /> تقرير التشخيص</h3>
                    <button onClick={() => { navigator.clipboard.writeText(execResult.phase2.report); toast.success("تم النسخ"); }} className="text-xs text-primary"><Copy className="w-3 h-3 inline mr-1" />نسخ</button>
                  </div>
                  <div className="text-sm text-muted-foreground whitespace-pre-wrap leading-relaxed max-h-52 overflow-y-auto">{execResult.phase2.report}</div>
                </div>

                {/* Fix Results */}
                {execResult.phase3.results.length > 0 && (
                  <div className="space-y-2">
                    <h3 className="font-bold text-sm">🔧 تفاصيل الإصلاحات:</h3>
                    {execResult.phase3.results.map((r: any, i: number) => (
                      <div key={i} className={`flex items-start gap-3 p-3 rounded-xl border text-xs ${r.success ? "bg-emerald-500/5 border-emerald-500/20" : "bg-red-500/5 border-red-500/20"}`}>
                        {r.success ? <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" /> : <XCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />}
                        <div>
                          <p className="font-mono font-bold">{r.file}</p>
                          <p className="text-muted-foreground mt-0.5">{r.explanation?.slice(0, 150)}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* ═══ Targeted Fix ═══ */}
        {tab === "targeted" && (
          <div className="space-y-6">
            <div className="bg-gradient-to-br from-primary/10 via-cyan-500/5 to-violet-500/10 border border-primary/20 rounded-2xl p-6 space-y-4">
              <div className="flex items-start gap-4">
                <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-primary to-cyan-600 flex items-center justify-center shadow-lg">
                  <Crosshair className="w-7 h-7 text-white" />
                </div>
                <div>
                  <h2 className="text-xl font-bold">إصلاح مخصص حسب الصفحة</h2>
                  <p className="text-sm text-muted-foreground mt-1">اختر أي صفحة من المنصة — AI يفحص ملفاتها ويعرض المشاكل مع إمكانية الإصلاح التلقائي</p>
                </div>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {TARGETED_MODULES.map(mod => (
                  <button
                    key={mod.id}
                    onClick={() => doTargetedFix(mod)}
                    disabled={targetedLoading}
                    className={`flex flex-col items-center gap-2 p-4 rounded-xl border transition-all hover:scale-[1.02] ${
                      targetedModule === mod.id && targetedLoading
                        ? "bg-primary/10 border-primary/40 animate-pulse"
                        : targetedModule === mod.id && targetedResult
                        ? "bg-emerald-500/10 border-emerald-500/30"
                        : "bg-card border-border hover:border-primary/30 hover:bg-primary/5"
                    }`}
                  >
                    {targetedModule === mod.id && targetedLoading ? (
                      <Loader2 className={`w-6 h-6 animate-spin ${mod.color}`} />
                    ) : (
                      <mod.icon className={`w-6 h-6 ${mod.color}`} />
                    )}
                    <span className="text-xs font-medium text-center">{mod.label}</span>
                    <span className="text-[9px] text-muted-foreground">{mod.files.length} ملف</span>
                  </button>
                ))}
              </div>
            </div>

            {targetedResult && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="font-bold text-lg flex items-center gap-2">
                    <targetedResult.module.icon className={`w-5 h-5 ${targetedResult.module.color}`} />
                    نتائج فحص: {targetedResult.module.label}
                  </h3>
                  {targetedResult.results.some((r: any) => r.fixes.length > 0) && (
                    <Button onClick={applyAllTargetedFixes} disabled={fixMut.isPending} className="gap-2 bg-gradient-to-r from-emerald-600 to-cyan-600">
                      {fixMut.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                      تطبيق كل الإصلاحات تلقائياً
                    </Button>
                  )}
                </div>

                {targetedResult.results.map((r: any, i: number) => (
                  <div key={i} className="bg-card border border-border rounded-xl p-4 space-y-3">
                    <div className="flex items-center gap-2">
                      <FileCode className="w-4 h-4 text-primary" />
                      <span className="font-mono text-sm font-bold text-primary">{r.file}</span>
                      <span className={`text-[10px] px-2 py-0.5 rounded-full border ${r.fixes.length > 0 ? "bg-amber-500/10 text-amber-400 border-amber-500/30" : "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"}`}>
                        {r.fixes.length > 0 ? `${r.fixes.length} مشكلة` : "سليم ✅"}
                      </span>
                    </div>
                    <div className="text-sm text-muted-foreground whitespace-pre-wrap leading-relaxed max-h-40 overflow-y-auto bg-secondary/20 rounded-lg p-3">{r.report}</div>
                    {r.fixes.length > 0 && (
                      <div className="space-y-2">
                        {r.fixes.map((fix: any, j: number) => (
                          <div key={j} className="flex items-start gap-2 p-2 rounded-lg bg-amber-500/5 border border-amber-500/10 text-xs">
                            <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                            <div>
                              <p className="font-medium">{fix.description}</p>
                              <p className="font-mono text-muted-foreground mt-0.5">{fix.file}</p>
                            </div>
                            <Button size="sm" onClick={() => { setFixFile(fix.file); setFixProblem(fix.description); setTab("fix"); }} className="text-[10px] h-6 px-2 mr-auto shrink-0">
                              <Play className="w-3 h-3" />
                            </Button>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ═══ Health ═══ */}
        {tab === "health" && (
          <div className="space-y-6">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {healthQ.data ? Object.entries(healthQ.data.checks).map(([name, check]: [string, any]) => (
                <div key={name} className={`bg-card border rounded-xl p-4 ${check.ok ? "border-emerald-500/20" : "border-red-500/20"}`}>
                  <div className="flex items-center gap-2 mb-2">
                    {check.ok ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <XCircle className="w-4 h-4 text-red-400" />}
                    <span className="text-sm font-bold capitalize">{name}</span>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    {name === "database" ? `${check.latency}ms` : name === "memory" ? `${check.latency} MB` : name === "uptime" ? `${Math.round(check.latency / 3600)}h` : check.ok ? "OK" : check.error}
                  </p>
                </div>
              )) : <div className="col-span-4 text-center text-muted-foreground text-sm py-8"><Loader2 className="w-6 h-6 animate-spin mx-auto mb-2" /> جاري الفحص...</div>}
            </div>

            {structureQ.data && (
              <div className="bg-card border border-border rounded-xl p-4 space-y-2">
                <h3 className="text-sm font-bold flex items-center gap-2"><FileCode className="w-4 h-4 text-primary" /> هيكل المشروع</h3>
                <div className="flex gap-4 text-xs text-muted-foreground">
                  <span>{structureQ.data.totalFiles} ملف</span>
                  <span>{structureQ.data.totalLines.toLocaleString()} سطر</span>
                </div>
                <details>
                  <summary className="text-xs text-primary cursor-pointer">عرض أكبر الملفات</summary>
                  <div className="mt-2 max-h-60 overflow-y-auto space-y-1">
                    {structureQ.data.files.slice(0, 30).map((f: any) => (
                      <div key={f.path} className="flex items-center justify-between text-[11px] py-1 border-b border-border/50">
                        <span className="font-mono text-muted-foreground truncate flex-1">{f.path}</span>
                        <span className="text-primary font-bold mr-2">{f.lines} سطر</span>
                      </div>
                    ))}
                  </div>
                </details>
              </div>
            )}
          </div>
        )}

        {/* ═══ Quick Scan ═══ */}
        {tab === "scan" && (
          <div className="space-y-6">
            <Button onClick={() => scanMut.mutate()} disabled={scanMut.isPending} className="w-full py-5 gap-2 bg-gradient-to-r from-blue-600 to-cyan-600">
              {scanMut.isPending ? <><Loader2 className="w-5 h-5 animate-spin" /> جاري الفحص السريع...</> : <><Search className="w-5 h-5" /> فحص سريع شامل (بدون AI)</>}
            </Button>

            {scanResult && (
              <div className="space-y-4">
                <div className="flex items-center gap-4">
                  <div className={`w-20 h-20 rounded-2xl flex items-center justify-center text-2xl font-bold ${scanResult.score >= 80 ? "bg-emerald-500/10 text-emerald-400" : scanResult.score >= 50 ? "bg-amber-500/10 text-amber-400" : "bg-red-500/10 text-red-400"}`}>
                    {scanResult.score}%
                  </div>
                  <div>
                    <h3 className="font-bold text-lg">{scanResult.overall === "healthy" ? "النظام سليم ✅" : scanResult.overall === "warnings" ? "تحذيرات ⚠️" : "مشاكل حرجة ❌"}</h3>
                    <p className="text-sm text-muted-foreground">{scanResult.scannedFiles} ملف — {scanResult.scannedLines.toLocaleString()} سطر</p>
                  </div>
                </div>

                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {scanResult.diagnostics.filter((d: any) => d.status !== "ok").map((d: any, i: number) => (
                    <div key={i} className={`flex items-start gap-3 p-3 rounded-xl border text-xs ${d.status === "error" ? "bg-red-500/5 border-red-500/20" : "bg-amber-500/5 border-amber-500/20"}`}>
                      {d.status === "error" ? <XCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" /> : <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />}
                      <div>
                        <p className="font-medium">[{d.category}] {d.message}</p>
                        {d.file && <p className="text-muted-foreground mt-0.5 font-mono">{d.file}{d.line ? `:${d.line}` : ""}</p>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ═══ AI Diagnose ═══ */}
        {tab === "diagnose" && (
          <div className="space-y-6">
            <div className="bg-card border border-border rounded-xl p-5 space-y-4">
              <h3 className="font-bold flex items-center gap-2"><Brain className="w-5 h-5 text-primary" /> تشخيص بالذكاء الاصطناعي</h3>
              <div className="space-y-2">
                <label className="text-sm text-muted-foreground">نطاق الفحص:</label>
                <div className="flex gap-2 flex-wrap">
                  {([
                    { id: "all" as const, label: "كل المشروع" },
                    { id: "frontend" as const, label: "الواجهة (Pages)" },
                    { id: "backend" as const, label: "الخلفية (Router)" },
                    { id: "routes" as const, label: "المسارات (Routes)" },
                    { id: "services" as const, label: "الخدمات (Services)" },
                  ]).map(s => (
                    <button key={s.id} onClick={() => setDiagScope(s.id)} className={`px-3 py-1.5 rounded-lg text-xs border ${diagScope === s.id ? "bg-primary/15 border-primary text-primary" : "border-border text-muted-foreground"}`}>{s.label}</button>
                  ))}
                </div>
              </div>
              <textarea value={diagNote} onChange={e => setDiagNote(e.target.value)} rows={3} placeholder="ملاحظات إضافية... (اختياري)" className="w-full bg-secondary/50 border border-border rounded-xl px-4 py-3 text-sm resize-none" />
              <Button onClick={() => diagMut.mutate({ scope: diagScope, userNote: diagNote || undefined })} disabled={diagMut.isPending} className="w-full py-5 gap-2 bg-gradient-to-r from-violet-600 to-purple-600">
                {diagMut.isPending ? <><Loader2 className="w-5 h-5 animate-spin" /> AI يشخّص...</> : <><Brain className="w-5 h-5" /> تشخيص شامل بـ AI</>}
              </Button>
            </div>

            {diagResult && (
              <div className="space-y-4">
                <div className="bg-card border border-border rounded-xl p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="font-bold text-sm">📋 تقرير التشخيص</h3>
                    <button onClick={() => { navigator.clipboard.writeText(diagResult.report); toast.success("تم النسخ"); }} className="text-xs text-primary"><Copy className="w-3 h-3 inline mr-1" />نسخ</button>
                  </div>
                  <div className="text-sm text-muted-foreground whitespace-pre-wrap leading-relaxed max-h-60 overflow-y-auto">{diagResult.report}</div>
                </div>

                {diagResult.fixes?.length > 0 && (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="font-bold text-sm">🔧 الإصلاحات المقترحة ({diagResult.fixes.length}):</h3>
                      <Button
                        size="sm"
                        onClick={() => {
                          const fixList = diagResult.fixes.map((f: any) => ({ file: f.file, problem: f.description }));
                          toast.info("انتقل إلى تبويب الإصلاح لتطبيق كل إصلاح");
                        }}
                        className="text-xs gap-1 bg-amber-500/20 text-amber-400 hover:bg-amber-500/30"
                      >
                        <Zap className="w-3 h-3" /> تطبيق الكل عبر المنفّذ
                      </Button>
                    </div>
                    {diagResult.fixes.map((fix: any, i: number) => (
                      <div key={i} className="bg-card border border-border rounded-xl p-4 space-y-2">
                        <div className="flex items-center justify-between">
                          <p className="text-sm font-bold font-mono text-primary">{fix.file}</p>
                          <Button size="sm" onClick={() => { setFixFile(fix.file); setFixProblem(fix.description); setTab("fix"); }} className="text-xs gap-1 h-7">
                            <Play className="w-3 h-3" /> إصلاح
                          </Button>
                        </div>
                        <p className="text-xs text-muted-foreground">{fix.description}</p>
                        {fix.code && <pre className="bg-black/20 rounded-lg p-3 text-xs font-mono overflow-x-auto max-h-40" dir="ltr">{fix.code}</pre>}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* ═══ AI Fix ═══ */}
        {tab === "fix" && (
          <div className="space-y-6">
            <div className="bg-card border border-border rounded-xl p-5 space-y-4">
              <h3 className="font-bold flex items-center gap-2"><Wrench className="w-5 h-5 text-amber-400" /> إصلاح فوري بـ AI</h3>

              <div className="space-y-2">
                <label className="text-sm text-muted-foreground">الملف المطلوب إصلاحه:</label>
                {structureQ.data ? (
                  <select value={fixFile} onChange={e => setFixFile(e.target.value)} className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm font-mono" dir="ltr">
                    <option value="">اختر ملف...</option>
                    {structureQ.data.files.map((f: any) => (
                      <option key={f.path} value={f.path}>{f.path} ({f.lines} سطر)</option>
                    ))}
                  </select>
                ) : (
                  <input value={fixFile} onChange={e => setFixFile(e.target.value)} placeholder="src/pages/Chat.tsx" className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-sm font-mono" dir="ltr" />
                )}
              </div>

              <div className="space-y-2">
                <label className="text-sm text-muted-foreground">وصف المشكلة:</label>
                <textarea value={fixProblem} onChange={e => setFixProblem(e.target.value)} rows={4} placeholder="مثال: زر الإرسال لا يعمل..." className="w-full bg-secondary/50 border border-border rounded-xl px-4 py-3 text-sm resize-none" />
              </div>

              <div className="flex items-center justify-between bg-secondary/30 rounded-xl p-3 border border-border">
                <div>
                  <p className="text-sm font-medium">حفظ تلقائي بعد الإصلاح</p>
                  <p className="text-[10px] text-muted-foreground">AI يعدّل الملف مباشرة مع نسخة احتياطية تلقائية</p>
                </div>
                <button onClick={() => setAutoApply(!autoApply)} className={`w-12 h-6 rounded-full transition-all ${autoApply ? "bg-emerald-500" : "bg-secondary"}`}>
                  <div className={`w-5 h-5 bg-white rounded-full shadow transition-transform ${autoApply ? "translate-x-6" : "translate-x-0.5"}`} />
                </button>
              </div>

              <Button onClick={() => fixMut.mutate({ filePath: fixFile, problem: fixProblem, autoApply })} disabled={fixMut.isPending || !fixFile || !fixProblem.trim()} className="w-full py-5 gap-2 bg-gradient-to-r from-amber-600 to-red-600">
                {fixMut.isPending ? <><Loader2 className="w-5 h-5 animate-spin" /> AI يصلح الكود...</> : <><Wrench className="w-5 h-5" /> إصلاح فوري بـ AI</>}
              </Button>
            </div>

            {fixResult && (
              <div className="space-y-4">
                {fixResult.applied && (
                  <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-4 flex items-center gap-3">
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    <div>
                      <p className="text-sm font-bold text-emerald-400">تم الحفظ تلقائياً ✅</p>
                      {fixResult.backupPath && <p className="text-[10px] text-muted-foreground font-mono">نسخة احتياطية: {fixResult.backupPath}</p>}
                    </div>
                  </div>
                )}
                <div className="bg-card border border-border rounded-xl p-4">
                  <h3 className="font-bold text-sm mb-2">📝 شرح الإصلاح:</h3>
                  <p className="text-sm text-muted-foreground whitespace-pre-wrap">{fixResult.explanation}</p>
                </div>
                <div className="bg-card border border-border rounded-xl overflow-hidden">
                  <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-secondary/30">
                    <span className="text-xs font-mono text-muted-foreground">{fixFile}</span>
                    <button onClick={() => { navigator.clipboard.writeText(fixResult.fixedCode); toast.success("تم نسخ الكود"); }} className="text-xs text-primary"><Copy className="w-3 h-3 inline mr-1" />نسخ</button>
                  </div>
                  <pre className="p-4 text-xs font-mono overflow-x-auto max-h-[400px] text-foreground/80 whitespace-pre" dir="ltr">{fixResult.fixedCode}</pre>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
