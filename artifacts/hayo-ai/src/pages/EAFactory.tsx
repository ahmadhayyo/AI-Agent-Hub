/**
 * HAYO AI — EA Factory (MQ4/MQ5 Dream Engine)
 * Upload 100 files → AI deep analysis → 10-30 strategies → select multiple → massive combined code
 */
import { useState, useRef, useCallback } from "react";
import { useAuth } from "@/_core/hooks/useAuth";
import { getLoginUrl } from "@/const";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { toast } from "sonner";
import {
  Upload, Download, Loader2, CheckCircle2, Code2, Zap, Brain,
  Home, Copy, X, FileCode, ChevronDown, ChevronUp, Eye, EyeOff,
  Sparkles, RefreshCw, Cpu, MessageSquare,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import LanguageSwitcher from "@/components/LanguageSwitcher";

interface UploadedFile { name: string; content: string; }
interface AnalyzedFile { name: string; type: string; platform: string; signals: string[]; indicators: string[]; logic: string; strengths: string[]; weaknesses: string[]; parameters: string[]; codePatterns: string[]; compatibleWith: string[]; }
interface Strategy { id: string; name: string; description: string; category: string; filesUsed: string[]; indicators: string[]; filters: string[]; entryLogic: string; exitLogic: string; riskManagement: string; timeframe: string; confidence: number; complexity: string; }
type Platform = "mq4" | "mq5";
type OutputType = "ea" | "indicator";
type Step = "upload" | "analyzing" | "strategies" | "generating" | "result";

const CATEGORY_LABELS: Record<string, { label: string; icon: string; color: string }> = {
  trend: { label: "متابعة اتجاه", icon: "📈", color: "text-emerald-400" },
  reversal: { label: "ارتداد", icon: "🔄", color: "text-blue-400" },
  breakout: { label: "كسر", icon: "💥", color: "text-red-400" },
  scalping: { label: "سكالبنغ", icon: "⚡", color: "text-yellow-400" },
  swing: { label: "سوينغ", icon: "🌊", color: "text-cyan-400" },
  mtf: { label: "متعدد الفريمات", icon: "📊", color: "text-violet-400" },
  filter: { label: "فلتر ذكي", icon: "🛡️", color: "text-amber-400" },
  hybrid: { label: "هجين", icon: "🧬", color: "text-pink-400" },
  custom_indicator: { label: "مؤشر مخصص", icon: "🔧", color: "text-indigo-400" },
  risk: { label: "إدارة مخاطر", icon: "⚖️", color: "text-orange-400" },
};

export default function EAFactory() {
  const { isAuthenticated, loading: authLoading } = useAuth();
  const [step, setStep] = useState<Step>("upload");
  const [files, setFiles] = useState<UploadedFile[]>([]);
  const [userNotes, setUserNotes] = useState("");
  const [analyzedFiles, setAnalyzedFiles] = useState<AnalyzedFile[]>([]);
  const [strategies, setStrategies] = useState<Strategy[]>([]);
  const [summary, setSummary] = useState("");
  const [totalIndicators, setTotalIndicators] = useState<string[]>([]);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [platform, setPlatform] = useState<Platform>("mq4");
  const [outputType, setOutputType] = useState<OutputType>("ea");
  const [generatedCode, setGeneratedCode] = useState("");
  const [codeAnalysis, setCodeAnalysis] = useState("");
  const [customPrompt, setCustomPrompt] = useState("");
  const [generateNotes, setGenerateNotes] = useState("");
  const [expandedFile, setExpandedFile] = useState<string | null>(null);
  const [showCode, setShowCode] = useState(true);
  const [filterCategory, setFilterCategory] = useState("all");
  const [compileErrors, setCompileErrors] = useState("");
  const [showFixPanel, setShowFixPanel] = useState(false);
  const [fixNotes, setFixNotes] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);

  const analyzeMut = trpc.eaFactory.analyze.useMutation();
  const generateMut = trpc.eaFactory.generate.useMutation();
  const customMut = trpc.eaFactory.generateCustom.useMutation();
  const fixErrorsMut = trpc.eaFactory.fixErrors.useMutation();

  const handleFiles = useCallback(async (fileList: FileList) => {
    const newFiles: UploadedFile[] = [];
    for (const file of Array.from(fileList)) {
      const ext = file.name.split(".").pop()?.toLowerCase() || "";
      if (!["mq4","mq5","mqh"].includes(ext)) { toast.error(`${file.name} — صيغة غير مدعومة (mq4/mq5/mqh فقط)`); continue; }
      newFiles.push({ name: file.name, content: await file.text() });
    }
    if (newFiles.length > 0) { setFiles(prev => [...prev, ...newFiles]); toast.success(`تم رفع ${newFiles.length} ملف`); }
  }, []);

  const handleAnalyze = async () => {
    if (files.length === 0) { toast.error("ارفع ملفات أولاً"); return; }
    setStep("analyzing");
    try {
      const result = await analyzeMut.mutateAsync({ files, userNotes: userNotes || undefined });
      setAnalyzedFiles(result.analyzedFiles);
      setStrategies(result.proposedStrategies);
      setSummary(result.summary);
      setTotalIndicators(result.totalIndicators);
      setStep("strategies");
      toast.success(`✅ ${result.analyzedFiles.length} ملف محلّل → ${result.proposedStrategies.length} استراتيجية مقترحة!`);
    } catch (err: any) { toast.error(`فشل: ${err.message}`); setStep("upload"); }
  };

  const toggleStrategy = (id: string) => {
    setSelectedIds(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });
  };

  const selectAll = () => setSelectedIds(new Set(filteredStrategies.map(s => s.id)));
  const deselectAll = () => setSelectedIds(new Set());

  const handleGenerate = async () => {
    const selected = strategies.filter(s => selectedIds.has(s.id));
    if (selected.length === 0) { toast.error("اختر استراتيجية واحدة على الأقل"); return; }
    setStep("generating");
    try {
      const result = await generateMut.mutateAsync({ strategies: selected, sourceFiles: files, platform, outputType, userNotes: generateNotes || undefined });
      setGeneratedCode(result.code);
      setCodeAnalysis(result.analysis);
      setStep("result");
      toast.success(`✅ تم إنشاء كود يدمج ${selected.length} استراتيجية! (${result.code.split("\n").length} سطر)`);
    } catch (err: any) { toast.error(`فشل: ${err.message}`); setStep("strategies"); }
  };

  const handleCustomGenerate = async () => {
    if (!customPrompt.trim()) { toast.error("اكتب وصف الاستراتيجية"); return; }
    setStep("generating");
    try {
      const result = await customMut.mutateAsync({ prompt: customPrompt, sourceFiles: files, platform, outputType, userNotes: generateNotes || undefined });
      setGeneratedCode(result.code);
      setCodeAnalysis(result.analysis);
      setStep("result");
      toast.success("✅ تم إنشاء الكود!");
    } catch (err: any) { toast.error(`فشل: ${err.message}`); setStep("strategies"); }
  };

  const handleCopy = () => { navigator.clipboard.writeText(generatedCode); toast.success("تم النسخ ✅ — الصقه في MetaEditor"); };

  const handleFixErrors = async () => {
    if (!compileErrors.trim()) { toast.error("الصق أخطاء التجميع من MetaEditor"); return; }
    toast.info("🔧 AI يصلح أخطاء التجميع...");
    try {
      const result = await fixErrorsMut.mutateAsync({
        code: generatedCode,
        errors: compileErrors,
        platform,
        outputType,
        userNotes: fixNotes || undefined,
      });
      setGeneratedCode(result.code);
      setCodeAnalysis(result.analysis);
      setCompileErrors("");
      setShowFixPanel(false);
      toast.success(`✅ تم إصلاح ${result.fixes.length} خطأ! جرّب التجميع مرة أخرى`);
    } catch (err: any) {
      toast.error(`فشل الإصلاح: ${err.message}`);
    }
  };
  const handleDownload = () => {
    const blob = new Blob([generatedCode], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = `HAYO_Strategy.${platform}`; a.click();
    URL.revokeObjectURL(url);
  };
  const handleReset = () => { setStep("upload"); setFiles([]); setAnalyzedFiles([]); setStrategies([]); setSummary(""); setSelectedIds(new Set()); setGeneratedCode(""); setCustomPrompt(""); setGenerateNotes(""); setUserNotes(""); };

  const categories = [...new Set(strategies.map(s => s.category))];
  const filteredStrategies = filterCategory === "all" ? strategies : strategies.filter(s => s.category === filterCategory);

  if (authLoading) return <div className="h-screen flex items-center justify-center bg-background"><Loader2 className="w-8 h-8 animate-spin text-primary" /></div>;
  if (!isAuthenticated) return (
    <div className="h-screen flex items-center justify-center bg-background p-4">
      <div className="bg-card border border-border rounded-2xl p-8 max-w-md w-full text-center space-y-4">
        <Cpu className="w-16 h-16 mx-auto text-primary opacity-60" />
        <h2 className="text-2xl font-bold">EA Factory</h2>
        <Button asChild className="w-full"><a href={getLoginUrl()}>تسجيل الدخول</a></Button>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-background text-foreground" dir="rtl">
      <header className="h-12 bg-card border-b border-border flex items-center justify-between px-4 sticky top-0 z-30">
        <div className="flex items-center gap-3">
          <Link href="/" className="text-muted-foreground hover:text-primary"><Home className="w-4 h-4" /></Link>
          <div className="w-px h-5 bg-border" />
          <Cpu className="w-5 h-5 text-primary" />
          <span className="font-bold text-sm">EA Factory</span>
          <span className="text-[9px] bg-primary/10 text-primary px-2 py-0.5 rounded-full">Dream Engine</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex bg-secondary/50 rounded-lg p-0.5">
            {(["mq4","mq5"] as const).map(p => (
              <button key={p} onClick={() => setPlatform(p)} className={`px-3 py-1 rounded-md text-xs font-bold ${platform===p?"bg-primary text-white shadow":"text-muted-foreground"}`}>{p.toUpperCase()}</button>
            ))}
          </div>
          <div className="flex bg-secondary/50 rounded-lg p-0.5">
            {([{id:"ea" as OutputType,label:"🤖 EA"},{id:"indicator" as OutputType,label:"📊 Indicator"}]).map(t => (
              <button key={t.id} onClick={() => setOutputType(t.id)} className={`px-3 py-1 rounded-md text-xs font-bold ${outputType===t.id?"bg-primary text-white shadow":"text-muted-foreground"}`}>{t.label}</button>
            ))}
          </div>
        </div>
      </header>

      <div className="max-w-6xl mx-auto p-6 space-y-6">
        {/* Steps */}
        <div className="flex items-center justify-center gap-1 text-xs flex-wrap">
          {[{key:"upload",label:"رفع",icon:"📁"},{key:"analyzing",label:"تحليل",icon:"🧠"},{key:"strategies",label:"استراتيجيات",icon:"⚡"},{key:"generating",label:"توليد",icon:"⚙️"},{key:"result",label:"النتيجة",icon:"✅"}].map((s,i) => {
            const steps: Step[] = ["upload","analyzing","strategies","generating","result"];
            const active = steps.indexOf(step) >= steps.indexOf(s.key as Step);
            return (<div key={s.key} className="flex items-center gap-1">{i>0&&<div className={`w-6 h-0.5 ${active?"bg-primary":"bg-border"}`}/>}<div className={`flex items-center gap-1 px-2 py-1 rounded-full ${active?"bg-primary/15 text-primary":"text-muted-foreground/40"}`}><span>{s.icon}</span><span className="hidden sm:inline">{s.label}</span></div></div>);
          })}
        </div>

        {/* ═══ UPLOAD ═══ */}
        {step === "upload" && (
          <div className="space-y-6">
            <div className="text-center space-y-3 py-4">
              <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-primary/10"><Cpu className="w-8 h-8 text-primary" /></div>
              <h1 className="text-2xl font-bold">مصنع الاستراتيجيات — Dream Engine</h1>
              <p className="text-muted-foreground max-w-2xl mx-auto">ارفع حتى 100 ملف MQ4/MQ5 → AI يحلل كل ملف بعمق → يقترح 10-30+ استراتيجية → اختر ما تريد → كود ضخم يدمج كل شيء</p>
            </div>
            <div onDragOver={e=>e.preventDefault()} onDrop={e=>{e.preventDefault();handleFiles(e.dataTransfer.files)}} onClick={()=>fileRef.current?.click()} className="border-2 border-dashed border-border hover:border-primary/60 rounded-2xl p-10 text-center cursor-pointer bg-secondary/10 hover:bg-secondary/20 transition-all">
              <input ref={fileRef} type="file" multiple accept=".mq4,.mq5,.mqh" className="hidden" onChange={e=>e.target.files&&handleFiles(e.target.files)} />
              <Upload className="w-12 h-12 mx-auto text-muted-foreground mb-3" />
              <p className="font-bold text-lg">اسحب ملفات MQ4/MQ5 هنا</p>
              <p className="text-sm text-muted-foreground mt-1">.mq4, .mq5, .mqh — حتى 100 ملف</p>
            </div>
            {files.length > 0 && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold flex items-center gap-2"><FileCode className="w-4 h-4 text-primary" /> {files.length} ملف</h3>
                  <Button variant="ghost" size="sm" className="text-xs text-red-400" onClick={()=>setFiles([])}>مسح الكل</Button>
                </div>
                <div className="grid grid-cols-3 sm:grid-cols-4 lg:grid-cols-6 gap-2">
                  {files.map(f => (
                    <div key={f.name} className="bg-card border border-border rounded-lg p-2 flex items-center gap-1.5 group text-xs">
                      <span>{f.name.endsWith(".mq5")?"🔵":"🟡"}</span>
                      <span className="font-mono truncate flex-1">{f.name}</span>
                      <button onClick={()=>setFiles(prev=>prev.filter(x=>x.name!==f.name))} className="opacity-0 group-hover:opacity-100 text-red-400"><X className="w-3 h-3" /></button>
                    </div>
                  ))}
                </div>
                {/* User Notes */}
                <div className="space-y-2">
                  <label className="text-sm font-bold flex items-center gap-2"><MessageSquare className="w-4 h-4 text-primary" /> ملاحظاتك لـ AI <span className="text-xs text-muted-foreground font-normal">(اختياري — ما تريد أن يركز عليه)</span></label>
                  <textarea value={userNotes} onChange={e=>setUserNotes(e.target.value)} rows={3} placeholder="مثال: أريد استراتيجيات للذهب فقط... ركّز على RSI + MACD... أريد سكالبنغ على فريم 5 دقائق... لا تستخدم Bollinger..." className="w-full bg-secondary/50 border border-border rounded-xl px-4 py-3 text-sm resize-none focus:ring-2 focus:ring-primary/50" />
                </div>
                <Button onClick={handleAnalyze} disabled={analyzeMut.isPending} className="w-full py-5 text-base gap-2 bg-gradient-to-r from-primary to-violet-600">
                  {analyzeMut.isPending ? <><Loader2 className="w-5 h-5 animate-spin" /> AI يحلل {files.length} ملف بعمق...</> : <><Brain className="w-5 h-5" /> تحليل عميق وإنشاء استراتيجيات ({files.length} ملف)</>}
                </Button>
              </div>
            )}
          </div>
        )}

        {/* ═══ ANALYZING ═══ */}
        {step === "analyzing" && (
          <div className="max-w-md mx-auto text-center py-12 space-y-6">
            <div className="relative mx-auto w-24 h-24"><div className="absolute inset-0 rounded-full bg-primary/10 animate-ping" style={{animationDuration:"2s"}}/><div className="relative w-24 h-24 rounded-full bg-primary/20 flex items-center justify-center"><Brain className="w-12 h-12 text-primary" /></div></div>
            <h2 className="text-xl font-bold">AI يحلل {files.length} ملف...</h2>
            <div className="space-y-2 text-sm text-muted-foreground">
              <p>📂 تحليل كل ملف على حدة (دفعات 15 ملف)</p>
              <p>🧠 فهم المنطق والمؤشرات والإشارات</p>
              <p>🔗 تحليل تقاطعي لاقتراح 10-30+ استراتيجية</p>
              <p>⚡ إنشاء استراتيجيات مبتكرة تدمج أفضل العناصر</p>
            </div>
          </div>
        )}

        {/* ═══ STRATEGIES ═══ */}
        {step === "strategies" && (
          <div className="space-y-6">
            <div className="bg-gradient-to-r from-primary/10 to-violet-500/10 border border-primary/20 rounded-2xl p-5">
              <h2 className="font-bold text-lg mb-2 flex items-center gap-2"><Sparkles className="w-5 h-5 text-primary" /> نتائج التحليل العميق</h2>
              <p className="text-sm text-muted-foreground leading-relaxed">{summary}</p>
              <div className="flex flex-wrap gap-2 mt-3 text-xs">
                <span className="bg-primary/10 text-primary px-3 py-1 rounded-full">{analyzedFiles.length} ملف</span>
                <span className="bg-emerald-500/10 text-emerald-400 px-3 py-1 rounded-full">{strategies.length} استراتيجية</span>
                <span className="bg-violet-500/10 text-violet-400 px-3 py-1 rounded-full">{totalIndicators.length} مؤشر</span>
                <span className="bg-amber-500/10 text-amber-400 px-3 py-1 rounded-full">{selectedIds.size} مختارة</span>
              </div>
            </div>

            {/* Analyzed Files */}
            <details className="bg-card border border-border rounded-xl">
              <summary className="px-4 py-3 text-sm font-bold cursor-pointer hover:bg-secondary/20 flex items-center gap-2"><FileCode className="w-4 h-4 text-primary" /> الملفات المحلّلة ({analyzedFiles.length})</summary>
              <div className="px-4 pb-3 space-y-1 max-h-60 overflow-y-auto">
                {analyzedFiles.map(f => (
                  <div key={f.name} className="text-xs bg-muted/20 rounded-lg p-2 flex items-center gap-2">
                    <span>{f.platform==="mq5"?"🔵":"🟡"}</span>
                    <span className="font-mono font-bold">{f.name}</span>
                    <span className="text-muted-foreground">[{f.type}]</span>
                    <span className="text-primary mr-auto">{f.indicators.join(", ")}</span>
                  </div>
                ))}
              </div>
            </details>

            {/* Category Filter + Select All */}
            <div className="flex items-center gap-2 flex-wrap">
              <button onClick={()=>setFilterCategory("all")} className={`px-3 py-1.5 rounded-lg text-xs border ${filterCategory==="all"?"bg-primary/15 border-primary text-primary":"border-border text-muted-foreground"}`}>الكل ({strategies.length})</button>
              {categories.map(cat => {
                const info = CATEGORY_LABELS[cat] || { label: cat, icon: "📋", color: "text-gray-400" };
                const count = strategies.filter(s=>s.category===cat).length;
                return (<button key={cat} onClick={()=>setFilterCategory(cat)} className={`px-3 py-1.5 rounded-lg text-xs border flex items-center gap-1 ${filterCategory===cat?"bg-primary/15 border-primary text-primary":"border-border text-muted-foreground"}`}>{info.icon} {info.label} ({count})</button>);
              })}
              <div className="mr-auto flex gap-2">
                <Button variant="outline" size="sm" className="text-[10px] h-7" onClick={selectAll}>تحديد الكل</Button>
                <Button variant="outline" size="sm" className="text-[10px] h-7" onClick={deselectAll}>إلغاء الكل</Button>
              </div>
            </div>

            {/* Strategy Cards */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
              {filteredStrategies.map(s => {
                const sel = selectedIds.has(s.id);
                const info = CATEGORY_LABELS[s.category] || { label: s.category, icon: "📋", color: "text-gray-400" };
                return (
                  <div key={s.id} onClick={()=>toggleStrategy(s.id)} className={`bg-card border rounded-xl p-4 space-y-2 cursor-pointer transition-all ${sel?"border-primary bg-primary/5 shadow-lg shadow-primary/10":"border-border hover:border-primary/30"}`}>
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <div className={`w-5 h-5 rounded border-2 flex items-center justify-center ${sel?"bg-primary border-primary":"border-border"}`}>{sel&&<CheckCircle2 className="w-3 h-3 text-white" />}</div>
                        <span className={`text-xs px-2 py-0.5 rounded-full ${info.color} bg-current/10`}>{info.icon} {info.label}</span>
                      </div>
                      <div className="flex items-center gap-1">
                        <span className={`text-[10px] px-1.5 py-0.5 rounded ${s.complexity==="advanced"?"bg-red-500/10 text-red-400":s.complexity==="medium"?"bg-amber-500/10 text-amber-400":"bg-emerald-500/10 text-emerald-400"}`}>{s.complexity}</span>
                        <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${s.confidence>=80?"bg-emerald-500/10 text-emerald-400":"bg-amber-500/10 text-amber-400"}`}>{s.confidence}%</span>
                      </div>
                    </div>
                    <h4 className="font-bold text-sm">{s.name}</h4>
                    <p className="text-xs text-muted-foreground">{s.description}</p>
                    <div className="text-[10px] space-y-0.5">
                      <p><span className="text-primary">مؤشرات:</span> {s.indicators.join(", ")}</p>
                      {s.filters?.length > 0 && <p><span className="text-amber-400">فلاتر:</span> {s.filters.join(", ")}</p>}
                      <p><span className="text-emerald-400">دخول:</span> {s.entryLogic.substring(0,100)}...</p>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Generate Notes + Button */}
            {selectedIds.size > 0 && (
              <div className="bg-gradient-to-r from-primary/5 to-violet-500/5 border border-primary/20 rounded-2xl p-5 space-y-4">
                <h3 className="font-bold flex items-center gap-2"><Zap className="w-5 h-5 text-primary" /> {selectedIds.size} استراتيجية مختارة — جاهز للتوليد</h3>
                <div className="space-y-2">
                  <label className="text-sm font-medium flex items-center gap-2"><MessageSquare className="w-4 h-4 text-primary" /> ملاحظات إضافية للكود</label>
                  <textarea value={generateNotes} onChange={e=>setGenerateNotes(e.target.value)} rows={3} placeholder="مثال: أضف dashboard على الشارت... استخدم lot size 0.01... أضف trailing stop 30 نقطة... لا تتداول وقت الأخبار..." className="w-full bg-secondary/50 border border-border rounded-xl px-4 py-3 text-sm resize-none focus:ring-2 focus:ring-primary/50" />
                </div>
                <Button onClick={handleGenerate} disabled={generateMut.isPending} className="w-full py-5 text-base gap-2 bg-gradient-to-r from-primary to-violet-600">
                  {generateMut.isPending ? <><Loader2 className="w-5 h-5 animate-spin" /> AI يكتب كود ضخم يدمج {selectedIds.size} استراتيجية...</> : <><Code2 className="w-5 h-5" /> إنشاء {platform.toUpperCase()} {outputType==="ea"?"Expert Advisor":"Indicator"} ({selectedIds.size} استراتيجية)</>}
                </Button>
              </div>
            )}

            {/* Custom Prompt */}
            <div className="bg-card border border-border rounded-2xl p-5 space-y-3">
              <h3 className="text-sm font-bold flex items-center gap-2"><Brain className="w-4 h-4 text-primary" /> أو اكتب استراتيجيتك الخاصة</h3>
              <textarea value={customPrompt} onChange={e=>setCustomPrompt(e.target.value)} rows={3} placeholder="ادمج RSI + MACD + Bollinger — شراء عندما RSI تحت 30 و MACD يتقاطع صعوداً..." className="w-full bg-secondary/50 border border-border rounded-xl px-4 py-3 text-sm resize-none focus:ring-2 focus:ring-primary/50" />
              <Button onClick={handleCustomGenerate} disabled={customMut.isPending||!customPrompt.trim()} className="w-full gap-2">
                {customMut.isPending?<><Loader2 className="w-4 h-4 animate-spin" /> جاري التوليد...</>:<><Sparkles className="w-4 h-4" /> إنشاء من وصفي</>}
              </Button>
            </div>
          </div>
        )}

        {/* ═══ GENERATING ═══ */}
        {step === "generating" && (
          <div className="max-w-md mx-auto text-center py-12 space-y-6">
            <div className="relative mx-auto w-24 h-24"><div className="absolute inset-0 rounded-full bg-violet-500/10 animate-ping" style={{animationDuration:"2s"}}/><div className="relative w-24 h-24 rounded-full bg-violet-500/20 flex items-center justify-center"><Code2 className="w-12 h-12 text-violet-400" /></div></div>
            <h2 className="text-xl font-bold">AI يكتب كود {platform.toUpperCase()} ضخم...</h2>
            <div className="space-y-2 text-sm text-muted-foreground">
              <p>🧠 AI #1 (Claude Opus) يكتب كود يدمج {selectedIds.size || 1} استراتيجية</p>
              <p>🔍 AI #2 (Sonnet) يراجع ويصلح أخطاء التجميع</p>
              <p>📏 كود 500+ سطر مع تعليقات عربية</p>
            </div>
          </div>
        )}

        {/* ═══ RESULT ═══ */}
        {step === "result" && generatedCode && (
          <div className="space-y-6">
            <div className="bg-gradient-to-r from-emerald-500/10 to-cyan-500/10 border border-emerald-500/20 rounded-2xl p-5 text-center space-y-2">
              <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto" />
              <h2 className="text-xl font-bold">تم إنشاء الكود بنجاح!</h2>
            </div>
            <div className="bg-card border border-border rounded-xl p-4 text-xs whitespace-pre-wrap font-mono text-muted-foreground">{codeAnalysis}</div>
            <div className="grid grid-cols-4 gap-3 text-xs">
              <div className="bg-card border border-border rounded-xl p-3 text-center"><p className="text-muted-foreground">منصة</p><p className="font-bold text-lg mt-1">{platform.toUpperCase()}</p></div>
              <div className="bg-card border border-border rounded-xl p-3 text-center"><p className="text-muted-foreground">نوع</p><p className="font-bold text-lg mt-1">{outputType==="ea"?"🤖 EA":"📊 IND"}</p></div>
              <div className="bg-card border border-border rounded-xl p-3 text-center"><p className="text-muted-foreground">حجم</p><p className="font-bold text-lg mt-1">{(generatedCode.length/1024).toFixed(1)}KB</p></div>
              <div className="bg-card border border-border rounded-xl p-3 text-center"><p className="text-muted-foreground">أسطر</p><p className="font-bold text-lg mt-1">{generatedCode.split("\n").length}</p></div>
            </div>
            <div className="bg-card border border-border rounded-2xl overflow-hidden">
              <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-secondary/30">
                <span className="text-xs font-mono text-muted-foreground">HAYO_Strategy.{platform}</span>
                <div className="flex gap-2">
                  <button onClick={()=>setShowCode(!showCode)} className="text-xs text-primary flex items-center gap-1">{showCode?<EyeOff className="w-3 h-3"/>:<Eye className="w-3 h-3"/>} {showCode?"إخفاء":"عرض"}</button>
                  <button onClick={handleCopy} className="text-xs text-primary flex items-center gap-1"><Copy className="w-3 h-3" /> نسخ</button>
                </div>
              </div>
              {showCode && <pre className="p-4 text-xs font-mono overflow-x-auto max-h-[500px] text-foreground/80 leading-relaxed whitespace-pre" dir="ltr">{generatedCode}</pre>}
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Button onClick={handleCopy} className="py-5 gap-2 bg-primary"><Copy className="w-5 h-5" /> نسخ الكود</Button>
              <Button onClick={handleDownload} variant="outline" className="py-5 gap-2 border-primary/30 text-primary"><Download className="w-5 h-5" /> تحميل .{platform}</Button>
            </div>

            {/* AI Fix Compile Errors */}
            <div className="bg-card border border-amber-500/20 rounded-2xl overflow-hidden">
              <button onClick={() => setShowFixPanel(!showFixPanel)} className="w-full flex items-center justify-between px-5 py-3 hover:bg-secondary/20 transition-colors">
                <span className="flex items-center gap-2 text-sm font-bold text-amber-400">
                  <Zap className="w-4 h-4" /> 🔧 ظهرت أخطاء في MetaEditor؟ — AI يصلحها فوراً
                </span>
                {showFixPanel ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
              </button>
              {showFixPanel && (
                <div className="px-5 pb-4 space-y-3 border-t border-border pt-3">
                  <p className="text-xs text-muted-foreground">الصق أخطاء التجميع من MetaEditor هنا (الأسطر الحمراء في نافذة Errors):</p>
                  <textarea
                    value={compileErrors}
                    onChange={e => setCompileErrors(e.target.value)}
                    rows={5}
                    dir="ltr"
                    placeholder={"مثال:\n'OrderSend' - wrong parameters count  line 245\n'pos' - undeclared identifier  line 312\n'OnCalculate' - wrong return type  line 89"}
                    className="w-full bg-[#0d1117] border border-border rounded-xl px-4 py-3 text-xs font-mono text-red-400 resize-none focus:ring-2 focus:ring-amber-500/50 placeholder:text-red-400/30"
                  />
                  <div className="space-y-2">
                    <label className="text-[10px] text-muted-foreground">ملاحظات إضافية (اختياري):</label>
                    <input value={fixNotes} onChange={e => setFixNotes(e.target.value)} placeholder="مثال: لا تحذف dashboard... أضف trailing stop..." className="w-full bg-secondary/50 border border-border rounded-lg px-3 py-2 text-xs" />
                  </div>
                  <Button onClick={handleFixErrors} disabled={fixErrorsMut.isPending || !compileErrors.trim()} className="w-full gap-2 bg-amber-600 hover:bg-amber-700">
                    {fixErrorsMut.isPending ? <><Loader2 className="w-4 h-4 animate-spin" /> AI يصلح الأخطاء (Opus + Sonnet)...</> : <><Zap className="w-4 h-4" /> إصلاح أخطاء التجميع بـ AI</>}
                  </Button>
                </div>
              )}
            </div>
            <div className="bg-muted/20 rounded-xl p-4 text-xs text-muted-foreground space-y-1">
              <p className="font-bold text-foreground">📋 خطوات الاستخدام:</p>
              <p>① انسخ الكود أو حمّل الملف → ② افتح MetaEditor → ③ File → New → {outputType==="ea"?"Expert Advisor":"Custom Indicator"} → ④ الصق الكود → ⑤ Compile (F7) → ⑥ {outputType==="ea"?"اسحب EA على الشارت":"أضف المؤشر من Navigator"}</p>
            </div>
            <div className="flex gap-3">
              <Button variant="outline" onClick={()=>setStep("strategies")} className="flex-1 gap-2"><RefreshCw className="w-4 h-4" /> اختيار استراتيجيات أخرى</Button>
              <Button variant="outline" onClick={handleReset} className="flex-1 gap-2"><Sparkles className="w-4 h-4" /> بداية جديدة</Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
