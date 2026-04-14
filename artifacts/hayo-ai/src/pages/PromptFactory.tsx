/*
 * HAYO AI — مصنع البرومبت (Prompt Factory)
 * يحوّل الأفكار البسيطة إلى برومبتات احترافية أكاديمية مع شرح تقني للتنفيذ
 */
import { useState, useRef, useEffect } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import {
  Sparkles, Copy, CheckCheck, Loader2, ChevronDown, ChevronUp,
  Wand2, Lightbulb, Cpu, Code2, Palette, BookOpen, BarChart3,
  Globe, ShoppingBag, MessageSquare, Brain, RotateCcw, Download,
  FlaskConical, ArrowRight, Zap,
} from "lucide-react";
import { useTranslation } from "react-i18next";
import LanguageSwitcher from "@/components/LanguageSwitcher";

// ─── Constants ────────────────────────────────────────────────

const CATEGORIES = [
  { id: "coding",    label: "برمجة وتطوير",  icon: Code2,        color: "text-blue-400",   bg: "bg-blue-500/10 border-blue-500/30" },
  { id: "creative",  label: "كتابة إبداعية", icon: Palette,      color: "text-pink-400",   bg: "bg-pink-500/10 border-pink-500/30" },
  { id: "research",  label: "بحث علمي",      icon: FlaskConical, color: "text-emerald-400", bg: "bg-emerald-500/10 border-emerald-500/30" },
  { id: "business",  label: "أعمال وتسويق",  icon: BarChart3,    color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/30" },
  { id: "education", label: "تعليم وشرح",    icon: BookOpen,     color: "text-violet-400", bg: "bg-violet-500/10 border-violet-500/30" },
  { id: "chat",      label: "محادثة وتفاعل", icon: MessageSquare,color: "text-cyan-400",   bg: "bg-cyan-500/10 border-cyan-500/30" },
  { id: "analysis",  label: "تحليل بيانات",  icon: Brain,        color: "text-amber-400",  bg: "bg-amber-500/10 border-amber-500/30" },
  { id: "seo",       label: "محتوى رقمي",    icon: Globe,        color: "text-teal-400",   bg: "bg-teal-500/10 border-teal-500/30" },
  { id: "ecommerce", label: "تجارة إلكترونية",icon: ShoppingBag, color: "text-red-400",    bg: "bg-red-500/10 border-red-500/30" },
] as const;

const TARGET_MODELS = [
  { id: "",             label: "الأفضل عموماً",   icon: "⚡" },
  { id: "Claude Opus",  label: "Claude Opus 4",   icon: "🟣" },
  { id: "GPT-4o",       label: "GPT-4o",           icon: "🟢" },
  { id: "Gemini Pro",   label: "Gemini 2.5 Pro",   icon: "🔵" },
  { id: "DeepSeek R1",  label: "DeepSeek R1",      icon: "⚡" },
  { id: "Llama 3",      label: "Llama 3 70B",      icon: "🦙" },
  { id: "Mistral",      label: "Mistral Large",    icon: "💨" },
] as const;

const EXAMPLE_REQUESTS = [
  "اكتب لي قصة قصيرة مشوّقة عن عالم مستقبلي تحكمه الروبوتات",
  "حلل بياناتي المالية وأعطني تقريراً شاملاً مع رسوم بيانية",
  "ساعدني في كتابة سيرة ذاتية احترافية لمهندس برمجيات خبرة 5 سنوات",
  "علّمني مفهوم الشبكات العصبية بطريقة بسيطة مع أمثلة كود Python",
  "أنشئ استراتيجية تسويق رقمي لمتجر إلكتروني جديد مع ميزانية 5000$",
  "راجع كودي Python وحسّن أداءه مع شرح كل تغيير",
  "اكتب عقد عمل قانوني بين شركة وموظف بكل البنود اللازمة",
  "أنشئ منهج دراسي كامل لتعليم JavaScript من الصفر في 30 يوم",
  "حلل اتجاهات سوق الذهب وأعطني توقعات مع أسباب فنية",
  "اكتب بريد إلكتروني بارد (cold email) لجذب عملاء B2B",
];

// ─── Section Component ────────────────────────────────────────

function ResultSection({ title, children, defaultOpen = true }: {
  title: string; children: React.ReactNode; defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border border-border rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-4 py-3 bg-muted/20 hover:bg-muted/30 transition-colors text-sm font-semibold text-right"
      >
        <span className="flex-1 text-right">{title}</span>
        {open ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
      </button>
      {open && <div className="px-4 py-3">{children}</div>}
    </div>
  );
}

// ─── Prompt Block (copyable) ──────────────────────────────────

function PromptBlock({ content }: { content: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(content);
    setCopied(true);
    toast.success("تم نسخ البرومبت!");
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <div className="relative group">
      <pre className="font-mono text-xs leading-relaxed whitespace-pre-wrap break-words bg-muted/30 rounded-xl p-4 border border-border text-foreground/90 max-h-80 overflow-y-auto">
        {content}
      </pre>
      <button
        onClick={copy}
        className="absolute top-2 left-2 opacity-0 group-hover:opacity-100 transition-opacity bg-card border border-border rounded-lg px-2.5 py-1.5 text-xs flex items-center gap-1.5 hover:bg-muted/50"
      >
        {copied ? <CheckCheck className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
        {copied ? "تم النسخ" : "نسخ"}
      </button>
    </div>
  );
}

// ─── Parse Result ─────────────────────────────────────────────

interface ParsedResult {
  prompt: string;
  variables: string;
  technical: string;
  steps: string;
  models: string;
  tips: string;
  example: string;
  raw: string;
}

function parseResult(raw: string): ParsedResult {
  const sections: Record<string, string> = {};
  const markers = [
    { key: "prompt",    prefix: "# 🎯 البرومبت الاحترافي" },
    { key: "variables", prefix: "# ⚙️ المتغيرات القابلة للتخصيص" },
    { key: "technical", prefix: "# 🔬 الشرح التقني" },
    { key: "steps",     prefix: "# 📋 خطوات التنفيذ" },
    { key: "models",    prefix: "# 🤖 النماذج المثالية" },
    { key: "tips",      prefix: "# 💡 نصائح متقدمة" },
    { key: "example",   prefix: "# 📤 مثال على المخرج المتوقع" },
  ];

  let remaining = raw;
  for (let i = 0; i < markers.length; i++) {
    const { key, prefix } = markers[i];
    const idx = remaining.indexOf(prefix);
    if (idx === -1) continue;
    const after = remaining.slice(idx + prefix.length);
    const nextIdx = markers.slice(i + 1).reduce((best, m) => {
      const pos = after.indexOf(m.prefix);
      return pos !== -1 && (best === -1 || pos < best) ? pos : best;
    }, -1);
    sections[key] = (nextIdx === -1 ? after : after.slice(0, nextIdx)).trim();
    remaining = remaining.slice(0, idx);
  }

  return {
    prompt: sections.prompt || raw,
    variables: sections.variables || "",
    technical: sections.technical || "",
    steps: sections.steps || "",
    models: sections.models || "",
    tips: sections.tips || "",
    example: sections.example || "",
    raw,
  };
}

// ═══════════════════════════════════════════════════════════════
// Main Page
// ═══════════════════════════════════════════════════════════════

export default function PromptFactory() {
  const [request, setRequest] = useState("");
  const [category, setCategory] = useState("");
  const [targetModel, setTargetModel] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const [result, setResult] = useState<ParsedResult | null>(null);
  const [modelUsed, setModelUsed] = useState("");
  const [charCount, setCharCount] = useState(0);
  const [refineInput, setRefineInput] = useState("");
  const [isRefining, setIsRefining] = useState(false);
  const [testInput, setTestInput] = useState("");
  const [testResult, setTestResult] = useState("");
  const [isTesting, setIsTesting] = useState(false);
  const [showRefine, setShowRefine] = useState(false);
  const [showTest, setShowTest] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const resultRef = useRef<HTMLDivElement>(null);

  useEffect(() => { setCharCount(request.length); }, [request]);

  const handleGenerate = async () => {
    if (!request.trim() || request.trim().length < 5) {
      toast.error("يرجى كتابة طلبك بوضوح أولاً");
      return;
    }
    setIsGenerating(true); setResult(null);
    try {
      const r = await fetch("/api/prompt-factory/generate", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ request: request.trim(), category, targetModel }),
      });
      const d = await r.json();
      if (!r.ok) { toast.error(d.error || "فشل توليد البرومبت"); return; }
      setResult(parseResult(d.result));
      setModelUsed(d.modelUsed || "");
      setTimeout(() => resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 100);
    } catch (e: any) { toast.error(e.message); }
    finally { setIsGenerating(false); }
  };

  const handleExample = (ex: string) => {
    setRequest(ex);
    textareaRef.current?.focus();
  };

  const downloadResult = () => {
    if (!result) return;
    const blob = new Blob([result.raw], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url;
    a.download = `prompt-factory-${Date.now()}.txt`; a.click();
    URL.revokeObjectURL(url);
  };

  // Refine/improve the generated prompt
  const handleRefine = async () => {
    if (!result?.prompt) return;
    setIsRefining(true);
    try {
      const r = await fetch("/api/prompt-factory/refine", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt: result.prompt, feedback: refineInput }),
      });
      const d = await r.json();
      if (!r.ok) { toast.error(d.error || "فشل التحسين"); return; }
      // Update the prompt section with refined version
      setResult({ ...result, prompt: d.result, raw: result.raw.replace(result.prompt, d.result) });
      setRefineInput("");
      setShowRefine(false);
      toast.success("✅ تم تحسين البرومبت!");
    } catch (e: any) { toast.error(e.message); }
    finally { setIsRefining(false); }
  };

  // Test the prompt on AI directly
  const handleTest = async () => {
    if (!result?.prompt) return;
    setIsTesting(true); setTestResult("");
    try {
      const r = await fetch("/api/prompt-factory/test", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt: result.prompt, testInput }),
      });
      const d = await r.json();
      if (!r.ok) { toast.error(d.error || "فشل الاختبار"); return; }
      setTestResult(d.result);
      toast.success("✅ تم اختبار البرومبت!");
    } catch (e: any) { toast.error(e.message); }
    finally { setIsTesting(false); }
  };

  return (
    <DashboardLayout>
      <div className="flex flex-col gap-6 p-4 md:p-6 max-w-5xl mx-auto w-full">

        {/* ── Header ── */}
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-violet-600 to-purple-700 flex items-center justify-center shadow-lg shadow-violet-500/25">
              <Wand2 className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold bg-gradient-to-r from-violet-400 to-purple-300 bg-clip-text text-transparent">
                مصنع البرومبت
              </h1>
              <p className="text-xs text-muted-foreground">حوّل فكرتك إلى برومبت احترافي بقوة أقوى نماذج AI</p>
            </div>
          </div>

          {/* Model badge */}
          {modelUsed && (
            <div className="flex items-center gap-1.5 text-xs bg-violet-500/10 border border-violet-500/30 rounded-full px-3 py-1.5 text-violet-300">
              <Cpu className="w-3 h-3" /> {modelUsed}
            </div>
          )}
        </div>

        {/* ── Main Grid ── */}
        <div className="grid grid-cols-1 lg:grid-cols-[1fr_320px] gap-6 items-start">

          {/* ── Input Column ── */}
          <div className="flex flex-col gap-4">

            {/* Category selector */}
            <div>
              <p className="text-xs text-muted-foreground mb-2 font-medium">الفئة (اختياري)</p>
              <div className="flex flex-wrap gap-2">
                <button
                  onClick={() => setCategory("")}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs border transition-all ${
                    !category ? "bg-violet-500/20 border-violet-500/50 text-violet-300" : "border-border text-muted-foreground hover:border-muted-foreground/50"
                  }`}
                >
                  <Sparkles className="w-3 h-3" /> الكل
                </button>
                {CATEGORIES.map(cat => {
                  const Icon = cat.icon;
                  const isSelected = category === cat.id;
                  return (
                    <button
                      key={cat.id}
                      onClick={() => setCategory(isSelected ? "" : cat.id)}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs border transition-all ${
                        isSelected ? `${cat.bg} ${cat.color}` : "border-border text-muted-foreground hover:border-muted-foreground/50"
                      }`}
                    >
                      <Icon className="w-3 h-3" /> {cat.label}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Target model selector */}
            <div>
              <p className="text-xs text-muted-foreground mb-2 font-medium">النموذج المستهدف (اختياري)</p>
              <div className="flex flex-wrap gap-2">
                {TARGET_MODELS.map(m => (
                  <button
                    key={m.id}
                    onClick={() => setTargetModel(m.id === targetModel ? "" : m.id)}
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs border transition-all ${
                      targetModel === m.id
                        ? "bg-violet-500/20 border-violet-500/50 text-violet-300"
                        : "border-border text-muted-foreground hover:border-muted-foreground/50"
                    }`}
                  >
                    <span>{m.icon}</span> {m.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Request textarea */}
            <div className="relative">
              <label className="text-xs text-muted-foreground mb-2 block font-medium">
                اكتب طلبك أو فكرتك <span className="text-red-400">*</span>
              </label>
              <div className={`relative rounded-xl border transition-all ${
                request.trim().length >= 5 ? "border-violet-500/50 shadow-sm shadow-violet-500/10" : "border-border"
              }`}>
                <textarea
                  ref={textareaRef}
                  value={request}
                  onChange={e => setRequest(e.target.value)}
                  placeholder="مثال: أريد برومبت يساعدني في كتابة تقرير بحثي علمي محكّم بأسلوب أكاديمي..."
                  rows={5}
                  maxLength={2000}
                  className="w-full bg-card/50 rounded-xl px-4 py-3 text-sm resize-none focus:outline-none placeholder:text-muted-foreground/50 text-right leading-relaxed"
                  onKeyDown={e => {
                    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) handleGenerate();
                  }}
                />
                <div className="flex items-center justify-between px-3 py-2 border-t border-border bg-muted/10 rounded-b-xl">
                  <span className="text-[10px] text-muted-foreground">Ctrl+Enter للإنشاء السريع</span>
                  <span className={`text-[10px] ${charCount > 1800 ? "text-red-400" : "text-muted-foreground"}`}>
                    {charCount}/2000
                  </span>
                </div>
              </div>
            </div>

            {/* Generate button */}
            <Button
              onClick={handleGenerate}
              disabled={isGenerating || request.trim().length < 5}
              className="w-full gap-2 py-6 text-base font-semibold bg-gradient-to-r from-violet-600 to-purple-600 hover:from-violet-500 hover:to-purple-500 shadow-lg shadow-violet-500/25 transition-all"
            >
              {isGenerating ? (
                <><Loader2 className="w-5 h-5 animate-spin" /> جاري توليد البرومبت...</>
              ) : (
                <><Wand2 className="w-5 h-5" /> إنشاء برومبت احترافي <ArrowRight className="w-4 h-4" /></>
              )}
            </Button>

            {/* Loading state */}
            {isGenerating && (
              <div className="flex flex-col items-center gap-3 py-8 text-center">
                <div className="relative w-16 h-16">
                  <div className="absolute inset-0 rounded-full border-4 border-violet-500/20 animate-ping" />
                  <div className="absolute inset-2 rounded-full bg-gradient-to-br from-violet-600 to-purple-700 flex items-center justify-center">
                    <Brain className="w-6 h-6 text-white animate-pulse" />
                  </div>
                </div>
                <p className="text-sm font-medium text-violet-300">أقوى نموذج AI يصيغ برومبتك...</p>
                <p className="text-xs text-muted-foreground">يتحقق من التقنيات ويُهيكل البرومبت الاحترافي</p>
              </div>
            )}
          </div>

          {/* ── Sidebar: Examples & Tips ── */}
          <div className="flex flex-col gap-4">

            {/* Examples */}
            <div className="bg-card border border-border rounded-2xl p-4 space-y-3">
              <div className="flex items-center gap-2 text-sm font-semibold">
                <Lightbulb className="w-4 h-4 text-amber-400" />
                أمثلة جاهزة
              </div>
              <div className="space-y-2">
                {EXAMPLE_REQUESTS.map((ex, i) => (
                  <button
                    key={i}
                    onClick={() => handleExample(ex)}
                    className="w-full text-right text-xs text-muted-foreground hover:text-foreground border border-border hover:border-violet-500/40 hover:bg-violet-500/5 rounded-lg px-3 py-2 transition-all leading-relaxed"
                  >
                    {ex}
                  </button>
                ))}
              </div>
            </div>

            {/* Info card */}
            <div className="bg-gradient-to-br from-violet-500/5 to-purple-500/5 border border-violet-500/20 rounded-2xl p-4 space-y-3">
              <div className="flex items-center gap-2 text-sm font-semibold text-violet-300">
                <Zap className="w-4 h-4" /> كيف يعمل
              </div>
              <div className="space-y-2 text-xs text-muted-foreground">
                {[
                  ["١", "اكتب فكرتك أو طلبك بأي لغة"],
                  ["٢", "اختر الفئة والنموذج (اختياري)"],
                  ["٣", "يحلّل أقوى AI طلبك"],
                  ["٤", "تحصل على برومبت + شرح تقني كامل"],
                ].map(([num, text]) => (
                  <div key={num} className="flex items-start gap-2">
                    <span className="text-violet-400 font-bold flex-shrink-0">{num}</span>
                    <span>{text}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* ══ Result ══ */}
        {result && (
          <div ref={resultRef} className="flex flex-col gap-4">
            {/* Result header */}
            <div className="flex items-center gap-3 pb-2 border-b border-border">
              <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-emerald-500 to-teal-600 flex items-center justify-center">
                <Sparkles className="w-4 h-4 text-white" />
              </div>
              <div className="flex-1">
                <h2 className="font-bold text-base">البرومبت الاحترافي</h2>
                {modelUsed && <p className="text-[10px] text-muted-foreground">تم التوليد بواسطة {modelUsed}</p>}
              </div>
              <div className="flex items-center gap-2">
                <Button size="sm" variant="outline" onClick={() => setShowRefine(!showRefine)} className="gap-1.5 h-8 text-xs text-amber-400 border-amber-400/30">
                  <Wand2 className="w-3 h-3" /> تحسين
                </Button>
                <Button size="sm" variant="outline" onClick={() => setShowTest(!showTest)} className="gap-1.5 h-8 text-xs text-emerald-400 border-emerald-400/30">
                  <Zap className="w-3 h-3" /> اختبار
                </Button>
                <Button
                  size="sm" variant="outline"
                  onClick={() => { setResult(null); setRequest(""); setCategory(""); setTargetModel(""); setModelUsed(""); setTestResult(""); setShowRefine(false); setShowTest(false); }}
                  className="gap-1.5 h-8 text-xs"
                >
                  <RotateCcw className="w-3 h-3" /> إعادة
                </Button>
                <Button size="sm" variant="outline" onClick={downloadResult} className="gap-1.5 h-8 text-xs">
                  <Download className="w-3 h-3" /> تحميل
                </Button>
                <Button
                  size="sm" variant="outline"
                  onClick={() => { navigator.clipboard.writeText(result.raw); toast.success("تم نسخ الكل!"); }}
                  className="gap-1.5 h-8 text-xs"
                >
                  <Copy className="w-3 h-3" /> نسخ
                </Button>
              </div>
            </div>

            {/* Sections */}
            <div className="flex flex-col gap-3">

              {/* Main prompt - always visible */}
              {result.prompt && (
                <ResultSection title="🎯 البرومبت الاحترافي الجاهز للاستخدام" defaultOpen={true}>
                  <PromptBlock content={result.prompt} />
                </ResultSection>
              )}

              {/* Refine Panel */}
              {showRefine && (
                <div className="bg-amber-500/5 border border-amber-500/20 rounded-xl p-4 space-y-3">
                  <h3 className="text-sm font-bold text-amber-400 flex items-center gap-2"><Wand2 className="w-4 h-4" /> تحسين البرومبت</h3>
                  <textarea value={refineInput} onChange={e => setRefineInput(e.target.value)} rows={3}
                    placeholder="ماذا تريد تحسينه؟ مثال: اجعله أقصر... أضف أمثلة أكثر... ركّز على SEO... اجعله بالإنجليزية..."
                    className="w-full bg-card border border-border rounded-xl px-4 py-3 text-sm resize-none focus:ring-2 focus:ring-amber-500/50" />
                  <Button onClick={handleRefine} disabled={isRefining} className="w-full gap-2 bg-amber-600 hover:bg-amber-700">
                    {isRefining ? <><Loader2 className="w-4 h-4 animate-spin" /> AI يحسّن البرومبت...</> : <><Wand2 className="w-4 h-4" /> تحسين بالذكاء الاصطناعي</>}
                  </Button>
                </div>
              )}

              {/* Test Panel */}
              {showTest && (
                <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-xl p-4 space-y-3">
                  <h3 className="text-sm font-bold text-emerald-400 flex items-center gap-2"><Zap className="w-4 h-4" /> اختبار البرومبت مباشرة</h3>
                  <textarea value={testInput} onChange={e => setTestInput(e.target.value)} rows={2}
                    placeholder="أدخل مثال لاختبار البرومبت (اختياري — إذا تركته فارغاً سيُختبر بمثال تلقائي)"
                    className="w-full bg-card border border-border rounded-xl px-4 py-3 text-sm resize-none focus:ring-2 focus:ring-emerald-500/50" />
                  <Button onClick={handleTest} disabled={isTesting} className="w-full gap-2 bg-emerald-600 hover:bg-emerald-700">
                    {isTesting ? <><Loader2 className="w-4 h-4 animate-spin" /> AI يختبر البرومبت...</> : <><Zap className="w-4 h-4" /> تشغيل الاختبار (Claude Sonnet)</>}
                  </Button>
                  {testResult && (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-emerald-400">📤 نتيجة الاختبار:</span>
                        <button onClick={() => { navigator.clipboard.writeText(testResult); toast.success("تم نسخ النتيجة"); }} className="text-xs text-primary hover:underline flex items-center gap-1"><Copy className="w-3 h-3" /> نسخ</button>
                      </div>
                      <div className="bg-card border border-border rounded-xl p-4 text-sm leading-relaxed whitespace-pre-wrap max-h-60 overflow-y-auto text-foreground/85">{testResult}</div>
                    </div>
                  )}
                </div>
              )}

              {/* Variables */}
              {result.variables && (
                <ResultSection title="⚙️ المتغيرات القابلة للتخصيص" defaultOpen={true}>
                  <div className="text-sm leading-relaxed whitespace-pre-wrap text-foreground/85">{result.variables}</div>
                </ResultSection>
              )}

              {/* Technical explanation */}
              {result.technical && (
                <ResultSection title="🔬 الشرح التقني لبنية البرومبت" defaultOpen={true}>
                  <div className="text-sm leading-relaxed whitespace-pre-wrap text-foreground/85">{result.technical}</div>
                </ResultSection>
              )}

              {/* Steps */}
              {result.steps && (
                <ResultSection title="📋 خطوات التنفيذ" defaultOpen={true}>
                  <div className="text-sm leading-relaxed whitespace-pre-wrap text-foreground/85">{result.steps}</div>
                </ResultSection>
              )}

              {/* Bottom row: models + tips */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {result.models && (
                  <ResultSection title="🤖 النماذج المثالية لهذا البرومبت" defaultOpen={true}>
                    <div className="text-sm leading-relaxed whitespace-pre-wrap text-foreground/85">{result.models}</div>
                  </ResultSection>
                )}
                {result.tips && (
                  <ResultSection title="💡 نصائح متقدمة" defaultOpen={true}>
                    <div className="text-sm leading-relaxed whitespace-pre-wrap text-foreground/85">{result.tips}</div>
                  </ResultSection>
                )}
              </div>

              {/* Expected output example */}
              {result.example && (
                <ResultSection title="📤 مثال على المخرج المتوقع" defaultOpen={false}>
                  <div className="text-sm leading-relaxed whitespace-pre-wrap text-foreground/85 bg-muted/20 rounded-lg p-3 border border-border">{result.example}</div>
                </ResultSection>
              )}

              {/* If parsing failed, show raw */}
              {!result.prompt && result.raw && (
                <ResultSection title="النتيجة الكاملة" defaultOpen={true}>
                  <div className="text-sm leading-relaxed whitespace-pre-wrap text-foreground/85">{result.raw}</div>
                </ResultSection>
              )}
            </div>
          </div>
        )}

      </div>
    </DashboardLayout>
  );
}
